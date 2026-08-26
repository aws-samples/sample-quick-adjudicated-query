"""CDK stack for the Quick lease-compliance PoC.

Task 1 scope: auth + the MCP server front door. Aurora arrives in task 3.

Design decisions this file implements (see design.md):
  - Auth is Cognito 2LO (client credentials). The API Gateway JWT authorizer validates the token
    before the Lambda runs, so the function contains no auth code. No unauthenticated route to the
    MCP endpoint exists at any commit.
  - Discovery routes (/.well-known/..., /health) are deliberately open: Quick must read
    protected-resource metadata *before* it has a token, and neither route exposes lease data.
"""

from aws_cdk import (
    CfnOutput,
    Duration,
    RemovalPolicy,
    Stack,
)
from aws_cdk import aws_apigatewayv2 as apigw
from aws_cdk import aws_apigatewayv2_authorizers as apigw_auth
from aws_cdk import aws_apigatewayv2_integrations as apigw_int
from aws_cdk import aws_cognito as cognito
from aws_cdk import aws_ec2 as ec2
from aws_cdk import aws_iam as iam
from aws_cdk import aws_lambda as lambda_
from aws_cdk import aws_logs as logs
from aws_cdk import aws_rds as rds
from constructs import Construct

RESOURCE_SERVER_ID = "lease-poc"
READ_SCOPE = "read"


class QuickPocStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # --- Cognito: a token endpoint, not a user directory -------------------------------
        # No users are ever created here. The pool exists solely because it gives us a public
        # OAuth token endpoint inside this account, which is what Quick's service authentication
        # requires (private OAuth providers are not supported). Swappable for any IdP later.
        user_pool = cognito.UserPool(
            self,
            "McpUserPool",
            user_pool_name="quick-poc-mcp",
            self_sign_up_enabled=False,
            removal_policy=RemovalPolicy.DESTROY,
        )

        # A stable, unique-ish domain prefix for the hosted token endpoint.
        domain_prefix = "quick-poc-mcp-%s" % self.account[-6:]
        user_pool.add_domain(
            "McpUserPoolDomain",
            cognito_domain=cognito.CognitoDomainOptions(domain_prefix=domain_prefix),
        )

        read_scope = cognito.ResourceServerScope(
            scope_name=READ_SCOPE,
            scope_description="Read-only access to lease compliance tools",
        )
        resource_server = user_pool.add_resource_server(
            "McpResourceServer",
            identifier=RESOURCE_SERVER_ID,
            scopes=[read_scope],
        )

        # Client-credentials grant = machine-to-machine (2LO). Quick stores the client id/secret
        # and fetches its own tokens.
        client = user_pool.add_client(
            "McpM2MClient",
            user_pool_client_name="quick-mcp-client",
            generate_secret=True,
            auth_flows=cognito.AuthFlow(),
            o_auth=cognito.OAuthSettings(
                flows=cognito.OAuthFlows(client_credentials=True),
                scopes=[cognito.OAuthScope.resource_server(resource_server, read_scope)],
            ),
            access_token_validity=Duration.hours(1),
        )

        full_scope = "%s/%s" % (RESOURCE_SERVER_ID, READ_SCOPE)
        issuer = "https://cognito-idp.%s.amazonaws.com/%s" % (self.region, user_pool.user_pool_id)
        token_endpoint = "https://%s.auth.%s.amazoncognito.com/oauth2/token" % (
            domain_prefix,
            self.region,
        )

        # --- Aurora Serverless v2: Postgres + pgvector -------------------------------------
        # Chosen over the DynamoDB/OpenSearch pair so the completeness receipt is a SQL count and
        # filter-then-rank is one statement (see design.md). Scales to zero when idle.
        #
        # A VPC is required even though the Lambda never enters it: the Lambda reaches the cluster
        # through the RDS Data API (a regional HTTPS endpoint, IAM-authorised), which is what keeps
        # the function on boto3 alone with no pg driver and no ENI cold-start cost. The VPC exists
        # for the cluster itself and for Quick Sight's VPC connection in task 8.
        vpc = ec2.Vpc(
            self,
            "DbVpc",
            max_azs=2,
            nat_gateways=0,  # nothing needs egress; avoids ~$32/mo of idle NAT
            subnet_configuration=[
                ec2.SubnetConfiguration(
                    name="isolated",
                    subnet_type=ec2.SubnetType.PRIVATE_ISOLATED,
                    cidr_mask=24,
                )
            ],
        )

        db = rds.DatabaseCluster(
            self,
            "LeaseDb",
            engine=rds.DatabaseClusterEngine.aurora_postgres(
                # pgvector ships with Aurora PostgreSQL 15+ as the `vector` extension.
                #
                # Pinned with of() rather than the AuroraPostgresEngineVersion enum: the installed
                # aws-cdk-lib only knows up to VER_16_9, while us-east-1 currently offers 16.11 /
                # 16.13 / 16.14 and has retired 16.6. The enum tracks CDK's release date, not what
                # RDS actually offers today, so an explicit version avoids a deploy-time
                # "Cannot find version" failure. Verify with:
                #   aws rds describe-db-engine-versions --engine aurora-postgresql
                version=rds.AuroraPostgresEngineVersion.of("16.14", "16")
            ),
            writer=rds.ClusterInstance.serverless_v2("writer"),
            # 0.5 ACU rather than 0.
            #
            # At 0 the cluster auto-pauses when idle and the first Data API call of a session fails
            # with DatabaseResumingException -- which happened on the very first question asked
            # through Quick. `db.py` now waits that out, but a demo should not open with a
            # 20-second stall on the headline question. 0.5 ACU keeps it warm for roughly $0.06/hr
            # (~$43/mo if left running), so it is a demo-window cost, not a permanent one.
            #
            # Set back to 0 between demo windows if the stack is being kept but not shown.
            serverless_v2_min_capacity=0.5,
            serverless_v2_max_capacity=8,  # headroom for the 50K-row sweep
            vpc=vpc,
            vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_ISOLATED),
            default_database_name="leases",
            enable_data_api=True,  # the whole reason the Lambda needs no VPC or pg driver
            removal_policy=RemovalPolicy.DESTROY,
            storage_encrypted=True,
            backup=rds.BackupProps(retention=Duration.days(1)),
        )

        # --- Quick Sight access to Aurora --------------------------------------------------
        # The dashboard is where "show me all 10,111 rows and let me drill into one" is answered.
        # Quick Sight reaches Aurora through a VPC connection, which needs its own security group
        # and an IAM role it assumes to create ENIs in the isolated subnets.
        qs_sg = ec2.SecurityGroup(
            self,
            "QuickSightSg",
            vpc=vpc,
            description="Quick Sight VPC connection for the lease compliance dashboard",
            allow_all_outbound=True,
        )
        # Exactly one inbound rule on the database, from this security group, on Postgres only --
        # not a CIDR range. The database SG otherwise has no inbound rules at all.
        db.connections.allow_from(qs_sg, ec2.Port.tcp(5432),
                                  "Quick Sight VPC connection")

        # The counterintuitive half, and the reason the first data source attempt failed with a bare
        # "The connection attempt failed": Quick Sight's VPC connection security group needs
        # inbound from the database on ALL TCP ports, because the destination port of an inbound
        # return packet is randomly allocated. Ordinary stateful security-group behaviour does not
        # apply to these network interfaces.
        # https://docs.aws.amazon.com/quicksight/latest/user/vpc-inbound-rules.html
        #
        # Still tightly scoped: source is the database's security group, not a CIDR, and both
        # groups live in isolated subnets with no route to the internet.
        qs_sg.add_ingress_rule(
            peer=ec2.SecurityGroup.from_security_group_id(
                self, "DbSgRef", db.connections.security_groups[0].security_group_id),
            connection=ec2.Port.all_tcp(),
            description="Return traffic from Aurora (random destination ports)",
        )

        qs_vpc_role = iam.Role(
            self,
            "QuickSightVpcRole",
            assumed_by=iam.ServicePrincipal("quicksight.amazonaws.com"),
            description="Assumed by Quick Sight to manage ENIs for its VPC connection",
        )
        # The ENI permissions a VPC connection requires. Scoped to EC2 networking actions only;
        # this role cannot read data.
        qs_vpc_role.add_to_policy(
            iam.PolicyStatement(
                actions=[
                    "ec2:CreateNetworkInterface",
                    "ec2:ModifyNetworkInterfaceAttribute",
                    "ec2:DeleteNetworkInterface",
                    "ec2:DescribeSubnets",
                    "ec2:DescribeSecurityGroups",
                ],
                resources=["*"],
            )
        )

        # --- Lambda: protocol + engine ----------------------------------------------------
        log_group = logs.LogGroup(
            self,
            "McpServerLogs",
            retention=logs.RetentionDays.ONE_WEEK,
            removal_policy=RemovalPolicy.DESTROY,
        )

        fn = lambda_.Function(
            self,
            "McpServerFn",
            function_name="quick-poc-mcp-server",
            runtime=lambda_.Runtime.PYTHON_3_12,
            handler="handler.lambda_handler",
            code=lambda_.Code.from_asset("mcp_server"),
            # Comfortably inside Quick's fixed 60s MCP ceiling, with headroom to observe a slow
            # sweep rather than have API Gateway cut it off first.
            timeout=Duration.seconds(50),
            # 1024MB rather than 512: `explore_clauses` classifies up to 25 clauses through a
            # thread pool, and Lambda CPU scales with memory, so the extra headroom keeps the
            # concurrent Bedrock calls from queueing behind a single throttled core.
            memory_size=1024,
            log_group=log_group,
            environment={
                "OAUTH_ISSUER": issuer,
                "OAUTH_SCOPES": full_scope,
                "DB_CLUSTER_ARN": db.cluster_arn,
                "DB_SECRET_ARN": db.secret.secret_arn,
                "DB_NAME": "leases",
            },
        )

        # Data API access + the credentials to use it. Read-only at the tool level is a property of
        # the SQL the engine issues, not of these grants: `sweep` must INSERT findings, so the
        # function needs write access to the database. No MCP tool exposes a mutation.
        db.grant_data_api_access(fn)

        # Bedrock, for `explore_clauses` only: Titan embeds the query, Claude assesses each ranked
        # clause. Inference actions only -- nothing here can create, modify, or delete a Bedrock
        # resource. `sweep_compliance` deliberately has no model dependency, which is why an
        # unreachable Bedrock degrades exploration without touching official determinations.
        fn.add_to_role_policy(
            iam.PolicyStatement(
                actions=["bedrock:InvokeModel"],
                resources=[
                    "arn:aws:bedrock:%s::foundation-model/amazon.titan-embed-text-v2:0" % self.region,
                    # Claude is invoked through a cross-region inference profile (the `us.` prefix),
                    # which requires both the profile ARN and the underlying model ARNs in every
                    # region the profile can route to.
                    "arn:aws:bedrock:*::foundation-model/anthropic.claude-*",
                    "arn:aws:bedrock:%s:%s:inference-profile/us.anthropic.claude-*"
                    % (self.region, self.account),
                ],
            )
        )

        # --- HTTP API: TLS + JWT validation -----------------------------------------------
        authorizer = apigw_auth.HttpJwtAuthorizer(
            "McpJwtAuthorizer",
            jwt_issuer=issuer,
            jwt_audience=[client.user_pool_client_id],
            identity_source=["$request.header.Authorization"],
        )

        http_api = apigw.HttpApi(
            self,
            "McpHttpApi",
            api_name="quick-poc-mcp",
            description="MCP server (streamable HTTP) for the Quick lease-compliance PoC",
        )
        integration = apigw_int.HttpLambdaIntegration("McpIntegration", fn)

        # The MCP endpoint itself -- authorized. POST carries JSON-RPC; GET and DELETE are part of
        # the streamable-HTTP transport (stream open / session end) and are routed so that a
        # client probing them is answered by the server -- and logged -- rather than rejected at
        # the edge with a 403 that looks like an auth failure.
        http_api.add_routes(
            path="/mcp",
            methods=[apigw.HttpMethod.POST, apigw.HttpMethod.GET, apigw.HttpMethod.DELETE],
            integration=integration,
            authorizer=authorizer,
        )

        # Open routes, by design: Quick reads discovery metadata before it holds a token, and
        # neither route can reach lease data.
        http_api.add_routes(
            path="/.well-known/oauth-protected-resource",
            methods=[apigw.HttpMethod.GET],
            integration=integration,
        )
        http_api.add_routes(
            path="/health",
            methods=[apigw.HttpMethod.GET],
            integration=integration,
        )

        mcp_url = "%s/mcp" % http_api.api_endpoint
        fn.add_environment("RESOURCE_URL", mcp_url)

        # --- Outputs: everything needed to register the integration in Quick ---------------
        CfnOutput(self, "McpUrl", value=mcp_url,
                  description="Register this as the MCP server URL in Amazon Quick")
        CfnOutput(self, "TokenEndpoint", value=token_endpoint,
                  description="OAuth token endpoint (service authentication)")
        CfnOutput(self, "ClientId", value=client.user_pool_client_id)
        CfnOutput(self, "ClientSecretCommand",
                  value=("aws cognito-idp describe-user-pool-client --user-pool-id %s "
                         "--client-id %s --query UserPoolClient.ClientSecret --output text"
                         % (user_pool.user_pool_id, client.user_pool_client_id)),
                  description="Run this to retrieve the client secret (never in an output)")
        CfnOutput(self, "Scope", value=full_scope)
        CfnOutput(self, "Issuer", value=issuer)
        CfnOutput(self, "HealthUrl", value="%s/health" % http_api.api_endpoint)
        CfnOutput(self, "DbClusterArn", value=db.cluster_arn)
        CfnOutput(self, "DbSecretArn", value=db.secret.secret_arn)
        CfnOutput(self, "DbName", value="leases")
        CfnOutput(self, "VpcId", value=vpc.vpc_id,
                  description="For the Quick Sight VPC connection in task 8")
        CfnOutput(self, "DbSecurityGroupId",
                  value=db.connections.security_groups[0].security_group_id,
                  description="Quick Sight's VPC connection SG must be allowed inbound here")
        CfnOutput(self, "QuickSightSgId", value=qs_sg.security_group_id,
                  description="Security group for the Quick Sight VPC connection")
        CfnOutput(self, "QuickSightVpcRoleArn", value=qs_vpc_role.role_arn,
                  description="Role Quick Sight assumes for its VPC connection")
        CfnOutput(self, "PrivateSubnetIds",
                  value=",".join(s.subnet_id for s in vpc.isolated_subnets),
                  description="Subnets for the Quick Sight VPC connection")
        CfnOutput(self, "DbEndpoint", value=db.cluster_endpoint.hostname,
                  description="Aurora writer endpoint for the Quick Sight data source")
        CfnOutput(self, "DbPort", value=str(db.cluster_endpoint.port))
