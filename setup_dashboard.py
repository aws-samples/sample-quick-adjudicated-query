"""Create the Quick Sight VPC connection, data source, and datasets.

This is what makes "show me all 10,111 rows, and let me drill into any one" real. The chat answer
carries counts, the receipt, and a 20-row sample; the dashboard carries the record.

Three datasets, deliberately separate:

  findings       -- one row per finding with its complete evidence chain (the 10,111-row table)
  sweep_receipt  -- the completeness receipt, so the table can never be read without its denominator
  not_evaluated  -- leases that could NOT be checked, kept apart from findings on purpose

Direct query, not SPICE: the receipt must reflect the database at the moment it is read, and a
stale import that disagreed with a chat answer would undermine the whole point.

    .venv/bin/python setup_dashboard.py           # create or update everything
    .venv/bin/python setup_dashboard.py --status  # report what exists
"""

import json
import os
import sys
import time

import boto3
from botocore.exceptions import ClientError

HERE = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(HERE, "outputs.json")) as f:
    OUT = json.load(f)["QuickPocStack"]

REGION = "us-east-1"
ACCOUNT = boto3.client("sts").get_caller_identity()["Account"]

VPC_CONNECTION_ID = "lease-poc-vpc"
DATA_SOURCE_ID = "lease-poc-aurora"
DATASETS = {
    "lease-poc-findings": {
        "name": "Lease Compliance - Findings (full evidence chain)",
        "sql": """
            SELECT finding_id, sweep_id, as_of_date, lease_id, community, state,
                   topic, rule_id, rule_version, rule_check, rule_citation,
                   rule_effective_date, rule_approved_by,
                   status, band, band_label, risk_score,
                   extracted_value, required_value, comparison,
                   clause_citation, clause_text,
                   method, engine_version, created_at,
                   CASE WHEN is_latest_sweep THEN 'true' ELSE 'false' END AS is_latest_sweep
              FROM v_findings
        """,
    },
    "lease-poc-receipt": {
        "name": "Lease Compliance - Completeness Receipts",
        "sql": """
            SELECT sweep_id, jurisdiction, topic, as_of_date, finished_at,
                   leases_scanned, leases_evaluated, leases_compliant, leases_noncompliant,
                   leases_ambiguous, leases_not_evaluated,
                   findings_total, findings_noncompliant, findings_ambiguous,
                   rules_applied, checks_run, population_basis, determination_method,
                   completeness_check
              FROM v_sweep_receipt
        """,
    },
    "lease-poc-not-evaluated": {
        "name": "Lease Compliance - Not Evaluated (rescan queue)",
        "sql": """
            SELECT sweep_id, as_of_date, lease_id, community, state, reason, status_label
              FROM v_not_evaluated
        """,
    },
}

qs = boto3.client("quicksight", region_name=REGION)


def log(msg):
    print(msg, flush=True)


def get_secret_credentials():
    sm = boto3.client("secretsmanager", region_name=REGION)
    secret = json.loads(sm.get_secret_value(SecretId=OUT["DbSecretArn"])["SecretString"])
    return secret["username"], secret["password"]


def ensure_vpc_connection():
    try:
        resp = qs.describe_vpc_connection(AwsAccountId=ACCOUNT,
                                          VPCConnectionId=VPC_CONNECTION_ID)
        status = resp["VPCConnection"]["AvailabilityStatus"]
        log("vpc connection: exists (%s)" % status)
        return status
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("ResourceNotFoundException",):
            raise

    log("vpc connection: creating ...")
    qs.create_vpc_connection(
        AwsAccountId=ACCOUNT,
        VPCConnectionId=VPC_CONNECTION_ID,
        Name="Lease PoC Aurora",
        SubnetIds=OUT["PrivateSubnetIds"].split(","),
        SecurityGroupIds=[OUT["QuickSightSgId"]],
        RoleArn=OUT["QuickSightVpcRoleArn"],
    )

    # Creation provisions ENIs; it is not instant.
    for _ in range(40):
        time.sleep(15)
        resp = qs.describe_vpc_connection(AwsAccountId=ACCOUNT,
                                          VPCConnectionId=VPC_CONNECTION_ID)
        status = resp["VPCConnection"]["AvailabilityStatus"]
        state = resp["VPCConnection"]["Status"]
        log("  status=%s availability=%s" % (state, status))
        if status == "AVAILABLE":
            return status
        if state and "FAILED" in state:
            raise SystemExit("vpc connection failed: %s" % json.dumps(
                resp["VPCConnection"], default=str))
    raise SystemExit("vpc connection did not become AVAILABLE in time")


def ensure_data_source():
    username, password = get_secret_credentials()
    params = {
        "AwsAccountId": ACCOUNT,
        "DataSourceId": DATA_SOURCE_ID,
        "Name": "Lease PoC Aurora (leases)",
        "Type": "AURORA_POSTGRESQL",
        "DataSourceParameters": {
            "AuroraPostgreSqlParameters": {
                "Host": OUT["DbEndpoint"],
                "Port": int(OUT["DbPort"]),
                "Database": OUT["DbName"],
            }
        },
        "Credentials": {
            "CredentialPair": {"Username": username, "Password": password}
        },
        "VpcConnectionProperties": {
            "VpcConnectionArn": "arn:aws:quicksight:%s:%s:vpcConnection/%s"
                                % (REGION, ACCOUNT, VPC_CONNECTION_ID)
        },
        "SslProperties": {"DisableSsl": False},
        "Permissions": [{
            "Principal": current_user_arn(),
            "Actions": [
                "quicksight:DescribeDataSource",
                "quicksight:DescribeDataSourcePermissions",
                "quicksight:PassDataSource",
                "quicksight:UpdateDataSource",
                "quicksight:DeleteDataSource",
                "quicksight:UpdateDataSourcePermissions",
            ],
        }],
    }
    try:
        qs.create_data_source(**params)
        log("data source: created")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceExistsException":
            raise
        params.pop("Type")
        params.pop("Permissions")
        qs.update_data_source(**params)
        log("data source: updated")

    for _ in range(20):
        time.sleep(5)
        d = qs.describe_data_source(AwsAccountId=ACCOUNT, DataSourceId=DATA_SOURCE_ID)
        status = d["DataSource"]["Status"]
        if status.endswith("SUCCESSFUL"):
            log("  data source status: %s" % status)
            return
        if status.endswith("FAILED"):
            raise SystemExit("data source failed: %s"
                             % json.dumps(d["DataSource"].get("ErrorInfo", {}), default=str))
    raise SystemExit("data source did not become ready")


_user_arn = None


def current_user_arn():
    """The Quick Sight user to grant ownership to."""
    global _user_arn
    if _user_arn:
        return _user_arn
    users = qs.list_users(AwsAccountId=ACCOUNT, Namespace="default")["UserList"]
    admins = [u for u in users if u["Role"] in ("ADMIN", "ADMIN_PRO")] or users
    _user_arn = admins[0]["Arn"]
    return _user_arn


def ensure_dataset(dataset_id, spec):
    ds_arn = "arn:aws:quicksight:%s:%s:datasource/%s" % (REGION, ACCOUNT, DATA_SOURCE_ID)
    physical_id = "%s-sql" % dataset_id

    params = {
        "AwsAccountId": ACCOUNT,
        "DataSetId": dataset_id,
        "Name": spec["name"],
        "PhysicalTableMap": {
            physical_id: {
                "CustomSql": {
                    "DataSourceArn": ds_arn,
                    "Name": spec["name"][:64],
                    "SqlQuery": " ".join(spec["sql"].split()),
                    "Columns": spec["columns"],
                }
            }
        },
        # DIRECT_QUERY, not SPICE: the dashboard must agree with the chat answer at read time. A
        # stale import that disagreed with a receipt would defeat the purpose of having receipts.
        "ImportMode": "DIRECT_QUERY",
        "Permissions": [{
            "Principal": current_user_arn(),
            "Actions": [
                "quicksight:DescribeDataSet",
                "quicksight:DescribeDataSetPermissions",
                "quicksight:PassDataSet",
                "quicksight:DescribeIngestion",
                "quicksight:ListIngestions",
                "quicksight:UpdateDataSet",
                "quicksight:DeleteDataSet",
                "quicksight:CreateIngestion",
                "quicksight:CancelIngestion",
                "quicksight:UpdateDataSetPermissions",
            ],
        }],
    }
    try:
        qs.create_data_set(**params)
        log("dataset %s: created" % dataset_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceExistsException":
            raise
        perms = params.pop("Permissions")
        qs.update_data_set(**params)
        # Same trap as the dashboard: update_data_set drops Permissions, so grant them
        # unconditionally rather than only on the create path.
        qs.update_data_set_permissions(
            AwsAccountId=ACCOUNT, DataSetId=dataset_id, GrantPermissions=perms)
        log("dataset %s: updated" % dataset_id)


# Column types must be declared for custom SQL. Everything not numeric or a timestamp is STRING:
# extracted_value and required_value are deliberately strings so a JSONB scalar renders as "12"
# rather than a blob, and so a boolean rule value does not need a different column type.
COLUMNS = {
    "lease-poc-findings": [
        ("finding_id", "STRING"), ("sweep_id", "STRING"), ("as_of_date", "DATETIME"),
        ("lease_id", "STRING"), ("community", "STRING"), ("state", "STRING"),
        ("topic", "STRING"), ("rule_id", "STRING"), ("rule_version", "INTEGER"),
        ("rule_check", "STRING"), ("rule_citation", "STRING"),
        ("rule_effective_date", "DATETIME"), ("rule_approved_by", "STRING"),
        ("status", "STRING"), ("band", "STRING"), ("band_label", "STRING"),
        ("risk_score", "INTEGER"), ("extracted_value", "STRING"),
        ("required_value", "STRING"), ("comparison", "STRING"),
        ("clause_citation", "STRING"), ("clause_text", "STRING"),
        ("method", "STRING"), ("engine_version", "STRING"), ("created_at", "DATETIME"),
        ("is_latest_sweep", "STRING"),
    ],
    "lease-poc-receipt": [
        ("sweep_id", "STRING"), ("jurisdiction", "STRING"), ("topic", "STRING"),
        ("as_of_date", "DATETIME"), ("finished_at", "DATETIME"),
        ("leases_scanned", "INTEGER"), ("leases_evaluated", "INTEGER"),
        ("leases_compliant", "INTEGER"), ("leases_noncompliant", "INTEGER"),
        ("leases_ambiguous", "INTEGER"), ("leases_not_evaluated", "INTEGER"),
        ("findings_total", "INTEGER"), ("findings_noncompliant", "INTEGER"),
        ("findings_ambiguous", "INTEGER"),
        ("rules_applied", "INTEGER"), ("checks_run", "INTEGER"),
        ("population_basis", "STRING"), ("determination_method", "STRING"),
        ("completeness_check", "STRING"), ("is_latest_sweep", "STRING"),
    ],
    "lease-poc-not-evaluated": [
        ("sweep_id", "STRING"), ("as_of_date", "DATETIME"), ("lease_id", "STRING"),
        ("community", "STRING"), ("state", "STRING"), ("reason", "STRING"),
        ("status_label", "STRING"),
    ],
}


def status_report():
    try:
        v = qs.describe_vpc_connection(AwsAccountId=ACCOUNT, VPCConnectionId=VPC_CONNECTION_ID)
        log("vpc connection: %s / %s" % (v["VPCConnection"]["Status"],
                                         v["VPCConnection"]["AvailabilityStatus"]))
    except ClientError as exc:
        log("vpc connection: %s" % exc.response["Error"]["Code"])
    try:
        d = qs.describe_data_source(AwsAccountId=ACCOUNT, DataSourceId=DATA_SOURCE_ID)
        log("data source:    %s" % d["DataSource"]["Status"])
    except ClientError as exc:
        log("data source:    %s" % exc.response["Error"]["Code"])
    for dataset_id in DATASETS:
        try:
            qs.describe_data_set(AwsAccountId=ACCOUNT, DataSetId=dataset_id)
            log("dataset %-26s OK" % dataset_id)
        except ClientError as exc:
            log("dataset %-26s %s" % (dataset_id, exc.response["Error"]["Code"]))
    try:
        d = qs.describe_dashboard(AwsAccountId=ACCOUNT, DashboardId=DASHBOARD_ID)
        log("dashboard:      %s" % d["Dashboard"]["Version"]["Status"])
        log("  URL: https://%s.quicksight.aws.amazon.com/sn/dashboards/%s" % (REGION, DASHBOARD_ID))
    except ClientError as exc:
        log("dashboard:      %s" % exc.response["Error"]["Code"])


# ---------------------------------------------------------------------------------------------
# The dashboard itself.
#
# Created through the API rather than by hand, because the workflow claim is "ask in chat, click
# once, see every row". Requiring a user to copy a sweep_id out of a chat answer and assemble a
# table visual is not a workflow -- it is homework, and it would also mean every demo depends on
# somebody rebuilding the same thing the same way.
# ---------------------------------------------------------------------------------------------

DASHBOARD_ID = "lease-poc-findings-dashboard"
DASHBOARD_NAME = "Lease Compliance - Findings"


def _col(dataset_id, name):
    return {"DataSetIdentifier": dataset_id, "ColumnName": name}


def _string_field(field_id, dataset_id, name):
    """Build a field well entry whose type matches the declared column type.

    Quick Sight rejects a CategoricalDimensionField pointing at an INTEGER or DATETIME column, so
    the declared types in COLUMNS drive the choice. Keeping real types (rather than casting
    everything to text in SQL) means counts stay sortable and dates stay filterable by range --
    which matters for a receipt whose numbers a viewer will want to order and compare.
    """
    declared = dict(COLUMNS[dataset_id]).get(name, "STRING")
    if declared in ("INTEGER", "DECIMAL"):
        return {"NumericalDimensionField": {"FieldId": field_id,
                                            "Column": _col(dataset_id, name)}}
    if declared == "DATETIME":
        return {"DateDimensionField": {"FieldId": field_id,
                                       "Column": _col(dataset_id, name),
                                       "DateGranularity": "DAY"}}
    return {"CategoricalDimensionField": {"FieldId": field_id, "Column": _col(dataset_id, name)}}


def _table_visual(visual_id, title, subtitle, dataset_id, columns,
                  actions=None, wrap_cells=False, cell_height=26):
    """A plain table. Deliberately not a chart: the requirement is to see every row and drill in."""
    visual = {
        "TableVisual": {
            "VisualId": visual_id,
            "Title": {"Visibility": "VISIBLE",
                      "FormatText": {"PlainText": title}},
            "Subtitle": {"Visibility": "VISIBLE",
                         "FormatText": {"PlainText": subtitle}},
            "ChartConfiguration": {
                "FieldWells": {
                    "TableAggregatedFieldWells": {
                        "GroupBy": [_string_field("f_%s" % c, dataset_id, c) for c in columns]
                    }
                },
                "TableOptions": {
                    "HeaderStyle": {"TextWrap": "WRAP",
                                    "Height": 30},
                    "CellStyle": {"Height": cell_height,
                                  "TextWrap": "WRAP" if wrap_cells else "NONE"},
                },
                # Show the vertical overflow indicator: with 10,111 rows a viewer must be able to
                # see that there is more below, rather than assume the visible page is the answer.
                "PaginatedReportOptions": {"VerticalOverflowVisibility": "VISIBLE"},
            },
        }
    }
    if actions:
        visual["TableVisual"]["Actions"] = actions
    return visual


# The drill-down parameter. Clicking a row on the findings table sets this and navigates to the
# detail sheet, which is filtered by it -- so "see the detail for this row" is one click rather than
# scrolling a 17-column table sideways with the clause text truncated in a cell.
DRILL_PARAMETER = "SelectedFindingId"


def _drill_action():
    return [{
        "CustomActionId": "drill_to_detail",
        "Name": "View full evidence chain",
        "Status": "ENABLED",
        "Trigger": "DATA_POINT_CLICK",
        # Order is enforced by Quick Sight: NavigationOperation must come BEFORE
        # SetParametersOperation, otherwise creation fails.
        "ActionOperations": [
            {
                "NavigationOperation": {
                    "LocalNavigationConfiguration": {"TargetSheetId": "detail_sheet"}
                }
            },
            {
                "SetParametersOperation": {
                    "ParameterValueConfigurations": [{
                        "DestinationParameterName": DRILL_PARAMETER,
                        # SourceField takes the field id directly, not a nested object.
                        "Value": {"SourceField": "f_finding_id"},
                    }]
                }
            },
        ],
    }]


def dashboard_definition():
    findings = "lease-poc-findings"
    receipt = "lease-poc-receipt"
    not_eval = "lease-poc-not-evaluated"

    return {
        "DataSetIdentifierDeclarations": [
            {"Identifier": findings,
             "DataSetArn": "arn:aws:quicksight:%s:%s:dataset/%s" % (REGION, ACCOUNT, findings)},
            {"Identifier": receipt,
             "DataSetArn": "arn:aws:quicksight:%s:%s:dataset/%s" % (REGION, ACCOUNT, receipt)},
            {"Identifier": not_eval,
             "DataSetArn": "arn:aws:quicksight:%s:%s:dataset/%s" % (REGION, ACCOUNT, not_eval)},
        ],
        "Sheets": [
            {
                "SheetId": "receipt_sheet",
                "Name": "1. Completeness receipt",
                # The receipt sheet comes FIRST on purpose. A findings table read without its
                # denominator is just a list; the receipt is what makes it an answer.
                "Visuals": [
                    _table_visual(
                        "receipt_table",
                        "Completeness receipt - every lease accounted for",
                        "LEASE counts: scanned = compliant + noncompliant + ambiguous + not evaluated. "
                        "FINDING counts are larger when several rules apply, because a lease "
                        "breaching two rules yields two findings. Computed, not hand-written.",
                        receipt,
                        ["sweep_id", "topic", "as_of_date",
                         "leases_scanned", "leases_evaluated", "leases_compliant",
                         "leases_noncompliant", "leases_ambiguous", "leases_not_evaluated",
                         "completeness_check",
                         "rules_applied", "findings_total", "findings_noncompliant",
                         "findings_ambiguous"],
                    ),
                    _table_visual(
                        "not_eval_table",
                        "Not evaluated - documents that could not be read",
                        "Kept separate from findings on purpose: 'we could not tell' is a "
                        "different problem from 'this lease breaks a rule', with a different fix.",
                        not_eval,
                        ["lease_id", "community", "state", "reason"],
                    ),
                ],
            },
            {
                "SheetId": "findings_sheet",
                "Name": "2. All findings",
                "Visuals": [
                    _table_visual(
                        "findings_table",
                        "All findings with full evidence chain",
                        "One row per (lease, RULE) - a lease breaching two rules appears twice, so this row count is the FINDING count, not the lease count. Every column needed to defend the "
                        "determination is on the row. Citations are SYNTHETIC PLACEHOLDERS, "
                        "not verified law.",
                        findings,
                        ["finding_id", "lease_id", "community", "state", "band_label",
                         "rule_id", "rule_version", "rule_check", "extracted_value",
                         "required_value", "comparison", "clause_citation", "method"],
                        actions=_drill_action(),
                    ),
                ],
                # Filter controls so a viewer can slice without editing the analysis.
                "FilterControls": [
                    {
                        "Dropdown": {
                            "FilterControlId": "ctl_sweep",
                            "Title": "Sweep",
                            "SourceFilterId": "flt_latest",
                            "DisplayOptions": {"SelectAllOptions": {"Visibility": "VISIBLE"}},
                            "Type": "MULTI_SELECT",
                        }
                    },
                    {
                        "Dropdown": {
                            "FilterControlId": "ctl_band",
                            "Title": "Severity band",
                            "SourceFilterId": "flt_band",
                            "DisplayOptions": {"SelectAllOptions": {"Visibility": "VISIBLE"}},
                            "Type": "MULTI_SELECT",
                        }
                    },
                ],
            },
            {
                "SheetId": "detail_sheet",
                "Name": "3. Finding detail (drill-down)",
                # Split into three visuals rather than one wide row, because the point of a detail
                # view is that a reviewer can READ the evidence. A 17-column table with the clause
                # text truncated in a cell is not an evidence chain, it is a spreadsheet.
                "Visuals": [
                    _table_visual(
                        "detail_identity",
                        "Finding",
                        "Click any row on sheet 2 to load it here.",
                        findings,
                        ["finding_id", "lease_id", "community", "state", "band_label",
                         "risk_score", "sweep_id", "as_of_date"],
                    ),
                    _table_visual(
                        "detail_evidence",
                        "Evidence - the clause this determination rests on",
                        "Verbatim lease text and where it appears in the document.",
                        findings,
                        ["clause_citation", "clause_text"],
                        wrap_cells=True, cell_height=120,
                    ),
                    _table_visual(
                        "detail_rule",
                        "Rule applied, and how the determination was made",
                        "Rule version, its citation and approver, the values compared, and the "
                        "comparison performed. Citations are SYNTHETIC PLACEHOLDERS, not law.",
                        findings,
                        ["rule_id", "rule_version", "rule_check", "extracted_value",
                         "required_value", "comparison", "method", "engine_version",
                         "rule_effective_date", "rule_approved_by", "rule_citation"],
                        wrap_cells=True, cell_height=60,
                    ),
                ],
            },
        ],
        "ParameterDeclarations": [{
            "StringParameterDeclaration": {
                "Name": DRILL_PARAMETER,
                "ParameterValueType": "SINGLE_VALUED",
                # Empty default: before anything is clicked the detail sheet shows nothing rather
                # than an arbitrary finding, so it can never be mistaken for a selection the user
                # actually made.
                "DefaultValues": {"StaticValues": [""]},
            }
        }],
        "FilterGroups": [
            {
                # Binds the detail sheet to whichever row was clicked.
                "FilterGroupId": "fg_detail",
                "Filters": [{
                    "CategoryFilter": {
                        "FilterId": "flt_detail",
                        "Column": _col("lease-poc-findings", "finding_id"),
                        "Configuration": {
                            "CustomFilterConfiguration": {
                                "MatchOperator": "EQUALS",
                                "ParameterName": DRILL_PARAMETER,
                                "NullOption": "NON_NULLS_ONLY",
                            }
                        },
                    }
                }],
                "ScopeConfiguration": {
                    "SelectedSheets": {
                        "SheetVisualScopingConfigurations": [{
                            "SheetId": "detail_sheet",
                            "Scope": "ALL_VISUALS",
                        }]
                    }
                },
                "Status": "ENABLED",
                "CrossDataset": "SINGLE_DATASET",
            },
            {
                # Defaults to the newest sweep, so the dashboard opens on the sweep just run in
                # chat. Clearing the filter reveals history -- nothing is hidden, it is just not
                # the default.
                "FilterGroupId": "fg_latest",
                "Filters": [{
                    "CategoryFilter": {
                        "FilterId": "flt_latest",
                        "Column": _col("lease-poc-findings", "is_latest_sweep"),
                        "Configuration": {
                            "FilterListConfiguration": {
                                # CONTAINS, not EQUALS: QuickSight's FilterListConfiguration only
                                # accepts CONTAINS / DOES_NOT_CONTAIN.
                                "MatchOperator": "CONTAINS",
                                "CategoryValues": ["true"],
                            }
                        },
                    }
                }],
                "ScopeConfiguration": {
                    "SelectedSheets": {
                        "SheetVisualScopingConfigurations": [{
                            "SheetId": "findings_sheet",
                            "Scope": "ALL_VISUALS",
                        }]
                    }
                },
                "Status": "ENABLED",
                "CrossDataset": "SINGLE_DATASET",
            },
            {
                # The receipt sheet is pinned to the SAME single sweep as the findings table.
                # A receipt displayed beside rows it does not describe lends false authority to
                # the wrong number -- worse than showing no receipt at all.
                "FilterGroupId": "fg_receipt_latest",
                "Filters": [{
                    "CategoryFilter": {
                        "FilterId": "flt_receipt_latest",
                        "Column": _col("lease-poc-receipt", "is_latest_sweep"),
                        "Configuration": {
                            "FilterListConfiguration": {
                                "MatchOperator": "CONTAINS",
                                "CategoryValues": ["true"],
                            }
                        },
                    }
                }],
                "ScopeConfiguration": {
                    "SelectedSheets": {
                        "SheetVisualScopingConfigurations": [{
                            "SheetId": "receipt_sheet",
                            "Scope": "ALL_VISUALS",
                        }]
                    }
                },
                "Status": "ENABLED",
                "CrossDataset": "SINGLE_DATASET",
            },
            {
                "FilterGroupId": "fg_band",
                "Filters": [{
                    "CategoryFilter": {
                        "FilterId": "flt_band",
                        "Column": _col("lease-poc-findings", "band_label"),
                        "Configuration": {
                            "FilterListConfiguration": {
                                "MatchOperator": "CONTAINS",
                                "CategoryValues": ["Clear violation", "Probable violation (needs sign-off)", "Needs review (no structured value)"],
                                "NullOption": "ALL_VALUES",
                            }
                        },
                    }
                }],
                "ScopeConfiguration": {
                    "SelectedSheets": {
                        "SheetVisualScopingConfigurations": [{
                            "SheetId": "findings_sheet",
                            "Scope": "ALL_VISUALS",
                        }]
                    }
                },
                "Status": "ENABLED",
                "CrossDataset": "SINGLE_DATASET",
            },
        ],
    }


def ensure_dashboard():
    definition = dashboard_definition()
    permissions = [{
        "Principal": current_user_arn(),
        "Actions": [
            "quicksight:DescribeDashboard",
            "quicksight:ListDashboardVersions",
            "quicksight:QueryDashboard",
            "quicksight:UpdateDashboard",
            "quicksight:DeleteDashboard",
            "quicksight:DescribeDashboardPermissions",
            "quicksight:UpdateDashboardPermissions",
            "quicksight:UpdateDashboardPublishedVersion",
        ],
    }]
    try:
        resp = qs.create_dashboard(
            AwsAccountId=ACCOUNT, DashboardId=DASHBOARD_ID, Name=DASHBOARD_NAME,
            Definition=definition, Permissions=permissions)
        log("dashboard: created")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceExistsException":
            raise
        resp = qs.update_dashboard(
            AwsAccountId=ACCOUNT, DashboardId=DASHBOARD_ID, Name=DASHBOARD_NAME,
            Definition=definition)
        log("dashboard: updated")

    # Grant permissions on EVERY run, not only at create.
    #
    # `update_dashboard` takes no Permissions argument, so a dashboard whose first create attempt
    # failed server-side (leaving the resource present but unpermissioned) stays permanently
    # unopenable: every later run takes the update path and silently skips permissions. The symptom
    # is a "We can't open that dashboard / you don't have access permission" page while the API
    # reports the dashboard as CREATION_SUCCESSFUL -- nothing in the build output looks wrong.
    qs.update_dashboard_permissions(
        AwsAccountId=ACCOUNT, DashboardId=DASHBOARD_ID, GrantPermissions=permissions)
    log("dashboard: permissions granted to %s" % current_user_arn().rsplit("/", 1)[-1])

    # Poll the version JUST submitted, not the published one.
    #
    # describe_dashboard without VersionNumber returns the *published* version, so a fresh update
    # reports the previously published version's status and errors -- which reads as "my fix did
    # nothing" when in fact the new version was never inspected. Cost an entirely wasted debugging
    # cycle chasing an error message that belonged to an older version.
    new_version = int(resp["VersionArn"].rsplit("/", 1)[-1])

    for _ in range(30):
        time.sleep(5)
        d = qs.describe_dashboard(AwsAccountId=ACCOUNT, DashboardId=DASHBOARD_ID,
                                  VersionNumber=new_version)
        status = d["Dashboard"]["Version"]["Status"]
        if status == "CREATION_SUCCESSFUL" or status == "UPDATE_SUCCESSFUL":
            version = d["Dashboard"]["Version"]["VersionNumber"]
            try:
                qs.update_dashboard_published_version(
                    AwsAccountId=ACCOUNT, DashboardId=DASHBOARD_ID, VersionNumber=version)
            except ClientError:
                pass
            log("dashboard: %s (v%s)" % (status, version))
            log("  URL: https://%s.quicksight.aws.amazon.com/sn/dashboards/%s"
                % (REGION, DASHBOARD_ID))
            return
        if "FAILED" in status:
            raise SystemExit("dashboard failed: %s" % json.dumps(
                d["Dashboard"]["Version"].get("Errors", []), default=str))
    raise SystemExit("dashboard did not finish building")


if __name__ == "__main__":
    if "--status" in sys.argv:
        status_report()
        sys.exit(0)

    for dataset_id, spec in DATASETS.items():
        spec["columns"] = [{"Name": n, "Type": t} for n, t in COLUMNS[dataset_id]]

    ensure_vpc_connection()
    ensure_data_source()
    for dataset_id, spec in DATASETS.items():
        ensure_dataset(dataset_id, spec)

    ensure_dashboard()
