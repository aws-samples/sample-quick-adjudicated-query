"""RDS Data API access + rule resolution.

boto3 only: no pg driver, no VPC attachment for the Lambda, no ENI cold start. Shared by the MCP
server and the local ingest/migration scripts so there is exactly one place that knows how to
talk to the database and exactly one implementation of rule resolution.
"""

import json
import logging
import os
import time

import boto3

logger = logging.getLogger()

_client = None


def client():
    global _client
    if _client is None:
        _client = boto3.client("rds-data", region_name=os.environ.get("AWS_REGION", "us-east-1"))
    return _client


def _param(name, value):
    """Convert a Python value to a Data API parameter.

    Everything the engine sends is bound as a parameter -- rule values, jurisdictions, dates. SQL
    text is only ever assembled from rulebook OPERATORS via a fixed template table, never from
    caller input, so there is no path by which user or model text reaches a query string.
    """
    if value is None:
        return {"name": name, "value": {"isNull": True}}
    if isinstance(value, bool):
        return {"name": name, "value": {"booleanValue": value}}
    if isinstance(value, int):
        return {"name": name, "value": {"longValue": value}}
    if isinstance(value, float):
        return {"name": name, "value": {"doubleValue": value}}
    if isinstance(value, (dict, list)):
        return {"name": name, "value": {"stringValue": json.dumps(value)}, "typeHint": "JSON"}
    return {"name": name, "value": {"stringValue": str(value)}}


# Columns stored as JSONB. Values from these are decoded on read.
_JSON_COLUMNS = frozenset({
    "extracted", "check_value", "receipt", "rules_applied",
    "extracted_value", "required_value",
})


def _unwrap(field):
    for key in ("stringValue", "longValue", "doubleValue", "booleanValue"):
        if key in field:
            return field[key]
    if field.get("isNull"):
        return None
    if "arrayValue" in field:
        return field["arrayValue"]
    return None


def _call_with_resume_retry(fn, **kwargs):
    """Invoke a Data API operation, waiting out an Aurora Serverless v2 resume.

    A cluster scaled to zero ACU auto-pauses when idle, and the first call after that fails with
    DatabaseResumingException while it wakes. Left unhandled this surfaces mid-demo as an error on
    the very first question of a session -- the worst possible moment -- so the wait is absorbed
    here instead.

    Budget is deliberately capped near 40s: Quick's MCP timeout is a hard 60s, so it is better to
    fail with a clear message and let the caller retry than to be cut off at the transport layer
    with no explanation.
    """
    delay, waited = 1.0, 0.0
    while True:
        try:
            return fn(**kwargs)
        except Exception as exc:
            name = type(exc).__name__
            resuming = (
                "DatabaseResuming" in name
                or "DatabaseResuming" in str(exc)
                or "resuming after being auto-paused" in str(exc)
            )
            if not resuming or waited >= 40:
                raise
            logger.info("Aurora is resuming; waited %.0fs, retrying in %.0fs", waited, delay)
            time.sleep(delay)
            waited += delay
            delay = min(delay * 1.6, 8.0)


def query(sql, params=None, database=None):
    """Run one statement, return a list of dicts."""
    kwargs = {
        "resourceArn": os.environ["DB_CLUSTER_ARN"],
        "secretArn": os.environ["DB_SECRET_ARN"],
        "database": database or os.environ.get("DB_NAME", "leases"),
        "sql": sql,
        "includeResultMetadata": True,
    }
    if params:
        kwargs["parameters"] = [_param(k, v) for k, v in params.items()]

    resp = _call_with_resume_retry(client().execute_statement, **kwargs)
    cols = [c["name"] for c in resp.get("columnMetadata", [])]
    rows = []
    for record in resp.get("records", []):
        row = {}
        for name, field in zip(cols, record):
            val = _unwrap(field)
            # JSONB columns arrive as strings and must be decoded, INCLUDING scalars: a rule's
            # check_value of 12 comes back as the string "12", and the engine needs the number to
            # compare against. Decoding only objects and arrays leaves every numeric rule bound as
            # text, which Postgres would then compare lexically -- "9" > "12".
            if isinstance(val, str) and name in _JSON_COLUMNS:
                try:
                    val = json.loads(val)
                except ValueError:
                    pass
            row[name] = val
        rows.append(row)
    return rows


def execute(sql, params=None, database=None):
    """Run one statement, return the number of rows affected."""
    kwargs = {
        "resourceArn": os.environ["DB_CLUSTER_ARN"],
        "secretArn": os.environ["DB_SECRET_ARN"],
        "database": database or os.environ.get("DB_NAME", "leases"),
        "sql": sql,
    }
    if params:
        kwargs["parameters"] = [_param(k, v) for k, v in params.items()]
    resp = _call_with_resume_retry(client().execute_statement, **kwargs)
    return resp.get("numberOfRecordsUpdated", 0)


def batch_execute(sql, param_sets, database=None):
    """Run one statement against many parameter sets (ingest path)."""
    total = 0
    # The Data API caps a batch; 100 keeps well clear and keeps error messages legible.
    for i in range(0, len(param_sets), 100):
        chunk = param_sets[i:i + 100]
        _call_with_resume_retry(
            client().batch_execute_statement,
            resourceArn=os.environ["DB_CLUSTER_ARN"],
            secretArn=os.environ["DB_SECRET_ARN"],
            database=database or os.environ.get("DB_NAME", "leases"),
            sql=sql,
            parameterSets=[[_param(k, v) for k, v in ps.items()] for ps in chunk],
        )
        total += len(chunk)
    return total


# --- rule resolution -------------------------------------------------------
#
# Ported from working-prototype/engine.py, including the lesson that cost a defect there:
# resolution returns a LIST, never a single rule.


def resolve_rules(jurisdiction, topic, as_of_date):
    """Every rule in force for a jurisdiction at a date, one winning version per rule_id.

    Two distinct rule_ids may share a topic -- they are independent obligations that happen to
    live in the same lease paragraph. Collapsing version selection and rule selection into one
    step silently drops the second rule, with no error and no receipt entry. That is the exact
    failure this system exists to prevent, so:

      1. filter by jurisdiction path + effective_date <= as_of  (+ topic, if narrowing)
      2. group by rule_id
      3. keep the winning version WITHIN each group (latest effective_date, then highest version)
      4. return EVERY surviving rule_id
    """
    sql = """
        SELECT DISTINCT ON (rule_id)
               rule_id, version, jurisdiction, topic,
               check_field, check_operator, check_value, on_missing_field,
               citation, effective_date, approved_by, risk_weight, qualitative_prompt
          FROM rulebook
         WHERE :jurisdiction LIKE jurisdiction || '%'
           AND effective_date <= CAST(:as_of AS DATE)
    """
    params = {"jurisdiction": jurisdiction, "as_of": as_of_date}
    if topic:
        sql += " AND topic = :topic"
        params["topic"] = topic
    # DISTINCT ON keeps the first row per rule_id under this ordering: most specific jurisdiction
    # path first, then latest effective date, then highest version.
    sql += """
         ORDER BY rule_id,
                  length(jurisdiction) DESC,
                  effective_date DESC,
                  version DESC
    """
    return query(sql, params)
