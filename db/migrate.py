"""Create the schema and seed the rulebook. Idempotent -- safe to re-run.

Run from the quick-poc directory:
    .venv/bin/python db/migrate.py
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "mcp_server"))

HERE = os.path.dirname(os.path.abspath(__file__))

# Views are dropped before recreation (see apply_views). Each statement is fully literal, one per
# view name -- there is no runtime string interpolation, only a lookup into this fixed table.
DROP_VIEW_SQL = {
    "v_sweep_receipt": "DROP VIEW IF EXISTS v_sweep_receipt CASCADE",
    "v_not_evaluated": "DROP VIEW IF EXISTS v_not_evaluated CASCADE",
    "v_findings": "DROP VIEW IF EXISTS v_findings CASCADE",
    "v_latest_sweep": "DROP VIEW IF EXISTS v_latest_sweep CASCADE",
}


def load_outputs():
    """Pull cluster/secret ARNs from the CDK outputs file into the environment."""
    with open(os.path.join(HERE, "..", "outputs.json")) as f:
        out = json.load(f)["QuickPocStack"]
    os.environ.setdefault("DB_CLUSTER_ARN", out["DbClusterArn"])
    os.environ.setdefault("DB_SECRET_ARN", out["DbSecretArn"])
    os.environ.setdefault("DB_NAME", out["DbName"])
    return out


load_outputs()
import db  # noqa: E402  (import after env is populated)


def apply_schema():
    with open(os.path.join(HERE, "schema.sql")) as f:
        sql = f.read()

    # The Data API runs one statement per call, so the file has to be split.
    #
    # Comments are stripped BEFORE splitting: a `--` comment containing a semicolon (there is one:
    # "...(jurisdiction, readable); this covers it") otherwise splits a statement in half and the
    # first fragment fails with "syntax error at end of input". Safe here because the schema has
    # no function bodies or dollar-quoted strings.
    lines = []
    for line in sql.splitlines():
        stripped = line.strip()
        if stripped.startswith("--"):
            continue
        # Also drop trailing comments on code lines.
        if "--" in line:
            line = line.split("--", 1)[0]
        if line.strip():
            lines.append(line)

    statements = [s.strip() for s in "\n".join(lines).split(";") if s.strip()]
    for stmt in statements:
        db.execute(stmt)
    print("schema: %d statements applied" % len(statements))


def seed_rulebook():
    with open(os.path.join(HERE, "rulebook.json")) as f:
        book = json.load(f)

    rules = book["rules"]

    # Rules are never edited in place, so seeding is insert-if-absent on (rule_id, version).
    # A re-run must not silently rewrite an approved rule: ON CONFLICT DO NOTHING makes that
    # structural rather than a matter of discipline.
    sql = """
        INSERT INTO rulebook (
            rule_id, version, jurisdiction, topic,
            check_field, check_operator, check_value, on_missing_field,
            citation, effective_date, approved_by, approved_date,
            risk_weight, qualitative_prompt
        ) VALUES (
            :rule_id, :version, :jurisdiction, :topic,
            :check_field, :check_operator, CAST(:check_value AS JSONB), :on_missing_field,
            :citation, CAST(:effective_date AS DATE), :approved_by, CAST(:approved_date AS DATE),
            :risk_weight, :qualitative_prompt
        )
        ON CONFLICT (rule_id, version) DO NOTHING
    """

    param_sets = []
    for r in rules:
        check = r["check"]
        param_sets.append({
            "rule_id": r["rule_id"],
            "version": r["version"],
            "jurisdiction": r["jurisdiction"],
            "topic": r["topic"],
            "check_field": check["field"],
            "check_operator": check["operator"],
            # `exists` carries no comparison value.
            "check_value": json.dumps(check.get("value")) if "value" in check else None,
            "on_missing_field": r.get("on_missing_field", "ambiguous"),
            "citation": r["citation"],
            "effective_date": r["effective_date"],
            "approved_by": r["approved_by"],
            "approved_date": r["approved_date"],
            "risk_weight": r.get("risk_weight", 50),
            "qualitative_prompt": r.get("qualitative_prompt"),
        })

    db.batch_execute(sql, param_sets)
    total = db.query("SELECT count(*) AS n FROM rulebook")[0]["n"]
    print("rulebook: %d rules in file, %d rows in table" % (len(rules), total))
    return len(rules), total


def verify():
    """Task 3 done-check: rules come back, and versions resolve correctly by as-of date."""
    failures = []

    def check(label, ok, detail=""):
        print("%s %s%s" % ("PASS" if ok else "FAIL", label, (" -- %s" % detail) if detail else ""))
        if not ok:
            failures.append(label)

    check("pgvector extension present",
          bool(db.query("SELECT 1 AS ok FROM pg_extension WHERE extname = 'vector'")))

    tables = {r["table_name"] for r in db.query(
        "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'")}
    expected = {"leases", "clauses", "rulebook", "sweeps", "findings"}
    check("all five tables exist", expected <= tables, ", ".join(sorted(expected - tables)) or "ok")

    # The point-in-time property: the SAME question resolves a DIFFERENT rule version by date.
    # TX-LATEFEE-CAP is v1 (12% cap) until 2026-01-01, v2 (5% cap) from then on.
    old = db.resolve_rules("US/TX", "late_fees", "2025-06-01")
    new = db.resolve_rules("US/TX", "late_fees", "2026-07-31")
    old_v = [(r["rule_id"], r["version"], r["check_value"]) for r in old]
    new_v = [(r["rule_id"], r["version"], r["check_value"]) for r in new]
    check("as-of 2025-06-01 resolves TX-LATEFEE-CAP v1 (12%)",
          old_v == [("TX-LATEFEE-CAP", 1, 12)], str(old_v))
    check("as-of 2026-07-31 resolves TX-LATEFEE-CAP v2 (5%)",
          new_v == [("TX-LATEFEE-CAP", 2, 5)], str(new_v))

    # Resolution must return a LIST of co-existing rules, one winning version each -- never one
    # rule per topic. TX has three distinct rule_ids in force across all topics.
    all_tx = db.resolve_rules("US/TX", None, "2026-07-31")
    ids = sorted(r["rule_id"] for r in all_tx)
    check("all-topics resolution returns every rule in force, one version each",
          ids == ["TX-EVICT-NOTICE", "TX-LATEFEE-CAP", "TX-RENTINC-NOTICE"], str(ids))

    # A future-dated rule must not leak into an earlier answer.
    check("no rule resolves before its effective date",
          all(str(r["effective_date"]) <= "2025-06-01" for r in old),
          str([str(r["effective_date"]) for r in old]))

    states = db.query("SELECT DISTINCT jurisdiction FROM rulebook ORDER BY jurisdiction")
    check("8 state jurisdictions authored", len(states) == 8,
          ", ".join(s["jurisdiction"] for s in states))

    print("\n%d/%d schema checks pass" % (7 - len(failures), 7))
    return not failures


def apply_views():
    """Presentation views for the Quick Sight dashboard."""
    with open(os.path.join(HERE, "views.sql")) as f:
        sql = f.read()

    lines = []
    for line in sql.splitlines():
        stripped = line.strip()
        if stripped.startswith("--"):
            continue
        if "--" in line:
            line = line.split("--", 1)[0]
        if line.strip():
            lines.append(line)

    # Drop first, then create.
    #
    # CREATE OR REPLACE VIEW only permits ADDING columns at the end of the select list -- inserting
    # one in the middle leaves the previous definition in place, and the migration reports success.
    # A schema change that silently does nothing is worse than one that fails, so views are dropped
    # explicitly. CASCADE because v_findings and v_sweep_receipt depend on v_latest_sweep.
    # Fully literal statements, one per view, built once at import time (see DROP_VIEW_SQL below)
    # rather than assembled at the call site -- there is no string interpolation left to audit
    # here, only a lookup into a fixed, finite table.
    for view in ("v_sweep_receipt", "v_not_evaluated", "v_findings", "v_latest_sweep"):
        db.execute(DROP_VIEW_SQL[view])

    statements = [s.strip() for s in "\n".join(lines).split(";") if s.strip()]
    for stmt in statements:
        db.execute(stmt)
    print("views: %d dropped and recreated" % len(statements))


if __name__ == "__main__":
    apply_schema()
    seed_rulebook()
    apply_views()
    print()
    sys.exit(0 if verify() else 1)
