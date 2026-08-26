"""Determination engine: rules as data, translated to SQL.

The central discipline of this file: **the engine knows OPERATORS, never jurisdictions or topics.**
A law change is a rulebook row. Adding a rule is data; adding an operator is the only code change
permitted. There is no state-specific or topic-specific branch anywhere below, and if one ever
appears the design has been violated.

The second discipline: **no natural language reaches SQL.** Query text is assembled from a fixed
operator->template table and rule values are bound as parameters. Nothing a user typed and nothing
a model produced is ever concatenated into a statement. This is why completeness stays provable --
a hallucinated WHERE clause could silently narrow a population and nobody would know.
"""

import datetime
import json
import uuid

import db

ENGINE_VERSION = "0.1.0"

# --- operator -> SQL --------------------------------------------------------
#
# Each entry answers: "given this rule, which clauses VIOLATE it?"
# `%(field)s` is the rule's check_field, which is never user input -- it comes from the rulebook and
# is quoted into a JSONB key path, and is validated against KNOWN_FIELDS before use.
VIOLATION_SQL = {
    # numeric: value must be <= threshold, so a violation is value > threshold
    "lte": "(c.extracted->>:check_field)::numeric > (:check_value)::numeric",
    # numeric: value must be >= threshold, so a violation is value < threshold
    "gte": "(c.extracted->>:check_field)::numeric < (:check_value)::numeric",
    # exact match required; a violation is any other value
    "equals": "(c.extracted->>:check_field) <> (:check_value)::text",
    # presence required; absence is handled by the missing-field branch, so a present key never
    # violates `exists`
    "exists": "FALSE",
}

# A rule's check_field is data, but it still ends up in a JSONB key path, so it is allow-listed
# rather than trusted. A typo'd or malicious field name must fail loudly, not silently match zero
# rows -- zero rows would look like "no violations found", which is the worst possible failure.
KNOWN_FIELDS = frozenset({
    "late_fee_pct",
    "notice_period_days",
    "rent_increase_notice_days",
    "flood_disclosure_present",
    "notice_delivery_certified",
})


class RuleError(Exception):
    pass


def _predicate(operator, value_param):
    """Render a violation predicate against a named bind parameter.

    `simulate` needs the same comparison evaluated at two different values in one statement, so
    the operator template's `:check_value` is retargeted. Both arguments are internal -- the
    operator is a VIOLATION_SQL key and the parameter name is a literal in this module -- so no
    caller-supplied text reaches the statement.
    """
    return VIOLATION_SQL[operator].replace(":check_value", ":" + value_param)


# --- fully-built SQL, computed once at import time -------------------------
#
# Both statements below embed a per-operator predicate from VIOLATION_SQL. Rather than splice
# that predicate into a string at the call site (which is indistinguishable, to both a human
# skimming the diff and to a static scanner, from splicing in untrusted text), every variant is
# built once here, at import time, from the fixed VIOLATION_SQL table. sweep()/simulate() then
# do a plain dict lookup -- there is no string construction left to audit at the point of use.

_NONCOMPLIANT_SQL_TEMPLATE = """
    INSERT INTO findings (
        finding_id, sweep_id, lease_id, rule_id, rule_version, topic, as_of_date,
        status, band, risk_score, clause_text, clause_citation,
        extracted_value, required_value, method, comparison, engine_version)
    SELECT
        'F-' || substr(md5(:sweep_id || l.lease_id || :rule_id), 1, 12),
        :sweep_id, l.lease_id, :rule_id, :rule_version, :topic, CAST(:as_of AS DATE),
        'NONCOMPLIANT', 'clear_violation', :risk, c.text, c.citation,
        c.extracted, CAST(:required_value AS JSONB), 'deterministic',
        :check_field || ' (' || (c.extracted->>:check_field) || ') '
            || :operator_label || ' ' || (:check_value)::text || ' -> false',
        :engine_version
      FROM leases l
      JOIN clauses c ON c.lease_id = l.lease_id AND c.topic = :topic
     WHERE :jurisdiction LIKE l.jurisdiction || '%'
       AND l.readable
       AND c.extracted ? :check_field
       AND {violation}
    ON CONFLICT (finding_id) DO NOTHING
"""

NONCOMPLIANT_SQL_BY_OPERATOR = {
    op: _NONCOMPLIANT_SQL_TEMPLATE.format(violation=pred)
    for op, pred in VIOLATION_SQL.items()
}

_HAS_FIELD = "(c.clause_id IS NOT NULL AND c.extracted ? :check_field)"

_SIMULATE_SQL_TEMPLATE = """
    SELECT
      count(*)                                                         AS evaluated,
      count(*) FILTER (WHERE {has} AND {va})                           AS baseline_noncompliant,
      count(*) FILTER (WHERE {has} AND {vp})                           AS proposed_noncompliant,
      count(*) FILTER (WHERE {has} AND NOT ({va}) AND {vp})            AS newly_noncompliant,
      count(*) FILTER (WHERE {has} AND {va} AND NOT ({vp}))            AS newly_compliant,
      count(*) FILTER (WHERE NOT {has})                                AS no_value
      FROM leases l
      LEFT JOIN clauses c ON c.lease_id = l.lease_id AND c.topic = :topic
     WHERE :jurisdiction LIKE l.jurisdiction || '%'
       AND l.readable
"""

# simulate() needs the same predicate evaluated against two different bind-parameter names
# (approved_value, proposed_value) in one statement -- see _predicate.
SIMULATE_SQL_BY_OPERATOR = {
    op: _SIMULATE_SQL_TEMPLATE.format(
        has=_HAS_FIELD,
        va=_predicate(op, "approved_value"),
        vp=_predicate(op, "proposed_value"),
    )
    for op in VIOLATION_SQL
}


def _validate(rule):
    op = rule["check_operator"]
    if op not in VIOLATION_SQL:
        raise RuleError("unsupported operator %r in %s -- add it to VIOLATION_SQL, never a "
                        "jurisdiction branch" % (op, rule["rule_id"]))
    if rule["check_field"] not in KNOWN_FIELDS:
        raise RuleError("unknown check_field %r in %s" % (rule["check_field"], rule["rule_id"]))


def band_for(status, method):
    """status + how it was determined -> the categorical label a person sees.

    Raw scores never reach a user-facing surface; only these bands do.
    """
    if status == "NONCOMPLIANT":
        return "clear_violation" if method == "deterministic" else "probable"
    return "needs_review"


def sweep(jurisdiction, as_of_date, topic=None):
    """Run an official, exhaustive sweep. Returns (sweep_id, receipt, totals, rules).

    Every lease in the population lands in exactly one bucket:
      compliant | noncompliant | ambiguous | not_evaluated
    and the receipt is COMPUTED from count(*) queries, never assembled by hand. The invariant is
    asserted before the sweep is allowed to finish.
    """
    rules = db.resolve_rules(jurisdiction, topic, as_of_date)
    if not rules:
        raise RuleError("no rules in force for %s%s as of %s" % (
            jurisdiction, (" topic=%s" % topic) if topic else "", as_of_date))
    for r in rules:
        _validate(r)

    sweep_id = "SW-%s-%s" % (datetime.date.today().isoformat(), uuid.uuid4().hex[:6])
    db.execute(
        """
        INSERT INTO sweeps (sweep_id, jurisdiction, topic, as_of_date, rules_applied)
        VALUES (:sweep_id, :jurisdiction, :topic, CAST(:as_of AS DATE),
                CAST(:rules AS JSONB))
        """,
        {
            "sweep_id": sweep_id,
            "jurisdiction": jurisdiction,
            "topic": topic,
            "as_of": as_of_date,
            "rules": json.dumps([
                {"rule_id": r["rule_id"], "version": r["version"], "citation": r["citation"],
                 "check": "%s %s %s" % (r["check_field"], r["check_operator"], r["check_value"]),
                 "approved_by": r["approved_by"]}
                for r in rules
            ]),
        },
    )

    # --- population: EXACT filter, never similarity ---------------------------------------
    # `scanned` counts the whole population including unreadable leases. They are excluded from
    # `evaluated` and named individually, because a lease that was never checked must be reported
    # as unchecked -- silent omission is the failure this system exists to prevent.
    scanned = db.query(
        """
        SELECT count(*) AS n FROM leases
         WHERE :jurisdiction LIKE jurisdiction || '%'
        """,
        {"jurisdiction": jurisdiction},
    )[0]["n"]

    not_evaluated_rows = db.query(
        """
        SELECT lease_id, unreadable_reason
          FROM leases
         WHERE :jurisdiction LIKE jurisdiction || '%'
           AND NOT readable
         ORDER BY lease_id
        """,
        {"jurisdiction": jurisdiction},
    )

    evaluable = scanned - len(not_evaluated_rows)

    # --- one determination per (readable lease, rule) --------------------------------------
    checks_run = 0
    findings_written = 0
    per_rule = []

    for rule in rules:
        params = {
            "sweep_id": sweep_id,
            "jurisdiction": jurisdiction,
            "as_of": as_of_date,
            "rule_id": rule["rule_id"],
            "rule_version": rule["version"],
            "topic": rule["topic"],
            "check_field": rule["check_field"],
            "check_value": json.dumps(rule["check_value"]),
            "required_value": json.dumps({
                "field": rule["check_field"],
                "operator": rule["check_operator"],
                "value": rule["check_value"],
            }),
            "risk": rule["risk_weight"],
            "engine_version": ENGINE_VERSION,
        }

        # 1. NONCOMPLIANT via deterministic comparison: the value is present and breaches the rule.
        #    This is the deterministic-first discipline -- a numeric comparison answers it, so no
        #    model is involved and the finding is machine-final. The statement itself is a plain
        #    lookup into NONCOMPLIANT_SQL_BY_OPERATOR (built once at import time, above) -- no
        #    string assembly happens here.
        noncompliant_sql = NONCOMPLIANT_SQL_BY_OPERATOR[rule["check_operator"]]

        n_noncompliant = 0
        if rule["check_operator"] != "exists":
            p = dict(params, operator_label=rule["check_operator"])
            n_noncompliant = db.execute(noncompliant_sql, p)

        # 2. AMBIGUOUS: no structured value to compare, so a deterministic answer is impossible.
        #    Filed as a finding with status AMBIGUOUS -- counted and named, never assumed
        #    compliant. `on_missing_field` decides whether absence is instead a violation, so the
        #    rulebook owns that judgement, not the engine.
        #
        #    NOTE (declared deviation from the prototype): the prototype deep-checks these with
        #    Claude inline. At 50K scale inside Quick's fixed 60s tool budget that is not honest
        #    engineering, so they land in a counted bucket for review instead. See design.md.
        missing_is_violation = rule["on_missing_field"] == "noncompliant"
        ambiguous_status = "NONCOMPLIANT" if missing_is_violation else "AMBIGUOUS"
        ambiguous_band = "clear_violation" if missing_is_violation else "needs_review"
        ambiguous_comparison = (
            "required clause or value absent -> treated as violation per rule.on_missing_field"
            if missing_is_violation else
            "no extracted value for %s -> deterministic comparison impossible, needs deep check"
            % rule["check_field"]
        )

        # A lease with NO clause on this topic at all, or a clause missing the field.
        ambiguous_sql = """
            INSERT INTO findings (
                finding_id, sweep_id, lease_id, rule_id, rule_version, topic, as_of_date,
                status, band, risk_score, clause_text, clause_citation,
                extracted_value, required_value, method, comparison, engine_version)
            SELECT
                'F-' || substr(md5(:sweep_id || l.lease_id || :rule_id), 1, 12),
                :sweep_id, l.lease_id, :rule_id, :rule_version, :topic, CAST(:as_of AS DATE),
                :status, :band, :risk, c.text, c.citation,
                COALESCE(c.extracted, '{}'::jsonb), CAST(:required_value AS JSONB),
                'deterministic', :comparison, :engine_version
              FROM leases l
              LEFT JOIN clauses c ON c.lease_id = l.lease_id AND c.topic = :topic
             WHERE :jurisdiction LIKE l.jurisdiction || '%'
               AND l.readable
               AND (c.clause_id IS NULL OR NOT (c.extracted ? :check_field))
            ON CONFLICT (finding_id) DO NOTHING
        """
        n_ambiguous = db.execute(ambiguous_sql, dict(
            params, status=ambiguous_status, band=ambiguous_band,
            comparison=ambiguous_comparison))

        # 3. COMPLIANT is the remainder. Counted, not filed: a finding is an exception record.
        n_evaluated_for_rule = db.query(
            """
            SELECT count(*) AS n
              FROM leases l
             WHERE :jurisdiction LIKE l.jurisdiction || '%'
               AND l.readable
            """,
            {"jurisdiction": jurisdiction},
        )[0]["n"]
        n_compliant = n_evaluated_for_rule - n_noncompliant - n_ambiguous

        checks_run += n_evaluated_for_rule
        findings_written += n_noncompliant + n_ambiguous
        per_rule.append({
            "rule_id": rule["rule_id"],
            "version": rule["version"],
            "citation": rule["citation"],
            "check": "%s %s %s" % (rule["check_field"], rule["check_operator"],
                                   rule["check_value"]),
            "approved_by": rule["approved_by"],
            "checked": n_evaluated_for_rule,
            "noncompliant": n_noncompliant,
            "ambiguous": n_ambiguous,
            "compliant": n_compliant,
        })

    # --- receipt: computed, then asserted ---------------------------------------------------
    lease_buckets = db.query(
        """
        SELECT
          count(*) FILTER (WHERE f.worst = 'NONCOMPLIANT')                  AS noncompliant,
          count(*) FILTER (WHERE f.worst = 'AMBIGUOUS')                     AS ambiguous
          FROM (
            SELECT lease_id,
                   CASE WHEN bool_or(status = 'NONCOMPLIANT') THEN 'NONCOMPLIANT'
                        ELSE 'AMBIGUOUS' END AS worst
              FROM findings
             WHERE sweep_id = :sweep_id
             GROUP BY lease_id
          ) f
        """,
        {"sweep_id": sweep_id},
    )[0]

    noncompliant_leases = lease_buckets["noncompliant"] or 0
    ambiguous_leases = lease_buckets["ambiguous"] or 0
    compliant_leases = evaluable - noncompliant_leases - ambiguous_leases

    receipt = {
        "population_basis": "exact_filter" if topic else "exact_filter_all_rules",
        "jurisdiction": jurisdiction,
        "topic": topic,
        "as_of_date": as_of_date,
        "scanned": scanned,
        "evaluated": evaluable,
        "compliant": compliant_leases,
        "noncompliant": noncompliant_leases,
        "ambiguous": ambiguous_leases,
        "not_evaluated": [
            {"lease_id": r["lease_id"], "reason": r["unreadable_reason"]}
            for r in not_evaluated_rows
        ],
        "not_evaluated_count": len(not_evaluated_rows),
        "rules_applied": len(rules),
        "checks_run": checks_run,
        "findings_written": findings_written,
        "determination_method": "deterministic (no model was consulted for any determination)",
    }

    # The invariant, asserted rather than assumed. Every lease is accounted for exactly once.
    total = receipt["compliant"] + receipt["noncompliant"] + receipt["ambiguous"] \
        + receipt["not_evaluated_count"]
    if total != scanned:
        raise RuleError(
            "receipt invariant violated: compliant(%d) + noncompliant(%d) + ambiguous(%d) + "
            "not_evaluated(%d) = %d != scanned(%d)" % (
                receipt["compliant"], receipt["noncompliant"], receipt["ambiguous"],
                receipt["not_evaluated_count"], total, scanned))

    db.execute(
        """
        UPDATE sweeps SET finished_at = now(), receipt = CAST(:receipt AS JSONB)
         WHERE sweep_id = :sweep_id
        """,
        {"sweep_id": sweep_id, "receipt": json.dumps(receipt)},
    )

    return sweep_id, receipt, per_rule, rules


def simulate(jurisdiction, as_of_date, rule_id, proposed_value):
    """What-if: evaluate one rule at a PROPOSED value against the approved rulebook baseline.

    Ported from the prototype's `threshold_override` path, and it writes NOTHING -- no sweep row,
    no findings, no ids. A proposed value has no `approved_by`, no `effective_date` and no
    citation, so a determination made against it is not a determination at all. That is why this
    is a separate function rather than a parameter on `sweep`: the write is structurally absent,
    not conditionally skipped.

    Two disciplines carried over from the prototype, both of which cost it a defect:

      1. **The override targets ONE named rule.** Rules are measured in days, percent and yes/no,
         so a bare number applied across a rule set is meaningless. `rule_id` is required.
      2. **Counts, not rows.** The sweep derives its counts from `numberOfRecordsUpdated` on the
         INSERTs, which cannot work here. The same operator templates are evaluated as
         `count(*) FILTER (...)` instead, so the comparison logic is shared rather than
         reimplemented -- a second implementation of the predicate could drift from the first and
         nobody would notice.

    Returns (result, rule) where result carries the baseline, the proposed outcome, and the
    directional deltas.
    """
    rules = db.resolve_rules(jurisdiction, None, as_of_date)
    if not rules:
        raise RuleError("no rules in force for %s as of %s" % (jurisdiction, as_of_date))

    target = None
    for r in rules:
        if r["rule_id"] == rule_id:
            target = r
            break
    if target is None:
        raise RuleError(
            "rule %r is not in force for %s as of %s. Rules in force: %s"
            % (rule_id, jurisdiction, as_of_date,
               ", ".join("%s (%s %s %s)" % (r["rule_id"], r["check_field"], r["check_operator"],
                                            r["check_value"]) for r in rules)))
    _validate(target)

    if target["check_operator"] == "exists":
        # A presence requirement has no threshold to move. Simulating one would mean inventing a
        # comparison the rule does not make, which is exactly the kind of quiet fabrication the
        # mode label is meant to prevent.
        raise RuleError(
            "%s is a presence requirement (%s exists), so there is no threshold to simulate. "
            "A what-if only applies to rules that compare a value."
            % (rule_id, target["check_field"]))

    approved_value = target["check_value"]
    if str(proposed_value) == str(approved_value):
        raise RuleError(
            "proposed value %s is identical to the approved value for %s, so there is nothing to "
            "simulate. Use sweep_compliance for the official answer."
            % (proposed_value, rule_id))

    topic = target["topic"]
    field = target["check_field"]
    op = target["check_operator"]

    scanned = db.query(
        "SELECT count(*) AS n FROM leases WHERE :jurisdiction LIKE jurisdiction || '%'",
        {"jurisdiction": jurisdiction},
    )[0]["n"]

    not_evaluated_rows = db.query(
        """
        SELECT lease_id, unreadable_reason
          FROM leases
         WHERE :jurisdiction LIKE jurisdiction || '%'
           AND NOT readable
         ORDER BY lease_id
        """,
        {"jurisdiction": jurisdiction},
    )

    # One statement, both scenarios. Evaluating them together is what makes the directional
    # counts trustworthy: "newly noncompliant" is computed per lease, not inferred by subtracting
    # two independent totals (which would be wrong the moment a change moves leases both ways).
    # The statement is a plain lookup into SIMULATE_SQL_BY_OPERATOR (built once at import time,
    # above) -- no string assembly happens here.
    sql = SIMULATE_SQL_BY_OPERATOR[op]

    row = db.query(sql, {
        "jurisdiction": jurisdiction,
        "topic": topic,
        "check_field": field,
        "approved_value": json.dumps(approved_value),
        "proposed_value": json.dumps(proposed_value),
    })[0]

    evaluated = row["evaluated"]
    no_value = row["no_value"]

    # The rulebook owns what absence means, here as in the sweep. If absence is itself a
    # violation, those leases are noncompliant under both values and the change does not move
    # them -- so they belong in both totals, not in a separate bucket.
    missing_is_violation = target["on_missing_field"] == "noncompliant"
    baseline_nc = row["baseline_noncompliant"] + (no_value if missing_is_violation else 0)
    proposed_nc = row["proposed_noncompliant"] + (no_value if missing_is_violation else 0)
    ambiguous = 0 if missing_is_violation else no_value

    receipt = {
        "population_basis": "exact_filter",
        "jurisdiction": jurisdiction,
        "topic": topic,
        "as_of_date": as_of_date,
        "scanned": scanned,
        "evaluated": evaluated,
        "compliant": evaluated - proposed_nc - ambiguous,
        "noncompliant": proposed_nc,
        "ambiguous": ambiguous,
        "not_evaluated": [
            {"lease_id": r["lease_id"], "reason": r["unreadable_reason"]}
            for r in not_evaluated_rows
        ],
        "not_evaluated_count": len(not_evaluated_rows),
        "rules_applied": 1,
        "checks_run": evaluated,
        "determination_method": (
            "simulated (deterministic comparison against an UNAPPROVED value; no model consulted)"
        ),
        "receipt_scope": (
            "This receipt describes the SIMULATED scenario only, for rule %s alone. Other rules "
            "in force were not evaluated." % rule_id
        ),
    }

    # The same invariant as an official sweep. A simulation that cannot account for its whole
    # population is not a weaker answer, it is a wrong one.
    total = (receipt["compliant"] + receipt["noncompliant"] + receipt["ambiguous"]
             + receipt["not_evaluated_count"])
    if total != scanned:
        raise RuleError(
            "simulation receipt invariant violated: compliant(%d) + noncompliant(%d) + "
            "ambiguous(%d) + not_evaluated(%d) = %d != scanned(%d)"
            % (receipt["compliant"], receipt["noncompliant"], receipt["ambiguous"],
               receipt["not_evaluated_count"], total, scanned))

    result = {
        "rule_id": rule_id,
        "rule_version_simulated_from": target["version"],
        "check_field": field,
        "check_operator": target["check_operator"],
        "approved_value": approved_value,
        "proposed_value": proposed_value,
        "baseline_noncompliant": baseline_nc,
        "proposed_noncompliant": proposed_nc,
        "net_change": proposed_nc - baseline_nc,
        "newly_noncompliant": row["newly_noncompliant"],
        "newly_compliant": row["newly_compliant"],
        "unchanged_ambiguous": ambiguous,
        "receipt": receipt,
        "engine_version": ENGINE_VERSION,
    }
    return result, target


CLAUSE_PREVIEW_CHARS = 400


def preview(sweep_id, limit_noncompliant=15, limit_ambiguous=5):
    """A STRATIFIED sample of findings for the chat answer, with the clause text.

    Two deliberate changes from a single severity-ordered LIMIT 20, both prompted by the customer
    asking that results carry enough context to review what was assessed:

      1. **Guaranteed slots per status.** Ordering by severity and taking 20 returned 20
         noncompliant rows and zero ambiguous ones, because there are 10,111 of the former. The
         689 leases that actually need a human were invisible in the chat answer -- present only
         as a number. Two bounded queries guarantee both groups appear; a blended ORDER BY only
         hopes they will.
      2. **The clause text travels.** For a noncompliant row `comparison` is self-explanatory
         ("late_fee_pct (12) lte 5 -> false"). For an ambiguous row it reads "no extracted value
         ... comparison impossible", which explains the mechanism and none of the substance. The
         reviewable content IS the vague wording -- "a reasonable late charge as determined by
         Landlord" -- so without it an ambiguous row cannot be reviewed at all.

    Truncated at CLAUSE_PREVIEW_CHARS with the true length reported alongside: synthetic clauses
    are one sentence, real ones will not be, and a preview must not become the payload's bulk.

    NOTE the sampling is now stratified, so the RATIO of statuses here is an artefact of the
    limits, not a property of the population. Callers must take proportions from the receipt.
    """
    def rows(status, limit):
        return db.query(
            """
            SELECT f.finding_id, f.lease_id, l.community, l.state, f.rule_id, f.rule_version,
                   f.status, f.band, f.risk_score, f.comparison, f.clause_citation,
                   -- (:chars)::int is required, not cosmetic: the Data API binds a Python int as
                   -- bigint and there is no left(text, bigint), so this fails at runtime without
                   -- the cast. Same reason the rule comparisons cast (:check_value)::numeric.
                   left(COALESCE(f.clause_text, ''), (:chars)::int) AS clause_text,
                   length(COALESCE(f.clause_text, ''))             AS clause_text_full_length
              FROM findings f JOIN leases l USING (lease_id)
             WHERE f.sweep_id = :sweep_id
               AND f.status = :status
             ORDER BY f.risk_score DESC, f.lease_id
             LIMIT :limit
            """,
            {"sweep_id": sweep_id, "status": status, "limit": limit,
             "chars": CLAUSE_PREVIEW_CHARS},
        )

    out = rows("NONCOMPLIANT", limit_noncompliant) + rows("AMBIGUOUS", limit_ambiguous)
    for r in out:
        if r["clause_text_full_length"] > CLAUSE_PREVIEW_CHARS:
            r["clause_text"] = r["clause_text"] + "... [truncated]"
        # Say what the row is FOR. An ambiguous row in a list of violations reads as a weaker
        # violation unless it is told apart explicitly.
        r["row_meaning"] = (
            "machine-final: a deterministic comparison failed"
            if r["status"] == "NONCOMPLIANT" else
            "NOT a violation: no comparable value in the clause, so no determination was possible "
            "and a human must read it"
        )
    return out


def violation_spread(sweep_id):
    """Aggregate statistics over EVERY violating finding in a sweep, per rule.

    Exists because a summarising model will characterise a population from whatever it was given:
    handed a 20-row preview, Quick reported that violations "range from 6% to 15%" as a fact about
    all 10,111 findings. The claim was true by luck. Supplying real aggregates is the honest fix --
    telling a model not to generalise is less reliable than giving it the number.

    Only numeric findings contribute; presence-based rules (`exists`) have no spread.
    """
    rows = db.query(
        """
        SELECT f.rule_id,
               f.rule_version,
               r.check_field,
               count(*)                                             AS findings,
               min((f.extracted_value->>r.check_field)::numeric)     AS min_value,
               max((f.extracted_value->>r.check_field)::numeric)     AS max_value,
               round(avg((f.extracted_value->>r.check_field)::numeric), 2) AS avg_value,
               r.check_value                                        AS required_value
          FROM findings f
          JOIN rulebook r ON r.rule_id = f.rule_id AND r.version = f.rule_version
         WHERE f.sweep_id = :sweep_id
           AND f.status = 'NONCOMPLIANT'
           AND f.extracted_value ? r.check_field
         GROUP BY f.rule_id, f.rule_version, r.check_field, r.check_value
         ORDER BY f.rule_id
        """,
        {"sweep_id": sweep_id},
    )
    return {
        "basis": "computed over every noncompliant finding in this sweep, not the preview sample",
        "by_rule": rows,
    }
