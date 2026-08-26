-- Presentation views for the Quick Sight dashboard.
--
-- The dashboard is where "show me all 10,111 rows, and let me drill into any one of them" is
-- answered. The chat response deliberately carries only counts, the receipt, and a 20-row sample:
-- a conversational answer must never be mistakable for the full record.
--
-- Idempotent: safe to re-run.

-- --------------------------------------------------------------------------------------------
-- v_latest_sweep: the most recent finished sweep per (jurisdiction, topic, as_of_date).
--
-- Exists so the dashboard can default to "the sweep you just ran" instead of requiring anyone to
-- copy a sweep_id out of a chat answer and paste it into a filter. Asking a question and then
-- doing clerical work to see the answer is not a workflow.
-- --------------------------------------------------------------------------------------------
-- EXACTLY ONE sweep: the single most recently finished one.
--
-- The first version of this view returned the latest sweep per (jurisdiction, topic, as_of_date),
-- which is a different thing entirely. Three legitimate sweeps -- TX all-topics, TX late-fees
-- as-of-2026, TX late-fees as-of-2025 -- were all "latest" by that definition, so the dashboard
-- showed 29,045 rows: the union of three populations evaluated under different rules on different
-- dates. Nothing on screen said so, and 29,045 corresponds to no receipt anywhere.
--
-- That is precisely the failure this system exists to prevent: a number that looks authoritative,
-- reconciles with nothing, and misleads silently. A findings table must always show ONE sweep,
-- because a sweep is the unit that has a receipt.
CREATE OR REPLACE VIEW v_latest_sweep AS
SELECT sweep_id, jurisdiction, topic, as_of_date, finished_at
  FROM sweeps
 WHERE receipt IS NOT NULL
 ORDER BY finished_at DESC
 LIMIT 1;

-- --------------------------------------------------------------------------------------------
-- v_findings: one row per finding, with the complete evidence chain flattened for a BI tool.
--
-- Everything a reviewer needs to defend the determination months later is on the row: the clause
-- text and its citation, the rule version and its legal citation, the extracted value against the
-- required value, and how the determination was made. No joins required of the dashboard author,
-- and no way to build a table that silently omits the evidence.
-- --------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW v_findings AS
SELECT
    f.finding_id,
    f.sweep_id,
    s.as_of_date,
    f.lease_id,
    l.community,
    l.state,
    l.jurisdiction,
    l.signed_date,
    f.topic,
    f.rule_id,
    f.rule_version,
    -- The synthetic-citation caveat is carried IN THE DATA, not added by the dashboard.
    -- Quick stripped a leading "ILLUSTRATIVE:" label when summarising a chat answer, so the
    -- caveat is a bracketed suffix here too: a screenshot of this table must not be able to
    -- present a fabricated citation as statute.
    regexp_replace(r.citation, '^ILLUSTRATIVE:\s*', '')
        || ' [SYNTHETIC PLACEHOLDER - NOT VERIFIED LAW]' AS rule_citation,
    r.check_field || ' ' || r.check_operator || ' ' || (r.check_value #>> '{}') AS rule_check,
    r.effective_date AS rule_effective_date,
    r.approved_by AS rule_approved_by,
    f.status,
    f.band,
    CASE f.band
        WHEN 'clear_violation' THEN 'Clear violation'
        WHEN 'probable'        THEN 'Probable violation (needs sign-off)'
        WHEN 'needs_review'    THEN 'Needs review (no structured value)'
    END AS band_label,
    f.risk_score,
    f.clause_citation,
    f.clause_text,
    -- Rendered as text so a BI table shows "12" rather than a JSON blob.
    (f.extracted_value #>> ARRAY[r.check_field]) AS extracted_value,
    (r.check_value #>> '{}') AS required_value,
    f.method,
    f.comparison,
    f.engine_version,
    f.created_at,
    -- Lets the dashboard open on the newest sweep with no filter fiddling. A viewer who wants an
    -- older sweep can still clear the filter and pick one -- history is never hidden, just not the
    -- default.
    (ls.sweep_id IS NOT NULL) AS is_latest_sweep
  FROM findings f
  JOIN leases l  USING (lease_id)
  JOIN sweeps s  USING (sweep_id)
  JOIN rulebook r ON r.rule_id = f.rule_id AND r.version = f.rule_version
  LEFT JOIN v_latest_sweep ls ON ls.sweep_id = f.sweep_id;

-- --------------------------------------------------------------------------------------------
-- v_not_evaluated: leases that could NOT be checked, per sweep.
--
-- A separate view on purpose. "We could not tell whether this lease complies" is a different
-- problem from "this lease breaks a rule", with a different owner and a different remedy
-- (rescan, not remediation). Merging them into the findings table is how a lease quietly
-- disappears from a dashboard -- the exact failure this system exists to prevent.
-- --------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW v_not_evaluated AS
SELECT
    s.sweep_id,
    s.as_of_date,
    l.lease_id,
    l.community,
    l.state,
    l.jurisdiction,
    l.unreadable_reason AS reason,
    'NOT EVALUATED - document could not be read' AS status_label
  FROM sweeps s
  JOIN leases l
    ON s.jurisdiction = ANY (
         -- the sweep's jurisdiction prefix-matches the lease's, mirroring engine population logic
         SELECT s.jurisdiction WHERE s.jurisdiction LIKE l.jurisdiction || '%'
       )
 WHERE NOT l.readable;

-- --------------------------------------------------------------------------------------------
-- v_sweep_receipt: the completeness receipt, one row per sweep, flattened.
--
-- On the dashboard beside the findings table so the table can never be read without its
-- denominator. A count of rows in a filtered table is not a compliance answer; the receipt is.
-- --------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW v_sweep_receipt AS
SELECT
    s.sweep_id,
    s.jurisdiction,
    COALESCE(s.topic, 'ALL TOPICS') AS topic,
    s.as_of_date,
    s.started_at,
    s.finished_at,
    -- LEASE-level counts. The invariant is lease-level: a lease breaching two rules is still one
    -- lease. Named explicitly, because the findings table counts something different.
    (s.receipt->>'scanned')::int             AS leases_scanned,
    (s.receipt->>'evaluated')::int           AS leases_evaluated,
    (s.receipt->>'compliant')::int           AS leases_compliant,
    (s.receipt->>'noncompliant')::int        AS leases_noncompliant,
    (s.receipt->>'ambiguous')::int           AS leases_ambiguous,
    (s.receipt->>'not_evaluated_count')::int AS leases_not_evaluated,
    -- FINDING-level counts: one finding per violated (lease, rule), which is what the findings
    -- table shows. With several rules in force these are legitimately LARGER than the lease counts.
    --
    -- Both are surfaced with unambiguous names because the alternative was observed to be
    -- confusing: a receipt reading "12,190 noncompliant" beside a table of 14,018 rows looks like
    -- one of them is wrong. Neither is; they count different things, and only explicit naming
    -- makes that legible.
    (s.receipt->>'findings_written')::int    AS findings_total,
    (SELECT count(*) FROM findings f2
      WHERE f2.sweep_id = s.sweep_id AND f2.status = 'NONCOMPLIANT') AS findings_noncompliant,
    (SELECT count(*) FROM findings f2
      WHERE f2.sweep_id = s.sweep_id AND f2.status = 'AMBIGUOUS')    AS findings_ambiguous,
    (s.receipt->>'rules_applied')::int       AS rules_applied,
    (s.receipt->>'checks_run')::int          AS checks_run,
    s.receipt->>'population_basis'           AS population_basis,
    s.receipt->>'determination_method'       AS determination_method,
    -- Pinned to the same single sweep as the findings table, so the receipt on screen always
    -- describes the rows on screen. A receipt beside a table it does not describe is worse than no
    -- receipt: it lends false authority to the wrong number.
    (ls.sweep_id IS NOT NULL) AS is_latest_sweep,
    -- Computed, not stored: the invariant is visible on the dashboard rather than merely asserted
    -- in code, so a viewer can confirm every lease is accounted for.
    CASE WHEN (s.receipt->>'compliant')::int + (s.receipt->>'noncompliant')::int
              + (s.receipt->>'ambiguous')::int + (s.receipt->>'not_evaluated_count')::int
              = (s.receipt->>'scanned')::int
         THEN 'BALANCED - every lease accounted for exactly once'
         ELSE 'IMBALANCED - investigate before relying on this sweep'
    END AS completeness_check
  FROM sweeps s
  LEFT JOIN v_latest_sweep ls ON ls.sweep_id = s.sweep_id
 WHERE s.receipt IS NOT NULL;
