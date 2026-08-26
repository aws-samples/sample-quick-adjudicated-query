-- Schema for the Quick lease-compliance PoC.
--
-- These are the prototype's records (working-prototype/leases.json, rulebook.json, findings.json)
-- normalised for 50K-row scale. Shaped like the real system's, not minimised for the demo, so the
-- PoC evidences that Option D's data model is buildable.
--
-- Idempotent: safe to re-run.

CREATE EXTENSION IF NOT EXISTS vector;

-- --------------------------------------------------------------------------------------------
-- leases: the population. One row per resident agreement.
-- --------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS leases (
    lease_id          TEXT PRIMARY KEY,
    community         TEXT        NOT NULL,
    -- Jurisdiction is a PATH ('US/TX', later 'US/TX/Austin') so a hierarchy has somewhere to live.
    -- Resolution is most-specific-wins; only state level is authored in this PoC.
    jurisdiction      TEXT        NOT NULL,
    state             CHAR(2)     NOT NULL,
    signed_date       DATE        NOT NULL,
    -- readable = false means the lease is counted in `scanned` but NOT in `evaluated`, and is
    -- named in the receipt's not_evaluated list. Never silently dropped: that is the single most
    -- important honesty property in the system.
    readable          BOOLEAN     NOT NULL DEFAULT TRUE,
    unreadable_reason TEXT
);

CREATE INDEX IF NOT EXISTS idx_leases_state        ON leases (state);
CREATE INDEX IF NOT EXISTS idx_leases_jurisdiction ON leases (jurisdiction);
-- The sweep's population filter is (jurisdiction, readable); this covers it.
CREATE INDEX IF NOT EXISTS idx_leases_juris_readable ON leases (jurisdiction, readable);

-- --------------------------------------------------------------------------------------------
-- clauses: the evidence. One row per topic per lease.
-- --------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS clauses (
    clause_id  TEXT PRIMARY KEY,
    lease_id   TEXT        NOT NULL REFERENCES leases (lease_id) ON DELETE CASCADE,
    topic      TEXT        NOT NULL,
    citation   TEXT        NOT NULL,
    text       TEXT        NOT NULL,
    -- Structured values pulled out at extraction time. A MISSING key is the routing signal:
    -- no extracted value means no deterministic comparison is possible, so the lease lands in the
    -- ambiguous bucket (counted and named) rather than being guessed at.
    extracted  JSONB       NOT NULL DEFAULT '{}'::jsonb,
    extraction_confidence NUMERIC(4,3),
    -- Populated only for `special_provisions` clauses: the exploratory corpus. Embedding every
    -- clause would cost more and prove nothing extra -- semantic ranking is only ever applied to
    -- the qualitative question.
    embedding  vector(1024)
);

CREATE INDEX IF NOT EXISTS idx_clauses_lease       ON clauses (lease_id);
CREATE INDEX IF NOT EXISTS idx_clauses_topic       ON clauses (topic);
CREATE INDEX IF NOT EXISTS idx_clauses_lease_topic ON clauses (lease_id, topic);

-- --------------------------------------------------------------------------------------------
-- rulebook: rules as DATA, versioned, never edited in place.
-- A law change is a new row. That is what makes point-in-time reconstruction possible.
-- --------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS rulebook (
    rule_id          TEXT    NOT NULL,
    version          INT     NOT NULL,
    jurisdiction     TEXT    NOT NULL,
    topic            TEXT    NOT NULL,
    -- Generic operators only: gte, lte, equals, exists. The engine knows operators; it must never
    -- know jurisdictions or topics. Adding a rule is data; adding an operator is the only code
    -- change permitted.
    check_field      TEXT    NOT NULL,
    check_operator   TEXT    NOT NULL CHECK (check_operator IN ('gte', 'lte', 'equals', 'exists')),
    check_value      JSONB,
    -- What to do when the field is absent: 'ambiguous' (needs human/deep check) or 'noncompliant'
    -- (absence IS the violation, e.g. a required disclosure). Rulebook decides, not the engine.
    on_missing_field TEXT    NOT NULL DEFAULT 'ambiguous'
                             CHECK (on_missing_field IN ('ambiguous', 'noncompliant')),
    citation         TEXT    NOT NULL,
    effective_date   DATE    NOT NULL,
    approved_by      TEXT    NOT NULL,
    approved_date    DATE    NOT NULL,
    risk_weight      INT     NOT NULL DEFAULT 50,
    qualitative_prompt TEXT,
    PRIMARY KEY (rule_id, version)
);

CREATE INDEX IF NOT EXISTS idx_rulebook_resolution
    ON rulebook (jurisdiction, topic, effective_date);

-- --------------------------------------------------------------------------------------------
-- sweeps: one row per official run, carrying the COMPUTED receipt.
-- --------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sweeps (
    sweep_id      TEXT PRIMARY KEY,
    jurisdiction  TEXT        NOT NULL,
    topic         TEXT,
    as_of_date    DATE        NOT NULL,
    started_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at   TIMESTAMPTZ,
    -- The receipt is derived from count(*) queries and asserted before commit:
    --   evaluated + ambiguous + not_evaluated = scanned
    -- It is never hand-written into a response.
    receipt       JSONB,
    rules_applied JSONB
);

-- --------------------------------------------------------------------------------------------
-- findings: append-only. One row per violated (lease, rule@version).
-- No UPDATE or DELETE statement against this table exists anywhere in the codebase.
-- --------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS findings (
    finding_id     TEXT PRIMARY KEY,
    sweep_id       TEXT        NOT NULL REFERENCES sweeps (sweep_id),
    lease_id       TEXT        NOT NULL REFERENCES leases (lease_id),
    rule_id        TEXT        NOT NULL,
    rule_version   INT         NOT NULL,
    topic          TEXT        NOT NULL,
    as_of_date     DATE        NOT NULL,
    -- NONCOMPLIANT | AMBIGUOUS. COMPLIANT leases are not filed as findings; they are counted in
    -- the receipt. NOT_EVALUATED leases are named in the receipt's not_evaluated list.
    status         TEXT        NOT NULL CHECK (status IN ('NONCOMPLIANT', 'AMBIGUOUS')),
    -- Categorical band for display. Raw scores never reach a user-facing surface.
    band           TEXT        NOT NULL
                               CHECK (band IN ('clear_violation', 'probable', 'needs_review')),
    risk_score     INT         NOT NULL,
    -- Evidence chain: what the finding is based on.
    clause_text    TEXT,
    clause_citation TEXT,
    extracted_value JSONB,
    required_value  JSONB,
    -- How the determination was made. No determination is anonymous.
    method         TEXT        NOT NULL CHECK (method IN ('deterministic', 'deep_check')),
    comparison     TEXT,
    engine_version TEXT        NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (rule_id, rule_version) REFERENCES rulebook (rule_id, version)
);

CREATE INDEX IF NOT EXISTS idx_findings_sweep  ON findings (sweep_id);
CREATE INDEX IF NOT EXISTS idx_findings_lease  ON findings (lease_id);
CREATE INDEX IF NOT EXISTS idx_findings_band   ON findings (band);
CREATE INDEX IF NOT EXISTS idx_findings_rule   ON findings (rule_id, rule_version);
