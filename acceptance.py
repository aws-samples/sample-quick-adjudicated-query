"""Acceptance suite. Runs against the DEPLOYED stack over HTTPS with a real OAuth token.

This is the only automated test in the project, deliberately. It asserts exactly the claims the
demo makes -- nothing about internals, nothing that would pass while the demo fails:

  1. the receipt equals independently-generated ground truth (manifest.json)
  2. the receipt invariant holds: every lease accounted for exactly once
  3. as_of_date is required at the schema, not defaulted
  4. explore returns a RANKING receipt, is labelled INTERPRETIVE, and writes no findings
  5. an earlier as_of_date resolves an older rule version and changes the answer
  6. every determination records how it was made
  7. unreadable leases are NAMED, never silently dropped
  8. the whole exchange works SSE-framed, which is what Quick requires
  9. a what-if is labelled EXPLORATORY, accounts for its whole population, and records nothing

Run:  .venv/bin/python acceptance.py
"""

import json
import os
import subprocess
import sys
import time
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))

with open(os.path.join(HERE, "outputs.json")) as f:
    OUT = json.load(f)["QuickPocStack"]
with open(os.path.join(HERE, "manifest.json")) as f:
    MANIFEST = json.load(f)

MCP_URL = OUT["McpUrl"]
POOL_ID = OUT["Issuer"].rsplit("/", 1)[-1]

AS_OF_NOW = "2026-07-31"
AS_OF_PAST = "2025-06-01"

failures = []
_token = None


def check(label, ok, detail=""):
    print("%s %s%s" % ("PASS" if ok else "FAIL", label, ("\n     %s" % detail) if detail else ""))
    if not ok:
        failures.append(label)


def _urlopen(req, timeout):
    """urlopen restricted to https.

    Every caller here passes a fixed https endpoint from outputs.json (CDK stack output) --
    never external or user-supplied input -- but the scheme is asserted explicitly rather than
    left as an assumption a reader (or a scanner) has to trust.
    """
    url = req.full_url if isinstance(req, urllib.request.Request) else req
    if not url.startswith("https://"):
        raise ValueError("refusing to open non-https URL: %r" % url)
    return urllib.request.urlopen(req, timeout=timeout)  # nosec B310 # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected


def token():
    global _token
    if _token:
        return _token
    secret = subprocess.check_output(
        ["aws", "cognito-idp", "describe-user-pool-client",
         "--user-pool-id", POOL_ID, "--client-id", OUT["ClientId"],
         "--query", "UserPoolClient.ClientSecret", "--output", "text"], text=True).strip()
    body = urllib.parse.urlencode({
        "grant_type": "client_credentials", "client_id": OUT["ClientId"],
        "client_secret": secret, "scope": OUT["Scope"]}).encode()
    req = urllib.request.Request(
        OUT["TokenEndpoint"], data=body,
        headers={"content-type": "application/x-www-form-urlencoded"})
    with _urlopen(req, timeout=20) as r:
        _token = json.loads(r.read())["access_token"]
    return _token


def call(name, arguments, request_id="acc-1"):
    """Invoke a tool exactly as Quick does: SSE-framed, bearer token, JSON-RPC."""
    payload = {"jsonrpc": "2.0", "id": request_id, "method": "tools/call",
               "params": {"name": name, "arguments": arguments}}
    req = urllib.request.Request(
        MCP_URL, data=json.dumps(payload).encode(),
        headers={
            "content-type": "application/json",
            # The header Quick sends. Answering it with plain JSON is what silently broke the
            # integration in task 2, so the acceptance path exercises the SSE branch.
            "accept": "application/json, text/event-stream",
            "authorization": "Bearer %s" % token(),
        })
    t0 = time.time()
    with _urlopen(req, timeout=90) as r:
        raw = r.read().decode()
        ctype = r.headers.get("content-type", "")
    elapsed = time.time() - t0

    assert "text/event-stream" in ctype, "expected SSE, got %r" % ctype
    body = json.loads(raw.split("data: ", 1)[1].strip())
    if "error" in body:
        return {"_rpc_error": body["error"]}, elapsed
    text = body["result"]["content"][0]["text"]
    return json.loads(text), elapsed


def findings_count():
    out, _ = call("list_rules", {"jurisdiction": "US/TX", "as_of_date": AS_OF_NOW})
    # No tool exposes a raw count, so use the DB directly for this one invariant.
    sys.path.insert(0, os.path.join(HERE, "mcp_server"))
    os.environ.setdefault("DB_CLUSTER_ARN", OUT["DbClusterArn"])
    os.environ.setdefault("DB_SECRET_ARN", OUT["DbSecretArn"])
    os.environ.setdefault("DB_NAME", OUT["DbName"])
    import db
    return db.query("SELECT count(*) AS n FROM findings")[0]["n"]


print("=" * 78)
print("ACCEPTANCE -- deployed stack, SSE transport, real OAuth token")
print("=" * 78)

# --- 1. the headline claim: receipt == independent ground truth --------------------------
sweep, elapsed = call("sweep_compliance",
                      {"jurisdiction": "US/TX", "as_of_date": AS_OF_NOW, "topic": "late_fees"})
receipt = sweep.get("completeness_receipt", {})
exp_v = MANIFEST["violations_by_rule"]["TX"]["TX-LATEFEE-CAP"]
exp_a = MANIFEST["ambiguous_by_rule"]["TX"]["TX-LATEFEE-CAP"]

check("1. TX late-fee receipt matches manifest ground truth",
      receipt.get("noncompliant") == exp_v and receipt.get("ambiguous") == exp_a,
      "receipt: noncompliant=%s ambiguous=%s | manifest: noncompliant=%s ambiguous=%s"
      % (receipt.get("noncompliant"), receipt.get("ambiguous"), exp_v, exp_a))

check("1b. sweep completes inside Quick's 60s MCP ceiling",
      elapsed < 60, "%.1fs" % elapsed)

# --- 2. the invariant: every lease accounted for exactly once ----------------------------
total = (receipt.get("compliant", 0) + receipt.get("noncompliant", 0)
         + receipt.get("ambiguous", 0) + receipt.get("not_evaluated_count", 0))
check("2. receipt invariant holds (compliant+noncompliant+ambiguous+not_evaluated == scanned)",
      total == receipt.get("scanned"),
      "%d == %s" % (total, receipt.get("scanned")))

# --- 3. as_of_date is required, never defaulted ------------------------------------------
missing, _ = call("sweep_compliance", {"jurisdiction": "US/TX"})
rejected = ("_rpc_error" in missing) or bool(missing.get("error")) or bool(missing.get("isError"))
check("3. sweep without as_of_date is rejected rather than silently defaulted",
      rejected, json.dumps(missing)[:200])

# --- 4. exploration is labelled, ranked, and writes nothing ------------------------------
before = findings_count()
exp, exp_elapsed = call("explore_clauses",
                        {"query_text": "clauses where the resident gives up the right to sue",
                         "jurisdiction": "US/TX", "k": 25})
after = findings_count()

check("4. explore is labelled INTERPRETIVE with a RANKING receipt, not a completeness claim",
      exp.get("mode") == "INTERPRETIVE"
      and exp.get("ranking_receipt", {}).get("population_basis") == "filter_then_rank"
      and "NO completeness claim" in exp.get("ranking_receipt", {}).get("claim", ""),
      "mode=%s basis=%s" % (exp.get("mode"),
                            exp.get("ranking_receipt", {}).get("population_basis")))

check("4b. explore writes no findings",
      before == after, "findings before=%d after=%d" % (before, after))

check("4c. explore reports its denominator (top K of N), so it cannot read as complete",
      exp.get("ranking_receipt", {}).get("population_pinned", 0) > exp.get(
          "ranking_receipt", {}).get("returned", 0),
      "top %s of %s" % (exp.get("ranking_receipt", {}).get("returned"),
                        exp.get("ranking_receipt", {}).get("population_pinned")))

check("4d. explore stays inside the 60s ceiling at k=25",
      exp_elapsed < 60, "%.1fs" % exp_elapsed)

# --- 5. time travel: an earlier date resolves an older rule version ----------------------
past, _ = call("sweep_compliance",
               {"jurisdiction": "US/TX", "as_of_date": AS_OF_PAST, "topic": "late_fees"})
past_rule = (past.get("rules_applied") or [{}])[0]
now_rule = (sweep.get("rules_applied") or [{}])[0]
check("5. earlier as_of_date resolves an older rule version and changes the answer",
      past_rule.get("version") == 1 and now_rule.get("version") == 2
      and past["completeness_receipt"]["noncompliant"] != receipt["noncompliant"],
      "as-of %s -> v%s (%s): %s noncompliant | as-of %s -> v%s (%s): %s noncompliant"
      % (AS_OF_PAST, past_rule.get("version"), past_rule.get("check"),
         past["completeness_receipt"]["noncompliant"],
         AS_OF_NOW, now_rule.get("version"), now_rule.get("check"), receipt["noncompliant"]))

# --- 6. no determination is anonymous ---------------------------------------------------
preview = sweep.get("preview_rows") or []
fid = preview[0]["finding_id"] if preview else None
detail, _ = call("get_finding", {"finding_id": fid}) if fid else ({}, 0)
det = detail.get("determination", {})
rule = detail.get("rule", {})
check("6. a finding carries its full evidence chain and how it was determined",
      bool(det.get("method")) and bool(det.get("comparison"))
      and bool(rule.get("citation")) and bool(rule.get("version"))
      and bool(detail.get("evidence", {}).get("clause_text")),
      "method=%s | %s | rule=%s v%s" % (det.get("method"), det.get("comparison"),
                                        rule.get("rule_id"), rule.get("version")))

check("6b. deterministic findings record that no model was involved",
      "no model" in receipt.get("determination_method", ""),
      receipt.get("determination_method"))

# --- 7. unreadable leases are named, never dropped --------------------------------------
not_eval = receipt.get("not_evaluated") or []
check("7. every unevaluated lease is named with a reason",
      len(not_eval) == receipt.get("not_evaluated_count")
      and all(x.get("lease_id") and x.get("reason") for x in not_eval),
      "%d named, e.g. %s" % (len(not_eval), not_eval[0] if not_eval else "none"))

# --- 8. all-rules sweep: co-existing rules are all evaluated ----------------------------
allrules, all_elapsed = call("sweep_compliance",
                             {"jurisdiction": "US/TX", "as_of_date": AS_OF_NOW})
ar = allrules.get("completeness_receipt", {})
check("8. all-topics sweep evaluates every rule in force, not one per topic",
      ar.get("rules_applied") == 3 and ar.get("checks_run") == 3 * ar.get("evaluated", 0),
      "rules=%s checks_run=%s evaluated=%s (%.1fs)"
      % (ar.get("rules_applied"), ar.get("checks_run"), ar.get("evaluated"), all_elapsed))

check("8b. lease-level invariant still holds when several rules apply",
      (ar.get("compliant", 0) + ar.get("noncompliant", 0) + ar.get("ambiguous", 0)
       + ar.get("not_evaluated_count", 0)) == ar.get("scanned"),
      "scanned=%s" % ar.get("scanned"))

# --- 9. honesty safeguards must survive a summarising renderer ---------------------------
# Both of these are regression tests for defects observed in Quick's actual rendering, not
# hypotheticals. Quick stripped an "ILLUSTRATIVE:" citation prefix and presented a synthetic
# citation as statute; and it inferred a population-wide range from a 20-row preview.
cited = (sweep.get("rules_applied") or [{}])[0].get("citation", "")
check("9. citations carry the synthetic-law caveat as a suffix, not a strippable prefix",
      "SYNTHETIC PLACEHOLDER" in cited and not cited.startswith("ILLUSTRATIVE"),
      cited[:110])

check("9b. the caveat is also a top-level field in sweep, get_finding and list_rules",
      all("IMPORTANT_citation_caveat" in payload
          for payload in (sweep, detail, call("list_rules", {
              "jurisdiction": "US/TX", "as_of_date": AS_OF_NOW})[0])))

spread = sweep.get("violation_spread", {}).get("by_rule") or []
check("9c. population statistics are supplied so a model need not extrapolate from the preview",
      bool(spread) and spread[0].get("findings") == exp_v
      and spread[0].get("min_value") is not None,
      "findings=%s min=%s max=%s avg=%s" % (
          spread[0].get("findings"), spread[0].get("min_value"),
          spread[0].get("max_value"), spread[0].get("avg_value")) if spread else "missing")

# Customer-driven: with 10,111 noncompliant findings, a severity-ordered LIMIT 20 returned 20
# noncompliant rows and zero ambiguous ones, so the 689 leases actually needing a human were
# invisible in the chat answer. And an ambiguous row without its clause text is unreviewable --
# `comparison` explains the mechanism, not the vague wording that caused it.
amb_rows = [r for r in preview if r["status"] == "AMBIGUOUS"]
nc_rows = [r for r in preview if r["status"] == "NONCOMPLIANT"]
check("9e. the preview shows BOTH statuses, each with the clause text that explains it",
      bool(amb_rows) and bool(nc_rows)
      and all(r.get("clause_text") for r in amb_rows)
      and all(r.get("row_meaning") for r in preview),
      "%d noncompliant + %d ambiguous rows | e.g. %s"
      % (len(nc_rows), len(amb_rows),
         (amb_rows[0]["clause_text"][:88] + "...") if amb_rows else "none"))

check("9f. the stratified sample declares its real denominators so the mix is not extrapolated",
      sweep.get("preview_composition", {}).get("ambiguous_total_in_sweep") == exp_a
      and sweep["preview_composition"]["noncompliant_total_in_sweep"] == exp_v
      and "artefact of" in sweep.get("preview_warning", "")
      and "NOT a violation" in sweep.get("ambiguous_meaning", ""),
      "shown %s nc / %s amb against totals %s / %s"
      % (sweep["preview_composition"]["noncompliant_rows_shown"],
         sweep["preview_composition"]["ambiguous_rows_shown"], exp_v, exp_a))

check("9d. the preview is explicitly labelled as a sample not to generalise from",
      "Do NOT infer" in sweep.get("preview_warning", ""),
      sweep.get("preview_warning", "")[:90])

# --- 10. the dashboard must reconcile with a receipt --------------------------------------
# Regression test for a real defect: "latest sweep" was defined per (jurisdiction, topic,
# as_of_date), so three legitimate sweeps were all "latest" and the dashboard showed 29,045 rows --
# the union of three populations evaluated under different rules on different dates. That number
# corresponded to no receipt anywhere, and nothing on screen said so.
sys.path.insert(0, os.path.join(HERE, "mcp_server"))
os.environ.setdefault("DB_CLUSTER_ARN", OUT["DbClusterArn"])
os.environ.setdefault("DB_SECRET_ARN", OUT["DbSecretArn"])
os.environ.setdefault("DB_NAME", OUT["DbName"])
import db as _db  # noqa: E402

n_latest = _db.query("SELECT count(*) AS n FROM v_latest_sweep")[0]["n"]
check("10. the dashboard's default view resolves to exactly ONE sweep",
      n_latest == 1, "v_latest_sweep returned %d rows" % n_latest)

dash_nc = _db.query("SELECT count(*) AS n FROM v_findings "
                    "WHERE is_latest_sweep AND status = 'NONCOMPLIANT'")[0]["n"]
dash_amb = _db.query("SELECT count(*) AS n FROM v_findings "
                     "WHERE is_latest_sweep AND status = 'AMBIGUOUS'")[0]["n"]
rec = _db.query("SELECT leases_noncompliant, leases_ambiguous, findings_noncompliant, "
                "findings_ambiguous, completeness_check FROM v_sweep_receipt "
                "WHERE is_latest_sweep")
# Compare like with like. The findings TABLE counts findings (one per violated rule); the receipt's
# lease counts count leases. Asserting the table against the lease count is what failed first, and
# the fix was to name both explicitly rather than to pick one -- a receipt reading "12,190
# noncompliant" beside 14,018 table rows looks like an error unless the units are stated.
check("10b. dashboard row counts reconcile exactly with that sweep's FINDING counts",
      len(rec) == 1 and dash_nc == rec[0]["findings_noncompliant"]
      and dash_amb == rec[0]["findings_ambiguous"],
      "table: nc=%d amb=%d | receipt findings: nc=%s amb=%s | receipt leases: nc=%s amb=%s"
      % (dash_nc, dash_amb,
         rec[0]["findings_noncompliant"] if rec else "?",
         rec[0]["findings_ambiguous"] if rec else "?",
         rec[0]["leases_noncompliant"] if rec else "?",
         rec[0]["leases_ambiguous"] if rec else "?"))

check("10d. lease counts and finding counts are both published, under unambiguous names",
      bool(rec) and rec[0]["leases_noncompliant"] is not None
      and rec[0]["findings_noncompliant"] is not None
      and rec[0]["findings_noncompliant"] >= rec[0]["leases_noncompliant"],
      "leases=%s findings=%s" % (rec[0]["leases_noncompliant"] if rec else "?",
                                 rec[0]["findings_noncompliant"] if rec else "?"))

check("10c. the receipt shown on the dashboard reports the invariant as balanced",
      bool(rec) and rec[0]["completeness_check"].startswith("BALANCED"),
      rec[0]["completeness_check"] if rec else "no receipt")

# --- 11. what-if: labelled EXPLORATORY, directional, and records nothing ------------------
# Ported from the prototype's threshold-override path (R4). The claim under test is not "the
# arithmetic is right" but "a simulated count cannot be mistaken for a compliance figure and
# cannot leave a trace", which is the only reason it is safe to expose at all.
sim_before_f = findings_count()
sim_before_s = _db.query("SELECT count(*) AS n FROM sweeps")[0]["n"]

tighten, sim_elapsed = call("simulate_rule_change", {
    "jurisdiction": "US/TX", "as_of_date": AS_OF_NOW,
    "rule_id": "TX-LATEFEE-CAP", "proposed_value": 3})
loosen, _ = call("simulate_rule_change", {
    "jurisdiction": "US/TX", "as_of_date": AS_OF_NOW,
    "rule_id": "TX-LATEFEE-CAP", "proposed_value": 12})

sim_after_f = findings_count()
sim_after_s = _db.query("SELECT count(*) AS n FROM sweeps")[0]["n"]

check("11. what-if is labelled EXPLORATORY and says so in the summary a model will paraphrase",
      tighten.get("mode") == "EXPLORATORY"
      and "NOT a compliance determination" in tighten.get("mode_meaning", "")
      and "EXPLORATORY" in tighten.get("answer_summary", ""),
      "mode=%s" % tighten.get("mode"))

check("11b. what-if records nothing: no findings, no sweep row, rulebook untouched",
      sim_before_f == sim_after_f and sim_before_s == sim_after_s
      # Not aliased: db.py decodes JSONB by COLUMN NAME, so `check_value AS v` comes back as the
      # string "5" and compares false against 5. Same trap as the rule-resolution defect in task 3.
      and _db.query("SELECT check_value FROM rulebook "
                    "WHERE rule_id='TX-LATEFEE-CAP' AND version=2")[0]["check_value"] == 5
      and tighten.get("writes_findings") is False,
      "findings %d->%d sweeps %d->%d" % (sim_before_f, sim_after_f, sim_before_s, sim_after_s))

check("11c. what-if accounts for the whole population, like an official sweep",
      (tighten["completeness_receipt"]["compliant"]
       + tighten["completeness_receipt"]["noncompliant"]
       + tighten["completeness_receipt"]["ambiguous"]
       + tighten["completeness_receipt"]["not_evaluated_count"])
      == tighten["completeness_receipt"]["scanned"],
      "scanned=%s" % tighten["completeness_receipt"]["scanned"])

# Direction matters: tightening must move leases INTO violation and loosening OUT of it. A single
# subtraction of totals would satisfy net_change while getting both directions wrong, so the
# per-lease counts are asserted against the identity that relates them.
check("11d. directional counts are per-lease, and both directions behave correctly",
      tighten["net_change"] == tighten["newly_noncompliant"] - tighten["newly_compliant"]
      and loosen["net_change"] == loosen["newly_noncompliant"] - loosen["newly_compliant"]
      and tighten["newly_noncompliant"] > 0 and tighten["newly_compliant"] == 0
      and loosen["newly_compliant"] > 0 and loosen["newly_noncompliant"] == 0
      and tighten["baseline_noncompliant"] == loosen["baseline_noncompliant"],
      "5%%->3%%: %+d (newly nc %d) | 5%%->12%%: %+d (newly compliant %d) | same baseline %d"
      % (tighten["net_change"], tighten["newly_noncompliant"],
         loosen["net_change"], loosen["newly_compliant"], tighten["baseline_noncompliant"]))

# A presence requirement has no threshold. Simulating one would mean inventing a comparison the
# rule does not make -- a fabrication the mode label would not catch, because the number would
# look ordinary.
presence, _ = call("simulate_rule_change", {
    "jurisdiction": "US/FL", "as_of_date": AS_OF_NOW,
    "rule_id": "FL-FLOOD-DISC", "proposed_value": 1})
check("11e. a presence requirement is refused rather than given an invented threshold",
      "presence requirement" in json.dumps(presence),
      json.dumps(presence)[:150])

total_checks = 28
print()
print("=" * 78)
print("%d/%d acceptance checks pass" % (total_checks - len(failures), total_checks))
if failures:
    print("failed: %s" % ", ".join(failures))
print("=" * 78)
sys.exit(1 if failures else 0)
