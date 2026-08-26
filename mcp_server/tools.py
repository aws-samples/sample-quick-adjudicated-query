"""The MCP tool contract.

**Tool descriptions are load-bearing.** They are the only thing steering Quick's agent when it
picks a tool, and Amazon Quick snapshots the tool list at registration time -- changing them later
requires deleting and recreating the integration. So each description states WHAT A RESULT MEANS,
exhaustive vs ranked, because a caller that cannot tell the difference will confidently report a
ranked sample as a completed audit.

Every safeguard lives in the RESPONSE PAYLOAD, never only in a rendering: receipts, mode labels,
the not_evaluated list, and how each determination was made. The UI is a renderer; non-human
callers get the same guarantees.

All four tools are READ-ONLY with respect to the compliance record. `sweep` writes findings, which
is a machine determination, but no tool files a review, an override, or a rule change -- those are
human acts and a model cannot supply a reviewer's name or reason honestly.
"""

import json
import os

import db
import engine
import explore

# Schema convention, learned the hard way in task 2: JSON Schema Draft 7 (`required` is an array at
# the schema root), only name/description/inputSchema, plain ASCII, non-empty required array.
TOOLS = [
    {
        "name": "sweep_compliance",
        "description": (
            "EXHAUSTIVE compliance check. Evaluates EVERY lease in a jurisdiction against every "
            "rule in force on a given date, and returns a completeness receipt accounting for all "
            "of them: compliant, noncompliant, ambiguous, or not evaluated with a named reason. "
            "Use this for any question about a whole population, such as which leases violate a "
            "law, or how many are affected. Results are official findings and are recorded. "
            "Returns counts, the receipt, and a small preview; the full findings table is in the "
            "Quick Sight dashboard, not in this response. Requires an explicit as_of_date because "
            "which rule version applies depends on the date."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "jurisdiction": {
                    "type": "string",
                    "description": (
                        "Jurisdiction path, for example US/TX. Available: US/TX, US/FL, US/MI, "
                        "US/CA, US/AZ, US/NC, US/GA, US/CO."
                    ),
                },
                "as_of_date": {
                    "type": "string",
                    "description": (
                        "The date the determination is made as of, YYYY-MM-DD. Required, never "
                        "assumed: rules are versioned, so an undated answer cannot be reconciled "
                        "with a dated finding later. Use today's date unless asked otherwise."
                    ),
                },
                "topic": {
                    "type": "string",
                    "description": (
                        "Optional. Narrow to one subject area: late_fees, eviction_notice, "
                        "rent_increase_notice, or flood_disclosure. Omit to evaluate every rule "
                        "in force. Note that one topic may carry several independent rules, and "
                        "all of them are evaluated."
                    ),
                },
            },
            "required": ["jurisdiction", "as_of_date"],
        },
    },
    {
        "name": "explore_clauses",
        "description": (
            "RANKED SAMPLE by meaning. NOT exhaustive and NOT an audit. Finds lease clauses that "
            "read like a described concept when no structured field captures it, for example "
            "clauses that read like liability waivers. Returns at most 25 clauses ranked by "
            "semantic similarity within a jurisdiction, each with a plain-language assessment. "
            "Because it ranks rather than enumerates, it CANNOT answer how many leases have "
            "something, and its results must never be reported as a complete or final count. Use "
            "sweep_compliance for any question about a whole population. Writes nothing and "
            "creates no findings."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "query_text": {
                    "type": "string",
                    "description": (
                        "Plain-language description of the clause concept to look for, for "
                        "example: clauses where the resident gives up the right to sue."
                    ),
                },
                "jurisdiction": {
                    "type": "string",
                    "description": (
                        "Optional jurisdiction path to rank within, for example US/TX. Omit to "
                        "rank across all states."
                    ),
                },
                "k": {
                    "type": "integer",
                    "description": "How many ranked clauses to return, 1 to 25. Default 10.",
                },
            },
            "required": ["query_text"],
        },
    },
    {
        "name": "simulate_rule_change",
        "description": (
            "WHAT-IF SIMULATION, not an official determination. Answers how a PROPOSED change to "
            "one rule's threshold would change the population, for example a bill that would "
            "lower a late fee cap from 5 percent to 3 percent. Use this when the question is "
            "hypothetical: what if, suppose, a proposed law, a bill under consideration. Returns "
            "the approved baseline, the simulated outcome, and how many leases would newly "
            "violate or newly comply, with a completeness receipt over the whole population. "
            "Records NOTHING: the proposed value has no approver, no effective date and no "
            "citation, so results must never be reported as findings or as compliance status. "
            "Use sweep_compliance for the official answer against the approved rulebook. Requires "
            "an explicit rule_id because a threshold applies to one rule; rules are measured in "
            "days, percent and yes/no, so a number applied across several rules is meaningless. "
            "Call list_rules first if the rule_id is not known."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "jurisdiction": {
                    "type": "string",
                    "description": (
                        "Jurisdiction path, for example US/TX. Available: US/TX, US/FL, US/MI, "
                        "US/CA, US/AZ, US/NC, US/GA, US/CO."
                    ),
                },
                "as_of_date": {
                    "type": "string",
                    "description": (
                        "The date the approved baseline is resolved as of, YYYY-MM-DD. Required, "
                        "never assumed: the baseline is whichever rule version was in force then, "
                        "so an undated simulation cannot be compared with anything."
                    ),
                },
                "rule_id": {
                    "type": "string",
                    "description": (
                        "The single rule to simulate, for example TX-LATEFEE-CAP. Must be in "
                        "force in this jurisdiction on this date. Use list_rules to discover it."
                    ),
                },
                "proposed_value": {
                    "type": "number",
                    "description": (
                        "The hypothetical threshold to test instead of the rule's approved value, "
                        "in the rule's own unit -- percent for fee caps, days for notice periods. "
                        "Not applicable to presence requirements, which have no threshold."
                    ),
                },
            },
            "required": ["jurisdiction", "as_of_date", "rule_id", "proposed_value"],
        },
    },
    {
        "name": "get_finding",
        "description": (
            "Full evidence chain for one official finding: the clause text and citation, the "
            "exact rule version applied with its legal citation and approver, the extracted value "
            "against the required value, and how the determination was made. Use this to drill "
            "into a single finding produced by sweep_compliance."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "finding_id": {
                    "type": "string",
                    "description": "Finding identifier, for example F-a1b2c3d4e5f6.",
                }
            },
            "required": ["finding_id"],
        },
    },
    {
        "name": "list_rules",
        "description": (
            "The rulebook in force for a jurisdiction on a given date, with each rule's version, "
            "the comparison it performs, its legal citation, and who approved it. Rules are "
            "versioned and never edited in place, so an earlier date returns the rules that "
            "applied then. Use this to explain why a finding was reached, or to show what will "
            "be checked before running a sweep."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "jurisdiction": {
                    "type": "string",
                    "description": "Jurisdiction path, for example US/TX.",
                },
                "as_of_date": {
                    "type": "string",
                    "description": "Date to resolve rule versions as of, YYYY-MM-DD.",
                },
                "topic": {
                    "type": "string",
                    "description": "Optional topic to narrow to.",
                },
            },
            "required": ["jurisdiction", "as_of_date"],
        },
    },
]


CITATION_SUFFIX = " [SYNTHETIC PLACEHOLDER - NOT VERIFIED LAW]"


def _cite(citation):
    """Attach the synthetic-citation caveat to every citation as it leaves the API.

    The rulebook stores citations prefixed "ILLUSTRATIVE:", and Quick stripped that prefix while
    summarising -- presenting a fabricated citation to the user as though it were statute. A
    leading label is easy for a model to drop as noise; a bracketed suffix reads as part of the
    citation phrase and survives paraphrase far better.

    Done here rather than by editing the rulebook, because rules are never edited in place. This is
    presentation, not a rule change, so immutability and point-in-time reconstruction are intact.
    """
    if not citation:
        return citation
    text = citation
    for prefix in ("ILLUSTRATIVE: ", "ILLUSTRATIVE:"):
        if text.startswith(prefix):
            text = text[len(prefix):]
            break
    if CITATION_SUFFIX.strip() in text:
        return text
    return text + CITATION_SUFFIX


DASHBOARD_URL = os.environ.get(
    "DASHBOARD_URL",
    "https://us-east-1.quicksight.aws.amazon.com/sn/dashboards/lease-poc-findings-dashboard",
)


def _dashboard_note():
    return (
        "The complete findings table is in the Quick Sight dashboard, which opens on the most "
        "recent sweep by default -- no filtering or sweep id needed. This response carries counts, "
        "the receipt, and a preview only; a chat answer must not be mistaken for the full record."
    )


def tool_sweep_compliance(args):
    jurisdiction = (args.get("jurisdiction") or "").strip()
    as_of_date = (args.get("as_of_date") or "").strip()
    topic = (args.get("topic") or "").strip() or None

    if not jurisdiction or not as_of_date:
        return {"error": "jurisdiction and as_of_date are both required"}

    sweep_id, receipt, per_rule, rules = engine.sweep(jurisdiction, as_of_date, topic)
    rows = engine.preview(sweep_id)
    spread = engine.violation_spread(sweep_id)
    n_nc = sum(1 for r in rows if r["status"] == "NONCOMPLIANT")
    n_amb = sum(1 for r in rows if r["status"] == "AMBIGUOUS")

    return {
        # The mode label is data, not decoration. An agent or downstream tool sees it too.
        "mode": "OFFICIAL",
        "mode_meaning": (
            "Exhaustive determination against the approved rulebook. Every lease in the population "
            "is accounted for in the receipt. These are official findings."
        ),
        "sweep_id": sweep_id,
        "completeness_receipt": receipt,
        "rules_applied": [dict(pr, citation=_cite(pr.get("citation"))) for pr in per_rule],
        # Aggregate spread over ALL violating leases, computed in SQL.
        #
        # Added because Quick, given only a 20-row preview, told the user that violations "range
        # from 6% to 15%" -- an extrapolation from a sample stated as a fact about all 10,111. It
        # happened to be correct, which is exactly what makes it dangerous. A summarising model
        # will characterise a population whether or not it has the data, so the honest fix is to
        # supply real aggregates rather than hope it abstains.
        "violation_spread": spread,
        "preview_rows": rows,
        # The sample is STRATIFIED, which introduces a misreading the old severity-ordered sample
        # could not: group sizes here are capped, so the ratio between them says nothing about the
        # population. Same class of error as inferring a 6-15% range from 20 rows, so it gets the
        # same treatment -- state the real denominators next to the sample.
        "preview_composition": {
            "noncompliant_rows_shown": n_nc,
            "ambiguous_rows_shown": n_amb,
            "noncompliant_total_in_sweep": receipt["noncompliant"],
            "ambiguous_total_in_sweep": receipt["ambiguous"],
            "sampling": (
                "Stratified with a fixed cap per status so that BOTH kinds of finding appear. "
                "Ambiguous findings are far rarer than this sample suggests -- take every "
                "proportion from completeness_receipt, never from these rows."
            ),
        },
        "ambiguous_meaning": (
            "An AMBIGUOUS finding is NOT a violation and NOT a model being uncertain -- no model "
            "was consulted. The clause is readable but states no comparable value, typically "
            "because it defers to the statute ('a reasonable late charge as determined by "
            "Landlord'). No deterministic answer exists, so an attorney must read it. Whether "
            "such a clause complies is a legal judgement, not an extraction problem."
        ),
        "preview_note": _dashboard_note(),
        # A real link, so the workflow is "ask, then click" rather than "ask, copy an id, go build
        # a table". The dashboard opens filtered to the latest sweep.
        "full_findings_dashboard_url": DASHBOARD_URL,
        "preview_warning": (
            "preview_rows is a SAMPLE of at most 20 findings, STRATIFIED by status with a fixed "
            "cap per group so that both noncompliant and ambiguous findings are visible. Do NOT "
            "infer ranges, distributions, the balance between statuses, or any other "
            "characteristic of the full findings set from it -- the mix you see is an artefact of "
            "the caps. Use completeness_receipt for how many are in each bucket and "
            "violation_spread for population statistics; both are computed over every finding."
        ),
        # Repeated at top level, in the answer text, and per rule. Quick stripped an
        # "ILLUSTRATIVE:" prefix from the citation string when summarising, presenting a synthetic
        # citation as real law -- so the caveat cannot live in the citation alone.
        "IMPORTANT_citation_caveat": (
            "THE LEGAL CITATIONS IN THIS RESPONSE ARE SYNTHETIC PLACEHOLDERS FOR A PROOF OF "
            "CONCEPT. THEY ARE NOT VERIFIED LAW AND MUST NOT BE REPEATED AS STATEMENTS OF "
            "STATUTE. Approver names are fictional. State this whenever you report a citation "
            "from this system."
        ),
        "answer_summary": (
            "Evaluated %d of %d %s leases as of %s against %d rule(s) in force: "
            "%d noncompliant, %d ambiguous (needs deep check), %d compliant, "
            "%d not evaluated (named in the receipt). "
            "NOTE: rule citations in this proof of concept are synthetic placeholders, not "
            "verified law."
            % (receipt["evaluated"], receipt["scanned"], jurisdiction, as_of_date,
               receipt["rules_applied"], receipt["noncompliant"], receipt["ambiguous"],
               receipt["compliant"], receipt["not_evaluated_count"])
        ),
    }


def tool_simulate_rule_change(args):
    """What-if against a proposed threshold. Labelled EXPLORATORY; records nothing.

    The mode label is the whole safeguard here, so it is data in three places: `mode`,
    `mode_meaning`, and inside `answer_summary` where a summarising model is most likely to
    reproduce it. A simulated count that loses its label becomes a compliance figure, which is
    the worst confusion this system can produce -- worse than a ranked sample read as complete,
    because the number looks exactly like an official one.
    """
    jurisdiction = (args.get("jurisdiction") or "").strip()
    as_of_date = (args.get("as_of_date") or "").strip()
    rule_id = (args.get("rule_id") or "").strip()
    proposed_value = args.get("proposed_value")

    if not jurisdiction or not as_of_date or not rule_id:
        return {"error": "jurisdiction, as_of_date and rule_id are all required"}
    if proposed_value is None:
        return {"error": "proposed_value is required"}

    result, rule = engine.simulate(jurisdiction, as_of_date, rule_id, proposed_value)

    direction = "tightened" if result["net_change"] > 0 else "loosened"
    return {
        "mode": "EXPLORATORY",
        "mode_meaning": (
            "Hypothetical simulation against an UNAPPROVED value. This is NOT a compliance "
            "determination and NOT an official finding. The proposed value has no approver, no "
            "effective date and no legal citation. Nothing was recorded, and no lease's "
            "compliance status changed. The approved rulebook is untouched."
        ),
        "simulation": {
            "rule_id": result["rule_id"],
            "baseline_version": result["rule_version_simulated_from"],
            "check": "%s %s <value>" % (result["check_field"], result["check_operator"]),
            "approved_value": result["approved_value"],
            "proposed_value": result["proposed_value"],
            "approved_citation": _cite(rule.get("citation")),
            "approved_by": rule.get("approved_by"),
        },
        "baseline_noncompliant": result["baseline_noncompliant"],
        "proposed_noncompliant": result["proposed_noncompliant"],
        "net_change": result["net_change"],
        # The actionable pair. Computed per lease inside one statement rather than by subtracting
        # two totals, which would be wrong for any change that moves leases in both directions.
        "newly_noncompliant": result["newly_noncompliant"],
        "newly_compliant": result["newly_compliant"],
        "unchanged_ambiguous": result["unchanged_ambiguous"],
        "unchanged_ambiguous_meaning": (
            "Leases whose clause carries no comparable value. A threshold change cannot resolve "
            "them: they need a human reading either way, at any threshold."
        ),
        "completeness_receipt": result["receipt"],
        "writes_findings": False,
        "record_created": "none",
        "IMPORTANT_citation_caveat": (
            "THE APPROVED VALUE AND CITATION SHOWN ARE SYNTHETIC PLACEHOLDERS FOR A PROOF OF "
            "CONCEPT, NOT VERIFIED LAW, AND THE PROPOSED VALUE IS HYPOTHETICAL. Neither may be "
            "repeated as a statement of statute or of pending legislation. State this whenever "
            "you report these numbers."
        ),
        "answer_summary": (
            "EXPLORATORY WHAT-IF, not an official determination and not recorded. If %s were %s "
            "from %s to %s, noncompliant %s leases would go from %d to %d (%+d). %d leases would "
            "newly violate and %d would newly comply. %d remain ambiguous either way. Every one "
            "of the %d leases in the population is accounted for in the receipt. Official "
            "compliance status is unchanged: use sweep_compliance for the approved answer. "
            "NOTE: values and citations in this proof of concept are synthetic placeholders."
            % (result["rule_id"], direction, result["approved_value"], result["proposed_value"],
               jurisdiction, result["baseline_noncompliant"], result["proposed_noncompliant"],
               result["net_change"], result["newly_noncompliant"], result["newly_compliant"],
               result["unchanged_ambiguous"], result["receipt"]["scanned"])
        ),
    }


def tool_explore_clauses(args):
    query_text = (args.get("query_text") or "").strip()
    jurisdiction = (args.get("jurisdiction") or "").strip() or None
    k = args.get("k") or 10

    if not query_text:
        return {"error": "query_text is required"}

    try:
        hits, population = explore.rank(query_text, jurisdiction, k)
    except explore.BedrockUnavailable as exc:
        # Degrade LOUDLY. No stub rationales: a caller cannot distinguish a fabricated
        # explanation from a real one, so none is offered.
        return {
            "mode": "INTERPRETIVE",
            "degraded": "bedrock_unreachable",
            "error": str(exc),
            "guidance": (
                "Semantic exploration is unavailable because the embedding model could not be "
                "reached. No results are returned and nothing has been inferred. Exhaustive "
                "compliance checks via sweep_compliance are unaffected -- they use no model."
            ),
        }

    # Classify in PARALLEL. Measured sequentially, one Claude call is ~2.7s, so k=25 would take
    # ~65s and breach Quick's fixed 60-second MCP timeout -- the tool would fail with HTTP 424
    # having already done all the work. The calls are I/O-bound, so a small thread pool collapses
    # that to a few seconds while keeping per-hit attribution intact.
    assessments = explore.classify_many(query_text, [h["text"] for h in hits])

    results, degraded = [], None
    for h, outcome in zip(hits, assessments):
        entry = {
            "lease_id": h["lease_id"],
            "community": h["community"],
            "state": h["state"],
            "clause_citation": h["citation"],
            "clause_text": h["text"],
            "rank_basis": "semantic similarity within the filtered population",
        }
        if outcome.get("error"):
            degraded = outcome["error"]
            entry["assessment"] = None
            entry["assessment_reason"] = (
                "not assessed: the model was unreachable, and no explanation is invented"
            )
        else:
            entry["assessment"] = outcome["band"]
            entry["assessment_reason"] = outcome["reason"]
            # No determination is anonymous, even an interpretive one.
            entry["determination"] = {
                "method": "deep_check",
                "model_id": outcome["model_id"],
                "prompt": outcome["prompt"],
                "response": outcome["raw"],
            }
        results.append(entry)

    payload = {
        "mode": "INTERPRETIVE",
        "mode_meaning": (
            "Ranked sample based on semantic similarity plus model assessment. This is NOT a "
            "completed audit and NOT a count. Clauses outside the returned ranking may also match."
        ),
        "ranking_receipt": {
            "population_basis": "filter_then_rank",
            "jurisdiction": jurisdiction or "all states",
            "population_pinned": population,
            "returned": len(results),
            "claim": (
                "top %d of %d clauses by similarity. This response makes NO completeness claim: "
                "no structured field encodes this concept, so an exhaustive answer to this "
                "question does not exist. Use sweep_compliance for population questions."
                % (len(results), population)
            ),
        },
        "writes_findings": False,
        "results": results,
    }
    if degraded:
        payload["degraded"] = "bedrock_unreachable"
        payload["degraded_detail"] = degraded
    return payload


def tool_get_finding(args):
    finding_id = (args.get("finding_id") or "").strip()
    if not finding_id:
        return {"error": "finding_id is required"}

    rows = db.query(
        """
        SELECT f.*, l.community, l.state, l.jurisdiction, l.signed_date,
               r.citation AS rule_citation, r.approved_by, r.approved_date,
               r.check_field, r.check_operator, r.check_value, r.effective_date
          FROM findings f
          JOIN leases l USING (lease_id)
          JOIN rulebook r ON r.rule_id = f.rule_id AND r.version = f.rule_version
         WHERE f.finding_id = :finding_id
        """,
        {"finding_id": finding_id},
    )
    if not rows:
        return {"error": "no finding with id %s" % finding_id}
    f = rows[0]

    return {
        "mode": "OFFICIAL",
        "finding_id": f["finding_id"],
        "sweep_id": f["sweep_id"],
        "status": f["status"],
        "band": f["band"],
        "band_meaning": {
            "clear_violation": "Deterministic numeric or presence comparison failed. Machine final.",
            "probable": "Model-assessed as likely noncompliant. Needs human sign-off.",
            "needs_review": "No structured value was available, so no deterministic answer exists.",
        }.get(f["band"]),
        "lease": {
            "lease_id": f["lease_id"],
            "community": f["community"],
            "state": f["state"],
            "jurisdiction": f["jurisdiction"],
            "signed_date": str(f["signed_date"]),
        },
        "rule": {
            "rule_id": f["rule_id"],
            "version": f["rule_version"],
            "citation": _cite(f["rule_citation"]),
            "check": "%s %s %s" % (f["check_field"], f["check_operator"], f["check_value"]),
            "effective_date": str(f["effective_date"]),
            "approved_by": f["approved_by"],
            "approved_date": str(f["approved_date"]),
        },
        "evidence": {
            "clause_text": f["clause_text"],
            "clause_citation": f["clause_citation"],
            "extracted_value": f["extracted_value"],
            "required_value": f["required_value"],
        },
        "determination": {
            "method": f["method"],
            "comparison": f["comparison"],
            "engine_version": f["engine_version"],
            "as_of_date": str(f["as_of_date"]),
            "made_at": str(f["created_at"]),
        },
        "review_note": (
            "This PoC is read-only: confirming, overruling, or assigning a finding is a human act "
            "requiring a named reviewer and a reason, and is not exposed as a tool."
        ),
        "IMPORTANT_citation_caveat": (
            "THE LEGAL CITATION IN THIS FINDING IS A SYNTHETIC PLACEHOLDER FOR A PROOF OF "
            "CONCEPT. IT IS NOT VERIFIED LAW AND MUST NOT BE REPEATED AS A STATEMENT OF STATUTE. "
            "The approver name is fictional."
        ),
    }


def tool_list_rules(args):
    jurisdiction = (args.get("jurisdiction") or "").strip()
    as_of_date = (args.get("as_of_date") or "").strip()
    topic = (args.get("topic") or "").strip() or None
    if not jurisdiction or not as_of_date:
        return {"error": "jurisdiction and as_of_date are both required"}

    rules = db.resolve_rules(jurisdiction, topic, as_of_date)
    return {
        "mode": "OFFICIAL",
        "jurisdiction": jurisdiction,
        "as_of_date": as_of_date,
        "topic": topic,
        "rules_in_force": [
            {
                "rule_id": r["rule_id"],
                "version": r["version"],
                "topic": r["topic"],
                "check": "%s %s %s" % (r["check_field"], r["check_operator"], r["check_value"]),
                "on_missing_field": r["on_missing_field"],
                "citation": _cite(r["citation"]),
                "effective_date": str(r["effective_date"]),
                "approved_by": r["approved_by"],
                "risk_weight": r["risk_weight"],
            }
            for r in rules
        ],
        "versioning_note": (
            "Rules are versioned and never edited in place. Asking for an earlier as_of_date "
            "returns the rules that applied then, which is what makes a past determination "
            "reconstructable."
        ),
        "IMPORTANT_citation_caveat": (
            "THE LEGAL CITATIONS BELOW ARE SYNTHETIC PLACEHOLDERS FOR A PROOF OF CONCEPT. THEY "
            "ARE NOT VERIFIED LAW AND MUST NOT BE REPEATED AS STATEMENTS OF STATUTE. Approver "
            "names are fictional. State this whenever you report a citation from this system. "
            "The mechanism being demonstrated is versioning and citation-carrying, not the "
            "content of any rule."
        ),
    }


HANDLERS = {
    "sweep_compliance": tool_sweep_compliance,
    "simulate_rule_change": tool_simulate_rule_change,
    "explore_clauses": tool_explore_clauses,
    "get_finding": tool_get_finding,
    "list_rules": tool_list_rules,
}
