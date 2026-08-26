"""Generate the synthetic lease corpus and its ground-truth manifest.

Deterministic: a fixed seed means the corpus regenerates byte-identically, so the manifest's counts
stay true and the acceptance suite can assert receipt == manifest.

The manifest is the point. A completeness claim is only demonstrable if something independent of
the engine knows the right answer: the generator seeds a known number of violations per
(state, topic, rule), writes those counts down, and the sweep's receipt has to match them. Without
it the demo would be asserting that the engine agrees with itself.

    .venv/bin/python gen_corpus.py            # writes corpus/ and manifest.json

NOTE: no PDFs and no extraction. Attribute records are seeded directly, because extraction quality
is the real-document spike's question, not this PoC's. What is demonstrated here is mechanism at
scale, never retrieval or extraction performance on the 150K real portfolio.
"""

import json
import os
import random

SEED = 20260731
TOTAL_LEASES = 50000

HERE = os.path.dirname(os.path.abspath(__file__))
OUT_DIR = os.path.join(HERE, "corpus")

# State weights. Texas is deliberately dominant so the demo's "evaluated ~23,000" moment is real
# rather than a rounding of a small number.
STATE_WEIGHTS = {
    "TX": 23000,
    "FL": 7000,
    "MI": 5500,
    "CA": 4500,
    "AZ": 3500,
    "NC": 2600,
    "GA": 2400,
    "CO": 1500,
}
assert sum(STATE_WEIGHTS.values()) == TOTAL_LEASES

COMMUNITY_NAMES = [
    "Maple Grove", "Cedar Ridge", "Sunset Villas", "Oak Hollow", "Palm Terrace",
    "Riverbend", "Whispering Pines", "Lakeview Estates", "Desert Vista", "Brookside",
    "Highland Park", "Willow Creek", "Sandpiper Bay", "Stonegate", "Meadowlark",
]

# Rules in force per state as of the demo date, mirroring db/rulebook.json. Kept here as the
# generator's own view so violation seeding can be counted per rule; migrate.py owns the
# authoritative rulebook.
RULES_AS_OF_DEMO = {
    "TX": [("TX-LATEFEE-CAP", 2, "late_fees", "late_fee_pct", "lte", 5),
           ("TX-EVICT-NOTICE", 1, "eviction_notice", "notice_period_days", "gte", 30),
           ("TX-RENTINC-NOTICE", 1, "rent_increase_notice", "rent_increase_notice_days", "gte", 60)],
    "FL": [("FL-LATEFEE-CAP", 1, "late_fees", "late_fee_pct", "lte", 5),
           ("FL-EVICT-NOTICE", 1, "eviction_notice", "notice_period_days", "gte", 30),
           ("FL-FLOOD-DISC", 1, "flood_disclosure", "flood_disclosure_present", "exists", None)],
    "MI": [("MI-LATEFEE-CAP", 1, "late_fees", "late_fee_pct", "lte", 10),
           ("MI-EVICT-NOTICE", 1, "eviction_notice", "notice_period_days", "gte", 30)],
    "CA": [("CA-LATEFEE-CAP", 1, "late_fees", "late_fee_pct", "lte", 6),
           ("CA-RENTINC-NOTICE", 1, "rent_increase_notice", "rent_increase_notice_days", "gte", 90)],
    "AZ": [("AZ-LATEFEE-CAP", 1, "late_fees", "late_fee_pct", "lte", 8),
           ("AZ-EVICT-NOTICE", 1, "eviction_notice", "notice_period_days", "gte", 30)],
    "NC": [("NC-LATEFEE-CAP", 1, "late_fees", "late_fee_pct", "lte", 5),
           ("NC-EVICT-NOTICE", 1, "eviction_notice", "notice_period_days", "gte", 30)],
    "GA": [("GA-LATEFEE-CAP", 1, "late_fees", "late_fee_pct", "lte", 10),
           ("GA-EVICT-NOTICE", 1, "eviction_notice", "notice_period_days", "gte", 30)],
    "CO": [("CO-EVICT-NOTICE", 1, "eviction_notice", "notice_period_days", "gte", 30),
           ("CO-RENTINC-NOTICE", 1, "rent_increase_notice", "rent_increase_notice_days", "gte", 60)],
}

# Target violation rates per (state, topic). TX late_fees is tuned to ~44% of 23,000 leases so the
# headline number lands near the 10,100 in the original ask.
VIOLATION_RATE = {
    ("TX", "late_fees"): 0.44,
    ("TX", "eviction_notice"): 0.06,
    ("TX", "rent_increase_notice"): 0.11,
    ("FL", "late_fees"): 0.18,
    ("FL", "eviction_notice"): 0.05,
    ("FL", "flood_disclosure"): 0.09,
    ("MI", "late_fees"): 0.07,
    ("MI", "eviction_notice"): 0.12,
    ("CA", "late_fees"): 0.15,
    ("CA", "rent_increase_notice"): 0.20,
    ("AZ", "late_fees"): 0.10,
    ("AZ", "eviction_notice"): 0.04,
    ("NC", "late_fees"): 0.16,
    ("NC", "eviction_notice"): 0.05,
    ("GA", "late_fees"): 0.06,
    ("GA", "eviction_notice"): 0.05,
    ("CO", "eviction_notice"): 0.07,
    ("CO", "rent_increase_notice"): 0.13,
}

# Fraction of clauses with NO extracted value -> the ambiguous bucket. These are neither compliant
# nor violations: they are "we cannot tell deterministically", and they must be counted and named,
# never quietly assumed compliant.
AMBIGUOUS_RATE = 0.03
UNREADABLE_COUNT = 40

UNREADABLE_REASONS = [
    "scanned fax, pages 8-14 illegible",
    "photocopy skew, fee schedule unreadable",
    "missing pages 3-9 in source PDF",
    "handwritten amendments not machine readable",
    "water-damaged original, partial scan only",
]

# --- clause text templates -------------------------------------------------
# Wording is varied so semantic ranking has something to work with, and so no single phrasing can
# be pattern-matched into looking like intelligence.

LATE_FEE_TEMPLATES = [
    "Resident shall pay a late charge equal to {pct} percent of the monthly lot rent if rent "
    "remains unpaid after the fifth day of the month.",
    "A late fee of {pct}% of monthly rent will be assessed on any payment received after the "
    "grace period stated in Section 4.",
    "In the event of late payment, Landlord may charge {pct} percent of the outstanding monthly "
    "rental amount as a late fee.",
    "Late charges are set at {pct} percent of base rent per occurrence and are due with the next "
    "monthly installment.",
]
LATE_FEE_AMBIGUOUS = [
    "Resident shall pay a reasonable late charge as determined by Landlord in accordance with "
    "applicable law.",
    "Late fees may be assessed at Landlord's discretion consistent with community policy then in "
    "effect.",
    "A late charge as permitted by applicable state law shall apply to overdue rent.",
]

NOTICE_TEMPLATES = [
    "Landlord may terminate this Agreement for nonpayment of rent upon {days} days written notice "
    "to Resident.",
    "Termination of tenancy requires not less than {days} days advance written notice delivered to "
    "the Resident's address of record.",
    "This Agreement may be terminated by Landlord after providing {days} days written notice "
    "specifying the grounds for termination.",
    "Upon default, Landlord shall provide Resident {days} days written notice prior to "
    "commencing eviction proceedings.",
]
NOTICE_AMBIGUOUS = [
    "Landlord shall provide reasonable advance written notice prior to termination as required by "
    "law.",
    "Termination notice shall be given in accordance with the notice period prescribed by "
    "applicable statute.",
]

RENTINC_TEMPLATES = [
    "Landlord shall provide {days} days written notice before any increase in monthly lot rent "
    "takes effect.",
    "Rent may be adjusted annually upon {days} days prior written notice to Resident.",
    "No increase in rent shall become effective until {days} days after written notice is "
    "delivered to Resident.",
]
RENTINC_AMBIGUOUS = [
    "Rent may be adjusted upon proper notice as required by applicable law.",
    "Landlord will provide advance notice of rent adjustments consistent with statutory "
    "requirements.",
]

FLOOD_TEMPLATES = [
    "FLOOD DISCLOSURE: This home is located in a designated special flood hazard area. Resident "
    "is advised to obtain flood insurance for personal property.",
    "Resident acknowledges receipt of the flood risk disclosure for this community as required by "
    "state law.",
]

# --- the exploratory scenario ---------------------------------------------
# Liability-waiver-flavoured special provisions. This is the semantic question: no structured
# attribute encodes "reads like a waiver", so it can only be found by meaning -- and therefore can
# only ever be RANKED, never exhaustively enumerated. That contrast is the demo's lesson.
WAIVER_CLAUSES = [
    "Resident agrees to hold Landlord harmless from any and all claims for personal injury "
    "arising from use of community facilities, including the pool and playground.",
    "Resident releases Landlord from liability for damage to personal property however caused, "
    "including damage resulting from Landlord's own negligence.",
    "By signing below, Resident waives any right to bring a claim against Landlord for injuries "
    "sustained on the common grounds.",
    "Landlord shall not be responsible for loss or injury of any kind, and Resident assumes all "
    "risk of harm while present in the community.",
    "Resident agrees that Landlord bears no responsibility for personal injury, and Resident "
    "covenants not to sue in connection with any such injury.",
    "Resident indemnifies and holds Landlord harmless against all liability, including claims "
    "arising from the condition of the premises.",
    "To the fullest extent permitted, Resident disclaims all claims against Landlord for bodily "
    "injury or property loss occurring anywhere in the community.",
]

# Near misses: superficially similar language that is NOT a liability waiver. They exist so the
# exploratory result is not trivially separable, which is what makes ranking an honest
# demonstration rather than a rigged one.
WAIVER_DISTRACTORS = [
    "Resident agrees to hold quiet enjoyment of the premises and shall not disturb neighbouring "
    "residents.",
    "Landlord shall not be responsible for delays in maintenance caused by supply shortages "
    "beyond its reasonable control.",
    "Resident waives the right to keep unregistered vehicles on the lot and agrees to remove them "
    "upon notice.",
    "Resident assumes responsibility for routine upkeep of the lot, including lawn care and "
    "seasonal debris removal.",
    "Landlord is not obligated to provide storage for personal property left after the tenancy "
    "ends.",
]

ORDINARY_PROVISIONS = [
    "Resident shall keep the lot free of debris and maintain the exterior of the home in good "
    "repair.",
    "Quiet hours are observed between 10:00 PM and 7:00 AM throughout the community.",
    "Guest parking is limited to designated spaces and may not exceed seven consecutive days.",
    "Pets must be registered with the community office and kept on leash in common areas.",
    "Resident shall not sublet the home or assign this Agreement without written consent.",
    "Trash collection occurs twice weekly; receptacles must be stored out of view between "
    "collections.",
]

WAIVER_SEED_COUNT = 150
DISTRACTOR_SEED_COUNT = 220

# Phrasing variation for the exploratory corpus.
#
# Without this the 150 waiver clauses draw from only 7 fixed strings, so a top-25 ranked result
# would show 25 near-identical rows -- which both looks like a bug and makes semantic ranking seem
# trivial. Varying the wording means the ranked list shows genuinely different clauses that share
# a MEANING rather than a template, which is the actual claim being demonstrated.
#
# Only the waiver and distractor clauses are varied (~370 texts). The ordinary provisions stay
# templated: they are population filler, never ranked into a result.
WAIVER_PREAMBLES = [
    "", "Notwithstanding any other provision of this Agreement, ",
    "As a condition of tenancy, ", "In consideration of the lease of the lot, ",
    "Except as prohibited by law, ", "To the extent permitted by applicable law, ",
]
WAIVER_SUFFIXES = [
    "", " This provision survives termination of the tenancy.",
    " Resident acknowledges having read and understood this paragraph.",
    " This paragraph applies to Resident, occupants, and guests alike.",
    " Resident has been advised to seek independent counsel regarding this clause.",
]
SECTION_CONTEXTS = [
    "", " See also the community rules addendum.",
    " This clause is in addition to the indemnity provisions above.",
]


def pick_value(operator, threshold, violating, rng):
    """Choose an extracted value that either satisfies or breaches the rule.

    Violation is decided FIRST and the value is chosen to match, so the manifest count is exact
    rather than a statistical estimate of what the engine will later find.
    """
    if operator == "lte":
        if violating:
            return rng.choice([threshold + 1, threshold + 2, threshold + 3, threshold + 5,
                               threshold + 5, threshold + 7, threshold + 10])
        return rng.choice([max(0, threshold - 3), max(0, threshold - 2),
                           max(1, threshold - 1), threshold, threshold])
    if operator == "gte":
        if violating:
            return rng.choice([max(1, threshold - 25), max(1, threshold - 15),
                               max(1, threshold - 10), max(1, threshold - 7),
                               max(1, threshold - 3), max(1, threshold - 1)])
        return rng.choice([threshold, threshold, threshold + 5, threshold + 15, threshold + 30])
    raise ValueError("pick_value does not handle operator %r" % operator)


def clause_for(topic, value, ambiguous, rng):
    """Return (text, extracted_dict) for a topic."""
    if topic == "late_fees":
        if ambiguous:
            return rng.choice(LATE_FEE_AMBIGUOUS), {}
        return rng.choice(LATE_FEE_TEMPLATES).format(pct=value), {"late_fee_pct": value}
    if topic == "eviction_notice":
        if ambiguous:
            return rng.choice(NOTICE_AMBIGUOUS), {}
        return rng.choice(NOTICE_TEMPLATES).format(days=value), {"notice_period_days": value}
    if topic == "rent_increase_notice":
        if ambiguous:
            return rng.choice(RENTINC_AMBIGUOUS), {}
        return (rng.choice(RENTINC_TEMPLATES).format(days=value),
                {"rent_increase_notice_days": value})
    if topic == "flood_disclosure":
        # Presence IS the value. A violation is the clause being ABSENT, handled by the caller.
        return rng.choice(FLOOD_TEMPLATES), {"flood_disclosure_present": True}
    raise ValueError("unknown topic %r" % topic)


def generate():
    rng = random.Random(SEED)

    leases = []
    clauses = []
    # manifest counts: violations[state][rule_id], ambiguous[state][topic], etc.
    manifest = {
        "seed": SEED,
        "total_leases": TOTAL_LEASES,
        "generated_for": "as_of_date 2026-07-31 rule versions",
        "by_state": {},
        "violations_by_rule": {},
        "ambiguous_by_rule": {},
        "unreadable": [],
        "exploratory": {},
    }

    # Decide which leases are unreadable up front: they are counted in `scanned` but never
    # `evaluated`, so they must not receive clauses at all.
    lease_index = 0
    all_ids = []
    for state, count in STATE_WEIGHTS.items():
        for i in range(count):
            all_ids.append("%s-%05d" % (state, i + 1))
    unreadable_ids = set(rng.sample(all_ids, UNREADABLE_COUNT))

    # Which leases carry the waiver-flavoured special provisions (the exploratory corpus).
    waiver_ids = set(rng.sample(all_ids, WAIVER_SEED_COUNT))
    remaining = [i for i in all_ids if i not in waiver_ids]
    distractor_ids = set(rng.sample(remaining, DISTRACTOR_SEED_COUNT))

    for state, count in STATE_WEIGHTS.items():
        rules = RULES_AS_OF_DEMO[state]
        manifest["by_state"][state] = {"leases": count, "unreadable": 0, "evaluable": 0}

        state_ids = ["%s-%05d" % (state, i + 1) for i in range(count)]

        # Pre-compute exact violation and ambiguity assignments per rule, so counts are decided
        # rather than sampled.
        assignments = {}
        for rule_id, _ver, topic, _field, operator, threshold in rules:
            readable_ids = [i for i in state_ids if i not in unreadable_ids]
            n = len(readable_ids)
            n_ambiguous = int(round(n * AMBIGUOUS_RATE))
            n_violating = int(round(n * VIOLATION_RATE[(state, topic)]))

            shuffled = readable_ids[:]
            rng.shuffle(shuffled)
            amb = set(shuffled[:n_ambiguous])
            viol = set(shuffled[n_ambiguous:n_ambiguous + n_violating])
            assignments[rule_id] = (amb, viol)

            manifest["violations_by_rule"].setdefault(state, {})[rule_id] = len(viol)
            manifest["ambiguous_by_rule"].setdefault(state, {})[rule_id] = len(amb)

        for lease_id in state_ids:
            unreadable = lease_id in unreadable_ids
            community = "%s %s" % (
                rng.choice(COMMUNITY_NAMES),
                rng.choice(["MHC", "Estates", "Community", "Park"]),
            )
            signed_year = rng.choice([2019, 2020, 2021, 2022, 2023, 2023, 2024, 2024, 2025])
            signed = "%d-%02d-%02d" % (signed_year, rng.randint(1, 12), rng.randint(1, 28))

            reason = None
            if unreadable:
                reason = rng.choice(UNREADABLE_REASONS)
                manifest["by_state"][state]["unreadable"] += 1
                manifest["unreadable"].append({"lease_id": lease_id, "reason": reason})
            else:
                manifest["by_state"][state]["evaluable"] += 1

            leases.append({
                "lease_id": lease_id,
                "community": community,
                "jurisdiction": "US/%s" % state,
                "state": state,
                "signed_date": signed,
                "readable": not unreadable,
                "unreadable_reason": reason,
            })

            if unreadable:
                # No clauses: extraction could not read the document. The receipt names it.
                continue

            for rule_id, _ver, topic, _field, operator, threshold in rules:
                amb, viol = assignments[rule_id]
                is_ambiguous = lease_id in amb
                is_violating = lease_id in viol

                if topic == "flood_disclosure":
                    # A violation here means the clause is ABSENT entirely, which is what the
                    # `exists` operator plus on_missing_field=noncompliant is for.
                    if is_violating:
                        continue
                    if is_ambiguous:
                        # Present but unreadable value -> still counts as ambiguous.
                        clauses.append({
                            "clause_id": "%s-%s" % (lease_id, topic),
                            "lease_id": lease_id, "topic": topic,
                            "citation": "S%d.%d, p.%d" % (rng.randint(3, 18), rng.randint(1, 9),
                                                          rng.randint(2, 24)),
                            "text": "Resident acknowledges receipt of applicable disclosures.",
                            "extracted": {},
                            "extraction_confidence": round(rng.uniform(0.41, 0.68), 3),
                        })
                        continue
                    text, extracted = clause_for(topic, True, False, rng)
                else:
                    value = None
                    if not is_ambiguous:
                        value = pick_value(operator, threshold, is_violating, rng)
                    text, extracted = clause_for(topic, value, is_ambiguous, rng)

                clauses.append({
                    "clause_id": "%s-%s" % (lease_id, topic),
                    "lease_id": lease_id,
                    "topic": topic,
                    "citation": "S%d.%d, p.%d" % (rng.randint(3, 18), rng.randint(1, 9),
                                                  rng.randint(2, 24)),
                    "text": text,
                    "extracted": extracted,
                    "extraction_confidence": (round(rng.uniform(0.41, 0.72), 3) if is_ambiguous
                                              else round(rng.uniform(0.88, 0.99), 3)),
                })

            # special_provisions: the exploratory corpus. Every readable lease gets one so the
            # semantic question has a full population to rank within.
            if lease_id in waiver_ids:
                # Composed rather than picked, so ranked results show clauses sharing a meaning
                # rather than repeats of one template.
                body = rng.choice(WAIVER_CLAUSES)
                pre = rng.choice(WAIVER_PREAMBLES)
                if pre:
                    body = body[0].lower() + body[1:]
                text = "%s%s%s%s" % (pre, body, rng.choice(WAIVER_SUFFIXES),
                                     rng.choice(SECTION_CONTEXTS))
                kind = "waiver"
            elif lease_id in distractor_ids:
                body = rng.choice(WAIVER_DISTRACTORS)
                pre = rng.choice(WAIVER_PREAMBLES)
                if pre:
                    body = body[0].lower() + body[1:]
                text = "%s%s%s" % (pre, body, rng.choice(WAIVER_SUFFIXES))
                kind = "distractor"
            else:
                text, kind = rng.choice(ORDINARY_PROVISIONS), "ordinary"

            clauses.append({
                "clause_id": "%s-special_provisions" % lease_id,
                "lease_id": lease_id,
                "topic": "special_provisions",
                "citation": "S%d.%d, p.%d" % (rng.randint(19, 26), rng.randint(1, 9),
                                              rng.randint(24, 40)),
                "text": text,
                "extracted": {},
                "extraction_confidence": round(rng.uniform(0.90, 0.99), 3),
                "_kind": kind,  # generator metadata; not ingested
            })

    manifest["exploratory"] = {
        "waiver_seeded": sum(1 for c in clauses if c.get("_kind") == "waiver"),
        "distractor_seeded": sum(1 for c in clauses if c.get("_kind") == "distractor"),
        "ordinary": sum(1 for c in clauses if c.get("_kind") == "ordinary"),
        "note": (
            "Waiver counts are seeded ground truth for judging RANKING quality only. They must "
            "never be presented as a completeness claim: no structured attribute encodes "
            "'reads like a waiver', so an exhaustive answer to that question does not exist."
        ),
    }
    manifest["totals"] = {
        "leases": len(leases),
        "clauses": len(clauses),
        "unreadable": len(manifest["unreadable"]),
        "embedded_clauses": sum(1 for c in clauses if c["topic"] == "special_provisions"),
    }

    return leases, clauses, manifest


def main():
    leases, clauses, manifest = generate()

    os.makedirs(OUT_DIR, exist_ok=True)
    with open(os.path.join(OUT_DIR, "leases.jsonl"), "w") as f:
        for row in leases:
            f.write(json.dumps(row) + "\n")
    with open(os.path.join(OUT_DIR, "clauses.jsonl"), "w") as f:
        for row in clauses:
            f.write(json.dumps(row) + "\n")
    with open(os.path.join(HERE, "manifest.json"), "w") as f:
        json.dump(manifest, f, indent=2)

    print("leases:  %6d" % len(leases))
    print("clauses: %6d" % len(clauses))
    print("unreadable: %d" % len(manifest["unreadable"]))
    print()
    print("TX ground truth (as-of 2026-07-31 rule versions):")
    for rule_id, n in sorted(manifest["violations_by_rule"]["TX"].items()):
        amb = manifest["ambiguous_by_rule"]["TX"][rule_id]
        print("  %-22s violations=%6d  ambiguous=%5d" % (rule_id, n, amb))
    print()
    print("exploratory corpus: %d waiver, %d distractor, %d ordinary" % (
        manifest["exploratory"]["waiver_seeded"],
        manifest["exploratory"]["distractor_seeded"],
        manifest["exploratory"]["ordinary"]))


if __name__ == "__main__":
    main()
