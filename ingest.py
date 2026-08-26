"""Load the generated corpus into Aurora and embed the exploratory clauses.

    .venv/bin/python ingest.py            # load + embed
    .venv/bin/python ingest.py --verify   # counts only, no writes

Deliberately a script, not a pipeline: ingestion architecture is explicitly not what this PoC
evaluates. What it must be is re-runnable and honest about what it loaded.

Embedding is restricted to `special_provisions` clauses (the exploratory corpus) and cached by
text hash, so a re-run makes zero Bedrock calls. Embedding all 179K clauses would cost more and
prove nothing extra: semantic ranking is only ever applied to the qualitative question.
"""

import hashlib
import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "mcp_server"))

HERE = os.path.dirname(os.path.abspath(__file__))
CORPUS = os.path.join(HERE, "corpus")
CACHE_PATH = os.path.join(HERE, "corpus", "embedding_cache.json")
EMBED_MODEL = "amazon.titan-embed-text-v2:0"
EMBED_DIMS = 1024


def load_env():
    with open(os.path.join(HERE, "outputs.json")) as f:
        out = json.load(f)["QuickPocStack"]
    os.environ.setdefault("DB_CLUSTER_ARN", out["DbClusterArn"])
    os.environ.setdefault("DB_SECRET_ARN", out["DbSecretArn"])
    os.environ.setdefault("DB_NAME", out["DbName"])


load_env()
import db  # noqa: E402

import boto3  # noqa: E402


def read_jsonl(name):
    with open(os.path.join(CORPUS, name)) as f:
        for line in f:
            yield json.loads(line)


def load_leases():
    rows = list(read_jsonl("leases.jsonl"))
    sql = """
        INSERT INTO leases (lease_id, community, jurisdiction, state, signed_date,
                            readable, unreadable_reason)
        VALUES (:lease_id, :community, :jurisdiction, :state, CAST(:signed_date AS DATE),
                :readable, :unreadable_reason)
        ON CONFLICT (lease_id) DO NOTHING
    """
    t0 = time.time()
    db.batch_execute(sql, rows)
    print("leases:  %6d loaded in %.1fs" % (len(rows), time.time() - t0))


def load_clauses():
    sql = """
        INSERT INTO clauses (clause_id, lease_id, topic, citation, text,
                             extracted, extraction_confidence)
        VALUES (:clause_id, :lease_id, :topic, :citation, :text,
                CAST(:extracted AS JSONB), :extraction_confidence)
        ON CONFLICT (clause_id) DO NOTHING
    """
    t0 = time.time()
    batch, total = [], 0
    for row in read_jsonl("clauses.jsonl"):
        batch.append({
            "clause_id": row["clause_id"],
            "lease_id": row["lease_id"],
            "topic": row["topic"],
            "citation": row["citation"],
            "text": row["text"],
            # extracted is JSONB; send as a JSON string with an explicit cast.
            "extracted": json.dumps(row["extracted"]),
            "extraction_confidence": row["extraction_confidence"],
        })
        if len(batch) >= 1000:
            db.batch_execute(sql, batch)
            total += len(batch)
            batch = []
            print("  clauses: %6d ... %.0fs" % (total, time.time() - t0))
    if batch:
        db.batch_execute(sql, batch)
        total += len(batch)
    print("clauses: %6d loaded in %.1fs" % (total, time.time() - t0))


# --- embeddings ------------------------------------------------------------


def load_cache():
    if os.path.exists(CACHE_PATH):
        with open(CACHE_PATH) as f:
            return json.load(f)
    return {}


def embed_special_provisions():
    """Embed distinct special_provisions texts, then attach vectors to their clauses.

    Distinct TEXTS, not clauses: the corpus draws from a fixed pool of phrasings, so ~50K clauses
    reduce to a couple of dozen unique strings. Embedding per clause would make tens of thousands
    of identical Bedrock calls for no additional information.
    """
    cache = load_cache()
    rows = db.query(
        "SELECT DISTINCT text FROM clauses WHERE topic = 'special_provisions'"
    )
    texts = [r["text"] for r in rows]
    print("special_provisions: %d distinct texts" % len(texts))

    bedrock = boto3.client("bedrock-runtime", region_name="us-east-1")
    calls = 0
    for text in texts:
        key = hashlib.sha256(text.encode()).hexdigest()
        if key in cache:
            continue
        resp = bedrock.invoke_model(
            modelId=EMBED_MODEL,
            body=json.dumps({"inputText": text, "dimensions": EMBED_DIMS}),
        )
        cache[key] = json.loads(resp["body"].read())["embedding"]
        calls += 1

    with open(CACHE_PATH, "w") as f:
        json.dump(cache, f)
    print("embeddings: %d Bedrock calls (%d served from cache)" % (calls, len(texts) - calls))

    # Attach vectors. One UPDATE per distinct text covers every clause sharing it.
    t0 = time.time()
    updated = 0
    for text in texts:
        key = hashlib.sha256(text.encode()).hexdigest()
        vec = cache[key]
        updated += db.execute(
            """
            UPDATE clauses
               SET embedding = CAST(:vec AS vector)
             WHERE topic = 'special_provisions'
               AND text = :text
               AND embedding IS NULL
            """,
            {"vec": "[" + ",".join("%.6f" % v for v in vec) + "]", "text": text},
        )
    print("embeddings attached to %d clauses in %.1fs" % (updated, time.time() - t0))


# --- verification ----------------------------------------------------------


def verify():
    with open(os.path.join(HERE, "manifest.json")) as f:
        manifest = json.load(f)

    failures = []

    def check(label, ok, detail=""):
        print("%s %s%s" % ("PASS" if ok else "FAIL", label, (" -- %s" % detail) if detail else ""))
        if not ok:
            failures.append(label)

    n_leases = db.query("SELECT count(*) AS n FROM leases")[0]["n"]
    n_clauses = db.query("SELECT count(*) AS n FROM clauses")[0]["n"]
    check("lease count matches manifest",
          n_leases == manifest["totals"]["leases"],
          "db=%d manifest=%d" % (n_leases, manifest["totals"]["leases"]))
    check("clause count matches manifest",
          n_clauses == manifest["totals"]["clauses"],
          "db=%d manifest=%d" % (n_clauses, manifest["totals"]["clauses"]))

    n_unreadable = db.query(
        "SELECT count(*) AS n FROM leases WHERE NOT readable")[0]["n"]
    check("unreadable count matches manifest",
          n_unreadable == manifest["totals"]["unreadable"],
          "db=%d manifest=%d" % (n_unreadable, manifest["totals"]["unreadable"]))

    check("every unreadable lease carries a named reason",
          db.query("SELECT count(*) AS n FROM leases "
                   "WHERE NOT readable AND (unreadable_reason IS NULL "
                   "OR unreadable_reason = '')")[0]["n"] == 0)

    check("unreadable leases have no clauses (extraction could not read them)",
          db.query("SELECT count(*) AS n FROM clauses c JOIN leases l USING (lease_id) "
                   "WHERE NOT l.readable")[0]["n"] == 0)

    tx = db.query("SELECT count(*) AS n FROM leases WHERE state = 'TX'")[0]["n"]
    check("TX population is ~23,000", tx == 23000, str(tx))

    # The headline number the demo rests on, checked against the DB rather than the generator:
    # TX leases whose extracted late_fee_pct breaches the v2 (5%) cap.
    tx_violations = db.query("""
        SELECT count(*) AS n
          FROM clauses c
          JOIN leases l USING (lease_id)
         WHERE l.state = 'TX'
           AND c.topic = 'late_fees'
           AND c.extracted ? 'late_fee_pct'
           AND (c.extracted->>'late_fee_pct')::numeric > 5
    """)[0]["n"]
    expected = manifest["violations_by_rule"]["TX"]["TX-LATEFEE-CAP"]
    check("TX late-fee violations in DB match manifest ground truth",
          tx_violations == expected, "db=%d manifest=%d" % (tx_violations, expected))

    tx_ambiguous = db.query("""
        SELECT count(*) AS n
          FROM clauses c JOIN leases l USING (lease_id)
         WHERE l.state = 'TX' AND c.topic = 'late_fees'
           AND NOT (c.extracted ? 'late_fee_pct')
    """)[0]["n"]
    check("TX late-fee ambiguous count matches manifest",
          tx_ambiguous == manifest["ambiguous_by_rule"]["TX"]["TX-LATEFEE-CAP"],
          "db=%d manifest=%d" % (tx_ambiguous,
                                 manifest["ambiguous_by_rule"]["TX"]["TX-LATEFEE-CAP"]))

    embedded = db.query(
        "SELECT count(*) AS n FROM clauses WHERE embedding IS NOT NULL")[0]["n"]
    check("every special_provisions clause is embedded",
          embedded == manifest["totals"]["embedded_clauses"],
          "db=%d manifest=%d" % (embedded, manifest["totals"]["embedded_clauses"]))

    # Semantic ranking sanity: the seeded waiver clauses must outrank ordinary provisions for a
    # waiver-flavoured query. This judges RANKING only -- it is never a completeness claim.
    probe = "clause where the resident gives up the right to sue for injury"
    bedrock = boto3.client("bedrock-runtime", region_name="us-east-1")
    resp = bedrock.invoke_model(
        modelId=EMBED_MODEL,
        body=json.dumps({"inputText": probe, "dimensions": EMBED_DIMS}))
    qvec = json.loads(resp["body"].read())["embedding"]
    top = db.query("""
        SELECT c.text, 1 - (c.embedding <=> CAST(:vec AS vector)) AS score
          FROM clauses c
         WHERE c.topic = 'special_provisions' AND c.embedding IS NOT NULL
         ORDER BY c.embedding <=> CAST(:vec AS vector)
         LIMIT 5
    """, {"vec": "[" + ",".join("%.6f" % v for v in qvec) + "]"})

    with open(os.path.join(CORPUS, "clauses.jsonl")) as f:
        waiver_texts = {json.loads(l)["text"] for l in f
                        if json.loads(l).get("_kind") == "waiver"}
    hits = sum(1 for r in top if r["text"] in waiver_texts)
    check("waiver-flavoured query ranks seeded waiver clauses top-5",
          hits >= 4, "%d/5 top hits are seeded waivers" % hits)

    print("\n%d/%d ingest checks pass" % (11 - len(failures), 11))
    return not failures


if __name__ == "__main__":
    if "--verify" in sys.argv:
        sys.exit(0 if verify() else 1)
    load_leases()
    load_clauses()
    embed_special_provisions()
    print()
    sys.exit(0 if verify() else 1)
