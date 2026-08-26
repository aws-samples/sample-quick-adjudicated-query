"""Print the raw tool payload a caller receives.

The argument this backs is that every safeguard lives in the DATA, not in a rendering -- so the
artifact has to be the payload itself, unedited. `acceptance.py` cannot serve this: it prints
PASS/FAIL lines with truncated detail strings, never a full response.

Uses the same OAuth client-credentials flow and the same SSE-framed JSON-RPC exchange as
acceptance.py, so what you see here is byte-for-byte what Amazon Quick receives.

Run:
    .venv/bin/python show_payload.py                        # list_rules for US/TX (read-only)
    .venv/bin/python show_payload.py list_rules
    .venv/bin/python show_payload.py explore_clauses
    .venv/bin/python show_payload.py sweep_compliance       # WRITES findings; asks first
    .venv/bin/python show_payload.py get_finding '{"finding_id": "F-..."}'
    .venv/bin/python show_payload.py list_rules --wire       # also show the SSE framing

Any tool accepts an explicit JSON argument object as the second positional argument.
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

MCP_URL = OUT["McpUrl"]
POOL_ID = OUT["Issuer"].rsplit("/", 1)[-1]

AS_OF = "2026-07-31"

# Defaults chosen to match the demo. sweep_compliance is scoped to late_fees so the payload
# matches the numbers in moments 1 and 2 (10,111 noncompliant / 689 ambiguous) rather than the
# all-rules totals.
DEFAULT_ARGS = {
    "list_rules": {"jurisdiction": "US/TX", "as_of_date": AS_OF},
    "sweep_compliance": {"jurisdiction": "US/TX", "as_of_date": AS_OF, "topic": "late_fees"},
    "explore_clauses": {
        "query_text": "clauses where the resident gives up the right to sue",
        "jurisdiction": "US/TX",
        "k": 5,
    },
    # The demo's what-if: 5% -> 3% is 10,111 -> 17,515 noncompliant. Writes nothing, so unlike
    # sweep_compliance this is safe to run at any point during a demo.
    "simulate_rule_change": {
        "jurisdiction": "US/TX",
        "as_of_date": AS_OF,
        "rule_id": "TX-LATEFEE-CAP",
        "proposed_value": 3,
    },
    "check_connection": {"note": "post-registration transport check"},
    "get_finding": {},  # finding_id must be supplied
}

# sweep_compliance records official findings. Everything else only reads.
WRITES = {"sweep_compliance"}


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
    """Fetch a client-credentials token. The secret is read at runtime, never stored."""
    try:
        secret = subprocess.check_output(
            ["aws", "cognito-idp", "describe-user-pool-client",
             "--user-pool-id", POOL_ID, "--client-id", OUT["ClientId"],
             "--query", "UserPoolClient.ClientSecret", "--output", "text"],
            text=True, stderr=subprocess.PIPE).strip()
    except subprocess.CalledProcessError as exc:
        # Expired credentials are the likeliest failure and the likeliest to happen mid-demo.
        # A one-line cause beats a stack trace when someone is watching.
        detail = (exc.stderr or "").strip().splitlines()
        hint = detail[-1] if detail else "aws cli exit %d" % exc.returncode
        if "ExpiredToken" in hint or "expired" in hint.lower():
            sys.exit("AWS credentials have expired. Refresh them and re-run.\n  %s" % hint)
        sys.exit("could not read the Cognito client secret.\n  %s" % hint)
    body = urllib.parse.urlencode({
        "grant_type": "client_credentials", "client_id": OUT["ClientId"],
        "client_secret": secret, "scope": OUT["Scope"]}).encode()
    req = urllib.request.Request(
        OUT["TokenEndpoint"], data=body,
        headers={"content-type": "application/x-www-form-urlencoded"})
    with _urlopen(req, timeout=20) as r:
        return json.loads(r.read())["access_token"]


def call(name, arguments):
    """Invoke a tool exactly as Quick does. Returns (wire_body, payload, elapsed)."""
    payload = {"jsonrpc": "2.0", "id": "moment-5", "method": "tools/call",
               "params": {"name": name, "arguments": arguments}}
    req = urllib.request.Request(
        MCP_URL, data=json.dumps(payload).encode(),
        headers={
            "content-type": "application/json",
            # The header Quick sends. Answering it with plain JSON completes the handshake and
            # then fails opaquely, which is why the SSE branch is what gets exercised.
            "accept": "application/json, text/event-stream",
            "authorization": "Bearer %s" % token(),
        })
    t0 = time.time()
    with _urlopen(req, timeout=90) as r:
        wire = r.read().decode()
    elapsed = time.time() - t0

    body = json.loads(wire.split("data: ", 1)[1].strip())
    if "error" in body:
        return wire, {"_rpc_error": body["error"]}, elapsed
    return wire, json.loads(body["result"]["content"][0]["text"]), elapsed


def main():
    argv = [a for a in sys.argv[1:] if a != "--wire"]
    show_wire = "--wire" in sys.argv

    tool = argv[0] if argv else "list_rules"
    if tool not in DEFAULT_ARGS:
        sys.exit("unknown tool %r; expected one of: %s"
                 % (tool, ", ".join(sorted(DEFAULT_ARGS))))

    args = json.loads(argv[1]) if len(argv) > 1 else dict(DEFAULT_ARGS[tool])
    if tool == "get_finding" and not args.get("finding_id"):
        sys.exit('get_finding needs an id: show_payload.py get_finding \'{"finding_id": "F-..."}\'')

    if tool in WRITES:
        print("NOTE: %s records official findings and a sweep row in the database." % tool)
        print("      It also becomes the sweep the QuickSight dashboard defaults to.")
        if input("      Continue? [y/N] ").strip().lower() not in ("y", "yes"):
            sys.exit("aborted")

    print("=" * 78)
    print("POST %s" % MCP_URL)
    print("tools/call %s %s" % (tool, json.dumps(args)))
    print("=" * 78)

    wire, payload, elapsed = call(tool, args)

    if show_wire:
        # The SSE framing is itself a finding: plain JSON completes the handshake and then fails
        # inside Quick with an opaque error, so the transport shape is worth seeing at least once.
        print("\n--- wire response (SSE-framed, truncated) ---")
        print(wire[:400] + ("..." if len(wire) > 400 else ""))
        print("--- end wire ---\n")

    print(json.dumps(payload, indent=2, default=str))
    print()
    print("-" * 78)
    print("%d bytes, %.1fs" % (len(json.dumps(payload)), elapsed))
    # The moment-5 argument, checked against the payload actually returned rather than asserted.
    for label, present in (
        ("mode label", "mode" in payload),
        ("completeness receipt", "completeness_receipt" in payload),
        ("ranking receipt", "ranking_receipt" in payload),
        ("not_evaluated list", "not_evaluated" in (payload.get("completeness_receipt") or {})),
        ("citation caveat", "IMPORTANT_citation_caveat" in payload),
        ("population statistics", "violation_spread" in payload),
        ("preview warning", "preview_warning" in payload),
        ("writes-nothing declaration", payload.get("writes_findings") is False),
        ("no record created", payload.get("record_created") == "none"),
    ):
        if present:
            print("  present in payload: %s" % label)
    print("-" * 78)


if __name__ == "__main__":
    main()
