"""Task 1 done-check against the deployed stack.

Asserts the two claims task 1 makes: a client-credentials token reaches the MCP server and gets
`pong`; no token gets 401. Also walks the full handshake Quick will perform, so a protocol
mismatch surfaces here rather than inside Quick's opaque registration flow.

Reads stack outputs from outputs.json; fetches the client secret from Cognito at runtime so no
secret is ever written to disk.
"""

import json
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

with open("outputs.json") as f:
    out = json.load(f)["QuickPocStack"]

MCP_URL = out["McpUrl"]
TOKEN_ENDPOINT = out["TokenEndpoint"]
CLIENT_ID = out["ClientId"]
SCOPE = out["Scope"]
POOL_ID = out["Issuer"].rsplit("/", 1)[-1]

failures = []


def check(label, ok, detail=""):
    print("%s %s%s" % ("PASS" if ok else "FAIL", label, (" -- %s" % detail) if detail else ""))
    if not ok:
        failures.append(label)


def get_secret():
    return subprocess.check_output(
        ["aws", "cognito-idp", "describe-user-pool-client",
         "--user-pool-id", POOL_ID, "--client-id", CLIENT_ID,
         "--query", "UserPoolClient.ClientSecret", "--output", "text"],
        text=True,
    ).strip()


def _urlopen(req, timeout):
    """urlopen restricted to https.

    Every caller here passes a fixed https endpoint read from outputs.json (CDK stack output) --
    never external or user-supplied input -- but the scheme is asserted explicitly rather than
    left as an assumption a reader (or a scanner) has to trust.
    """
    url = req.full_url if isinstance(req, urllib.request.Request) else req
    if not url.startswith("https://"):
        raise ValueError("refusing to open non-https URL: %r" % url)
    return urllib.request.urlopen(req, timeout=timeout)  # nosec B310 # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected


def get_token(secret):
    body = urllib.parse.urlencode(
        {"grant_type": "client_credentials", "client_id": CLIENT_ID,
         "client_secret": secret, "scope": SCOPE}
    ).encode()
    req = urllib.request.Request(
        TOKEN_ENDPOINT, data=body,
        headers={"content-type": "application/x-www-form-urlencoded"},
    )
    with _urlopen(req, timeout=20) as r:
        return json.loads(r.read())["access_token"]


def rpc(payload, token=None):
    headers = {"content-type": "application/json"}
    if token:
        headers["authorization"] = "Bearer %s" % token
    req = urllib.request.Request(MCP_URL, data=json.dumps(payload).encode(), headers=headers)
    try:
        with _urlopen(req, timeout=30) as r:
            raw = r.read().decode()
            return r.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        return e.code, None


# --- 1. the negative case first: no token must not reach the server -----------------------
status, _ = rpc({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
check("unauthenticated MCP call is rejected", status == 401, "HTTP %s" % status)

status, _ = rpc({"jsonrpc": "2.0", "id": 1, "method": "initialize"},
                token="not-a-real-token")  # nosec B106 -- deliberately invalid test value, not a
                # real credential; this check exists to assert malformed bearer tokens get a 401.
check("malformed bearer token is rejected", status == 401, "HTTP %s" % status)

# --- 2. token acquisition (exactly what Quick will do) -----------------------------------
token = None
try:
    token = get_token(get_secret())
    check("client-credentials token issued", bool(token), "%d chars" % len(token))
except Exception as exc:
    check("client-credentials token issued", False, "%s: %s" % (type(exc).__name__, exc))

if not token:
    print("\ncannot continue without a token")
    sys.exit(1)

# --- 3. the handshake Quick performs -----------------------------------------------------
status, r = rpc({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                 "params": {"protocolVersion": "2025-06-18",
                            "capabilities": {},
                            "clientInfo": {"name": "verify", "version": "0"}}}, token)
ok = status == 200 and "result" in (r or {}) and "protocolVersion" in r["result"]
check("initialize succeeds over HTTPS", ok,
      json.dumps((r or {}).get("result", {}).get("serverInfo", {})))

status, r = rpc({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}, token)
tools = (r or {}).get("result", {}).get("tools", [])
check("tools/list returns the check_connection tool", status == 200 and len(tools) == 1,
      ", ".join(t["name"] for t in tools))

status, r = rpc({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                 "params": {"name": "check_connection", "arguments": {"note": "task-1 done check"}}}, token)
payload = {}
try:
    payload = json.loads(r["result"]["content"][0]["text"])
except Exception:
    pass
check("check_connection tool returns pong", payload.get("message") == "pong",
      "echo=%r" % payload.get("echo"))

# --- 4. open discovery routes (Quick reads these before it has a token) ------------------
for label, url in (("health", out["HealthUrl"]),
                   ("protected-resource metadata",
                    MCP_URL.replace("/mcp", "/.well-known/oauth-protected-resource"))):
    try:
        with _urlopen(url, timeout=20) as r:
            body = json.loads(r.read())
        check("%s route answers without auth" % label, r.status == 200,
              json.dumps(body)[:120])
    except Exception as exc:
        check("%s route answers without auth" % label, False, str(exc))

total = 7
print("\n%d/%d deployed checks pass" % (total - len(failures), total))
sys.exit(1 if failures else 0)
