"""Local check of the MCP protocol layer -- no AWS calls, no deploy needed.

Exists because the expensive failure in task 2 is a malformed handshake or a Draft-3 inputSchema,
and both are detectable here in a second rather than after a five-minute deploy plus a Quick
registration that fails with a generic "Creation failed".
"""

import json
import sys

sys.path.insert(0, "mcp_server")
from handler import TOOLS, lambda_handler  # noqa: E402


def post(payload):
    return json.loads(
        lambda_handler(
            {
                "rawPath": "/mcp",
                "requestContext": {"http": {"method": "POST"}},
                "body": json.dumps(payload),
            },
            None,
        )["body"]
        or "{}"
    )


failures = []


def check(label, ok, detail=""):
    print("%s %s%s" % ("PASS" if ok else "FAIL", label, (" -- %s" % detail) if detail else ""))
    if not ok:
        failures.append(label)


# 1. initialize handshake
r = post({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
check("initialize returns protocolVersion + serverInfo",
      "result" in r and "protocolVersion" in r["result"] and "serverInfo" in r["result"],
      json.dumps(r.get("result", {}).get("serverInfo", {})))

# 2. initialized notification -> no response body (202)
raw = lambda_handler(
    {"rawPath": "/mcp", "requestContext": {"http": {"method": "POST"}},
     "body": json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"})}, None)
check("initialized notification returns 202 with no body", raw["statusCode"] == 202)

# 3. tools/list
r = post({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
tools = r.get("result", {}).get("tools", [])
names = [t["name"] for t in tools]
check("tools/list returns every tool in the contract",
      sorted(names) == sorted(["check_connection", "sweep_compliance", "simulate_rule_change",
                               "explore_clauses", "get_finding", "list_rules"]),
      ", ".join(names))
N_TOOLS = len(names)

# 3b. protocol version negotiation: a client asking for an older revision must be answered with
#     the version it asked for, not our newest.
r = post({"jsonrpc": "2.0", "id": 21, "method": "initialize",
          "params": {"protocolVersion": "2025-03-26"}})
check("initialize echoes the client's requested protocol version",
      r.get("result", {}).get("protocolVersion") == "2025-03-26")

# 3c. a tool with only-optional parameters is an odd shape for a strict validator; assert we
#     declare at least one required parameter per tool.
check("every tool declares a non-empty required array",
      all(len(t["inputSchema"].get("required", [])) >= 1 for t in TOOLS))

# 4. THE constraint that silently breaks Quick publish: JSON Schema Draft 7 compliance.
#    `required` must be an array at the schema root, never a boolean inside a property.
schema_ok, why = True, []
for t in TOOLS:
    schema = t["inputSchema"]
    if not isinstance(schema.get("required", []), list):
        schema_ok = False
        why.append("%s: root `required` is not an array" % t["name"])
    for prop_name, prop in (schema.get("properties") or {}).items():
        if "required" in prop:
            schema_ok = False
            why.append("%s.%s: Draft 3 `required` inside a property" % (t["name"], prop_name))
    if not t.get("description"):
        schema_ok = False
        why.append("%s: missing description (it is what steers Quick's agent)" % t["name"])
check("every inputSchema is Draft 7 compliant", schema_ok, "; ".join(why))

# 5. tools/call -> pong, wrapped in MCP content blocks
r = post({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
          "params": {"name": "check_connection", "arguments": {"note": "hello from smoke test"}}})
content = r.get("result", {}).get("content", [])
payload = json.loads(content[0]["text"]) if content else {}
check("tools/call check_connection returns pong and echoes the note",
      payload.get("message") == "pong" and payload.get("echo") == "hello from smoke test")

# 6. unknown tool -> JSON-RPC error, not a crash
r = post({"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "nope"}})
check("unknown tool returns INVALID_PARAMS", r.get("error", {}).get("code") == -32602)

# 7. malformed body -> parse error, not a 500
raw = lambda_handler({"rawPath": "/mcp", "requestContext": {"http": {"method": "POST"}},
                      "body": "{not json"}, None)
check("malformed body returns a JSON-RPC parse error",
      raw["statusCode"] == 200 and json.loads(raw["body"])["error"]["code"] == -32700)

# 8. discovery + health routes answer without auth
raw = lambda_handler({"rawPath": "/.well-known/oauth-protected-resource",
                      "requestContext": {"http": {"method": "GET"}}}, None)
check("protected-resource metadata route answers", raw["statusCode"] == 200)
raw = lambda_handler({"rawPath": "/health", "requestContext": {"http": {"method": "GET"}}}, None)
check("health route answers", raw["statusCode"] == 200)


# 12. Tool definitions must stay within the conservative field set Quick's control plane accepts.
#     Quick completed the handshake, received the tool list, then rejected it with a validation
#     error -- so anything beyond name/description/inputSchema is treated as guilty until proven
#     otherwise, and plain ASCII is required.
ALLOWED_TOOL_FIELDS = {"name", "description", "inputSchema"}
extra, nonascii = [], []
for t in TOOLS:
    extra += ["%s.%s" % (t["name"], k) for k in t if k not in ALLOWED_TOOL_FIELDS]
    for label, text in [("description", t["description"])] + [
        ("%s.description" % p, v.get("description", ""))
        for p, v in (t["inputSchema"].get("properties") or {}).items()
    ]:
        if not all(ord(c) < 128 for c in text):
            nonascii.append("%s.%s" % (t["name"], label))
check("tools declare no fields beyond name/description/inputSchema", not extra, ", ".join(extra))
check("tool text is plain ASCII", not nonascii, ", ".join(nonascii))


# 14-16. Content negotiation: a client advertising text/event-stream must get SSE framing, and a
# client that does not must still get plain JSON. Quick sends
# `accept: application/json, text/event-stream`.
raw = lambda_handler(
    {"rawPath": "/mcp",
     "requestContext": {"http": {"method": "POST"}},
     "headers": {"accept": "application/json, text/event-stream",
                 "content-type": "application/json"},
     "body": json.dumps({"jsonrpc": "2.0", "id": "q-1", "method": "tools/list", "params": {}})},
    None,
)
check("SSE requested -> content-type is text/event-stream",
      raw["headers"]["content-type"] == "text/event-stream")
check("SSE body carries the data: prefix and blank-line terminator",
      raw["body"].startswith("event: message\ndata: ") and raw["body"].endswith("\n\n"))
parsed = json.loads(raw["body"].split("data: ", 1)[1].strip())
check("SSE payload is the JSON-RPC response, id preserved",
      parsed.get("id") == "q-1" and len(parsed["result"]["tools"]) == N_TOOLS)

raw = lambda_handler(
    {"rawPath": "/mcp",
     "requestContext": {"http": {"method": "POST"}},
     "headers": {"accept": "application/json", "content-type": "application/json"},
     "body": json.dumps({"jsonrpc": "2.0", "id": 9, "method": "tools/list", "params": {}})},
    None,
)
check("plain JSON requested -> content-type stays application/json",
      raw["headers"]["content-type"] == "application/json"
      and len(json.loads(raw["body"])["result"]["tools"]) == N_TOOLS)

TOTAL_ALL = 17
print("%d/%d local checks pass (with SSE negotiation)" % (TOTAL_ALL - len(failures), TOTAL_ALL))
sys.exit(1 if failures else 0)
