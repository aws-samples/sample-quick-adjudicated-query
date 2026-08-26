"""MCP server for the Quick lease-compliance PoC.

Task 1 scope: protocol plumbing only, with a single throwaway `ping` tool. The real four-tool
contract (sweep / explore / get_finding / list_rules) arrives in task 5 — deliberately, so that
Quick's MCP handshake (the least-documented step, and risk #1 in design.md) is proven against a
trivial tool before anything real depends on it.

Protocol: JSON-RPC 2.0 over streamable HTTP, per the MCP specification. API Gateway terminates TLS
and validates the JWT ahead of this function, so there is no auth code here.

Two constraints from Amazon Quick's MCP docs are honoured by construction:
  1. Tool `inputSchema` MUST be JSON Schema Draft 7 or later -- `required` is an array at the
     schema root, never a boolean inside a property. Draft 3 syntax passes discovery and then
     fails at publish with a generic "Creation failed", which is expensive to debug.
  2. MCP operations have a fixed 60-second timeout (HTTP 424 on breach). Nothing here may block.
"""

import json
import logging
import os

logger = logging.getLogger()
logger.setLevel(logging.INFO)

PROTOCOL_VERSION = "2025-06-18"
# Versions this server can speak. On `initialize` the client's requested version is echoed back
# when we know it, rather than always answering with our newest -- a client that asked for an
# older revision and is answered with a newer one is entitled to abandon the connection.
SUPPORTED_PROTOCOL_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")
SERVER_NAME = "lease-compliance-poc"
SERVER_VERSION = "0.1.0"

# JSON-RPC 2.0 error codes (https://www.jsonrpc.org/specification#error_object)
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603


# --- tool registry ---------------------------------------------------------
#
# Tool descriptions are load-bearing: they are the only thing steering Quick's agent when it
# chooses a tool, and Quick snapshots the tool list at registration time (changing tools later
# requires deleting and recreating the integration). They get written once, carefully, in task 5.

# Schema shape is deliberately conservative after Quick rejected the first attempt with
# "One or more parameters is invalid":
#   - `required` is a NON-EMPTY array. An empty `required: []` is legal in Draft 6+ but Draft 4
#     validators reject it, and a tool with no required parameter at all is an unusual shape for
#     a validator to meet. `note` is therefore required.
#   - no `additionalProperties` key -- legal everywhere, but it is one more thing to be strict
#     about and buys nothing here.
# Once the handshake is proven this shape is the template for the real four-tool contract.

# The tool contract lives in tools.py. Schema conventions established in task 2 and enforced by
# smoke_local.py: JSON Schema Draft 7 (`required` is an array at the schema root), only
# name/description/inputSchema, plain ASCII, non-empty required array.
#
# `check_connection` is retained alongside the four real tools: it is the one tool that can prove
# the transport is alive without touching the database, which is the first thing worth knowing when
# something breaks mid-demo.
CHECK_CONNECTION = {
    # Deliberately NOT named `ping`: that collides with the protocol-level `ping` method in MCP
    # itself, and an ambiguity between a transport keepalive and a callable tool is not worth
    # risking.
    "name": "check_connection",
    "description": (
        "Connectivity check for the lease compliance server. Returns a fixed acknowledgement and "
        "echoes the supplied note. Carries no lease data and makes no compliance determination. "
        "Use it only to verify that the connection is live."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "note": {
                "type": "string",
                "description": "Text to echo back in the response.",
            }
        },
        "required": ["note"],
    },
}


def tool_ping(args):
    return {
        "ok": True,
        "server": SERVER_NAME,
        "version": SERVER_VERSION,
        "message": "pong",
        "echo": args.get("note"),
    }


# Imported lazily inside a try so that a database or Bedrock import problem cannot take down the
# whole server: check_connection must still answer, which is what makes it useful for triage.
try:
    import tools as _tools

    TOOLS = [CHECK_CONNECTION] + _tools.TOOLS
    HANDLERS = dict(_tools.HANDLERS)
    HANDLERS["check_connection"] = tool_ping
    IMPORT_ERROR = None
except Exception as _exc:  # pragma: no cover - surfaced via /health and tool errors
    logger.exception("tool module failed to import")
    TOOLS = [CHECK_CONNECTION]
    HANDLERS = {"check_connection": tool_ping}
    IMPORT_ERROR = "%s: %s" % (type(_exc).__name__, _exc)

TOOLS_BY_NAME = {t["name"]: t for t in TOOLS}


# --- JSON-RPC plumbing -----------------------------------------------------


def _result(request_id, payload):
    return {"jsonrpc": "2.0", "id": request_id, "result": payload}


def _error(request_id, code, message):
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def _tool_result(payload, is_error=False):
    """MCP tools return content blocks, not bare JSON.

    The whole payload is serialised into one text block so callers -- and the raw-JSON moment in
    the demo -- see exactly what the engine produced, with nothing dropped in translation.
    """
    return {
        "content": [{"type": "text", "text": json.dumps(payload, indent=2, default=str)}],
        "isError": is_error,
    }


def handle_rpc(message):
    """Dispatch one JSON-RPC message. Returns a response dict, or None for notifications."""
    if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
        return _error(None, INVALID_REQUEST, "expected a JSON-RPC 2.0 message")

    method = message.get("method")
    request_id = message.get("id")
    params = message.get("params") or {}

    # Notifications (no id) expect no response body -- notably `notifications/initialized`,
    # which clients send immediately after the handshake.
    is_notification = "id" not in message

    if method == "initialize":
        requested = params.get("protocolVersion")
        agreed = requested if requested in SUPPORTED_PROTOCOL_VERSIONS else PROTOCOL_VERSION
        logger.info("initialize: client requested %r -> answering %r", requested, agreed)
        return _result(
            request_id,
            {
                "protocolVersion": agreed,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
            },
        )

    if method in ("notifications/initialized", "notifications/cancelled"):
        return None

    if method == "ping":
        # Protocol-level liveness check, distinct from the `ping` *tool*.
        return _result(request_id, {})

    if method == "tools/list":
        return _result(request_id, {"tools": TOOLS})

    if method == "tools/call":
        name = params.get("name")
        args = params.get("arguments") or {}
        if name not in HANDLERS:
            return _error(request_id, INVALID_PARAMS, "unknown tool: %s" % name)
        try:
            return _result(request_id, _tool_result(HANDLERS[name](args)))
        except Exception as exc:  # surfaced to the caller as a tool error, not a 500
            return _result(
                request_id,
                _tool_result({"error": type(exc).__name__, "detail": str(exc)}, is_error=True),
            )

    if is_notification:
        return None
    return _error(request_id, METHOD_NOT_FOUND, "unsupported method: %s" % method)


# --- Lambda entry point ----------------------------------------------------


def _http(status, body, content_type="application/json"):
    return {
        "statusCode": status,
        "headers": {"content-type": content_type, "cache-control": "no-store"},
        "body": body if isinstance(body, str) else json.dumps(body),
    }


def _sse(status, payload):
    """Frame a JSON-RPC response as a single Server-Sent Event.

    Streamable HTTP permits a server to answer a POST either with `application/json` or with an
    SSE stream, and the client declares what it accepts. Amazon Quick's client sends
    `accept: application/json, text/event-stream`, and its published parsing behaviour is built
    around stripping a `data:` prefix -- so when it asks for a stream, give it a stream. Plain
    JSON is kept for clients that do not ask for SSE.

    One event, then the stream ends: this server is stateless request/response, so there is
    nothing further to push.
    """
    body = "event: message\ndata: %s\n\n" % json.dumps(payload, default=str)
    return {
        "statusCode": status,
        "headers": {
            "content-type": "text/event-stream",
            "cache-control": "no-store",
            "connection": "keep-alive",
        },
        "body": body,
    }


def lambda_handler(event, context):
    path = (event.get("rawPath") or "/").rstrip("/") or "/"
    method = (event.get("requestContext", {}).get("http", {}).get("method") or "POST").upper()

    # Log the full request. Quick's client-side validation errors are opaque ("One or more
    # parameters is invalid"), so the only way to tell a token problem from a protocol problem
    # from a schema problem is to see exactly what it asked for and what we answered.
    headers = {k.lower(): v for k, v in (event.get("headers") or {}).items()}
    logger.info(
        "REQ %s %s accept=%r content-type=%r ua=%r body=%s",
        method,
        path,
        headers.get("accept"),
        headers.get("content-type"),
        headers.get("user-agent"),
        (event.get("body") or "")[:2000],
    )

    # Unauthenticated discovery documents. Quick reads protected-resource metadata to learn where
    # to get a token; API Gateway leaves these routes open deliberately (they contain no data).
    if path == "/.well-known/oauth-protected-resource":
        issuer = os.environ.get("OAUTH_ISSUER", "")
        return _http(
            200,
            {
                "resource": os.environ.get("RESOURCE_URL", ""),
                "authorization_servers": [issuer] if issuer else [],
                "scopes_supported": [s for s in os.environ.get("OAUTH_SCOPES", "").split() if s],
                "bearer_methods_supported": ["header"],
            },
        )

    if path == "/health":
        return _http(200, {"ok": IMPORT_ERROR is None, "server": SERVER_NAME,
                           "version": SERVER_VERSION,
                           "tools": [t["name"] for t in TOOLS],
                           "import_error": IMPORT_ERROR})

    # Streamable HTTP allows a client to open a GET stream for server-initiated messages, and to
    # DELETE a session. This server is stateless request/response, so both are answered politely
    # rather than with a 405 that a strict client could read as a broken endpoint.
    if method == "GET":
        return _http(405, {"error": "this MCP server is stateless; use POST"})
    if method == "DELETE":
        return _http(204, "")
    if method != "POST":
        return _http(405, {"error": "method not allowed"})

    raw = event.get("body") or ""
    if event.get("isBase64Encoded"):
        import base64

        raw = base64.b64decode(raw).decode("utf-8")

    try:
        message = json.loads(raw)
    except (ValueError, TypeError):
        return _http(200, _error(None, PARSE_ERROR, "body is not valid JSON"))

    wants_sse = "text/event-stream" in (headers.get("accept") or "")

    # A client may batch messages in one array.
    if isinstance(message, list):
        responses = [r for r in (handle_rpc(m) for m in message) if r is not None]
        if not responses:
            return _http(202, "")
        return _sse(200, responses) if wants_sse else _http(200, responses)

    response = handle_rpc(message)
    if response is None:
        logger.info("RES 202 (notification, no body) for method=%r", message.get("method"))
        return _http(202, "")

    logger.info("RES 200 (%s) method=%r body=%s", "sse" if wants_sse else "json",
                message.get("method"), json.dumps(response, default=str)[:3000])
    return _sse(200, response) if wants_sse else _http(200, response)
