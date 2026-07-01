"""Whisper client for the Dify plugin - two tiers, one small module.

Tier 1 (keyless, anonymous) - the public identity API at
``https://rdap.whisper.online``. No API key, no account:
  GET /verify-identity?ip=<addr>   -> identity verdict
  GET /ip/<addr>                   -> RDAP record
  GET /ip/<addr>/transparency      -> tamper-evident issuance log
  GET /ip/<addr>/lookups           -> inbound lookup feed

Tier 2 (with the user's API key) - the control plane at
``https://graph.whisper.security/api/query``. One Cypher verb,
``CALL whisper.agents({op:'…', args:{…}})``, authenticated with the
caller's ``whisper_live_`` key (``X-API-Key``):
  register / identity / list / policy / logs / revoke.

Robustness Principle (RFC 761): conservative in what we EMIT - every value
embedded in a Cypher literal is escaped so it can never break out of the map,
and requests are strict, deterministic, keyed only by what the caller passed;
liberal in what we ACCEPT - both control-plane wire shapes are decoded, an
address is taken in any notation, and every failure surfaces as a clear,
helpful message rather than an opaque 500.
"""

from typing import Any, Optional

import requests

# Tier-1 keyless identity API (anonymous).
BASE_URL = "https://rdap.whisper.online"
# Tier-2 control plane (needs the user's whisper_live_ API key).
CONTROL_URL = "https://graph.whisper.security/api/query"

TIMEOUT = 15
CONTROL_TIMEOUT = 30
USER_AGENT = "whisper-dify-plugin/1"


class WhisperControlError(Exception):
    """A helpful, secret-free control-plane failure (RFC-7807 shaped).

    ``detail`` is written to be surfaced verbatim to the operator - a clear,
    actionable message, never an opaque 500.
    """

    def __init__(
        self,
        detail: str,
        status: Optional[int] = None,
        suggestions: Optional[list] = None,
    ) -> None:
        super().__init__(detail)
        self.detail = detail
        self.status = status
        self.suggestions = suggestions or []


# --- address / credential helpers -------------------------------------------------


def normalize_address(tool_parameters: dict[str, Any]) -> str:
    """Accept an address liberally; fail with a clear, helpful message.

    IPv6 (compressed or expanded) and IPv4 literals are both accepted; the
    server does the parsing. We only strip surrounding whitespace and reject
    an empty value here so the caller gets an actionable error, never a 500.
    """
    address = (tool_parameters.get("address") or "").strip()
    if not address:
        raise ValueError(
            "An IP address is required. Provide `address` as an IPv6 (or IPv4) "
            "literal, e.g. 2a04:2a01:b69a:6717:e3b0:51ff:3bf7:f478."
        )
    return address


def api_key(credentials: Optional[dict[str, Any]]) -> str:
    """Return the caller's API key (trimmed), or "" when none is configured."""
    if not credentials:
        return ""
    return (credentials.get("api_key") or "").strip()


def require_api_key(credentials: Optional[dict[str, Any]]) -> str:
    """Return the API key, or raise a clear "add your key" error.

    The control tools (register / policy / logs / revoke) need a key; the
    keyless tools (verify / RDAP / transparency / lookups) do not. This is the
    one place that explains the two-tier model when a key is missing.
    """
    key = api_key(credentials)
    if not key:
        raise WhisperControlError(
            "This action needs your Whisper API key. Open the plugin settings, "
            "click Authorize, and paste your whisper_live_… key. (The keyless "
            "tools - Verify Agent Identity, Lookup RDAP Record, Get Transparency "
            "Log, Get Inbound Lookups - work with no key at all.)",
            status=401,
        )
    return key


def _proxies(credentials: Optional[dict[str, Any]]) -> Optional[dict[str, str]]:
    """Egress: route this request out through the agent's /128 when configured.

    When the operator runs ``whisper connect`` on the Dify host it prints a
    loopback proxy (``socks5h://127.0.0.1:<port>``) bound to the agent's
    routable Whisper /128. Point the plugin's ``egress_proxy`` credential at it
    and every call this plugin makes sources from that /128. When it is unset
    we return None and ``requests`` still honours the standard HTTP(S)_PROXY /
    ALL_PROXY environment (liberal in what we accept), so container-level egress
    also just works.
    """
    if not credentials:
        return None
    proxy = (credentials.get("egress_proxy") or "").strip()
    if not proxy:
        return None
    return {"http": proxy, "https": proxy}


# --- Tier 1: keyless identity API -------------------------------------------------


def whisper_get(
    path: str,
    params: Optional[dict[str, Any]] = None,
    credentials: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """GET a keyless endpoint and return its JSON body.

    The API returns a structured JSON body for both success and expected
    "no identity" cases (e.g. RDAP answers 404 with an RDAP error object for
    an address that anchors no Whisper agent). We surface that JSON verbatim
    so the agent gets a meaningful answer instead of an opaque HTTP failure;
    only genuine transport / non-JSON errors are raised.
    """
    response = requests.get(
        f"{BASE_URL}{path}",
        params=params,
        headers={
            # Liberal in what we accept: RDAP is served as application/rdap+json,
            # the others as application/json - ask for both so no endpoint 406s.
            "Accept": "application/rdap+json, application/json;q=0.9, */*;q=0.1",
            "User-Agent": USER_AGENT,
        },
        timeout=TIMEOUT,
        proxies=_proxies(credentials),
    )
    try:
        return response.json()
    except ValueError:
        response.raise_for_status()
        return {
            "error": "non_json_response",
            "status_code": response.status_code,
            "body": response.text[:500],
        }


# --- Tier 2: control plane (whisper.agents) ---------------------------------------


def _cypher_escape(s: str) -> str:
    """Render s safe inside a single-quoted Cypher literal.

    openCypher escapes a single quote by DOUBLING it; a backslash is doubled
    too so a trailing backslash can never escape the closing quote. Order
    matters: backslashes first, then quotes. A legitimate apostrophe just
    works; a breakout attempt stays trapped inside the literal.
    """
    return s.replace("\\", "\\\\").replace("'", "''")


def _cypher_lit(v: Any) -> str:
    """Render an arbitrary value as a Cypher literal (injection-proof)."""
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        return repr(v)
    if isinstance(v, str):
        return "'" + _cypher_escape(v) + "'"
    if isinstance(v, (list, tuple)):
        return "[" + ",".join(_cypher_lit(e) for e in v) + "]"
    if isinstance(v, dict):
        return _cypher_map(v)
    # Anything unexpected is stringified then quoted, so it can never inject.
    return "'" + _cypher_escape(str(v)) + "'"


def _cypher_map(m: dict[str, Any]) -> str:
    """Render a map literal {k:v,…} with keys sorted for deterministic output."""
    if not m:
        return "{}"
    parts = [f"{k}:{_cypher_lit(m[k])}" for k in sorted(m)]
    return "{" + ",".join(parts) + "}"


def build_agents_query(op: str, args: Optional[dict[str, Any]] = None) -> str:
    """Build the one control-plane verb: CALL whisper.agents({op, args})."""
    return f"CALL whisper.agents({{op:{_cypher_lit(op)}, args:{_cypher_map(args or {})}}})"


def _result_to_records(result: Any) -> list[dict[str, Any]]:
    """Turn a {columns,rows} result into column-keyed dicts (liberal shapes)."""
    if not isinstance(result, dict):
        return []
    columns = result.get("columns") or []
    rows = result.get("rows") or []
    records: list[dict[str, Any]] = []
    for row in rows:
        if isinstance(row, dict):
            records.append(row)
            continue
        if isinstance(row, list):
            rec: dict[str, Any] = {}
            for i, col in enumerate(columns):
                rec[col] = row[i] if i < len(row) else None
            records.append(rec)
    return records


def _decode_envelope(body: Any, status: int) -> list[dict[str, Any]]:
    """Normalise a control-plane reply to records; raise on failure.

    Liberal in what we accept - three shapes:
      1. {ok,status,result:{columns,rows},error}
      2. {rows:[{result:{columns,rows}}]}          (live Neo4j wrapper -> ok)
      3. a bare RFC-7807 problem object            (-> WhisperControlError)
    """
    if not isinstance(body, dict):
        raise WhisperControlError(
            "control plane returned an unexpected reply", status=status
        )

    # Shape 1: an explicit ok flag.
    if body.get("ok") is not None:
        if body.get("ok"):
            return _result_to_records(body.get("result"))
        err = body.get("error") or {}
        raise WhisperControlError(
            err.get("detail") or err.get("title") or "control plane reported failure",
            status=err.get("status") or status,
            suggestions=err.get("suggestions"),
        )

    # Shape 3: a bare problem object (no ok, no result/rows, problem-ish fields).
    has_problem = any(k in body for k in ("detail", "title", "type", "error"))
    if body.get("error") or (
        has_problem and "result" not in body and "rows" not in body
    ):
        err = body.get("error") or body
        raise WhisperControlError(
            err.get("detail") or err.get("title") or err.get("type")
            or "control plane reported failure",
            status=err.get("status") or status,
            suggestions=err.get("suggestions"),
        )

    # Shape 2: the live Neo4j wrapper - rows[0] is a per-op envelope
    # {op,ok,status,result,error,retry_after} - or a plain {columns,rows} table.
    rows = body.get("rows")
    if isinstance(rows, list):
        if not rows:
            return []
        head = rows[0]
        if isinstance(head, dict) and "ok" in head:
            if head.get("ok") is False:
                err = head.get("error") or {}
                raise WhisperControlError(
                    err.get("detail") or err.get("title") or err.get("type")
                    or "control plane reported failure",
                    status=err.get("status") or head.get("status") or status,
                    suggestions=err.get("suggestions"),
                )
            if head.get("result") is not None:
                return _result_to_records(head["result"])
            return [head]
        columns = body.get("columns")
        if isinstance(columns, list):
            return _result_to_records({"columns": columns, "rows": rows})
        return [r for r in rows if isinstance(r, dict)]

    # A top-level result, or a shapeless-but-valid object (read ops fail open).
    if body.get("result") is not None:
        return _result_to_records(body.get("result"))
    return []


def control_call(
    credentials: Optional[dict[str, Any]],
    op: str,
    args: Optional[dict[str, Any]] = None,
) -> list[dict[str, Any]]:
    """Run CALL whisper.agents({op, args}) and return the records.

    POSTs the documented body ({"query": "…"}) to the control plane with the
    caller's X-API-Key. Raises WhisperControlError on transport failure or an
    ok:false envelope, with a clear, secret-free detail.
    """
    key = require_api_key(credentials)
    query = build_agents_query(op, args)
    try:
        response = requests.post(
            CONTROL_URL,
            json={"query": query},
            headers={
                "X-API-Key": key,
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": USER_AGENT,
            },
            timeout=CONTROL_TIMEOUT,
            proxies=_proxies(credentials),
        )
    except requests.RequestException as exc:
        raise WhisperControlError(
            f"control plane unreachable at {CONTROL_URL}: {exc}"
        ) from exc

    try:
        body = response.json()
    except ValueError:
        raise WhisperControlError(
            "control plane returned a non-JSON reply", status=response.status_code
        )
    return _decode_envelope(body, response.status_code)


def first(records: list[dict[str, Any]]) -> dict[str, Any]:
    """The first record (control ops that return exactly one), or {}."""
    return records[0] if records else {}


def field(record: dict[str, Any], *names: str) -> Optional[Any]:
    """First present, non-empty value among aliased column names."""
    for name in names:
        if name in record and record[name] not in (None, ""):
            return record[name]
    return None


# --- egress (op:connect) secret hygiene -------------------------------------------

# The op:connect result carries the egress bearer (http_proxy / connection_string,
# both embed an et_ token) and, for WireGuard, a client_private_key. A Dify workflow
# variable or execution log must NEVER hold a live credential, so by default we emit
# only an ALLOWLIST of safe identity fields - conservative in what we emit (Postel): a
# field we do not explicitly recognise is dropped, so a future server field can never
# leak. For real egress, run `whisper connect` on the Dify host (it hands the bearer
# straight to a local proxy and prints only a bearer-free socks5h://127.0.0.1:<port>).
SAFE_CONNECT_KEYS = (
    "tier",
    "address",
    "addr128",
    "fqdn",
    "ptr",
    "state",
    "agent",
    "label",
    "verified",
)


def sanitize_connect(
    record: dict[str, Any], selector: str = ""
) -> dict[str, Any]:
    """Strip the egress bearer / private key; keep only safe identity fields.

    Returns the allowlisted fields plus a `proxy_hint` telling the operator how to
    bring up real, bearer-free egress on the Dify host. There is intentionally no
    opt-in to raw secrets here: a plugin tool's output flows into workflow data and
    logs, so we never surface a live credential.
    """
    out: dict[str, Any] = {}
    for key in SAFE_CONNECT_KEYS:
        if key in record and record[key] not in (None, ""):
            out[key] = record[key]
    agent_arg = f" --agent {selector}" if selector else ""
    out["proxy_hint"] = (
        f"On the Dify host run:  whisper connect{agent_arg}  - it prints a "
        "bearer-free local endpoint (socks5h://127.0.0.1:<port>) bound to this "
        "agent's /128. Point the Dify plugin_daemon/api/worker HTTP_PROXY (or this "
        "plugin's egress_proxy credential) at it and traffic sources from that /128. "
        "See EGRESS.md."
    )
    return out


def csv_list(raw: Optional[str]) -> list[str]:
    """Parse a comma/whitespace-separated string into a clean token list.

    Liberal in what we accept: 'a, b  c' and 'a,b,c' both yield [a,b,c]; empty
    in -> empty out.
    """
    if not raw:
        return []
    out: list[str] = []
    for chunk in str(raw).replace("\n", ",").split(","):
        for token in chunk.split():
            token = token.strip()
            if token:
                out.append(token)
    return out
