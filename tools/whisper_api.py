"""Whisper client for the Dify plugin - two tiers, one small module.

Tier 1 (keyless, anonymous) - the public identity API at
``https://rdap.whisper.online``. No API key, no account:
  GET /verify-identity?ip=<addr>   -> identity verdict
  GET /ip/<addr>                   -> RDAP record
  GET /ip/<addr>/transparency      -> tamper-evident issuance log
  GET /ip/<addr>/lookups           -> inbound lookup feed

The whisper.security graph (same two tiers) - ``POST
https://graph.whisper.online/api/query`` with
``{"query": "<cypher>", "parameters": {...}}``, envelope
``{columns, rows, statistics}`` (rows are objects keyed by column):
  keyless  -> the direct read procedures (whisper.assess / identify /
              explain / variants / walk / origins / history / psl.* /
              asSet / lookupTorRelay / db.schema), rate-limited
  with key -> unlimited, plus raw Cypher and the multi-step catalog
              flows (run via the gallery runner, SSE)

Tier 2 (with the user's API key) - the control plane at the same
endpoint. One Cypher verb, ``CALL whisper.agents({op:'…', args:{…}})``,
authenticated with the caller's ``whisper_live_`` key (``X-API-Key``):
  register / identity / list / policy / logs / revoke.

Robustness Principle (RFC 761): conservative in what we EMIT - every value
embedded in a Cypher literal is escaped so it can never break out of the map,
graph queries carry user values only as ``$``-parameters (never spliced into
the query text), and requests are strict, deterministic, keyed only by what
the caller passed; liberal in what we ACCEPT - both control-plane wire shapes
are decoded, an address is taken in any notation, and every failure surfaces
as a clear, helpful message rather than an opaque 500.
"""

import json
import os
from typing import Any, Optional

import requests

# Tier-1 keyless identity API (anonymous).
BASE_URL = "https://rdap.whisper.online"
# The whisper.security graph + control plane (one endpoint, two tiers).
CONTROL_URL = "https://graph.whisper.online/api/query"
GRAPH_URL = CONTROL_URL
# The gallery flow runner - executes a multi-step catalog flow (keyed, SSE).
FLOW_RUN_URL = "https://console.whisper.security/api/gallery/run"
# Docs live under docsBase + each catalog entry's docPath.
DOCS_BASE = "https://www.whisper.security"

TIMEOUT = 15
CONTROL_TIMEOUT = 30
# Flow runs are multi-step graph programs; the read timeout is per SSE chunk.
FLOW_TIMEOUT = (10, 120)
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


# --- the whisper.security graph: raw Cypher, direct reads, catalog flows ----------


def graph_call(
    credentials: Optional[dict[str, Any]],
    cypher: str,
    parameters: Optional[dict[str, Any]] = None,
    require_key: bool = False,
) -> dict[str, Any]:
    """POST a Cypher query to the graph; return the {columns,rows,statistics} envelope.

    Two-tier (Postel - auth is optional): the caller's key is sent iff configured.
    The direct read procedures answer keyless (rate-limited, ~100/window); raw
    Cypher keyless gets a depth-limited anonymous taste; a key lifts both. User
    values travel ONLY as $-parameters in the ``parameters`` map - they are never
    spliced into the query text, so a hostile value can never become Cypher.

    Failures arrive as RFC-7807 problem objects and are raised as a clear
    WhisperControlError, never an opaque 500.
    """
    key = require_api_key(credentials) if require_key else api_key(credentials)
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": USER_AGENT,
    }
    if key:
        headers["X-API-Key"] = key
    try:
        response = requests.post(
            GRAPH_URL,
            json={"query": cypher, "parameters": parameters or {}},
            headers=headers,
            timeout=CONTROL_TIMEOUT,
            proxies=_proxies(credentials),
        )
    except requests.RequestException as exc:
        raise WhisperControlError(
            f"graph endpoint unreachable at {GRAPH_URL}: {exc}"
        ) from exc

    try:
        body = response.json()
    except ValueError:
        raise WhisperControlError(
            "graph endpoint returned a non-JSON reply", status=response.status_code
        )

    if isinstance(body, dict) and "rows" in body and "columns" in body:
        return body

    # An RFC-7807 problem object ({type,title,status,detail,suggestions}).
    if isinstance(body, dict):
        detail = (
            body.get("detail")
            or body.get("title")
            or body.get("message")
            or "graph query failed"
        )
        status = body.get("status") or response.status_code
        if status == 429 and not key:
            detail += (
                " (keyless graph calls are rate-limited; add your Whisper API "
                "key in the plugin settings to lift the limit)"
            )
        raise WhisperControlError(
            detail, status=status, suggestions=body.get("suggestions")
        )
    raise WhisperControlError(
        "graph endpoint returned an unexpected reply", status=response.status_code
    )


# --- the query catalog (vendored from whisper-sec/whisper-catalog) -----------------

_CATALOG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "catalog.json")
_catalog_by_id: Optional[dict[str, dict[str, Any]]] = None


def catalog_entries() -> dict[str, dict[str, Any]]:
    """The catalog entries keyed by id (loaded once from tools/catalog.json)."""
    global _catalog_by_id
    if _catalog_by_id is None:
        with open(_CATALOG_PATH, encoding="utf-8") as fh:
            data = json.load(fh)
        _catalog_by_id = {e["id"]: e for e in data.get("entries", [])}
    return _catalog_by_id


def catalog_entry(recipe_id: str) -> dict[str, Any]:
    """One catalog entry by id, or a clear error naming every valid id."""
    entries = catalog_entries()
    entry = entries.get((recipe_id or "").strip())
    if entry is None:
        raise WhisperControlError(
            f"Unknown recipe '{recipe_id}'. Valid recipes: "
            + ", ".join(sorted(entries)),
            status=404,
        )
    return entry


def doc_url(entry: dict[str, Any]) -> str:
    """The docs deep-link for a catalog entry (docsBase + docPath)."""
    return DOCS_BASE + (entry.get("docPath") or "/docs")


def recipe_parameters(
    entry: dict[str, Any],
    value: str = "",
    extra: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Build the $-parameter map for a direct catalog entry.

    Liberal in what we accept: start from the entry's recorded defaults, map the
    caller's single ``value`` onto the entry's primary input (the input whose id
    is ``value``, else the first input), then let explicit ``extra`` parameters
    win. Everything stays a $-parameter - nothing is spliced into the Cypher.
    """
    params: dict[str, Any] = dict((entry.get("exec") or {}).get("params") or {})
    inputs = entry.get("inputs") or []
    if value:
        primary = next((i for i in inputs if i.get("id") == "value"), None)
        primary = primary or (inputs[0] if inputs else None)
        if primary and primary.get("paramName"):
            params[primary["paramName"]] = value
    for inp in inputs:
        name = inp.get("paramName")
        if name and name not in params and inp.get("default") is not None:
            params[name] = inp["default"]
    if extra:
        params.update(extra)
    return params


def direct_read(
    credentials: Optional[dict[str, Any]],
    recipe_id: str,
    value: str,
    extra: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Run a direct (single-Cypher) catalog entry; return {columns,rows,statistics}.

    The keyless read procedures work with no key at all; the entry's recorded
    access tier decides whether a key is required (only ``submit`` among the
    direct entries). A configured key is always sent - it lifts the rate limit.
    """
    entry = catalog_entry(recipe_id)
    exec_ = entry.get("exec") or {}
    if exec_.get("mode") != "direct":
        raise WhisperControlError(
            f"Recipe '{recipe_id}' is a multi-step flow - run it via run_recipe "
            "(it needs your API key).",
            status=400,
        )
    return graph_call(
        credentials,
        exec_["cypher"],
        recipe_parameters(entry, value, extra),
        require_key=entry.get("access") == "keyed",
    )


# --- catalog flows via the gallery runner (SSE) ------------------------------------


def _iter_sse(response: requests.Response):
    """Yield (event, data) pairs from an SSE stream, liberally.

    Handles multi-line ``data:`` fields per the SSE spec; unknown fields and
    comments are ignored; a data payload that is not JSON is skipped rather than
    failing the whole run.
    """
    event = ""
    data_lines: list[str] = []
    for raw in response.iter_lines(decode_unicode=True):
        if raw is None:
            continue
        line = raw.rstrip("\r")
        if line == "":
            if data_lines:
                try:
                    payload = json.loads("\n".join(data_lines))
                except ValueError:
                    payload = None
                if payload is not None:
                    yield (event or "message", payload)
            event = ""
            data_lines = []
            continue
        if line.startswith("event:"):
            event = line[len("event:"):].strip()
        elif line.startswith("data:"):
            data_lines.append(line[len("data:"):].lstrip())


def flow_run(
    credentials: Optional[dict[str, Any]],
    slug: str,
    value: str = "",
    param_values: Optional[dict[str, Any]] = None,
    max_rows: int = 50,
) -> dict[str, Any]:
    """Run a multi-step catalog flow via the gallery runner and collect its steps.

    Keyed only - the runner authenticates every step's graph reads with the
    caller's key (a keyless caller gets the clear two-tier message, not a 401).
    Body: {slug, value, paramValues}; the reply is an SSE stream (start /
    step-start / step / graph / complete / error) - each finished step's table
    is collected with its rows capped at ``max_rows``.
    """
    key = require_api_key(credentials)
    body: dict[str, Any] = {"slug": slug}
    if value:
        body["value"] = value
    if param_values:
        body["paramValues"] = param_values
    try:
        response = requests.post(
            FLOW_RUN_URL,
            json=body,
            headers={
                "X-API-Key": key,
                "Content-Type": "application/json",
                "Accept": "text/event-stream",
                "User-Agent": USER_AGENT,
                "X-Whisper-Client": USER_AGENT,
            },
            timeout=FLOW_TIMEOUT,
            stream=True,
            proxies=_proxies(credentials),
        )
    except requests.RequestException as exc:
        raise WhisperControlError(
            f"flow runner unreachable at {FLOW_RUN_URL}: {exc}"
        ) from exc

    if response.status_code != 200:
        try:
            problem = response.json()
        except ValueError:
            problem = {}
        raise WhisperControlError(
            problem.get("message")
            or problem.get("detail")
            or f"flow runner replied HTTP {response.status_code}",
            status=response.status_code,
        )

    steps: list[dict[str, Any]] = []
    summary: dict[str, Any] = {}
    try:
        for event, data in _iter_sse(response):
            if event == "step" and isinstance(data, dict):
                rows = data.get("rows") or []
                step: dict[str, Any] = {
                    "id": data.get("id"),
                    "title": data.get("title"),
                    "columns": data.get("columns") or [],
                    "rowCount": data.get("rowCount", len(rows)),
                    "rows": rows[:max_rows],
                }
                if len(rows) > max_rows:
                    step["truncated"] = True
                # The trailing presentation step carries the shaped report.
                if data.get("output") is not None:
                    step["output"] = data["output"]
                steps.append(step)
            elif event == "error" and isinstance(data, dict):
                raise WhisperControlError(
                    data.get("message") or "flow run failed",
                    status=500,
                )
            elif event == "complete" and isinstance(data, dict):
                summary = data
    finally:
        response.close()

    return {
        "slug": slug,
        "steps": steps,
        "stepCount": len(steps),
        "totalLatencyMs": summary.get("totalLatencyMs"),
    }


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
