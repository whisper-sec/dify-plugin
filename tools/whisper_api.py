"""Thin, keyless client for Whisper's public agent-identity API.

Host: https://rdap.whisper.online  (anonymous - no API key, no account).
Endpoints used by this plugin:
  GET /verify-identity?ip=<addr>   -> identity verdict
  GET /ip/<addr>                   -> RDAP record
  GET /ip/<addr>/transparency      -> tamper-evident issuance log
  GET /ip/<addr>/lookups           -> inbound lookup feed
"""

from typing import Any, Optional

import requests

BASE_URL = "https://rdap.whisper.online"
TIMEOUT = 15


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


def whisper_get(path: str, params: Optional[dict[str, Any]] = None) -> dict[str, Any]:
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
        headers={"Accept": "application/json"},
        timeout=TIMEOUT,
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
