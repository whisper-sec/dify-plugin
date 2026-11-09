# SPDX-License-Identifier: MIT
"""Revoke Agent: a revoke that matches nothing reads as "nothing was revoked".

The control plane answers HTTP 200 with the per-op row carrying status 404
and error code NOT_FOUND. An older plane answered with an ok row whose status
is "not_found". Both must come out as a clear, final answer that tells the
caller retrying will not help; any other failure keeps the server's message.
"""

from typing import Any

import pytest
import requests

from tools import whisper_api
from tools.revoke_agent import RevokeAgentTool
from tools.whisper_api import NotFoundError, WhisperControlError, _decode_envelope

COLUMNS = ["op", "ok", "status", "result", "error", "retry_after", "elapsed_ms"]
SERVER_MESSAGE = (
    "nothing was revoked: no agent of yours matches 'agent-a0'. If you revoked "
    "it before, there is nothing left to revoke"
)


def row(ok: bool, status: Any, result: Any = None, error: Any = None) -> dict:
    return {
        "columns": COLUMNS,
        "rows": [
            {
                "op": "revoke",
                "ok": ok,
                "status": status,
                "result": result,
                "error": error,
                "retry_after": None,
                "elapsed_ms": 12,
            }
        ],
        "statistics": {"rowCount": 1},
    }


NOT_FOUND_ROW = row(
    False,
    404,
    error={"code": "NOT_FOUND", "message": SERVER_MESSAGE, "retryable": False},
)


class FakeResponse:
    def __init__(self, body: Any, status: int = 200) -> None:
        self._body = body
        self.status_code = status

    def json(self) -> Any:
        return self._body


@pytest.fixture
def answer(monkeypatch):
    """Serve one canned reply to the control call and record the request."""
    seen: dict[str, Any] = {}

    def install(body: Any, status: int = 200) -> dict:
        def fake_post(url, json=None, headers=None, timeout=None, proxies=None):
            seen["url"] = url
            seen["query"] = (json or {}).get("query")
            seen["calls"] = seen.get("calls", 0) + 1
            return FakeResponse(body, status)

        monkeypatch.setattr(whisper_api.requests, "post", fake_post)
        return seen

    return install


def run(agent: str = "agent-a0", confirm: Any = True) -> tuple[list[str], list[dict]]:
    tool = RevokeAgentTool.from_credentials({"api_key": "whisper_live_test"})
    texts: list[str] = []
    objects: list[dict] = []
    for msg in tool._invoke({"agent": agent, "confirm": confirm}):
        inner = msg.message
        if hasattr(inner, "text"):
            texts.append(inner.text)
        else:
            objects.append(dict(inner.json_object))
    return texts, objects


# --- the decoder ----------------------------------------------------------------


def test_in_row_not_found_raises_not_found_error_with_server_message():
    with pytest.raises(NotFoundError) as caught:
        _decode_envelope(NOT_FOUND_ROW, 200)
    err = caught.value
    assert isinstance(err, WhisperControlError)
    assert err.code == "NOT_FOUND"
    assert err.status == 404
    assert err.retryable is False
    assert err.detail == SERVER_MESSAGE


def test_flat_not_found_envelope_raises_not_found_error():
    body = {
        "ok": False,
        "status": 404,
        "error": {"code": "NOT_FOUND", "message": SERVER_MESSAGE},
    }
    with pytest.raises(NotFoundError) as caught:
        _decode_envelope(body, 404)
    assert caught.value.detail == SERVER_MESSAGE


def test_bare_404_without_the_code_is_not_a_not_found_error():
    body = row(False, 404, error={"message": "no such route"})
    with pytest.raises(WhisperControlError) as caught:
        _decode_envelope(body, 200)
    assert not isinstance(caught.value, NotFoundError)
    assert caught.value.detail == "no such route"
    assert caught.value.status == 404


def test_other_in_row_error_keeps_code_message_and_retryable():
    body = row(
        False,
        403,
        error={"code": "FORBIDDEN", "message": "key lacks scope", "retryable": False},
    )
    with pytest.raises(WhisperControlError) as caught:
        _decode_envelope(body, 200)
    err = caught.value
    assert not isinstance(err, NotFoundError)
    assert (err.code, err.status, err.retryable) == ("FORBIDDEN", 403, False)
    assert err.detail == "key lacks scope"


def test_rfc7807_problem_detail_is_still_read():
    body = {"type": "about:blank", "title": "Unauthorized", "detail": "bad key", "status": 401}
    with pytest.raises(WhisperControlError) as caught:
        _decode_envelope(body, 401)
    assert caught.value.detail == "bad key"
    assert caught.value.status == 401


# --- the tool -----------------------------------------------------------------------


def test_successful_revoke_reports_revoked(answer):
    seen = answer(
        row(
            True,
            200,
            result={"columns": ["agent", "status"], "rows": [["agent-a0", "revoked"]]},
        )
    )
    texts, objects = run()
    assert texts == ["agent-a0: revoked"]
    assert objects == [{"agent": "agent-a0", "status": "revoked"}]
    assert "op:'revoke'" in seen["query"]


def test_in_row_not_found_says_nothing_was_revoked_and_not_retryable(answer):
    seen = answer(NOT_FOUND_ROW)
    texts, objects = run()
    assert texts == ["Nothing" + SERVER_MESSAGE[len("nothing"):]]
    assert objects == [
        {
            "agent": "agent-a0",
            "revoked": False,
            "status": "not_found",
            "code": "NOT_FOUND",
            "retryable": False,
            "message": SERVER_MESSAGE,
        }
    ]
    assert seen["calls"] == 1, "a revoke that matched nothing is never retried"


def test_older_plane_not_found_row_says_nothing_was_revoked(answer):
    answer(
        row(
            True,
            200,
            result={"columns": ["agent", "status"], "rows": [["agent-a0", "not_found"]]},
        )
    )
    texts, objects = run()
    assert texts[0].startswith("Nothing was revoked: ")
    assert objects[0]["revoked"] is False
    assert objects[0]["code"] == "NOT_FOUND"
    assert objects[0]["retryable"] is False


def test_older_plane_not_found_under_item_says_nothing_was_revoked(answer):
    answer(
        row(
            True,
            200,
            result={
                "columns": ["item"],
                "rows": [[{"agent": "agent-a0", "status": "not_found", "message": "gone"}]],
            },
        )
    )
    texts, objects = run()
    assert texts == ["Nothing was revoked: gone"]
    assert objects[0]["status"] == "not_found"


def test_other_error_reports_server_message_and_code(answer):
    answer(
        row(
            False,
            403,
            error={"code": "FORBIDDEN", "message": "key lacks scope", "retryable": False},
        )
    )
    texts, objects = run()
    assert texts == ["Revoke failed: key lacks scope"]
    assert objects == [
        {"error": "key lacks scope", "status": 403, "code": "FORBIDDEN", "retryable": False}
    ]


def test_transport_failure_is_a_clear_message(monkeypatch):
    def boom(*args, **kwargs):
        raise requests.ConnectionError("connection refused")

    monkeypatch.setattr(whisper_api.requests, "post", boom)
    texts, objects = run()
    assert texts[0].startswith("Revoke failed: control plane unreachable")
    assert objects[0]["status"] is None


def test_unconfirmed_revoke_never_calls_the_control_plane(answer):
    seen = answer(NOT_FOUND_ROW)
    texts, objects = run(confirm=False)
    assert objects == [{"revoked": False, "reason": "not_confirmed"}]
    assert "calls" not in seen
