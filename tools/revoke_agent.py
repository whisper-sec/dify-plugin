from typing import Any, Generator

from dify_plugin import Tool
from dify_plugin.entities.tool import ToolInvokeMessage

from tools.whisper_api import (
    NotFoundError,
    WhisperControlError,
    control_call,
    field,
    first,
)

# The status an older control plane put in an ok row when nothing matched.
_NOT_FOUND_STATUSES = ("not_found", "notfound", "not-found")


def _truthy(value: Any) -> bool:
    """Accept the confirm flag liberally: true / 'true' / 'yes' / '1' / 'on'."""
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("true", "yes", "1", "on")


class RevokeAgentTool(Tool):
    def _invoke(
        self, tool_parameters: dict[str, Any]
    ) -> Generator[ToolInvokeMessage, None, None]:
        agent = (tool_parameters.get("agent") or "").strip()
        if not agent:
            raise ValueError(
                "An agent selector is required. Provide `agent` - the agent id or its "
                "/128 address."
            )

        if not _truthy(tool_parameters.get("confirm")):
            msg = (
                f"Refusing to revoke '{agent}' - revocation is irreversible. "
                "Set confirm=true to proceed."
            )
            yield self.create_text_message(msg)
            yield self.create_json_message({"revoked": False, "reason": "not_confirmed"})
            return

        try:
            records = control_call(
                self.runtime.credentials, "revoke", {"agent": agent}
            )
        except NotFoundError as exc:
            yield from self._nothing_revoked(agent, exc.detail)
            return
        except WhisperControlError as exc:
            yield self.create_text_message(f"Revoke failed: {exc.detail}")
            out: dict[str, Any] = {"error": exc.detail, "status": exc.status}
            if exc.code:
                out["code"] = exc.code
            if exc.retryable is not None:
                out["retryable"] = exc.retryable
            yield self.create_json_message(out)
            return

        record = first(records)
        item = record.get("item") if isinstance(record.get("item"), dict) else {}
        status = field(record, "status", "state") or field(item, "status", "state")
        if str(status or "").strip().lower() in _NOT_FOUND_STATUSES:
            message = field(record, "message", "detail") or field(
                item, "message", "detail"
            )
            yield from self._nothing_revoked(agent, message)
            return
        status = status or "revoked"
        yield self.create_text_message(f"{agent}: {status}")
        yield self.create_json_message(record or {"agent": agent, "status": status})

    def _nothing_revoked(
        self, agent: str, message: Any
    ) -> Generator[ToolInvokeMessage, None, None]:
        """A revoke that matched nothing: a clear answer, never a retry.

        The control plane answers NOT_FOUND when no agent of the caller's
        matches the selector, including one that was already revoked. That is
        a final answer: running the tool again cannot change it.
        """
        text = str(message or "").strip() or (
            f"no agent of yours matches '{agent}'. If you revoked it before, "
            "there is nothing left to revoke"
        )
        if text.lower().startswith("nothing was revoked"):
            shown = text[0].upper() + text[1:]
        else:
            shown = f"Nothing was revoked: {text}"
        yield self.create_text_message(shown)
        yield self.create_json_message(
            {
                "agent": agent,
                "revoked": False,
                "status": "not_found",
                "code": "NOT_FOUND",
                "retryable": False,
                "message": text,
            }
        )
