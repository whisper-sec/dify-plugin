from typing import Any, Generator

from dify_plugin import Tool
from dify_plugin.entities.tool import ToolInvokeMessage

from tools.whisper_api import WhisperControlError, control_call, field, first


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
        except WhisperControlError as exc:
            yield self.create_text_message(f"Revoke failed: {exc.detail}")
            yield self.create_json_message(
                {"error": exc.detail, "status": exc.status}
            )
            return

        record = first(records)
        status = field(record, "status", "state") or "revoked"
        yield self.create_text_message(f"{agent}: {status}")
        yield self.create_json_message(record or {"agent": agent, "status": status})
