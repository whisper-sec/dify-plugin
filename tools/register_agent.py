from typing import Any, Generator

from dify_plugin import Tool
from dify_plugin.entities.tool import ToolInvokeMessage

from tools.whisper_api import WhisperControlError, control_call, field, first


class RegisterAgentTool(Tool):
    def _invoke(
        self, tool_parameters: dict[str, Any]
    ) -> Generator[ToolInvokeMessage, None, None]:
        name = (tool_parameters.get("name") or "").strip()
        if not name:
            raise ValueError(
                "An agent name is required. Provide `name` - the agent's human name "
                "(e.g. scout)."
            )

        args: dict[str, Any] = {"label": name}
        contact = (tool_parameters.get("contact_email") or "").strip()
        if contact:
            args["contact_email"] = contact

        try:
            records = control_call(self.runtime.credentials, "register", args)
        except WhisperControlError as exc:
            yield self.create_text_message(f"Register failed: {exc.detail}")
            yield self.create_json_message(
                {"error": exc.detail, "status": exc.status}
            )
            return

        record = first(records)
        address = field(record, "address", "addr128")
        summary = f"Registered agent '{name}'"
        if address:
            summary += f" - {address}"
        if field(record, "api_key"):
            summary += " (api_key returned once - store it now)"

        yield self.create_text_message(summary)
        yield self.create_json_message(record)
