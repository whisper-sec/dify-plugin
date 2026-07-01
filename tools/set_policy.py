from typing import Any, Generator

from dify_plugin import Tool
from dify_plugin.entities.tool import ToolInvokeMessage

from tools.whisper_api import WhisperControlError, control_call, csv_list


class SetPolicyTool(Tool):
    def _invoke(
        self, tool_parameters: dict[str, Any]
    ) -> Generator[ToolInvokeMessage, None, None]:
        args: dict[str, Any] = {}

        default_action = (tool_parameters.get("default_action") or "").strip()
        if default_action and default_action != "unchanged":
            args["default"] = default_action

        block = csv_list(tool_parameters.get("block"))
        if block:
            args["block"] = block
        allow = csv_list(tool_parameters.get("allow"))
        if allow:
            args["allow"] = allow

        reading = not args  # no changes requested -> read the current policy back

        try:
            records = control_call(self.runtime.credentials, "policy", args)
        except WhisperControlError as exc:
            yield self.create_text_message(f"Policy update failed: {exc.detail}")
            yield self.create_json_message(
                {"error": exc.detail, "status": exc.status}
            )
            return

        if reading:
            summary = f"Current policy: {len(records)} setting(s)"
        else:
            summary = "Policy updated"
        yield self.create_text_message(summary)
        yield self.create_json_message({"policy": records})
