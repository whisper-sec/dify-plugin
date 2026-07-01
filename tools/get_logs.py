from typing import Any, Generator

from dify_plugin import Tool
from dify_plugin.entities.tool import ToolInvokeMessage

from tools.whisper_api import WhisperControlError, control_call


class GetLogsTool(Tool):
    def _invoke(
        self, tool_parameters: dict[str, Any]
    ) -> Generator[ToolInvokeMessage, None, None]:
        args: dict[str, Any] = {}

        agent = (tool_parameters.get("agent") or "").strip()
        if agent:
            args["agent"] = agent

        kind = (tool_parameters.get("kind") or "").strip()
        if kind and kind != "all":
            args["kind"] = kind

        for key in ("from", "to"):
            val = (tool_parameters.get(key) or "").strip()
            if val:
                args[key] = val

        limit = tool_parameters.get("limit")
        if limit not in (None, "", 0):
            try:
                args["limit"] = int(limit)
            except (TypeError, ValueError):
                pass  # be liberal: ignore a non-numeric limit, use the server default

        try:
            records = control_call(self.runtime.credentials, "logs", args)
        except WhisperControlError as exc:
            yield self.create_text_message(f"Log query failed: {exc.detail}")
            yield self.create_json_message(
                {"error": exc.detail, "status": exc.status}
            )
            return

        yield self.create_text_message(f"{len(records)} event(s) in this window")
        yield self.create_json_message({"count": len(records), "events": records})
