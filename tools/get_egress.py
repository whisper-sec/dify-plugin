from typing import Any, Generator

from dify_plugin import Tool
from dify_plugin.entities.tool import ToolInvokeMessage

from tools.whisper_api import (
    WhisperControlError,
    control_call,
    field,
    first,
    sanitize_connect,
)


class GetEgressTool(Tool):
    def _invoke(
        self, tool_parameters: dict[str, Any]
    ) -> Generator[ToolInvokeMessage, None, None]:
        args: dict[str, Any] = {}
        agent = (tool_parameters.get("agent") or "").strip()
        if agent:
            args["agent"] = agent
        tier = (tool_parameters.get("tier") or "").strip()
        if tier:
            args["tier"] = tier

        try:
            records = control_call(self.runtime.credentials, "connect", args)
        except WhisperControlError as exc:
            yield self.create_text_message(f"Egress config failed: {exc.detail}")
            yield self.create_json_message(
                {"error": exc.detail, "status": exc.status}
            )
            return

        record = first(records)
        # Conservative-emit: strip the bearer / private key; keep only safe fields.
        safe = sanitize_connect(record, selector=agent)
        address = field(record, "address", "addr128")
        summary = f"Egress config ({safe.get('tier', tier or 'socks5')})"
        if address:
            summary += f" for {address}"
        summary += " - run `whisper connect` on the Dify host for actual egress"

        yield self.create_text_message(summary)
        yield self.create_json_message(safe)
