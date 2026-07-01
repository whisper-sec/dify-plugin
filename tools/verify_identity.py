from typing import Any, Generator

from dify_plugin import Tool
from dify_plugin.entities.tool import ToolInvokeMessage

from tools.whisper_api import normalize_address, whisper_get


class VerifyIdentityTool(Tool):
    def _invoke(
        self, tool_parameters: dict[str, Any]
    ) -> Generator[ToolInvokeMessage, None, None]:
        address = normalize_address(tool_parameters)
        result = whisper_get("/verify-identity", params={"ip": address})

        if result.get("is_whisper_agent"):
            fqdn = result.get("fqdn") or (result.get("evidence") or {}).get("ptr")
            summary = f"{address} is a verified Whisper agent" + (
                f" ({fqdn})" if fqdn else ""
            )
        else:
            summary = f"{address} is not a Whisper agent identity"

        yield self.create_text_message(summary)
        yield self.create_json_message(result)
