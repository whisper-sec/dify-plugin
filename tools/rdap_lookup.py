from typing import Any, Generator

from dify_plugin import Tool
from dify_plugin.entities.tool import ToolInvokeMessage

from tools.whisper_api import normalize_address, whisper_get


class RdapLookupTool(Tool):
    def _invoke(
        self, tool_parameters: dict[str, Any]
    ) -> Generator[ToolInvokeMessage, None, None]:
        address = normalize_address(tool_parameters)
        result = whisper_get(f"/ip/{address}")

        if result.get("errorCode"):
            title = result.get("title") or "Not Found"
            yield self.create_text_message(
                f"No RDAP record for {address}: {title}"
            )
        else:
            yield self.create_text_message(f"RDAP record for {address}")
        yield self.create_json_message(result)
