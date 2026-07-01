from typing import Any, Generator

from dify_plugin import Tool
from dify_plugin.entities.tool import ToolInvokeMessage

from tools.whisper_api import normalize_address, whisper_get


class InboundLookupsTool(Tool):
    def _invoke(
        self, tool_parameters: dict[str, Any]
    ) -> Generator[ToolInvokeMessage, None, None]:
        address = normalize_address(tool_parameters)
        result = whisper_get(f"/ip/{address}/lookups")

        count = result.get("count", 0)
        yield self.create_text_message(
            f"{address}: {count} inbound lookup(s) recorded"
        )
        yield self.create_json_message(result)
