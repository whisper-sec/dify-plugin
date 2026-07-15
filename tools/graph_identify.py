from typing import Any, Generator

from dify_plugin import Tool
from dify_plugin.entities.tool import ToolInvokeMessage

from tools.whisper_api import WhisperControlError, catalog_entry, direct_read, doc_url


class GraphIdentifyTool(Tool):
    def _invoke(
        self, tool_parameters: dict[str, Any]
    ) -> Generator[ToolInvokeMessage, None, None]:
        value = (tool_parameters.get("value") or "").strip()
        if not value:
            yield self.create_text_message(
                "A host or IP is required, e.g. api.openai.com."
            )
            return
        try:
            result = direct_read(self.runtime.credentials, "identify", value)
        except (WhisperControlError, ValueError) as exc:
            detail = getattr(exc, "detail", str(exc))
            yield self.create_text_message(f"Identity lookup failed: {detail}")
            yield self.create_json_message(
                {"error": detail, "status": getattr(exc, "status", None)}
            )
            return

        docs = doc_url(catalog_entry("identify"))
        rows = result.get("rows") or []
        first = rows[0] if rows else {}
        vendor = first.get("canonical_name") or first.get("vendor_id")
        category = first.get("category")
        if vendor:
            summary = f"{value}: {vendor}" + (f" ({category})" if category else "")
        else:
            summary = f"{value}: no known vendor/operator"
        yield self.create_text_message(summary + f". Docs: {docs}")
        yield self.create_json_message(
            {"columns": result.get("columns") or [], "rows": rows, "docs": docs}
        )
