from typing import Any, Generator

from dify_plugin import Tool
from dify_plugin.entities.tool import ToolInvokeMessage

from tools.whisper_api import WhisperControlError, direct_read, doc_url, catalog_entry


class GraphAssessTool(Tool):
    def _invoke(
        self, tool_parameters: dict[str, Any]
    ) -> Generator[ToolInvokeMessage, None, None]:
        value = (tool_parameters.get("value") or "").strip()
        if not value:
            yield self.create_text_message(
                "A host or IP is required, e.g. 8.8.8.8 or example.com."
            )
            return
        try:
            result = direct_read(self.runtime.credentials, "assess", value)
        except (WhisperControlError, ValueError) as exc:
            detail = getattr(exc, "detail", str(exc))
            yield self.create_text_message(f"Threat assessment failed: {detail}")
            yield self.create_json_message(
                {"error": detail, "status": getattr(exc, "status", None)}
            )
            return

        docs = doc_url(catalog_entry("assess"))
        rows = result.get("rows") or []
        first = rows[0] if rows else {}
        label = first.get("label", "unknown")
        band = first.get("band", "")
        coverage = first.get("coverage", "")
        summary = f"{value}: {label}" + (f" ({band})" if band else "")
        if coverage:
            summary += f", coverage {coverage}"
        yield self.create_text_message(summary + f". Docs: {docs}")
        yield self.create_json_message(
            {"columns": result.get("columns") or [], "rows": rows, "docs": docs}
        )
