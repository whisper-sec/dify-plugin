from typing import Any, Generator

from dify_plugin import Tool
from dify_plugin.entities.tool import ToolInvokeMessage

from tools.whisper_api import WhisperControlError, catalog_entry, direct_read, doc_url


class GraphExplainTool(Tool):
    def _invoke(
        self, tool_parameters: dict[str, Any]
    ) -> Generator[ToolInvokeMessage, None, None]:
        value = (tool_parameters.get("value") or "").strip()
        if not value:
            yield self.create_text_message(
                "An indicator (host, IP or domain) is required, e.g. paypal.com."
            )
            return
        try:
            result = direct_read(self.runtime.credentials, "explain", value)
        except (WhisperControlError, ValueError) as exc:
            detail = getattr(exc, "detail", str(exc))
            yield self.create_text_message(f"Explain failed: {detail}")
            yield self.create_json_message(
                {"error": detail, "status": getattr(exc, "status", None)}
            )
            return

        docs = doc_url(catalog_entry("explain"))
        rows = result.get("rows") or []
        first = rows[0] if rows else {}
        level = first.get("level", "NONE")
        score = first.get("score")
        sources = first.get("sources") or []
        summary = f"{value}: {level}"
        if score is not None:
            summary += f" (score {score})"
        summary += f", {len(sources)} source(s)"
        yield self.create_text_message(summary + f". Docs: {docs}")
        yield self.create_json_message(
            {"columns": result.get("columns") or [], "rows": rows, "docs": docs}
        )
