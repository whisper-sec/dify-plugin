from typing import Any, Generator

from dify_plugin import Tool
from dify_plugin.entities.tool import ToolInvokeMessage

from tools.whisper_api import WhisperControlError, catalog_entry, direct_read, doc_url


class GraphVariantsTool(Tool):
    def _invoke(
        self, tool_parameters: dict[str, Any]
    ) -> Generator[ToolInvokeMessage, None, None]:
        value = (tool_parameters.get("value") or "").strip()
        if not value:
            yield self.create_text_message(
                "A domain is required, e.g. paypal.com."
            )
            return

        max_rows = tool_parameters.get("max_rows")
        try:
            max_rows = int(max_rows) if max_rows not in (None, "", 0) else 200
        except (TypeError, ValueError):
            max_rows = 200  # be liberal: a non-numeric cap means the default

        try:
            result = direct_read(self.runtime.credentials, "variants", value)
        except (WhisperControlError, ValueError) as exc:
            detail = getattr(exc, "detail", str(exc))
            yield self.create_text_message(f"Variant generation failed: {detail}")
            yield self.create_json_message(
                {"error": detail, "status": getattr(exc, "status", None)}
            )
            return

        docs = doc_url(catalog_entry("variants"))
        rows = result.get("rows") or []
        registered = [r for r in rows if r.get("exists")]
        payload: dict[str, Any] = {
            "columns": result.get("columns") or [],
            "rows": rows[:max_rows],
            "registeredCount": len(registered),
            "docs": docs,
        }
        if len(rows) > max_rows:
            payload["truncated"] = True
        yield self.create_text_message(
            f"{value}: {len(rows)} look-alike variant(s), {len(registered)} "
            f"registered. Docs: {docs}"
        )
        yield self.create_json_message(payload)
