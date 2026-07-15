import json
from typing import Any, Generator

from dify_plugin import Tool
from dify_plugin.entities.tool import ToolInvokeMessage

from tools.whisper_api import (
    WhisperControlError,
    catalog_entry,
    doc_url,
    flow_run,
    graph_call,
    recipe_parameters,
)


class RunRecipeTool(Tool):
    def _invoke(
        self, tool_parameters: dict[str, Any]
    ) -> Generator[ToolInvokeMessage, None, None]:
        recipe_id = (tool_parameters.get("recipe") or "").strip()
        value = (tool_parameters.get("value") or "").strip()

        raw = (tool_parameters.get("params") or "").strip()
        extra: dict[str, Any] = {}
        if raw:
            try:
                extra = json.loads(raw)
            except ValueError:
                yield self.create_text_message(
                    'Params must be a JSON object, e.g. {"instanceType":"Global"}.'
                )
                return
            if not isinstance(extra, dict):
                yield self.create_text_message(
                    "Params must be a JSON object keyed by parameter name."
                )
                return

        max_rows = tool_parameters.get("max_rows")
        try:
            max_rows = int(max_rows) if max_rows not in (None, "", 0) else 50
        except (TypeError, ValueError):
            max_rows = 50  # be liberal: a non-numeric cap means the default

        try:
            entry = catalog_entry(recipe_id)
            exec_ = entry.get("exec") or {}
            docs = doc_url(entry)

            if exec_.get("mode") == "flow":
                # Multi-step flow via the gallery runner (keyed, SSE).
                result = flow_run(
                    self.runtime.credentials,
                    entry["id"],
                    value=value,
                    param_values=extra or None,
                    max_rows=max_rows,
                )
                total_rows = sum(s.get("rowCount", 0) for s in result["steps"])
                yield self.create_text_message(
                    f"{entry['title']}: {result['stepCount']} step(s), "
                    f"{total_rows} row(s). Docs: {docs}"
                )
                yield self.create_json_message(
                    {
                        "recipe": entry["id"],
                        "title": entry["title"],
                        "mode": "flow",
                        "steps": result["steps"],
                        "totalLatencyMs": result.get("totalLatencyMs"),
                        "docs": docs,
                    }
                )
                return

            # Direct single-Cypher entry; user values ride as $-parameters.
            result = graph_call(
                self.runtime.credentials,
                exec_["cypher"],
                recipe_parameters(entry, value, extra),
                require_key=entry.get("access") == "keyed",
            )
        except (WhisperControlError, ValueError) as exc:
            detail = getattr(exc, "detail", str(exc))
            yield self.create_text_message(f"Recipe failed: {detail}")
            yield self.create_json_message(
                {"error": detail, "status": getattr(exc, "status", None)}
            )
            return

        rows = result.get("rows") or []
        payload: dict[str, Any] = {
            "recipe": entry["id"],
            "title": entry["title"],
            "mode": "direct",
            "columns": result.get("columns") or [],
            "rows": rows[:max_rows],
            "statistics": result.get("statistics") or {},
            "docs": docs,
        }
        if len(rows) > max_rows:
            payload["truncated"] = True
        yield self.create_text_message(
            f"{entry['title']}: {len(rows)} row(s). Docs: {docs}"
        )
        yield self.create_json_message(payload)
