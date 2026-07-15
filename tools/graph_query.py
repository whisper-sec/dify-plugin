import json
from typing import Any, Generator

from dify_plugin import Tool
from dify_plugin.entities.tool import ToolInvokeMessage

from tools.whisper_api import WhisperControlError, graph_call


class GraphQueryTool(Tool):
    def _invoke(
        self, tool_parameters: dict[str, Any]
    ) -> Generator[ToolInvokeMessage, None, None]:
        cypher = (tool_parameters.get("cypher") or "").strip()
        if not cypher:
            yield self.create_text_message(
                "A Cypher query is required. Example: "
                "MATCH (h:HOSTNAME {name:$name})-[:RESOLVES_TO]->(ip) "
                "RETURN ip.name AS address LIMIT 5  with parameters "
                '{"name":"example.com"}.'
            )
            return

        # User values travel ONLY as $-parameters - never spliced into the query.
        raw = (tool_parameters.get("parameters") or "").strip()
        parameters: dict[str, Any] = {}
        if raw:
            try:
                parameters = json.loads(raw)
            except ValueError:
                yield self.create_text_message(
                    'Parameters must be a JSON object, e.g. {"name":"example.com"}.'
                )
                return
            if not isinstance(parameters, dict):
                yield self.create_text_message(
                    'Parameters must be a JSON object mapping $-parameter names '
                    'to values, e.g. {"name":"example.com"}.'
                )
                return

        max_rows = tool_parameters.get("max_rows")
        try:
            max_rows = int(max_rows) if max_rows not in (None, "", 0) else 100
        except (TypeError, ValueError):
            max_rows = 100  # be liberal: a non-numeric cap means the default

        try:
            result = graph_call(self.runtime.credentials, cypher, parameters)
        except (WhisperControlError, ValueError) as exc:
            detail = getattr(exc, "detail", str(exc))
            yield self.create_text_message(f"Graph query failed: {detail}")
            yield self.create_json_message(
                {"error": detail, "status": getattr(exc, "status", None)}
            )
            return

        rows = result.get("rows") or []
        payload: dict[str, Any] = {
            "columns": result.get("columns") or [],
            "rows": rows[:max_rows],
            "statistics": result.get("statistics") or {},
        }
        if len(rows) > max_rows:
            payload["truncated"] = True
        yield self.create_text_message(
            f"{len(rows)} row(s)" + (f", returning first {max_rows}" if len(rows) > max_rows else "")
        )
        yield self.create_json_message(payload)
