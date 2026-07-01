from typing import Any

from dify_plugin import ToolProvider


class WhisperProvider(ToolProvider):
    def _validate_credentials(self, credentials: dict[str, Any]) -> None:
        # Whisper's public identity API is fully keyless and anonymous:
        # there are no credentials to configure or validate, so authorization
        # always succeeds. (Be liberal in what we accept.)
        return
