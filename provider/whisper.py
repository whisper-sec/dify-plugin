from typing import Any

from dify_plugin import ToolProvider
from dify_plugin.errors.tool import ToolProviderCredentialValidationError

from tools.whisper_api import WhisperControlError, api_key, control_call


class WhisperProvider(ToolProvider):
    def _validate_credentials(self, credentials: dict[str, Any]) -> None:
        """Two-tier auth, validated liberally (Postel).

        - No key  -> the keyless tier (verify / RDAP / transparency / lookups) is
          fully anonymous, so there is nothing to validate - authorize succeeds.
        - A key   -> validate it against the control plane with a cheap, read-only
          op:list. A bad/unauthorized key fails fast with a clear message; any
          other transient issue is surfaced verbatim, never an opaque 500.

        The optional egress_proxy is only validated for shape (a proxy URL), not
        reachability - the `whisper connect` proxy may legitimately be brought up
        after the plugin is authorized.
        """
        proxy = (credentials.get("egress_proxy") or "").strip()
        if proxy and "://" not in proxy:
            raise ToolProviderCredentialValidationError(
                "Egress Proxy must be a proxy URL, e.g. "
                "socks5h://host.docker.internal:1080 (from `whisper connect`)."
            )

        if not api_key(credentials):
            return  # keyless tier - nothing to validate

        try:
            control_call(credentials, "list", {"kind": "agents"})
        except WhisperControlError as exc:
            if exc.status in (401, 403):
                raise ToolProviderCredentialValidationError(
                    f"Whisper API key rejected: {exc.detail}"
                ) from exc
            raise ToolProviderCredentialValidationError(
                f"Could not validate the Whisper API key: {exc.detail}"
            ) from exc
