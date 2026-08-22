# Privacy Policy - Whisper Agent Identity plugin

## What this plugin does

The plugin talks to Whisper's identity services on your behalf. It works in two
tiers:

- **Keyless tier** - anonymous lookups against the public identity API at
  `https://rdap.whisper.online`. No credentials.
- **Control-plane tier** - when you configure a Whisper API key, the plugin can
  provision and govern agents via `https://graph.whisper.online/api/query`.

The plugin stores nothing itself.

## Data it sends

**Keyless tools** send **only the IP address you (or your agent) provide** to the
public API, as an anonymous HTTPS GET:

- `GET /verify-identity?ip=<address>`
- `GET /ip/<address>` · `/ip/<address>/transparency` · `/ip/<address>/lookups`

No API key, account identifier, or Dify workspace information is sent for these.

**Control-plane tools** (Register Agent, Set Policy, Get Logs, Revoke Agent, Get
Egress Config) send your **Whisper API key** in the `X-API-Key` header and the
parameters you supply (e.g. an agent name, policy entries, an agent selector) to
the control plane, as an HTTPS POST of a single `whisper.agents` control call. The
key is used only to authenticate you to Whisper; it is never logged by the plugin
and never placed in tool output.

## Credentials

Your Whisper API key and the optional egress-proxy URL are held by Dify's
credential store and read at call time. The plugin does not persist them anywhere
else. The **Get Egress Config** tool deliberately **strips** any egress bearer or
WireGuard private key from its output so live credentials never reach workflow data
or execution logs.

## Data it collects or stores

The plugin itself collects and stores **nothing**. It returns each API response to
your Dify application and discards it.

## Third-party service

Requests are served by Whisper Security / viaGraph B.V. As with any RDAP or
identity service, the operator may log the querying source and the queried address
for abuse prevention and to power the public "inbound lookups" feed. Do not query
addresses you are not permitted to look up. Control-plane actions are confined to
the tenant your API key belongs to.

## Contact

For questions about this plugin or the API, see
<https://whisper.online/platform>.
