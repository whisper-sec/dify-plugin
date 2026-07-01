# Privacy Policy - Whisper Agent Identity plugin

## What this plugin does

The plugin looks up agent-identity information from Whisper's public, keyless API at
`https://rdap.whisper.online`. It requires no credentials and stores nothing.

## Data it sends

For each tool call, the plugin sends **only the IP address you (or your agent)
provide** to the Whisper public API, as an ordinary anonymous HTTPS GET request:

- `GET /verify-identity?ip=<address>`
- `GET /ip/<address>`
- `GET /ip/<address>/transparency`
- `GET /ip/<address>/lookups`

No API key, account identifier, user data, or Dify workspace information is
transmitted. The lookups are anonymous.

## Data it collects or stores

The plugin itself collects and stores **nothing**. It holds no credentials and keeps
no logs; it returns the API response to your Dify application and discards it.

## Third-party service

Requests are served by Whisper's public identity API (Whisper Security / viaGraph
B.V.). As with any RDAP or identity-verification service, the operator may log the
querying source and the queried address for abuse prevention and to power the public
"inbound lookups" feed. Do not query addresses you are not permitted to look up.

## Contact

For questions about this plugin or the public API, see
<https://whisper.online/platform>.
