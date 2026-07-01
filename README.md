# Whisper Agent Identity - Dify plugin

**Verify and resolve AI-agent identities on the wire.** Ask "is this IPv6 address a
genuine agent, and who operates it?" - then pull its registry record, its
tamper-evident issuance log, and its inbound lookup feed.

Every call is **keyless and anonymous**. No API key, no account, no configuration.
Install it, and your Dify agents and workflows can check agent identity immediately.

## Tools

| Tool | Answers | Endpoint |
|------|---------|----------|
| **Verify Agent Identity** | Is this address a genuine Whisper agent? (verdict + DNS/PTR evidence) | `GET /verify-identity?ip=<addr>` |
| **Lookup RDAP Record** | The IP-anchored RDAP registry record | `GET /ip/<addr>` |
| **Get Transparency Log** | The hash-chained, signed identity issuance history | `GET /ip/<addr>/transparency` |
| **Get Inbound Lookups** | Who has recently checked this identity | `GET /ip/<addr>/lookups` |

All four take a single `address` parameter - an IPv6 (compressed or expanded) or
IPv4 literal. Whisper agent addresses live in `2a04:2a01::/32` (AS219419).

## Configuration

None. There are no credentials to set - the [Whisper](https://whisper.online/platform)
identity API is fully public. Click **Authorize** and it just works.

## Use it

- **Agent applications** - add the Whisper tools; the agent verifies or resolves an
  address by calling the right tool.
- **Chatflow / Workflow** - drop a Whisper tool node and wire the `address` input.

### Example

Verify an address:

```
Verify Agent Identity  address = 2a04:2a01:b69a:6717:e3b0:51ff:3bf7:f478
```

Returns a verdict such as:

```json
{
  "is_whisper_agent": true,
  "fqdn": "…",
  "evidence": { "address": "…", "ptr": "…" }
}
```

An address that anchors no agent returns `"is_whisper_agent": false` with the reason -
never an opaque error.

## About

Whisper gives each AI agent a real, routable IPv6 identity so **the agent's address
is its identity**. Learn more at [whisper.online/platform](https://whisper.online/platform).
The Whisper CLI is open source (MIT): <https://github.com/whisper-sec/whisper-cli>.

## Source & contact

- **Source repository:** <https://github.com/whisper-sec/dify-plugin>
- **Homepage:** <https://whisper.online/platform>
- **Issues / contact:** <https://github.com/whisper-sec/dify-plugin/issues>
- **API host:** `https://rdap.whisper.online` (public, keyless - no credentials)

Published by Whisper Security (viaGraph B.V.). Licensed MIT.
