# Whisper Agent Identity - Dify plugin

**Give your AI agents a real, routable IPv6 identity - then verify, govern and
route it.** Whisper allocates each agent a routable IPv6 `/128`, so *the agent's
address is its identity*. This plugin brings that to Dify in two tiers.

- **Keyless (no account):** ask "is this IPv6 address a genuine agent, and who
  operates it?", then pull its RDAP record, its tamper-evident issuance log, and
  its inbound-lookup feed. Plus **query the whisper.security graph** - assess a
  threat posture, identify a vendor, explain a score, generate look-alikes, and
  run the keyless catalog recipes. Zero configuration.
- **With your Whisper API key:** raw **Cypher** over the whole graph, the
  multi-step **investigation recipes**, and the full control plane - **register**
  an agent with its own `/128` and key, **set DNS policy**, read **logs**,
  **revoke**, and get **egress config** so a self-hosted agent's traffic sources
  from its `/128`.

Auth is optional: install it and the keyless tools work immediately; add a key to
lift the rate limit and unlock raw Cypher, the recipes, and provisioning.

## Tools

### Keyless - no credentials

| Tool | Answers | Endpoint |
|------|---------|----------|
| **Verify Agent Identity** | Is this address a genuine Whisper agent? (verdict + DNS/PTR evidence) | `GET /verify-identity?ip=<addr>` |
| **Lookup RDAP Record** | The IP-anchored RDAP registry record | `GET /ip/<addr>` |
| **Get Transparency Log** | The hash-chained, signed identity issuance history | `GET /ip/<addr>/transparency` |
| **Get Inbound Lookups** | Who has recently checked this identity | `GET /ip/<addr>/lookups` |
| **Assess Threat Posture** | A labelled threat posture (malicious / benign / unknown) for a host or IP | `whisper.assess` |
| **Identify Vendor / Operator** | Who runs a host or IP (canonical name, category, roles) | `whisper.identify` |
| **Explain Threat Score** | Why an indicator is flagged - score, level, cited feeds | `whisper.explain` |
| **Generate Look-alike Variants** | Typosquat / look-alike variants of a domain, and which are registered | `whisper.variants` |
| **Run Graph Recipe** *(keyless recipes)* | Any of the 13 keyless read recipes from the catalog | catalog `direct` |

### Graph + control plane - needs your Whisper API key

| Tool | Does |
|------|------|
| **Query Graph (Cypher)** | Run any Cypher over the whole whisper.security graph; values bound as `$`-parameters |
| **Run Graph Recipe** *(flows)* | Any of the 16 multi-step investigation recipes (typosquat, attack-surface, BGP hygiene, ...) |
| **Register Agent** | Mint a new agent with its own routable `/128` **and** its own API key (returned once) |
| **Set Policy** | Set/read the per-tenant DNS resolver policy (default action + allow/deny lists) |
| **Get Logs** | Query recent DNS / connection / allocation activity |
| **Revoke Agent** | Fully revoke an agent - withdraw its `/128`, PTR, tokens and key (irreversible) |
| **Get Egress Config** | Get an agent's egress binding to its `/128` (secret-free; see Egress) |

The graph tools POST `{"query":"<cypher>","parameters":{…}}` to
`https://graph.whisper.online/api/query` (the keyless read procedures work with
no key, rate-limited; a key lifts the limit and unlocks raw Cypher + flows). The
control tools speak the one Whisper control verb -
`CALL whisper.agents({op:…})`, POSTed to the same endpoint with your key in the
`X-API-Key` header. The exact wire contract is documented at
<https://github.com/whisper-sec/whisper-cli> (the CLI is the reference client).

## Query the whisper.security graph

Whisper runs a graph of billions of internet-infrastructure nodes (hostnames,
IPs, organizations, ASNs, threat feeds) and their relationships. Four one-shot
read tools, 29 named recipes, and raw Cypher expose it - **two-tier, so you get
real value with no key at all** and the full power with one.

### Keyless - real answers, no account

```
Assess Threat Posture   value = 8.8.8.8
```

```json
{ "columns": ["host","label","band","coverage",...],
  "rows": [ { "host":"8.8.8.8", "label":"benign-allowlisted", "band":"INFO", "coverage":"known-clean" } ] }
```

```
Identify Vendor / Operator   value = api.openai.com     -> "Cloudflare (cdn)"
Explain Threat Score         value = paypal.com         -> score + cited feeds
Generate Look-alike Variants value = paypal.com         -> variants + which are registered
```

The keyless read procedures are rate-limited (about 100 calls per window);
adding your API key lifts the limit. Docs:
<https://www.whisper.security/docs/whisper-graph/procedures>.

### With a key - raw Cypher

```
Query Graph (Cypher)
  cypher     = MATCH (h:HOSTNAME {name:$name})-[:RESOLVES_TO]->(ip) RETURN ip.name AS address LIMIT 5
  parameters = {"name":"google.com"}
```

Always pass user values through `parameters` as `$`-parameters (never
concatenate them into the query) - the tool keeps them as data, so a hostile
value can never become Cypher. Discover the schema with **Run Graph Recipe ->
Graph Schema Catalog (db.schema)**. Docs:
<https://www.whisper.security/docs/cypher-api>.

### Named recipes

**Run Graph Recipe** exposes all 29 curated catalog recipes as a dropdown. The
13 keyless direct reads run with no key; the 16 multi-step flows (typosquat,
attack-surface, BGP hygiene, subdomain-takeover, ...) run via the gallery runner
and need your key.

```
Run Graph Recipe   recipe = typosquat   value = example.com
```

Returns every step's table (registered look-alikes, brand owner, per-variant
threat verdict, hosting, WHOIS, ...). The full catalog:
<https://www.whisper.security/docs>.

## Configuration

Open the plugin's settings (**Authorize**):

- **Whisper API Key** - *optional*. Leave blank for the keyless tools. Paste your
  `whisper_live_…` key to unlock the control plane. Get one at
  [whisper.online/platform](https://whisper.online/platform).
- **Egress Proxy** - *optional*. A local proxy from `whisper connect` on the Dify
  host (e.g. `socks5h://host.docker.internal:1080`) that routes this plugin's
  outbound calls through an agent's `/128`. See **Egress** below.

## Egress - route agent traffic through its `/128`

Because Dify is **self-hostable**, you can make an agent's traffic actually *leave*
from its Whisper identity. Install the open-source CLI on the Dify host and bring up
a local, bearer-free egress bound to the agent's `/128`:

```sh
curl https://get.whisper.online | sh
whisper connect --port 1080          # prints socks5h://127.0.0.1:1080, bound to your /128
```

Then route traffic through it, either:

1. **Whole deployment (recommended):** set `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY`
   on Dify's `plugin_daemon` (and `api`/`worker`) containers so *all* agent and
   tool traffic sources from the `/128`. A ready-to-use override is in
   [`egress.compose.yaml`](./egress.compose.yaml); see [`EGRESS.md`](./EGRESS.md).
2. **This plugin only:** paste the endpoint into the **Egress Proxy** credential
   above.

The **Get Egress Config** tool returns the binding for an agent but, for safety,
**never** returns the raw egress bearer or WireGuard key - those would leak into
workflow data and logs. Bring up real egress with `whisper connect` as above.

## Use it

- **Agent applications** - add the Whisper tools; the agent verifies, provisions or
  governs by calling the right tool.
- **Chatflow / Workflow** - drop a Whisper tool node and wire its inputs.

### Example - verify (keyless)

```
Verify Agent Identity  address = 2a04:2a01:b69a:6717:e3b0:51ff:3bf7:f478
```

```json
{ "is_whisper_agent": true, "fqdn": "…", "evidence": { "ptr": "…" } }
```

An address that anchors no agent returns `"is_whisper_agent": false` with the
reason - never an opaque error.

### Example - register (with a key)

```
Register Agent  name = scout   contact_email = ops@example.com
```

Returns the new agent's `address` (its `/128`), `fqdn`, and its `api_key` - shown
**once**, so capture it.

## About

Whisper gives each AI agent a real, routable IPv6 identity so **the agent's address
is its identity**. Learn more at [whisper.online/platform](https://whisper.online/platform).
The Whisper CLI is open source (MIT): <https://github.com/whisper-sec/whisper-cli>.

## Source & contact

- **Source repository:** <https://github.com/whisper-sec/dify-plugin>
- **Homepage:** <https://whisper.online/platform>
- **Issues / contact:** <https://github.com/whisper-sec/dify-plugin/issues>
- **Keyless API host:** `https://rdap.whisper.online` (public, no credentials)
- **Control plane:** `https://graph.whisper.online/api/query` (needs your API key)

Published by Whisper Security (viaGraph B.V.). Licensed MIT.
