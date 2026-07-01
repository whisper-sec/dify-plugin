# Egress - route Dify agent traffic through a Whisper `/128`

Dify is self-hostable, so you can make an agent's traffic actually **leave from its
Whisper identity**: outbound connections source from the agent's routable IPv6
`/128`, and a remote peer that reverse-resolves the address sees the agent's
identity. This is Whisper's Tier-1.5 (SOCKS5) / Tier-1 (WireGuard) egress, brought
up with the open-source `whisper` CLI on the Dify host.

Nothing here needs the plugin - the plugin's **Get Egress Config** tool just reports
an agent's binding. Real egress is a host + container concern, wired once.

## 1. Bring up egress on the Dify host

Install the CLI (MIT, no root, no daemon) and connect, binding to an agent you own:

```sh
curl https://get.whisper.online | sh

# Log in once (or export WHISPER_API_KEY=whisper_live_…)
whisper login

# Bring up a local, bearer-free egress bound to your agent's /128 on a fixed port.
whisper connect --port 1080
# → prints:  socks5h://127.0.0.1:1080
```

`whisper connect` holds the tunnel open and prints **one** loopback proxy string.
The egress bearer / WireGuard key stay inside the CLI - they are never printed, so
nothing secret ends up in a container env or a log. Pin `--agent <id|/128>` to bind
a specific identity; use `--tier wireguard` for a routed `/128`.

## 2. Route Dify's containers through it

Point Dify's plugin daemon (and the API / worker, so agent and tool HTTP both
egress) at the proxy. Drop the override below next to your Dify `docker-compose.yaml`
and start with both files. From inside a container the host proxy is reachable as
`host.docker.internal` (Docker Desktop) or your host's bridge IP / `--add-host`.

```sh
docker compose -f docker-compose.yaml -f egress.compose.yaml up -d
```

See [`egress.compose.yaml`](./egress.compose.yaml). It sets, on `plugin_daemon`,
`api` and `worker`:

```yaml
environment:
  HTTP_PROXY:  socks5h://host.docker.internal:1080
  HTTPS_PROXY: socks5h://host.docker.internal:1080
  ALL_PROXY:   socks5h://host.docker.internal:1080
  # keep intra-cluster calls off the proxy
  NO_PROXY:    localhost,127.0.0.1,db,redis,weaviate,sandbox,plugin_daemon,api,ssrf_proxy
```

`requests` (this plugin) and most HTTP clients honour these variables automatically,
so no plugin change is needed. Prefer `socks5h://` (not `socks5://`) so DNS is
resolved at the proxy.

## 3. Or route just this plugin

If you only want this plugin's own calls to source from the `/128`, skip the compose
override and set the plugin's **Egress Proxy** credential to the endpoint from step 1
(e.g. `socks5h://host.docker.internal:1080`). The plugin then sends its requests
through that proxy.

## 4. Verify

From the Dify host, confirm the egress IP is your `/128` and reverse-resolves to the
agent:

```sh
# The address egress presents:
curl --proxy socks5h://127.0.0.1:1080 https://api64.ipify.org ; echo
# Prove it is a genuine Whisper agent (keyless):
curl "https://rdap.whisper.online/verify-identity?ip=<that-/128>"
# Reverse DNS → the agent's identity:
dig -x <that-/128> +short
```

Inside Dify, add the **Verify Agent Identity** tool and pass the `/128` - a healthy
egress returns `is_whisper_agent: true`.

## Notes

- **Secret hygiene.** Never put the egress bearer / WireGuard private key into
  container env, workflow data, or logs. `whisper connect` keeps them internal; the
  **Get Egress Config** tool strips them from its output by design.
- **IPv6.** The Docker host must have working IPv6 to reach the `/128` network; the
  loopback SOCKS5 endpoint itself is plain `127.0.0.1`.
- The CLI is the reference client and is open source (MIT):
  <https://github.com/whisper-sec/whisper-cli>.
