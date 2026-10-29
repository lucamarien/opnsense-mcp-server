# OPNsense MCP Server

A secure [Model Context Protocol](https://modelcontextprotocol.io/) (MCP) server for managing OPNsense firewalls through AI assistants like [Claude Code](https://docs.anthropic.com/en/docs/claude-code), Cursor, and other MCP-compatible tools.

**64 tools** across 10 domains (system, network, firewall, DNS, DHCP, VPN, HAProxy, services, diagnostics, security), plus **3 guided-workflow prompts** and **MCP resources** for configuration context. Every tool carries MCP tool annotations (`readOnlyHint`/`destructiveHint`) so clients can auto-approve reads.

## Requirements

- **Python 3.11+**
- **OPNsense 24.7 or newer** — the MCP server relies on the MVC-based API endpoints introduced in OPNsense 24.7. Older versions use a different API structure that is not compatible. The server auto-detects the OPNsense version on first connect and selects the correct endpoint naming (camelCase for pre-25.7, snake_case for 25.7+). OPNsense 26.x is fully supported, including its changed firmware status response format.

## Security Model

This MCP server is designed with security as the primary concern:

- **Read-only by default** — write operations require explicit opt-in via `OPNSENSE_ALLOW_WRITES=true`
- **Savepoint/rollback (OPNsense < 26.7 only)** — where OPNsense still offers the savepoint API, firewall *filter* modifications use its built-in 60-second auto-revert; changes must be explicitly confirmed or they roll back automatically. OPNsense 26.7 removed that API upstream — the server detects the missing endpoint at runtime and applies firewall changes immediately, with no automatic rollback. NAT (port forward) changes always apply immediately — OPNsense's savepoint mechanism never covered the NAT model (verified upstream), and the tools say so honestly
- **Sensitive data double-gate** — `include_sensitive=true` on config tools additionally requires `OPNSENSE_ALLOW_SENSITIVE=true` in the server environment; the model cannot self-elevate to read passwords/keys
- **HTTPS enforced** — `http://` URLs are refused unless `OPNSENSE_ALLOW_INSECURE_HTTP=true` (API credentials travel as Basic Auth)
- **Tool annotations** — all 64 tools declare `readOnlyHint`/`destructiveHint`/`idempotentHint`, so MCP clients can auto-approve reads and warn on destructive calls
- **Endpoint blocklist** — dangerous endpoints (`halt`, `reboot`, `poweroff`, `firmware update/upgrade`) are hard-blocked at the API client level and can never be called
- **API-only** — no SSH access, no command execution, no direct config file manipulation
- **Local transport** — STDIO only, no network-exposed HTTP/SSE endpoints
- **No credential exposure** — API keys are never included in tool output, logs, or error messages
- **Input validation** — hostname parameters are validated against shell metacharacter injection
- **Sensitive data stripping** — config backup strips passwords and keys by default

## Quick Start

### 1. Create an OPNsense API Key

1. Log in to your OPNsense web interface
2. Go to **System > Access > Users**
3. Either edit an existing user or create a dedicated API user:
   - For production use, create a dedicated user (e.g., `mcp-api`) with only the privileges needed
   - For read-only access, assign the user to a group with read-only API access
4. Scroll down to the **API keys** section and click the **+** button
5. A key/secret pair will be generated and a file (`apikey.txt`) will be downloaded
6. The file contains two lines — `key=your-api-key-here` and `secret=your-api-secret-here`
7. Store these credentials securely — the secret cannot be retrieved again from OPNsense

> **Tip:** For a read-only setup (recommended for getting started), you don't need to change any permissions — the default API access is sufficient for all read-only tools.

### 2. Install

```bash
# Using pip
pip install opnsense-mcp-server

# Using uv (recommended for isolated environments)
uv pip install opnsense-mcp-server

# Using Docker
docker pull uhlenheide/opnsense-mcp-server

# From source
git clone https://github.com/lucamarien/opnsense-mcp-server
cd opnsense-mcp-server
pip install -e .
```

> **Docker image:** the official image is [`uhlenheide/opnsense-mcp-server`](https://hub.docker.com/r/uhlenheide/opnsense-mcp-server), published from this repository by [`.github/workflows/publish-docker.yml`](.github/workflows/publish-docker.yml) on every `v*` tag. There is no `lucamarien/opnsense-mcp-server` image — earlier README versions named it by mistake.

### 3. Configure Your AI Assistant

#### Claude Code

Add to your project's `.mcp.json`:

```json
{
  "mcpServers": {
    "opnsense": {
      "command": "opnsense-mcp",
      "env": {
        "OPNSENSE_URL": "https://192.168.1.1/api",
        "OPNSENSE_API_KEY": "your-api-key-here",
        "OPNSENSE_API_SECRET": "your-api-secret-here",
        "OPNSENSE_VERIFY_SSL": "false",
        "OPNSENSE_ALLOW_WRITES": "false"
      }
    }
  }
}
```

> **Alternative:** Use `"command": "python", "args": ["-m", "opnsense_mcp"]` if the `opnsense-mcp` CLI is not on your PATH.

Or add it globally to `~/.claude/claude_code_config.json`.

#### Claude Code (Docker)

```json
{
  "mcpServers": {
    "opnsense": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "-e", "OPNSENSE_URL=https://192.168.1.1/api",
        "-e", "OPNSENSE_API_KEY=your-api-key-here",
        "-e", "OPNSENSE_API_SECRET=your-api-secret-here",
        "-e", "OPNSENSE_VERIFY_SSL=false",
        "-e", "OPNSENSE_ALLOW_WRITES=false",
        "uhlenheide/opnsense-mcp-server"
      ]
    }
  }
}
```

#### Cursor

Add to your Cursor MCP settings (Settings > MCP):

```json
{
  "mcpServers": {
    "opnsense": {
      "command": "opnsense-mcp",
      "env": {
        "OPNSENSE_URL": "https://192.168.1.1/api",
        "OPNSENSE_API_KEY": "your-api-key-here",
        "OPNSENSE_API_SECRET": "your-api-secret-here",
        "OPNSENSE_VERIFY_SSL": "false"
      }
    }
  }
}
```

## Configuration

| Environment Variable | Default | Description |
| --- | --- | --- |
| `OPNSENSE_URL` | *(required)* | OPNsense API base URL (must end with `/api`) |
| `OPNSENSE_API_KEY` | *(required)* | API key from OPNsense user settings |
| `OPNSENSE_API_SECRET` | *(required)* | API secret from OPNsense user settings |
| `OPNSENSE_VERIFY_SSL` | `true` | Verify SSL certificate (`false` for self-signed certs) |
| `OPNSENSE_ALLOW_WRITES` | `false` | Enable write operations (firewall rules, service control) |
| `OPNSENSE_ALLOW_SENSITIVE` | `false` | Permit `include_sensitive=true` on config tools (otherwise secrets are always redacted) |
| `OPNSENSE_ALLOW_INSECURE_HTTP` | `false` | Permit `http://` URLs (credentials would travel in cleartext) |
| `OPNSENSE_API_STYLE` | `auto` | `camel` or `snake` forces the endpoint naming style and skips version detection — use when the API key lacks the firmware/status privilege |

**Custom ports:** If your OPNsense web GUI runs on a non-standard port (e.g., 10443), include it in the URL: `https://192.168.1.1:10443/api`

## Available Tools (64)

Surface pattern: `opn_list_*` / `opn_get_*` / `*_status` for reads, `opn_manage_*(action=...)`
for writes (HAProxy uses a generic `resource_type` CRUD because its 9 resource types share one
uniform API). All errors come back as `{"error", "error_type", ...}` dicts.

### System (8 tools)

| Tool | Description |
| --- | --- |
| `opn_system_status` | System info including firmware version and product name |
| `opn_system_health` | Memory, disk usage, load/uptime, and temperature sensors |
| `opn_list_services` | List all services and their running status. Params: `search`, `limit` |
| `opn_gateway_status` | Gateway availability, latency, and dpinger health checks |
| `opn_download_config` | Download `config.xml` backup (secrets redacted; `include_sensitive` requires the env gate) |
| `opn_scan_config` | Scan the full configuration into cached, queryable sections + runtime inventory. Params: `force` |
| `opn_get_config_section` | Get a specific config section as structured JSON. Params: `section`, `include_sensitive` |
| `opn_mcp_info` | MCP server version, write/sensitive mode, detected OPNsense version, API style, and whether firewall writes still get savepoint/rollback protection |

### Network (7 tools)

| Tool | Description |
| --- | --- |
| `opn_find_host` | Find a device by IP/MAC/hostname across ARP + NDP + DHCP leases + DNS overrides in one call. Params: `query` |
| `opn_traffic_top` | Current top bandwidth consumers per interface (iftop-style snapshot). Params: `interfaces` |
| `opn_interface_stats` | Per-interface traffic statistics (bytes in/out, packets, errors) |
| `opn_arp_table` | ARP table (IPv4-to-MAC). Params: `search`, `limit` |
| `opn_ndp_table` | NDP table (IPv6-to-MAC). Params: `search`, `limit` |
| `opn_ipv6_status` | IPv6 configuration and live addresses for all interfaces |
| `opn_list_static_routes` | Configured static routes. Params: `search`, `limit` |

### Firewall (11 tools)

| Tool | Description | Writes |
| --- | --- | --- |
| `opn_list_firewall_rules` | List MVC firewall filter rules. Params: `search`, `limit` | No |
| `opn_list_firewall_aliases` | List alias definitions. Params: `search`, `limit` | No |
| `opn_list_nat_rules` | List NAT port forwarding (DNAT) rules. Params: `search`, `limit` | No |
| `opn_list_firewall_categories` | List rule categories and their UUIDs. Params: `search`, `limit` | No |
| `opn_firewall_log` | Recent firewall log entries with filtering. Params: `source_ip`, `destination_ip`, `action`, `interface`, `limit` | No |
| `opn_confirm_changes` | Confirm pending savepoint changes (cancels 60s auto-rollback; OPNsense < 26.7, a no-op returning `not_applicable` on 26.7+). Params: `revision` | Yes |
| `opn_manage_firewall_rule` | Add/update/delete/toggle a filter rule (savepoint-protected on OPNsense < 26.7). Params: `action`, `uuid`, `rule_action`, `direction`, `interface`, `ip_protocol`, `protocol`, source/destination nets+ports, `gateway`, `log`, `quick`, `sequence`, `categories`, `description`, `enabled` | Yes |
| `opn_manage_alias` | Add/update/delete/toggle an alias (applies immediately). Params: `action`, `uuid`, `name`, `alias_type`, `content`, `description`, `enabled` | Yes |
| `opn_manage_nat_rule` | Add/update/delete a port forward — **applies immediately, no auto-revert** (OPNsense limitation). Params: `action`, `uuid`, `interface`, `protocol`, `destination_port`, `target_ip`, `target_port`, `description`, `enabled` | Yes |
| `opn_manage_firewall_category` | Add/delete a rule category (delete is savepoint-protected on OPNsense < 26.7). Params: `action`, `uuid`, `name`, `color` | Yes |
| `opn_add_icmpv6_rules` | Create the 5 essential ICMPv6 rules for IPv6 (RFC 4890) under one savepoint (OPNsense < 26.7). Params: `interface` | Yes |

> **Note:** Savepoint protection only exists on OPNsense < 26.7. On 26.7+ these tools apply changes immediately and permanently — see [Write Operations and Savepoints](#write-operations-and-savepoints).

### DNS (10 tools)

| Tool | Description | Writes |
| --- | --- | --- |
| `opn_list_dns_overrides` | Unbound host overrides (local DNS records). Params: `search`, `limit` | No |
| `opn_list_dns_forwards` | DNS forward zones. Params: `search`, `limit` | No |
| `opn_dns_stats` | Unbound resolver statistics | No |
| `opn_manage_dns_override` | Add/update/delete a host override (applies immediately). Params: `action`, `uuid`, `hostname`, `domain`, `server`, `description`, `enabled` | Yes |
| `opn_reconfigure_unbound` | Apply pending Unbound configuration changes | Yes |
| `opn_list_dnsbl` | List DNSBL blocklist configurations. Params: `search`, `limit` | No |
| `opn_get_dnsbl` | Full DNSBL config by UUID (providers, allowlists, settings) | No |
| `opn_set_dnsbl` | Update DNSBL settings (read-modify-write). Params: `uuid`, `enabled`, `providers`, lists, `nxdomain`, `cache_ttl`, ... | Yes |
| `opn_edit_dnsbl_allowlist` | Add and/or remove allowlist domains without replacing the list. Params: `uuid`, `add_domains`, `remove_domains` | Yes |
| `opn_apply_dnsbl` | Reload blocklist files and restart Unbound (no config change) | Yes |

### DHCP (4 tools)

| Tool | Description | Writes |
| --- | --- | --- |
| `opn_list_dhcp_leases` | Leases from the active (or a specific) backend. Params: `backend` (auto/dnsmasq/kea/isc), `search`, `limit` | No |
| `opn_list_dnsmasq_ranges` | DHCP address ranges incl. IPv6/RA config. Params: `search`, `limit` | No |
| `opn_manage_dnsmasq_range` | Add/update/delete a DHCP range (applies immediately). Params: `action`, `uuid`, `interface`, `start_addr`, `end_addr`, `prefix_len`, `ra_mode`, `lease_time`, `description`, `enabled` | Yes |
| `opn_reconfigure_dnsmasq` | Apply pending dnsmasq configuration changes | Yes |

### VPN (3 tools)

| Tool | Description |
| --- | --- |
| `opn_wireguard_status` | WireGuard tunnel and peer status (requires os-wireguard) |
| `opn_ipsec_status` | IPsec tunnel status — IKE (Phase 1) and ESP/AH (Phase 2) |
| `opn_openvpn_status` | OpenVPN instances, sessions, and routes |

### HAProxy (8 tools)

Full configuration management for the HAProxy load balancer (requires os-haproxy plugin).

| Tool | Description | Writes |
| --- | --- | --- |
| `opn_haproxy_status` | Service status and backend health | No |
| `opn_haproxy_search` | Search resources by type. Params: `resource_type` (frontends/backends/servers/actions/acls/healthchecks/errorfiles/resolvers/mailers), `search`, `limit` | No |
| `opn_haproxy_get` | Full configuration of one resource. Params: `resource_type`, `uuid` | No |
| `opn_haproxy_configtest` | Validate configuration syntax without applying | No |
| `opn_haproxy_add` | Create a resource. Params: `resource_type`, `config` (dict) | Yes |
| `opn_haproxy_update` | Update a resource (partial). Params: `resource_type`, `uuid`, `config` | Yes |
| `opn_haproxy_delete` | Delete a resource. Params: `resource_type`, `uuid` | Yes |
| `opn_reconfigure_haproxy` | **Validates first** (refuses on a failing configtest), then applies pending changes | Yes |

### Services (8 tools)

| Tool | Description | Writes |
| --- | --- | --- |
| `opn_list_acme_certs` | ACME/Let's Encrypt certificates and status. Params: `search`, `limit` | No |
| `opn_list_cron_jobs` | Scheduled cron jobs. Params: `search`, `limit` | No |
| `opn_crowdsec_status` | CrowdSec engine status + active decisions + recent alerts. Params: `search`, `limit` | No |
| `opn_list_ddns_accounts` | Dynamic DNS accounts (credentials masked). Params: `search`, `limit` | No |
| `opn_manage_ddns_account` | Add/update/delete a DDNS account (applies immediately). Params: `action`, `uuid`, `service`, `hostname`, `username`, `password`, `checkip`, `interface`, `description`, `enabled` | Yes |
| `opn_reconfigure_ddclient` | Apply pending Dynamic DNS configuration changes | Yes |
| `opn_mdns_repeater_status` | mDNS Repeater status and configuration | No |
| `opn_configure_mdns_repeater` | Configure cross-VLAN mDNS relay (preserves unmanaged settings). Params: `enabled`, `interfaces` | Yes |

### Diagnostics (4 tools)

| Tool | Description |
| --- | --- |
| `opn_ping` | Ping from the firewall. Params: `host`, `count` (1-10) |
| `opn_traceroute` | Trace network path. Params: `host`, `protocol` (ICMP/UDP/TCP), `ip_version` (4/6) |
| `opn_dns_lookup` | DNS lookup from the firewall. Params: `hostname`, `server` |
| `opn_pf_states` | Active PF state table. Params: `search`, `limit` (max 1000) |

### Security (1 tool)

| Tool | Description |
| --- | --- |
| `opn_security_audit` | Comprehensive 11-area security audit with PCI DSS / BSI / NIST / CIS compliance tagging |

## Prompts & Resources

Beyond tools, the server exposes MCP **prompts** (guided multi-step workflows) and
**resources** (URI-addressable read-only context):

| Prompt | Purpose |
| --- | --- |
| `ipv6_migration` | Step-by-step IPv6 enablement for an interface (ICMPv6 rules, RA, DNS, DDNS, verification) |
| `expose_service` | Safely expose an internal service (VPN/reverse-proxy alternatives first, scoped NAT, hardening) |
| `remediate_audit` | Run the security audit and walk through fixing the top findings one at a time |

| Resource | Content |
| --- | --- |
| `opnsense://inventory` | Runtime inventory (firmware, plugins, DHCP/DNS backends, interfaces, services) |
| `opnsense://config/{section}` | Any parsed config.xml section as JSON (always redacted) |

## Untrusted Data (Threat Model)

Several tools surface strings that external parties control: DHCP lease hostnames and
ARP/NDP hostnames are set by client devices, CrowdSec alert fields derive from attacker
traffic, firewall log entries reflect observed packets, and DNS lookup responses come from
remote servers. A malicious device could name itself something that looks like an
instruction to an AI assistant.

The affected tools label this in their docstrings, and the server never interpolates such
content into its own guidance messages — but the final safeguard is the operator: treat
tool output as data, keep `OPNSENSE_ALLOW_WRITES=false` unless needed, and review every
write your assistant proposes.

## Write Operations and Savepoints

Write operations require `OPNSENSE_ALLOW_WRITES=true`. On **OPNsense < 26.7**, firewall *filter* changes
additionally go through OPNsense's savepoint mechanism:

1. **Before a filter-rule or category change**, a savepoint is created automatically
2. **The change is applied** (rule add, update, delete, or toggle)
3. **A 60-second countdown starts** — if not confirmed, OPNsense automatically reverts the change
4. **Use `opn_confirm_changes`** with the returned `revision` to make changes permanent —
   one change per savepoint (the server refuses a new savepoint while one is pending)

On those versions, if an AI assistant makes a bad firewall rule change that locks you out, the change
reverts automatically within 60 seconds.

**OPNsense 26.7 removed the savepoint/rollback API upstream, so there is no auto-revert on 26.7+.** The server does not hardcode a version cut-off: it probes for the savepoint endpoint on the first firewall write and, if OPNsense answers that the endpoint does not exist, degrades to direct apply for the rest of the session. Check `opn_mcp_info` — its `savepoint_support` field reports `true`, `false`, or `null` if no write has probed yet. Write tools then return an empty `revision`, `opn_confirm_changes` answers with `status: "not_applicable"`, and every firewall change is immediate and permanent.

> **Warning:** On OPNsense 26.7+ take a config backup (`opn_download_config`, or System > Configuration > Backups) before enabling writes, and keep out-of-band access to the box — a rule that locks you out will not revert itself.

> **NAT is the exception:** OPNsense's savepoint mechanism does not cover the NAT (port
> forward) model — `opn_manage_nat_rule` changes apply immediately and cannot be
> auto-reverted. The same applies to alias/DNS/DHCP/DDNS writes and the `opn_reconfigure_*`
> tools, which apply service configuration directly. `opn_reconfigure_haproxy` mitigates
> this by validating the configuration first and refusing to apply a broken one.

## IPv6 Support

### Fully Automated via MCP

- **IPv6 Firewall Rules** — Create rules with `ip_protocol="inet6"` (savepoint-protected on OPNsense < 26.7)
- **HAProxy IPv6 Bindings** — Frontends with `[::]:443` or `[2001:db8::1]:443` bind addresses
- **HAProxy IPv6 Backends** — Servers with IPv6 addresses, `resolvePrefer: ipv6` on backends
- **Dynamic DNS with IPv6** — DDNS accounts with IPv6-capable checkip methods
- **DHCPv6 Ranges (dnsmasq)** — IPv6 DHCP ranges with Router Advertisement configuration
- **DNS AAAA Records** — Unbound host overrides with IPv6 addresses
- **IPv6 Diagnostics** — Traceroute with `ip_version="6"`, ping via hostname

### Requires Manual GUI Configuration

These settings lack MVC API support in OPNsense and must be configured via the web GUI:

- **WAN IPv6 setup** — PPPoE with DHCPv6 prefix delegation, static IPv6, SLAAC
- **LAN IPv6 addressing** — Track Interface mode, static /64 assignment, prefix ID
- **Interface assignment** — Assigning physical ports to WAN/LAN/OPT roles
- **6to4/6rd tunnels** — Transition tunnel mechanisms

### Known Limitations

- **ISC DHCP / Kea DHCPv6**: Not implemented. Only dnsmasq (the modern default) is supported for DHCPv6 ranges and Router Advertisements. ISC DHCP is deprecated; Kea DHCPv6 lease visibility is limited in the API.
- **radvd**: Not implemented as a separate tool set. Dnsmasq handles Router Advertisements natively via range configuration. Only one RA daemon should run per interface.
- **Dual-stack firewall rules**: `inet46` (dual-stack) works correctly in MVC API rules (`opn_manage_firewall_rule`). However, `inet46` in legacy XML filter rules (GUI) silently produces no PF output — this is a known OPNsense bug that only affects legacy rules.
- **Legacy GUI rules**: Firewall rules created via the traditional OPNsense GUI are not accessible through the MVC API. Use `opn_get_config_section("filter")` for read-only access.

### Recommended IPv6 Migration Workflow

1. **Manual (GUI):** Configure WAN IPv6 (DHCPv6-PD from ISP or static)
2. **Manual (GUI):** Configure LAN interfaces (Track Interface mode for prefix delegation)
3. **MCP:** Configure Router Advertisements via `opn_manage_dnsmasq_range` with RA flags
4. **MCP:** Create IPv6 firewall rules (ICMPv6 must be allowed for NDP/RA/PMTUD)
5. **MCP:** Add IPv6 DNS records via `opn_manage_dns_override`
6. **MCP:** Configure Dynamic DNS with IPv6 checkip method
7. **MCP:** Add IPv6 bind addresses to HAProxy frontends
8. **MCP:** Verify with `opn_ping`, `opn_traceroute` (ip_version="6"), `opn_gateway_status`

## Version Compatibility

| OPNsense Version | Status |
| --- | --- |
| 24.7 (Thriving Tiger) | Supported |
| 25.1 (Ultimate Unicorn) | Supported |
| 25.7 (Visionary Viper) | Supported (auto-detects snake_case API) |
| 26.1+ | Supported |

The server automatically detects the OPNsense version on first connection and selects the correct API endpoint naming convention (camelCase for pre-25.7, snake_case for 25.7+).

**Note on firewall rules:** `opn_list_firewall_rules` shows rules managed via the MVC/automation API. Rules configured through the OPNsense GUI use a legacy format not accessible via this API. This is a known OPNsense limitation.

## Troubleshooting

### Connection Issues

#### "Connection refused" or timeout errors

- Verify `OPNSENSE_URL` ends with `/api` (e.g., `https://192.168.1.1/api`)
- If using a non-standard port, include it: `https://192.168.1.1:10443/api`
- Ensure the OPNsense web GUI is accessible from the machine running the MCP server

#### SSL certificate errors

- For self-signed certificates (default OPNsense setup), set `OPNSENSE_VERIFY_SSL=false`
- For production, install a proper certificate on OPNsense and keep `OPNSENSE_VERIFY_SSL=true`

### Authentication Issues

#### 401 Unauthorized

- Verify `OPNSENSE_API_KEY` and `OPNSENSE_API_SECRET` are correct
- API keys are case-sensitive — copy them exactly from the downloaded `apikey.txt`
- Check that the API user is not disabled in OPNsense
- Verify the API user has sufficient privileges for the operations you're attempting

#### 403 Forbidden

- The API user may lack permissions for the requested endpoint
- For write operations, ensure `OPNSENSE_ALLOW_WRITES=true` is set

### Tool-Specific Issues

#### `opn_list_firewall_rules` returns empty results

- This tool only shows MVC/automation rules, not legacy GUI rules
- Create rules via the automation API or `opn_manage_firewall_rule` to see them

#### `opn_ping` times out

- The firewall may not have a route to the target host
- Check gateway status with `opn_gateway_status`
- Default timeout is 30 seconds (30 poll cycles)

#### `opn_download_config` shows `[REDACTED]` values

- This is the default behavior for security. Pass `include_sensitive=true` to include passwords and keys (use with caution in AI conversations)

#### Write operations fail with "writes not enabled"

- Set `OPNSENSE_ALLOW_WRITES=true` in your MCP server configuration
- This is intentionally disabled by default for safety

#### Savepoint confirmation fails

- The `revision` parameter must match exactly what was returned by the write operation
- Confirmations must happen within 60 seconds or the change auto-reverts
- On OPNsense 26.7+ there is no savepoint API: write tools return an empty `revision` and `opn_confirm_changes` returns `status: "not_applicable"`. That is expected, not a failure — the change already applied permanently

### Diagnostic Commands

If you need to debug the MCP server:

```bash
# Test API connectivity directly
curl -k -u "your-key:your-secret" https://your-opnsense-ip/api/core/firmware/status

# Run the server directly
python -m opnsense_mcp

# Run tests to verify installation
pytest -v
```

## Development

```bash
# Clone and install dev dependencies
git clone https://github.com/lucamarien/opnsense-mcp-server
cd opnsense-mcp-server
pip install -e ".[dev]"

# Run all tests (no real OPNsense needed — all tests use mocked API)
pytest -v

# Full CI pipeline (lint, format, type check, security scan, tests)
make validate

# Individual checks
ruff check src/ tests/          # Lint (includes bandit security checks)
ruff format src/ tests/          # Format
mypy src/ --strict               # Type checking
```

## Best Practices

Domain-specific guides for common firewall configuration tasks:

- [WhatsApp Calling Firewall Rules](docs/best-practices/voip-whatsapp.md) — Allow WhatsApp voice/video calls through a default-deny firewall using URL table aliases and scoped rules
- [DDNS with Cloudflare](docs/best-practices/ddns-cloudflare.md) — Configure Dynamic DNS with Cloudflare API tokens, interface checkip methods, and IPv6 EUI-64 addresses

These guides show real-world MCP tool usage patterns and explain the security considerations behind each approach.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines. Key points:

1. All tests must use mocked API responses — never connect to a real OPNsense
2. No overlapping tools — each tool must have a distinct purpose
3. Write clear docstrings — they're the AI's only guide to tool selection
4. Return structured data (dicts), not formatted strings
5. Run `make validate` before submitting

## License

MIT
