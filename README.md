# OPNsense MCP Server

A secure [Model Context Protocol](https://modelcontextprotocol.io/) (MCP) server for managing OPNsense firewalls through AI assistants like [Claude Code](https://docs.anthropic.com/en/docs/claude-code), Cursor, and other MCP-compatible tools.

**62 tools** across 10 domains: system, firewall, network, DNS, DHCP, VPN, HAProxy, services, diagnostics, and security.

## Security Model

This MCP server is designed with security as the primary concern:

- **Read-only by default** — write operations require explicit opt-in via `OPNSENSE_ALLOW_WRITES=true`
- **Savepoint/rollback** — all firewall modifications use OPNsense's built-in 60-second auto-revert mechanism; changes must be explicitly confirmed or they roll back automatically
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
docker pull lucamarien/opnsense-mcp-server

# From source
git clone https://github.com/lucamarien/opnsense-mcp-server
cd opnsense-mcp-server
pip install -e .
```

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
        "lucamarien/opnsense-mcp-server"
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
| `OPNSENSE_URL` | `https://192.168.1.1/api` | OPNsense API base URL (must end with `/api`) |
| `OPNSENSE_API_KEY` | *(required)* | API key from OPNsense user settings |
| `OPNSENSE_API_SECRET` | *(required)* | API secret from OPNsense user settings |
| `OPNSENSE_VERIFY_SSL` | `true` | Verify SSL certificate (`false` for self-signed certs) |
| `OPNSENSE_ALLOW_WRITES` | `false` | Enable write operations (firewall rules, service control) |

**Custom ports:** If your OPNsense web GUI runs on a non-standard port (e.g., 10443), include it in the URL: `https://192.168.1.1:10443/api`

## Available Tools (62)

### System (6 tools)

| Tool | Description |
| --- | --- |
| `opn_system_status` | System info including firmware version, product name, and architecture |
| `opn_list_services` | List all services and their running status. Params: `search`, `limit` |
| `opn_gateway_status` | Gateway availability, latency, and dpinger health checks |
| `opn_download_config` | Download `config.xml` backup with optional sensitive data stripping. Params: `include_sensitive` (default: `false` — passwords and keys are redacted) |
| `opn_scan_config` | Scan the full configuration, parse it into sections, and collect runtime inventory (firmware, plugins, DHCP, DNS, interfaces, services). Results are cached per session. Params: `force` |
| `opn_get_config_section` | Get a specific config section as structured JSON. Params: `section`, `include_sensitive` |

### Network (5 tools)

| Tool | Description |
| --- | --- |
| `opn_interface_stats` | Per-interface traffic statistics (bytes in/out, packets, errors) |
| `opn_arp_table` | ARP table showing IP-to-MAC address mappings |
| `opn_ndp_table` | NDP (Neighbor Discovery Protocol) table showing IPv6-to-MAC address mappings |
| `opn_ipv6_status` | IPv6 configuration and address status for all interfaces (method, live addresses, summary) |
| `opn_list_static_routes` | Configured static routes. Params: `search`, `limit` |

### Firewall (15 tools)

| Tool | Description | Writes |
| --- | --- | --- |
| `opn_list_firewall_rules` | List MVC firewall filter rules. Params: `search`, `limit` | No |
| `opn_list_firewall_aliases` | List alias definitions (IP lists, port groups, GeoIP, URLs). Params: `search`, `limit` | No |
| `opn_list_nat_rules` | List NAT port forwarding (DNAT) rules. Params: `search`, `limit` | No |
| `opn_list_firewall_categories` | List firewall rule categories and their UUIDs. Params: `search`, `limit` | No |
| `opn_firewall_log` | Recent firewall log entries with client-side filtering. Params: `source_ip`, `destination_ip`, `action`, `interface`, `limit` | No |
| `opn_confirm_changes` | Confirm pending changes, cancelling 60-second auto-rollback. Params: `revision` | Yes |
| `opn_toggle_firewall_rule` | Toggle a rule's enabled/disabled state with savepoint. Params: `uuid` | Yes |
| `opn_add_firewall_rule` | Create a new filter rule with savepoint. Params: `action`, `direction`, `interface`, `ip_protocol`, `protocol`, `source_net`, `destination_net`, `destination_port`, `description` | Yes |
| `opn_delete_firewall_rule` | Delete a filter rule by UUID with savepoint. Params: `uuid` | Yes |
| `opn_add_alias` | Create a new alias. Params: `name`, `alias_type`, `content`, `description` | Yes |
| `opn_add_nat_rule` | Create a NAT port forwarding rule with savepoint. Params: `destination_port`, `target_ip`, `interface`, `protocol`, `target_port`, `description` | Yes |
| `opn_add_firewall_category` | Create a new firewall rule category. Params: `name`, `color` | Yes |
| `opn_delete_firewall_category` | Delete a firewall rule category by UUID with savepoint. Params: `uuid` | Yes |
| `opn_set_rule_categories` | Assign categories to a firewall rule with savepoint. Params: `uuid`, `categories` | Yes |
| `opn_add_icmpv6_rules` | Create essential ICMPv6 rules required for IPv6 operation (NDP, RA, ping6) per RFC 4890. Params: `interface` | Yes |

### DNS (5 tools)

| Tool | Description | Writes |
| --- | --- | --- |
| `opn_list_dns_overrides` | Unbound host overrides (local DNS records). Params: `search`, `limit` | No |
| `opn_list_dns_forwards` | DNS forward zones (domain-specific servers). Params: `search`, `limit` | No |
| `opn_dns_stats` | Unbound resolver statistics (queries, cache hits, uptime) | No |
| `opn_reconfigure_unbound` | Apply pending DNS resolver configuration changes | Yes |
| `opn_add_dns_override` | Add an Unbound DNS host override (A/AAAA record) and apply immediately. Params: `hostname`, `domain`, `server`, `description` | Yes |

### DHCP (6 tools)

| Tool | Description | Writes |
| --- | --- | --- |
| `opn_list_dhcp_leases` | Active DHCPv4 leases from the ISC DHCP server | No |
| `opn_list_kea_leases` | DHCPv4 leases from the Kea DHCP server. Params: `search`, `limit` | No |
| `opn_list_dnsmasq_leases` | DHCPv4 and DHCPv6 leases from the dnsmasq DNS/DHCP server. Params: `search`, `limit` | No |
| `opn_list_dnsmasq_ranges` | Configured DHCP address ranges (both DHCPv4 and DHCPv6 with RA config). Params: `search`, `limit` | No |
| `opn_add_dnsmasq_range` | Create a new DHCP range (IPv4 or IPv6 with Router Advertisement configuration). Params: `interface`, `start_addr`, `end_addr`, `prefix_len`, `ra_mode`, `lease_time`, `description` | Yes |
| `opn_reconfigure_dnsmasq` | Apply pending dnsmasq DNS/DHCP configuration changes | Yes |

### VPN (3 tools)

| Tool | Description |
| --- | --- |
| `opn_wireguard_status` | WireGuard tunnel and peer status (requires os-wireguard plugin) |
| `opn_ipsec_status` | IPsec VPN tunnel status — IKE (Phase 1) and ESP/AH (Phase 2) sessions |
| `opn_openvpn_status` | OpenVPN connection status — instances, sessions, and routes |

### HAProxy (8 tools)

Full configuration management for the HAProxy load balancer (requires os-haproxy plugin).

| Tool | Description | Writes |
| --- | --- | --- |
| `opn_haproxy_status` | HAProxy service status and backend health | No |
| `opn_haproxy_search` | Search HAProxy resources by type. Params: `resource_type` (frontends/backends/servers/actions/acls/healthchecks/errorfiles/resolvers/mailers), `search`, `limit` | No |
| `opn_haproxy_get` | Get detailed configuration for a specific resource. Params: `resource_type`, `uuid` | No |
| `opn_haproxy_configtest` | Validate HAProxy configuration syntax before applying | No |
| `opn_haproxy_add` | Create a new HAProxy resource. Params: `resource_type`, `config` (dict of field values) | Yes |
| `opn_haproxy_update` | Update an existing HAProxy resource (partial updates). Params: `resource_type`, `uuid`, `config` | Yes |
| `opn_haproxy_delete` | Delete a HAProxy resource by UUID. Params: `resource_type`, `uuid` | Yes |
| `opn_reconfigure_haproxy` | Apply pending HAProxy configuration changes | Yes |

> **Note:** HAProxy changes do NOT use savepoint protection — they apply immediately on reconfigure. Always call `opn_haproxy_configtest` before `opn_reconfigure_haproxy`.

### Services (9 tools)

| Tool | Description | Writes |
| --- | --- | --- |
| `opn_list_acme_certs` | ACME/Let's Encrypt certificates and their status. Params: `search`, `limit` | No |
| `opn_list_cron_jobs` | Scheduled cron jobs. Params: `search`, `limit` | No |
| `opn_crowdsec_status` | CrowdSec security engine status and active decisions | No |
| `opn_crowdsec_alerts` | CrowdSec security alerts (detected threats). Params: `search`, `limit` | No |
| `opn_list_ddns_accounts` | Dynamic DNS accounts and their update status. Params: `search`, `limit` | No |
| `opn_add_ddns_account` | Create a new Dynamic DNS account. Params: `service`, `hostname`, `username`, `password`, `checkip`, `interface`, `description` | Yes |
| `opn_reconfigure_ddclient` | Apply pending Dynamic DNS configuration changes | Yes |
| `opn_mdns_repeater_status` | mDNS Repeater status and configuration (enabled, interfaces, blocklist). Requires `os-mdns-repeater` plugin | No |
| `opn_configure_mdns_repeater` | Configure mDNS Repeater for cross-VLAN device discovery (HomeKit, Chromecast, AirPlay). Params: `enabled`, `interfaces` | Yes |

### Diagnostics (4 tools)

| Tool | Description |
| --- | --- |
| `opn_ping` | Ping a host from the firewall to test connectivity. Params: `host`, `count` (1-10, default 3) |
| `opn_traceroute` | Trace network path to a destination. Params: `host`, `protocol` (ICMP/UDP/TCP), `ip_version` (4/6) |
| `opn_dns_lookup` | DNS lookup from the firewall. Params: `hostname`, `server` (optional custom DNS server) |
| `opn_pf_states` | Query active PF state table. Params: `search`, `limit` (max 1000) |

### Security (1 tool)

| Tool | Description |
| --- | --- |
| `opn_security_audit` | Comprehensive 11-area security audit: firmware, firewall rules (MVC + legacy, port grouping, insecure protocols), NAT forwarding, DNS security (DNSSEC, DoT), system hardening (SSH, HTTPS, syslog), services, certificates (ACME + system + CAs), VPN (WireGuard config, IPsec, OpenVPN), HAProxy (headers, health checks), gateways. Findings tagged with PCI DSS v4.0, BSI IT-Grundschutz, NIST 800-41, CIS compliance references. |

## Write Operations and Savepoints

Write operations require `OPNSENSE_ALLOW_WRITES=true` and use OPNsense's savepoint mechanism for safety:

1. **Before any firewall change**, a savepoint is created automatically
2. **The change is applied** (rule toggle, add, or delete)
3. **A 60-second countdown starts** — if not confirmed, OPNsense automatically reverts the change
4. **Use `opn_confirm_changes`** with the returned `revision` to make changes permanent

This means if an AI assistant makes a bad firewall change that locks you out, the change will automatically revert within 60 seconds.

> **Note:** `opn_reconfigure_unbound`, `opn_reconfigure_haproxy`, `opn_reconfigure_ddclient`, `opn_reconfigure_dnsmasq`, and `opn_configure_mdns_repeater` require writes but don't use savepoints — they apply service configuration changes and are not automatically revertible.

## IPv6 Support

### Fully Automated via MCP

- **IPv6 Firewall Rules** — Create rules with `ip_protocol="inet6"` (savepoint-protected)
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
- **Dual-stack firewall rules**: `inet46` (dual-stack) works correctly in MVC API rules (`opn_add_firewall_rule`). However, `inet46` in legacy XML filter rules (GUI) silently produces no PF output — this is a known OPNsense bug that only affects legacy rules.
- **Legacy GUI rules**: Firewall rules created via the traditional OPNsense GUI are not accessible through the MVC API. Use `opn_get_config_section("filter")` for read-only access.

### Recommended IPv6 Migration Workflow

1. **Manual (GUI):** Configure WAN IPv6 (DHCPv6-PD from ISP or static)
2. **Manual (GUI):** Configure LAN interfaces (Track Interface mode for prefix delegation)
3. **MCP:** Configure Router Advertisements via `opn_add_dnsmasq_range` with RA flags
4. **MCP:** Create IPv6 firewall rules (ICMPv6 must be allowed for NDP/RA/PMTUD)
5. **MCP:** Add IPv6 DNS records via `opn_add_dns_override`
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
- Create rules via the automation API or `opn_add_firewall_rule` to see them

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

These guides show real-world MCP tool usage patterns and explain the security considerations behind each approach.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines. Key points:

1. All tests must use mocked API responses — never connect to a real OPNsense
2. Keep total tool count under 65 (currently 62)
3. Write clear docstrings — they're the AI's only guide to tool selection
4. Return structured data (dicts), not formatted strings
5. Run `make validate` before submitting

## License

MIT
