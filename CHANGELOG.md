# Changelog

All notable changes to this project will be documented in this file.

This project follows [Semantic Versioning](https://semver.org/).

## [0.3.5] - 2026-03-25

### Added

- **System:** `opn_mcp_info` — query MCP server version, write mode, detected OPNsense version, and API style
- **System:** MCP server version now included in protocol-level `initialize` handshake via FastMCP
- **DNS:** `opn_update_dnsbl` — reload DNSBL blocklist files and restart Unbound without config changes (manual recovery tool)

### Fixed

- **DNS:** DNSBL tools (`opn_set_dnsbl`, `opn_add_dnsbl_allowlist`, `opn_remove_dnsbl_allowlist`) now restart Unbound after regenerating blocklist files, flushing DNS cache so changes take effect immediately. Previously, old cached `0.0.0.0` entries (TTL 72000s) persisted and toggling DNSBL off→on left lists unloaded.

### Changed

- **DNS:** DNSBL tool response format changed from `{"applied": "OK"}` to `{"dnsbl_status": "OK", "service_status": "ok"}` for clearer status reporting

## [0.3.4] - 2026-03-24

### Added

- **DNS:** 5 new DNSBL (DNS Blocklist) management tools:
  - `opn_list_dnsbl` — list blocklist configurations with providers and status
  - `opn_get_dnsbl` — get full blocklist config by UUID (providers, allowlists, settings)
  - `opn_set_dnsbl` — update blocklist settings (read-modify-write, preserves unmodified fields)
  - `opn_add_dnsbl_allowlist` — add domains to allowlist without overwriting existing entries
  - `opn_remove_dnsbl_allowlist` — remove domains from allowlist
- **DNS:** 8 new API endpoints registered for Unbound DNSBL operations
- **Integration tests:** DNSBL read-only tests in live test suite, plus dedicated write round-trip test

### Changed

- **CI:** Updated GitHub Actions to Node.js 24-compatible versions (checkout v5, setup-python v6, docker/login-action v4, docker/build-push-action v7)
- **Docs:** Replaced arbitrary tool count cap with quality guidelines (no overlapping tools, clear naming)

## [0.3.3] - 2026-03-23

### Added

- **Firewall:** `opn_add_firewall_rule` now supports 8 additional parameters:
  - `destination_not` — invert destination match (e.g. `!Private_Networks` for internet-only rules)
  - `sequence` — control rule ordering within priority groups
  - `source_not` — invert source match
  - `categories` — assign category UUIDs at creation time (saves extra API roundtrip)
  - `source_port` — source port filtering
  - `log` — per-rule logging toggle
  - `gateway` — policy-based routing via specific gateway
  - `quick` — now configurable (was hardcoded to True); set False for last-match-wins logic

## [0.3.2] - 2026-03-17

### Fixed

- **Diagnostics:** `opn_dns_lookup` now sends correct API payload (`dns.settings.hostname` instead of `dns.hostname`) — lookups were silently failing with validation error
- **VPN:** `opn_ipsec_status` now uses POST for `searchPhase1`/`searchPhase2` endpoints — GET was returning empty or failed responses
- **VPN:** `opn_openvpn_status` now uses POST with pagination for all three search endpoints (instances, sessions, routes)
- **Services:** `opn_crowdsec_status` now uses POST for decisions/alerts search — consistent with `opn_crowdsec_alerts`

### Security

- **Diagnostics:** Expanded hostname validation to reject additional shell metacharacters (`(`, `)`, `{`, `}`, `<`, `>`, `'`, `"`, `\`, space)
- **Diagnostics:** `opn_dns_lookup` now validates the `server` parameter against the same injection rules as `hostname`

### Changed

- **Firewall:** `opn_firewall_log` now supports client-side filtering via `source_ip`, `destination_ip`, `action`, `interface`, and `limit` parameters — reduces context window size when investigating specific devices

## [0.3.1] - 2026-02-25

Packaging readiness and documentation sync.

### Fixed

- Version numbers synced across pyproject.toml, \_\_init\_\_.py, and CHANGELOG (was stuck at 0.1.0)
- README updated to document all 60 tools (was 57 — missing firewall categories, ICMPv6 rules, NDP table, IPv6 status)
- Narrowed broad `except Exception` to specific exceptions in `opn_ipv6_status`

### Added

- CLI entry point: `opnsense-mcp` command available after `pip install`
- `__main__.py` for `python -m opnsense_mcp` support
- PEP 561 `py.typed` marker for downstream type checking
- Test registration updated to cover all 60 tools

## [0.3.0] - 2026-02-22

Comprehensive security audit overhaul — from 4 surface-level checks to 11 in-depth security areas with compliance framework tagging.

### Changed

- **Security:** `opn_security_audit` completely rewritten with 11 audit sections (was 4):
  - **Firewall rules:** Paginated analysis (no more 500-row cap), MVC + legacy config.xml rules, broad source/destination detection, port grouping best practices (SSH isolation, mixed service detection), management port exposure on WAN, insecure protocol detection (FTP, Telnet, plaintext SMTP/POP3/IMAP/LDAP, rsh/rlogin)
  - **NAT port forwarding:** Dangerous port exposure, unrestricted sources, UDP amplification risk, insecure protocol forwarding
  - **DNS security:** DNSSEC validation, DNS-over-TLS forwarding, resolver identity/version hiding
  - **System hardening:** Web GUI HTTPS enforcement, SSH root login/password auth/default port, remote syslog configuration
  - **Services:** Expanded critical service list (7 services, was 4), CrowdSec plugin detection
  - **Certificates:** ACME + system certificate store + CA certificates (not just ACME)
  - **VPN security:** WireGuard config audit with stale peer detection, IPsec status, OpenVPN instances
  - **HAProxy security:** HTTP frontend detection, HTTPS redirect checks, backend health checks, security header audit (HSTS, X-Frame-Options, X-Content-Type-Options)
  - **Gateway health:** Down/offline detection, packet loss >5%, latency >100ms
  - **Compliance tagging:** Every finding tagged with applicable PCI DSS v4.0, BSI IT-Grundschutz, NIST SP 800-41, and CIS Benchmark controls. Manual review items listed separately.

### Added

- 6 new read-only API endpoint registrations: WireGuard server/client search, HAProxy frontend/backend/server/action search
- `_fetch_all_pages` pagination helper for unbounded rule analysis
- Port parsing, classification, and insecure protocol detection helpers
- 97 security tests (was 18)

## [0.2.0] - 2026-02-22

Expands from 35 to 41 tools with NAT port forwarding, full VPN coverage, DNS write operations, and static route visibility.

### Added

- **Firewall:** `opn_list_nat_rules` — list NAT port forwarding (DNAT) rules with search/pagination
- **Firewall:** `opn_add_nat_rule` — create NAT port forwarding rules with savepoint protection
- **VPN:** `opn_ipsec_status` — IPsec tunnel status (IKE Phase 1 + ESP/AH Phase 2)
- **VPN:** `opn_openvpn_status` — OpenVPN instances, sessions, and routes
- **DNS:** `opn_add_dns_override` — add Unbound host overrides (A/AAAA) with auto-reconfigure and input validation
- **Network:** `opn_list_static_routes` — list configured static routes with search/pagination
- 11 new API endpoint registrations with dual camelCase/snake_case support
- DNS input validation (hostname, domain, IP address regex)
- NAT protocol validation (TCP, UDP, TCP/UDP)

## [0.1.0] - 2026-02-21

Initial release with 35 tools across 9 domains.

### Added

#### Phase 1: Foundation

- Core infrastructure: config loading, API client with HTTP Basic Auth, SSL verification, 30s timeout
- OPNsense version auto-detection (camelCase for pre-25.7, snake_case for 25.7+)
- Dual endpoint registry supporting both API naming conventions
- Endpoint blocklist: `halt`, `reboot`, `poweroff`, `firmware update/upgrade` are permanently blocked
- FastMCP server with STDIO transport
- 16 read-only tools:
  - **System:** `opn_system_status`, `opn_list_services`, `opn_gateway_status`
  - **Network:** `opn_interface_stats`, `opn_arp_table`
  - **Firewall:** `opn_list_firewall_rules`, `opn_list_firewall_aliases`, `opn_firewall_log`
  - **DNS:** `opn_list_dns_overrides`, `opn_list_dns_forwards`, `opn_dns_stats`
  - **DHCP:** `opn_list_dhcp_leases`
  - **VPN:** `opn_wireguard_status`
  - **Services:** `opn_haproxy_status`, `opn_list_acme_certs`, `opn_list_cron_jobs`

#### Phase 2: Write Operations

- SavepointManager for safe firewall modifications with 60-second auto-rollback
- Write guard requiring `OPNSENSE_ALLOW_WRITES=true` environment variable
- 8 write tools:
  - **Firewall:** `opn_confirm_changes`, `opn_toggle_firewall_rule`, `opn_add_firewall_rule`, `opn_delete_firewall_rule`, `opn_add_alias`
  - **DNS:** `opn_reconfigure_unbound`
  - **Services:** `opn_reconfigure_haproxy`

#### Phase 3: Advanced Features

- **Security:** `opn_security_audit` — comprehensive firewall audit (firmware, permissive rules, disabled rules, critical services, ACME certificates)
- **Config:** `opn_download_config` — download `config.xml` with XML-aware sensitive data stripping (passwords, keys, secrets redacted by default)
- **Config:** `opn_scan_config` — session-cached full configuration scan with runtime inventory
- **Config:** `opn_get_config_section` — retrieve individual config sections as structured JSON
- **Diagnostics:** `opn_ping` (async job-based with guaranteed cleanup), `opn_traceroute`, `opn_dns_lookup`, `opn_pf_states`
- **DHCP:** `opn_list_kea_leases` — Kea DHCP server leases
- **DHCP:** `opn_list_dnsmasq_leases` — dnsmasq DNS/DHCP server leases
- **Services:** `opn_crowdsec_status`, `opn_crowdsec_alerts` — CrowdSec security engine status and alerts
- ConfigCache system for session-scoped config caching with automatic invalidation on writes
- Hostname input validation against shell metacharacter injection
- `get_text()` API client method for non-JSON responses (XML config backup)

### Security

- Bandit security scanning via Ruff (S105/S106/S107 for hardcoded credentials, S501 for SSL verification)
- Strict mypy type checking
- All tests use mocked API — no real OPNsense credentials in test suite
- 242 tests with full coverage of security-critical paths
