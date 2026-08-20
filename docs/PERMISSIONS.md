# Tool → OPNsense Privilege Map

Maps every `opn_*` MCP tool to the OPNsense REST API endpoint(s) it calls and the
OPNsense privilege/ACL (System > Access > Groups) required to grant it — so you can
create a minimally-scoped API key instead of handing this server a full-admin account.

## Read this first

- **OPNsense's API enforces the exact same ACL checks as the GUI.** `ACL.php`'s
  `isPageAccessible()` runs one `urlMatch()` against both `ui/...` and `api/...`
  patterns under the same privilege key — there is no separate, coarser API
  permission model. Fine-grained scoping is genuinely achievable.
  ([ACL.php](https://github.com/opnsense/core/blob/master/src/opnsense/mvc/app/models/OPNsense/Core/ACL.php),
  [acl.html](https://docs.opnsense.org/development/components/acl.html))
- **Granularity is per page/feature, not per HTTP method or single endpoint.** Some
  modules split read (list/search/get) from write (add/set/del/toggle) into two
  privileges (e.g. Firewall Aliases); others bundle everything — read and write — into
  one privilege (e.g. HAProxy, IPsec Connections). Check each module below.
- **Known legacy-endpoint gotcha**: [opnsense/core#9093](https://github.com/opnsense/core/issues/9093)
  (closed, not planned) — scoping to "Diagnostics: ARP Table" causes the legacy
  camelCase endpoint (`api/diagnostics/interface/getArp`) to 403 while the newer
  snake_case form (`get_arp`) works, because the ACL pattern only lists the new name.
  This server's `api_client.py` picks camelCase or snake_case based on your detected
  OPNsense version (`25.7` threshold) — **when scoping a key, test the exact form your
  OPNsense version will actually call**, not just the one listed here.
- **This table is original work, not a re-derivation of an existing community
  reference** — none was found. It was built by pairing this repo's
  `src/opnsense_mcp/api_client.py` `ENDPOINT_REGISTRY` (the source of truth for
  endpoints) against OPNsense's own per-module `ACL.xml` files. Several entries below
  are flagged `⚠️ unverified` or `❓ not researched` where the source ACL.xml extraction
  was incomplete or the module wasn't covered — **before treating a scoped group as
  authoritative, create it and empirically test each tool you intend to allow (expect
  200, not 403) against a real instance.**

### Confidence legend

| Marker | Meaning |
|---|---|
| ✅ | Privilege confirmed directly against the module's `ACL.xml` pattern list |
| ⚠️ | Likely privilege identified, but the exact API pattern wasn't confirmed in the source extraction — verify directly before relying on it |
| ❓ | Module's ACL.xml wasn't researched this pass — privilege unknown, check `System > Access > Groups` or the module's `ACL/ACL.xml` directly |

## Always blocked, regardless of privilege

`BLOCKED_ENDPOINTS` in `api_client.py` hard-blocks these at the application layer — no
OPNsense privilege grant makes them callable through this server:
`core/system/halt`, `core/system/reboot`, `core/firmware/poweroff`,
`core/firmware/update`, `core/firmware/upgrade`.

## Broad, hard-to-scope tools

`opn_scan_config` and `opn_get_config_section` front a session-cached parse of the
**full `config.xml`** via `core.backup.download` (`core/backup/download/this`) — the
same privilege (`page-diagnostics-configurationhistory`, "Diagnostics: Configuration
History") that grants the entire config export, secrets included. This can't be scoped
narrower than "can download the whole config." It's also the surface for this project's
audit HIGH-3 finding (secret-redaction gap) — see the consuming project's own
audit report for current fix status before granting this privilege.

`opn_security_audit` is a single composite tool that internally calls endpoints across
nearly every module in this doc (firewall, NAT, unbound, services, ACME, WireGuard,
IPsec, OpenVPN, HAProxy, gateway). Meaningfully scoping a key for this tool alone
requires granting most of the read-side privileges below — it doesn't have a
single narrow privilege of its own.

## Tool tables

### System

| Tool | Endpoint(s) | Privilege | Notes |
|---|---|---|---|
| `opn_system_status` | `core/firmware/status` | ❓ not researched | |
| `opn_list_services` | `core/service/search` | ❓ not researched | |
| `opn_gateway_status` | `routes/gateway/status` | ❓ not researched | |
| `opn_download_config` | `core/backup/download/this` | ✅ `page-diagnostics-configurationhistory` — "Diagnostics: Configuration History" | full config export, secrets included |
| `opn_scan_config` | `core/firmware/info`, `dnsmasq.*`, `kea.*`, `dhcpv4/leases/searchLease`, `unbound/settings/get`, `interface.config`, `interface.names`, **+** `core/backup/download/this` | mixed — see "Broad, hard-to-scope tools" above | triggers a full config download |
| `opn_get_config_section` | reads from `opn_scan_config`'s cache (triggers a scan if not yet loaded) | same as `opn_scan_config` | |
| `opn_mcp_info` | none (local server metadata) | none | |

### Network / Diagnostics — interfaces & routes

| Tool | Endpoint(s) | Privilege | Notes |
|---|---|---|---|
| `opn_interface_stats` | `diagnostics/interface/getInterfaceStatistics` | ⚠️ `page-diagnostics-netstat` ("get_interface_statistics" is listed under this key) — `page-status-interfaces` ("Status: Interfaces", `api/interfaces/overview/*`) is a plausible alternate; unconfirmed which the server actually needs | |
| `opn_arp_table` | `diagnostics/interface/getArp` | ✅ `page-diagnostics-arptable` — "Diagnostics: ARP Table" | ⚠️ **#9093**: camelCase form may 403 under this privilege on some versions — test directly |
| `opn_ndp_table` | `diagnostics/interface/getNdp` | ⚠️ `page-diagnostics-ndptable` — "Diagnostics: NDP Table" | same camelCase/snake_case risk as ARP is plausible but not separately confirmed |
| `opn_ipv6_status` | `diagnostics/interface/getInterfaceConfig` | ❓ not researched | |
| `opn_list_static_routes` | `routes/routes/searchroute` | ❓ not researched — check the Routing module's `ACL.xml` | |

### Firewall — rules & filter

| Tool | Endpoint(s) | Privilege | Notes |
|---|---|---|---|
| `opn_list_firewall_rules` | `firewall/filter/searchRule` | ⚠️ `page-firewall-rules` — "Firewall: Rules" | this exact `api/firewall/filter/*` pattern wasn't confirmed in the source extraction (only `firewall_rules.php*` and a couple of narrower `api/firewall/...` patterns surfaced) — verify directly |
| `opn_confirm_changes` | `firewall/filter/cancelRollback` | ⚠️ `page-firewall-rules-edit` — "Firewall: Rules: Edit" | same caveat |
| `opn_toggle_firewall_rule` | `savepoint` → `firewall/filter/toggleRule` → `apply` | ⚠️ `page-firewall-rules-edit` | |
| `opn_add_firewall_rule` | `savepoint` → `firewall/filter/addRule` → `apply` | ⚠️ `page-firewall-rules-edit` | |
| `opn_delete_firewall_rule` | `savepoint` → `firewall/filter/delRule` → `apply` | ⚠️ `page-firewall-rules-edit` | |
| `opn_update_firewall_rule` | `savepoint` → `firewall/filter/setRule` → `apply` | ⚠️ `page-firewall-rules-edit` | |
| `opn_set_rule_categories` | `savepoint` → `firewall/filter/setRule` → `apply` | ⚠️ `page-firewall-rules-edit` | same endpoint as update, patches `categories` only |
| `opn_add_icmpv6_rules` | `savepoint` → `firewall/filter/addRule` ×5 → `apply` | ⚠️ `page-firewall-rules-edit` | |

> The `savepoint → action → apply` trio (`firewall/filter/savepoint`,
> the specific action, `firewall/filter/apply`) is shared by every firewall/NAT write
> tool above and below — all three calls need the same privilege as the action itself.

### Firewall — aliases

| Tool | Endpoint(s) | Privilege | Notes |
|---|---|---|---|
| `opn_list_firewall_aliases` | `firewall/alias/searchItem` | ✅ `page-firewall-aliases` — "Firewall: Aliases" | read-only privilege, confirmed to include `search*`/`get*`/`export`/`list*` |
| `opn_add_alias` | `firewall/alias/addItem` | ✅ `page-firewall-alias-edit` — "Firewall: Alias: Edit" | |
| `opn_update_alias` | `firewall/alias/getItem` + `firewall/alias/setItem` | ✅ `page-firewall-alias-edit` (write) — `getItem` also needs `page-firewall-aliases` (read) | |
| `opn_delete_alias` | `firewall/alias/delItem` | ✅ `page-firewall-alias-edit` | |
| `opn_toggle_alias` | `firewall/alias/toggleItem` | ✅ `page-firewall-alias-edit` | |

### Firewall — categories

| Tool | Endpoint(s) | Privilege | Notes |
|---|---|---|---|
| `opn_list_firewall_categories` | `firewall/category/searchItem` | ⚠️ possibly `page-firewall-rules` (a `category/search_item*` pattern was seen under this key, but for the *rules* privilege, not confirmed as the categories module's own key) | |
| `opn_add_firewall_category` | `firewall/category/addItem` | ❓ not researched | |
| `opn_delete_firewall_category` | `firewall/category/delItem` | ❓ not researched | |

### Firewall — NAT

| Tool | Endpoint(s) | Privilege | Notes |
|---|---|---|---|
| `opn_list_nat_rules` | `firewall/d_nat/searchRule` | ⚠️ `page-firewall-nat-portforward-edit` — "Firewall: NAT: Destination NAT" | single privilege, no separate read-only split found |
| `opn_add_nat_rule` | `savepoint` → `firewall/d_nat/addRule` → `apply` | ⚠️ `page-firewall-nat-portforward-edit` **+** `page-firewall-rules-edit` (shared savepoint/apply) | |
| `opn_update_nat_rule` | `savepoint` → `firewall/d_nat/setRule` → `apply` | ⚠️ same as above | |
| `opn_delete_nat_rule` | `savepoint` → `firewall/d_nat/delRule` → `apply` | ⚠️ same as above | |

### DNS (Unbound)

| Tool | Endpoint(s) | Privilege | Notes |
|---|---|---|---|
| `opn_list_dns_overrides` | `unbound/settings/searchHostOverride` | ✅ `page-services-dnsresolver-overrides` — "Host/domain overrides" | |
| `opn_add_dns_override` | `unbound/settings/addHostOverride` + `unbound/service/reconfigure` | ✅ `page-services-dnsresolver-overrides` **+** reconfigure privilege below | |
| `opn_update_dns_override` | `unbound/settings/setHostOverride` + reconfigure | ✅ same | |
| `opn_delete_dns_override` | `unbound/settings/delHostOverride` + reconfigure | ✅ same | |
| `opn_list_dns_forwards` | `unbound/settings/searchForward` | ❓ not researched — no dedicated "forwards" key surfaced | |
| `opn_dns_stats` | `unbound/diagnostics/stats` | ⚠️ possibly `page-status-dnsoverview` ("Status: DNS Overview", grants `api/unbound/overview*`) — pattern match to `diagnostics/stats` not confirmed | |
| `opn_reconfigure_unbound` | `unbound/service/reconfigure` | ⚠️ `page-services-unbound` (catch-all "Services: Unbound", `api/unbound/*`) — no dedicated reconfigure key found, likely falls to the catch-all | |
| `opn_list_dnsbl` / `opn_get_dnsbl` / `opn_set_dnsbl` / `opn_add_dnsbl_allowlist` / `opn_remove_dnsbl_allowlist` / `opn_update_dnsbl` | `unbound/settings/*Dnsbl`, `unbound/service/dnsbl` | ❓ not researched — no DNSBL-specific key confirmed; may fall under `page-services-dnsresolver-acls` ("Access Lists") or the catch-all `page-services-unbound` | |

### DHCP

| Tool | Endpoint(s) | Privilege | Notes |
|---|---|---|---|
| `opn_list_dhcp_leases` | `dhcpv4/leases/searchLease` | ✅ `page-status-dhcpleases` — "Status: DHCP leases" (legacy ISC backend) | |
| `opn_list_kea_leases` | `kea/leases4/search` | ✅ `page-dhcp-kea-v4` — "Services: DHCP: Kea(v4)" | |
| `opn_list_dnsmasq_leases` | `dnsmasq/leases/search` | ❓ not researched — Dnsmasq module ACL not covered this pass | |
| `opn_list_dnsmasq_ranges` | `dnsmasq/settings/searchRange` | ❓ not researched | |
| `opn_add_dnsmasq_range` | `dnsmasq/settings/addRange` + reconfigure | ❓ not researched | |
| `opn_update_dnsmasq_range` | `dnsmasq/settings/setRange` + reconfigure | ❓ not researched | |
| `opn_delete_dnsmasq_range` | `dnsmasq/settings/delRange` + reconfigure | ❓ not researched | |
| `opn_reconfigure_dnsmasq` | `dnsmasq/service/reconfigure` | ❓ not researched | |

### VPN

| Tool | Endpoint(s) | Privilege | Notes |
|---|---|---|---|
| `opn_wireguard_status` | `wireguard/service/show` | ✅ `page-wireguard-diagnostics` — "VPN: WireGuard: Status" (also granted by `page-wireguard-config`) | WireGuard moved plugin→core ~22.1; confirm your version has it under `OPNsense/Wireguard` |
| `opn_ipsec_status` | `ipsec/service/status`, `ipsec/sessions/searchPhase1`, `ipsec/sessions/searchPhase2` | ⚠️ `ipsec/service/status` is granted by any of `page-vpn-ipsec-keypairs`/`-connections`/`-spd`; the two session-search endpoints likely need `page-status-ipsec`/`-sad`/`-spd` specifically — not individually confirmed | |
| `opn_openvpn_status` | `openvpn/instances/search`, `openvpn/service/searchSessions`, `openvpn/service/searchRoutes` | ⚠️ `page-status-openvpn` — "Status: OpenVPN" covers the `service/*` calls; `instances/search` may additionally require `page-openvpn-instances` (config privilege) | |

### HAProxy

| Tool | Endpoint(s) | Privilege | Notes |
|---|---|---|---|
| `opn_haproxy_status`, `opn_haproxy_configtest`, `opn_haproxy_search`, `opn_haproxy_get`, `opn_haproxy_add`, `opn_haproxy_update`, `opn_haproxy_delete`, `opn_reconfigure_haproxy` | `haproxy/service/*`, `haproxy/settings/*` (dynamic per-resource registry — see `tools/haproxy.py`) | ✅ `page-services-haproxy` — "Services: HAProxy" | single catch-all privilege for the entire module, no read/write split — every HAProxy tool needs exactly this one privilege |

### Services (DDNS, ACME, cron, CrowdSec, mDNS repeater)

| Tool | Endpoint(s) | Privilege | Notes |
|---|---|---|---|
| `opn_list_ddns_accounts` / `opn_add_ddns_account` / `opn_update_ddns_account` / `opn_delete_ddns_account` / `opn_reconfigure_ddclient` | `dyndns/accounts/*`, `dyndns/service/reconfigure` | ❓ not researched — DynDNS module ACL not covered this pass | |
| `opn_list_acme_certs` | `acmeclient/certificates/search` | ❓ not researched | |
| `opn_list_cron_jobs` | `cron/settings/searchJobs` | ✅ `page-system-cron` — "System: Settings: Cron" | single privilege, no split |
| `opn_crowdsec_status` / `opn_crowdsec_alerts` | `crowdsec/service/status`, `crowdsec/decisions/search`, `crowdsec/alerts/search` | ❓ not researched | |
| `opn_mdns_repeater_status` / `opn_configure_mdns_repeater` | `mdnsrepeater/settings/*`, `mdnsrepeater/service/*` | ❓ not researched | |

### Diagnostics — active probes

| Tool | Endpoint(s) | Privilege | Notes |
|---|---|---|---|
| `opn_ping` | `diagnostics/ping/{set,start,searchJobs,remove}` | ✅ `page-diagnostics-ping` | requires app-layer writes (`api.require_writes()`) independent of this privilege |
| `opn_traceroute` | `diagnostics/traceroute/set` | ✅ `page-diagnostics-traceroute` | requires app-layer writes |
| `opn_dns_lookup` | `diagnostics/dns_diagnostics/set` | ❓ not researched | requires app-layer writes |
| `opn_pf_states` | `diagnostics/firewall/queryStates` | ✅ `page-diagnostics-showstates` | read-only despite POST verb |

### Security audit (composite)

| Tool | Endpoint(s) | Privilege | Notes |
|---|---|---|---|
| `opn_security_audit` | see "Broad, hard-to-scope tools" above for the full call list | spans most read privileges in this doc | not meaningfully scopable to a single narrow privilege |

## Sources

- [ACL.php](https://github.com/opnsense/core/blob/master/src/opnsense/mvc/app/models/OPNsense/Core/ACL.php) — confirms API and GUI share one ACL check
- [docs.opnsense.org — ACL development guide](https://docs.opnsense.org/development/components/acl.html)
- [docs.opnsense.org — API guide](https://docs.opnsense.org/development/api.html)
- [Core `ACL.xml`](https://github.com/opnsense/core/blob/master/src/opnsense/mvc/app/models/OPNsense/Core/ACL/ACL.xml) and per-module `ACL/ACL.xml` files under `OPNsense/Core`, `Unbound`, `Kea`, `IPsec`, `Wireguard`, `Cron`, and the HAProxy plugin
- [opnsense/core#9093](https://github.com/opnsense/core/issues/9093) — legacy camelCase endpoint ACL gap (closed, not planned)
- This repo's `src/opnsense_mcp/api_client.py` (`ENDPOINT_REGISTRY`, `BLOCKED_ENDPOINTS`) — canonical source for every tool's underlying endpoint

**Before relying on this doc to grant a real API key**: create the scoped group, assign
it to a dedicated API user, and empirically test — call each MCP tool you intend to
allow and confirm you get a 200, not a 403. ACL.xml patterns are known to occasionally
lag what the running code actually requests (see the #9093 example above), and several
rows here are flagged `⚠️`/`❓` precisely because they weren't independently confirmed.
