# Best Practice: Dynamic DNS with Cloudflare

## Problem

Dynamic DNS (DDNS) with Cloudflare on OPNsense has several non-obvious configuration
pitfalls that cause authentication errors, wrong IPs, or silent update failures.
This guide covers the correct setup using the `os-ddclient` plugin and the
OPNsense MCP server tools.

## Prerequisites

- **OPNsense plugin:** `os-ddclient` installed (System > Firmware > Plugins)
- **Cloudflare API Token** with `Zone:DNS:Edit` permission for the target zone
  (Dashboard > Profile > API Tokens > Create Token)
- **DNS zone** already configured in Cloudflare with an existing A/AAAA record
  for the hostname you want to update

## Step 1: Create the IPv4 DDNS Account

In OPNsense: **Services > Dynamic DNS > Accounts > Add**

| Field | Value | Notes |
|-------|-------|-------|
| **Service** | `Cloudflare` | The DNS provider |
| **Username** | `token` | Literal string — tells ddclient to use Bearer auth |
| **Password** | Your API Token | The scoped token from Cloudflare |
| **Hostname** | `home.example.com` | FQDN to update |
| **Check IP Method** | `Interface [IPv4]` | **Not** "Cloudflare" — see below |
| **Interface** | Your WAN interface | e.g., `WAN` or `PPPoE` |
| **Description** | `Cloudflare IPv4` | Optional |

**MCP tool:**

```
opn_add_ddns_account(
    service="cloudflare",
    hostname="home.example.com",
    username="token",
    password="<your-api-token>",
    checkip="if",
    interface="wan",
    description="Cloudflare IPv4"
)
```

## Step 2: Create the IPv6 DDNS Account

Create a second account for IPv6 (AAAA record). Same settings except:

| Field | Value |
|-------|-------|
| **Check IP Method** | `Interface [IPv6]` |
| **Description** | `Cloudflare IPv6` |

**IPv6 address behavior:** The DDNS record will contain the OPNsense's own IPv6
address — a stable EUI-64 address derived from the interface's MAC address
(recognizable by `ff:fe` in the host portion). This is correct if you want to
reach services running on the OPNsense itself (HAProxy, VPN, etc.).

If you need DDNS pointing to a specific device behind the firewall, you'll need
a DDNS client running on that device — the router can only register its own address.

## Step 3: Verify

```
opn_list_ddns_accounts()
```

Check that both accounts show `enabled: true` and a valid `current_ip`. After the
first update cycle (typically within 5 minutes), verify with DNS:

```
nslookup home.example.com
```

## Critical Configuration Notes

### Username Must Be `token`

When using a **Cloudflare API Token** (the modern, scoped tokens), the username
field **must** be the literal string `token`. Without this, ddclient sends the
credential via the `X-Auth-Key` header, which is the legacy Global API Key format.
Cloudflare rejects this with:

```
error 6003: Invalid request headers
error 6103: Invalid format for X-Auth-Key header
```

If you use the **Global API Key** instead, set username to your Cloudflare email
address. But scoped API Tokens are recommended for security (least privilege).

### Use Interface Check IP, Not Cloudflare

Set the check IP method to **"Interface [IPv4/IPv6]"** instead of "Cloudflare":

- The Cloudflare check IP method (`web_cloudflare`) queries an external Cloudflare
  endpoint to determine your public IP. This endpoint breaks intermittently, causing
  DDNS updates to fail silently.
- The Interface method (`if`) reads the IP directly from the WAN interface — faster,
  more reliable, and no external dependency.
- The **service type** ("Cloudflare") is separate from the check IP method. You still
  use Cloudflare as the DNS provider; you're just changing how ddclient discovers
  your current IP.

### IPv6 With "Request Prefix Only" (1&1 / Deutsche Telekom)

On ISPs that use "Request prefix only" (common with Deutsche Telekom infrastructure):

- The WAN interface has **no public IPv6** — only a link-local `fe80::` address
- The ISP delegates a `/64` prefix to your LAN via DHCPv6-PD
- The OPNsense LAN interface gets a stable EUI-64 address in that prefix
- This EUI-64 address is what ddclient registers — it's globally routable and stable

## German ISP: Controlling the Forced Disconnect (Zwangstrennung)

Many German ISPs force a PPPoE disconnect after ~24 hours. Instead of having this
happen at a random time during the day, schedule it at a convenient time:

1. Go to **System > Settings > Cron**
2. Add a new entry:
   - **Minutes:** `0`
   - **Hours:** `4` (4 AM)
   - **Command:** `Periodic interface reset`
   - **Parameters:** Your WAN interface name (check Interfaces > Overview)
   - **Description:** `Zwangstrennung 4 AM`
3. Save

ddclient automatically detects the IP change after reconnection (polls every
~5 minutes by default) — no need for a separate ddclient restart cron job.

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Error 6103 "Invalid format for X-Auth-Key header" | API Token sent as Global API Key | Set username to `token` |
| DDNS updates silently fail | Cloudflare checkip endpoint down | Switch to Interface checkip method |
| Wrong IPv6 address (EUI-64 vs privacy address) | ddclient registers the router's IPv6, not a client's | Expected behavior — use client-side DDNS for specific devices |
| IPv4 mismatch after ISP reconnect | ddclient hasn't polled yet | Wait 5 minutes or run `opn_reconfigure_ddclient()` |
| IPv6 updates not happening | Missing `allowipv6` setting | Enable IPv6 in Services > Dynamic DNS > General Settings |

## References

- [Cloudflare API Token Permissions](https://developers.cloudflare.com/fundamentals/api/get-started/create-token/)
- [OPNsense Dynamic DNS Plugin](https://docs.opnsense.org/manual/dynamic_dns.html)
- [OPNsense Cron Jobs](https://docs.opnsense.org/manual/settingsmenu.html#cron)
