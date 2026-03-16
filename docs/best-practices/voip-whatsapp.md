# Best Practice: WhatsApp Calling Firewall Rules

## Problem

WhatsApp voice and video calling fails on networks with a default-deny firewall
policy. While WhatsApp messaging works over TCP 443/5222, **calling** relies on
STUN/TURN (UDP 3478) for call setup and **dynamically negotiated high UDP ports**
for the actual media stream. Without explicit allow rules, these UDP flows are
blocked.

## WhatsApp Network Requirements

### TCP Ports (Signaling)

| Port | Purpose |
|------|---------|
| 443 | HTTPS (initial connection, often already allowed) |
| 5222, 5223 | XMPP signaling |
| 5228, 5242 | Push notifications / signaling |
| 4244, 50318, 59234 | Media relay / calling |

### UDP Ports (Media)

| Port | Purpose |
|------|---------|
| 3478 | STUN/TURN (call setup, **critical** -- calls fail without this) |
| Dynamic | Media stream uses negotiated high ports (not a fixed range) |

**Key insight:** UDP port 3478 is used to negotiate the call. The actual
voice/video data then flows on a **random high UDP port** assigned by WhatsApp's
relay servers. This is why allowing only a few specific UDP ports is insufficient.

## Recommended Firewall Configuration

### Principle: Restrict on All Three Dimensions

Every rule should be scoped on destination IPs, ports, AND source:

- **Restrict the destination** to WhatsApp's known server IP ranges (urltable)
- **Restrict UDP ports** to STUN (3478) + ephemeral media range (49152-65535)
- **Restrict TCP ports** to known signaling ports
- **Restrict source** to the specific interface subnet

### Step 1: Create a URL Table Alias for WhatsApp Servers

Use a `urltable` alias that auto-updates from a maintained CIDR list:

```
Name:        WhatsApp_Servers
Type:        URL Table (IPs)
Refresh:     1 day
URL:         https://raw.githubusercontent.com/HybridNetworks/whatsapp-cidr/main/WhatsApp/whatsapp_cidr_ipv4.txt
Description: WhatsApp server IPs (auto-updated daily)
```

This list contains ~229 IPv4 CIDR blocks covering WhatsApp's infrastructure.
Auto-updating ensures new server ranges are included without manual intervention.

**IPv6:** No WhatsApp-specific IPv6 CIDR list exists. WhatsApp runs on Meta's
infrastructure, which uses two IPv6 supernets. Create a separate network alias:

```
Name:        WhatsApp_Servers_v6
Type:        Network
Content:     2a03:2880::/32, 2620:0:1c00::/40
Description: Meta IPv6 supernets (covers WhatsApp relay infrastructure)
```

This covers all of Meta's IPv6 space. The port restrictions on the rules keep
the scope limited to WhatsApp-relevant traffic.

**MCP tools:**
```
opn_add_alias(
    name="WhatsApp_Servers",
    alias_type="urltable",
    content="https://raw.githubusercontent.com/HybridNetworks/whatsapp-cidr/main/WhatsApp/whatsapp_cidr_ipv4.txt",
    description="WhatsApp server IPs (auto-updated daily)"
)

opn_add_alias(
    name="WhatsApp_Servers_v6",
    alias_type="network",
    content="2a03:2880::/32\n2620:0:1c00::/40",
    description="Meta IPv6 supernets (covers WhatsApp relay infrastructure)"
)
```

### Step 2: Create Port Aliases

**TCP signaling:**
```
Name:    whatsapp_tcp
Type:    Port
Ports:   4244, 5222:5223, 5228, 5242, 50318, 59234
```

Ports 443 and 80 are typically already allowed by other rules (HTTP/HTTPS).
Include them in the alias if your firewall blocks HTTPS by default.

**UDP media:**
```
Name:    whatsapp_udp
Type:    Port
Ports:   3478, 49152:65535
```

Port 3478 is STUN/TURN (call setup). The ephemeral range 49152-65535 covers
the dynamically allocated media ports. This is the IANA dynamic port range
that WhatsApp's relay servers allocate from.

### Step 3: Create Firewall Rules

For each network interface that needs WhatsApp calling:

**TCP rule (signaling):**
```
opn_add_firewall_rule(
    action="pass",
    direction="in",
    interface="<interface>",
    ip_protocol="inet",
    protocol="TCP",
    source_net="<interface_subnet>",
    destination_net="WhatsApp_Servers",
    destination_port="whatsapp_tcp",
    description="WhatsApp calling - TCP to WhatsApp servers"
)
```

**UDP rule (media):**
```
opn_add_firewall_rule(
    action="pass",
    direction="in",
    interface="<interface>",
    ip_protocol="inet",
    protocol="UDP",
    source_net="<interface_subnet>",
    destination_net="WhatsApp_Servers",
    destination_port="whatsapp_udp",
    description="WhatsApp calling - UDP to WhatsApp servers"
)
```

**IPv6 rules:** Create the same TCP and UDP rules with `ip_protocol="inet6"` and
`destination_net="WhatsApp_Servers_v6"`. Use separate `inet` and `inet6` rules
(not `inet46`) so each IP version targets its own destination alias.

The rules are scoped on all three dimensions: destination IPs, destination ports
(STUN + ephemeral range), and source subnet.

### Step 4: Rule Ordering

Rules must be placed **before** any block/deny rules on the same interface.
In OPNsense MVC rules, this is controlled by the `sequence` field. Ensure
WhatsApp rules have a lower sequence number than:

- Block rules for private networks
- Default deny rules

### Step 5: Verify

After applying rules:

1. Check rule list: `opn_list_firewall_rules(search="WhatsApp")`
2. Test a WhatsApp voice call from a device on each network
3. Check firewall logs: `opn_firewall_log(action="pass")` should show UDP
   traffic to WhatsApp server IPs

## Security Considerations

### Why This Is Safe

| Aspect | Restriction |
|--------|-------------|
| Destination IPs | IPv4: WhatsApp-specific 229 CIDRs (urltable, auto-updated) |
| | IPv6: Meta supernets `2a03:2880::/32` + `2620:0:1c00::/40` |
| Destination Ports | TCP: 7 specific ports; UDP: 3478 + ephemeral 49152-65535 |
| Protocol | Separate rules for TCP and UDP |
| Source | Scoped to specific interface subnet |
| Direction | `in` on LAN interface = outbound from clients only |
| IP version | Separate `inet` and `inet6` rules with matching destination aliases |

### What NOT To Do

- **Don't open broad UDP port ranges to `any` destination** -- always combine
  port ranges with a destination IP restriction (urltable alias)
- **Don't skip the destination restriction** -- without it, any UDP traffic
  to any server would be allowed
- **Don't allow all UDP ports even to known servers** -- use the ephemeral range
  (49152-65535) + STUN (3478) instead of the full 0-65535 range
- **Don't use `inet46` in legacy XML rules** -- it silently produces no PF output;
  only use it in MVC API rules (Settings > Firewall > Automation)

## Production Safety: Savepoint/Rollback

All firewall modifications via the MCP server use OPNsense's savepoint mechanism:

1. A savepoint is created before any change
2. Changes are applied with a **60-second auto-revert timer**
3. If the change breaks connectivity, OPNsense automatically rolls back
4. Only explicit confirmation (`opn_confirm_changes`) makes changes permanent

This prevents accidental lockouts when modifying firewall rules on production
systems.

## Diagnostic Workflow

Before creating rules, always diagnose first:

1. **Check firewall logs** for blocked WhatsApp traffic:
   `opn_firewall_log(action="block")` -- look for UDP blocks to WhatsApp IPs
2. **List existing rules** to avoid duplicates:
   `opn_list_firewall_rules(search="WhatsApp")`
3. **List existing aliases** to reuse what's already configured:
   `opn_list_firewall_aliases(search="whatsapp")`

## References

- [Screwloose IT: WhatsApp Firewall Ports](https://screwlooseit.com.au/whatsapp-firewall-ports/)
- [IT Infrastructure Architect: Outbound Firewall Ports](https://www.itinfrastructurearchitect.co.uk/outbound-firewall-ports-required-for-whatsapp/)
- [Fortinet: WhatsApp VoIP Troubleshooting](https://community.fortinet.com/t5/FortiGate/Troubleshooting-Tip-Allow-port-ranges-and-protocol-to-access/ta-p/344183)
- [HybridNetworks: WhatsApp CIDR List](https://github.com/HybridNetworks/whatsapp-cidr)
