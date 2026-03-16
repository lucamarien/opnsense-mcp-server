"""Diagnostics tools — ping, traceroute, DNS lookup, PF states."""

from __future__ import annotations

import asyncio
from typing import Any

from fastmcp import Context

from opnsense_mcp.server import get_api, mcp

_MAX_PING_POLLS = 30
_PING_POLL_INTERVAL = 1.0
_HOSTNAME_REJECT = frozenset({";", "&", "|", "$", "`", "\n", "\r"})


def _validate_hostname(value: str) -> str | None:
    """Return an error message if the hostname/IP is invalid, else None."""
    if not value or len(value) > 255:
        return "Hostname must be 1–255 characters."
    if any(c in value for c in _HOSTNAME_REJECT):
        return "Hostname contains invalid characters."
    return None


@mcp.tool()
async def opn_ping(
    ctx: Context,
    host: str,
    count: int = 3,
) -> dict[str, Any]:
    """Ping a host from the OPNsense firewall to test connectivity.

    Use this when you need to check if a host is reachable from the firewall,
    measure round-trip latency, or diagnose network connectivity issues.
    The ping runs on the firewall itself, not locally.
    Returns: dict with ping results including loss percentage and RTT stats.
    """
    if err := _validate_hostname(host):
        return {"error": err}
    count = max(1, min(count, 10))
    api = get_api(ctx)

    # Create and configure the ping job
    result = await api.post(
        "diagnostics.ping.set",
        {"ping": {"settings": {"hostname": host, "count": str(count)}}},
    )
    uuid = result.get("uuid", "")
    if not uuid:
        return {"error": "Failed to create ping job", "details": result}

    # Start the job
    await api.post("diagnostics.ping.start", path_suffix=uuid)

    # Poll until enough pings are sent or job completes.
    # The OPNsense ping API runs continuously — we stop it once we have enough data.
    try:
        for _ in range(_MAX_PING_POLLS):
            await asyncio.sleep(_PING_POLL_INTERVAL)
            jobs = await api.get("diagnostics.ping.search_jobs")
            for job in jobs.get("rows", []):
                job_id = job.get("uuid") or job.get("id", "")
                if job_id != uuid:
                    continue
                status = job.get("status", "")
                sent = int(job.get("send") or 0)
                # Return when job is done/stopped OR enough pings have been sent
                if status in ("done", "stopped") or sent >= count:
                    await api.post("diagnostics.ping.remove", path_suffix=uuid)
                    return {"host": host, "count": count, **job}
    except Exception:
        # Ensure cleanup on any error
        await api.post("diagnostics.ping.remove", path_suffix=uuid)
        raise

    # Timeout — clean up the job
    await api.post("diagnostics.ping.remove", path_suffix=uuid)
    return {"error": f"Ping to {host} timed out waiting for results", "host": host}


@mcp.tool()
async def opn_traceroute(
    ctx: Context,
    host: str,
    protocol: str = "ICMP",
    ip_version: str = "4",
) -> dict[str, Any]:
    """Trace the network path from OPNsense to a destination host.

    Use this when you need to diagnose routing issues, identify where packets
    are being dropped, or visualize the network hops to a destination.
    Returns: dict with 'result' (str) and 'response' (list of hops).
    """
    if err := _validate_hostname(host):
        return {"error": err}
    if protocol not in ("ICMP", "UDP", "TCP"):
        return {"error": f"Invalid protocol '{protocol}'. Use ICMP, UDP, or TCP."}
    if ip_version not in ("4", "6"):
        return {"error": f"Invalid ip_version '{ip_version}'. Use '4' or '6'."}

    api = get_api(ctx)
    result = await api.post(
        "diagnostics.traceroute.set",
        {
            "traceroute": {
                "hostname": host,
                "protocol": protocol,
                "ipproto": ip_version,
                "source_address": "",
            },
        },
    )
    return {"host": host, **result}


@mcp.tool()
async def opn_dns_lookup(
    ctx: Context,
    hostname: str,
    server: str = "",
) -> dict[str, Any]:
    """Perform a DNS lookup from the OPNsense firewall.

    Use this when you need to test DNS resolution from the firewall's
    perspective, verify Unbound is resolving correctly, or check if a
    specific DNS server returns expected results.
    Returns: dict with 'result' (str) and 'response' (DNS query results).
    """
    if err := _validate_hostname(hostname):
        return {"error": err}
    api = get_api(ctx)
    result = await api.post(
        "diagnostics.dns_diagnostics.set",
        {"dns": {"settings": {"hostname": hostname, "server": server}}},
    )
    return {"hostname": hostname, **result}


@mcp.tool()
async def opn_pf_states(
    ctx: Context,
    search: str = "",
    limit: int = 200,
) -> dict[str, Any]:
    """Query the active PF (packet filter) state table.

    Use this when you need to see active connections through the firewall,
    debug NAT issues, or identify which hosts are communicating.
    Returns: dict with 'rows' (list of state entries) and 'rowCount' (total).
    """
    api = get_api(ctx)
    return await api.post(
        "diagnostics.firewall.query_states",
        {"current": 1, "rowCount": min(limit, 1000), "searchPhrase": search},
    )
