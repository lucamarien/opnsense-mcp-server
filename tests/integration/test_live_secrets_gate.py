"""Live verification for HIGH-2: the OPNSENSE_ALLOW_SECRETS operator gate must hold
even when a caller explicitly requests include_sensitive=True.

Usage:
    # With .env file in project root:
    set -a && source .env && set +a && python -m tests.integration.test_live_secrets_gate

    # Or with explicit env vars:
    OPNSENSE_URL=https://192.168.1.1:10443/api \
    OPNSENSE_API_KEY=... \
    OPNSENSE_API_SECRET=... \
    OPNSENSE_VERIFY_SSL=false \
    python -m tests.integration.test_live_secrets_gate

Requires a running OPNsense instance. Deliberately does NOT set
OPNSENSE_ALLOW_SECRETS=true — the whole point is to prove the operator-side
gate wins over the caller-supplied argument. Never runs write operations.
"""

from __future__ import annotations

import asyncio
import os
import sys
import traceback
from unittest.mock import MagicMock

from opnsense_mcp.api_client import OPNsenseAPI, SavepointManager
from opnsense_mcp.config import load_config
from opnsense_mcp.config_cache import ConfigCache
from opnsense_mcp.tools.system import opn_download_config, opn_get_config_section

PASS = "\033[92mPASS\033[0m"
FAIL = "\033[91mFAIL\033[0m"


def _make_ctx(api: OPNsenseAPI, mgr: SavepointManager) -> MagicMock:
    ctx = MagicMock()
    ctx.lifespan_context = {"api": api, "savepoint_mgr": mgr, "config_cache": ConfigCache()}
    return ctx


async def main() -> int:
    if os.environ.get("OPNSENSE_ALLOW_SECRETS", "").lower() == "true":
        print(f"[{FAIL}] OPNSENSE_ALLOW_SECRETS=true is set — unset it to test the gate itself.")
        return 2

    config = load_config()
    api = OPNsenseAPI(config)
    ctx = _make_ctx(api, SavepointManager(api))

    print("=" * 70)
    print("  HIGH-2 live check: include_sensitive=True without operator opt-in")
    print("=" * 70)

    failed = 0

    result = await opn_download_config(ctx, include_sensitive=True)
    stripped = result.get("stripped")
    status = PASS if stripped is True else FAIL
    print(f"  [{status}] opn_download_config(include_sensitive=True) -> stripped={stripped}")
    if stripped is not True:
        failed += 1

    section = await opn_get_config_section(ctx, section="cert", include_sensitive=True)
    data = section.get("data", {})
    prv = data.get("prv") if isinstance(data, dict) else None
    leaked = prv is not None and prv != "[REDACTED]"
    status = FAIL if leaked else PASS
    print(f"  [{status}] opn_get_config_section('cert', include_sensitive=True) -> prv={prv!r}")
    if leaked:
        failed += 1

    print("=" * 70)
    if failed:
        print(f"  \033[91m** {failed} check(s) FAILED — secrets gate NOT holding **\033[0m")
    else:
        print("  \033[92mGate holds: include_sensitive=True alone did not disable redaction.\033[0m")
    print("=" * 70)

    await api.close()
    return 1 if failed else 0


if __name__ == "__main__":
    try:
        exit_code = asyncio.run(main())
    except Exception:
        traceback.print_exc()
        exit_code = 2
    sys.exit(exit_code)
