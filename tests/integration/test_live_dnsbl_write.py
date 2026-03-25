"""Live integration tests for DNSBL write tools against a real OPNsense instance.

Usage:
    # With .env file (OPNSENSE_ALLOW_WRITES=true required):
    set -a && source .env && set +a && python -m tests.integration.test_live_dnsbl_write

    # Or with explicit env vars:
    OPNSENSE_URL=https://192.168.1.1:10443/api \
    OPNSENSE_API_KEY=... \
    OPNSENSE_API_SECRET=... \
    OPNSENSE_VERIFY_SSL=false \
    OPNSENSE_ALLOW_WRITES=true \
    python -m tests.integration.test_live_dnsbl_write

Requires a running OPNsense instance with at least one DNSBL configuration.
All changes are REVERTED at the end — this test is self-cleaning.
"""

from __future__ import annotations

import asyncio
import sys
import traceback
from unittest.mock import MagicMock

from opnsense_mcp.api_client import OPNsenseAPI, SavepointManager
from opnsense_mcp.config import load_config
from opnsense_mcp.config_cache import ConfigCache
from opnsense_mcp.tools.dns import (
    opn_add_dnsbl_allowlist,
    opn_get_dnsbl,
    opn_list_dnsbl,
    opn_remove_dnsbl_allowlist,
    opn_set_dnsbl,
)

PASS = "\033[92mPASS\033[0m"
FAIL = "\033[91mFAIL\033[0m"

TEST_DOMAIN = "integration-test.example.com"


def _make_ctx(api: OPNsenseAPI, mgr: SavepointManager) -> MagicMock:
    """Create a mock FastMCP Context wrapping a real API client."""
    ctx = MagicMock()
    config_cache = ConfigCache()
    ctx.lifespan_context = {"api": api, "savepoint_mgr": mgr, "config_cache": config_cache}
    return ctx


async def main() -> int:
    """Run DNSBL write integration tests."""
    config = load_config()
    if not config.allow_writes:
        print("\033[91mERROR: OPNSENSE_ALLOW_WRITES must be 'true' for this test.\033[0m")
        return 2

    api = OPNsenseAPI(config)
    mgr = SavepointManager(api)
    ctx = _make_ctx(api, mgr)

    passed = 0
    failed = 0

    print("=" * 70)
    print("  OPNsense MCP Server — DNSBL Write Integration Test")
    print("=" * 70)
    print(f"  URL:    {config.url}")
    print("  Writes: ENABLED")
    print(f"  Test domain: {TEST_DOMAIN}")
    print("=" * 70)

    def _check(name: str, condition: bool, detail: str = "") -> None:
        nonlocal passed, failed
        if condition:
            passed += 1
            print(f"  [{PASS}] {name:45s} {detail}")
        else:
            failed += 1
            print(f"  [{FAIL}] {name:45s} {detail}")

    try:
        # --- Step 1: Discover DNSBL UUID ---
        print("\n--- Step 1: Discover DNSBL UUID ---")
        list_result = await opn_list_dnsbl(ctx)
        rows = list_result.get("rows", [])
        _check("opn_list_dnsbl returns rows", len(rows) > 0, f"({len(rows)} configs)")
        if not rows:
            print("  No DNSBL configurations found. Cannot continue.")
            await api.close()
            return 1
        uuid = rows[0]["uuid"]
        print(f"  Using UUID: {uuid}")

        # --- Step 2: Snapshot current state ---
        print("\n--- Step 2: Snapshot current state ---")
        snapshot = await opn_get_dnsbl(ctx, uuid=uuid)
        _check("opn_get_dnsbl returns config", "selected_providers" in snapshot)
        original_allowlists = snapshot.get("allowlists", [])
        original_description = snapshot.get("description", "")
        print(f"  Providers: {', '.join(snapshot.get('selected_providers', []))}")
        print(f"  Allowlists: {len(original_allowlists)} entries")
        print(f"  Description: {original_description!r}")

        # --- Step 3: Add allowlist domain ---
        print("\n--- Step 3: Add allowlist domain ---")
        add_result = await opn_add_dnsbl_allowlist(ctx, uuid=uuid, domains=TEST_DOMAIN)
        _check(
            "opn_add_dnsbl_allowlist succeeds",
            "error" not in add_result,
            f"result={add_result.get('result', '?')}",
        )
        _check(
            "domain reported as added",
            TEST_DOMAIN in add_result.get("added", []),
            f"added={add_result.get('added', [])}",
        )
        _check(
            "dnsbl lists reloaded",
            "OK" in add_result.get("dnsbl_status", ""),
            f"dnsbl_status={add_result.get('dnsbl_status', '?')!r}",
        )
        _check(
            "unbound service restarted",
            add_result.get("service_status", "") in ("ok", "OK"),
            f"service_status={add_result.get('service_status', '?')!r}",
        )

        # --- Step 4: Verify added ---
        print("\n--- Step 4: Verify domain was added ---")
        verify_add = await opn_get_dnsbl(ctx, uuid=uuid)
        _check(
            "domain present in allowlists",
            TEST_DOMAIN in verify_add.get("allowlists", []),
            f"allowlists={verify_add.get('allowlists', [])}",
        )

        # --- Step 5: Add again (idempotency) ---
        print("\n--- Step 5: Add same domain again (idempotency) ---")
        add2_result = await opn_add_dnsbl_allowlist(ctx, uuid=uuid, domains=TEST_DOMAIN)
        _check(
            "domain reported as already_present",
            TEST_DOMAIN in add2_result.get("already_present", []),
            f"already_present={add2_result.get('already_present', [])}",
        )
        _check(
            "not duplicated in added list",
            TEST_DOMAIN not in add2_result.get("added", []),
        )

        # --- Step 6: Remove allowlist domain ---
        print("\n--- Step 6: Remove allowlist domain ---")
        remove_result = await opn_remove_dnsbl_allowlist(ctx, uuid=uuid, domains=TEST_DOMAIN)
        _check(
            "opn_remove_dnsbl_allowlist succeeds",
            "error" not in remove_result,
            f"result={remove_result.get('result', '?')}",
        )
        _check(
            "domain reported as removed",
            TEST_DOMAIN in remove_result.get("removed", []),
            f"removed={remove_result.get('removed', [])}",
        )

        # --- Step 7: Verify removed ---
        print("\n--- Step 7: Verify domain was removed ---")
        verify_remove = await opn_get_dnsbl(ctx, uuid=uuid)
        _check(
            "domain no longer in allowlists",
            TEST_DOMAIN not in verify_remove.get("allowlists", []),
            f"allowlists={verify_remove.get('allowlists', [])}",
        )

        # --- Step 8: Remove again (not found) ---
        print("\n--- Step 8: Remove same domain again (not found) ---")
        remove2_result = await opn_remove_dnsbl_allowlist(ctx, uuid=uuid, domains=TEST_DOMAIN)
        _check(
            "domain reported as not_found",
            TEST_DOMAIN in remove2_result.get("not_found", []),
            f"not_found={remove2_result.get('not_found', [])}",
        )

        # --- Step 9: Update description ---
        print("\n--- Step 9: Update description via opn_set_dnsbl ---")
        test_desc = "MCP integration test — will be reverted"
        set_result = await opn_set_dnsbl(ctx, uuid=uuid, description=test_desc)
        _check(
            "opn_set_dnsbl succeeds",
            "error" not in set_result,
            f"result={set_result.get('result', '?')}",
        )

        # --- Step 10: Verify description updated ---
        print("\n--- Step 10: Verify description updated ---")
        verify_desc = await opn_get_dnsbl(ctx, uuid=uuid)
        _check(
            "description updated",
            verify_desc.get("description") == test_desc,
            f"description={verify_desc.get('description')!r}",
        )

        # --- Step 11: Restore description ---
        print("\n--- Step 11: Restore original description ---")
        restore_result = await opn_set_dnsbl(ctx, uuid=uuid, description=original_description)
        _check(
            "description restored",
            "error" not in restore_result,
        )

        # --- Step 12: Final snapshot comparison ---
        print("\n--- Step 12: Final snapshot comparison ---")
        final = await opn_get_dnsbl(ctx, uuid=uuid)
        _check(
            "allowlists match original",
            sorted(final.get("allowlists", [])) == sorted(original_allowlists),
            f"original={sorted(original_allowlists)}, final={sorted(final.get('allowlists', []))}",
        )
        _check(
            "description matches original",
            final.get("description") == original_description,
        )
        _check(
            "providers unchanged",
            sorted(final.get("selected_providers", [])) == sorted(snapshot.get("selected_providers", [])),
        )

    except Exception as exc:
        failed += 1
        print(f"\n  [{FAIL}] UNEXPECTED ERROR: {type(exc).__name__}: {exc}")
        traceback.print_exc()

    # --- Final Summary ---
    print("\n" + "=" * 70)
    total = passed + failed
    print(f"  RESULT: {passed}/{total} passed, {failed} failed")
    if failed > 0:
        print(f"  \033[91m** {failed} test(s) FAILED **\033[0m")
    else:
        print("  \033[92mAll tests passed! DNSBL state restored to original.\033[0m")
    print("=" * 70)

    await api.close()
    return 1 if failed > 0 else 0


if __name__ == "__main__":
    try:
        exit_code = asyncio.run(main())
    except Exception:
        traceback.print_exc()
        exit_code = 2
    sys.exit(exit_code)
