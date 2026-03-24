# Contributing to OPNsense MCP Server

Thank you for your interest in contributing! This guide covers the coding standards, security requirements, and workflow for adding tools or fixing bugs.

## Development Setup

```bash
git clone https://github.com/lucamarien/opnsense-mcp-server
cd opnsense-mcp-server
pip install -e ".[dev]"
```

## Coding Standards

- **Python 3.11+** with strict typing (`mypy --strict`)
- **Linting:** `ruff check src/ tests/` (includes bandit security rules)
- **Formatting:** `ruff format src/ tests/`
- **Tests:** `pytest -v` (all tests use mocked API responses, no real OPNsense needed)
- **No external dependencies** beyond `fastmcp` (which provides `httpx`)

Run the full CI pipeline locally before submitting:

```bash
make validate
```

This runs: lint, format check, security scan, type check, tests, and dependency audit.

## Adding a New Tool

1. Pick the right domain file in `src/opnsense_mcp/tools/`
2. Add your function with the `@mcp.tool()` decorator
3. Use Python type hints — FastMCP auto-generates JSON schema from them
4. Write a clear docstring (it's the AI's **only** guide to tool selection)
5. Return `dict`, not formatted strings
6. Add tests in `tests/test_tools/`
7. Review against the security checklist below

```python
@mcp.tool()
async def opn_example_tool(ctx: Context, search: str = "", limit: int = 50) -> dict[str, Any]:
    """One-line description of what this does.

    Use this when you need to [specific scenario].
    Returns: dict with 'rows' (list) and 'total' (int).
    """
    api = get_api(ctx)
    return await api.get("endpoint.logical_name")
```

### Tool Naming

- All tools use the `opn_` prefix
- Use descriptive names: `opn_list_firewall_rules`, `opn_add_dns_override`
- Read tools: `opn_list_*`, `opn_*_status`, `opn_get_*`
- Write tools: `opn_add_*`, `opn_delete_*`, `opn_toggle_*`, `opn_reconfigure_*`

### Endpoint Registry

Never hardcode API paths in tools. Use logical endpoint names resolved by the API client:

```python
# Good — uses the endpoint registry (auto-resolves camelCase/snake_case)
await api.get("firewall.search_rule")

# Bad — hardcodes the endpoint path
await api.get("api/firewall/filter/searchRule")
```

Add new endpoints to `ENDPOINT_REGISTRY` in `src/opnsense_mcp/api_client.py` with both naming variants:

```python
"firewall.search_rule": ("firewall/filter/searchRule", "firewall/filter/search_rule"),
```

## Security Requirements

These are non-negotiable for all contributions:

### Never Do

- Hardcode credentials, API keys, or secrets (enforced by Ruff S105/S106/S107)
- Log, print, or include API keys in any output or error messages
- Add API endpoints without checking against the blocklist
- Disable SSL verification without explicit user configuration
- Use global mutable state for credential storage
- Expose internal file paths, stack traces, or sensitive config in tool responses

### Always Do

- Load credentials from environment variables only
- Guard write operations with the `OPNSENSE_ALLOW_WRITES` check
- Use the savepoint/rollback mechanism for all firewall modifications
- Keep transport as STDIO only — never expose HTTP/SSE endpoints
- Validate user-provided inputs (hostnames, IP addresses) against injection

### Blocked Endpoints

The following endpoints are **permanently blocked** at the API client level and must never be exposed through any tool:

- `core/system/halt` — shuts down the firewall instantly
- `core/system/reboot` — reboots instantly
- `core/firmware/poweroff` — powers off instantly
- `core/firmware/update` — triggers system update
- `core/firmware/upgrade` — triggers major upgrade

## Testing Requirements

- **All tests must use mocked API responses** — never connect to a real OPNsense instance
- Test both success and error paths
- Test that blocked endpoints are rejected
- Test that write guards work (`ALLOW_WRITES=false` must fail)
- Test both camelCase and snake_case endpoint variants for version compatibility

```bash
# Run all tests
pytest -v

# Run tests for a specific domain
make test-domain DOMAIN=firewall

# Run with verbose output on failures
pytest -v --tb=long
```

## Quick Decision Trees

- **GET vs POST:** Status/read operations use GET. Search with filters uses POST. Modifications/actions use POST.
- **Write guard?** Read operations don't need one. Firewall changes need write guard + savepoint. Other modifications (DNS, HAProxy) need write guard only.
- **Savepoint?** Firewall rule changes (add/delete/toggle) use savepoints with 60-second auto-revert. Service reconfigurations (Unbound, HAProxy, dnsmasq) do not.

## Pull Request Checklist

- [ ] `make validate` passes locally
- [ ] New tools have tests with mocked API responses
- [ ] Docstrings are clear and describe when to use the tool
- [ ] No hardcoded credentials or sensitive data
- [ ] Write operations are guarded and use savepoints where appropriate
- [ ] No overlapping tools — new tool has a distinct purpose from existing ones

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
