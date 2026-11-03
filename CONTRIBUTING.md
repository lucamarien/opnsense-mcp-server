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
@mcp.tool(annotations=READ_ONLY)  # presets in tools/_util.py
@catch_api_errors                 # uniform {"error", "error_type"} envelope
async def opn_example_tool(ctx: Context, search: str = "", limit: int = 50) -> dict[str, Any]:
    """One-line description of what this does.

    Use this when you need to [specific scenario].
    Returns: dict with 'rows' (list) and 'total' (int).
    """
    api = get_api(ctx)
    return await api.post("endpoint.logical_name", {"current": 1, "rowCount": clamp_limit(limit), "searchPhrase": search})
```

### Tool Naming & Surface Pattern

- All tools use the `opn_` prefix; **tool budget: the total count must stay below 65**
  (enforced by `test_registration.py`) — consolidate before adding
- Read tools: `opn_list_*`, `opn_get_*`, `opn_*_status`
- Write tools: one `opn_manage_<entity>(action=Literal["add","update","delete",...])`
  per entity — do NOT add separate add/update/delete tools (HAProxy's generic
  `resource_type` CRUD is the one sanctioned exception)
- Closed-set parameters use `Literal[...]` types, never free strings + manual validation

### Annotations, Errors, Docstrings (enforced by tests/test_tools/test_meta.py)

- Every tool carries a `ToolAnnotations` preset from `tools/_util.py`
  (READ_ONLY / READ_PROBE / WRITE / WRITE_IDEMPOTENT / DESTRUCTIVE)
- Every tool is wrapped in `@catch_api_errors` (below `@mcp.tool`) — never raise
  out of a tool body for expected failures; return `{"error", "error_type"}` dicts
- Every docstring has a `Returns:` line and, for write tools, an explicit revert
  story ("auto-revert" / "applies immediately" / "not applied until ...")
- Tools that surface device-supplied strings (hostnames, log lines, alerts) add an
  untrusted-data SECURITY note
- Avoid Google-style `Args:` sections — FastMCP strips them from the model-visible
  description; use a `Parameters:` list instead

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
- Route all firewall modifications through the savepoint manager — it uses savepoint/rollback where OPNsense provides it (< 26.7) and degrades to direct apply on 26.7+
- Keep transport as STDIO only — never expose HTTP/SSE endpoints
- Validate user-provided inputs (hostnames, IP addresses) against injection

### Blocked Endpoints

The following endpoints are **permanently blocked** at the API client level and must never be exposed through any tool:

- `core/system/halt` — shuts down the firewall instantly
- `core/system/reboot` — reboots instantly
- `core/firmware/reboot` — reboots instantly (firmware controller twin of `core/system/reboot`)
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
- **Savepoint?** Firewall filter-rule and category changes go through the savepoint manager: 60-second auto-revert on OPNsense < 26.7, direct apply on 26.7+ where upstream removed the API. The manager detects this by probing the endpoint at runtime, not by a hardcoded version check; the detected version only corroborates a 404 whose error body is localised and therefore unmatchable. Never gate the behaviour on the version alone, and never treat a bare 404 as proof — a reverse proxy produces the same status and would silently strip the rollback net. NAT, aliases, DNS, DHCP, DDNS, and service reconfigurations never use it (OPNsense's savepoint mechanism only covered the filter model) — their docstrings must say "applies immediately".

## Pull Request Checklist

- [ ] `make validate` passes locally
- [ ] New tools have tests with mocked API responses
- [ ] Docstrings are clear and describe when to use the tool
- [ ] No hardcoded credentials or sensitive data
- [ ] Write operations are guarded and go through the savepoint manager where appropriate
- [ ] No overlapping tools — new tool has a distinct purpose from existing ones

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
