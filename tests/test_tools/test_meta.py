"""Meta tests — framework conventions enforced across the whole tool surface."""

from __future__ import annotations

from opnsense_mcp.server import mcp


async def _tools():
    return await mcp.list_tools()


class TestToolConventions:
    async def test_every_tool_has_annotations(self):
        missing = [t.name for t in await _tools() if t.annotations is None]
        assert not missing, f"Tools without ToolAnnotations: {missing}"

    async def test_every_tool_declares_read_only_hint(self):
        undeclared = [t.name for t in await _tools() if t.annotations.readOnlyHint is None]
        assert not undeclared, f"Tools without explicit readOnlyHint: {undeclared}"

    async def test_read_named_tools_are_read_only(self):
        # Naming grammar: list_/get_/_status/_stats/_table/_log names are reads.
        read_markers = ("opn_list_", "opn_get_")
        read_suffixes = ("_status", "_stats", "_table", "_log", "_info", "_health", "_audit")
        wrong = []
        for t in await _tools():
            looks_read = t.name.startswith(read_markers) or t.name.endswith(read_suffixes)
            if looks_read and t.annotations.readOnlyHint is not True:
                wrong.append(t.name)
        assert not wrong, f"Read-named tools not marked readOnlyHint=True: {wrong}"

    async def test_manage_tools_are_marked_destructive(self):
        wrong = [
            t.name
            for t in await _tools()
            if t.name.startswith("opn_manage_") and t.annotations.destructiveHint is not True
        ]
        assert not wrong, f"manage_* tools must carry destructiveHint=True: {wrong}"

    async def test_every_docstring_documents_returns(self):
        missing = [t.name for t in await _tools() if "Returns:" not in (t.description or "")]
        assert not missing, f"Tools without a 'Returns:' contract: {missing}"

    async def test_every_docstring_is_substantial(self):
        # The docstring is the model-facing API — a one-liner is not enough.
        thin = [t.name for t in await _tools() if len(t.description or "") < 150]
        assert not thin, f"Tools with thin docstrings (<150 chars): {thin}"

    async def test_all_tools_use_opn_prefix(self):
        wrong = [t.name for t in await _tools() if not t.name.startswith("opn_")]
        assert not wrong, f"Tools without the opn_ prefix: {wrong}"

    async def test_write_tools_document_revert_story(self):
        # Every non-read tool must state its revert semantics: either the
        # savepoint contract or an explicit "immediately/cannot be auto-revert".
        markers = (
            "auto-revert",
            "auto-rollback",
            "applied immediately",
            "applies immediately",
            "take effect immediately",
            "takes effect immediately",
            "effect immediately",
            "no savepoint protection",
            "not applied until",
        )
        silent = []
        for t in await _tools():
            if t.annotations.readOnlyHint is True:
                continue
            desc = (t.description or "").lower()
            if not any(m in desc for m in markers):
                silent.append(t.name)
        assert not silent, f"Write tools without a stated revert story: {silent}"
