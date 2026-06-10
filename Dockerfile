FROM python:3.13-slim AS builder

WORKDIR /build
COPY pyproject.toml README.md LICENSE ./
COPY src/ src/
RUN pip install --no-cache-dir build && python -m build --wheel

FROM python:3.13-slim

LABEL org.opencontainers.image.title="opnsense-mcp-server" \
      org.opencontainers.image.description="Secure MCP server for OPNsense firewall management" \
      org.opencontainers.image.source="https://github.com/lucamarien/opnsense-mcp-server" \
      org.opencontainers.image.licenses="MIT"

COPY --from=builder /build/dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm /tmp/*.whl \
    && useradd --create-home --shell /usr/sbin/nologin mcp

USER mcp

ENTRYPOINT ["opnsense-mcp"]
