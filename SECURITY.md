# Security Policy

## Supported Versions

Security fixes are released for the latest minor version on PyPI.

| Version | Supported |
| ------- | --------- |
| 0.5.x   | yes       |
| < 0.5   | no        |

## Reporting a Vulnerability

Please do **not** open a public issue for security problems.

Report privately through GitHub's private vulnerability reporting:
[Report a vulnerability](https://github.com/lucamarien/opnsense-mcp-server/security/advisories/new)
(Security tab → "Report a vulnerability"). Include the affected version, a
reproduction, and, if you have one, a proposed fix.

Fixes are developed in the advisory's private fork and released as a patch
version; the advisory is published afterwards with credit to the reporter
unless you prefer otherwise.

## Scope

In scope: anything that lets a tool caller get past the server's own safety
controls, for example:

- reaching an endpoint in `BLOCKED_ENDPOINTS`
- performing a write while `OPNSENSE_ALLOW_WRITES` is off
- secrets (passwords, keys, API credentials) leaking into tool output, logs or
  error messages despite redaction
- injection through tool parameters into OPNsense API calls

Out of scope: vulnerabilities in OPNsense itself (report those to the
[OPNsense project](https://github.com/opnsense/core/security)), and attacks
that require an already compromised MCP host or OPNsense API credentials.
