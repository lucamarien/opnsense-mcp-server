# Documentation

Best-practice guides for common OPNsense firewall configuration tasks using the MCP server.

## Best Practices

| Guide | Description |
| --- | --- |
| [WhatsApp Calling](best-practices/voip-whatsapp.md) | Allow WhatsApp voice/video calls through a default-deny firewall using URL table aliases, port restrictions, and scoped rules with savepoint protection |

## Contributing Guides

Want to add a best-practice guide? Each guide should:

1. Describe the problem clearly
2. Show the recommended firewall/network configuration
3. Include MCP tool examples (`opn_add_alias`, `opn_add_firewall_rule`, etc.)
4. Explain security considerations and what NOT to do
5. Include a verification workflow using MCP diagnostic tools
