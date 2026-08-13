# MCP compatibility

FixCenter supports both MCP protocol eras over newline-delimited stdio JSON-RPC.

- Legacy handshake revisions: `2024-11-05`, `2025-03-26`, `2025-06-18`, `2025-11-25`.
- Modern stateless revision: `2026-07-28`, discovered through `server/discover` and accepted through per-request `_meta`.

The server advertises read-only, non-destructive, idempotent and closed-world tool annotations. Every tool returns both a serialized text block and object-shaped `structuredContent`, with a root object `outputSchema`.

The `tools/list` result is deterministic and carries modern `ttlMs` and `cacheScope` hints. Legacy clients may ignore those additive fields.

Primary references:

- [MCP 2026-07-28 release](https://blog.modelcontextprotocol.io/posts/2026-07-28/)
- [MCP stdio transport](https://modelcontextprotocol.io/specification/2025-06-18/basic/transports)
- [MCP tool schemas and structured content](https://modelcontextprotocol.io/specification/2025-06-18/server/tools)
