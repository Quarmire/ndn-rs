# ndn-mcp

A Model Context Protocol (MCP) server that provides AI assistants with tools
for navigating and understanding the ndn-rs codebase.

## Tools

- **lookup_crate** -- Look up a workspace crate by name (description, layer, key types, deps, path)
- **lookup_type** -- Find the definition of a Rust type (struct/enum/trait) in the codebase
- **spec_gaps** -- Return the contents of `docs/spec-gaps.md`
- **pipeline_stage** -- Describe an NDN forwarding pipeline stage (position, behavior, Action variants)
- **search_docs** -- Search across `docs/wiki/src/**/*.md` for matching content

## Install

```bash
cd tools/ndn-mcp
npm install
```

## Run

```bash
node tools/ndn-mcp/server.js
```

The server communicates over stdio using the MCP protocol.

## Configure in Claude Code

Add the following to your Claude Code MCP settings (`.claude/settings.json` or
project-level `.mcp.json`):

```json
{
  "mcpServers": {
    "ndn-mcp": {
      "command": "node",
      "args": ["tools/ndn-mcp/server.js"]
    }
  }
}
```

If you prefer to use an absolute path:

```json
{
  "mcpServers": {
    "ndn-mcp": {
      "command": "node",
      "args": ["/path/to/ndn-rs/tools/ndn-mcp/server.js"]
    }
  }
}
```
