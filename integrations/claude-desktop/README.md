# yof for Claude Desktop

`manifest.json` is an MCP Bundle (.mcpb) manifest, written to the MCPB manifest spec (manifest_version 0.3, checked 2026-11-09).

Build the bundle after `npm run build` in the CLI folder:

```
mkdir -p integrations/claude-desktop/server
cp dist/bin.js dist/chunk-*.js integrations/claude-desktop/server/
npx @anthropic-ai/mcpb pack integrations/claude-desktop yof.mcpb
```

To confirm before publishing: that the packed bundle installs and starts on Claude Desktop for macOS and Windows, and that `privacy_policies` is accepted as written. Until a bundle is published, Claude Desktop users can add this to `claude_desktop_config.json` instead:

```json
{ "mcpServers": { "yof": { "command": "npx", "args": ["-y", "@yof/cli", "mcp", "/path/to/your/project"] } } }
```
