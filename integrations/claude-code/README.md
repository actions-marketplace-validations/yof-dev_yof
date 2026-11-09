# yof for Claude Code

A Claude Code plugin: yof checks the code Claude writes for leaked keys and made-up packages before it says the work is done. Everything runs on your computer.

What is inside:

- `.mcp.json`: the yof MCP server (`npx -y @yof/cli mcp`). If `YOF_API_KEY` is set, it can also read your yof.io findings and Patch pull requests.
- `skills/check-before-done`: tells Claude to run `yof_check_diff`, fix every "fix now" finding and confirm with `yof_verify` before finishing.
- `hooks/hooks.json`: after each Write or Edit, a quick key check of what changed; before Claude stops, the full check. A "fix now" finding is sent back to Claude once, never in a loop.

Install (until the plugin is listed in a marketplace):

```
claude plugin marketplace add yof-dev/yof
claude plugin install yof@yof
```

Or without the plugin, only the MCP server:

```
claude mcp add yof -- npx -y @yof/cli mcp
```

Format checked against Claude Code's plugin reference on 2026-11-09 (`.claude-plugin/plugin.json`, `.mcp.json`, `skills/<name>/SKILL.md` and `hooks/hooks.json` at the plugin root). Docs: https://yof.io/docs/ai-builders/claude-code
