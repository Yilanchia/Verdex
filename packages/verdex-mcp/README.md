# verdex-mcp

Stdio MCP entry point for [Verdex](https://github.com/Yilanchia/Verdex).

This package exists so `npx -y verdex-mcp` works: npm's `npx <name>` resolves a
**package** by name, while the Verdex CLI lives in the `verdex` package.

```bash
npx -y verdex-mcp
```

It starts the same read-only, text-only analysis server (35 tools). For the CLI
(`verdex scan <dir>`, `verdex doctor`, `verdex explain ...`), use the `verdex`
package instead:

```bash
npx -y verdex --version
npm install -g verdex
```

Safety model: Verdex never executes a target, never sends network requests, and
never attacks anything. `pwn_*` / `web_recon` / `web_poc` / `frida_script` /
`impact_proof` require an explicit authorized-target declaration, emit text only,
and expect you to run every command yourself inside an authorized scope.
