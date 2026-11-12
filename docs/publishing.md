# Publishing & registry checklist

Verdex ships two npm packages. They must be published in order:

| Package | What it is | Depends on |
| --- | --- | --- |
| `verdex` | CLI, analysis library and every MCP tool (`src/`) | — |
| `verdex-mcp` | 15-line stdio entry so `npx -y verdex-mcp` works | `verdex` |

`npx <name>` resolves a **package** by name, which is why the MCP entry has its own
package. Both names were confirmed free on the official npm registry on 2026-11-12
(`npm view verdex --registry https://registry.npmjs.org` → 404).

## 1. Preflight

> **Registry note:** this machine currently points npm at `registry.npmmirror.com`
> (a read-only mirror). Publishing there does **not** create the package on the
> official registry that the MCP registry and `npx` users read. Either pass
> `--registry https://registry.npmjs.org` to the publish commands below, or run
> `npm config set registry https://registry.npmjs.org` for the release session.
> The `Release` workflow already uses the official registry via `setup-node`.

```bash
npm whoami --registry https://registry.npmjs.org   # must be logged in (or NPM_TOKEN in CI)
npm test                   # all green
npm pack --dry-run         # root tarball: src, web, bin, docs, README*, LICENSE
npm publish --dry-run --registry https://registry.npmjs.org
node src/cli.js doctor     # optional sanity check
```

Bump the version in **all** of these before releasing:

- `package.json`
- `packages/verdex-mcp/package.json` (and its `verdex` dependency range)
- `server.json`
- `CHANGELOG.md` (`[Unreleased]` → new version)
- `src/mcp.js` needs nothing (serverInfo reads `package.json`)

Then commit and tag:

```bash
git tag v0.2.0
git push origin main --tags
```

The `Release` workflow (`.github/workflows/release.yml`) runs the tests, then
publishes both packages with `--provenance`. It needs an `NPM_TOKEN` repository
secret with publish rights. Publishing manually is the same two commands:

```bash
npm publish --registry https://registry.npmjs.org --access public
(cd packages/verdex-mcp && npm publish --registry https://registry.npmjs.org --access public)
```

Verify from a clean directory:

```bash
npx -y verdex --version
npx -y verdex doctor
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' | npx -y verdex-mcp
```

## 2. Official MCP registry

`server.json` is ready (schema `2025-12-11`). The registry checks `mcpName` inside
the **published** package and requires it to equal the server name
(`io.github.Yilanchia/verdex`), which `packages/verdex-mcp/package.json` provides.

```bash
# install the publisher CLI (see modelcontextprotocol.io/registry/quickstart)
mcp-publisher login github          # GitHub device flow; namespace must be io.github.Yilanchia
mcp-publisher publish               # reads ./server.json
curl "https://registry.modelcontextprotocol.io/v0.1/servers?search=io.github.Yilanchia/verdex"
```

If validation fails, check:

- `verdex-mcp@0.2.0` is actually on npm;
- its `mcpName` matches `server.json.name` exactly;
- `server.json` version equals the published package version.

## 3. Smithery

`smithery.yaml` starts `npx -y verdex-mcp` over stdio and declares an empty config
schema. Claim the repository on <https://smithery.ai>, point it at the GitHub repo,
and let it read `smithery.yaml`. Keep the description explicit about
**read-only / text-only / authorized targets only** — directory reviewers treat
"security tool" entries with suspicion, and the safety model is the strongest
argument for approval.

## 4. Directories that auto-crawl GitHub

`mcp.so`, `glama.ai` and similar directories mostly index GitHub. No file is
needed, but the repo must clearly answer, in English:

1. what the server does (README first paragraph),
2. how to install/run it (`npx -y verdex-mcp`),
3. what it will **not** do (read-only, text-only, authorized targets only),
4. where the tool reference is (`docs/tools.md`).

## 5. Post-publish checks

- npm pages render the README and show two bins (`verdex`, `verdex-mcp`).
- `npx -y verdex-mcp` starts and answers `initialize` + `tools/list` (35 tools).
- The registry search result shows `io.github.Yilanchia/verdex` with a stdio npm
  package.
- No sensitive strings in the published tarballs:

```bash
npm pack --dry-run --json | node -e "let s='';process.stdin.on('data',d=>s+=d).on('end',()=>console.log(JSON.parse(s)[0].files.map(f=>f.path).join('\n')))"
```
