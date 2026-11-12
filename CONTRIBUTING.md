# Contributing to Verdex

Thanks for helping. Verdex is deliberately small and **read-only**; the most
valuable contributions are sharper evidence, clearer explanations, and more
target formats — not more attack capability.

## Setup

```bash
git clone https://github.com/Yilanchia/Verdex.git
cd Verdex
npm ci
npm test          # node --test tests/*.test.mjs
npm run doctor    # optional: see which backends are present
```

Requirements: Node.js >= 20. Optional backends (Ghidra/IDA/jadx/ilspycmd/WSL)
are only needed for the tools that use them; tests must pass without them.

## Ground rules (non-negotiable)

Every change must preserve Verdex's three gates:

1. **Authorized-target declaration is required** for gate tools
   (`pwn_template`, `web_recon`, `web_poc`, `frida_script`, `impact_proof`,
   and any future dynamic-assist tool). Missing declaration = reject.
2. **Text only.** No network requests, no target execution, no attach/injection,
   no command execution on behalf of the user. Do not add a "just run it" mode.
3. **Human in the loop.** Generated scripts/commands are reviewed and run by the
   user inside scope. Output must say so.

Also: keep static findings marked as `inferred` candidates; never upgrade them
to `fact` without runtime evidence. Do not weaken `brief` red lines. Do not add
tool behavior that targets systems the user has not declared.

Pull requests that add unauthorized-attack capability, bypass the gates, or
weaken the evidence model will be closed.

## Adding a tool

1. Create (or extend) a module under `src/` that exports a `*_TOOLS` array:

```js
export const EXAMPLE_TOOLS = [
  {
    name: "example_tool",
    // English first, then the Chinese summary — hosts and non-Chinese models
    // route on the English half.
    description: "One-sentence English description (text-only; no network). | 中文:一句话中文说明(只产文本,不联网)。",
    inputSchema: {
      type: "object",
      required: ["root"],
      properties: {
        root: { type: "string", description: "Absolute path to the workspace. | 中文:作业夹绝对路径。" },
      },
    },
    run: async (args) => ({ schema: "VerdexExample/v1", tool: "example_tool", ... }),
  },
];
```

2. Register the array in `ALL_TOOLS` in `src/mcp.js`. If the tool writes files,
   also add its name to `WRITES_ARTIFACTS` so annotations stay honest
   (`readOnlyHint:false`, `idempotentHint:false`).
3. Return a JSON object with a `schema` marker, the `tool` name, evidence
   (`file:line` + snippet + content hash where possible), and `limitations`.
   Never return secrets in clear text; redact by default.
4. Add a test in `tests/` that proves (a) the happy path, (b) missing inputs are
   rejected, and (c) no network/exec side effect is introduced.
5. Document the tool in `docs/tools.md` and, if it is a headline capability, in
   the README tool table.
6. Add a CHANGELOG entry under `[Unreleased]`.

## Descriptions and i18n

Tool and schema-field descriptions are **bilingual**: English first, then
` | 中文:...`. Keep the safety semantics in the English half too (read-only,
text-only, authorized target required, human runs it). Do not change tool
names, argument names, or return shapes while translating.

## Commits and pull requests

- Small, focused commits. English commit messages describing what and why.
- Run `npm test` before pushing; CI runs Node 20/22/24 on Linux.
- Update docs/CHANGELOG for user-visible changes.
- Do not commit secrets, real customer data, or internal engagement notes.
  Before pushing:

```bash
git grep -nE "AKIA[0-9A-Z]{16}|sk_live_|ghp_|BEGIN (RSA |EC )?PRIVATE KEY" -- . || echo clean
```

- Do not add AI attribution lines to commits.

## Releases

`verdex` and `verdex-mcp` are published together on a version tag; the full
checklist (version bumps, npm, MCP registry, Smithery, directories) is in
[docs/publishing.md](docs/publishing.md).

## Reporting bugs / security issues

- Functional bugs: open a GitHub issue using the bug template (include
  `verdex doctor --json`, Node version, OS).
- Security issues in Verdex itself: follow [SECURITY.md](SECURITY.md), not a
  public issue.
- Requests to attack unauthorized targets are out of scope and will not be
  accepted.
