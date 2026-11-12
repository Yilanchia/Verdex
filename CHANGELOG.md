# Changelog

All notable changes to this project are documented in this file. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-11-12

### Added

- `verdex doctor`: local, read-only diagnostics for Node and optional backends
  (binutils, IDA, Ghidra, JDK, jadx, .NET/ilspycmd, WSL/squashfs-tools), with
  `--json` output. It never runs a target and never touches the network.
- npm bin entry points: `verdex` (CLI) and `verdex-mcp` (stdio MCP server).
- GitHub Actions CI on Node 20 / 22 / 24, plus a job that packs the npm tarball
  and smoke-tests both bin entry points.
- Package/CLI/MCP-over-stdio smoke tests (Node test runner).
- `initialize` now returns server `instructions` describing the safety model and
  the recommended first call (`analyze_target`).
- `explain` tool: turns a scanner kind / secrets rule id / CWE / impact-proof
  class into a plain-language triad (what it is, why it matters, what to do) plus
  CWE, verification signals and references, bilingual (zh/en). Reports
  (`report.md`, `report.html`) now open with a "给非技术读者" section for
  high/critical findings.
- `README.en.md`, `docs/tools.md` (full tool reference), issue templates, and
  PR template.
- Distribution scaffolding: `server.json` for the official MCP registry,
  `smithery.yaml`, a `verdex-mcp` stdio entry package (so `npx -y verdex-mcp`
  resolves), and a tag-triggered `Release` workflow that publishes both packages
  with npm provenance. See `docs/publishing.md`.

### Changed

- Package renamed `verdex-workbench` → `verdex`; version bumped to `0.2.0`;
  `private` removed; MIT metadata, repository/homepage/bugs, keywords, `files`
  and `bin` added so the package is publishable.
- MCP `serverInfo.version` now follows `package.json` (no more hardcoded
  `0.1.0`).
- `verdex` with no arguments prints help instead of silently scanning the
  current directory. Use `verdex scan <dir>` explicitly.
- Unknown-tool, unsupported-method and tool-failure messages are bilingual
  (EN / 中文).
- README restructured for a mixed audience: what it is, who it is for, a
  5-minute quickstart, the safety model, and a tool overview.

### Security

- Removed real engagement identifiers and credential values from the test
  fixtures (they had been committed in earlier releases): the app key, the
  signing salt and the location-secret value are now synthetic, and the sample
  manifest path no longer embeds a project name. **If you cloned or forked this
  repository before 0.2.0, treat those values as exposed and rotate them** —
  they remain in git history until the history is rewritten.
- Added `tests/hygiene.test.mjs`: a repo-wide guard that fails when engagement
  identifiers, local user paths or the leaked fragments reappear in any tracked
  file, including tests and docs.

### Fixed

- `verdex doctor` now probes `dotnet --list-runtimes` instead of `dotnet
  --version`, so runtime-only .NET installs (no SDK) are reported as available —
  the runtime is all `dotnet_decompile` needs to host ilspycmd.
- Python AST analysis now tries `$PYTHON`, then `python3`, then `python`, instead
  of assuming `python` exists. Linux and CI images that only ship `python3` keep
  structured Python routes/definitions/dataflows; without any interpreter the
  graph degrades to the bounded text fallback and reports it in `coverage`.
- The AST dataflow test skips only the Python assertions when no interpreter is
  available, so a clean Linux runner without Python still passes while still
  checking TypeScript dataflows.

## [0.1.0] - 2026-10-14

Initial open-source release: read-only analysis core (assets, code graph, rule
scan, dataflow candidates), reports (Markdown / HTML / SARIF), MCP server with
34 tools, reverse engineering, pwn/web/mobile/firmware/JS/.NET/Electron
analysis, `analyze_target` routing, impact-proof planning, and the local GUI.

[Unreleased]: https://github.com/Yilanchia/Verdex/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/Yilanchia/Verdex/releases/tag/v0.2.0
[0.1.0]: https://github.com/Yilanchia/Verdex/releases/tag/v0.1.0
