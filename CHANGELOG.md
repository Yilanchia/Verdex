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
- `README.en.md`, `docs/tools.md` (full tool reference), issue templates, and
  PR template.

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

## [0.1.0] - 2026-10-14

Initial open-source release: read-only analysis core (assets, code graph, rule
scan, dataflow candidates), reports (Markdown / HTML / SARIF), MCP server with
34 tools, reverse engineering, pwn/web/mobile/firmware/JS/.NET/Electron
analysis, `analyze_target` routing, impact-proof planning, and the local GUI.

[Unreleased]: https://github.com/Yilanchia/Verdex/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/Yilanchia/Verdex/releases/tag/v0.2.0
[0.1.0]: https://github.com/Yilanchia/Verdex/releases/tag/v0.1.0
