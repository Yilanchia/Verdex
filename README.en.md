# Verdex

[![XERJ Corpus Hub contributor](https://hub.xerj.org/contributors/Yilanchia/badge.svg)](https://hub.xerj.org/contributors/Yilanchia)
[![M8ven Score](https://m8ven.ai/badge/mcp/yilanchia-verdex-1s28o0?v=8acf7584845a7b298157c8c27d0f28fc)](https://m8ven.ai/mcp/yilanchia-verdex-1s28o0?s=readme)
[![CI](https://github.com/Yilanchia/Verdex/actions/workflows/ci.yml/badge.svg)](https://github.com/Yilanchia/Verdex/actions/workflows/ci.yml)

**Evidence-first local security research toolset, driven by LLMs over MCP.**

Verdex turns source auditing, binary reverse engineering, pwn/web assist, mobile and firmware analysis into **read-only tools an LLM can orchestrate** over the Model Context Protocol (stdio + JSON-RPC 2.0). It is not a static toolbox: it produces an evidence chain from *asset evidence → static relationships → dataflow candidates → human conclusions*.

> **Responsible use**
> Verdex is **read-only and text-only**: it never executes a target, never sends a network request, never attacks on its own, and never generates payloads aimed at unauthorized systems. Tools marked *gate* (`pwn_*`, `web_recon`, `web_poc`, `frida_script`, `impact_proof`) require an explicit authorized-target declaration, emit text only, and expect a human in the loop. Authorized scopes only: CTF, your own lab, or systems you own or are explicitly permitted to test.

## Why it is different

- **Evidence, not vibes.** Findings keep `file:line`, snippets, file hashes, an evidence fingerprint for deduplication, and honest `inferred` vs `fact` markers.
- **Enforced scope.** A `brief` fixes scope, vulnerability classes, minimum confidence and mandatory `no-payload / no-bruteforce / no-out-of-scope` red lines. Loosening them is rejected.
- **Immutable runs.** `report` writes a snapshot (`analysis.json`, `findings.json`, redacted `osint.json`, `report.md`, self-contained `report.html`, SARIF 2.1.0); `diff` compares runs by fingerprint.
- **Human-readable output.** `explain` translates a rule/CWE into *what it is / why it matters / what to do* for non-technical readers.

## Who it is for

| You are | Use Verdex to | Start with |
| --- | --- | --- |
| Security researcher / auditor | Keep a reviewable evidence chain and snapshot instead of a pile of notes | `scan` → `report` |
| Bug bounty hunter | Turn a hostname into a staged recon playbook; turn a "conditional" finding into a reviewable proof plan | `analyze_target` → `web_recon` / `impact_proof` |
| RE / pwn / CTF player | checksec, gadgets, libc offsets, cyclic offsets, gdb scripts, exploit scaffolds, decompilation | `VERDEX_PROFILE=pwn` + `pwn_*` / `bin_decompile` |
| Developer auditing your own app | Unpack APK/IPA/mini-program/Electron/firmware; inspect permissions, exported components, secrets | `mobile_unpack` → `secrets` / `har_analyze` |

## Quickstart

Requires **Node.js >= 20** (CI covers 20/22/24).

```bash
git clone https://github.com/Yilanchia/Verdex.git
cd Verdex
npm ci

# Run the MCP server from source (works today)
node src/cli.js mcp

# Or, once 0.2.0 is on npm
npx -y verdex-mcp
```

Then wire it into your agent (Claude Desktop / Cursor / Cline share this shape):

```json
{
  "mcpServers": {
    "verdex": { "command": "npx", "args": ["-y", "verdex-mcp"] }
  }
}
```

Source checkout variant:

```json
{
  "mcpServers": {
    "verdex": {
      "command": "node",
      "args": ["/absolute/path/to/Verdex/src/cli.js", "mcp"]
    }
  }
}
```

DeepSeek Harness (`cordis.yml`, or use the bundled `verdex-mcp.patch.yml`):

```yaml
- id: mcp-verdex
  name: '@deepseek-ai/dsh-mcp-client'
  config:
    serverName: verdex
    transport: stdio
    command: node
    args: ['/absolute/path/to/Verdex/src/cli.js', 'mcp']
```

First run: ask the agent to call `analyze_target` with a local path (or an authorized domain), then follow the recommended chain (`scan` → `report` → open `report.html`), and use `explain` if a finding needs plain language.

### CLI

```bash
node src/cli.js scan   <dir> [brief.json]
node src/cli.js assets <dir>
node src/cli.js map    <dir>
node src/cli.js osint  <dir> [brief.json]
node src/cli.js report <dir> [out] [brief]
node src/cli.js doctor      # backend self-check, no network
node src/cli.js --version
```

### Local GUI

```bash
npm start      # http://127.0.0.1:3210
```

Pick a workspace, add domains/URLs/IPs, fill a brief, review coverage/assets/redacted OSINT/candidates, save a snapshot. Local-only listener; analysis makes no network requests; the optional AI review is off by default and secrets stay in process memory.

## Tools (34)

Full inputs, backends and gates: **[docs/tools.md](docs/tools.md)**.

| Group | Tools | Backend |
| --- | --- | --- |
| Source / project | `assets` `map` `scan` `osint` `report` `diff` `secrets` | none (pure Node) |
| Orchestration | `analyze_target` | none |
| Reverse engineering | `bin_info` `bin_symbols` `bin_strings` `bin_disasm` `bin_dossier` `bin_decompile` `reconstruct` | binutils; IDA or Ghidra for decompile |
| Pwn assist (authorized labs) | `pwn_checksec` `pwn_gadgets` `pwn_template` `pwn_cyclic` `pwn_gdbscript` `pwn_libc` | binutils; text-only |
| Web assist | `web_recon` `har_analyze` `web_poc` | your HAR; text-only |
| Mobile | `mobile_unpack` `wxapkg_unpack` `dex_decompile` | pure Node; jadx for DEX |
| Firmware | `fw_scan` `fw_extract` | WSL + squashfs-tools on Windows |
| JS / Electron / .NET | `js_deobfuscate` `asar_unpack` `dotnet_decompile` | pure Node; ilspycmd for .NET |
| Dynamic / proof | `frida_script` `impact_proof` | authorization declaration only; text-only |

For pwn/CTF sessions, `VERDEX_PROFILE=pwn` trims the advertised tool surface to save context; capability is not removed (hidden tools still dispatch).

## Safety model

1. **Authorized-target declaration is required** for every gate tool (domain / URL / target), rejected when missing.
2. **Text only.** No network requests, no attach/injection, no target execution, no command execution by Verdex.
3. **Human in the loop.** Generated commands and scripts are reviewed and run by you, inside scope, following project rules (rate limits, no brute force).

Everything else follows the same rule: static findings are `inferred` candidates for human review, not confirmed vulnerabilities.

## Optional backends

| Backend | Used by | Configure |
| --- | --- | --- |
| binutils (`objdump`/`nm`/`strings`/`file`) | reverse tools | put on `PATH` (Windows: MSYS2/ucrt64) |
| IDA Pro / Hex-Rays | `bin_decompile` (preferred) | `VERDEX_IDA` → `idat.exe` / `idat64` |
| Ghidra headless | `bin_decompile` (free fallback) | `VERDEX_GHIDRA` → `support/analyzeHeadless[.bat]`, JDK 21+ |
| jadx | `dex_decompile` | `VERDEX_JADX` → `bin/jadx[.bat]` |
| ilspycmd + .NET runtime | `dotnet_decompile` | `VERDEX_ILSPY` → `ilspycmd.dll` |
| WSL + squashfs-tools | `fw_extract` (Windows) | `VERDEX_WSL_DISTRO` |

`verdex doctor` reports what is present, where, and what it affects — without running a target or touching the network.

## What Verdex does not do

- Execute target files, attach to processes, inject code, or send HTTP/DNS requests.
- Generate payloads for unauthorized targets or run an automatic attack chain.
- Perform identity correlation or data-broker lookups; local OSINT is redacted by default.
- Present inferences as facts.

## Contributing, security, license

- [CONTRIBUTING.md](CONTRIBUTING.md) — test setup, tool conventions, red lines.
- [CHANGELOG.md](CHANGELOG.md) — release history.
- [SECURITY.md](SECURITY.md) — private vulnerability reporting.
- MIT © 2026 Yilanchia.

中文说明见 [README.md](README.md)。
