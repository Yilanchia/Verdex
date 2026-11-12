# Security Policy

Verdex is a **read-only, text-only** analysis toolset. Its own code must never
execute a target, open a network connection, write outside its output
directories, or let a crafted target file escape the sandbox of a parser.

## Supported versions

| Version | Supported |
| --- | --- |
| 0.2.x | ✅ |
| < 0.2 | ❌ |

## Reporting a vulnerability in Verdex

**Do not open a public issue.** Use GitHub's private vulnerability reporting:

1. Go to <https://github.com/Yilanchia/Verdex/security/advisories>
2. Choose **Report a vulnerability**
3. Include: affected version, OS/Node version, the command or MCP tool call,
   a minimal reproducer, and impact.

If private advisories are unavailable, contact the maintainer through the
GitHub profile <https://github.com/Yilanchia> and ask for a private channel.

Please give us a reasonable window to fix the issue before disclosure. We aim
to acknowledge within 72 hours and to ship a fix or mitigation as soon as
practicable. Credit is given in the advisory unless you ask otherwise.

## What counts as a Verdex vulnerability

- Path traversal or arbitrary file write in an unpacker (`mobile_unpack`,
  `wxapkg_unpack`, `asar_unpack`, `fw_extract`).
- Unexpected network access from any tool (Verdex must stay offline).
- Unexpected execution of a target binary or of content from a target file.
- A way to bypass the authorized-target gate or the `brief` red lines.
- Secret leakage: a tool that returns a credential in clear text, or writes one
  into a report/snapshot.
- Denial of service against the local MCP server caused by a crafted target
  (include the sample file, redacted if needed).
- Supply-chain issues in the published package (unexpected files, scripts).

## What is **not** in scope

- Vulnerabilities in a third-party app or server that a user chooses to analyze
  with Verdex — that is the user's authorized engagement, not a Verdex bug.
- Requests to add attack capability, target unauthorized systems, or bypass
  authorization gates.
- Vulnerabilities that require the user to run a generated exploit against an
  unauthorized target.
- Missing optional backends (Ghidra/jadx/…) — that is a setup issue; run
  `verdex doctor` and open a normal bug report if the diagnostics are wrong.

## Handling of user data

Verdex reads local files chosen by the user and writes reports under the
workspace's `.verdex/` directory. OSINT is redacted by default. Do not paste
real secrets into issues; redact values and keep the sha256 prefix if it helps
reproduction.
