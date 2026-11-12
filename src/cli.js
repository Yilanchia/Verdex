#!/usr/bin/env node
import path from "node:path";
import { extractAssets } from "./assets.js";
import { buildCodeGraph } from "./graph.js";
import { analyzeProject } from "./project.js";
import { loadBrief } from "./brief.js";
import { collectOsint } from "./osint.js";
import { writeRun } from "./store.js";
import { collectWorkspace, resolveRoot } from "./workspace.js";
import { packageInfo } from "./package-info.js";

const argv = process.argv.slice(2);
const command = argv[0] || "help";
process.stdout.on("error", (error) => {
  if (error.code === "EPIPE") process.exit(0);
  throw error;
});

if (command === "mcp") {
  const { startMcpServer } = await import("./mcp.js");
  startMcpServer();
} else if (command === "help" || command === "--help" || command === "-h") {
  printHelp();
} else if (command === "version" || command === "--version" || command === "-v") {
  process.stdout.write(`${packageInfo().version}\n`);
} else if (command === "doctor") {
  const { doctor } = await import("./doctor.js");
  const report = await doctor();
  if (argv.includes("--json")) process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  else process.stdout.write(formatDoctor(report));
} else if (command === "explain") {
  const { explain } = await import("./explain.js");
  const query = argv[1];
  if (!query) {
    process.stderr.write("用法 / Usage: verdex explain <rule|kind|cwe> [--en] [--json]\n");
    process.exitCode = 1;
  } else {
    const result = explain(query, { lang: argv.includes("--en") ? "en" : "zh" });
    if (argv.includes("--json")) process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    else process.stdout.write(formatExplain(result));
  }
} else {
  await runOnce();
}

async function runOnce() {
  const root = resolveRoot(argv[1] || process.cwd());
  const workspace = collectWorkspace(root);
  let output;
  if (command === "assets") output = extractAssets(workspace);
  else if (command === "map") output = buildCodeGraph(root, { workspace, includeFlows: true });
  else if (command === "osint") {
    const brief = argv[2] ? loadBrief(path.resolve(argv[2])) : null;
    output = collectOsint(workspace, brief ? { ...brief.osint } : {});
  } else if (command === "scan") {
    const brief = argv[2] ? loadBrief(path.resolve(argv[2])) : null;
    output = analyzeProject(root, brief ? { brief } : {});
  } else if (command === "report") {
    const outputDirectory = path.resolve(argv[2] || path.join(root, ".verdex"));
    const briefPath = argv[3];
    const brief = briefPath ? loadBrief(path.resolve(briefPath)) : null;
    const analysis = analyzeProject(root, brief ? { brief } : {});
    output = writeRun(analysis, outputDirectory, brief);
  } else throw new Error(`未知命令 / Unknown command: ${command}。运行 verdex help 查看全部命令。`);
  process.stdout.write(`${JSON.stringify(output, null, 2)}\n`);
}

function printHelp() {
  const { version } = packageInfo();
  process.stdout.write(`verdex ${version} — evidence-first local security research toolset

Usage / 用法:
  verdex <command> [args]
  verdex-mcp                     # start the MCP server (stdio), for agents

Commands / 命令:
  scan <dir> [brief.json]        Static analysis: assets, code graph, rules, dataflows
  assets <dir>                   Domains/URLs/IPs with file:line evidence
  map <dir>                      Code graph: files, functions, routes, calls
  osint <dir> [brief.json]       Local OSINT, redacted by default
  report <dir> [out] [brief]     Immutable run snapshot (JSON / MD / HTML / SARIF)
  explain <rule|cwe> [--en]      Plain-language explanation of a finding class
  doctor [--json]                Check Node + optional backends (IDA/Ghidra/jadx/...)
  mcp                            Start the MCP server over stdio
  help | --help                  Show this help
  version | --version            Print the version

Everything is read-only: Verdex never executes a target and never sends a
network request. Exploit/PoC scaffolding is text-only and requires an explicit
authorized-target declaration; you run every command yourself, in scope.
全部只读:不执行目标、不发网络请求;利用/验证脚手架只产出文本,必须声明授权目标,
由你在授权范围内亲自运行。
`);
}

function formatExplain(result) {
  if (!result.matched) {
    return `未找到规则解释 / No explanation for "${result.query}".\n支持的 id / Supported ids: ${result.supported.join(", ")}\n`;
  }
  const zh = result.lang === "zh";
  const cwe = result.technical.cwe ? ` · ${result.technical.cwe}` : "";
  const lines = [
    `${result.title}${cwe} · ${result.rule_id}`,
    "",
    zh ? `  这是什么   ${result.plain.what}` : `  What it is     ${result.plain.what}`,
    zh ? `  为什么要紧 ${result.plain.why}` : `  Why it matters ${result.plain.why}`,
    zh ? `  该怎么办   ${result.plain.fix}` : `  What to do     ${result.plain.fix}`,
    "",
    zh ? "技术细节 / 怎么复核:" : "Technical detail / how to verify:",
    ...result.technical.signals.map((signal) => `  - ${signal}`),
  ];
  if (result.technical.references.length) lines.push("", `${zh ? "参考" : "References"}: ${result.technical.references.join(" ")}`);
  lines.push("", zh ? "解释针对规则类,不判定具体某条发现的利用性;静态命中仍需人工复核。" : "Explanations describe a rule class, not exploitability of a specific finding; static hits still need human review.");
  return `${lines.join("\n")}\n`;
}

function formatDoctor(report) {
  const lines = [
    `Verdex ${report.package.version} · Node ${report.runtime.node} · ${report.runtime.platform}/${report.runtime.arch} · profile ${report.runtime.profile} · ${report.runtime.tools_visible} tools`,
    "",
    "Backends / 可选后端:",
  ];
  for (const backend of report.backends) {
    const mark = backend.status === "ok" ? "[ok]" : backend.status === "partial" ? "[~] " : "[--]";
    const where = backend.path ? ` ${backend.path}` : backend.detail ? ` ${backend.detail}` : "";
    lines.push(`  ${mark} ${backend.id.padEnd(10)}${backend.label}${where}`);
    if (backend.status !== "ok" && backend.hint) lines.push(`        ↳ ${backend.hint}`);
  }
  lines.push("", `Summary: ${report.summary.ok} ok, ${report.summary.partial} partial, ${report.summary.missing} missing (nothing required except Node >= 20).`);
  for (const step of report.next_steps) lines.push(`  - ${step}`);
  lines.push("", "All checks are local and read-only; doctor sends no network requests.");
  return `${lines.join("\n")}\n`;
}
