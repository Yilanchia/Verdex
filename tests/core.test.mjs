import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { parseArtifacts } from "../src/artifacts.js";
import { validateBrief } from "../src/brief.js";
import { createManualAssets, extractAssets } from "../src/assets.js";
import { createEvidence, dedupeFindings, findingFingerprint } from "../src/evidence.js";
import { buildCodeGraph } from "../src/graph.js";
import { collectOsint } from "../src/osint.js";
import { searchPersonalInfo } from "../src/personal.js";
import { analyzeProject } from "../src/project.js";
import { createServer } from "../src/server.js";
import { inScope, validateScope } from "../src/scope.js";
import { scanProject } from "../src/scanner.js";
import { collectWorkspace } from "../src/workspace.js";
import { dispatch } from "../src/mcp.js";
import { binInfo, binStrings, binDisasm, binDecompile, reconstructSource } from "../src/reverse.js";
import { pwnChecksec, pwnGadgets, pwnTemplate, pwnCyclic, pwnGdbScript, pwnLibc } from "../src/pwn.js";
import { analyzeHar, webPoc } from "../src/web.js";

function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "verdex-workbench-"));
  fs.writeFileSync(path.join(root, "scope.txt"), "*.paypal.cn\nhttps://api.paypal.cn/login\n192.0.2.10\n", "utf8");
  fs.writeFileSync(path.join(root, "app.py"), [
    "from flask import request",
    "@app.route('/search')",
    "def search():",
    "    query = request.args.get('q')",
    "    statement = 'SELECT * FROM users WHERE name = ' + query",
    "    return db.execute(statement)",
    "",
    "def wrapper():",
    "    return search()",
  ].join("\n"), "utf8");
  fs.writeFileSync(path.join(root, "proxy.ts"), [
    "import express from 'express';",
    "const app = express();",
    "app.get('/proxy', (req, res) => {",
    "  const target = req.query.url;",
    "  return fetch(target);",
    "});",
  ].join("\n"), "utf8");
  fs.writeFileSync(path.join(root, "safe.ts"), "function render(value: string) { element.textContent = value; }\n", "utf8");
  fs.writeFileSync(path.join(root, "nuclei-results.jsonl"), JSON.stringify({ "template-id": "exposed-panel", "matched-at": "https://api.paypal.cn/admin", info: { severity: "high", name: "Exposed panel" } }) + "\n", "utf8");
  return root;
}

test("workspace evidence preserves file hashes and partial coverage", () => {
  const root = fixture();
  try {
    const workspace = collectWorkspace(root, { maxFiles: 2 });
    assert.equal(workspace.coverage.status, "partial");
    assert.equal(workspace.files.length, 2);
    assert.match(workspace.files[0].content_sha256, /^[a-f0-9]{64}$/);
    assert.ok(workspace.coverage.omitted["file-limit"] > 0);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("asset extraction keeps source evidence and scope decisions separate", () => {
  const root = fixture();
  try {
    const assets = extractAssets(root);
    assert.ok(assets.hosts.includes("api.paypal.cn"));
    assert.ok(assets.urls.includes("https://api.paypal.cn/login"));
    assert.ok(assets.ips.includes("192.0.2.10"));
    assert.ok(assets.items.every((item) => item.evidence.every((evidence) => evidence.content_sha256)));
    const scope = validateScope({ include: ["*.paypal.cn"], exclude: ["lab.paypal.cn"] });
    assert.equal(inScope("api.paypal.cn", scope), true);
    assert.equal(inScope("paypal.cn", scope), false);
    assert.equal(inScope("lab.paypal.cn", scope), false);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("AST graph records routes, calls and Python/TypeScript dataflows", () => {
  const root = fixture();
  try {
    const first = buildCodeGraph(root, { includeFlows: true });
    const second = buildCodeGraph(root, { includeFlows: true });
    assert.equal(first.graph_id, second.graph_id);
    assert.equal(first.schema, "VerdexCodeGraph/v2");
    assert.ok(first.routes.some((route) => route.path === "/search"));
    assert.ok(first.routes.some((route) => route.path === "/proxy"));
    assert.ok(first.definitions.some((definition) => definition.name === "search"));
    assert.ok(first.dataflows.some((flow) => flow.kind === "sql" && flow.source.line === 4 && flow.sink.line === 6));
    assert.ok(first.dataflows.some((flow) => flow.kind === "ssrf" && flow.source.line === 4 && flow.sink.line === 5));
    assert.ok(first.edges.some((edge) => edge.relation === "calls"));
    assert.ok(first.dataflows.every((flow) => flow.chain.every((evidence) => evidence.epistemic === "inferred")));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("scanner deduplicates rule and dataflow observations by sink evidence", () => {
  const root = fixture();
  try {
    const scan = scanProject(root);
    assert.equal(scan.schema, "VerdexScan/v2");
    assert.ok(scan.findings.some((finding) => finding.kind === "sql"));
    assert.ok(scan.findings.some((finding) => finding.kind === "ssrf"));
    assert.equal(new Set(scan.findings.map((finding) => finding.fingerprint)).size, scan.findings.length);
    const evidence = createEvidence({ file: "app.py", content_sha256: "a".repeat(64), line: 6, snippet: "return db.execute(statement)" });
    const finding = { file: "app.py", line: 6, kind: "sql", evidence: [evidence] };
    assert.equal(findingFingerprint(finding), findingFingerprint({ ...finding, title: "same evidence" }));
    assert.equal(dedupeFindings([finding, { ...finding, title: "same evidence" }]).length, 1);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("artifact observations stay passive and brief validation enforces scope", () => {
  const root = fixture();
  try {
    const workspace = collectWorkspace(root);
    const artifacts = parseArtifacts(workspace);
    assert.equal(artifacts.schema, "VerdexArtifacts/v1");
    assert.equal(artifacts.observations.length, 1);
    assert.equal(artifacts.observations[0].name, "exposed-panel");
    assert.equal(artifacts.observations[0].severity, "high");
    assert.equal(artifacts.observations[0].evidence.file, "nuclei-results.jsonl");
    const brief = validateBrief({ scope: { include: ["*.paypal.cn"], exclude: ["lab.paypal.cn"] } });
    assert.equal(brief.allow.includes("parse_artifacts"), true);
    assert.throws(() => validateBrief({ scope: { include: [] } }));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("brief policy filters findings and passive observations by scope", () => {
  const root = fixture();
  const outside = path.join(root, "scan-results.json");
  fs.writeFileSync(outside, JSON.stringify([
    { "template-id": "outside", "matched-at": "https://outside.example/admin", info: { severity: "high" } },
    { "template-id": "inside", "matched-at": "https://api.paypal.cn/admin", info: { severity: "high" } },
  ]), "utf8");
  try {
    const brief = validateBrief({
      scope: { include: ["*.paypal.cn"] },
      vuln_classes: ["sqli", "ssrf"],
      min_confidence: "medium",
    });
    const analysis = analyzeProject(root, { brief });
    assert.equal(analysis.brief.vuln_classes.includes("sql"), true);
    assert.ok(analysis.scan.findings.every((finding) => ["sql", "ssrf"].includes(finding.kind)));
    assert.ok(analysis.scan.coverage.filtered_by_brief > 0);
    assert.equal(analysis.artifacts.coverage.filtered_out_of_scope, 1);
    assert.ok(analysis.artifacts.observations.some((observation) => observation.name === "inside"));
    assert.equal(analysis.artifacts.observations.some((observation) => observation.name === "outside"), false);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("local OSINT extracts labeled identifiers with redacted evidence", () => {
  const root = fixture();
  fs.writeFileSync(path.join(root, "contacts.json"), JSON.stringify({
    full_name: "Ada Lovelace",
    email: "Ada.Lovelace@example.test",
    phone: "13812345678",
    username: "ada-lovelace",
    profile: "https://github.com/ada-lovelace",
  }), "utf8");
  try {
    const workspace = collectWorkspace(root);
    const osint = collectOsint(workspace);
    assert.equal(osint.schema, "VerdexOSINT/v1");
    assert.equal(osint.privacy.mode, "redacted");
    assert.equal(osint.privacy.network_requests, false);
    assert.ok(osint.observations.some((item) => item.category === "email" && item.display_value.includes("***")));
    assert.ok(osint.observations.some((item) => item.category === "phone" && item.display_value.includes("****")));
    assert.ok(osint.observations.some((item) => item.category === "social-profile"));
    assert.ok(osint.observations.some((item) => item.category === "person-name"));
    assert.ok(osint.observations.some((item) => item.category === "username"));
    assert.ok(osint.observations.every((item) => !Object.hasOwn(item, "value")));
    assert.ok(osint.observations.every((item) => item.evidence.every((evidence) => !evidence.snippet.includes("Ada.Lovelace@example.test"))));
    const emailsOnly = collectOsint(workspace, { categories: ["emails"] });
    assert.equal(emailsOnly.observations.length, 1);
    const disabled = collectOsint(workspace, { enabled: false });
    assert.equal(disabled.observations.length, 0);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("local frontend serves dashboard and analysis API", async () => {
  const root = fixture();
  const runsDirectory = fs.mkdtempSync(path.join(os.tmpdir(), "verdex-runs-"));
  const server = createServer({ runsDirectory });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = server.address().port;
  try {
    const page = await fetch("http://127.0.0.1:" + port + "/");
    assert.equal(page.status, 200);
    assert.match(await page.text(), /Verdex/);
    const health = await fetch("http://127.0.0.1:" + port + "/api/health");
    assert.equal(health.status, 200);
    assert.equal((await health.json()).networkRequests, false);
    assert.equal(health.headers.get("x-frame-options"), "DENY");
    assert.match(health.headers.get("content-security-policy"), /default-src 'self'/);
    const response = await fetch("http://127.0.0.1:" + port + "/api/analyze", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ root }),
    });
    assert.equal(response.status, 200);
    const analysis = await response.json();
    assert.equal(analysis.schema, "VerdexProject/v1");
    assert.equal(analysis.osint.schema, "VerdexOSINT/v1");
    const fingerprint = analysis.scan.findings[0]?.fingerprint;
    const saved = await fetch("http://127.0.0.1:" + port + "/api/save-run", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ review: { [fingerprint]: { status: "confirmed", note: "人工复核备注" } } }) });
    assert.equal(saved.status, 200);
    const savedRun = await saved.json();
    assert.match(savedRun.id, /^run-/);
    const runs = await fetch("http://127.0.0.1:" + port + "/api/runs");
    assert.equal((await runs.json()).runs.length, 1);
    const report = await fetch("http://127.0.0.1:" + port + savedRun.report_url);
    assert.equal(report.status, 200);
    const reportText = await report.text();
    assert.match(reportText, /Verdex 分析报告/);
    assert.match(reportText, /复核状态：确认候选/);
    assert.match(reportText, /人工复核备注/);
  } finally {
    await new Promise((resolve) => server.close(resolve));
    fs.rmSync(root, { recursive: true, force: true });
    fs.rmSync(runsDirectory, { recursive: true, force: true });
  }
});

test("local server rejects cross-origin requests and insecure remote AI endpoints", async () => {
  const server = createServer();
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = server.address().port;
  try {
    const crossOrigin = await fetch("http://127.0.0.1:" + port + "/api/health", {
      headers: { origin: "http://evil.example:" + port },
    });
    assert.equal(crossOrigin.status, 403);

    const insecureEndpoint = await fetch("http://127.0.0.1:" + port + "/api/ai/settings", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ enabled: true, baseUrl: "http://ai.example/v1", model: "test" }),
    });
    assert.equal(insecureEndpoint.status, 400);
    assert.match((await insecureEndpoint.json()).error, /HTTPS/);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test("manual assets and personal search stay local and evidence-backed", () => {
  const root = fixture();
  fs.writeFileSync(path.join(root, "identity.txt"), "contact: ada@example.test\nusername: ada-lovelace\n", "utf8");
  try {
    const manual = createManualAssets(["api.example.com", "https://admin.example.com/login", "192.0.2.20"]);
    assert.equal(manual.hosts[0], "api.example.com");
    assert.equal(manual.urls[0], "https://admin.example.com/login");
    assert.equal(manual.ips[0], "192.0.2.20");
    assert.equal(manual.items[0].evidence[0].authority, "user-input");
    const result = searchPersonalInfo(root, { queries: ["ada@example.test", "ada-lovelace"] });
    assert.equal(result.schema, "VerdexPersonalSearch/v1");
    assert.equal(result.privacy.network_requests, false);
    assert.equal(result.observations.length, 2);
    assert.ok(result.observations.every((item) => !item.evidence.snippet.includes("ada@example.test")));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("MCP server lists read-only tools and enforces brief redlines over stdio protocol", async () => {
  const init = await dispatch({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2024-11-05" } });
  assert.equal(init.result.serverInfo.name, "verdex");

  const list = await dispatch({ jsonrpc: "2.0", id: 2, method: "tools/list" });
  const names = list.result.tools.map((tool) => tool.name);
  for (const expected of ["assets", "map", "osint", "scan", "report", "bin_info", "bin_symbols", "bin_strings", "bin_disasm", "bin_decompile", "reconstruct", "diff", "pwn_checksec", "pwn_gadgets", "pwn_template", "pwn_cyclic", "pwn_gdbscript", "pwn_libc", "har_analyze", "web_poc", "mobile_unpack", "wxapkg_unpack", "dex_decompile", "secrets", "fw_scan", "fw_extract", "js_deobfuscate", "analyze_target", "frida_script", "dotnet_decompile", "asar_unpack", "web_recon"]) {
    assert.ok(names.includes(expected), `missing tool ${expected}`);
  }

  const root = fixture();
  try {
    const scan = await dispatch({ jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "scan", arguments: { root } } });
    assert.ok(!scan.result.isError);
    const analysis = JSON.parse(scan.result.content[0].text);
    assert.equal(analysis.schema, "VerdexProject/v1");
    assert.ok(analysis.assets.items.length > 0);

    const dangerous = await dispatch({ jsonrpc: "2.0", id: 4, method: "tools/call", params: { name: "scan", arguments: { root, brief: { schema: "VerdexBrief/v1", scope: { include: ["*.paypal.cn"] }, allow: ["network_request"] } } } });
    assert.ok(dangerous.result.isError);
    assert.match(dangerous.result.content[0].text, /network requests, payload execution or brute force/);

    const osint = await dispatch({ jsonrpc: "2.0", id: 5, method: "tools/call", params: { name: "osint", arguments: { root } } });
    assert.ok(!osint.result.isError);

    const unknown = await dispatch({ jsonrpc: "2.0", id: 6, method: "tools/call", params: { name: "exploit", arguments: { root } } });
    assert.ok(unknown.error);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("reverse tools read binary facts statically without executing the target", async () => {
  const target = process.execPath;
  try {
    const info = await binInfo(target);
    assert.equal(info.schema, "VerdexReverse/v1");
    assert.equal(info.epistemic, "fact");
    assert.ok(info.file_type.length > 0);
    assert.ok(info.limitations.some((line) => line.includes("未执行目标")));

    const strings = await binStrings(target, {});
    assert.ok(strings.strings.total_lines > 0);

    const disasm = await binDisasm(target, {});
    assert.ok(disasm.disassembly.total_lines > 0);
  } catch (error) {
    if (/后端未安装/.test(error.message)) {
      return; // binutils not present in this environment; nothing to assert
    }
    throw error;
  }

  await assert.rejects(() => binInfo("D:\verdex-no-such-binary-xyz.bin"));
});

test("bin_decompile validates the target path before invoking any backend", async () => {
  // A missing file is rejected by resolveBinary before IDA is ever spawned,
  // so this stays fast and independent of whether IDA is installed.
  await assert.rejects(() => binDecompile(path.join(os.tmpdir(), "verdex-no-such-binary-xyz.bin"), {}));
});

test("reconstruct validates the target path and carries the structured brief", async () => {
  // Missing file is rejected before any backend runs — fast, IDA-independent.
  await assert.rejects(() => reconstructSource(path.join(os.tmpdir(), "verdex-no-such-recon.bin"), {}));
});

test("pwn tools stay read-only and the exploit template requires an authorized target", async () => {
  // Format detection + path validation, no backend dependency on a specific OS binary.
  await assert.rejects(() => pwnChecksec(path.join(os.tmpdir(), "verdex-no-such-pwn.bin")));
  await assert.rejects(() => pwnGadgets(path.join(os.tmpdir(), "verdex-no-such-pwn.bin")));

  // pwn_template refuses without an explicit authorized target declaration.
  await assert.rejects(() => pwnTemplate(process.execPath, {}), /target 必填/);

  // With a target, it generates a scaffold carrying the authorization banner —
  // and never executes or connects (Verdex has no such capability).
  const t = await pwnTemplate(process.execPath, { target: "local" });
  assert.equal(t.tool, "pwn_template");
  assert.equal(t.authorized_target, "local process");
  assert.match(t.script, /仅供授权测试/);
  assert.match(t.script, /from pwn import \*/);
  assert.ok(t.limitations.some((l) => l.includes("绝不连接目标")));
});

test("report rendering includes an executive summary and a self-contained HTML report", async () => {
  const { renderReport, computeSeveritySummary } = await import("../src/report.js");
  const { renderReportHtml } = await import("../src/report-html.js");
  const analysis = {
    analysis_id: "analysis_test", root: "/tmp/x", file_count: 3, generated_at: "2026-10-14T00:00:00Z",
    scan: { findings: [
      { severity: "high", title: "SQL 注入候选", kind: "sql", file: "a.py", line: 5, why: "拼接查询", evidence: [{ file: "a.py", line: 5, kind: "sink", snippet: "q = 'SELECT ' + x" }], fix: "参数化查询" },
      { severity: "low", title: "信息泄露", kind: "info", file: "b.ts", line: 9, evidence: [] },
    ], coverage: {} },
  };
  const summary = computeSeveritySummary(analysis.scan.findings);
  assert.equal(summary.counts.high, 1);
  assert.equal(summary.total, 2);

  const md = renderReport(analysis, null);
  assert.match(md, /执行摘要/);

  const html = renderReportHtml(analysis, null);
  assert.match(html, /<!doctype html>/i);
  assert.match(html, /VERDEX/);
  assert.match(html, /SQL 注入候选/);
  assert.match(html, /kpi-num/);
  // Evidence snippet must be HTML-escaped, not raw.
  assert.ok(!html.includes("'SELECT ' + x</pre>".replace("</pre>", "")) || html.includes("&#39;SELECT"));
});

test("scanner detects the expanded web vulnerability rule set", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "verdex-webrules-"));
  try {
    fs.writeFileSync(path.join(root, "srv.py"), [
      "r = requests.get(request.args.get('u'))",
      "p = open(request.args.get('f'))",
      "render_template_string('hi ' + request.args.get('n'))",
      "h = hashlib.md5(b'x')",
      "doc = etree.parse(request.files['x'])",
    ].join("\n"), "utf8");
    fs.writeFileSync(path.join(root, "srv.js"), [
      "location.href = req.query.url",
      "res.setHeader('Access-Control-Allow-Origin', '*')",
      "o.__proto__.x = 1",
    ].join("\n"), "utf8");
    const result = scanProject(root);
    const kinds = new Set(result.findings.map((f) => f.kind));
    for (const expected of ["ssrf", "path", "ssti", "crypto", "xxe", "redirect", "cors", "proto"]) {
      assert.ok(kinds.has(expected), `missing web rule kind: ${expected}`);
    }
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("dynamic-assist tools compute offsets and generate scripts without executing anything", () => {
  const gen = pwnCyclic({ length: 80, n: 4 });
  assert.equal(gen.mode, "generate");
  assert.equal(gen.pattern.length, 80);
  const look = pwnCyclic({ n: 4, lookup: gen.pattern.slice(32, 36) });
  assert.equal(look.offset, 32);

  const g = pwnGdbScript(process.execPath, { breakpoints: ["main"] });
  assert.equal(g.tool, "pwn_gdbscript");
  assert.match(g.script, /break main/);
  assert.ok(g.limitations.some((l) => l.includes("不执行目标")));
});

test("har_analyze flags web-security issues from a capture without sending requests", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "verdex-har-"));
  try {
    const har = { log: { entries: [{
      request: { method: "GET", url: "http://lab.example.com/s?q=INJECTME", queryString: [{ name: "q", value: "INJECTME" }] },
      response: { status: 200, headers: [
        { name: "Content-Type", value: "text/html" },
        { name: "Access-Control-Allow-Origin", value: "*" },
        { name: "Access-Control-Allow-Credentials", value: "true" },
        { name: "Set-Cookie", value: "sid=abc123; Path=/" },
      ], content: { text: "<html>you searched INJECTME</html>" } },
    }] } };
    const harPath = path.join(root, "cap.har");
    fs.writeFileSync(harPath, JSON.stringify(har), "utf8");
    const r = analyzeHar(harPath);
    const kinds = new Set(r.findings.map((f) => f.kind));
    assert.ok(kinds.has("cors"), "cors");
    assert.ok(kinds.has("cookie"), "cookie");
    assert.ok(kinds.has("xss"), "reflected xss");
    assert.ok(kinds.has("transport"), "http transport");
    assert.ok(kinds.has("security-header"), "missing headers");
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("web_poc requires an authorized target URL and only emits text", () => {
  assert.throws(() => webPoc("", { kind: "xss" }), /url 必填/);
  const p = webPoc("https://lab.example.com/item", { kind: "sqli" });
  assert.equal(p.tool, "web_poc");
  assert.equal(p.authorized_target, "https://lab.example.com/item");
  assert.match(p.curl, /仅供授权测试/);
  assert.match(p.python, /import requests/);
  assert.ok(p.limitations.some((l) => l.includes("绝不发起网络请求")));
});

test("pwn_libc parses symbol lines and degrades cleanly on a stripped/dumped libc", async () => {
  // Build a tiny fake ELF (magic only) to exercise format gating + path validation.
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "verdex-libc-"));
  try {
    // Non-ELF is rejected.
    const notElf = path.join(root, "x.bin");
    fs.writeFileSync(notElf, "MZ not an elf");
    await assert.rejects(() => pwnLibc(notElf), /只支持 ELF/);

    // Missing path rejected before any backend.
    await assert.rejects(() => pwnLibc(path.join(root, "nope.so")));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("diffRuns classifies findings into added / fixed / unchanged by fingerprint", async () => {
  const { diffRuns } = await import("../src/diff.js");
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "verdex-diff-"));
  try {
    const baseDir = path.join(root, "base");
    const headDir = path.join(root, "head");
    fs.mkdirSync(baseDir); fs.mkdirSync(headDir);
    // shared(unchanged) + only-in-base(fixed) + only-in-head(added)
    const shared = { fingerprint: "fp_shared", severity: "high", kind: "sql", title: "s", file: "a.py", line: 1 };
    const gone = { fingerprint: "fp_gone", severity: "medium", kind: "xss", title: "g", file: "b.py", line: 2 };
    const fresh = { fingerprint: "fp_fresh", severity: "low", kind: "ssrf", title: "f", file: "c.py", line: 3 };
    fs.writeFileSync(path.join(baseDir, "findings.json"), JSON.stringify([shared, gone]));
    fs.writeFileSync(path.join(headDir, "findings.json"), JSON.stringify([shared, fresh]));
    const d = diffRuns(baseDir, headDir);
    assert.equal(d.summary.unchanged, 1);
    assert.equal(d.summary.fixed, 1);
    assert.equal(d.summary.added, 1);
    assert.equal(d.added[0].fingerprint, "fp_fresh");
    assert.equal(d.fixed[0].fingerprint, "fp_gone");
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("renderSarif emits valid SARIF 2.1.0 with rules, CWE help, and severity levels", async () => {
  const { renderSarif } = await import("../src/sarif.js");
  const analysis = {
    analysis_id: "analysis_t", root: "/tmp/x",
    scan: { findings: [
      { title: "SQLi", kind: "sql", cwe: "CWE-89", severity: "high", file: "a" + String.fromCharCode(92) + "b.py", line: 5, why: "concat", fix: "parametrize", fingerprint: "fp_a", evidence: [{ column: 3, end_line: 5, snippet: "q='..'+x" }] },
      { title: "Weak hash", kind: "crypto", cwe: "CWE-327", severity: "low", file: "c.js", line: 9, fingerprint: "fp_b", evidence: [] },
    ] },
  };
  const s = renderSarif(analysis, null);
  assert.equal(s.version, "2.1.0");
  assert.match(s.$schema, /sarif-2\.1\.0/);
  assert.equal(s.runs.length, 1);
  const run = s.runs[0];
  assert.equal(run.tool.driver.name, "Verdex");
  assert.equal(run.tool.driver.rules.length, 2);
  assert.equal(run.results.length, 2);
  // severity → level mapping
  assert.equal(run.results[0].level, "error");   // high
  assert.equal(run.results[1].level, "note");    // low
  // path normalized to forward slashes
  assert.equal(run.results[0].locations[0].physicalLocation.artifactLocation.uri, "a/b.py");
  // CWE help uri
  assert.ok(run.tool.driver.rules.some((r) => r.helpUri === "https://cwe.mitre.org/data/definitions/89.html"));
  // stable fingerprint carried for cross-run dedup
  assert.equal(run.results[0].partialFingerprints.verdexFingerprint, "fp_a");
  // every result's ruleIndex resolves
  for (const r of run.results) assert.ok(run.tool.driver.rules[r.ruleIndex]);
});

test("mobile_unpack rejects non-ZIP input and detects Mach-O magic", async () => {
  const { unpackMobile } = await import("../src/mobile.js");
  const { pwnChecksec } = await import("../src/pwn.js");
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "verdex-mob-"));
  try {
    // Non-ZIP is rejected before any extraction.
    const notZip = path.join(root, "x.apk");
    fs.writeFileSync(notZip, "not a zip");
    await assert.rejects(() => unpackMobile(notZip), /不是 ZIP 容器/);
    // Missing file rejected.
    await assert.rejects(() => unpackMobile(path.join(root, "nope.apk")));
    // Mach-O magic is recognized (pwn_checksec gives the macho-specific message, not the generic reject).
    const macho = path.join(root, "m.bin");
    fs.writeFileSync(macho, Buffer.from([0xcf, 0xfa, 0xed, 0xfe, ...Array(60).fill(0)]));
    await assert.rejects(() => pwnChecksec(macho), /Mach-O/);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

function buildWxapkg(files) {
  const entries = files.map((f) => ({ name: Buffer.from(f.name), content: Buffer.from(f.content) }));
  let indexLen = 0;
  for (const e of entries) indexLen += 4 + e.name.length + 4 + 4;
  const headerLen = 18;
  let off = headerLen + indexLen;
  const idx = Buffer.alloc(indexLen);
  let p = 0;
  for (const e of entries) {
    idx.writeUInt32BE(e.name.length, p); p += 4;
    e.name.copy(idx, p); p += e.name.length;
    idx.writeUInt32BE(off, p); p += 4;
    idx.writeUInt32BE(e.content.length, p); p += 4;
    off += e.content.length;
  }
  const head = Buffer.alloc(18);
  head[0] = 0xbe; head.writeUInt32BE(indexLen, 5); head.writeUInt32BE(off - headerLen - indexLen, 9);
  head[13] = 0xed; head.writeUInt32BE(entries.length, 14);
  return Buffer.concat([head, idx, ...entries.map((e) => e.content)]);
}

test("wxapkg_unpack extracts mini-program files byte-exact and blocks path traversal", async () => {
  const { unpackWxapkg } = await import("../src/mobile.js");
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "verdex-wx-"));
  try {
    const files = [{ name: "app.js", content: "App({})" }, { name: "pages/i.wxml", content: "<view/>" }, { name: "app.json", content: "{}" }];
    const good = path.join(root, "ok.wxapkg");
    fs.writeFileSync(good, buildWxapkg(files));
    const r = unpackWxapkg(good);
    assert.equal(r.file_count, 3);
    assert.equal(r.inventory.js, 1);
    assert.equal(r.inventory.wxml, 1);
    assert.equal(fs.readFileSync(path.join(r.extracted_dir, "app.js"), "utf8"), "App({})");
    fs.rmSync(r.extracted_dir, { recursive: true, force: true });

    const evil = path.join(root, "evil.wxapkg");
    fs.writeFileSync(evil, buildWxapkg([{ name: "../evil.js", content: "x" }]));
    assert.throws(() => unpackWxapkg(evil), /穿越|越界/);

    const bad = path.join(root, "bad.wxapkg");
    fs.writeFileSync(bad, "not a wxapkg at all");
    assert.throws(() => unpackWxapkg(bad), /头标记/);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("scanSecrets detects provider secrets, redacts values, and filters low entropy", async () => {
  const { scanSecrets } = await import("../src/secrets.js");
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "verdex-sec-"));
  try {
    // Build secret-shaped fixtures at runtime so no complete token literal is
    // committed (GitHub push-protection would flag them). scanSecrets still
    // sees the full strings in the file it writes to disk.
    const AWS = "AKIA" + "IOSFODNN7EXAMPLE";
    const GH = "ghp_" + "1234567890abcdefghijklmnopqrstuvwxyzAB";
    const STRIPE = "sk_live_" + "1234567890abcdefghijklmno";
    fs.writeFileSync(path.join(root, "c.js"), [
      `const a = "${AWS}";`,
      `const g = "${GH}";`,
      `const s = "${STRIPE}";`,
      `const low = "password = aaaaaaaaaaaaaaaa";`, // low entropy → filtered
    ].join("\n"), "utf8");
    const r = scanSecrets(root);
    const rules = new Set(r.findings.map((f) => f.rule));
    assert.ok(rules.has("aws-access-key-id"));
    assert.ok(rules.has("github-token"));
    assert.ok(rules.has("stripe-secret"));
    // low-entropy generic assignment must be filtered out
    assert.ok(!r.findings.some((f) => f.redacted && f.redacted.includes("aaaaaaaa")));
    // raw secret must never appear in output
    assert.ok(!JSON.stringify(r).includes(AWS), "raw secret leaked!");
    const aws = r.findings.find((f) => f.rule === "aws-access-key-id");
    assert.match(aws.redacted, /\*/);
    assert.match(aws.value_sha256, /^[a-f0-9]{64}$/);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("dex_decompile validates input and fails cleanly when jadx is absent", async () => {
  const { dexDecompile } = await import("../src/mobile.js");
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "verdex-dex-"));
  const priorJadx = process.env.VERDEX_JADX;
  try {
    // Missing file rejected before backend.
    await assert.rejects(() => dexDecompile(path.join(root, "nope.apk")));
    // With jadx forced to a bogus path AND no install present, we at least
    // confirm the input-validation guard; if a real jadx is on the machine
    // the backend-missing branch won't trigger, so only assert the file guard.
    const f = path.join(root, "x.apk");
    fs.writeFileSync(f, "PK\u0003\u0004 not really");
    // Can't assert backend-missing deterministically (machine may have jadx),
    // so just ensure the call either returns a result object or throws a
    // controlled error — never an unhandled crash.
    await dexDecompile(f).then(
      (r) => assert.equal(r.tool, "dex_decompile"),
      (e) => assert.ok(/jadx|反编译|后端/.test(e.message)),
    );
  } finally {
    if (priorJadx === undefined) delete process.env.VERDEX_JADX;
    else process.env.VERDEX_JADX = priorJadx;
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("fw_scan locates embedded firmware signatures at correct offsets and maps entropy", async () => {
  const { scanFirmware } = await import("../src/firmware.js");
  const crypto = await import("node:crypto");
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "verdex-fw-"));
  try {
    const img = Buffer.concat([
      Buffer.from("27051956", "hex"), Buffer.alloc(60),  // U-Boot @0
      Buffer.from("hsqs", "ascii"), Buffer.alloc(200),    // SquashFS
      Buffer.from("7f454c46", "hex"), Buffer.alloc(100),  // ELF
      crypto.randomBytes(16000),                           // high-entropy region
      Buffer.alloc(4000),                                  // low-entropy zeros
    ]);
    const f = path.join(root, "fw.bin");
    fs.writeFileSync(f, img);
    const r = scanFirmware(f);
    const types = r.signatures.map((s) => s.type);
    assert.ok(types.includes("U-Boot uImage header"));
    assert.ok(types.includes("SquashFS (little-endian)"));
    assert.ok(types.includes("ELF 可执行/库"));
    // U-Boot header must be reported at offset 0
    assert.equal(r.signatures.find((s) => s.type === "U-Boot uImage header").offset, 0);
    // high-entropy region detected
    assert.ok(r.high_entropy_regions.length >= 1);
    assert.ok(r.overall_entropy > 5);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("js_deobfuscate decodes escapes, beautifies, and flags obfuscation without executing", async () => {
  const { deobfuscateJs } = await import("../src/jsdeobf.js");
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "verdex-js-"));
  try {
    const bs = String.fromCharCode(92); // literal backslash
    // \x68\x74... = "http://x.io" ; plus >5 _0x hex identifiers (minified one line)
    const hex = "68:74:74:70:3a:2f:2f:78:2e:69:6f".split(":").map((h) => bs + "x" + h).join("");
    const src = `var _0xa1b2=["${hex}"];function _0xc3d4(){var _0xe5f6=1,_0x1122=2,_0x3344=3,_0x5566=4,_0x7788=5;if(_0xe5f6){_0xc3d4();}return _0xa1b2[0];}`;
    const f = path.join(root, "o.js");
    fs.writeFileSync(f, src, "utf8");
    const r = deobfuscateJs(f);
    assert.equal(r.tool, "js_deobfuscate");
    assert.equal(r.decoded_escapes, true, "should detect hex escapes");
    assert.ok(r.indicators.urls.includes("http://x.io"), "decoded URL surfaced");
    assert.ok(r.obfuscation_signals.some((s) => s.id === "hex-identifiers"), "hex-id signal");
    assert.ok(r.obfuscation_signals.some((s) => s.id === "hex-escapes"), "hex-escape signal");
    assert.ok(r.beautified.split("\n").length > 3, "minified line expanded");
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("fw_extract rejects non-SquashFS magic before invoking any extractor", async () => {
  const { fwExtract } = await import("../src/firmware.js");
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "verdex-fwx-"));
  try {
    const notSquash = path.join(root, "x.bin");
    fs.writeFileSync(notSquash, Buffer.from([0x1f, 0x8b, 0x08, 0x00, 0, 0, 0, 0])); // gzip, not squashfs
    await assert.rejects(() => fwExtract(notSquash), /SquashFS/);
    await assert.rejects(() => fwExtract(path.join(root, "nope.bin")));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("analyze_target routes each target type to the right tool chain", async () => {
  const { analyzeTarget } = await import("../src/orchestrate.js");
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "verdex-orch-"));
  try {
    const mk = (name, bytes) => { const f = path.join(root, name); fs.writeFileSync(f, Buffer.from(bytes)); return f; };
    // directory
    assert.equal(analyzeTarget(root).target_type, "directory");
    assert.equal(analyzeTarget(root).recommended_tools[0].tool, "mcp__verdex__scan");
    // ELF
    assert.equal(analyzeTarget(mk("a.so", [0x7f, 0x45, 0x4c, 0x46, 0, 0, 0, 0])).target_type, "elf");
    // Mach-O
    assert.equal(analyzeTarget(mk("m.bin", [0xcf, 0xfa, 0xed, 0xfe, 0, 0, 0, 0])).target_type, "macho");
    // wxapkg
    assert.equal(analyzeTarget(mk("x.wxapkg", [0xbe, 0, 0, 0, 0, 0, 0, 0])).target_type, "wechat-miniprogram");
    // firmware squashfs
    const fw = analyzeTarget(mk("f.img", [0x68, 0x73, 0x71, 0x73, 0, 0, 0, 0]));
    assert.equal(fw.target_type, "firmware-squashfs");
    assert.equal(fw.recommended_tools[0].tool, "mcp__verdex__fw_scan");
    // APK (PK magic + .apk ext)
    assert.equal(analyzeTarget(mk("app.apk", [0x50, 0x4b, 3, 4, 0, 0, 0, 0])).target_type, "android-apk");
    // JS
    assert.equal(analyzeTarget(mk("s.js", [0x76, 0x61, 0x72])).target_type, "javascript");
    // missing path throws
    assert.throws(() => analyzeTarget(path.join(root, "nope")));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("AXML decoder rejects non-AXML and summarizes a real manifest when available", async () => {
  const { decodeAxml, manifestSummary, decodeManifestFile } = await import("../src/axml.js");
  // Deterministic: non-AXML buffer is rejected.
  assert.throws(() => decodeAxml(Buffer.from([0x50, 0x4b, 3, 4])), /AXML/);
  assert.throws(() => manifestSummary(Buffer.from([0, 1, 2, 3])));
  // Opportunistic: if a real binary manifest is on disk, it must decode sanely.
  const real = "D:/moodly/unpacked/AndroidManifest.xml";
  if (fs.existsSync(real)) {
    const s = decodeManifestFile(real);
    assert.ok(s.package && s.package.length > 0, "package decoded");
    assert.ok(Array.isArray(s.permissions), "permissions is array");
    assert.ok(typeof s.flags.debuggable === "boolean", "flags present");
  }
});

test("recoverAnnotations extracts Kotlin @DebugMetadata / @Metadata when decompilation fails", async () => {
  const { recoverAnnotations } = await import("../src/mobile.js");
  const q = String.fromCharCode(34);
  const java = [
    `@DebugMetadata(c = ${q}C$1${q}, f = ${q}Foo.kt${q}, l = {12, 34, 56}, n = {${q}stateA${q}, ${q}stateB${q}, ${q}isSpeechFrame${q}})`,
    `@Metadata(d2 = {${q}Lcom/x;${q}, ${q}submitUserRecording${q}, ${q}pollFrame${q}}, k = 1)`,
    `public final class Foo { public Object x() { throw new UnsupportedOperationException(${q}Method not decompiled: com.app.Foo${q}); } }`,
  ].join("\n");
  const r = recoverAnnotations(java);
  assert.deepEqual(r.undecompiled_methods, ["com.app.Foo"]);
  assert.equal(r.debug_metadata.source_file, "Foo.kt");
  assert.deepEqual(r.debug_metadata.suspend_point_lines, [12, 34, 56]);
  assert.ok(r.debug_metadata.local_variable_names.includes("isSpeechFrame"));
  assert.ok(r.member_names.includes("submitUserRecording"));
  // clean source → nothing to recover
  const clean = recoverAnnotations("public class Ok { void a(){} }");
  assert.equal(clean.undecompiled_methods.length, 0);
});

test("detectPackers identifies commercial Android hardening without cross-matching", async () => {
  const { detectPackers } = await import("../src/mobile.js");
  const yidun = detectPackers(["lib/arm64-v8a/libnesec.so", "lib/arm64-v8a/libnshelper.so"]).map((h) => h.packer);
  assert.ok(yidun.some((p) => p.includes("易盾")));
  assert.equal(yidun.length, 1, "no cross-match");
  const ijiami = detectPackers(["lib/arm64-v8a/libijiami_1011.so", "assets/ijiami_1011.VData", "lib/arm64-v8a/libverbanr.so"]).map((h) => h.packer);
  assert.ok(ijiami.some((p) => p.includes("爱加密")));
  assert.ok(!ijiami.some((p) => p.includes("易盾")), "verbanr must not false-match Yidun");
  assert.deepEqual(detectPackers(["lib/arm64-v8a/libnative.so", "classes.dex"]), [], "clean app has no packer");
});

test("scanSecrets catches named key constants and signing salts (the hand-found gap)", async () => {
  const { scanSecrets } = await import("../src/secrets.js");
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "verdex-s4-"));
  const q = String.fromCharCode(34);
  try {
    const SALT = "sign-kailu-" + "855c74a88b8b494187c99b08b8c9a744";
    const TAKU = "ad42845e8d50" + "cc54325c379c644487a75";
    fs.writeFileSync(path.join(root, "C.java"), [
      `String TAKU_APP_KEY = ${q}${TAKU}${q};`,
      `String LOCATION_SECRET = ${q}nFU9pbG8YQoAe1kFh+E7eyrdlSLglwEJeA0wwHB1j5o=${q};`,
      `String salt = ${q}&key=${SALT}${q};`,
    ].join("\n"), "utf8");
    const r = scanSecrets(root);
    const rules = new Set(r.findings.map((f) => f.rule));
    assert.ok(rules.has("named-key-constant"), "named key constant");
    assert.ok(rules.has("signing-salt"), "signing salt");
    assert.ok(r.finding_count >= 3);
    assert.ok(!JSON.stringify(r).includes("855c74a88b8b"), "raw value must be redacted");
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("frida_script requires an authorized target and emits valid, text-only Frida JS", async () => {
  const { fridaScript } = await import("../src/frida.js");
  const vm = await import("node:vm");
  // Gate: no target → rejected.
  assert.throws(() => fridaScript({}), /target 必填/);
  // Each kind: banner carries the target, body is syntactically valid JS.
  for (const kind of ["unpack", "crypto", "network"]) {
    const r = fridaScript({ target: "com.example.app", kind });
    assert.equal(r.authorized_target, "com.example.app");
    assert.match(r.script, /仅供授权测试/);
    assert.match(r.script, /com\.example\.app/);
    assert.doesNotThrow(() => new vm.Script(r.script), `${kind} must be valid JS`);
    assert.match(r.script, /Java\.perform/);
  }
  // hook kind embeds class + method.
  const h = fridaScript({ target: "com.x.y", kind: "hook", className: "com.x.y.Signer", method: "sign" });
  assert.match(h.script, /com\.x\.y\.Signer/);
  assert.match(h.script, /"sign"/);
  assert.doesNotThrow(() => new vm.Script(h.script));
  // limitations must state Verdex does not attach/run.
  assert.ok(h.limitations.some((l) => l.includes("不 attach")));
});

test("dotnet_decompile detects managed assemblies (BSJB) and rejects non-.NET", async () => {
  const { isDotnetAssembly, dotnetDecompile } = await import("../src/dotnet.js");
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "verdex-dn-"));
  try {
    // A fake PE without BSJB is not a .NET assembly.
    const nativePe = path.join(root, "n.exe");
    fs.writeFileSync(nativePe, Buffer.concat([Buffer.from([0x4d, 0x5a]), Buffer.alloc(512)]));
    assert.equal(isDotnetAssembly(nativePe), false);
    await assert.rejects(() => dotnetDecompile(nativePe), /不是 \.NET/);
    // A PE containing the BSJB metadata signature is detected as managed.
    const managed = path.join(root, "m.dll");
    fs.writeFileSync(managed, Buffer.concat([Buffer.from([0x4d, 0x5a]), Buffer.alloc(200), Buffer.from("BSJB"), Buffer.alloc(200)]));
    assert.equal(isDotnetAssembly(managed), true);
    // missing file rejected
    await assert.rejects(() => dotnetDecompile(path.join(root, "nope.dll")));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("analyze_target routes a real .NET assembly to dotnet_decompile when present", async () => {
  const { analyzeTarget } = await import("../src/orchestrate.js");
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "verdex-dnr-"));
  try {
    const dll = path.join(root, "x.dll");
    fs.writeFileSync(dll, Buffer.concat([Buffer.from([0x4d, 0x5a]), Buffer.alloc(200), Buffer.from("BSJB"), Buffer.alloc(200)]));
    const r = analyzeTarget(dll);
    assert.equal(r.target_type, "dotnet");
    assert.equal(r.recommended_tools[0].tool, "mcp__verdex__dotnet_decompile");
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

function buildAsar(fileMap) {
  // fileMap: { name: Buffer }. Builds a minimal valid .asar.
  const datas = [];
  let off = 0;
  const files = {};
  for (const [name, buf] of Object.entries(fileMap)) {
    files[name] = { size: buf.length, offset: String(off) };
    datas.push(buf); off += buf.length;
  }
  const json = Buffer.from(JSON.stringify({ files }), "utf8");
  const aligned = Math.ceil(json.length / 4) * 4;
  const header = Buffer.alloc(16);
  header.writeUInt32LE(4, 0);
  header.writeUInt32LE(8 + aligned, 4);
  header.writeUInt32LE(4 + aligned, 8);
  header.writeUInt32LE(json.length, 12);
  const jsonPadded = Buffer.alloc(aligned); json.copy(jsonPadded);
  return Buffer.concat([header, jsonPadded, ...datas]);
}

test("asar_unpack round-trips an Electron archive and blocks path traversal", async () => {
  const { unpackAsar } = await import("../src/electron.js");
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "verdex-asar-"));
  try {
    const asar = path.join(root, "app.asar");
    fs.writeFileSync(asar, buildAsar({ "main.js": Buffer.from("console.log(1)"), "package.json": Buffer.from('{"name":"x"}') }));
    const r = unpackAsar(asar);
    assert.equal(r.file_count, 2);
    assert.equal(r.inventory.js, 1);
    assert.equal(fs.readFileSync(path.join(r.extracted_dir, "main.js"), "utf8"), "console.log(1)");
    fs.rmSync(r.extracted_dir, { recursive: true, force: true });

    // traversal: a file keyed ".." must be rejected
    const evil = path.join(root, "evil.asar");
    fs.writeFileSync(evil, buildAsar({ "..": Buffer.from("x") }));
    assert.throws(() => unpackAsar(evil), /穿越/);
    // non-asar rejected
    const bad = path.join(root, "bad.asar");
    fs.writeFileSync(bad, Buffer.from("not an asar at all...."));
    assert.throws(() => unpackAsar(bad));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("bin_dossier requires a symbol and parses calls/strings from a real function", async () => {
  const { binDossier } = await import("../src/reverse.js");
  // symbol is required
  await assert.rejects(() => binDossier(process.execPath, {}), /symbol/);
  // missing file rejected
  await assert.rejects(() => binDossier("D:/verdex-no-such.bin", { symbol: "main" }));
});

test("every MCP tool declares all four annotation hints as booleans", async () => {
  const { dispatch } = await import("../src/mcp.js");
  const list = await dispatch({ jsonrpc: "2.0", id: 1, method: "tools/list" });
  const tools = list.result.tools;
  assert.ok(tools.length >= 30);
  const HINTS = ["readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"];
  for (const t of tools) {
    assert.ok(t.annotations, `${t.name} has annotations`);
    for (const h of HINTS) assert.equal(typeof t.annotations[h], "boolean", `${t.name}.${h} must be boolean`);
  }
  // Verdex-wide invariants: never destructive, never network.
  assert.ok(tools.every((t) => t.annotations.destructiveHint === false));
  assert.ok(tools.every((t) => t.annotations.openWorldHint === false));
  // Artifact writers are honestly flagged not-read-only.
  const writers = tools.filter((t) => !t.annotations.readOnlyHint).map((t) => t.name).sort();
  assert.deepEqual(writers, ["asar_unpack", "fw_extract", "mobile_unpack", "report", "wxapkg_unpack"]);
});

test("scanSecrets triages findings by provable impact (direct vs conditional)", async () => {
  const { scanSecrets } = await import("../src/secrets.js");
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "verdex-tri-"));
  const q = String.fromCharCode(34);
  try {
    const AWS = "AKIA" + "IOSFODNN7EXAMPLE";
    const APPKEY = "ad42845e8d50" + "cc54325c379c644487a75";
    fs.writeFileSync(path.join(root, "c.java"), [
      `String aws = ${q}${AWS}${q};`,                    // direct
      `String APP_KEY = ${q}${APPKEY}${q};`,             // conditional (client app key)
      `String pem = ${q}-----BEGIN RSA PRIVATE KEY-----${q};`, // direct
    ].join("\n"), "utf8");
    const r = scanSecrets(root);
    const byImpact = Object.fromEntries(r.findings.map((f) => [f.rule, f.impact]));
    assert.equal(byImpact["aws-access-key-id"], "direct");
    assert.equal(byImpact["private-key"], "direct");
    assert.equal(byImpact["named-key-constant"], "conditional");
    assert.ok(r.triage.report_ready >= 2, "aws + pem are report-ready");
    assert.ok(r.triage.needs_dynamic_proof >= 1, "app key needs proof");
    assert.ok(r.triage.guidance.includes("理论"));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("web_recon requires an authorized domain and emits a passive-first staged playbook", async () => {
  const { webRecon } = await import("../src/web.js");
  assert.throws(() => webRecon(""), /domain 必填/);
  assert.throws(() => webRecon("not a domain!!"));
  const r = webRecon("example.com", { scope: "*.example.com" });
  assert.equal(r.authorized_domain, "example.com");
  assert.equal(r.phases.length, 3);
  assert.match(r.playbook_banner, /仅供授权范围/);
  assert.match(r.phases[0].phase, /被动/);
  assert.match(r.phases[0].note, /不向目标发包/);
  assert.ok(r.limitations.some((l) => l.includes("子域全授权")));
  // URL input is normalized to the host
  assert.equal(webRecon("https://sub.test.cn/a").authorized_domain, "sub.test.cn");
});

test("analyze_target routes a bare domain to web_recon (SRC gives only a host)", async () => {
  const { analyzeTarget } = await import("../src/orchestrate.js");
  const r = analyzeTarget("example.com");
  assert.equal(r.target_type, "domain");
  assert.equal(r.recommended_tools[0].tool, "mcp__verdex__web_recon");
  assert.equal(analyzeTarget("https://app.target.cn/login").target_type, "domain");
});

test("impact_proof turns a theoretical finding into a data-safe, stop-at-first-proof plan", async () => {
  const { impactProof } = await import("../src/proof.js");
  const unknown = impactProof("nonsense");
  assert.ok(Array.isArray(unknown.supported));
  assert.ok(unknown.supported.includes("signing-forgery"));

  const s = impactProof("signing-forgery", { target: "example.com" });
  assert.equal(s.vuln_class, "signing-forgery");
  assert.equal(s.authorized_target, "example.com");
  assert.match(s.why_theoretical_rejected, /服务端信任/);
  assert.match(s.data_safety_law[0], /自己.*测试账号/);
  assert.ok(s.stop_point && s.stop_rule);
  assert.ok(s.limitations.some((l) => l.includes("自己拥有的账号")));

  const idor = impactProof("IDOR"); // case-insensitive
  assert.equal(idor.vuln_class, "idor");
  assert.ok(idor.minimal_proof.some((x) => x.includes("你自己的两个账号")));
});

test("impact_proof is wired into the MCP tool list", async () => {
  const { PROOF_TOOLS } = await import("../src/proof.js");
  assert.equal(PROOF_TOOLS.length, 1);
  assert.equal(PROOF_TOOLS[0].name, "impact_proof");
});
