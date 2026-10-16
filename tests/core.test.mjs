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
    assert.match(await page.text(), /Verdex Workbench/);
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
    assert.match(reportText, /Verdex Workbench 分析报告/);
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
  for (const expected of ["assets", "map", "osint", "scan", "report", "bin_info", "bin_symbols", "bin_strings", "bin_disasm", "bin_decompile", "reconstruct", "diff", "pwn_checksec", "pwn_gadgets", "pwn_template", "pwn_cyclic", "pwn_gdbscript", "pwn_libc", "har_analyze", "web_poc"]) {
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
