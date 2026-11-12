import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { EXPLAIN_RULES, explain, plainExplanation, resolveRule } from "../src/explain.js";
import { dispatch } from "../src/mcp.js";
import { renderReport } from "../src/report.js";
import { renderReportHtml } from "../src/report-html.js";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const execFileAsync = promisify(execFile);

const SCANNER_KINDS = ["secret", "sql", "cmd", "eval", "deser", "xss", "ssrf", "path", "ssti", "redirect", "cors", "crypto", "xxe", "proto"];
const SECRET_RULES = [
  "aws-access-key-id",
  "aws-secret-access-key",
  "github-token",
  "github-fine-grained",
  "google-api-key",
  "slack-token",
  "stripe-secret",
  "stripe-restricted",
  "private-key",
  "jwt",
  "slack-webhook",
  "generic-assignment",
  "named-key-constant",
  "signing-salt",
];

test("every explain rule is complete and bilingual", () => {
  assert.ok(EXPLAIN_RULES.length >= 28, "v1 catalog covers scanner kinds, secrets and access control");
  const ids = new Set();
  const aliases = new Map();
  for (const rule of EXPLAIN_RULES) {
    assert.ok(rule.id && !ids.has(rule.id), `duplicate rule id ${rule.id}`);
    ids.add(rule.id);
    assert.match(rule.cwe, /^CWE-\d+$/, `${rule.id} has a CWE`);
    assert.ok(rule.title.zh && rule.title.en, `${rule.id} bilingual title`);
    for (const lang of ["zh", "en"]) {
      for (const field of ["what", "why", "fix"]) {
        assert.ok(typeof rule.plain[lang][field] === "string" && rule.plain[lang][field].length > 8, `${rule.id}.${lang}.${field}`);
      }
      assert.ok(rule.verify[lang].length >= 1, `${rule.id}.${lang} has verification signals`);
    }
    assert.ok(rule.references.length >= 1, `${rule.id} has a reference`);
    assert.ok(["critical", "high", "medium", "low", "info"].includes(rule.severity), `${rule.id} severity`);
    for (const alias of rule.aliases) {
      const key = alias.toLowerCase();
      assert.ok(!aliases.has(key), `alias ${alias} collides with ${aliases.get(key)}`);
      aliases.set(key, rule.id);
    }
  }
});

test("catalog covers every scanner kind and secrets rule", () => {
  for (const kind of SCANNER_KINDS) {
    const rule = resolveRule(kind);
    assert.ok(rule && rule.id === kind, `scanner kind ${kind} has an explanation`);
  }
  for (const secret of SECRET_RULES) {
    const rule = resolveRule(secret);
    assert.ok(rule && rule.id === secret, `secrets rule ${secret} has an explanation`);
  }
  for (const cls of ["idor", "auth-bypass", "signing-forgery", "hardcoded-cred", "sqli", "open-redirect"]) {
    assert.ok(resolveRule(cls), `impact_proof class ${cls} resolves`);
  }
});

test("explain resolves ids, aliases and CWEs to the same rule", () => {
  const sql = explain("sql");
  assert.equal(sql.matched, true);
  assert.equal(sql.rule_id, "sql");
  assert.equal(sql.technical.cwe, "CWE-89");
  assert.ok(sql.plain.what.length > 0 && sql.plain.why.length > 0 && sql.plain.fix.length > 0);
  assert.equal(explain("CWE-89").rule_id, "sql");
  assert.equal(explain("cwe 89").rule_id, "sql");
  assert.equal(explain("SQLi").rule_id, "sql");
  assert.equal(explain("signing-forgery").rule_id, "signing-salt");
  assert.equal(explain("hardcoded-cred").rule_id, "secret");
  assert.equal(explain("open-redirect").rule_id, "redirect");
  assert.equal(explain("aws-access-key-id").rule_id, "aws-access-key-id");
});

test("explain returns the requested language and the translation", () => {
  const zh = explain("sql", { lang: "zh" });
  assert.match(zh.plain.what, /SQL/);
  assert.ok(zh.translations.en.plain.what.length > 0);
  const en = explain("sql", { lang: "en" });
  assert.equal(en.lang, "en");
  assert.match(en.plain.what, /SQL/);
  assert.ok(en.translations.zh.plain.what.length > 0);
});

test("unknown rules return a hint and the supported list instead of throwing", () => {
  const result = explain("definitely-not-a-rule");
  assert.equal(result.matched, false);
  assert.equal(result.rule_id, "generic-candidate");
  assert.ok(result.supported.includes("sql"));
  assert.ok(result.supported.includes("aws-access-key-id"));
  assert.ok(result.hint.length > 0);
  assert.ok(result.plain.what.length > 0);
});

test("plainExplanation works for findings, rule ids and unknown input", () => {
  const byFinding = plainExplanation({ title: "x", kind: "ssrf", cwe: "CWE-918", file: "a.py", line: 1 });
  assert.equal(byFinding.rule_id, "ssrf");
  assert.ok(byFinding.what.length > 0);
  // A specific secrets rule id wins over the broad kind.
  const byRule = plainExplanation({ kind: "secret", rule: "aws-access-key-id" });
  assert.equal(byRule.rule_id, "aws-access-key-id");
  // CWE-only findings still resolve.
  assert.equal(plainExplanation({ cwe: "CWE-79" }).rule_id, "xss");
  const unknown = plainExplanation({ kind: "mystery" });
  assert.equal(unknown.matched, false);
  assert.ok(unknown.fix.length > 0);
});

test("markdown report adds a plain-language section for high-severity findings", () => {
  const analysis = {
    analysis_id: "analysis_test",
    root: "/tmp/x",
    file_count: 1,
    generated_at: "2026-11-12T00:00:00Z",
    scan: {
      findings: [
        { severity: "high", title: "SQL 注入候选", kind: "sql", cwe: "CWE-89", file: "a.py", line: 5, why: "拼接查询", fix: "参数化", evidence: [] },
        { severity: "low", title: "信息泄露", kind: "info", file: "b.ts", line: 9, evidence: [] },
      ],
      coverage: {},
    },
  };
  const md = renderReport(analysis, null);
  assert.match(md, /## 给非技术读者/);
  assert.match(md, /这是什么/);
  assert.match(md, /为什么.*要/);
  assert.match(md, /参数化查询/); // from the sql fix text
  assert.doesNotMatch(md, /#### 1\. 信息泄露/); // only high/critical get plain cards

  const html = renderReportHtml(analysis, null);
  assert.match(html, /给非技术读者/);
  assert.match(html, /plain-card/);
  assert.match(html, /参数化查询/);
});

test("reports without findings skip the plain-language section", () => {
  const analysis = { analysis_id: "a", root: "/tmp", file_count: 0, scan: { findings: [], coverage: {} } };
  assert.doesNotMatch(renderReport(analysis, null), /给非技术读者/);
  assert.doesNotMatch(renderReportHtml(analysis, null), /给非技术读者/);
});

test("MCP exposes explain as a read-only tool and dispatches it", async () => {
  const list = await dispatch({ jsonrpc: "2.0", id: 1, method: "tools/list" });
  const tool = list.result.tools.find((entry) => entry.name === "explain");
  assert.ok(tool, "explain is advertised");
  assert.equal(tool.annotations.readOnlyHint, true);
  assert.equal(tool.annotations.openWorldHint, false);
  assert.equal(tool.annotations.destructiveHint, false);
  assert.match(tool.description, /plain language/i);
  assert.match(tool.description, /\| 中文:/);

  const call = await dispatch({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "explain", arguments: { rule_id: "sqli", lang: "en" } } });
  assert.ok(!call.result.isError);
  const payload = JSON.parse(call.result.content[0].text);
  assert.equal(payload.schema, "VerdexExplain/v1");
  assert.equal(payload.rule_id, "sql");
  assert.equal(payload.lang, "en");
});

test("CLI explain prints a human-readable triad", async () => {
  const { stdout } = await execFileAsync(process.execPath, [path.join(ROOT, "src/cli.js"), "explain", "sql"], { cwd: ROOT });
  assert.match(stdout, /这是什么/);
  assert.match(stdout, /CWE-89/);
  const { stdout: json } = await execFileAsync(process.execPath, [path.join(ROOT, "src/cli.js"), "explain", "aws-access-key-id", "--json"], { cwd: ROOT });
  assert.equal(JSON.parse(json).rule_id, "aws-access-key-id");
  assert.ok(fs.existsSync(path.join(ROOT, "src/explain.js")));
});
