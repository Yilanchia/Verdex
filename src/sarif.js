// Exports analysis findings as SARIF 2.1.0 so they can flow into GitHub code
// scanning, PR annotations, and the VS Code SARIF viewer. Pure JSON transform.

function sarifLevel(severity) {
  const s = String(severity || "info").toLowerCase();
  if (s === "critical" || s === "high") return "error";
  if (s === "medium") return "warning";
  return "note"; // low / info / unknown
}

function toUri(p) {
  return String(p || "").replace(/\\/g, "/").replace(/^\.\//, "");
}

function cweHelpUri(cwe) {
  const m = String(cwe || "").match(/CWE-(\d+)/i);
  return m ? `https://cwe.mitre.org/data/definitions/${m[1]}.html` : undefined;
}

export function renderSarif(analysis, brief = null) {
  const findings = analysis?.scan?.findings || [];

  // One rule per distinct (kind). SARIF requires each result's ruleId to resolve.
  const ruleIndex = new Map();
  const rules = [];
  for (const f of findings) {
    const id = `verdex/${f.kind || "finding"}`;
    if (ruleIndex.has(id)) continue;
    ruleIndex.set(id, rules.length);
    const help = cweHelpUri(f.cwe);
    rules.push({
      id,
      name: f.kind || "finding",
      shortDescription: { text: f.title || f.kind || "Verdex finding" },
      ...(f.cwe ? { properties: { cwe: f.cwe, tags: [f.cwe] } } : {}),
      ...(help ? { helpUri: help } : {}),
      defaultConfiguration: { level: sarifLevel(f.severity) },
    });
  }

  const results = findings.map((f) => {
    const id = `verdex/${f.kind || "finding"}`;
    const line = Math.max(1, Number(f.line) || 1);
    const region = { startLine: line };
    const ev = f.evidence?.[0];
    if (ev?.column) region.startColumn = Math.max(1, Number(ev.column));
    if (ev?.end_line) region.endLine = Math.max(line, Number(ev.end_line));
    if (ev?.snippet) region.snippet = { text: String(ev.snippet).slice(0, 2000) };
    return {
      ruleId: id,
      ruleIndex: ruleIndex.get(id),
      level: sarifLevel(f.severity),
      message: { text: `${f.title || f.kind || "候选"}${f.why ? " — " + f.why : ""}` },
      locations: [{
        physicalLocation: {
          artifactLocation: { uri: toUri(f.file) },
          region,
        },
      }],
      ...(f.fingerprint ? { partialFingerprints: { verdexFingerprint: f.fingerprint } } : {}),
      properties: {
        kind: f.kind,
        confidence: f.confidence,
        epistemic: "inferred",
        security_severity: String(f.severity || "info"),
        ...(f.fix ? { remediation: f.fix } : {}),
      },
    };
  });

  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [{
      tool: {
        driver: {
          name: "Verdex",
          informationUri: "https://github.com/Yilanchia/Verdex",
          version: "0.1.0",
          rules,
        },
      },
      ...(analysis?.root ? { originalUriBaseIds: { SRCROOT: { uri: toUri(analysis.root) } } } : {}),
      results,
      properties: {
        analysis_id: analysis?.analysis_id,
        note: "所有 result 为待人工复核的静态推断(epistemic: inferred),非已验证漏洞。",
        ...(brief ? { brief_scope: brief.scope?.include } : {}),
      },
    }],
  };
}
