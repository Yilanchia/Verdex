const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const SEVERITY_LEVELS = ["critical", "high", "medium", "low", "info"];
const SEVERITY_LABELS = { critical: "严重", high: "高", medium: "中", low: "低", info: "信息" };

export function computeSeveritySummary(findings = []) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const finding of findings) {
    const key = String(finding?.severity || "info").toLowerCase();
    counts[key] = (counts[key] ?? 0) + 1;
  }
  return { counts, total: findings.length, levels: SEVERITY_LEVELS, labels: SEVERITY_LABELS };
}

export function renderReport(analysis, brief = null) {
  const findings = [...(analysis.scan?.findings || [])].sort((left, right) => (SEVERITY_ORDER[left.severity] ?? 9) - (SEVERITY_ORDER[right.severity] ?? 9));
  const lines = [
    "# Verdex Workbench 分析报告",
    "",
    `- 分析 ID：${analysis.analysis_id || "unknown"}`,
    `- 工作目录：${analysis.root || "unknown"}`,
    `- 文件数：${analysis.file_count ?? "unknown"}`,
    `- 候选数：${findings.length}`,
    `- 生成时间：${analysis.generated_at || "unknown"}`,
    "",
    "## 执行摘要",
    "",
    "| 严重 | 高 | 中 | 低 | 信息 | 合计 |",
    "| --- | --- | --- | --- | --- | --- |",
    (() => {
      const s = computeSeveritySummary(findings);
      return `| ${s.counts.critical} | ${s.counts.high} | ${s.counts.medium} | ${s.counts.low} | ${s.counts.info} | ${s.total} |`;
    })(),
    "",
    "所有候选均为待人工复核的静态推断，非已验证漏洞；严重度为初步评级，需结合运行时上下文确认。",
    "",
    "## 证据边界",
    "",
    "本报告只整理作业夹中的本地文件证据。静态关系和数据流属于 inferred，不能单独证明运行时可达、权限缺失或漏洞可利用。",
    "",
  ];
  if (brief) {
    lines.push("## 范围", "", `- include：${brief.scope.include.join(", ")}`, `- exclude：${brief.scope.exclude.join(", ") || "（无）"}`, `- 红线：${brief.redlines.join(", ")}`, "");
  }
  lines.push("## 覆盖", "", `- 工作区：${analysis.scan?.coverage?.workspace?.status || "unknown"}`, `- 规则命中：${analysis.scan?.coverage?.rule_hits ?? 0}`, `- 数据流候选：${analysis.scan?.coverage?.dataflow_hits ?? 0}`, "");
  if (analysis.osint) {
    lines.push(
      "## 本地 OSINT 观察",
      "",
      `- 隐私模式：${analysis.osint.privacy?.mode || "redacted"}`,
      `- 观察数量：${analysis.osint.coverage?.observations ?? 0}`,
      `- 分类统计：${formatCategoryCounts(analysis.osint.coverage?.by_category)}`,
      "",
      "结果只来自作业夹已有文件；报告展示脱敏值，不代表身份归属或当前有效性。",
      "",
    );
    for (const observation of analysis.osint.observations || []) {
      lines.push(`- ${observation.category}：${observation.display_value} · ${observation.evidence?.[0]?.file}:${observation.evidence?.[0]?.line}`);
    }
    if (analysis.osint.observations?.length) lines.push("");
  }
  if (analysis.scan?.graph?.limitations?.length) lines.push("### 已知限制", "", ...analysis.scan.graph.limitations.map((item) => `- ${item}`), "");
  lines.push("## 待人工复核候选", "");
  if (!findings.length) lines.push("本轮没有产出候选。", "");
  for (const [index, finding] of findings.entries()) {
    const review = analysis.review?.[finding.fingerprint];
    lines.push(
      `### ${index + 1}. [${String(finding.severity || "info").toUpperCase()}] ${finding.title}`,
      "",
      `- 类型：${finding.kind || "unknown"}`,
      `- CWE：${finding.cwe || "待定"}`,
      `- 置信度：${finding.confidence || "unknown"}`,
      `- 位置：\`${finding.file}:${finding.line}\``,
      `- 来源：${(finding.sources || [finding.source || "unknown"]).join(", ")}`,
      ...(review ? [`- 复核状态：${reviewStatusLabel(review.status)}`, ...(review.note ? [`- 复核备注：${review.note}`] : [])] : []),
      "",
      finding.why || "需要人工核对。",
      "",
      "#### 证据",
      "",
    );
    for (const evidence of finding.evidence || []) {
      lines.push(`- ${evidence.file}:${evidence.line} · ${evidence.kind} · ${evidence.id}`, "  ```", `  ${evidence.snippet}`, "  ```");
    }
    lines.push("", "#### 修复方向", "", finding.fix || "结合实际数据流和权限边界修复。", "");
  }
  return lines.join("\n");
}

function reviewStatusLabel(value) {
  return {
    "needs-review": "待复核",
    confirmed: "确认候选",
    "false-positive": "误报",
    "accepted-risk": "可接受风险",
  }[value] || "待复核";
}

function formatCategoryCounts(counts = {}) {
  const entries = Object.entries(counts);
  return entries.length ? entries.map(([key, value]) => `${key}=${value}`).join(", ") : "（无）";
}
