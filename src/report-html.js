import { computeSeveritySummary } from "./report.js";

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const SEV_COLOR = { critical: "#ff727e", high: "#f3b860", medium: "#53d9ee", low: "#9b8cff", info: "#8996aa" };

function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

// Self-contained HTML report — inline CSS, no external assets, matches the
// workbench dark theme. Safe to open from a file:// URL or hand to anyone.
export function renderReportHtml(analysis, brief = null) {
  const findings = [...(analysis.scan?.findings || [])].sort(
    (a, b) => (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9),
  );
  const summary = computeSeveritySummary(findings);
  const kpis = summary.levels.map((level) => `
      <div class="kpi" style="--sev:${SEV_COLOR[level]}">
        <div class="kpi-num">${summary.counts[level]}</div>
        <div class="kpi-label">${esc(summary.labels[level])}</div>
      </div>`).join("");

  const findingCards = findings.length
    ? findings.map((f, i) => renderFinding(f, i)).join("")
    : `<div class="empty">本轮没有产出候选。</div>`;

  return `<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Verdex 分析报告</title>
<style>${STYLE}</style></head>
<body>
<header class="hero">
  <div class="brand"><span class="mark">V</span><span class="name">VERDEX</span></div>
  <div class="hero-sub">证据优先 · 本地分析报告</div>
</header>
<main>
  <section class="meta">
    <div><span>分析 ID</span><code>${esc(analysis.analysis_id || "unknown")}</code></div>
    <div><span>工作目录</span><code>${esc(analysis.root || "unknown")}</code></div>
    <div><span>文件数</span><code>${esc(analysis.file_count ?? "?")}</code></div>
    <div><span>生成时间</span><code>${esc(analysis.generated_at || "unknown")}</code></div>
  </section>
  <section class="kpis">${kpis}
    <div class="kpi total"><div class="kpi-num">${summary.total}</div><div class="kpi-label">候选合计</div></div>
  </section>
  <p class="disclaimer">所有候选均为待人工复核的静态推断，非已验证漏洞；严重度为初步评级，需结合运行时上下文确认。本报告只读取本地文件证据，不发起网络请求。</p>
  <h2>待复核候选</h2>
  ${findingCards}
</main>
<footer>Verdex Workbench · evidence-first local analysis</footer>
</body></html>`;
}

function renderFinding(f, index) {
  const sev = String(f.severity || "info").toLowerCase();
  const evidence = (f.evidence || []).map((e) => `
      <div class="ev">
        <div class="ev-loc">${esc(e.file)}:${esc(e.line)} · ${esc(e.kind || "")}</div>
        <pre>${esc(e.snippet || "")}</pre>
      </div>`).join("");
  return `
  <article class="finding" style="--sev:${SEV_COLOR[sev]}">
    <div class="f-head">
      <span class="sev-tag">${esc((f.severity || "info").toUpperCase())}</span>
      <span class="f-title">${index + 1}. ${esc(f.title || "候选")}</span>
    </div>
    <div class="f-meta">
      <span>类型 ${esc(f.kind || "unknown")}</span>
      <span>CWE ${esc(f.cwe || "待定")}</span>
      <span>置信度 ${esc(f.confidence || "unknown")}</span>
      <span class="loc">${esc(f.file)}:${esc(f.line)}</span>
    </div>
    <p class="f-why">${esc(f.why || "需要人工核对。")}</p>
    ${evidence ? `<div class="ev-wrap">${evidence}</div>` : ""}
    <div class="f-fix"><strong>修复方向：</strong>${esc(f.fix || "结合实际数据流和权限边界修复。")}</div>
  </article>`;
}

const STYLE = `
:root{--bg:#080b12;--panel:#111722;--line:rgba(137,157,188,.17);--text:#ecf2fb;--muted:#8996aa;--cyan:#53d9ee}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.6 -apple-system,"Segoe UI",system-ui,sans-serif}
.hero{padding:28px 32px;border-bottom:1px solid var(--line);display:flex;align-items:center;gap:16px}
.brand{display:flex;align-items:center;gap:10px}
.mark{display:grid;place-items:center;width:32px;height:32px;border-radius:9px;background:linear-gradient(135deg,var(--cyan),#9b8cff);color:#06121a;font-weight:800}
.name{font-weight:700;letter-spacing:.14em}
.hero-sub{color:var(--muted);font-size:12px}
main{max-width:980px;margin:0 auto;padding:28px 32px}
.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;margin-bottom:24px}
.meta>div{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:12px 14px}
.meta span{display:block;color:var(--muted);font-size:11px;margin-bottom:4px}
.meta code{color:var(--text);font-size:12px;word-break:break-all}
.kpis{display:grid;grid-template-columns:repeat(6,1fr);gap:12px;margin-bottom:18px}
.kpi{background:var(--panel);border:1px solid var(--line);border-top:3px solid var(--sev,var(--muted));border-radius:10px;padding:16px 12px;text-align:center}
.kpi-num{font-size:26px;font-weight:800;color:var(--sev,var(--text))}
.kpi.total .kpi-num{color:var(--text)}
.kpi-label{color:var(--muted);font-size:12px;margin-top:4px}
.disclaimer{color:var(--muted);font-size:12px;background:rgba(83,217,238,.05);border:1px solid var(--line);border-radius:8px;padding:10px 12px}
h2{margin:28px 0 14px;font-size:16px}
.finding{background:var(--panel);border:1px solid var(--line);border-left:3px solid var(--sev,var(--muted));border-radius:10px;padding:16px 18px;margin-bottom:14px}
.f-head{display:flex;align-items:center;gap:10px;margin-bottom:8px}
.sev-tag{background:var(--sev);color:#06121a;font-weight:700;font-size:11px;padding:2px 8px;border-radius:6px}
.f-title{font-weight:600}
.f-meta{display:flex;flex-wrap:wrap;gap:14px;color:var(--muted);font-size:12px;margin-bottom:10px}
.f-meta .loc{color:var(--cyan);font-family:ui-monospace,monospace}
.f-why{margin:0 0 12px}
.ev-wrap{display:flex;flex-direction:column;gap:8px;margin-bottom:12px}
.ev-loc{color:var(--muted);font-size:11px;font-family:ui-monospace,monospace;margin-bottom:3px}
.ev pre{margin:0;background:rgba(4,7,12,.6);border:1px solid var(--line);border-radius:7px;padding:9px 11px;overflow-x:auto;font-size:12px;color:#cfe3ea}
.f-fix{font-size:13px;color:#cde6cf;background:rgba(104,213,161,.06);border-radius:7px;padding:9px 11px}
.empty{color:var(--muted);text-align:center;padding:30px}
footer{text-align:center;color:var(--muted);font-size:11px;padding:24px;border-top:1px solid var(--line);margin-top:30px}
@media(max-width:720px){.kpis{grid-template-columns:repeat(3,1fr)}}
`;
