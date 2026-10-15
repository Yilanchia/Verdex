import path from "node:path";
import { filterFindings } from "./brief.js";
import { createEvidence, dedupeFindings, locationEvidence } from "./evidence.js";
import { buildCodeGraph } from "./graph.js";
import { collectWorkspace } from "./workspace.js";

const RULES = [
  { kind: "secret", cwe: "CWE-798", severity: "high", rx: /(?:SECRET_KEY|PASSWORD|API_KEY|TOKEN)\s*=\s*["'][^"']{4,}/i, note: "可能存在硬编码密钥或口令" },
  { kind: "sql", cwe: "CWE-89", severity: "high", rx: /(?:SELECT|INSERT|UPDATE|DELETE).{0,100}(?:\+|f["']|%s|\{)/i, note: "SQL 与字符串拼接" },
  { kind: "cmd", cwe: "CWE-78", severity: "high", rx: /os\.(?:system|popen)\(|subprocess\.(?:call|run|Popen)\([^)]*shell\s*=\s*True/i, note: "命令执行接口或 shell=True" },
  { kind: "eval", cwe: "CWE-95", severity: "high", rx: /\b(?:eval|exec|Function)\s*\(/, note: "动态执行接口" },
  { kind: "deser", cwe: "CWE-502", severity: "high", rx: /(?:pickle\.loads|yaml\.(?:load|unsafe_load)|unserialize)\s*\(/, note: "不安全反序列化接口" },
  { kind: "xss", cwe: "CWE-79", severity: "medium", rx: /(?:innerHTML|dangerouslySetInnerHTML|mark_safe)/, note: "直接 HTML 渲染接口" },
  { kind: "ssrf", cwe: "CWE-918", severity: "high", rx: /(?:requests\.(?:get|post|put|delete)|urllib\.request\.urlopen|urlopen|axios\.(?:get|post)|fetch)\s*\([^)]*(?:req|request|params|query|args|input)/i, note: "外部请求目标可能来自用户输入(SSRF)" },
  { kind: "path", cwe: "CWE-22", severity: "high", rx: /(?:open|readFile|readFileSync|sendFile|fopen|include|require)\s*\([^)]*(?:req|request|params|query|args|input)[^)]*\)/i, note: "文件路径可能来自用户输入(路径穿越)" },
  { kind: "ssti", cwe: "CWE-1336", severity: "high", rx: /render_template_string\s*\(|Template\s*\([^)]*(?:\+|%|\{)|\$\{[^}]*(?:req|request|params|query)[^}]*\}/i, note: "模板拼接用户输入(服务端模板注入 SSTI)" },
  { kind: "redirect", cwe: "CWE-601", severity: "medium", rx: /(?:redirect|location\.href\s*=|header\s*\(\s*["']Location)[^;\n]*(?:req|request|params|query|args|input)/i, note: "重定向目标来自用户输入(开放重定向)" },
  { kind: "cors", cwe: "CWE-942", severity: "medium", rx: /Access-Control-Allow-Origin["']?\s*[:,]\s*["']\*|origin\s*:\s*(?:true|["']\*["'])/i, note: "CORS 允许任意源(配合凭证时危险)" },
  { kind: "crypto", cwe: "CWE-327", severity: "medium", rx: /hashlib\.(?:md5|sha1)|createHash\s*\(\s*["'](?:md5|sha1)|MessageDigest\.getInstance\s*\(\s*["'](?:MD5|SHA-?1)|["']ECB["']|Math\.random\s*\(\s*\)/i, note: "弱哈希/弱加密/不安全随机" },
  { kind: "xxe", cwe: "CWE-611", severity: "high", rx: /etree\.parse|XMLParser|DocumentBuilderFactory|SAXParser|resolveEntity|noent\s*=\s*True/i, note: "XML 解析可能启用外部实体(XXE)" },
  { kind: "proto", cwe: "CWE-1321", severity: "medium", rx: /__proto__|constructor\s*\[\s*["']prototype|Object\.assign\s*\([^,]*,\s*(?:req|request|JSON\.parse)|\bmerge\s*\([^)]*(?:req|request)/i, note: "可能的原型链污染" },
];

export function scanProject(value, options = {}) {
  const workspace = typeof value === "string" ? collectWorkspace(value, options) : value;
  const ruleFindings = [];
  for (const file of workspace.files) {
    if (!isCode(file.path)) continue;
    for (const [index, line] of file.text.split(/\r?\n/).entries()) {
      if (isComment(line)) continue;
      for (const rule of RULES) {
        if (!rule.rx.test(line)) continue;
        ruleFindings.push({
          title: rule.note,
          kind: rule.kind,
          cwe: rule.cwe,
          severity: rule.severity,
          file: file.path,
          line: index + 1,
          why: "这是本地规则命中，需要结合输入来源、权限边界和实际调用关系人工确认。",
          fix: "核对数据来源和安全 API，按项目约定替换危险接口或加入严格校验。",
          confidence: "low",
          source: "static-rule",
          evidence: [locationEvidence(file, { line: index + 1, kind: `rule-${rule.kind}` })],
          chains: [],
        });
        break;
      }
    }
  }
  const graph = buildCodeGraph(workspace.root, { ...options, workspace, includeFlows: true, flowLimit: options.flowLimit || 100 });
  const flowFindings = graph.dataflows.map((flow) => ({
    title: flow.note,
    kind: flow.kind,
    cwe: flow.cwe,
    severity: flow.severity,
    file: flow.file,
    line: flow.line,
    why: "静态数据流候选显示请求输入与危险操作位于同一条局部传播路径，需要人工核对控制流、编码和权限条件。",
    fix: "优先使用参数化 API、固定枚举或安全封装，并确认入口处存在必要的认证、授权和输入约束。",
    confidence: flow.confidence,
    source: "dataflow",
    evidence: flow.chain,
    chains: [flow.chain],
    sink: flow.sink,
  }));
  const allFindings = dedupeFindings([...ruleFindings, ...flowFindings]);
  const filtered = filterFindings(allFindings, options.brief);
  const findings = filtered.findings;
  return {
    schema: "VerdexScan/v2",
    authority: "local-static-analysis",
    epistemic: "inferred",
    findings,
    graph,
    coverage: {
      workspace: workspace.coverage,
      rule_hits: ruleFindings.length,
      dataflow_hits: flowFindings.length,
      pre_filter_findings: allFindings.length,
      filtered_by_brief: filtered.excluded.length,
      findings: findings.length,
    },
    limitations: [
      "规则命中和数据流候选都不是已确认漏洞，必须回到原文件复核。",
      ...(options.brief ? [`本轮按 brief 过滤了 ${filtered.excluded.length} 个低于置信度或不在漏洞类型清单内的候选。`] : []),
    ],
  };
}

function isCode(file) {
  return [".c", ".cpp", ".cs", ".go", ".java", ".js", ".jsx", ".kt", ".mjs", ".php", ".py", ".rb", ".rs", ".ts", ".tsx"].includes(path.extname(file).toLowerCase());
}

function isComment(line) {
  const text = line.trim();
  return text.startsWith("#") || text.startsWith("//") || text.startsWith("*");
}
