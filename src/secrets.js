import { collectWorkspace } from "./workspace.js";
import { hashBytes } from "./evidence.js";

// Detects hardcoded secrets by provider signatures + high-entropy heuristics.
// Evidence-first: never emits the raw secret — only a redacted preview, a
// sha256 of the value, and the file/line. Read-only, no network.

// impact: "direct"      = 暴露即成立,审核可自行验证(服务端凭据/私钥) → report-ready
//         "conditional" = 危害取决于服务端行为(客户端密钥/盐),静态证不了 →
//                          多半被当"理论风险"拒,除非动态打通一次
const PROVIDER_RULES = [
  { id: "aws-access-key-id", severity: "high", impact: "direct", rx: /\bAKIA[0-9A-Z]{16}\b/, note: "AWS Access Key ID" },
  { id: "aws-secret-access-key", severity: "high", impact: "direct", rx: /\baws_secret_access_key\b["'\s:=]+([A-Za-z0-9/+]{40})\b/i, group: 1, note: "AWS Secret Access Key" },
  { id: "github-token", severity: "high", impact: "direct", rx: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/, note: "GitHub Token" },
  { id: "github-fine-grained", severity: "high", impact: "direct", rx: /\bgithub_pat_[A-Za-z0-9_]{60,}\b/, note: "GitHub fine-grained PAT" },
  { id: "google-api-key", severity: "medium", impact: "conditional", rx: /\bAIza[0-9A-Za-z_-]{35}\b/, note: "Google API Key(常为客户端嵌入,危害看是否限流/限包名)" },
  { id: "slack-token", severity: "high", impact: "direct", rx: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/, note: "Slack Token" },
  { id: "stripe-secret", severity: "critical", impact: "direct", rx: /\bsk_live_[0-9A-Za-z]{24,}\b/, note: "Stripe Live Secret Key" },
  { id: "stripe-restricted", severity: "high", impact: "direct", rx: /\brk_live_[0-9A-Za-z]{24,}\b/, note: "Stripe Restricted Key" },
  { id: "private-key", severity: "critical", impact: "direct", rx: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/, note: "私钥(PEM)" },
  { id: "jwt", severity: "medium", impact: "conditional", rx: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/, note: "JWT(危害看是否有效/高权)" },
  { id: "slack-webhook", severity: "high", impact: "direct", rx: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9/]{20,}/, note: "Slack Webhook URL" },
  { id: "generic-assignment", severity: "medium", impact: "conditional", rx: /\b(?:api[_-]?key|secret|token|passwd|password|access[_-]?key)\b["'\s:=]+["']?([A-Za-z0-9/+_-]{16,})["']?/i, group: 1, note: "通用密钥赋值(高熵)", entropy: 3.5 },
  // Named key/secret constants (the pattern the hand-done reports found): an
  // identifier whose name contains key/secret/token/appid/clientId, assigned a
  // ≥8-char literal. The NAME is the signal, so no entropy gate.
  { id: "named-key-constant", severity: "medium", impact: "conditional", rx: /\b[A-Za-z0-9]*(?:_?APP_?KEY|_?APP_?SECRET|_SECRET|_KEY|CLIENT_?ID|ACCESS_?KEY|API_?KEY|APPKEY|APPSECRET)\b\s*[:=]\s*["']([A-Za-z0-9/+=_-]{8,})["']/i, group: 1, note: "命名密钥常量赋值(多为客户端 app key,危害条件性)" },
  // Signing salt / secret in a signature string: appSecret=.. or &key=sign-..
  { id: "signing-salt", severity: "medium", impact: "conditional", rx: /(?:appSecret|[?&]key)\s*=\s*["']?((?:sign-)?[A-Za-z0-9/+=_-]{12,})/i, group: 1, note: "签名密钥/盐(危害取决于服务端是否信任伪造签名)" },
];

function shannonEntropy(s) {
  if (!s) return 0;
  const freq = {};
  for (const ch of s) freq[ch] = (freq[ch] || 0) + 1;
  let e = 0;
  for (const k in freq) { const p = freq[k] / s.length; e -= p * Math.log2(p); }
  return e;
}

function redact(value) {
  const s = String(value);
  if (s.length <= 8) return "*".repeat(s.length);
  return `${s.slice(0, 3)}${"*".repeat(Math.max(3, s.length - 7))}${s.slice(-4)}`;
}

const CODE_EXT = new Set([".js", ".mjs", ".ts", ".tsx", ".jsx", ".py", ".rb", ".php", ".go", ".java", ".kt", ".cs", ".env", ".yml", ".yaml", ".json", ".xml", ".ini", ".conf", ".txt", ".sh", ".properties", ""]);

export function scanSecrets(value, options = {}) {
  const workspace = typeof value === "string" ? collectWorkspace(value, options) : value;
  const findings = [];
  const seen = new Set();
  for (const file of workspace.files) {
    const ext = (file.path.match(/\.[^.\\/]+$/) || [""])[0].toLowerCase();
    if (!CODE_EXT.has(ext)) continue;
    const lines = file.text.split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      for (const rule of PROVIDER_RULES) {
        const m = rule.rx.exec(line);
        if (!m) continue;
        const raw = rule.group ? m[rule.group] : m[0];
        if (!raw) continue;
        if (rule.entropy && shannonEntropy(raw) < rule.entropy) continue; // skip low-entropy false positives
        const valueSha256 = hashBytes(raw);
        const key = `${rule.id}|${file.path}|${i + 1}|${valueSha256.slice(0, 12)}`;
        if (seen.has(key)) continue;
        seen.add(key);
        findings.push({
          rule: rule.id,
          title: rule.note,
          severity: rule.severity,
          impact: rule.impact || "conditional",
          file: file.path,
          line: i + 1,
          column: m.index + 1,
          redacted: redact(raw),
          value_sha256: valueSha256,
          entropy: Number(shannonEntropy(raw).toFixed(2)),
          evidence: { file: file.path, line: i + 1, kind: `secret-${rule.id}`, content_sha256: file.content_sha256 },
        });
      }
    }
  }
  const bySeverity = {};
  for (const f of findings) bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;
  const reportReady = findings.filter((f) => f.impact === "direct");
  const needsProof = findings.filter((f) => f.impact !== "direct");
  return {
    schema: "VerdexSecrets/v1",
    authority: "local-static-scan",
    epistemic: "inferred",
    reveal: false,
    finding_count: findings.length,
    by_severity: bySeverity,
    triage: {
      report_ready: reportReady.length,
      needs_dynamic_proof: needsProof.length,
      guidance: "report_ready(impact=direct):服务端凭据/私钥,暴露即成立,审核可自验,适合直接上报。needs_dynamic_proof(impact=conditional):客户端密钥/签名盐,静态证不了危害,单独上报多半被判'理论风险'拒收——接 impact_proof(vuln_class=signing-forgery/hardcoded-cred)拿'最小影响+数据安全+点到为止'的验证方案,在授权范围内打通一次(伪造签名/自证调用)再上报;否则只作背景证据。",
    },
    findings,
    limitations: [
      "按服务商特征与高熵启发式匹配,是候选而非确认;需人工核对是否为真实有效凭据。",
      "默认脱敏:只给前后几位 + value_sha256 + 文件行号,不输出密钥原文。",
      "只读本地文件,不访问网络、不验证凭据有效性。",
      "只扫描 workspace 收集的文本文件;无扩展名的密钥文件(如 id_rsa)可能不在收集范围内。",
    ],
  };
}

export const SECRETS_TOOLS = [
  {
    name: "secrets",
    description: "扫描硬编码密钥:按服务商特征(AWS/GitHub/Google/Slack/Stripe/私钥/JWT 等)+ 高熵启发式识别,默认脱敏(只给前后几位+sha256+文件行号,不输出原文)。只读本地,不联网、不验证凭据。",
    inputSchema: { type: "object", required: ["root"], properties: { root: { type: "string", description: "本地作业夹路径。" } } },
    run: ({ root }) => scanSecrets(root),
  },
];
