import fs from "node:fs";
import path from "node:path";

// Read-only web traffic analysis + authorized-only PoC scaffolding. Verdex
// NEVER sends HTTP requests or attacks a live target. har_analyze parses a
// capture YOU already took (Burp/DevTools HAR export). web_poc only generates
// request templates text for a target you explicitly declare authorization for.

const SECURITY_HEADERS = [
  { name: "content-security-policy", label: "CSP", note: "缺少内容安全策略(XSS 纵深防御)" },
  { name: "x-frame-options", label: "X-Frame-Options", note: "缺少点击劫持防护" },
  { name: "x-content-type-options", label: "X-Content-Type-Options", note: "缺少 MIME 嗅探防护(应为 nosniff)" },
  { name: "strict-transport-security", label: "HSTS", note: "缺少 HSTS(HTTPS 强制)" },
  { name: "referrer-policy", label: "Referrer-Policy", note: "缺少引用来源策略" },
];
const TOKEN_RX = /(?:token|secret|api[_-]?key|password|authorization|session)[=:"']\s*[^\s"'&]{8,}/i;

function headerMap(headers) {
  const map = new Map();
  for (const h of headers || []) if (h && h.name) map.set(String(h.name).toLowerCase(), String(h.value ?? ""));
  return map;
}

function finding(list, severity, kind, title, where, detail) {
  list.push({ severity, kind, title, where, detail });
}

function analyzeEntry(entry, index, findings) {
  const req = entry.request || {};
  const res = entry.response || {};
  const where = `#${index + 1} ${req.method || "?"} ${(req.url || "").slice(0, 120)}`;
  const resHeaders = headerMap(res.headers);
  const status = Number(res.status || 0);

  // Insecure transport
  if (/^http:\/\//i.test(req.url || "")) finding(findings, "medium", "transport", "明文 HTTP 传输", where, "请求走 http,凭证/数据可被中间人读取。");

  // Only check security headers on HTML-ish successful responses
  const ctype = resHeaders.get("content-type") || "";
  if (status >= 200 && status < 400 && /html/i.test(ctype)) {
    for (const sh of SECURITY_HEADERS) {
      if (!resHeaders.has(sh.name)) finding(findings, "low", "security-header", `缺失安全响应头:${sh.label}`, where, sh.note);
    }
    const xcto = resHeaders.get("x-content-type-options");
    if (xcto && !/nosniff/i.test(xcto)) finding(findings, "low", "security-header", "X-Content-Type-Options 非 nosniff", where, `当前值:${xcto}`);
  }

  // CORS
  const acao = resHeaders.get("access-control-allow-origin");
  const acac = resHeaders.get("access-control-allow-credentials");
  if (acao === "*") finding(findings, acac && /true/i.test(acac) ? "high" : "medium", "cors", "CORS 允许任意源", where, acac && /true/i.test(acac) ? "allow-origin:* 且 allow-credentials:true —— 跨站可携凭证读响应,危险。" : "allow-origin:*,如涉及敏感数据需收紧。");

  // Set-Cookie flags
  for (const h of res.headers || []) {
    if (String(h.name || "").toLowerCase() !== "set-cookie") continue;
    const v = String(h.value || "");
    const cname = (v.split("=")[0] || "cookie").trim();
    const missing = [];
    if (!/;\s*HttpOnly/i.test(v)) missing.push("HttpOnly");
    if (!/;\s*Secure/i.test(v)) missing.push("Secure");
    if (!/;\s*SameSite/i.test(v)) missing.push("SameSite");
    if (missing.length) finding(findings, "medium", "cookie", `Cookie ${cname} 缺少 ${missing.join("/")}`, where, "会话 cookie 缺少安全属性,易被窃取或 CSRF 利用。");
  }

  // Reflected params → XSS candidate
  const body = typeof res.content?.text === "string" ? res.content.text : "";
  if (body) {
    for (const q of req.queryString || []) {
      const val = String(q.value || "");
      if (val.length >= 4 && body.includes(val)) finding(findings, "medium", "xss", `查询参数 ${q.name} 的值反射进响应体`, where, `参数值原样出现在响应中,存在反射型 XSS 候选(需确认是否转义)。`);
    }
  }

  // Secrets in URL
  if (TOKEN_RX.test(req.url || "")) finding(findings, "medium", "info-exposure", "URL 中疑似携带敏感令牌", where, "令牌出现在 URL,会进日志/历史/Referer。");
}

const SEV_ORDER = { high: 0, medium: 1, low: 2, info: 3 };

export function analyzeHar(value) {
  if (typeof value !== "string" || !value.trim()) throw new Error("参数 path 必须是 HAR 文件路径");
  const file = path.resolve(value);
  if (!fs.statSync(file).isFile()) throw new Error("path 必须指向一个文件");
  let har;
  try {
    har = JSON.parse(fs.readFileSync(file, "utf8"));
  } catch (e) {
    throw new Error(`HAR 解析失败(应为 JSON):${e.message}`);
  }
  const entries = har?.log?.entries;
  if (!Array.isArray(entries)) throw new Error("不是有效 HAR:缺少 log.entries 数组");
  const findings = [];
  entries.forEach((entry, i) => analyzeEntry(entry, i, findings));
  findings.sort((a, b) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9));
  const byKind = {};
  for (const f of findings) byKind[f.kind] = (byKind[f.kind] || 0) + 1;
  return {
    schema: "VerdexWeb/v1",
    tool: "har_analyze",
    file: path.basename(file),
    authority: "local-capture-static",
    epistemic: "inferred",
    entry_count: entries.length,
    finding_count: findings.length,
    by_kind: byKind,
    findings,
    limitations: [
      "只静态分析你提供的抓包文件,未发起任何网络请求、未与目标交互。",
      "反射/CORS/cookie 等为候选,需结合实际转义、鉴权和业务上下文人工确认。",
    ],
  };
}

const POC_KINDS = {
  sqli: { param: "id", payload: "1' OR '1'='1", note: "SQL 注入:观察响应是否随布尔条件变化,或是否报数据库错误。" },
  xss: { param: "q", payload: "<vx>alert(1)</vx>", note: "反射型 XSS:看标记是否未转义出现在响应 HTML 中。" },
  ssrf: { param: "url", payload: "http://127.0.0.1:80/", note: "SSRF:看服务端是否代为请求内网地址(观察时延/回显)。" },
  path: { param: "file", payload: "../../../../etc/passwd", note: "路径穿越:看是否读到预期外文件。" },
  redirect: { param: "next", payload: "https://example.org/", note: "开放重定向:看是否 3xx 跳到外部域。" },
};

export function webPoc(url, options = {}) {
  const target = String(url || "").trim();
  if (!target) throw new Error("参数 url 必填:显式声明授权目标(例如 https://lab.example.com/item)");
  if (!/^https?:\/\/[^\s"'<>]+$/i.test(target)) throw new Error("url 应为 http(s) 地址");
  const kindKey = String(options.kind || "").toLowerCase();
  const spec = POC_KINDS[kindKey] || POC_KINDS.xss;
  const q = `${spec.param}=${encodeURIComponent(spec.payload)}`;
  const sep = target.includes("?") ? "&" : "?";
  const full = `${target}${sep}${q}`;
  const banner = [
    `# Verdex 生成的 web 验证请求模板 —— 仅供授权测试(你拥有或被明确授权的目标)。`,
    `# 授权目标: ${target}`,
    `# 检测类型: ${kindKey || "xss"} —— ${spec.note}`,
    `# 使用者负责确认授权;禁止用于未授权系统。Verdex 不代为发送,由你审阅后自行执行。`,
  ].join("\n");
  const curl = `${banner}\n\ncurl -sS -i ${JSON.stringify(full)}`;
  const python = [
    banner,
    ``,
    `import requests`,
    `# 请在你有授权的范围内手动运行。`,
    `url = ${JSON.stringify(target)}`,
    `params = {${JSON.stringify(spec.param)}: ${JSON.stringify(spec.payload)}}`,
    `r = requests.get(url, params=params, timeout=10)`,
    `print(r.status_code)`,
    `print(${JSON.stringify(spec.payload)} in r.text, "<- 载荷是否出现在响应(据此判断)")`,
  ].join("\n");
  return {
    schema: "VerdexWeb/v1",
    tool: "web_poc",
    authorized_target: target,
    kind: kindKey || "xss",
    authority: "generated-scaffold",
    epistemic: "generated",
    curl,
    python,
    usage: "审阅模板,确认对目标有合法授权后在你自己的环境运行。Verdex 不会代为发送请求。",
    limitations: [
      "这是验证请求模板,不是完成的利用;需你在授权范围内手动运行并判断结果。",
      "Verdex 只生成文本,绝不发起网络请求、不与目标交互;授权与运行责任在使用者。",
      "仅限你拥有或被明确授权的目标(自建实验室 / 授权测试);禁止用于未授权系统。",
    ],
  };
}

export const WEB_TOOLS = [
  {
    name: "har_analyze",
    description: "静态分析你抓的 HAR 流量文件(Burp/浏览器 DevTools 导出):标出缺失安全头、不安全 Cookie、CORS 任意源、反射参数(XSS 候选)、URL 泄露令牌、明文传输。只读文件,不发起任何请求。",
    inputSchema: { type: "object", required: ["path"], properties: { path: { type: "string", description: "本地 HAR 文件路径。" } } },
    run: (args) => analyzeHar(args.path),
  },
  {
    name: "web_poc",
    description: "生成 web 漏洞验证请求模板(curl + python,仅文本)。url 必填=显式声明授权目标,写进授权 banner。kind:sqli/xss/ssrf/path/redirect。Verdex 不代为发送,由使用者在授权范围自行运行。禁止用于未授权系统。",
    inputSchema: { type: "object", required: ["url"], properties: { url: { type: "string", description: "授权目标 URL(http/https)。" }, kind: { type: "string", description: "检测类型:sqli/xss/ssrf/path/redirect(默认 xss)。" } } },
    run: (args) => webPoc(args.url, { kind: args.kind }),
  },
];
