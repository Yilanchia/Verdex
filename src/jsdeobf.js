import fs from "node:fs";
import path from "node:path";

// Static JS de-obfuscation aid. It NEVER evaluates the script (that is exactly
// what obfuscators rely on). It decodes \xHH / \uHHHH escapes, beautifies
// minified layout, flags obfuscation signatures, and extracts strings/URLs.
const MAX_INPUT = 8 * 1024 * 1024;
const MAX_OUT_LINES = 6000;

function decodeEscapes(src) {
  return src
    .replace(/\\x([0-9a-fA-F]{2})/g, (_, h) => safeChar(parseInt(h, 16)))
    .replace(/\\u([0-9a-fA-F]{4})/g, (_, h) => safeChar(parseInt(h, 16)))
    .replace(/\\u\{([0-9a-fA-F]+)\}/g, (_, h) => safeChar(parseInt(h, 16)));
}

function safeChar(code) {
  // Only decode printable-ish chars; leave control bytes as-is to avoid garbling.
  if (code >= 0x20 && code !== 0x7f) {
    try { return String.fromCodePoint(code); } catch { return ""; }
  }
  return code === 0x09 || code === 0x0a || code === 0x0d ? String.fromCharCode(code) : `\\x${code.toString(16).padStart(2, "0")}`;
}

function detectSignals(src) {
  const signals = [];
  const hexIds = (src.match(/_0x[0-9a-f]{4,}/gi) || []).length;
  if (hexIds > 5) signals.push({ id: "hex-identifiers", note: `${hexIds} 个 _0x 十六进制标识符(obfuscator.io 典型)` });
  if (/eval\(function\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*[dr]\s*\)/.test(src)) signals.push({ id: "dean-edwards-packer", note: "Dean Edwards packer(eval(function(p,a,c,k,e,d)))" });
  if (/\beval\s*\(/.test(src)) signals.push({ id: "eval-call", note: "存在 eval 调用(动态执行,静态分析受限)" });
  if (/\b(atob|unescape|decodeURIComponent)\s*\(/.test(src)) signals.push({ id: "runtime-decode", note: "运行时解码(atob/unescape),真实字符串需运行才现形" });
  const bigArray = src.match(/\[\s*(?:(['"])(?:\\.|(?!\1).)*\1\s*,\s*){15,}/);
  if (bigArray) signals.push({ id: "string-array", note: "大字符串数组(常见于字符串混淆的查表)" });
  if (/\\x[0-9a-f]{2}/i.test(src)) signals.push({ id: "hex-escapes", note: "\\xHH 转义字符串(已尝试解码)" });
  return signals;
}

// Beautify minified JS by inserting newlines/indentation at structural tokens,
// while tracking string/template/regex/comment context so we never reformat
// inside a literal. Does not parse — a lightweight character scanner.
function beautify(src) {
  let out = "";
  let indent = 0;
  const pad = () => "  ".repeat(Math.max(0, indent));
  let i = 0;
  const n = src.length;
  let prev = "";
  while (i < n) {
    const c = src[i];
    const two = src.slice(i, i + 2);
    // comments
    if (two === "//") { const e = src.indexOf("\n", i); const end = e === -1 ? n : e; out += src.slice(i, end); i = end; continue; }
    if (two === "/*") { const e = src.indexOf("*/", i); const end = e === -1 ? n : e + 2; out += src.slice(i, end); i = end; continue; }
    // strings / templates
    if (c === '"' || c === "'" || c === "`") {
      const q = c; let j = i + 1;
      while (j < n) { if (src[j] === "\\") { j += 2; continue; } if (src[j] === q) { j++; break; } j++; }
      out += src.slice(i, j); prev = q; i = j; continue;
    }
    // regex literal (heuristic: / after an operator/punctuator, not after value)
    if (c === "/" && /[([{=:;,!&|?+\-*%^~<>]/.test(prev)) {
      let j = i + 1; let inClass = false; let ok = false;
      while (j < n) { const d = src[j]; if (d === "\\") { j += 2; continue; } if (d === "[") inClass = true; else if (d === "]") inClass = false; else if (d === "/" && !inClass) { j++; ok = true; break; } else if (d === "\n") break; j++; }
      if (ok) { while (j < n && /[a-z]/i.test(src[j])) j++; out += src.slice(i, j); prev = "/"; i = j; continue; }
    }
    if (c === "{" || c === "[") { indent++; out += c + "\n" + pad(); prev = c; i++; while (/\s/.test(src[i])) i++; continue; }
    if (c === "}" || c === "]") { indent--; out = out.replace(/\s+$/, "") + "\n" + pad() + c; prev = c; i++; continue; }
    if (c === ";") { out += ";\n" + pad(); prev = c; i++; while (/\s/.test(src[i])) i++; continue; }
    if (c === "\n" || c === "\r") { i++; continue; }
    out += c; if (!/\s/.test(c)) prev = c; i++;
  }
  return out.split(/\n/).map((l) => l.replace(/\s+$/, "")).filter((l, idx, arr) => !(l === "" && arr[idx - 1] === "")).join("\n");
}

function extractIndicators(src) {
  const urls = [...new Set((src.match(/https?:\/\/[^\s"'`<>()]{4,}/g) || []))].slice(0, 100);
  const ips = [...new Set((src.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || []).filter((x) => x.split(".").every((o) => +o <= 255)))].slice(0, 50);
  const b64 = [...new Set((src.match(/[A-Za-z0-9+/]{40,}={0,2}/g) || []))].slice(0, 20);
  return { urls, ips, long_base64: b64 };
}

export function deobfuscateJs(value) {
  if (typeof value !== "string" || !value.trim()) throw new Error("参数 path 必须是本地 JS 文件路径");
  const file = path.resolve(value);
  if (!fs.statSync(file).isFile()) throw new Error("path 必须指向一个文件");
  const raw = fs.readFileSync(file, "utf8").slice(0, MAX_INPUT);

  const signals = detectSignals(raw);
  const decoded = decodeEscapes(raw);
  const beautified = beautify(decoded);
  const lines = beautified.split("\n");
  const truncated = lines.length > MAX_OUT_LINES;
  // Indicators from the DECODED text so \xHH-hidden URLs surface.
  const indicators = extractIndicators(decoded);

  return {
    schema: "VerdexJs/v1",
    tool: "js_deobfuscate",
    file: path.basename(file),
    authority: "local-static",
    epistemic: "inferred",
    obfuscation_signals: signals,
    decoded_escapes: /\\x[0-9a-f]{2}|\\u[0-9a-f]{4}/i.test(raw),
    indicators,
    beautified: truncated ? lines.slice(0, MAX_OUT_LINES).join("\n") : beautified,
    beautified_truncated: truncated,
    limitations: [
      "纯静态处理:解转义 + 美化 + 特征识别,绝不执行脚本。",
      "字符串数组/atob 等运行时解码需要执行才能还原真实值,本工具不做(越红线);signals 会提示这类情况。",
      "正则/模板的美化为启发式,极端混淆下排版可能不完美,但不改变语义。",
    ],
  };
}

export const JSDEOBF_TOOLS = [
  {
    name: "js_deobfuscate",
    description: "JS 反混淆辅助(纯静态,绝不执行):解 \\xHH/\\uHHHH 转义揪出藏的 URL/字符串、美化压缩代码、识别混淆特征(_0x 标识符/packer/eval/atob/字符串数组)、提取 URL/IP/base64。字符串数组等运行时解码需执行才现形,本工具不做。只读本地。",
    inputSchema: { type: "object", required: ["path"], properties: { path: { type: "string", description: "本地 JS 文件路径。" } } },
    run: ({ path: p }) => deobfuscateJs(p),
  },
];
