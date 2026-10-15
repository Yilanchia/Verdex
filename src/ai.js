import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";

const PROJECT_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const SETTINGS_DIRECTORY = path.join(PROJECT_ROOT, ".verdex");
const SETTINGS_FILE = path.join(SETTINGS_DIRECTORY, "ai-settings.json");
let sessionApiKey = "";
const DEFAULT_SETTINGS = {
  enabled: false,
  provider: "openai-compatible",
  baseUrl: "http://127.0.0.1:11434/v1",
  model: "",
  apiKeyConfigured: false,
  allowNetwork: false,
};

export function getAiSettings() {
  const settings = readSettings();
  return { ...settings, apiKeyConfigured: Boolean(sessionApiKey), apiKey: undefined };
}

export function saveAiSettings(value) {
  const current = readSettings();
  const next = {
    ...DEFAULT_SETTINGS,
    enabled: value?.enabled === true,
    provider: cleanText(value?.provider || current.provider, 80),
    baseUrl: normalizeBaseUrl(value?.baseUrl || current.baseUrl),
    model: cleanText(value?.model || current.model, 160),
    allowNetwork: value?.allowNetwork === true,
  };
  if (typeof value?.apiKey === "string" && value.apiKey.trim()) sessionApiKey = value.apiKey.trim().slice(0, 4000);
  if (value?.clearApiKey === true) sessionApiKey = "";
  fs.mkdirSync(SETTINGS_DIRECTORY, { recursive: true });
  fs.writeFileSync(SETTINGS_FILE, JSON.stringify(next, null, 2) + "\n", "utf8");
  return getAiSettings();
}

export async function reviewWithAi(payload) {
  const settings = readSettings();
  if (!settings.enabled) throw new Error("AI 接入未启用");
  if (!settings.allowNetwork) throw new Error("AI 网络调用未授权；请在设置中明确开启后再执行复核");
  if (!settings.model) throw new Error("AI 模型名称不能为空");
  if (!sessionApiKey && !isLocalEndpoint(settings.baseUrl)) throw new Error("远程 AI 端点需要 API Key");
  const endpoint = normalizeBaseUrl(settings.baseUrl).replace(/\/$/, "") + "/chat/completions";
  const selectedEvidence = Array.isArray(payload?.evidence) ? payload.evidence.slice(0, 20) : [];
  const prompt = String(payload?.prompt || "请基于给定证据，输出待人工复核的风险点、依据和不确定性。不要生成利用代码、载荷或攻击步骤。").slice(0, 4000);
  const response = await fetch(endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...(sessionApiKey ? { Authorization: "Bearer " + sessionApiKey } : {}) },
    body: JSON.stringify({ model: settings.model, temperature: 0.1, messages: [{ role: "system", content: "你是防守型安全分析助手。只做证据整理和风险复核，不输出利用代码、载荷、爆破或越界操作。" }, { role: "user", content: prompt + "\n\n证据：\n" + JSON.stringify(selectedEvidence) }] }),
    signal: AbortSignal.timeout(30_000),
  });
  const result = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(result.error?.message || `AI 请求失败：HTTP ${response.status}`);
  return { schema: "VerdexAIReview/v1", authority: "configured-ai-endpoint", epistemic: "inferred", model: settings.model, content: result.choices?.[0]?.message?.content || "模型未返回文本", network_request: true };
}

function readSettings() {
  try {
    const value = JSON.parse(fs.readFileSync(SETTINGS_FILE, "utf8"));
    return { ...DEFAULT_SETTINGS, ...value, apiKey: undefined };
  } catch {
    return { ...DEFAULT_SETTINGS };
  }
}

function normalizeBaseUrl(value) {
  const text = cleanText(value, 500).replace(/\/$/, "");
  try {
    const url = new URL(text);
    if (url.username || url.password || !["http:", "https:"].includes(url.protocol)) throw new Error("unsupported endpoint");
    if (url.protocol === "http:" && !isLocalEndpoint(url.href)) throw new Error("远程 AI 端点必须使用 HTTPS");
    return url.href.replace(/\/$/, "");
  } catch {
    throw new Error("AI Base URL 必须是 HTTPS 地址；本机模型可使用 http://127.0.0.1 或 localhost");
  }
}

function isLocalEndpoint(value) {
  try {
    const hostname = new URL(value).hostname.replace(/^\[|\]$/g, "").toLowerCase();
    if (hostname === "localhost") return true;
    if (net.isIP(hostname) === 4) return hostname.split(".")[0] === "127";
    return hostname === "::1";
  } catch {
    return false;
  }
}

function cleanText(value, limit) {
  return String(value || "").trim().slice(0, limit);
}
