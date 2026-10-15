import { createEvidence, hashBytes } from "./evidence.js";
import { collectWorkspace } from "./workspace.js";

const EMAIL_RE = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,63}\b/giu;
const CHINA_PHONE_RE = /(?<!\d)(?:\+?86[\s.-]?)?1[3-9]\d{9}(?!\d)/gu;
const INTERNATIONAL_PHONE_RE = /(?<!\d)\+\d{1,3}(?:[\s().-]?\d{2,4}){2,5}(?!\d)/gu;
const SOCIAL_PROFILE_RE = /https?:\/\/(?:www\.)?(?:github\.com|gitlab\.com|linkedin\.com\/in|twitter\.com|x\.com|t\.me|telegram\.me|reddit\.com\/u)\/[A-Za-z0-9][A-Za-z0-9_.-]{1,99}/giu;
const PERSON_FIELD_RE = /(?:^|[{\s,;])["']?(?:full[_ -]?name|real[_ -]?name|display[_ -]?name|contact[_ -]?name|联系人|姓名)["']?\s*[:=]\s*["'\x60]?([^"'\x60\r\n,;}]{1,80})/giu;
const USERNAME_FIELD_RE = /(?:^|[{\s,;])["']?(?:username|user_name|screen_name|handle|账号|用户名)["']?\s*[:=]\s*["'\x60]?([A-Za-z0-9][A-Za-z0-9_.-]{1,63})/giu;

const CATEGORY_ALIASES = new Map([
  ["emails", "email"],
  ["mail", "email"],
  ["phones", "phone"],
  ["telephone", "phone"],
  ["profiles", "social-profile"],
  ["social", "social-profile"],
  ["names", "person-name"],
  ["people", "person-name"],
  ["handles", "username"],
]);

const BLOCKED_LABEL_VALUES = new Set(["admin", "anonymous", "false", "none", "null", "n/a", "unknown", "user", "username"]);

export function collectOsint(value, options = {}) {
  const workspace = typeof value === "string" ? collectWorkspace(value, options) : value;
  const enabled = options.enabled !== false;
  const reveal = options.reveal === true;
  const allowedCategories = normalizeCategories(options.categories);
  if (!enabled) return disabledResult(workspace, reveal);

  const records = new Map();
  const categoryCounts = {};
  let matchesDetected = 0;
  let filesScanned = 0;

  function add(category, rawValue, file, line, column) {
    const normalized = normalizeValue(category, rawValue);
    if (!normalized || !categoryAllowed(category, allowedCategories)) return;
    matchesDetected += 1;
    const valueSha256 = hashBytes(normalized);
    const key = category + "|" + valueSha256;
    const displayValue = redactValue(category, normalized);
    const sourceLine = file.text.split(/\r?\n/)[line - 1] || "";
    const evidence = createEvidence({
      file: file.path,
      content_sha256: file.content_sha256,
      line,
      column,
      snippet: reveal ? sourceLine : redactSnippet(sourceLine, rawValue, displayValue),
      kind: "osint-" + category,
      epistemic: "observed",
      confidence: "exact",
    });
    const existing = records.get(key);
    if (existing) {
      if (!existing.evidence.some((item) => item.id === evidence.id)) existing.evidence.push(evidence);
      return;
    }
    const observation = {
      category,
      display_value: displayValue,
      value_sha256: valueSha256,
      sensitivity: "personal-identifier",
      evidence: [evidence],
    };
    if (reveal) observation.value = normalized;
    records.set(key, observation);
    categoryCounts[category] = (categoryCounts[category] || 0) + 1;
  }

  for (const file of workspace.files) {
    filesScanned += 1;
    for (const [index, line] of file.text.split(/\r?\n/).entries()) {
      const lineNumber = index + 1;
      collectMatches(line, EMAIL_RE, (match) => add("email", match[0], file, lineNumber, match.index + 1));
      const lineWithoutEmails = line.replace(EMAIL_RE, (match) => " ".repeat(match.length));
      collectMatches(lineWithoutEmails, CHINA_PHONE_RE, (match) => add("phone", match[0], file, lineNumber, match.index + 1));
      collectMatches(lineWithoutEmails, INTERNATIONAL_PHONE_RE, (match) => add("phone", match[0], file, lineNumber, match.index + 1));
      collectMatches(line, SOCIAL_PROFILE_RE, (match) => add("social-profile", match[0], file, lineNumber, match.index + 1));
      collectMatches(line, PERSON_FIELD_RE, (match) => add("person-name", match[1], file, lineNumber, match.index + match[0].indexOf(match[1]) + 1));
      collectMatches(line, USERNAME_FIELD_RE, (match) => add("username", match[1], file, lineNumber, match.index + match[0].indexOf(match[1]) + 1));
    }
  }

  return {
    schema: "VerdexOSINT/v1",
    authority: "local-file-evidence",
    epistemic: "observed",
    privacy: {
      mode: reveal ? "revealed" : "redacted",
      raw_values_included: reveal,
      network_requests: false,
    },
    observations: [...records.values()],
    coverage: {
      workspace: workspace.coverage,
      files_scanned: filesScanned,
      matches_detected: matchesDetected,
      observations: records.size,
      by_category: categoryCounts,
    },
    limitations: [
      "仅从本地工作区已有文件提取显式标识符，不访问搜索引擎、社交平台、数据经纪或其他网络服务。",
      "姓名和用户名只识别带明确字段标签的值，不对任意文本做身份推断。",
      "观察结果表示文件中出现过该标识符，不代表其当前有效、属于目标本人或获得了使用授权。",
    ],
  };
}

function disabledResult(workspace, reveal) {
  return {
    schema: "VerdexOSINT/v1",
    authority: "local-file-evidence",
    epistemic: "observed",
    privacy: { mode: reveal ? "revealed" : "redacted", raw_values_included: false, network_requests: false },
    observations: [],
    coverage: { workspace: workspace.coverage, files_scanned: 0, matches_detected: 0, observations: 0, by_category: {} },
    limitations: ["OSINT 提取已在 brief 或调用选项中禁用。"],
  };
}

function collectMatches(line, regex, callback) {
  regex.lastIndex = 0;
  for (const match of line.matchAll(regex)) callback(match);
}

function normalizeCategories(value) {
  if (!Array.isArray(value) || !value.length) return null;
  return new Set(value.map((item) => CATEGORY_ALIASES.get(String(item).trim().toLowerCase()) || String(item).trim().toLowerCase()).filter(Boolean));
}

function categoryAllowed(category, allowedCategories) {
  return !allowedCategories || allowedCategories.has(category);
}

function normalizeValue(category, value) {
  const text = String(value || "").trim().replace(/[).,;}\]]+$/g, "");
  if (!text) return "";
  if (category === "email") {
    const normalized = text.toLowerCase();
    return /^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,63}$/i.test(normalized) ? normalized : "";
  }
  if (category === "phone") return normalizePhone(text);
  if (category === "social-profile") return normalizeProfile(text);
  if (category === "person-name") return normalizePersonName(text);
  if (category === "username") return normalizeUsername(text);
  return "";
}

function normalizePhone(value) {
  const digits = value.replace(/\D/g, "");
  if (digits.length < 7 || digits.length > 15 || /^(\d)\1+$/.test(digits)) return "";
  if (digits.length === 11 && /^1[3-9]\d{9}$/.test(digits)) return "+86" + digits;
  if (digits.length === 13 && digits.startsWith("86")) return "+" + digits;
  return value.trim().startsWith("+") ? "+" + digits : digits;
}

function normalizeProfile(value) {
  try {
    const url = new URL(value);
    if (!["http:", "https:"].includes(url.protocol)) return "";
    return url.protocol + "//" + url.host + url.pathname.replace(/\/+$/, "");
  } catch {
    return "";
  }
}

function normalizePersonName(value) {
  const normalized = value.replace(/\s+/g, " ").trim();
  if (normalized.length < 2 || normalized.length > 80 || BLOCKED_LABEL_VALUES.has(normalized.toLowerCase())) return "";
  if (/[/:@{}[\]=<>]/.test(normalized)) return "";
  return normalized;
}

function normalizeUsername(value) {
  const normalized = value.trim();
  if (normalized.length < 2 || normalized.length > 64 || BLOCKED_LABEL_VALUES.has(normalized.toLowerCase())) return "";
  return normalized;
}

function redactValue(category, value) {
  if (category === "email") {
    const [local, domain] = value.split("@");
    if (local.length <= 2) return (local[0] || "*") + "***@" + domain;
    return local[0] + "***" + local.at(-1) + "@" + domain;
  }
  if (category === "phone") {
    const digits = value.replace(/\D/g, "");
    return (value.startsWith("+") ? "+" : "") + digits.slice(0, 3) + "****" + digits.slice(-4);
  }
  if (category === "social-profile") {
    const parts = value.split("/");
    const username = parts.pop() || "";
    return parts.join("/") + "/" + maskIdentifier(username);
  }
  if (category === "person-name") return value.slice(0, 1) + "*".repeat(Math.max(2, Math.min(6, value.length - 1)));
  return maskIdentifier(value);
}

function maskIdentifier(value) {
  if (value.length <= 2) return (value[0] || "*") + "*";
  return value[0] + "***" + value.at(-1);
}

function redactSnippet(source, rawValue, displayValue) {
  let redacted = source.replace(EMAIL_RE, (match) => redactValue("email", normalizeValue("email", match)));
  redacted = redacted.replace(INTERNATIONAL_PHONE_RE, (match) => redactValue("phone", normalizeValue("phone", match)));
  redacted = redacted.replace(CHINA_PHONE_RE, (match) => redactValue("phone", normalizeValue("phone", match)));
  redacted = redacted.replace(SOCIAL_PROFILE_RE, (match) => redactValue("social-profile", normalizeValue("social-profile", match)));
  redacted = redacted.replace(PERSON_FIELD_RE, (whole, name) => whole.replace(name, redactValue("person-name", normalizeValue("person-name", name))));
  redacted = redacted.replace(USERNAME_FIELD_RE, (whole, username) => whole.replace(username, redactValue("username", normalizeValue("username", username))));
  const raw = String(rawValue || "");
  if (raw && redacted.includes(raw)) redacted = redacted.split(raw).join(displayValue);
  return redacted.slice(0, 800);
}
