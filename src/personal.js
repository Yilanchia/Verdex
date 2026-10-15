import path from "node:path";
import { createEvidence, hashBytes } from "./evidence.js";
import { collectWorkspace } from "./workspace.js";

const QUERY_LIMIT = 20;
const QUERY_LENGTH_LIMIT = 160;

export function searchPersonalInfo(value, options = {}) {
  const workspace = typeof value === "string" ? collectWorkspace(value, options) : value;
  const queries = normalizeQueries(options.queries);
  const reveal = options.reveal === true;
  const matches = [];
  let filesScanned = 0;

  for (const file of workspace.files) {
    filesScanned += 1;
    const lines = file.text.split(/\r?\n/);
    for (const [index, line] of lines.entries()) {
      for (const query of queries) {
        const column = findQueryColumn(line, query.normalized);
        if (column < 0) continue;
        const sourceValue = line.slice(Math.max(0, column - 1), Math.min(line.length, column - 1 + query.normalized.length));
        const displayValue = reveal ? query.value : redactQuery(query.type, query.value);
        const snippet = reveal ? line : redactLine(line, query.value, displayValue);
        const evidence = createEvidence({
          file: file.path,
          content_sha256: file.content_sha256,
          line: index + 1,
          column,
          snippet,
          kind: "personal-search-match",
          authority: "local-file-evidence",
          epistemic: "observed",
          confidence: "exact",
        });
        matches.push({
          query_type: query.type,
          query_display: reveal ? query.value : redactQuery(query.type, query.value),
          matched_display: reveal ? sourceValue : redactQuery(query.type, sourceValue),
          file: file.path,
          line: index + 1,
          evidence,
        });
      }
    }
  }
  const observations = dedupeMatches(matches);
  return {
    schema: "VerdexPersonalSearch/v1",
    authority: "local-file-evidence",
    epistemic: "observed",
    privacy: { mode: reveal ? "revealed" : "redacted", raw_values_included: reveal, network_requests: false },
    queries: queries.map((query) => ({ type: query.type, display: reveal ? query.value : redactQuery(query.type, query.value), value_sha256: hashBytes(query.normalized) })),
    observations,
    coverage: { workspace: workspace.coverage, files_scanned: filesScanned, matches: observations.length, query_count: queries.length },
    limitations: [
      "仅在指定本地工作目录内做精确文本匹配，不访问互联网、社交平台或数据经纪服务。",
      "匹配表示输入信息出现在文件中，不代表身份归属、账号控制权或当前有效性。",
    ],
  };
}

function normalizeQueries(values) {
  const list = Array.isArray(values) ? values : String(values || "").split(/\r?\n/);
  const seen = new Set();
  const queries = [];
  for (const value of list) {
    const raw = typeof value === "string" ? value.trim() : String(value?.value || "").trim();
    if (!raw || raw.length > QUERY_LENGTH_LIMIT) continue;
    const normalized = normalizeQuery(raw);
    if (!normalized || seen.has(normalized)) continue;
    seen.add(normalized);
    queries.push({ value: raw, normalized, type: classifyQuery(raw) });
    if (queries.length >= QUERY_LIMIT) break;
  }
  return queries;
}

function normalizeQuery(value) {
  return value.toLowerCase().replace(/\s+/g, " ").trim();
}

function classifyQuery(value) {
  if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) return "email";
  if (/^\+?[\d\s().-]{7,}$/.test(value)) return "phone";
  if (/^https?:\/\//i.test(value)) return "profile-or-url";
  if (/^[\w.-]{2,64}$/.test(value)) return "username-or-token";
  return "text";
}

function findQueryColumn(line, normalized) {
  const lower = line.toLowerCase();
  const index = lower.indexOf(normalized);
  return index < 0 ? -1 : index + 1;
}

function redactQuery(type, value) {
  if (type === "email") {
    const [local, domain] = value.toLowerCase().split("@");
    return (local?.[0] || "*") + "***@" + domain;
  }
  if (type === "phone") {
    const digits = value.replace(/\D/g, "");
    return (value.trim().startsWith("+") ? "+" : "") + digits.slice(0, 3) + "****" + digits.slice(-4);
  }
  if (type === "profile-or-url") {
    const parts = value.split("/");
    const last = parts.pop() || "";
    return parts.join("/") + "/" + mask(last);
  }
  return mask(value);
}

function redactLine(line, value, displayValue) {
  if (line.toLowerCase().includes(value.toLowerCase())) return line.replace(new RegExp(escapeRegExp(value), "ig"), displayValue);
  return line.slice(0, 800);
}

function mask(value) {
  if (value.length <= 2) return (value[0] || "*") + "*";
  return value[0] + "***" + value.at(-1);
}

function dedupeMatches(matches) {
  const seen = new Set();
  return matches.filter((match) => {
    const key = `${match.query_type}|${match.query_display}|${match.evidence.file}:${match.evidence.line}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
