import path from "node:path";
import { locationEvidence } from "./evidence.js";
import { explainScope, normalizeHost } from "./scope.js";

const ARTIFACT_EXTENSIONS = new Set([".json", ".jsonl", ".log", ".txt", ".sarif"]);
const URL_KEYS = ["matched-at", "matched_at", "url", "uri", "target", "host", "endpoint"];
const NAME_KEYS = ["template-id", "template_id", "template", "name", "title", "ruleId", "rule_id", "id"];

export function parseArtifacts(workspace, options = {}) {
  const observations = [];
  const limitations = [];
  let filesConsidered = 0;
  let recordsSeen = 0;
  let filteredOutOfScope = 0;
  let parseErrors = 0;

  for (const file of workspace.files) {
    if (!ARTIFACT_EXTENSIONS.has(path.extname(file.path).toLowerCase()) || !isArtifactName(file.path)) continue;
    filesConsidered += 1;
    const parsed = parseRecords(file);
    parseErrors += parsed.errors;
    for (const record of parsed.records) {
      recordsSeen += 1;
      const normalized = normalizeRecord(record.value);
      if (!normalized) continue;
      const scope = options.scope ? artifactScope(normalized, options.scope) : null;
      if (scope && !scope.allowed) {
        filteredOutOfScope += 1;
        continue;
      }
      observations.push({
        ...normalized,
        file: file.path,
        record_line: record.line,
        evidence: locationEvidence(file, { line: record.line, kind: "artifact-record" }),
        ...(scope ? { scope } : {}),
      });
    }
  }
  if (!filesConsidered) limitations.push("没有识别到常见扫描器结果文件；资产与源码分析仍可独立进行。");
  if (parseErrors) limitations.push(`有 ${parseErrors} 条结果记录无法解析，未纳入观察结果。`);
  if (options.scope && filteredOutOfScope) limitations.push(`有 ${filteredOutOfScope} 条结果记录因不在 brief 范围内被过滤。`);
  return {
    schema: "VerdexArtifacts/v1",
    authority: "artifact-bytes",
    epistemic: "observed",
    observations: dedupe(observations),
    coverage: {
      files_considered: filesConsidered,
      records_seen: recordsSeen,
      observations: observations.length,
      filtered_out_of_scope: filteredOutOfScope,
      parse_errors: parseErrors,
      truncated: false,
    },
    limitations,
  };
}

function parseRecords(file) {
  const extension = path.extname(file.path).toLowerCase();
  if (extension === ".jsonl" || extension === ".log" || extension === ".txt") {
    const records = [];
    let errors = 0;
    for (const [index, line] of file.text.split(/\r?\n/).entries()) {
      if (!line.trim()) continue;
      try {
        const value = JSON.parse(line);
        for (const item of expandRecords(value)) records.push({ value: item, line: index + 1 });
      } catch {
        errors += 1;
      }
    }
    return { records, errors };
  }
  try {
    const value = JSON.parse(file.text);
    if (isSarif(value)) {
      const records = [];
      for (const run of value.runs || []) {
        for (const result of run.results || []) records.push({ value: result, line: findRecordLine(file.text, result.ruleId) });
      }
      return { records, errors: 0 };
    }
    return { records: expandRecords(value).map((item) => ({ value: item, line: 1 })), errors: 0 };
  } catch {
    return { records: [], errors: 1 };
  }
}

function expandRecords(value) {
  if (Array.isArray(value)) return value;
  if (value && typeof value === "object" && Array.isArray(value.results)) return value.results;
  return [value];
}

function normalizeRecord(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const info = value.info && typeof value.info === "object" ? value.info : {};
  const location = value.locations?.[0]?.physicalLocation;
  const sarifUri = location?.artifactLocation?.uri;
  const url = firstString(value, URL_KEYS) || firstString(info, URL_KEYS) || (typeof sarifUri === "string" ? sarifUri : "");
  const name = firstString(value, NAME_KEYS) || firstString(info, NAME_KEYS);
  const message = typeof value.message?.text === "string" ? value.message.text.trim().slice(0, 1000) : "";
  const severity = firstString(value, ["severity", "risk", "level"]) || firstString(info, ["severity", "risk", "level"]);
  const type = firstString(value, ["type", "category", "matcher-name", "matcher_name"]) || firstString(info, ["type", "category"]);
  const targetHost = normalizeHost(url);
  if (!url && !name && !severity && !type && !message) return null;
  return {
    kind: "scanner-observation",
    url: url || "",
    target_host: targetHost || "",
    name: name || "",
    message,
    severity: normalizeSeverity(severity),
    type: type || "unknown",
    target_file: typeof sarifUri === "string" ? sarifUri : "",
    target_line: Number.isInteger(location?.region?.startLine) ? location.region.startLine : null,
    raw_keys: Object.keys(value).slice(0, 40),
  };
}

function artifactScope(record, scope) {
  const target = record.target_host || record.url;
  if (!target) return { allowed: false, reason: "no-target", matched: null };
  return explainScope(target, scope);
}

function firstString(value, keys) {
  for (const key of keys) {
    if (typeof value?.[key] === "string" && value[key].trim()) return value[key].trim().slice(0, 1000);
  }
  return "";
}

function normalizeSeverity(value) {
  const text = String(value || "unknown").toLowerCase();
  if (["critical", "emergency", "fatal"].includes(text)) return "critical";
  if (["high", "error"].includes(text)) return "high";
  if (["medium", "moderate", "warning"].includes(text)) return "medium";
  if (["low", "note"].includes(text)) return "low";
  if (["info", "informational", "none"].includes(text)) return "info";
  return "unknown";
}

function isArtifactName(file) {
  return /(?:nuclei|httpx|naabu|burp|zap|sarif|scan|finding|result|report|recon|alive|subdomain|template|vuln)/i.test(file);
}

function isSarif(value) {
  return Boolean(value && typeof value === "object" && value.version && Array.isArray(value.runs));
}

function findRecordLine(text, needle) {
  if (!needle) return 1;
  const index = text.indexOf(JSON.stringify(needle).slice(1, -1));
  return index < 0 ? 1 : text.slice(0, index).split(/\r?\n/).length;
}

function dedupe(items) {
  const seen = new Set();
  return items.filter((item) => {
    const key = `${item.name}|${item.url}|${item.type}|${item.severity}|${item.evidence.file}:${item.record_line}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}
