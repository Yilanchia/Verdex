import fs from "node:fs";
import { validateScope } from "./scope.js";

export const DEFAULT_BRIEF = {
  schema: "VerdexBrief/v1",
  scope: { include: [], exclude: [] },
  vuln_classes: [],
  osint: { enabled: true, categories: [], reveal: false },
  redlines: ["no-payload", "no-bruteforce", "no-out-of-scope"],
  allow: ["read_workspace", "parse_artifacts"],
  min_confidence: "medium",
};

const REQUIRED_REDLINES = ["no-payload", "no-bruteforce", "no-out-of-scope"];
const CONFIDENCE_RANK = { unknown: 0, low: 1, medium: 2, high: 3, exact: 4 };
const CLASS_ALIASES = new Map([
  ["sqli", "sql"],
  ["sql-injection", "sql"],
  ["command-injection", "cmd"],
  ["os-command-injection", "cmd"],
  ["rce", "cmd"],
  ["code-injection", "eval"],
  ["xss", "xss"],
  ["path-traversal", "path"],
  ["directory-traversal", "path"],
  ["ssrf", "ssrf"],
  ["open-redirect", "redirect"],
  ["deserialization", "deser"],
  ["insecure-deserialization", "deser"],
  ["hardcoded-secret", "secret"],
  ["hardcoded-credential", "secret"],
]);
const OSINT_CATEGORIES = new Set(["email", "phone", "social-profile", "person-name", "username"]);
const OSINT_CATEGORY_ALIASES = new Map([
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

export function validateBrief(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Brief must be an object");
  const brief = {
    ...DEFAULT_BRIEF,
    ...value,
    scope: { ...DEFAULT_BRIEF.scope, ...(value?.scope || {}) },
    osint: { ...DEFAULT_BRIEF.osint, ...(value?.osint || {}) },
  };
  validateScope(brief.scope);
  if (!brief.schema || brief.schema !== DEFAULT_BRIEF.schema) throw new Error(`Brief schema must be ${DEFAULT_BRIEF.schema}`);
  if (!brief.scope.include.length) throw new Error("Brief requires at least one included host");
  for (const field of ["vuln_classes", "redlines", "allow"]) {
    if (!Array.isArray(brief[field]) || brief[field].some((item) => typeof item !== "string")) throw new Error(`Brief field ${field} must be a string array`);
  }
  const redlines = [...new Set([...REQUIRED_REDLINES, ...brief.redlines.map((item) => item.trim()).filter(Boolean)])];
  if (redlines.some((item) => !/^[a-z0-9][a-z0-9-]*$/i.test(item))) throw new Error("Brief redlines must use simple identifiers");
  const vulnClasses = [...new Set(brief.vuln_classes.map(normalizeVulnClass).filter(Boolean))];
  if (brief.vuln_classes.some((item) => !normalizeVulnClass(item))) throw new Error("Brief vuln_classes must use non-empty identifiers");
  const allow = [...new Set(brief.allow.map((item) => item.trim()).filter(Boolean))];
  if (allow.some((item) => item === "network_request" || item === "payload_execution" || item === "bruteforce")) {
    throw new Error("Brief cannot authorize network requests, payload execution or brute force");
  }
  if (typeof brief.osint.enabled !== "boolean" || typeof brief.osint.reveal !== "boolean") throw new Error("Brief osint.enabled and osint.reveal must be booleans");
  if (!Array.isArray(brief.osint.categories) || brief.osint.categories.some((item) => typeof item !== "string")) throw new Error("Brief osint.categories must be a string array");
  const osintCategories = [...new Set(brief.osint.categories.map(normalizeOsintCategory).filter(Boolean))];
  if (brief.osint.categories.some((item) => !normalizeOsintCategory(item))) throw new Error("Brief osint.categories contains an unsupported category");
  if (brief.osint.reveal && !brief.osint.enabled) throw new Error("Brief cannot reveal OSINT values while OSINT is disabled");
  if (!["low", "medium", "high"].includes(brief.min_confidence)) throw new Error("Brief min_confidence must be low, medium or high");
  return { ...brief, vuln_classes: vulnClasses, osint: { ...brief.osint, categories: osintCategories }, redlines, allow };
}

export function loadBrief(file) {
  const text = fs.readFileSync(file, "utf8");
  return validateBrief(JSON.parse(text));
}

export function normalizeVulnClass(value) {
  const text = String(value || "").trim().toLowerCase();
  return CLASS_ALIASES.get(text) || text;
}

export function normalizeOsintCategory(value) {
  const text = String(value || "").trim().toLowerCase();
  const normalized = OSINT_CATEGORY_ALIASES.get(text) || text;
  return OSINT_CATEGORIES.has(normalized) ? normalized : "";
}

export function confidenceAtLeast(actual, minimum) {
  return (CONFIDENCE_RANK[String(actual || "unknown").toLowerCase()] || 0) >= (CONFIDENCE_RANK[String(minimum || "low").toLowerCase()] || 0);
}

export function findingMatchesBrief(finding, brief) {
  const kind = normalizeVulnClass(finding?.kind);
  const classAllowed = !brief.vuln_classes.length || brief.vuln_classes.includes(kind);
  return classAllowed && confidenceAtLeast(finding?.confidence, brief.min_confidence);
}

export function filterFindings(findings, brief) {
  if (!brief) return { findings: [...(findings || [])], excluded: [] };
  const included = [];
  const excluded = [];
  for (const finding of findings || []) {
    (findingMatchesBrief(finding, brief) ? included : excluded).push(finding);
  }
  return { findings: included, excluded };
}
