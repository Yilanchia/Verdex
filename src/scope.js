import { isIP } from "node:net";

export function normalizeHost(value) {
  const text = String(value || "").trim();
  if (!text || /[\s\\]/.test(text)) return "";
  if (isIP(text)) return text.toLowerCase();
  try {
    const url = new URL(text.includes("://") ? text : `https://${text}`);
    if (!["http:", "https:"].includes(url.protocol) || url.username || url.password) return "";
    return url.hostname.toLowerCase().replace(/\.$/, "").replace(/^\[|\]$/g, "");
  } catch {
    return "";
  }
}

export function hostMatches(host, pattern) {
  const rawPattern = String(pattern || "").trim();
  const wildcard = rawPattern.startsWith("*.");
  const actual = normalizeHost(host);
  const wanted = normalizeHost(wildcard ? rawPattern.slice(2) : rawPattern);
  if (!actual || !wanted || actual.includes("*") || wanted.includes("*")) return false;
  if (wildcard) return !isIP(wanted) && actual !== wanted && actual.endsWith(`.${wanted}`);
  return actual === wanted;
}

export function validateScope(scope) {
  if (!scope || !Array.isArray(scope.include) || !Array.isArray(scope.exclude || [])) throw new Error("Scope requires include and optional exclude arrays");
  for (const pattern of [...scope.include, ...(scope.exclude || [])]) {
    if (typeof pattern !== "string") throw new Error("Scope patterns must be strings");
    const value = pattern.startsWith("*.") ? pattern.slice(2) : pattern;
    if (!normalizeHost(value) || value.includes("*") || /[/?#]/.test(value.replace(/^https?:\/\//i, ""))) throw new Error(`Invalid scope pattern: ${pattern}`);
  }
  return { include: scope.include, exclude: scope.exclude || [] };
}

export function explainScope(target, scope) {
  const excluded = (scope.exclude || []).find((pattern) => hostMatches(target, pattern));
  if (excluded) return { allowed: false, reason: "excluded", matched: excluded };
  const included = scope.include.find((pattern) => hostMatches(target, pattern));
  return included ? { allowed: true, reason: "included", matched: included } : { allowed: false, reason: "not-included", matched: null };
}

export function inScope(target, scope) {
  return explainScope(target, scope).allowed;
}
