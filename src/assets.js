import { isIP } from "node:net";
import { createEvidence, hashBytes, locationEvidence } from "./evidence.js";
import { explainScope, normalizeHost } from "./scope.js";
import { collectWorkspace } from "./workspace.js";

const URL_RE = /https?:\/\/[^\s'"`<>\\]+/gi;
const IPV4_RE = /(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])/g;
const HOST_RE = /(?<![\w.@/])(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}(?![\w.-])/gi;
const FILE_SUFFIXES = new Set(["js", "ts", "py", "json", "md", "png", "jpg", "txt", "css", "html", "vue", "map", "dll", "exe"]);

export function extractAssets(value, options = {}) {
  const workspace = typeof value === "string" ? collectWorkspace(value, options) : value;
  const records = new Map();
  let invalidUrls = 0;

  function add(kind, asset, file, line, column) {
    const key = `${kind}|${asset}`;
    const evidence = locationEvidence(file, { line, column });
    const record = records.get(key) || {
      kind,
      value: asset,
      evidence: [],
      scope: options.scope ? explainScope(asset, options.scope) : { allowed: null, reason: "not-configured", matched: null },
    };
    if (!record.evidence.some((item) => item.id === evidence.id)) record.evidence.push(evidence);
    records.set(key, record);
  }

  for (const file of workspace.files) {
    for (const [index, line] of file.text.split(/\r?\n/).entries()) {
      const urlRanges = [];
      for (const match of line.matchAll(URL_RE)) {
        urlRanges.push([match.index, match.index + match[0].length]);
        const text = match[0].replace(/[).,;\]}]+$/, "");
        try {
          const url = new URL(text);
          if (!url.hostname || url.username || url.password) { invalidUrls += 1; continue; }
          add("url", url.href, file, index + 1, match.index + 1);
          add(isIP(url.hostname) ? "ip" : "host", url.hostname.toLowerCase(), file, index + 1, match.index + 1);
        } catch {
          invalidUrls += 1;
        }
      }
      for (const match of line.matchAll(HOST_RE)) {
        if (urlRanges.some(([start, end]) => match.index >= start && match.index < end)) continue;
        const host = match[0].toLowerCase();
        if (FILE_SUFFIXES.has(host.split(".").at(-1))) continue;
        if (!/scope|host|domain|target/i.test(file.path) && !/^[\s#*\-\d.:]*$/.test(line.slice(0, match.index))) continue;
        add("host", host, file, index + 1, match.index + 1);
      }
      for (const match of line.matchAll(IPV4_RE)) {
        if (isIP(match[0]) === 4) add("ip", match[0], file, index + 1, match.index + 1);
      }
    }
  }
  const items = [...records.values()];
  return {
    schema: "VerdexAssets/v1",
    authority: "local-file-evidence",
    epistemic: "observed",
    items,
    urls: items.filter((item) => item.kind === "url").map((item) => item.value),
    hosts: items.filter((item) => item.kind === "host").map((item) => item.value),
    ips: items.filter((item) => item.kind === "ip").map((item) => item.value),
    coverage: { ...workspace.coverage, invalid_urls: invalidUrls, records: items.length },
    limitations: ["String occurrences describe local evidence, not asset ownership or availability.", "Source-code property names are not treated as domain evidence."],
  };
}

export function createManualAssets(values, options = {}) {
  const records = new Map();
  const inputs = Array.isArray(values) ? values : String(values || "").split(/\r?\n/);
  for (const [index, raw] of inputs.entries()) {
    const text = typeof raw === "string" ? raw.trim() : String(raw?.value || "").trim();
    if (!text || text.startsWith("#")) continue;
    const asset = normalizeManualAsset(text);
    if (!asset) continue;
    const key = `${asset.kind}|${asset.value}`;
    const evidence = createEvidence({
      file: "user-input",
      content_sha256: hashBytes(text),
      line: index + 1,
      snippet: text,
      kind: "manual-asset",
      authority: "user-input",
      epistemic: "observed",
      confidence: "user-supplied",
    });
    records.set(key, {
      kind: asset.kind,
      value: asset.value,
      source: "manual",
      evidence: [evidence],
      scope: options.scope ? explainScope(asset.value, options.scope) : { allowed: null, reason: "not-configured", matched: null },
    });
  }
  const items = [...records.values()];
  return {
    schema: "VerdexAssetsManual/v1",
    authority: "user-input",
    epistemic: "observed",
    items,
    urls: items.filter((item) => item.kind === "url").map((item) => item.value),
    hosts: items.filter((item) => item.kind === "host").map((item) => item.value),
    ips: items.filter((item) => item.kind === "ip").map((item) => item.value),
    coverage: { records: items.length },
    limitations: ["手动资产是用户输入，不代表已验证归属、可达性或存活状态。"],
  };
}

export function mergeAssets(observed, manual) {
  const items = [...(observed?.items || [])];
  const seen = new Set(items.map((item) => `${item.kind}|${item.value}`));
  for (const item of manual?.items || []) {
    const key = `${item.kind}|${item.value}`;
    if (!seen.has(key)) {
      items.push(item);
      seen.add(key);
    }
  }
  return {
    ...observed,
    items,
    urls: items.filter((item) => item.kind === "url").map((item) => item.value),
    hosts: items.filter((item) => item.kind === "host").map((item) => item.value),
    ips: items.filter((item) => item.kind === "ip").map((item) => item.value),
    coverage: { ...(observed?.coverage || {}), records: items.length, manual_records: manual?.coverage?.records || 0 },
    limitations: [...new Set([...(observed?.limitations || []), ...(manual?.limitations || [])])],
  };
}

function normalizeManualAsset(value) {
  if (isIP(value)) return { kind: "ip", value: value.toLowerCase() };
  if (!value.includes("://")) {
    const host = normalizeHost(value);
    if (host && !host.includes("/") && !host.includes("*")) return { kind: "host", value: host };
    return null;
  }
  try {
    const url = new URL(value);
    if (["http:", "https:"].includes(url.protocol) && !url.username && !url.password) return { kind: "url", value: url.href };
  } catch {
    return null;
  }
  return null;
}
