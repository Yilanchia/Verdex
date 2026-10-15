import crypto from "node:crypto";

export function createEvidence(input) {
  if (!input.file || !Number.isInteger(input.line) || input.line < 1 || !String(input.snippet || "").trim()) {
    throw new Error("Evidence requires a file, positive line number and source snippet");
  }
  if (!/^[a-f0-9]{64}$/.test(input.content_sha256 || "")) throw new Error("Evidence requires source file SHA-256");
  const value = {
    authority: input.authority || "artifact-bytes",
    epistemic: input.epistemic || "observed",
    confidence: input.confidence || "exact",
    kind: input.kind || "source-location",
    file: input.file.replace(/\\/g, "/"),
    content_sha256: input.content_sha256,
    line: input.line,
    column: input.column || 1,
    end_line: input.end_line || input.line,
    snippet: String(input.snippet).slice(0, 800),
  };
  return { id: `ev_${digest(value).slice(0, 24)}`, ...value };
}

export function locationEvidence(file, location) {
  const lines = file.text.split(/\r?\n/);
  const line = location.line || 1;
  return createEvidence({
    file: file.path,
    content_sha256: file.content_sha256,
    line,
    column: location.column || 1,
    end_line: location.end_line || line,
    snippet: lines.slice(line - 1, location.end_line || line).join("\n") || location.snippet,
    kind: location.kind,
    epistemic: location.epistemic,
    confidence: location.confidence,
  });
}

export function findingFingerprint(finding) {
  const sink = finding.sink || finding.evidence?.at(-1);
  return `fp_${digest({
    file: String(finding.file || "").replace(/\\/g, "/"),
    line: finding.line,
    column: sink?.column || 1,
    content_sha256: sink?.content_sha256,
    kind: finding.kind,
  }).slice(0, 24)}`;
}

export function dedupeFindings(findings) {
  const merged = new Map();
  for (const finding of findings || []) {
    const fingerprint = findingFingerprint(finding);
    const previous = merged.get(fingerprint);
    const chains = finding.chains || (finding.chain?.length ? [finding.chain] : []);
    if (!previous) {
      merged.set(fingerprint, {
        ...finding,
        fingerprint,
        evidence: mergeEvidence([], finding.evidence),
        chains: [...chains],
        sources: [...new Set([...(finding.sources || []), finding.source].filter(Boolean))],
      });
      continue;
    }
    previous.evidence = mergeEvidence(previous.evidence, finding.evidence);
    previous.chains = mergeRecords(previous.chains, chains);
    previous.sources = [...new Set([...previous.sources, ...(finding.sources || []), finding.source].filter(Boolean))];
    const rank = { unknown: 0, low: 1, medium: 2, high: 3 };
    if ((rank[finding.confidence] || 0) > (rank[previous.confidence] || 0)) previous.confidence = finding.confidence;
  }
  return [...merged.values()];
}

export function digest(value) {
  return hashBytes(stableStringify(value));
}

export function hashBytes(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

export function stableStringify(value) {
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).filter((key) => value[key] !== undefined).sort().map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function mergeEvidence(left = [], right = []) {
  const entries = new Map([...left, ...right].map((entry) => [entry.id, entry]));
  return [...entries.values()];
}

function mergeRecords(left = [], right = []) {
  const entries = new Map([...left, ...right].map((entry) => [digest(entry), entry]));
  return [...entries.values()];
}
