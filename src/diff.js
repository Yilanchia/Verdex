import fs from "node:fs";
import path from "node:path";
import { findingFingerprint } from "./evidence.js";

const SEV = ["critical", "high", "medium", "low", "info"];

// Compares two immutable run snapshots by finding fingerprint, so a team can
// track which candidates are new, which were fixed, and which still stand
// between two scans. Read-only: reads findings.json from each run directory.
function readFindings(dir) {
  const root = path.resolve(dir);
  const candidates = [path.join(root, "findings.json"), path.join(root, "analysis.json")];
  for (const file of candidates) {
    if (!fs.existsSync(file)) continue;
    const data = JSON.parse(fs.readFileSync(file, "utf8"));
    const findings = Array.isArray(data) ? data : (data.scan?.findings || data.findings || []);
    return findings.map((f) => ({ ...f, fingerprint: f.fingerprint || findingFingerprint(f) }));
  }
  throw new Error(`在 ${dir} 下未找到 findings.json 或 analysis.json`);
}

function tally(findings) {
  const counts = Object.fromEntries(SEV.map((s) => [s, 0]));
  for (const f of findings) counts[String(f.severity || "info").toLowerCase()] = (counts[String(f.severity || "info").toLowerCase()] ?? 0) + 1;
  return counts;
}

function slim(f) {
  return { fingerprint: f.fingerprint, severity: f.severity || "info", kind: f.kind, title: f.title, file: f.file, line: f.line };
}

export function diffRuns(baseDir, headDir) {
  const base = readFindings(baseDir);
  const head = readFindings(headDir);
  const baseMap = new Map(base.map((f) => [f.fingerprint, f]));
  const headMap = new Map(head.map((f) => [f.fingerprint, f]));

  const added = head.filter((f) => !baseMap.has(f.fingerprint)).map(slim);
  const fixed = base.filter((f) => !headMap.has(f.fingerprint)).map(slim);
  const unchanged = head.filter((f) => baseMap.has(f.fingerprint)).map(slim);

  const rank = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const bySev = (a, b) => (rank[a.severity] ?? 9) - (rank[b.severity] ?? 9);
  added.sort(bySev); fixed.sort(bySev); unchanged.sort(bySev);

  return {
    schema: "VerdexDiff/v1",
    authority: "local-run-comparison",
    epistemic: "inferred",
    base: { dir: path.resolve(baseDir), finding_count: base.length, by_severity: tally(base) },
    head: { dir: path.resolve(headDir), finding_count: head.length, by_severity: tally(head) },
    summary: { added: added.length, fixed: fixed.length, unchanged: unchanged.length },
    added,
    fixed,
    unchanged,
    limitations: [
      "按证据指纹(文件/行/列/内容哈希/类型)比对;重构或大改动可能让同一问题指纹变化而被记为 fixed+added。",
      "候选仍是待复核的静态推断,diff 只反映两次快照之间的候选集合变化。",
    ],
  };
}
