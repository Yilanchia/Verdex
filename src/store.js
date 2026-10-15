import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { renderReport } from "./report.js";
import { renderReportHtml } from "./report-html.js";

const DEFAULT_RUNS_DIRECTORY = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", ".verdex", "runs");

export function writeRun(analysis, outputDirectory = DEFAULT_RUNS_DIRECTORY, brief = null) {
  if (!analysis || typeof analysis !== "object") throw new Error("Analysis result is required");
  const root = path.resolve(outputDirectory);
  const runName = `run-${new Date().toISOString().replace(/[:.]/g, "-")}-${analysis.analysis_id?.slice(-8) || "latest"}`;
  const directory = path.join(root, runName);
  fs.mkdirSync(directory, { recursive: true });
  fs.writeFileSync(path.join(directory, "analysis.json"), `${JSON.stringify({ ...analysis, brief }, null, 2)}\n`, "utf8");
  fs.writeFileSync(path.join(directory, "findings.json"), `${JSON.stringify(analysis.scan?.findings || [], null, 2)}\n`, "utf8");
  fs.writeFileSync(path.join(directory, "osint.json"), `${JSON.stringify(analysis.osint || {}, null, 2)}\n`, "utf8");
  fs.writeFileSync(path.join(directory, "report.md"), renderReport(analysis, brief), "utf8");
  fs.writeFileSync(path.join(directory, "report.html"), renderReportHtml(analysis, brief), "utf8");
  fs.writeFileSync(path.join(root, "LATEST.txt"), `${directory}\n`, "utf8");
  return { directory, analysis: path.join(directory, "analysis.json"), findings: path.join(directory, "findings.json"), osint: path.join(directory, "osint.json"), report: path.join(directory, "report.md"), report_html: path.join(directory, "report.html") };
}

export function listRuns(outputDirectory = DEFAULT_RUNS_DIRECTORY, limit = 20) {
  const root = path.resolve(outputDirectory);
  if (!fs.existsSync(root)) return [];
  return fs.readdirSync(root, { withFileTypes: true })
    .filter((entry) => entry.isDirectory() && /^run-[A-Za-z0-9_-]+$/.test(entry.name))
    .map((entry) => readRunSummary(root, entry.name))
    .filter(Boolean)
    .sort((left, right) => right.saved_at.localeCompare(left.saved_at))
    .slice(0, Math.max(1, Math.min(Number(limit) || 20, 100)));
}

export function readRunReport(outputDirectory, runId) {
  const directory = resolveRunDirectory(outputDirectory, runId);
  return fs.readFileSync(path.join(directory, "report.md"), "utf8");
}

function readRunSummary(root, runId) {
  const directory = resolveRunDirectory(root, runId);
  try {
    const analysis = JSON.parse(fs.readFileSync(path.join(directory, "analysis.json"), "utf8"));
    return {
      id: runId,
      analysis_id: analysis.analysis_id || "unknown",
      generated_at: analysis.generated_at || null,
      saved_at: fs.statSync(directory).mtime.toISOString(),
      root: analysis.root || "unknown",
      file_count: Number(analysis.file_count || 0),
      asset_count: Number(analysis.assets?.items?.length || 0),
      finding_count: Number(analysis.scan?.findings?.length || 0),
      report_url: `/api/runs/${encodeURIComponent(runId)}/report`,
    };
  } catch {
    return null;
  }
}

function resolveRunDirectory(outputDirectory, runId) {
  if (!/^[A-Za-z0-9_-]+$/.test(String(runId || ""))) throw new Error("Invalid run id");
  const root = path.resolve(outputDirectory);
  const directory = path.resolve(root, runId);
  if (directory !== root && !directory.startsWith(root + path.sep)) throw new Error("Invalid run id");
  return directory;
}
