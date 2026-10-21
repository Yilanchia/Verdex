import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import { analyzeProject } from "./project.js";
import { loadBrief } from "./brief.js";
import { searchPersonalInfo } from "./personal.js";
import { getAiSettings, saveAiSettings, reviewWithAi } from "./ai.js";
import { listRuns, readRunReport, writeRun } from "./store.js";
import { resolveRoot } from "./workspace.js";

const SOURCE_DIRECTORY = path.dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = path.resolve(SOURCE_DIRECTORY, "..");
const WEB_ROOT = path.join(PROJECT_ROOT, "web");
const DEFAULT_HOST = "127.0.0.1";
const DEFAULT_PORT = 3210;
const MAX_BODY_BYTES = 64 * 1024;
const execFileAsync = promisify(execFile);

export function createServer(options = {}) {
  const host = options.host || DEFAULT_HOST;
  const port = Number(options.port || DEFAULT_PORT);
  const runsDirectory = options.runsDirectory || path.join(PROJECT_ROOT, ".verdex", "runs");
  let latestAnalysis = null;
  return http.createServer(async (request, response) => {
    try {
      if (!isLocalRequest(request, host)) {
        return sendJson(response, 403, { error: "仅允许本机访问工作台" });
      }
      const requestUrl = new URL(request.url || "/", "http://" + (request.headers.host || host));
      if (request.method === "GET" && requestUrl.pathname === "/api/health") {
        return sendJson(response, 200, {
          name: "Verdex",
          schema: "VerdexUI/v1",
          root: PROJECT_ROOT,
          defaultBrief: path.join(PROJECT_ROOT, "brief.example.json"),
          networkRequests: false,
          ai: getAiSettings(),
        });
      }
      if (request.method === "GET" && requestUrl.pathname === "/api/ai/settings") return sendJson(response, 200, getAiSettings());
      if (request.method === "GET" && requestUrl.pathname === "/api/runs") return sendJson(response, 200, { schema: "VerdexRuns/v1", runs: listRuns(runsDirectory) });
      const reportMatch = requestUrl.pathname.match(/^\/api\/runs\/([^/]+)\/report$/);
      if (request.method === "GET" && reportMatch) {
        const runId = decodeURIComponent(reportMatch[1]);
        return sendText(response, 200, readRunReport(runsDirectory, runId), {
          "Content-Type": "text/markdown; charset=utf-8",
          "Content-Disposition": `attachment; filename="${runId}.md"`,
        });
      }
      if (request.method === "POST" && requestUrl.pathname === "/api/analyze") {
        const body = await readJson(request);
        const root = resolveRoot(body.root || PROJECT_ROOT);
        const brief = body.briefPath ? loadBrief(path.resolve(String(body.briefPath))) : null;
        const analysis = analyzeProject(root, { ...(brief ? { brief } : {}), manualAssets: body.manualAssets || [] });
        latestAnalysis = analysis;
        return sendJson(response, 200, analysis);
      }
      if (request.method === "POST" && requestUrl.pathname === "/api/save-run") {
        if (!latestAnalysis) throw new Error("请先完成一次分析");
        const review = normalizeReview((await readJson(request)).review);
        const snapshot = { ...latestAnalysis, ...(Object.keys(review).length ? { review } : {}) };
        const result = writeRun(snapshot, runsDirectory, latestAnalysis.brief || null);
        return sendJson(response, 200, {
          schema: "VerdexRun/v1",
          id: path.basename(result.directory),
          analysis_id: latestAnalysis.analysis_id,
          report_url: `/api/runs/${encodeURIComponent(path.basename(result.directory))}/report`,
        });
      }
      if (request.method === "POST" && requestUrl.pathname === "/api/select-directory") {
        return sendJson(response, 200, { path: await selectDirectory() });
      }
      if (request.method === "POST" && requestUrl.pathname === "/api/personal-search") {
        const body = await readJson(request);
        const root = resolveRoot(body.root || PROJECT_ROOT);
        return sendJson(response, 200, searchPersonalInfo(root, { queries: body.queries || [], reveal: body.reveal === true }));
      }
      if (request.method === "POST" && requestUrl.pathname === "/api/ai/settings") return sendJson(response, 200, saveAiSettings(await readJson(request)));
      if (request.method === "POST" && requestUrl.pathname === "/api/ai/review") return sendJson(response, 200, await reviewWithAi(await readJson(request)));
      if (request.method === "GET") return serveStatic(requestUrl.pathname, response);
      return sendJson(response, 405, { error: "Method not allowed" });
    } catch (error) {
      const status = error?.code === "PAYLOAD_TOO_LARGE" ? 413 : 400;
      return sendJson(response, status, { error: error?.message || "Request failed" });
    }
  });
}

function normalizeReview(value) {
  const statuses = new Set(["needs-review", "confirmed", "false-positive", "accepted-risk"]);
  if (!value || typeof value !== "object" || Array.isArray(value)) return {};
  return Object.entries(value).slice(0, 500).reduce((result, [fingerprint, entry]) => {
    if (!/^fp_[a-f0-9]{24}$/.test(fingerprint) || !entry || typeof entry !== "object") return result;
    const status = statuses.has(entry.status) ? entry.status : "needs-review";
    const note = String(entry.note || "").trim().slice(0, 2000);
    if (status !== "needs-review" || note) result[fingerprint] = { status, ...(note ? { note } : {}) };
    return result;
  }, {});
}

async function selectDirectory() {
  if (process.platform !== "win32") throw new Error("系统目录选择器目前仅支持 Windows，请直接输入本地目录路径");
  const script = [
    "$ErrorActionPreference='Stop'",
    "Add-Type -AssemblyName System.Windows.Forms",
    "$dialog=New-Object System.Windows.Forms.FolderBrowserDialog",
    "$dialog.Description='选择要分析的本地工作目录'",
    "$dialog.ShowNewFolderButton=$false",
    "if($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK){[Console]::Write($dialog.SelectedPath)}",
  ].join(";");
  const result = await execFileAsync("powershell.exe", ["-NoProfile", "-STA", "-Command", script], { windowsHide: false, timeout: 120_000, maxBuffer: 16 * 1024 });
  const selected = result.stdout.trim();
  if (!selected) throw new Error("未选择工作目录");
  return resolveRoot(selected);
}

export function startServer(options = {}) {
  const host = options.host || DEFAULT_HOST;
  const port = Number(options.port || DEFAULT_PORT);
  const server = createServer({ host, port });
  server.listen(port, host, () => {
    process.stdout.write("Verdex running at http://" + host + ":" + port + "\n");
    process.stdout.write("Local-only mode: network requests are disabled.\n");
  });
  return server;
}

async function readJson(request) {
  const chunks = [];
  let total = 0;
  for await (const chunk of request) {
    total += chunk.length;
    if (total > MAX_BODY_BYTES) {
      const error = new Error("Request body is too large");
      error.code = "PAYLOAD_TOO_LARGE";
      throw error;
    }
    chunks.push(chunk);
  }
  if (!chunks.length) return {};
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    throw new Error("Request body must be valid JSON");
  }
}

function serveStatic(requestPath, response) {
  const pathname = requestPath === "/" ? "/index.html" : requestPath;
  const decoded = decodeURIComponent(pathname);
  const filePath = path.resolve(WEB_ROOT, "." + decoded);
  if (filePath !== WEB_ROOT && !filePath.startsWith(WEB_ROOT + path.sep)) {
    return sendJson(response, 403, { error: "Forbidden" });
  }
  if (!fs.existsSync(filePath) || !fs.statSync(filePath).isFile()) {
    return sendJson(response, 404, { error: "Not found" });
  }
  const contentType = {
    ".css": "text/css; charset=utf-8",
    ".html": "text/html; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".svg": "image/svg+xml",
  }[path.extname(filePath).toLowerCase()] || "text/plain; charset=utf-8";
  response.writeHead(200, securityHeaders({ "Content-Type": contentType, "Cache-Control": "no-store" }));
  fs.createReadStream(filePath).pipe(response);
}

function sendJson(response, status, value) {
  response.writeHead(status, securityHeaders({
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
  }));
  response.end(JSON.stringify(value));
}

function sendText(response, status, value, headers = {}) {
  response.writeHead(status, securityHeaders({ ...headers, "Cache-Control": "no-store" }));
  response.end(value);
}

function securityHeaders(headers = {}) {
  return {
    ...headers,
    "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
  };
}

function isLocalRequest(request, configuredHost) {
  if (!isLoopbackAddress(request.socket.remoteAddress)) return false;
  const requestHost = normalizeRequestHost(request.headers.host || "");
  if (!requestHost || !isAllowedLocalHost(requestHost.hostname, configuredHost)) return false;
  const origin = request.headers.origin;
  if (!origin) return true;
  try {
    const originUrl = new URL(origin);
    const originHost = originUrl.hostname.replace(/^\[|\]$/g, "").toLowerCase();
    const originPort = originUrl.port || "80";
    const requestPort = requestHost.port || "80";
    return originUrl.protocol === "http:" && originPort === requestPort && isAllowedLocalHost(originHost, configuredHost);
  } catch {
    return false;
  }
}

function normalizeRequestHost(value) {
  const text = String(value).trim();
  if (!text) return null;
  try {
    const url = new URL("http://" + text);
    return { hostname: url.hostname.replace(/^\[|\]$/g, "").toLowerCase(), port: url.port };
  } catch {
    return null;
  }
}

function isAllowedLocalHost(hostname, configuredHost) {
  const normalized = String(hostname || "").replace(/^\[|\]$/g, "").toLowerCase();
  const configured = String(configuredHost || "").replace(/^\[|\]$/g, "").toLowerCase();
  return normalized === configured || normalized === "localhost" || normalized === "127.0.0.1" || normalized === "::1";
}

function isLoopbackAddress(address) {
  const normalized = String(address || "").replace(/^::ffff:/i, "");
  return normalized === "::1" || normalized === "127.0.0.1" || /^127\./.test(normalized);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const portIndex = process.argv.indexOf("--port");
  const hostIndex = process.argv.indexOf("--host");
  startServer({
    port: portIndex >= 0 ? process.argv[portIndex + 1] : DEFAULT_PORT,
    host: hostIndex >= 0 ? process.argv[hostIndex + 1] : DEFAULT_HOST,
  });
}
