import path from "node:path";
import { extractAssets } from "./assets.js";
import { buildCodeGraph } from "./graph.js";
import { analyzeProject } from "./project.js";
import { loadBrief } from "./brief.js";
import { collectOsint } from "./osint.js";
import { writeRun } from "./store.js";
import { collectWorkspace, resolveRoot } from "./workspace.js";

const command = process.argv[2] || "scan";
process.stdout.on("error", (error) => {
  if (error.code === "EPIPE") process.exit(0);
  throw error;
});

if (command === "mcp") {
  const { startMcpServer } = await import("./mcp.js");
  startMcpServer();
} else {
  await runOnce();
}

async function runOnce() {
const root = resolveRoot(process.argv[3] || process.cwd());
const workspace = collectWorkspace(root);
let output;
if (command === "assets") output = extractAssets(workspace);
else if (command === "map") output = buildCodeGraph(root, { workspace, includeFlows: true });
else if (command === "osint") {
  const brief = process.argv[4] ? loadBrief(path.resolve(process.argv[4])) : null;
  output = collectOsint(workspace, brief ? { ...brief.osint } : {});
}
else if (command === "scan") {
  const brief = process.argv[4] ? loadBrief(path.resolve(process.argv[4])) : null;
  output = analyzeProject(root, brief ? { brief } : {});
}
else if (command === "report") {
  const outputDirectory = path.resolve(process.argv[4] || path.join(root, ".verdex"));
  const briefPath = process.argv[5];
  const brief = briefPath ? loadBrief(path.resolve(briefPath)) : null;
  const analysis = analyzeProject(root, brief ? { brief } : {});
  output = writeRun(analysis, outputDirectory, brief);
}
else throw new Error(`未知命令：${command}`);
process.stdout.write(`${JSON.stringify(output, null, 2)}\n`);
}
