import assert from "node:assert/strict";
import { execFile, spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const execFileAsync = promisify(execFile);
const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, "package.json"), "utf8"));

function readFirstLine(relative) {
  return fs.readFileSync(path.join(ROOT, relative), "utf8").split(/\r?\n/, 1)[0];
}

function spawnEntry(args) {
  const child = spawn(process.execPath, args, { cwd: ROOT, stdio: ["pipe", "pipe", "pipe"], windowsHide: true });
  const lines = [];
  const waiters = [];
  let buffer = "";
  child.stdout.setEncoding("utf8");
  child.stdout.on("data", (chunk) => {
    buffer += chunk;
    let index;
    while ((index = buffer.indexOf("\n")) >= 0) {
      const line = buffer.slice(0, index).trim();
      buffer = buffer.slice(index + 1);
      if (!line) continue;
      const waiter = waiters.shift();
      if (waiter) waiter(line);
      else lines.push(line);
    }
  });
  const nextLine = (timeoutMs = 20_000) =>
    new Promise((resolve, reject) => {
      if (lines.length) return resolve(lines.shift());
      const timer = setTimeout(() => reject(new Error("timed out waiting for MCP output")), timeoutMs);
      waiters.push((line) => {
        clearTimeout(timer);
        resolve(line);
      });
    });
  return { child, nextLine };
}

test("package metadata is publishable as verdex", () => {
  assert.equal(pkg.name, "verdex");
  assert.equal(pkg.private, undefined, "the package must not stay private");
  assert.match(pkg.version, /^\d+\.\d+\.\d+$/);
  assert.equal(pkg.license, "MIT");
  assert.equal(pkg.type, "module");
  assert.deepEqual(pkg.bin, { verdex: "src/cli.js", "verdex-mcp": "bin/verdex-mcp.mjs" });
  for (const entry of ["src", "web", "bin", "docs"]) {
    assert.ok(pkg.files.includes(entry), `files must ship ${entry}`);
  }
  assert.equal(pkg.repository.url, "https://github.com/Yilanchia/Verdex.git");
  assert.ok(pkg.scripts.test);
  assert.equal(pkg.scripts.prepublishOnly, "npm test");
  // typescript is a *runtime* dependency of the AST code graph; keep it.
  assert.equal(pkg.dependencies.typescript, "5.9.3");
});

test("both bin entry points start with a node shebang", () => {
  for (const entry of [pkg.bin.verdex, pkg.bin["verdex-mcp"]]) {
    assert.match(readFirstLine(entry), /^#!\/usr\/bin\/env node$/);
  }
});

test("CLI entry prints the package version and help", async () => {
  const { stdout: version } = await execFileAsync(process.execPath, [path.join(ROOT, "src/cli.js"), "--version"], { cwd: ROOT });
  assert.equal(version.trim(), pkg.version);
  const { stdout: help } = await execFileAsync(process.execPath, [path.join(ROOT, "src/cli.js"), "help"], { cwd: ROOT });
  assert.match(help, /verdex-mcp/);
  assert.match(help, /read-only/i);
});

test("bin/verdex-mcp.mjs speaks MCP over stdio", async () => {
  const { child, nextLine } = spawnEntry([path.join(ROOT, "bin", "verdex-mcp.mjs")]);
  try {
    child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2024-11-05" } })}\n`);
    const init = JSON.parse(await nextLine());
    assert.equal(init.result.protocolVersion, "2024-11-05");
    assert.equal(init.result.serverInfo.name, "verdex");
    assert.equal(init.result.serverInfo.version, pkg.version);
    assert.match(init.result.instructions, /read-only/);

    child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list" })}\n`);
    const list = JSON.parse(await nextLine());
    assert.ok(list.result.tools.length >= 35, "full tool surface is advertised");
    assert.ok(list.result.tools.every((tool) => tool.annotations.openWorldHint === false));
    assert.ok(list.result.tools.every((tool) => tool.annotations.destructiveHint === false));
    assert.ok(list.result.tools.some((tool) => tool.name === "analyze_target"));
  } finally {
    child.kill();
  }
});

test("distribution scaffolding ships verdex + verdex-mcp consistently", () => {
  const server = JSON.parse(fs.readFileSync(path.join(ROOT, "server.json"), "utf8"));
  assert.equal(server.name, "io.github.Yilanchia/verdex");
  assert.equal(server.version, pkg.version);
  assert.equal(server.repository.url, "https://github.com/Yilanchia/Verdex");
  assert.equal(server.packages.length, 1);
  const npmPackage = server.packages[0];
  assert.equal(npmPackage.registryType, "npm");
  assert.equal(npmPackage.identifier, "verdex-mcp");
  assert.equal(npmPackage.version, pkg.version);
  assert.equal(npmPackage.transport.type, "stdio");

  const wrapper = JSON.parse(fs.readFileSync(path.join(ROOT, "packages/verdex-mcp/package.json"), "utf8"));
  assert.equal(wrapper.name, "verdex-mcp");
  assert.equal(wrapper.version, pkg.version);
  assert.equal(wrapper.mcpName, server.name, "registry mcpName must equal the server name");
  assert.deepEqual(wrapper.bin, { "verdex-mcp": "bin.mjs" });
  assert.ok(wrapper.dependencies.verdex, "the entry package depends on the CLI package");
  assert.match(readFirstLine("packages/verdex-mcp/bin.mjs"), /^#!\/usr\/bin\/env node$/);
  assert.match(fs.readFileSync(path.join(ROOT, "packages/verdex-mcp/bin.mjs"), "utf8"), /from "verdex\/src\/mcp.js"/);

  const smithery = fs.readFileSync(path.join(ROOT, "smithery.yaml"), "utf8");
  assert.match(smithery, /type: stdio/);
  assert.match(smithery, /verdex-mcp/);

  const release = fs.readFileSync(path.join(ROOT, ".github/workflows/release.yml"), "utf8");
  assert.match(release, /npm publish --provenance --access public/);
  assert.match(release, /working-directory: packages\/verdex-mcp/);
  assert.match(release, /NPM_TOKEN/);
});

test("doctor reports local backends and a tool surface without network access", async () => {
  const { doctor } = await import("../src/doctor.js");
  const report = await doctor();
  assert.equal(report.schema, "VerdexDoctor/v1");
  assert.equal(report.package.name, "verdex");
  assert.equal(report.package.version, pkg.version);
  assert.ok(Number(report.runtime.node.split(".")[0]) >= 20, "doctor requires Node 20+");
  assert.ok(report.runtime.tools_visible >= 35);
  assert.ok(Array.isArray(report.backends) && report.backends.length >= 5);
  for (const backend of report.backends) {
    assert.ok(["ok", "partial", "missing"].includes(backend.status), `${backend.id} status`);
    assert.ok(Array.isArray(backend.affects));
  }
  const ids = report.backends.map((backend) => backend.id);
  for (const id of ["binutils", "ida", "ghidra", "jadx", "dotnet", "ilspy"]) {
    assert.ok(ids.includes(id), `doctor must check ${id}`);
  }
  assert.equal(report.summary.ok + report.summary.partial + report.summary.missing, report.backends.length);
});
