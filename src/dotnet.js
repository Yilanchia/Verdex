import fs from "node:fs";
import path from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const TIMEOUT_MS = 180_000;
const MAX_BUFFER = 48 * 1024 * 1024;
const MAX_LINES = 6000;

// Decompiles a .NET (CLR) assembly to C# via ILSpy's ilspycmd. Read-only:
// parses the assembly, never executes it. Closes the gap vs REA on .NET.

function resolveFile(value) {
  if (typeof value !== "string" || !value.trim()) throw new Error("参数 path 必须是本地 .NET 程序集路径");
  const file = path.resolve(value);
  if (!fs.statSync(file).isFile()) throw new Error("path 必须指向一个文件");
  return file;
}

// A managed assembly is a PE (MZ) whose CLR metadata root carries the "BSJB"
// signature. Cheap, reliable detector without full PE parsing.
export function isDotnetAssembly(file) {
  try {
    const fd = fs.openSync(file, "r");
    try {
      const head = Buffer.alloc(2); fs.readSync(fd, head, 0, 2, 0);
      if (head[0] !== 0x4d || head[1] !== 0x5a) return false; // not PE
      const size = fs.statSync(file).size;
      const cap = Math.min(size, 8 * 1024 * 1024);
      const buf = Buffer.alloc(cap); fs.readSync(fd, buf, 0, cap, 0);
      return buf.includes(Buffer.from("BSJB"));
    } finally { fs.closeSync(fd); }
  } catch { return false; }
}

function findDotnet() {
  for (const c of [process.env.VERDEX_DOTNET, "C:\\Program Files\\dotnet\\dotnet.exe", "/usr/bin/dotnet", "/usr/local/bin/dotnet"].filter(Boolean)) {
    try { if (fs.statSync(c).isFile()) return c; } catch { /* keep looking */ }
  }
  return "dotnet"; // fall back to PATH
}

function findIlspy() {
  for (const c of [process.env.VERDEX_ILSPY, "C:\\ilspycmd\\ilspycmd.dll", "/opt/ilspycmd/ilspycmd.dll"].filter(Boolean)) {
    try { if (fs.statSync(c).isFile()) return c; } catch { /* keep looking */ }
  }
  return null;
}

function clip(text) {
  const lines = String(text || "").split(/\r?\n/);
  const truncated = lines.length > MAX_LINES;
  return { text: truncated ? lines.slice(0, MAX_LINES).join("\n") : String(text || ""), truncated, total_lines: lines.length };
}

export async function dotnetDecompile(value, options = {}) {
  const file = resolveFile(value);
  if (!isDotnetAssembly(file)) throw new Error("不是 .NET 程序集(需 PE + BSJB 元数据签名);原生二进制请用 bin_decompile");
  const ilspy = findIlspy();
  if (!ilspy) throw new Error("后端未安装:未找到 ilspycmd;设置 VERDEX_ILSPY 指向 ilspycmd.dll(ILSpy 的 .NET tool)");
  const dotnet = findDotnet();
  const typeName = typeof options.typeName === "string" && /^[A-Za-z0-9_.`+<>]{1,256}$/.test(options.typeName) ? options.typeName : null;

  const args = [ilspy, file];
  if (typeName) args.push("-t", typeName);
  let stdout;
  try {
    ({ stdout } = await execFileAsync(dotnet, args, { timeout: TIMEOUT_MS, maxBuffer: MAX_BUFFER, windowsHide: true }));
  } catch (e) {
    if (e.stdout && e.stdout.length) stdout = e.stdout;
    else throw new Error(`ilspycmd 反编译失败:${String(e.message).split("\n")[0]}`);
  }
  const body = clip(stdout);
  return {
    schema: "VerdexDotnet/v1",
    tool: "dotnet_decompile",
    file: path.basename(file),
    authority: "local-binary-static",
    epistemic: "inferred",
    backend: "ilspy",
    type_filter: typeName,
    csharp: body.text,
    truncated: body.truncated,
    total_lines: body.total_lines,
    limitations: [
      "ILSpy 反编译得到的是 C# 重建,非原始源码;局部名/注释可能与原工程不同。",
      "只静态反编译,未执行该程序集,未访问网络。",
      typeName ? null : "未指定 typeName 时输出整程序集(已截断);用 typeName 聚焦某个类型。",
    ].filter(Boolean),
  };
}

export const DOTNET_TOOLS = [
  {
    name: "dotnet_decompile",
    description: ".NET/CLR 程序集(.dll/.exe)反编译成 C#(ILSpy/ilspycmd 后端,只读不执行)。可选 typeName 聚焦某类型(如 System.Guid),不传则全量(截断)。需装 ilspycmd(VERDEX_ILSPY 指向 ilspycmd.dll)+ 对应 .NET runtime。处理 C#/VB/F# 编译出的托管程序集。",
    inputSchema: { type: "object", required: ["path"], properties: { path: { type: "string", description: "本地 .NET 程序集路径(.dll/.exe)。" }, typeName: { type: "string", description: "可选:只反编译该类型(含命名空间,如 Namespace.ClassName)。" } } },
    run: (args) => dotnetDecompile(args.path, { typeName: args.typeName }),
  },
];
