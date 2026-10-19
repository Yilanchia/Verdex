import fs from "node:fs";
import os from "node:os";
import path from "node:path";

// Pure-Node Electron .asar unpacker → file tree + inventory. .asar uses a
// Chromium Pickle header: u32[1] = header payload size; the JSON directory
// starts at offset 16 with length u32[3]; file data base = 8 + headerSize.
// Read-only: extracts files, runs nothing. Guards against path traversal.
const MAX_LISTED = 500;

function safeJoin(base, rel) {
  const target = path.resolve(base, rel);
  const baseResolved = path.resolve(base);
  if (target !== baseResolved && !target.startsWith(baseResolved + path.sep)) {
    throw new Error(`asar 条目路径越界(疑似穿越):${rel}`);
  }
  return target;
}

function readHeader(fd) {
  const h = Buffer.alloc(16);
  fs.readSync(fd, h, 0, 16, 0);
  const headerSize = h.readUInt32LE(4);   // Pickle payload size
  const jsonLen = h.readUInt32LE(12);      // length of the JSON string
  if (jsonLen <= 0 || jsonLen > 256 * 1024 * 1024) throw new Error("不像 asar(JSON 头长度异常)");
  const json = Buffer.alloc(jsonLen);
  fs.readSync(fd, json, 0, jsonLen, 16);
  const baseOffset = 8 + headerSize;        // where file data begins
  return { tree: JSON.parse(json.toString("utf8")), baseOffset };
}

function bucketOf(rel) {
  const ext = path.extname(rel).toLowerCase();
  if (ext === ".js" || ext === ".mjs" || ext === ".cjs") return "js";
  if (ext === ".json") return "json";
  if (ext === ".html" || ext === ".htm") return "html";
  if (ext === ".css") return "css";
  if (ext === ".node") return "native";
  return "other";
}

export function unpackAsar(value) {
  if (typeof value !== "string" || !value.trim()) throw new Error("参数 path 必须是本地 .asar 路径");
  const file = path.resolve(value);
  if (!fs.statSync(file).isFile()) throw new Error("path 必须指向一个文件");
  const fd = fs.openSync(file, "r");
  const work = fs.mkdtempSync(path.join(os.tmpdir(), "verdex-asar-"));
  try {
    const { tree, baseOffset } = readHeader(fd);
    const buckets = { js: [], json: [], html: [], css: [], native: [], other: [] };
    let count = 0;

    const walk = (node, prefix) => {
      if (!node || !node.files) return;
      for (const [name, entry] of Object.entries(node.files)) {
        const rel = prefix ? `${prefix}/${name}` : name;
        if (entry.files) { walk(entry, rel); continue; }
        if (count >= 20000) return;
        if (entry.offset === undefined || entry.unpacked) continue; // unpacked files live outside
        const off = baseOffset + Number(entry.offset);
        const size = Number(entry.size) || 0;
        const dest = safeJoin(work, rel);
        fs.mkdirSync(path.dirname(dest), { recursive: true });
        const b = Buffer.alloc(size);
        if (size > 0) fs.readSync(fd, b, 0, size, off);
        fs.writeFileSync(dest, b);
        buckets[bucketOf(rel)].push({ path: rel, size });
        count++;
      }
    };
    walk(tree, "");

    const inventory = Object.fromEntries(Object.entries(buckets).map(([k, v]) => [k, v.length]));
    return {
      schema: "VerdexElectron/v1",
      tool: "asar_unpack",
      file: path.basename(file),
      file_count: count,
      inventory,
      extracted_dir: work,
      js_files: buckets.js.slice(0, MAX_LISTED).map((f) => f.path),
      entrypoints: buckets.json.filter((f) => /(^|\/)package\.json$/.test(f.path)).map((f) => f.path),
      next_steps: {
        js: "scan / js_deobfuscate 分析主/渲染进程逻辑;Electron 的 node 集成是攻击面重点",
        native: ".node 原生插件 → bin_decompile",
        json: "package.json 看 main 入口、依赖;看有无 nodeIntegration/contextIsolation 配置",
      },
      limitations: [
        "只解包 .asar 并清点,未执行任何代码;已防路径穿越。",
        "unpacked(asar.unpacked)外置文件不在包内,需单独看同目录 app.asar.unpacked/。",
        "仅限你拥有或被授权分析的应用。",
      ],
    };
  } catch (err) {
    fs.rmSync(work, { recursive: true, force: true });
    throw err;
  } finally {
    fs.closeSync(fd);
  }
}

export const ELECTRON_TOOLS = [
  {
    name: "asar_unpack",
    description: "解包 Electron .asar 归档(纯 Node,防路径穿越,只读不执行):提取并清点 js/json/html/css/.node,js 可路由 js_deobfuscate,.node 原生插件可 bin_decompile。桌面 Electron 应用逆向入口。仅限你拥有或被授权的应用。",
    inputSchema: { type: "object", required: ["path"], properties: { path: { type: "string", description: "本地 .asar 文件路径(通常 resources/app.asar)。" } } },
    run: (args) => unpackAsar(args.path),
  },
];
