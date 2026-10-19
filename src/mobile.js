import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { manifestSummary } from "./axml.js";

const execFileAsync = promisify(execFile);

// Read-only mobile-package unpacker. APK/IPA/JAR/AAB are ZIP archives; this
// extracts one to a temp dir and inventories its contents, routing each file
// type to the right Verdex tool. It NEVER executes anything inside the package.
const EXTRACT_TIMEOUT_MS = 120_000;
const MAX_BUFFER = 32 * 1024 * 1024;
const MAX_LISTED = 500;

function isZip(file) {
  const fd = fs.openSync(file, "r");
  try {
    const buf = Buffer.alloc(2);
    fs.readSync(fd, buf, 0, 2, 0);
    return buf[0] === 0x50 && buf[1] === 0x4b; // "PK"
  } finally {
    fs.closeSync(fd);
  }
}

function packageKind(file) {
  const ext = path.extname(file).toLowerCase();
  if (ext === ".apk") return "android-apk";
  if (ext === ".aab") return "android-aab";
  if (ext === ".ipa") return "ios-ipa";
  if (ext === ".jar") return "java-jar";
  if (ext === ".xapk") return "android-xapk";
  return "zip";
}

function machoOrElf(file) {
  try {
    const fd = fs.openSync(file, "r");
    try {
      const b = Buffer.alloc(4);
      fs.readSync(fd, b, 0, 4, 0);
      if (b[0] === 0x7f && b[1] === 0x45 && b[2] === 0x4c && b[3] === 0x46) return "elf";
      const be = b.readUInt32BE(0);
      if ([0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe, 0xcafebabe, 0xbebafeca].includes(be)) return "macho";
    } finally { fs.closeSync(fd); }
  } catch { /* ignore */ }
  return null;
}

function classify(rel, abs) {
  const lower = rel.toLowerCase();
  const ext = path.extname(lower);
  if (ext === ".so" || ext === ".dylib" || /\/lib[^/]+\.(so|dylib)/.test("/" + lower)) return "native";
  if (ext === ".dex") return "dex";
  if (/\.(js|wxs)$/.test(lower)) return "js";
  if (ext === ".wxapkg") return "miniprogram";
  if (/(^|\/)(androidmanifest\.xml|info\.plist)$/.test(lower)) return "manifest";
  if (/\.(wxml|wxss|json|xml|plist)$/.test(lower)) return "resource";
  // Extensionless files inside Payload/*.app or lib/ may be native (iOS exec / stripped .so)
  if (!ext) { const m = machoOrElf(abs); if (m) return "native"; }
  return "other";
}

function dirHasFiles(dir) {
  try { return fs.readdirSync(dir).length > 0; } catch { return false; }
}

async function extractZip(archive, dest) {
  // unzip exits non-zero on mere warnings (e.g. backslash paths) but still
  // extracts; judge success by whether files landed, not by exit code.
  const attempts = [
    ["unzip", ["-o", "-q", archive, "-d", dest]],
    ["tar", ["--force-local", "-xf", archive, "-C", dest]],
  ];
  const errors = [];
  for (const [cmd, args] of attempts) {
    try {
      await execFileAsync(cmd, args, { timeout: EXTRACT_TIMEOUT_MS, maxBuffer: MAX_BUFFER, windowsHide: true });
      if (dirHasFiles(dest)) return cmd;
    } catch (e) {
      errors.push(`${cmd}: ${e.message.split("\n")[0]}`);
      if (dirHasFiles(dest)) return cmd; // warning exit but files extracted
    }
  }
  throw new Error(`解包失败(${errors.join(" / ")})`);
}

function walk(dir, base, acc) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const abs = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(abs, base, acc);
    else if (entry.isFile()) acc.push({ rel: path.relative(base, abs).replace(/\\/g, "/"), abs, size: fs.statSync(abs).size });
  }
}

// Commercial Android packer/hardening fingerprints (by .so name / asset path).
const PACKER_SIGS = [
  { name: "网易易盾 (NetEase Yidun)", rx: /lib(nesec|nshelper|neguard|dexfix)\b/i },
  { name: "爱加密 (Ijiami)", rx: /lib(ijiami|exec(main)?)\b|ijiami[^/]*\.(dat|vdata)$|\.VData$/i },
  { name: "梆梆安全 (Bangcle)", rx: /lib(secexe|secmain|DexHelper|SecShell)\b/i },
  { name: "腾讯乐固 (Tencent Legu)", rx: /lib(shell[a-z]*|tup|tosprotection|mobisec)\b/i },
  { name: "360 加固保 (Qihoo)", rx: /lib(jiagu[a-z]*|protectClass)\b/i },
  { name: "百度加固 (Baidu)", rx: /libbaiduprotect\b/i },
  { name: "娜迦 (Nagain)", rx: /lib(chaosvmp|ddog|fdog)\b/i },
  { name: "几维安全 (Kiwi)", rx: /lib(kwscmm|kwscr|KiwiProtect)\b/i },
];

export function detectPackers(relPaths) {
  const hits = [];
  for (const sig of PACKER_SIGS) {
    const matched = relPaths.filter((p) => sig.rx.test(p)).slice(0, 5);
    if (matched.length) hits.push({ packer: sig.name, evidence: matched });
  }
  return hits;
}

const NEXT_TOOL = {
  native: "bin_decompile / bin_info / bin_disasm(ELF/Mach-O 原生库,直接能逆)",
  dex: "需 jadx/apktool 转 Java(Verdex 暂未内置 DEX 后端)",
  js: "scan / map(前端逻辑;若压缩混淆需反混淆,暂未内置)",
  miniprogram: "需 wxapkg 解包(暂未内置)",
  manifest: "人工查看权限/入口/组件暴露面",
};

export async function unpackMobile(value) {
  if (typeof value !== "string" || !value.trim()) throw new Error("参数 path 必须是本地安装包路径");
  const archive = path.resolve(value);
  if (!fs.statSync(archive).isFile()) throw new Error("path 必须指向一个文件");
  if (!isZip(archive)) {
    if (path.extname(archive).toLowerCase() === ".wxapkg") throw new Error("这是微信小程序包,请用 wxapkg_unpack 工具解包");
    throw new Error("不是 ZIP 容器(APK/IPA/JAR/AAB 应以 PK 开头)");
  }

  const kind = packageKind(archive);
  const work = fs.mkdtempSync(path.join(os.tmpdir(), "verdex-mobile-"));
  try {
    const extractor = await extractZip(archive, work);
    const files = [];
    walk(work, work, files);

    const buckets = { native: [], dex: [], js: [], miniprogram: [], manifest: [], resource: [], other: [] };
    for (const f of files) buckets[classify(f.rel, f.abs)].push({ path: f.rel, size: f.size });

    // Copy native libs out so paths survive temp cleanup and can be fed to bin_decompile.
    const keepDir = fs.mkdtempSync(path.join(os.tmpdir(), "verdex-native-"));
    const native = buckets.native.slice(0, 200).map((n) => {
      const out = path.join(keepDir, path.basename(n.path));
      try { fs.copyFileSync(path.join(work, n.path), out); } catch { /* skip */ }
      return { path: n.path, size: n.size, extracted_to: out, format: machoOrElf(out) };
    });

    const inventory = {};
    for (const [k, v] of Object.entries(buckets)) inventory[k] = v.length;

    const packers = detectPackers(files.map((f) => f.rel));

    // Decode the binary AndroidManifest (if present) into an attack-surface view.
    let manifest = null;
    const mf = files.find((f) => /(^|\/)androidmanifest\.xml$/i.test(f.rel));
    if (mf) {
      try { manifest = manifestSummary(fs.readFileSync(mf.abs)); }
      catch (e) { manifest = { error: `AndroidManifest 解析失败:${e.message}` }; }
    }

    return {
      schema: "VerdexMobile/v1",
      tool: "mobile_unpack",
      file: path.basename(archive),
      package_kind: kind,
      extractor,
      file_count: files.length,
      inventory,
      ...(packers.length ? { detected_packers: packers, packer_note: "检测到商业加固:业务 dex 很可能被加密,jadx 只能看到壳;拿业务层需在授权设备上脱壳(超出 Verdex 静态范围)。" } : {}),
      ...(manifest ? { manifest } : {}),
      native_libs: native,
      dex_files: buckets.dex.slice(0, 50),
      js_files: buckets.js.slice(0, MAX_LISTED),
      miniprogram_bundles: buckets.miniprogram.slice(0, 50),
      manifests: buckets.manifest,
      next_steps: NEXT_TOOL,
      limitations: [
        "只解包并清点本地安装包内容,未执行包内任何代码。",
        "native 原生库已复制到 extracted_to,可直接喂给 bin_decompile;DEX/小程序/混淆 JS 的后端尚未内置。",
        "仅限你拥有或被明确授权分析的 app;禁止用于未授权目标。",
      ],
      extracted_native_dir: keepDir,
    };
  } finally {
    fs.rmSync(work, { recursive: true, force: true });
  }
}

// Parses the WeChat mini-program .wxapkg container (custom binary format):
//   [0] firstMark=0xBE  [1..4] info1(u32 BE)  [5..8] indexInfoLength
//   [9..12] bodyInfoLength  [13] lastMark=0xED
//   [14..17] fileCount(u32 BE)
//   then fileCount entries: nameLen(u32) name offset(u32) size(u32)
//   then the data section. Pure parse — no execution.
function safeJoin(base, rel) {
  const clean = String(rel).replace(/^[/\\]+/, "").replace(/\\/g, "/");
  const target = path.resolve(base, clean);
  const baseResolved = path.resolve(base);
  if (target !== baseResolved && !target.startsWith(baseResolved + path.sep)) {
    throw new Error(`wxapkg 条目路径越界(疑似路径穿越):${rel}`);
  }
  return target;
}

export function unpackWxapkg(value) {
  if (typeof value !== "string" || !value.trim()) throw new Error("参数 path 必须是本地 .wxapkg 路径");
  const file = path.resolve(value);
  if (!fs.statSync(file).isFile()) throw new Error("path 必须指向一个文件");
  const buf = fs.readFileSync(file);
  if (buf.length < 18 || buf[0] !== 0xbe || buf[13] !== 0xed) {
    throw new Error("不是有效 wxapkg(头标记 0xBE / 尾标记 0xED 不匹配)");
  }
  const fileCount = buf.readUInt32BE(14);
  if (fileCount <= 0 || fileCount > 100000) throw new Error(`wxapkg 文件数异常:${fileCount}`);

  const work = fs.mkdtempSync(path.join(os.tmpdir(), "verdex-wxapkg-"));
  let pos = 18;
  const entries = [];
  try {
    for (let i = 0; i < fileCount; i++) {
      const nameLen = buf.readUInt32BE(pos); pos += 4;
      if (nameLen <= 0 || nameLen > 4096 || pos + nameLen + 8 > buf.length) throw new Error("wxapkg 索引越界(文件可能损坏)");
      const name = buf.toString("utf8", pos, pos + nameLen); pos += nameLen;
      const offset = buf.readUInt32BE(pos); pos += 4;
      const size = buf.readUInt32BE(pos); pos += 4;
      if (offset < 0 || size < 0 || offset + size > buf.length) throw new Error(`wxapkg 数据区越界:${name}`);
      const dest = safeJoin(work, name);
      fs.mkdirSync(path.dirname(dest), { recursive: true });
      fs.writeFileSync(dest, buf.subarray(offset, offset + size));
      entries.push({ path: name.replace(/^[/\\]+/, ""), size });
    }

    const buckets = { js: [], wxml: [], wxss: [], json: [], other: [] };
    for (const e of entries) {
      const ext = path.extname(e.path).toLowerCase();
      const k = ext === ".js" ? "js" : ext === ".wxml" ? "wxml" : ext === ".wxss" ? "wxss" : ext === ".json" ? "json" : "other";
      buckets[k].push(e);
    }
    const inventory = Object.fromEntries(Object.entries(buckets).map(([k, v]) => [k, v.length]));
    return {
      schema: "VerdexMobile/v1",
      tool: "wxapkg_unpack",
      file: path.basename(file),
      file_count: entries.length,
      inventory,
      extracted_dir: work,
      js_files: buckets.js.slice(0, MAX_LISTED),
      entries: entries.slice(0, MAX_LISTED),
      next_steps: {
        js: "scan / map 分析小程序逻辑(appservice/page 脚本);若压缩混淆需反混淆(暂未内置)",
        wxml_wxss: "人工查看页面结构与样式",
        json: "app.json/页面配置:看路由、权限、分包、接口域名",
      },
      limitations: [
        "只解包 wxapkg 并清点,未执行任何小程序代码;已防路径穿越。",
        "小程序 JS 常经压缩/混淆,深入分析需后续反混淆能力。",
        "仅限你拥有或被授权分析的小程序;禁止用于未授权目标。",
      ],
    };
  } catch (err) {
    fs.rmSync(work, { recursive: true, force: true });
    throw err;
  }
}

// Recovers structure from Kotlin @DebugMetadata / @Metadata annotations when a
// method body fails to decompile ("Method not decompiled"). Kotlin writes local
// variable names, suspend-point line numbers, and the class member list into
// these annotations — recoverable even when jadx can't reconstruct the body.
function parseStringArray(block, key) {
  const m = block.match(new RegExp(key + "\\s*=\\s*\\{([\\s\\S]*?)\\}"));
  if (!m) return [];
  return [...m[1].matchAll(/"((?:\\.|[^"\\])*)"/g)].map((x) => x[1]).filter(Boolean);
}
function parseIntArray(block, key) {
  const m = block.match(new RegExp(key + "\\s*=\\s*\\{([^}]*)\\}"));
  if (!m) return [];
  return [...m[1].matchAll(/-?\d+/g)].map((x) => Number(x[0]));
}
function grabAnnotation(text, name) {
  // Match @Name( ... ) balancing to the closing paren of the annotation.
  const start = text.indexOf("@" + name + "(");
  if (start === -1) return null;
  let i = text.indexOf("(", start), depth = 0;
  for (; i < text.length; i++) {
    if (text[i] === "(") depth++;
    else if (text[i] === ")") { depth--; if (depth === 0) return text.slice(start, i + 1); }
  }
  return null;
}

export function recoverAnnotations(javaText) {
  const failed = [...javaText.matchAll(/Method not decompiled:\s*([^\s"]+)/g)].map((m) => m[1]);
  const dbg = grabAnnotation(javaText, "DebugMetadata");
  const meta = grabAnnotation(javaText, "Metadata");
  const result = {
    undecompiled_methods: [...new Set(failed)],
    debug_metadata: dbg ? {
      source_file: (dbg.match(/f\s*=\s*"([^"]*)"/) || [])[1] || null,
      coroutine: (dbg.match(/c\s*=\s*"([^"]*)"/) || [])[1] || null,
      suspend_point_lines: parseIntArray(dbg, "l"),
      local_variable_names: parseStringArray(dbg, "n"),
    } : null,
    member_names: meta ? parseStringArray(meta, "d2") : [],
  };
  const vars = result.debug_metadata?.local_variable_names || [];
  result.summary = failed.length
    ? `${failed.length} 个方法未反编译;从注解恢复 ${vars.length} 个局部变量名 + ${result.member_names.length} 个类成员名(足以推断逻辑结构)`
    : "无反编译失败的方法";
  return result;
}

// Locates the jadx DEX→Java decompiler. Set VERDEX_JADX to bin/jadx[.bat].
const JADX_CANDIDATES = [
  "C:\\jadx\\bin\\jadx.bat",
  "/opt/jadx/bin/jadx",
  "/usr/local/bin/jadx",
];

function findJadx() {
  const env = process.env.VERDEX_JADX;
  for (const c of [env, ...JADX_CANDIDATES].filter(Boolean)) {
    try { if (fs.statSync(c).isFile()) return c; } catch { /* keep looking */ }
  }
  return null;
}

// Decompiles an APK or .dex to Java via jadx (read-only; jadx never runs the
// app). Returns a package/class inventory and, if className given, that source.
export async function dexDecompile(value, options = {}) {
  if (typeof value !== "string" || !value.trim()) throw new Error("参数 path 必须是本地 APK/dex 路径");
  const target = path.resolve(value);
  if (!fs.statSync(target).isFile()) throw new Error("path 必须指向一个文件");
  const jadx = findJadx();
  if (!jadx) throw new Error("后端未安装:未找到 jadx;设置环境变量 VERDEX_JADX 指向 bin/jadx(.bat)");

  const outDir = fs.mkdtempSync(path.join(os.tmpdir(), "verdex-jadx-"));
  try {
    const jadxArgs = ["--no-res", "-d", outDir, target];
    const [cmd, args] = jadx.toLowerCase().endsWith(".bat")
      ? [process.env.ComSpec || "cmd.exe", ["/c", jadx, ...jadxArgs]]
      : [jadx, jadxArgs];
    await execFileAsync(cmd, args, { timeout: EXTRACT_TIMEOUT_MS, maxBuffer: MAX_BUFFER, windowsHide: true })
      .catch((e) => { if (!fs.existsSync(path.join(outDir, "sources"))) throw new Error(`jadx 反编译失败:${e.message.split("\n")[0]}`); });

    const srcRoot = path.join(outDir, "sources");
    const javaFiles = [];
    if (fs.existsSync(srcRoot)) walk(srcRoot, srcRoot, javaFiles);
    const java = javaFiles.filter((f) => f.rel.endsWith(".java"));

    const wanted = typeof options.className === "string" ? options.className.replace(/\./g, "/") : null;
    let sourceText = null;
    if (wanted) {
      const hit = java.find((f) => f.rel.replace(/\.java$/, "") === wanted || f.rel.endsWith("/" + wanted + ".java"));
      if (hit) sourceText = fs.readFileSync(hit.abs, "utf8");
    }
    const recovered = sourceText && /Method not decompiled/.test(sourceText) ? recoverAnnotations(sourceText) : null;
    if (sourceText) sourceText = sourceText.slice(0, 60000);
    const packages = [...new Set(java.map((f) => path.dirname(f.rel).replace(/\//g, ".")))].slice(0, 200);
    return {
      schema: "VerdexMobile/v1",
      tool: "dex_decompile",
      file: path.basename(target),
      authority: "local-binary-static",
      epistemic: "inferred",
      backend: "jadx",
      class_count: java.length,
      package_count: packages.length,
      packages,
      classes: java.slice(0, MAX_LISTED).map((f) => f.rel.replace(/\.java$/, "").replace(/\//g, ".")),
      ...(wanted ? { requested_class: options.className, source: sourceText, found: Boolean(sourceText) } : {}),
      ...(recovered ? { recovered_from_annotations: recovered } : {}),
      limitations: [
        "jadx 反编译 DEX 得到的是 Java 重建,非原始源码;混淆(ProGuard/R8)会让类名/变量名变成 a/b/c。",
        "只静态反编译,未运行 APK;不访问网络。",
        "仅限你拥有或被授权分析的 app;禁止用于未授权目标。",
      ],
    };
  } finally {
    fs.rmSync(outDir, { recursive: true, force: true });
  }
}

export const MOBILE_TOOLS = [
  {
    name: "dex_decompile",
    description: "用 jadx 把 APK/DEX 反编译成 Java(只读,不运行 app):清点 package/class,可选 className 返回指定类的 Java 源码。需装 jadx(VERDEX_JADX 指向 bin/jadx)。安卓逆向 Java 层必备。仅限你拥有或被授权的 app。",
    inputSchema: { type: "object", required: ["path"], properties: { path: { type: "string", description: "本地 APK 或 .dex 路径。" }, className: { type: "string", description: "可选:返回该类的 Java 源码(如 com.app.MainActivity)。" } } },
    run: (args) => dexDecompile(args.path, { className: args.className }),
  },
  {
    name: "wxapkg_unpack",
    description: "解包微信小程序 .wxapkg 包(自定义二进制格式,纯解析):提取并清点 js/wxml/wxss/json,JS 可路由到 scan 分析逻辑。防路径穿越,只读不执行。仅限你拥有或被授权的小程序。",
    inputSchema: { type: "object", required: ["path"], properties: { path: { type: "string", description: "本地 .wxapkg 文件路径。" } } },
    run: (args) => unpackWxapkg(args.path),
  },
  {
    name: "mobile_unpack",
    description: "解包移动安装包(APK/IPA/AAB/JAR,ZIP 容器)并清点内容:原生库(.so/.dylib/Mach-O→可直接 bin_decompile)、DEX、JS、小程序包、manifest。原生库会被抽出到可用路径。只读解包,不执行包内代码。仅限你拥有或被授权的 app。",
    inputSchema: { type: "object", required: ["path"], properties: { path: { type: "string", description: "本地 APK/IPA/AAB/JAR 路径。" } } },
    run: (args) => unpackMobile(args.path),
  },
];
