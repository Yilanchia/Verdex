// Generates Frida instrumentation SCRIPTS (text only). Verdex NEVER attaches to
// a process, never injects, never runs Frida. The human runs the generated
// script against a target they declared and are authorized to test (their own
// app / CTF / written-scope engagement). Three gates:
//   1) target (package/process) is a required authorization declaration
//   2) Verdex only emits text — the user runs `frida -U -f <target> -l x.js`
//   3) human-in-the-loop: the model proposes, the user approves and runs
// Dynamic analysis is where static can't reach: unpacking, runtime keys, live
// request params. Keep it inside owned/authorized targets.

function requireTarget(target) {
  const t = String(target || "").trim();
  if (!t) throw new Error("参数 target 必填:声明授权目标(应用包名如 com.example.app,或进程名)。这是授权声明,不是可选项");
  if (!/^[A-Za-z0-9_.:-]{1,128}$/.test(t)) throw new Error("target 应为包名/进程名(字母数字.:_-)");
  return t;
}

function banner(target, kind) {
  return [
    "// ============================================================",
    "// Verdex 生成的 Frida 动态分析脚本 —— 仅供授权测试。",
    `// 授权目标: ${target}   检测类型: ${kind}`,
    "// 你负责确认对该目标拥有合法授权(自有 App / CTF / 书面 scope)。",
    "// Verdex 不 attach、不注入、不运行;由你审阅后自行执行:",
    `//   frida -U -f ${target} -l this_script.js --no-pause`,
    "// 禁止用于你不拥有、未被授权的 App 或线上系统。",
    "// ============================================================",
  ].join("\n");
}

function unpackScript() {
  return [
    "// 脱壳:dump 运行时解密后的 dex(加壳 App 的业务代码只在内存里出现)。",
    "// 产物写到 /data/local/tmp/,之后 adb pull 下来喂给 dex_decompile。",
    "Java.perform(function () {",
    "  var out = '/data/local/tmp/verdex_dump';",
    "  var File = Java.use('java.io.File'); new File(out).mkdirs();",
    "  function dumpBytes(name, bytes) {",
    "    var FOS = Java.use('java.io.FileOutputStream');",
    "    var f = FOS.$new(out + '/' + name);",
    "    f.write(bytes); f.close();",
    "    console.log('[verdex] dumped ' + name + ' (' + bytes.length + ' bytes)');",
    "  }",
    "  // 1) 枚举已加载的 ClassLoader,触发壳把 dex 解到内存",
    "  Java.enumerateClassLoaders({",
    "    onMatch: function (l) { console.log('[verdex] classloader: ' + l); },",
    "    onComplete: function () { console.log('[verdex] classloader enumeration done'); },",
    "  });",
    "  // 2) hook InMemoryDexClassLoader —— 多数壳在这里交付解密后的 dex",
    "  try {",
    "    var IMDCL = Java.use('dalvik.system.InMemoryDexClassLoader');",
    "    var BB = Java.use('java.nio.ByteBuffer');",
    "    IMDCL.$init.overload('java.nio.ByteBuffer', 'java.lang.ClassLoader').implementation = function (buf, parent) {",
    "      try { var arr = Java.array('byte', (function(){var d=buf.duplicate(); var n=d.remaining(); var o=Java.array('byte', new Array(n).fill(0)); d.get(o); return o;})());",
    "        dumpBytes('mem_' + Date.now() + '.dex', arr); } catch (e) { console.log('[verdex] buf dump err: ' + e); }",
    "      return this.$init(buf, parent);",
    "    };",
    "  } catch (e) { console.log('[verdex] InMemoryDexClassLoader hook skipped: ' + e); }",
    "  // 3) 备选:hook libart 的 OpenMemory / DefineClass 需 native 版,见文档;",
    "  //    对多数易盾/爱加密样本,上面两步已能拿到业务 dex。",
    "});",
  ].join("\n");
}

function hookScript(className, method) {
  const c = String(className || "com.example.Target");
  const m = String(method || "targetMethod");
  if (!/^[A-Za-z0-9_.$]{1,200}$/.test(c) || !/^[A-Za-z0-9_$<>]{1,100}$/.test(m)) throw new Error("className/method 格式非法");
  return [
    `// hook ${c}.${m} —— 打印每次调用的参数与返回值(覆盖所有重载)。`,
    "Java.perform(function () {",
    `  var T = Java.use(${JSON.stringify(c)});`,
    `  var overloads = T[${JSON.stringify(m)}].overloads;`,
    "  overloads.forEach(function (ov) {",
    "    ov.implementation = function () {",
    "      var args = Array.prototype.slice.call(arguments);",
    `      console.log('[verdex] ${c}.${m}(' + args.map(String).join(', ') + ')');`,
    "      var ret = ov.apply(this, arguments);",
    "      console.log('[verdex]   -> ' + ret);",
    "      return ret;",
    "    };",
    "  });",
    `  console.log('[verdex] hooked ${c}.${m} (' + overloads.length + ' overloads)');`,
    "});",
  ].join("\n");
}

function cryptoScript() {
  return [
    "// 抓运行时加解密/摘要:看真实 key/IV/明文/算法(静态只能看到常量)。",
    "Java.perform(function () {",
    "  var b64 = function (b) { try { return Java.use('android.util.Base64').encodeToString(b, 0); } catch (e) { return '<' + b.length + ' bytes>'; } };",
    "  var Cipher = Java.use('javax.crypto.Cipher');",
    "  Cipher.doFinal.overload('[B').implementation = function (input) {",
    "    console.log('[verdex] Cipher(' + this.getAlgorithm() + ').doFinal in=' + b64(input));",
    "    var out = this.doFinal(input);",
    "    console.log('[verdex]   out=' + b64(out)); return out;",
    "  };",
    "  var SKS = Java.use('javax.crypto.spec.SecretKeySpec');",
    "  SKS.$init.overload('[B', 'java.lang.String').implementation = function (key, algo) {",
    "    console.log('[verdex] SecretKeySpec algo=' + algo + ' key=' + b64(key)); return this.$init(key, algo);",
    "  };",
    "  var MD = Java.use('java.security.MessageDigest');",
    "  MD.digest.overload('[B').implementation = function (input) {",
    "    console.log('[verdex] MessageDigest(' + this.getAlgorithm() + ') in=' + b64(input));",
    "    return this.digest(input);",
    "  };",
    "  console.log('[verdex] crypto hooks installed');",
    "});",
  ].join("\n");
}

function networkScript() {
  return [
    "// 抓 OkHttp 请求:URL + headers + body —— 看签名(sign/orderRiskSign)怎么拼的。",
    "Java.perform(function () {",
    "  try {",
    "    var RB = Java.use('okhttp3.Request$Builder');",
    "    RB.build.implementation = function () {",
    "      var req = this.build();",
    "      console.log('[verdex] ' + req.method() + ' ' + req.url());",
    "      var h = req.headers(); for (var i = 0; i < h.size(); i++) console.log('[verdex]   ' + h.name(i) + ': ' + h.value(i));",
    "      return req;",
    "    };",
    "    console.log('[verdex] okhttp Request.Builder hooked');",
    "  } catch (e) { console.log('[verdex] okhttp hook skipped (无 okhttp3?): ' + e); }",
    "});",
  ].join("\n");
}

const KINDS = { unpack: unpackScript, hook: hookScript, crypto: cryptoScript, network: networkScript };

export function fridaScript(options = {}) {
  const target = requireTarget(options.target);
  const kind = KINDS[options.kind] ? options.kind : "unpack";
  const body = kind === "hook" ? hookScript(options.className, options.method) : KINDS[kind]();
  const script = `${banner(target, kind)}\n\n${body}\n`;
  return {
    schema: "VerdexFrida/v1",
    tool: "frida_script",
    authorized_target: target,
    kind,
    language: "frida-javascript",
    script,
    run_hint: `frida -U -f ${target} -l verdex_${kind}.js --no-pause   (或 -n <进程名> attach 已运行的)`,
    limitations: [
      "这是动态分析脚本模板;Verdex 不 attach、不注入、不运行——由你在自己环境里对授权目标执行。",
      "脱壳/hook/抓参会运行目标 App;只在你拥有或被明确授权的设备与 App 上做。",
      "unpack 对不同壳成功率不同;顽固壳需配合 native 层 hook(见报告建议)。",
    ],
  };
}

export const FRIDA_TOOLS = [
  {
    name: "frida_script",
    description: "生成 Frida 动态分析脚本(仅文本,Verdex 不 attach/不注入/不运行)。target 必填=授权目标声明(包名/进程)。kind:unpack(脱壳 dump 内存 dex)、hook(hook 指定 class.method 抓参数/返回,需 className+method)、crypto(抓运行时 key/IV/明文/算法)、network(抓 okhttp URL/headers 看签名拼接)。由你审阅后在自己授权的设备/App 上运行。禁止用于未授权目标。",
    inputSchema: {
      type: "object",
      required: ["target"],
      properties: {
        target: { type: "string", description: "授权目标:App 包名(com.example.app)或进程名。" },
        kind: { type: "string", description: "unpack / hook / crypto / network(默认 unpack)。" },
        className: { type: "string", description: "kind=hook 时:目标类全名。" },
        method: { type: "string", description: "kind=hook 时:目标方法名。" },
      },
    },
    run: (args) => fridaScript({ target: args.target, kind: args.kind, className: args.className, method: args.method }),
  },
];
