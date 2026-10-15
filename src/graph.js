import path from "node:path";
import { spawnSync } from "node:child_process";
import ts from "typescript";
import { createEvidence, digest, locationEvidence } from "./evidence.js";
import { collectWorkspace, relativePath } from "./workspace.js";

const CODE_EXTENSIONS = new Set([".c", ".cpp", ".cs", ".go", ".java", ".js", ".jsx", ".kt", ".mjs", ".php", ".py", ".rb", ".rs", ".ts", ".tsx"]);

const SINKS = {
  sql: { cwe: "CWE-89", severity: "high", note: "外部输入可能进入数据库查询" },
  cmd: { cwe: "CWE-78", severity: "high", note: "外部输入可能进入命令执行" },
  eval: { cwe: "CWE-95", severity: "high", note: "外部输入可能进入动态执行" },
  xss: { cwe: "CWE-79", severity: "medium", note: "外部输入可能进入 HTML 渲染" },
  path: { cwe: "CWE-22", severity: "high", note: "外部输入可能进入文件路径操作" },
  deser: { cwe: "CWE-502", severity: "high", note: "外部输入可能进入不安全反序列化" },
  ssrf: { cwe: "CWE-918", severity: "high", note: "外部输入可能控制服务端请求目标" },
  redirect: { cwe: "CWE-601", severity: "medium", note: "外部输入可能控制重定向目标" },
};

const PYTHON_ANALYZER = String.raw`
import ast
import json
import sys

SINKS = {
    "execute": ("sql", "CWE-89", "high", "外部输入可能进入数据库查询"),
    "executemany": ("sql", "CWE-89", "high", "外部输入可能进入数据库查询"),
    "query": ("sql", "CWE-89", "high", "外部输入可能进入数据库查询"),
    "raw": ("sql", "CWE-89", "high", "外部输入可能进入数据库查询"),
    "system": ("cmd", "CWE-78", "high", "外部输入可能进入命令执行"),
    "popen": ("cmd", "CWE-78", "high", "外部输入可能进入命令执行"),
    "run": ("cmd", "CWE-78", "high", "外部输入可能进入命令执行"),
    "call": ("cmd", "CWE-78", "high", "外部输入可能进入命令执行"),
    "Popen": ("cmd", "CWE-78", "high", "外部输入可能进入命令执行"),
    "exec": ("eval", "CWE-95", "high", "外部输入可能进入动态执行"),
    "eval": ("eval", "CWE-95", "high", "外部输入可能进入动态执行"),
    "render_template_string": ("xss", "CWE-79", "medium", "外部输入可能进入 HTML 渲染"),
    "mark_safe": ("xss", "CWE-79", "medium", "外部输入可能进入 HTML 渲染"),
    "open": ("path", "CWE-22", "high", "外部输入可能进入文件路径操作"),
    "send_file": ("path", "CWE-22", "high", "外部输入可能进入文件路径操作"),
    "send_from_directory": ("path", "CWE-22", "high", "外部输入可能进入文件路径操作"),
    "loads": ("deser", "CWE-502", "high", "外部输入可能进入不安全反序列化"),
    "load": ("deser", "CWE-502", "high", "外部输入可能进入不安全反序列化"),
    "get": ("ssrf", "CWE-918", "high", "外部输入可能控制服务端请求目标"),
    "post": ("ssrf", "CWE-918", "high", "外部输入可能控制服务端请求目标"),
    "request": ("ssrf", "CWE-918", "high", "外部输入可能控制服务端请求目标"),
    "urlopen": ("ssrf", "CWE-918", "high", "外部输入可能控制服务端请求目标"),
    "redirect": ("redirect", "CWE-601", "medium", "外部输入可能控制重定向目标"),
}
SOURCE_NAMES = {"request", "req", "argv", "environ"}

def source_kind(node):
    names = {item.id for item in ast.walk(node) if isinstance(item, ast.Name)}
    attrs = {item.attr for item in ast.walk(node) if isinstance(item, ast.Attribute)}
    if names.intersection(SOURCE_NAMES) or attrs.intersection({"args", "form", "json", "values", "query", "body", "params", "headers", "cookies", "files", "GET", "POST", "argv"}):
        return "request"
    return None

def call_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""

def dotted_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = dotted_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""

def names_used(node):
    return {item.id for item in ast.walk(node) if isinstance(item, ast.Name) and isinstance(item.ctx, ast.Load)}

class Collector(ast.NodeVisitor):
    def __init__(self, source):
        self.source = source
        self.lines = source.splitlines()
        self.definitions = []
        self.routes = []
        self.imports = []
        self.calls = []
        self.flows = []
        self.tainted = {}
        self.function_stack = []

    def snippet(self, line):
        return self.lines[line - 1].strip()[:240] if 0 < line <= len(self.lines) else ""

    def visit_FunctionDef(self, node):
        self.record_definition(node)
        self.record_routes(node)
        self.function_stack.append({"name": node.name, "line": node.lineno})
        old = self.tainted
        self.tainted = {}
        self.generic_visit(node)
        self.tainted = old
        self.function_stack.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    def record_definition(self, node):
        self.definitions.append({"name": node.name, "kind": "function", "line": node.lineno, "end_line": getattr(node, "end_lineno", node.lineno), "snippet": self.snippet(node.lineno)})

    def record_routes(self, node):
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call):
                continue
            name = call_name(decorator.func)
            if name not in {"route", "get", "post", "put", "patch", "delete"} or not decorator.args:
                continue
            path_value = decorator.args[0]
            if isinstance(path_value, ast.Constant) and isinstance(path_value.value, str):
                self.routes.append({"method": name.upper(), "path": path_value.value, "line": decorator.lineno, "handler": node.name, "snippet": self.snippet(decorator.lineno)})

    def visit_Import(self, node):
        for item in node.names:
            self.imports.append({"module": item.name, "line": node.lineno, "snippet": self.snippet(node.lineno)})

    def visit_ImportFrom(self, node):
        if node.module:
            self.imports.append({"module": node.module, "line": node.lineno, "snippet": self.snippet(node.lineno)})

    def visit_Call(self, node):
        name = call_name(node.func)
        if name:
            self.calls.append({"name": name, "line": node.lineno, "snippet": self.snippet(node.lineno), "caller": self.function_stack[-1] if self.function_stack else None})
        sink_kind = self.sink_kind(node)
        sink = next((item for item in SINKS.values() if item[0] == sink_kind), None)
        if sink:
            influences = [self.tainted[name] for name in names_used(node) if name in self.tainted]
            source = source_kind(node)
            if influences or source:
                origin = influences[0] if influences else {"line": node.lineno, "variable": "request", "kind": source, "function": self.function_stack[-1] if self.function_stack else None, "snippet": self.snippet(node.lineno)}
                self.flows.append({"kind": sink_kind, "cwe": sink[1], "severity": sink[2], "line": node.lineno, "source_line": origin["line"], "source_variable": origin.get("variable", "request"), "source_kind": origin.get("kind", source), "source_function": origin.get("function"), "source_snippet": origin["snippet"], "sink_snippet": self.snippet(node.lineno), "note": sink[3], "chain": [{"line": origin["line"], "role": "source", "snippet": origin["snippet"]}, {"line": node.lineno, "role": "sink", "snippet": self.snippet(node.lineno)}]})
        self.generic_visit(node)

    def sink_kind(self, node):
        name = call_name(node.func)
        if name in {"execute", "executemany", "query", "raw"}: return "sql"
        if name in {"system", "popen", "run", "call", "Popen"}: return "cmd"
        if name in {"exec", "eval"}: return "eval"
        if name in {"render_template_string", "mark_safe"}: return "xss"
        if name in {"open", "send_file", "send_from_directory"}: return "path"
        if name in {"loads", "load"}: return "deser"
        full = dotted_name(node.func)
        if name == "urlopen" or full.startswith(("requests.", "httpx.", "urllib.", "urllib3.", "aiohttp.")): return "ssrf"
        if name == "redirect": return "redirect"
        return None

    def visit_Assign(self, node):
        source = source_kind(node.value)
        used = names_used(node.value)
        origin = next((self.tainted[name] for name in used if name in self.tainted), None)
        for target in node.targets:
            if not isinstance(target, ast.Name):
                continue
            if source or origin:
                self.tainted[target.id] = origin or {"line": node.lineno, "variable": target.id, "kind": source, "function": self.function_stack[-1] if self.function_stack else None, "snippet": self.snippet(node.lineno)}
        self.generic_visit(node)

def analyze(item):
    try:
        tree = ast.parse(item["text"], filename=item["path"])
    except SyntaxError as exc:
        return {"path": item["path"], "error": f"SyntaxError: {exc.msg}", "definitions": [], "routes": [], "imports": [], "calls": [], "flows": []}
    collector = Collector(item["text"])
    collector.visit(tree)
    return {"path": item["path"], "definitions": collector.definitions, "routes": collector.routes, "imports": collector.imports, "calls": collector.calls, "flows": collector.flows}

payload = json.loads(sys.stdin.read())
print(json.dumps([analyze(item) for item in payload], ensure_ascii=False))
`;

export function buildCodeGraph(root, options = {}) {
  const workspace = options.workspace || collectWorkspace(root);
  const files = workspace.files.filter((file) => CODE_EXTENSIONS.has(path.extname(file.path).toLowerCase()));
  const records = new Map();
  const parserStats = { typescript: 0, python: 0, fallback: 0 };
  const unknowns = [];
  const pythonFiles = files.filter((file) => path.extname(file.path).toLowerCase() === ".py");
  for (const result of analyzePython(pythonFiles)) {
    records.set(result.path, { ...result, parser: "python-ast" });
    parserStats.python += 1;
    if (result.error) unknowns.push({ file: result.path, reason: result.error });
  }
  for (const file of files.filter((item) => !records.has(item.path))) {
    if ([".js", ".jsx", ".mjs", ".ts", ".tsx"].includes(path.extname(file.path).toLowerCase())) {
      records.set(file.path, { ...analyzeTypeScript(file), parser: "typescript-ast" });
      parserStats.typescript += 1;
    } else {
      records.set(file.path, { ...analyzeFallback(file), parser: "bounded-text-fallback" });
      parserStats.fallback += 1;
      unknowns.push({ file: file.path, reason: "语言未启用结构化解析器，关系来自有限文本规则" });
    }
  }

  const definitions = [];
  const routes = [];
  const imports = [];
  const calls = [];
  const flows = [];
  for (const [filePath, record] of records) {
    const file = workspace.files.find((item) => item.path === filePath);
    for (const item of record.definitions || []) definitions.push(withEvidence(item, file, "definition"));
    for (const item of record.routes || []) routes.push(withEvidence(item, file, "route"));
    for (const item of record.imports || []) imports.push(withEvidence(item, file, "import"));
    for (const item of record.calls || []) calls.push({ ...item, file: filePath, evidence: evidenceAt(file, item.line, "call") });
    if (options.includeFlows !== false) for (const item of record.flows || []) flows.push(createFlow(file, item));
  }
  const nodes = [];
  for (const file of workspace.files) nodes.push({ id: nodeId("file", file.path), kind: "file", path: file.path, content_sha256: file.content_sha256 });
  for (const definition of definitions) nodes.push({ id: nodeId("function", definition.file, definition.line, definition.name), kind: "function", name: definition.name, file: definition.file, line: definition.line });
  for (const route of routes) nodes.push({ id: nodeId("route", route.file, route.line, route.path), kind: "route", method: route.method, path: route.path, file: route.file, line: route.line });
  const edges = [];
  for (const definition of definitions) edges.push({ from: nodeId("file", definition.file), to: nodeId("function", definition.file, definition.line, definition.name), relation: "contains", evidence: definition.evidence });
  for (const route of routes) edges.push({ from: nodeId("file", route.file), to: nodeId("route", route.file, route.line, route.path), relation: "exposes", evidence: route.evidence });
  const definitionIndex = new Map();
  for (const definition of definitions) {
    const list = definitionIndex.get(definition.name) || [];
    list.push(definition);
    definitionIndex.set(definition.name, list);
  }
  for (const route of routes) {
    const target = route.handler ? (definitionIndex.get(route.handler) || []).find((item) => item.file === route.file) : null;
    if (target) edges.push({ from: nodeId("route", route.file, route.line, route.path), to: nodeId("function", target.file, target.line, target.name), relation: "handles", evidence: route.evidence });
  }
  for (const call of calls) {
    const targets = definitionIndex.get(call.name) || [];
    const caller = typeof call.caller === "string"
      ? definitions.find((item) => item.file === call.file && item.name === call.caller)
      : call.caller;
    if (targets.length === 1) {
      edges.push({ from: caller ? nodeId("function", call.file, caller.line, caller.name) : nodeId("file", call.file), to: nodeId("function", targets[0].file, targets[0].line, targets[0].name), relation: "calls", evidence: call.evidence });
    } else if (targets.length > 1) {
      unknowns.push({ file: call.file, line: call.line, reason: `调用 ${call.name} 对应多个定义` });
    }
  }
  for (const flow of flows) {
    edges.push({ from: nodeId("function", flow.file, flow.source.line, flow.source.function || ""), to: nodeId("sink", flow.file, flow.sink.line, flow.kind), relation: "dataflow", kind: flow.kind, evidence: flow.sink });
  }
  const semantic = {
    schema: "VerdexCodeGraph/v2",
    authority: "local-static-analysis",
    epistemic: "inferred",
    nodes: nodes.sort((left, right) => left.id.localeCompare(right.id)),
    edges: edges.sort((left, right) => `${left.from}|${left.relation}|${left.to}`.localeCompare(`${right.from}|${right.relation}|${right.to}`)),
    definitions,
    routes,
    imports,
    dataflows: flows,
    coverage: { workspace: workspace.coverage, parser_stats: parserStats, unknowns: unknowns.slice(0, 200) },
    limitations: [
      "JavaScript/TypeScript 使用 TypeScript AST，Python 使用标准库 AST，其余语言使用有界文本解析。",
      "静态关系属于 inferred，不代表运行时可达、已认证或可利用。",
      "跨文件数据流、动态导入、反射、宏和别名仍需要专门解析器或人工验证。",
    ],
  };
  return { ...semantic, graph_id: `cg_${digest(semantic).slice(0, 24)}` };
}

export function findDataflows(root, options = {}) {
  return buildCodeGraph(root, { ...options, includeFlows: true }).dataflows;
}

function analyzeTypeScript(file) {
  const scriptKind = path.extname(file.path).toLowerCase() === ".tsx" || path.extname(file.path).toLowerCase() === ".jsx" ? ts.ScriptKind.TSX : ts.ScriptKind.TS;
  const sourceFile = ts.createSourceFile(file.path, file.text, ts.ScriptTarget.Latest, true, scriptKind);
  const definitions = [];
  const routes = [];
  const imports = [];
  const calls = [];
  const flows = [];
  const scopes = [{ tainted: new Map(), definition: null }];

  function lineOf(node) {
    return sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile)).line + 1;
  }
  function snippetOf(node) {
    const start = node.getStart(sourceFile);
    const end = node.getEnd();
    return file.text.slice(start, Math.min(end, start + 800)).trim().split(/\r?\n/)[0].slice(0, 240);
  }
  function evidenceOf(node, kind, epistemic = "observed", confidence = "exact") {
    return createEvidence({ file: file.path, content_sha256: file.content_sha256, line: lineOf(node), end_line: lineOf(node), snippet: snippetOf(node), kind, epistemic, confidence });
  }
  function current() { return scopes.at(-1); }
  function functionName(node) {
    if (ts.isFunctionDeclaration(node) || ts.isMethodDeclaration(node)) return node.name?.getText(sourceFile) || "";
    if (ts.isArrowFunction(node) || ts.isFunctionExpression(node)) return node.parent?.name?.getText(sourceFile) || "";
    return "";
  }
  function expressionText(node) { return node.getText(sourceFile); }
  function sourceKind(node) {
    const text = expressionText(node);
    return /\b(?:req|request)\.(?:query|body|params|headers|cookies|files|args|form|json|values|data)\b|\b(?:ctx|context)\.(?:request|query|body|params)\b|\bprocess\.argv\b/.test(text) ? "request" : null;
  }
  function usedTaint(node) {
    const result = [];
    function visit(child) {
      if (ts.isIdentifier(child)) {
        const item = current().tainted.get(child.text);
        if (item) result.push(item);
      }
      ts.forEachChild(child, visit);
    }
    visit(node);
    return result;
  }
  function sinkKind(node) {
    if (!ts.isCallExpression(node)) return null;
    const expression = expressionText(node.expression);
    if (/\.(?:execute|executemany|query|raw)$/.test(expression)) return "sql";
    if (/(?:os|child_process|subprocess)\.(?:system|popen|run|call|Popen|exec|execFile|spawn)$/.test(expression) || /\bexec$/.test(expression)) return "cmd";
    if (/^(?:eval|Function)$/.test(expression) || /\.(?:eval|exec)$/.test(expression)) return "eval";
    if (/innerHTML|outerHTML|insertAdjacentHTML|dangerouslySetInnerHTML|render_template_string|mark_safe/.test(expression)) return "xss";
    if (/(?:^|\.)(?:open|sendFile|send_file|send_from_directory|readFile|readFileSync|writeFile|writeFileSync)$/.test(expression) || /\.(?:join|resolve)$/.test(expression)) return "path";
    if (/(?:pickle|yaml|marshal)\.(?:loads|load|unsafe_load)$/.test(expression) || /\bunserialize$/.test(expression)) return "deser";
    if (/(?:axios|httpx|requests|got)\.(?:get|post|put|patch|delete|request)$/.test(expression) || /^(?:fetch|urlopen)$/.test(expression)) return "ssrf";
    if (/(?:^|\.)(?:redirect)$/.test(expression)) return "redirect";
    return null;
  }
  function visit(node) {
    if (ts.isImportDeclaration(node)) {
      imports.push({ module: node.moduleSpecifier.text, line: lineOf(node), evidence: evidenceOf(node, "import") });
    }
    if (ts.isFunctionDeclaration(node) || ts.isMethodDeclaration(node)) {
      const name = functionName(node);
      if (name) definitions.push({ name, kind: "function", line: lineOf(node), end_line: lineOf(node), evidence: evidenceOf(node, "definition") });
    }
    if (ts.isVariableDeclaration(node) && node.initializer && (ts.isArrowFunction(node.initializer) || ts.isFunctionExpression(node.initializer))) {
      definitions.push({ name: node.name.getText(sourceFile), kind: "function", line: lineOf(node), end_line: lineOf(node), evidence: evidenceOf(node, "definition") });
    }
    if (ts.isCallExpression(node)) {
      const callName = ts.isIdentifier(node.expression) ? node.expression.text : ts.isPropertyAccessExpression(node.expression) ? node.expression.name.text : "";
      if (callName) calls.push({ name: callName, line: lineOf(node), caller: current().definition, evidence: evidenceOf(node, "call") });
      const route = parseTypeScriptRoute(node, sourceFile);
      if (route) routes.push({ ...route, line: lineOf(node), evidence: evidenceOf(node, "route") });
      const kind = sinkKind(node);
      if (kind) {
        const influences = node.arguments.flatMap((argument) => usedTaint(argument));
        const source = node.arguments.map(sourceKind).find(Boolean);
        if (influences.length || source) {
          const origin = influences[0] || { line: lineOf(node), variable: "request", kind: source, evidence: evidenceOf(node, "flow-source", "inferred", "high") };
          const sink = evidenceOf(node, "flow-sink", "inferred", "high");
          flows.push({ kind, file: file.path, line: lineOf(node), source: { line: origin.line, variable: origin.variable, function: origin.function, evidence: origin.evidence || origin }, sink, chain: [origin.evidence || origin, sink], confidence: influences.length ? "high" : "medium", ...SINKS[kind] });
        }
      }
    }
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer) {
      const source = sourceKind(node.initializer);
      const inherited = usedTaint(node.initializer);
      if (source || inherited.length) current().tainted.set(node.name.text, inherited[0] || { line: lineOf(node), variable: node.name.text, kind: source, function: current().definition, evidence: evidenceOf(node, "flow-source", "inferred", "high") });
    }
    if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken && ts.isIdentifier(node.left)) {
      const source = sourceKind(node.right);
      const inherited = usedTaint(node.right);
      if (source || inherited.length) current().tainted.set(node.left.text, inherited[0] || { line: lineOf(node), variable: node.left.text, kind: source, function: current().definition, evidence: evidenceOf(node, "flow-source", "inferred", "high") });
    }
    if (ts.isFunctionLike(node) && (ts.isFunctionDeclaration(node) || ts.isMethodDeclaration(node) || ts.isArrowFunction(node) || ts.isFunctionExpression(node))) {
      const name = functionName(node);
      if (node.body) {
        scopes.push({ tainted: new Map(), definition: name ? { name, line: lineOf(node) } : null });
        ts.forEachChild(node.body, visit);
        scopes.pop();
      }
      return;
    }
    ts.forEachChild(node, visit);
  }
  ts.forEachChild(sourceFile, visit);
  return { definitions, routes, imports, calls, flows: dedupeFlows(flows) };
}

function parseTypeScriptRoute(node, sourceFile) {
  if (!ts.isCallExpression(node) || !ts.isPropertyAccessExpression(node.expression) || !node.arguments.length) return null;
  const method = node.expression.name.text.toLowerCase();
  if (!["route", "get", "post", "put", "patch", "delete", "use"].includes(method)) return null;
  const first = node.arguments[0];
  if (!ts.isStringLiteral(first) && !ts.isNoSubstitutionTemplateLiteral(first)) return null;
  return { method: method.toUpperCase(), path: first.text, snippet: node.getText(sourceFile).slice(0, 240) };
}

function analyzePython(files) {
  if (!files.length) return [];
  const input = JSON.stringify(files.slice(0, 300).map((file) => ({ path: file.path, text: file.text })));
  const result = spawnSync(globalThis.process.env.PYTHON || "python", ["-c", PYTHON_ANALYZER], { input, encoding: "utf8", windowsHide: true, timeout: 30_000, maxBuffer: 8 * 1024 * 1024 });
  if (result.error || result.status !== 0) return files.map((file) => ({ path: file.path, error: "Python AST parser unavailable", ...analyzeFallback(file) }));
  try { return JSON.parse(result.stdout); } catch { return files.map((file) => ({ path: file.path, error: "Python AST parser returned invalid JSON", ...analyzeFallback(file) })); }
}

function analyzeFallback(file) {
  const definitions = [];
  const routes = [];
  const imports = [];
  for (const [index, line] of file.text.split(/\r?\n/).entries()) {
    const definition = line.match(/^\s*(?:function|def|func)\s+([A-Za-z_$][\w$]*)\s*\(/);
    if (definition) definitions.push({ name: definition[1], kind: "function", line: index + 1, snippet: line.trim() });
    const route = line.match(/(?:route|get|post|put|patch|delete)\s*\(\s*["'`]([^"'`]+)["'`]/i);
    if (route) routes.push({ method: "UNKNOWN", path: route[1], line: index + 1, snippet: line.trim() });
    const imported = line.match(/^\s*(?:import|from)\s+([\w./-]+)/);
    if (imported) imports.push({ module: imported[1], line: index + 1, snippet: line.trim() });
  }
  return { definitions, routes, imports, calls: [], flows: [] };
}

function createFlow(file, item) {
  const sourceLine = item.source_line || item.source?.line || item.line;
  const sinkLine = item.line;
  const sourceEvidence = item.source?.evidence?.id ? item.source.evidence : evidenceAt(file, sourceLine, "flow-source", "inferred", item.confidence);
  const sinkEvidence = item.sink?.id ? item.sink : evidenceAt(file, sinkLine, "flow-sink", "inferred", item.confidence);
  return {
    kind: item.kind,
    cwe: item.cwe,
    severity: item.severity,
    note: item.note || SINKS[item.kind]?.note,
    file: file.path,
    line: sinkLine,
    source: { line: sourceLine, variable: item.source_variable || item.source?.variable || "request", function: item.source_function || item.source?.function, evidence: sourceEvidence },
    sink: sinkEvidence,
    chain: [sourceEvidence, sinkEvidence],
    confidence: item.confidence || "medium",
    source_kind: item.source_kind || item.source?.kind || "request",
  };
}

function withEvidence(item, file, kind) {
  const line = item.line || 1;
  return { ...item, file: file.path, evidence: item.evidence?.id ? item.evidence : evidenceAt(file, line, kind) };
}

function evidenceAt(file, line, kind, epistemic = "observed", confidence = "exact") {
  return locationEvidence(file, { line, snippet: file.text.split(/\r?\n/)[line - 1] || "" , kind, epistemic, confidence });
}

function dedupeFlows(flows) {
  const seen = new Set();
  return flows.filter((flow) => {
    const key = `${flow.kind}|${flow.line}|${flow.source_line}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function nodeId(kind, ...parts) {
  return `n_${kind}_${digest(parts).slice(0, 16)}`;
}
