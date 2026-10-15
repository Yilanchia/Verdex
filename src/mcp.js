import readline from "node:readline";
import { extractAssets } from "./assets.js";
import { buildCodeGraph } from "./graph.js";
import { analyzeProject } from "./project.js";
import { validateBrief } from "./brief.js";
import { collectOsint } from "./osint.js";
import { resolveRoot } from "./workspace.js";
import { writeRun } from "./store.js";
import { REVERSE_TOOLS } from "./reverse.js";
import { PWN_TOOLS } from "./pwn.js";
import { WEB_TOOLS } from "./web.js";

const PROTOCOL_VERSION = "2024-11-05";
const SERVER_INFO = { name: "verdex", version: "0.1.0" };

const ROOT_SCHEMA = {
  type: "object",
  required: ["root"],
  properties: { root: { type: "string", description: "本地作业夹绝对路径；只读分析，不访问网络。" } },
};

// All tools are read-only static analysis. They never attack live targets,
// generate payloads, or produce exploit/attack steps.
const TOOLS = [
  {
    name: "assets",
    description: "列出目标本地代码中的资产（域名/URL/IP 等）及文件行号证据。只读静态分析，不验证存活。",
    inputSchema: ROOT_SCHEMA,
    run: ({ root }) => extractAssets(resolveRoot(root)),
  },
  {
    name: "map",
    description: "生成代码图：文件、函数、路由、导入、调用关系与数据流候选（静态推断）。只读，不执行代码。",
    inputSchema: ROOT_SCHEMA,
    run: ({ root }) => buildCodeGraph(resolveRoot(root), { includeFlows: true }),
  },
  {
    name: "scan",
    description: "完整静态分析：资产、代码图、规则命中、source→sink 数据流候选、被动结果观察。候选均为待人工复核的静态推断，非已验证漏洞；不生成载荷或攻击步骤。",
    inputSchema: {
      type: "object",
      required: ["root"],
      properties: {
        root: ROOT_SCHEMA.properties.root,
        brief: { type: "object", description: "可选 VerdexBrief/v1：限定范围、漏洞类型、最低置信度；强制 no-payload/no-bruteforce/no-out-of-scope 红线。" },
      },
    },
    run: ({ root, brief }) => analyzeProject(resolveRoot(root), brief ? { brief: validateBrief(brief) } : {}),
  },
  {
    name: "osint",
    description: "本地 OSINT：从作业夹文件中提取标注过的邮箱/电话/社交资料/姓名/用户名，默认脱敏，保留文件证据。不访问网络、不做身份反查或账号关联。",
    inputSchema: {
      type: "object",
      required: ["root"],
      properties: {
        root: ROOT_SCHEMA.properties.root,
        categories: { type: "array", items: { type: "string" }, description: "可选类别过滤：email/phone/social-profile/person-name/username。" },
        reveal: { type: "boolean", description: "是否显示明文值；默认 false（脱敏）。" },
      },
    },
    run: ({ root, categories, reveal }) => collectOsint(resolveRoot(root), { categories, reveal: reveal === true }),
  },
  {
    name: "report",
    description: "对目标跑完整分析并在 .verdex/runs 下保存一份不可变快照:analysis.json、findings.json、脱敏 osint.json、Markdown 报告(含执行摘要)和自包含 HTML 报告(严重度看板+证据链)。返回各文件路径,HTML 可直接打开/分享。只读分析,不访问网络。",
    inputSchema: {
      type: "object",
      required: ["root"],
      properties: {
        root: ROOT_SCHEMA.properties.root,
        brief: { type: "object", description: "可选 VerdexBrief/v1:限定范围、漏洞类型、最低置信度;强制红线。" },
      },
    },
    run: ({ root, brief }) => {
      const validated = brief ? validateBrief(brief) : null;
      const analysis = analyzeProject(resolveRoot(root), validated ? { brief: validated } : {});
      const paths = writeRun(analysis, undefined, validated);
      return { schema: "VerdexReportRun/v1", analysis_id: analysis.analysis_id, finding_count: analysis.scan?.findings?.length || 0, saved: paths };
    },
  },
];

const ALL_TOOLS = [...TOOLS, ...REVERSE_TOOLS, ...PWN_TOOLS, ...WEB_TOOLS];
const TOOL_MAP = new Map(ALL_TOOLS.map((tool) => [tool.name, tool]));

function ok(id, result) {
  return { jsonrpc: "2.0", id, result };
}

function fail(id, code, message) {
  return { jsonrpc: "2.0", id, error: { code, message } };
}

async function callTool(id, params) {
  const tool = TOOL_MAP.get(params?.name);
  if (!tool) return fail(id, -32602, `未知工具：${params?.name}`);
  const args = params?.arguments || {};
  try {
    const output = await tool.run(args);
    return ok(id, { content: [{ type: "text", text: JSON.stringify(output, null, 2) }] });
  } catch (error) {
    return ok(id, { isError: true, content: [{ type: "text", text: `分析失败：${error.message}` }] });
  }
}

// Returns a JSON-RPC response object, or null for notifications that need none.
export async function dispatch(message) {
  const { id, method, params } = message || {};
  if (method === "initialize") {
    return ok(id, { protocolVersion: params?.protocolVersion || PROTOCOL_VERSION, capabilities: { tools: {} }, serverInfo: SERVER_INFO });
  }
  if (method === "tools/list") {
    return ok(id, { tools: ALL_TOOLS.map(({ name, description, inputSchema }) => ({ name, description, inputSchema })) });
  }
  if (method === "tools/call") return callTool(id, params);
  if (method === "ping") return ok(id, {});
  if (id !== undefined && id !== null) return fail(id, -32601, `不支持的方法：${method}`);
  return null;
}

export function startMcpServer() {
  const rl = readline.createInterface({ input: process.stdin });
  rl.on("line", async (line) => {
    const text = line.trim();
    if (!text) return;
    let message;
    try {
      message = JSON.parse(text);
    } catch {
      process.stdout.write(`${JSON.stringify({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "解析错误：无效 JSON" } })}\n`);
      return;
    }
    const response = await dispatch(message);
    if (response) process.stdout.write(`${JSON.stringify(response)}\n`);
  });
  process.stderr.write("verdex mcp server ready (stdio)\n");
}
