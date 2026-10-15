import { createManualAssets, extractAssets, mergeAssets } from "./assets.js";
import { parseArtifacts } from "./artifacts.js";
import { validateBrief } from "./brief.js";
import { digest } from "./evidence.js";
import { collectOsint } from "./osint.js";
import { scanProject } from "./scanner.js";
import { collectWorkspace, resolveRoot } from "./workspace.js";

export function analyzeProject(value, options = {}) {
  const root = resolveRoot(value);
  const workspace = collectWorkspace(root, options);
  const brief = options.brief ? validateBrief(options.brief) : null;
  const policyOptions = brief ? { ...options, brief, scope: brief.scope } : options;
  const assets = mergeAssets(
    extractAssets(workspace, policyOptions),
    createManualAssets(options.manualAssets, policyOptions),
  );
  const artifacts = parseArtifacts(workspace, policyOptions);
  const scan = scanProject(workspace, policyOptions);
  const osint = collectOsint(workspace, brief ? { ...policyOptions, ...brief.osint } : policyOptions);
  const semantic = {
    schema: "VerdexProject/v1",
    authority: "local-file-evidence",
    epistemic: "inferred",
    file_count: workspace.files.length,
    assets,
    artifacts,
    scan,
    osint,
    ...(brief ? { brief } : {}),
    limitations: [
      "本项目只读取本地作业夹，未验证资产存活或漏洞可利用性。",
      "运行时行为、权限配置和动态调用需要后续独立证据确认。",
      ...(brief ? ["已应用 brief：资产与被动结果按范围过滤，代码候选按漏洞类型和最低置信度过滤，OSINT 默认脱敏。"] : []),
    ],
  };
  return {
    ...semantic,
    analysis_id: `analysis_${digest({ assets, artifacts, osint, graph: scan.graph.graph_id, findings: scan.findings.map((item) => item.fingerprint), brief }).slice(0, 24)}`,
    root,
    generated_at: new Date().toISOString(),
  };
}
