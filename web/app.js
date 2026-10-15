(function () {
  "use strict";

  var state = { analysis: null, health: null, ai: null, personal: null, runs: [], selectedFindings: {}, review: {} };
  var elements = {
    root: document.getElementById("root-input"),
    chooseDirectory: document.getElementById("choose-directory-button"),
    brief: document.getElementById("brief-input"),
    manualAssets: document.getElementById("manual-assets-input"),
    analyze: document.getElementById("analyze-button"),
    example: document.getElementById("example-button"),
    error: document.getElementById("error-banner"),
    statusDot: document.getElementById("status-dot"),
    statusText: document.getElementById("status-text"),
    runTime: document.getElementById("run-time"),
    analysisId: document.getElementById("analysis-id"),
    personalQuery: document.getElementById("personal-query-input"),
    personalReveal: document.getElementById("personal-reveal"),
    personalSearch: document.getElementById("personal-search-button"),
    aiEnabled: document.getElementById("ai-enabled"),
    aiProvider: document.getElementById("ai-provider"),
    aiBaseUrl: document.getElementById("ai-base-url"),
    aiModel: document.getElementById("ai-model"),
    aiApiKey: document.getElementById("ai-api-key"),
    aiNetwork: document.getElementById("ai-network"),
    aiSave: document.getElementById("ai-save-button"),
    aiReview: document.getElementById("ai-review-button"),
    aiPresetHint: document.getElementById("ai-preset-hint"),
    aiReviewResult: document.getElementById("ai-review-result"),
    saveRun: document.getElementById("save-run-button"),
    saveRunResult: document.getElementById("save-run-result"),
    refreshRuns: document.getElementById("refresh-runs-button"),
    runHistory: document.getElementById("run-history"),
    findingList: document.getElementById("finding-list"),
    findingSelectionSummary: document.getElementById("finding-selection-summary"),
    findingsSelectAll: document.getElementById("findings-select-all"),
    findingsClear: document.getElementById("findings-clear"),
  };

  document.addEventListener("DOMContentLoaded", initialize);

  async function initialize() {
    bindEvents();
    try {
      state.health = await requestJson("/api/health");
      elements.root.value = state.health.root || "";
      elements.brief.value = state.health.defaultBrief || "";
      hydrateAi(state.health.ai || {});
      await analyze();
      await loadRuns();
    } catch (error) {
      showError(error.message);
      setStatus("服务未连接", "muted");
    }
  }

  function bindEvents() {
    elements.analyze.addEventListener("click", analyze);
    elements.chooseDirectory.addEventListener("click", chooseDirectory);
    elements.personalSearch.addEventListener("click", personalSearch);
    elements.aiSave.addEventListener("click", saveAi);
    elements.aiReview.addEventListener("click", reviewWithAi);
    document.querySelectorAll(".preset-chip").forEach(function (chip) {
      chip.addEventListener("click", function () { applyAiPreset(chip.getAttribute("data-preset")); });
    });
    elements.saveRun.addEventListener("click", saveRun);
    elements.refreshRuns.addEventListener("click", loadRuns);
    elements.findingsSelectAll.addEventListener("click", selectAllFindings);
    elements.findingsClear.addEventListener("click", clearFindings);
    elements.findingList.addEventListener("change", handleFindingChange);
    elements.findingList.addEventListener("input", handleFindingChange);
    elements.example.addEventListener("click", function () {
      if (state.health) {
        elements.root.value = state.health.root || "";
        elements.brief.value = state.health.defaultBrief || "";
      }
      analyze();
    });
    document.querySelectorAll(".tab").forEach(function (button) {
      button.addEventListener("click", function () {
        activateTab(button.getAttribute("data-tab"));
      });
    });
    document.querySelectorAll("[data-open-tab]").forEach(function (button) {
      button.addEventListener("click", function () {
        activateTab(button.getAttribute("data-open-tab"));
      });
    });
  }

  async function analyze() {
    elements.analyze.disabled = true;
    elements.analyze.innerHTML = '<span class="button-icon">◌</span>分析中…';
    hideError();
    setStatus("正在分析", "muted");
    try {
      var body = { root: elements.root.value.trim() };
      if (elements.brief.value.trim()) body.briefPath = elements.brief.value.trim();
      body.manualAssets = elements.manualAssets.value.split(/\r?\n/).map(function (value) { return value.trim(); }).filter(Boolean);
      state.analysis = await requestJson("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      state.selectedFindings = {};
      state.review = {};
      renderAnalysis(state.analysis);
      elements.saveRun.disabled = false;
      setStatus("分析完成", "ready");
    } catch (error) {
      showError(error.message);
      setStatus("分析失败", "error");
    } finally {
      elements.analyze.disabled = false;
      elements.analyze.innerHTML = '<span class="button-icon">↗</span>开始分析';
    }
  }

  async function saveRun() {
    if (!state.analysis) return;
    elements.saveRun.disabled = true;
    elements.saveRunResult.textContent = "正在保存…";
    try {
      var result = await requestJson("/api/save-run", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ review: state.review }) });
      elements.saveRunResult.textContent = "已保存：" + result.id;
      await loadRuns();
    } catch (error) {
      elements.saveRunResult.textContent = error.message;
    } finally {
      elements.saveRun.disabled = false;
    }
  }

  async function loadRuns() {
    try {
      var result = await requestJson("/api/runs");
      state.runs = result.runs || [];
      renderRuns(state.runs);
    } catch (error) {
      elements.runHistory.innerHTML = '<div class="empty-state">运行记录暂时不可用：' + escapeHtml(error.message) + '</div>';
    }
  }

  function renderRuns(runs) {
    if (!runs.length) {
      elements.runHistory.innerHTML = '<div class="empty-state">尚未保存分析快照。</div>';
      return;
    }
    elements.runHistory.innerHTML = runs.map(function (run) {
      return '<div class="run-item"><div class="run-item-main"><div class="run-item-title">' + escapeHtml(run.analysis_id) + '</div><div class="run-item-meta">' + escapeHtml(formatTime(run.saved_at)) + ' · ' + escapeHtml(run.root) + '</div></div><div class="run-item-stats">' + escapeHtml(run.file_count + ' 文件 · ' + run.asset_count + ' 资产 · ' + run.finding_count + ' 候选') + '</div><a class="run-report-link" href="' + escapeHtml(run.report_url) + '" download>报告 ↓</a></div>';
    }).join("");
  }

  async function chooseDirectory() {
    elements.chooseDirectory.disabled = true;
    try {
      var result = await requestJson("/api/select-directory", { method: "POST" });
      if (result.path) elements.root.value = result.path;
    } catch (error) {
      showError(error.message);
    } finally {
      elements.chooseDirectory.disabled = false;
    }
  }

  async function requestJson(url, options) {
    var response = await fetch(url, options);
    var data;
    try {
      data = await response.json();
    } catch {
      throw new Error("服务返回了无法解析的响应");
    }
    if (!response.ok) throw new Error(data.error || "请求失败");
    return data;
  }

  function renderAnalysis(analysis) {
    var assets = analysis.assets || {};
    var osint = analysis.osint || {};
    var scan = analysis.scan || {};
    var findings = scan.findings || [];
    var assetCount = (assets.items || []).length;
    var osintCount = (osint.observations || []).length;
    var coverage = scan.coverage || {};
    var workspace = coverage.workspace || {};

    setText("metric-files", formatNumber(analysis.file_count));
    setText("metric-files-note", workspace.status === "partial" ? "工作区部分读取" : "工作区完整读取");
    setText("metric-assets", formatNumber(assetCount));
    setText("metric-assets-note", (assets.urls || []).length + " URL · " + (assets.hosts || []).length + " Host · " + (assets.ips || []).length + " IP");
    setText("metric-osint", formatNumber(osintCount));
    setText("metric-osint-note", osint.privacy && osint.privacy.mode === "revealed" ? "显式值模式" : "默认脱敏");
    setText("metric-findings", formatNumber(findings.length));
    setText("metric-findings-note", (coverage.filtered_by_brief || 0) + " 条按 brief 过滤");
    setText("asset-tab-count", formatNumber(assetCount));
    setText("osint-tab-count", formatNumber(osintCount));
    setText("finding-tab-count", formatNumber(findings.length));
    elements.analysisId.textContent = "ANALYSIS / " + (analysis.analysis_id || "—").replace(/^analysis_/, "");
    setText("footer-generated", analysis.generated_at ? "生成于 " + formatTime(analysis.generated_at) : "—");
    setText("coverage-status", workspace.status === "partial" ? "PARTIAL" : "COMPLETE");
    setText("asset-scope-state", analysis.brief ? "按 brief 过滤" : "未配置范围");
    setText("osint-privacy-state", osint.privacy && osint.privacy.mode === "revealed" ? "显式值模式" : "脱敏模式");
    renderCoverage(analysis);
    renderSignals(findings);
    renderWorkspace(analysis);
    renderAssets(assets);
    renderOsint(osint);
    renderFindings(findings);
  }

  async function personalSearch() {
    var queries = elements.personalQuery.value.split(/\r?\n/).map(function (value) { return value.trim(); }).filter(Boolean);
    if (!queries.length) {
      setText("personal-result-summary", "请先输入至少一条已知信息。");
      return;
    }
    elements.personalSearch.disabled = true;
    elements.personalSearch.innerHTML = '<span class="button-icon">◌</span>查找中…';
    try {
      state.personal = await requestJson("/api/personal-search", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ root: elements.root.value.trim(), queries: queries, reveal: elements.personalReveal.checked }),
      });
      renderPersonal(state.personal);
    } catch (error) {
      setText("personal-result-summary", error.message);
    } finally {
      elements.personalSearch.disabled = false;
      elements.personalSearch.innerHTML = '<span class="button-icon">⌕</span>开始查找';
    }
  }

  function renderPersonal(result) {
    var observations = result.observations || [];
    setText("personal-privacy-state", result.privacy && result.privacy.mode === "revealed" ? "显式值模式" : "脱敏模式");
    setText("personal-result-summary", "查询 " + (result.coverage?.query_count || 0) + " 项，命中 " + observations.length + " 条；仅限本地文件。");
    var target = document.getElementById("personal-result-list");
    if (!observations.length) {
      target.innerHTML = '<div class="empty-state">没有找到精确匹配。</div>';
      return;
    }
    target.innerHTML = observations.map(function (item) {
      return '<div class="personal-result"><span class="personal-result-value">' + escapeHtml(item.matched_display || item.query_display) + '</span><span class="personal-result-evidence">' + escapeHtml(item.file + ":" + item.line) + '</span><span class="personal-result-kind">' + escapeHtml((item.query_type || "text").toUpperCase()) + "</span></div>";
    }).join("");
  }

  function hydrateAi(settings) {
    state.ai = settings || {};
    elements.aiEnabled.checked = settings.enabled === true;
    elements.aiProvider.value = settings.provider || "openai-compatible";
    elements.aiBaseUrl.value = settings.baseUrl || "http://127.0.0.1:11434/v1";
    elements.aiModel.value = settings.model || "";
    elements.aiNetwork.checked = settings.allowNetwork === true;
    setText("ai-status-pill", settings.enabled ? (settings.apiKeyConfigured || settings.baseUrl ? "已配置" : "待配置") : "未启用");
  }

  var AI_PRESETS = {
    "deepseek-pro": { provider: "deepseek", baseUrl: "https://api.deepseek.com", model: "deepseek-v4-pro", remote: true },
    "deepseek-flash": { provider: "deepseek", baseUrl: "https://api.deepseek.com", model: "deepseek-v4-flash", remote: true },
    "ollama": { provider: "openai-compatible", baseUrl: "http://127.0.0.1:11434/v1", model: "", remote: false },
  };

  function applyAiPreset(name) {
    var preset = AI_PRESETS[name];
    if (!preset) return;
    elements.aiProvider.value = preset.provider;
    elements.aiBaseUrl.value = preset.baseUrl;
    if (preset.model) elements.aiModel.value = preset.model;
    if (elements.aiPresetHint) {
      elements.aiPresetHint.textContent = preset.remote
        ? "已填入远程端点。保存前请勾选“启用”和“允许联网”，并填写 API Key。"
        : "已填入本地端点。本地模型无需 API Key，勾选“启用”后即可使用。";
    }
  }

  async function saveAi() {
    elements.aiSave.disabled = true;
    try {
      var settings = await requestJson("/api/ai/settings", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ enabled: elements.aiEnabled.checked, provider: elements.aiProvider.value, baseUrl: elements.aiBaseUrl.value, model: elements.aiModel.value, apiKey: elements.aiApiKey.value, allowNetwork: elements.aiNetwork.checked }),
      });
      elements.aiApiKey.value = "";
      hydrateAi(settings);
      elements.aiReviewResult.textContent = "设置已保存在本机 .verdex/ai-settings.json。API Key 不会回显。";
    } catch (error) {
      elements.aiReviewResult.textContent = error.message;
    } finally {
      elements.aiSave.disabled = false;
    }
  }

  async function reviewWithAi() {
    var selectedFindings = getSelectedFindings();
    if (!selectedFindings.length) {
      elements.aiReviewResult.textContent = "请先在候选列表中勾选要提交的证据。";
      return;
    }
    var target = state.ai && state.ai.baseUrl ? state.ai.baseUrl : "未配置端点";
    if (!window.confirm("将已勾选的 " + selectedFindings.length + " 条候选证据发送到以下 AI 端点：\n" + target + "\n\n继续吗？")) return;
    elements.aiReview.disabled = true;
    elements.aiReviewResult.textContent = "正在请求 AI…";
    try {
      var findings = selectedFindings.slice(0, 20).map(function (finding) {
        return { title: finding.title, kind: finding.kind, confidence: finding.confidence, file: finding.file, line: finding.line, why: finding.why, evidence: finding.evidence };
      });
      var result = await requestJson("/api/ai/review", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ evidence: findings }) });
      elements.aiReviewResult.textContent = result.content || "模型没有返回文本。";
    } catch (error) {
      elements.aiReviewResult.textContent = error.message;
    } finally {
      elements.aiReview.disabled = false;
    }
  }

  function renderCoverage(analysis) {
    var scan = analysis.scan || {};
    var coverage = scan.coverage || {};
    var workspace = coverage.workspace || {};
    var filesRead = Number(workspace.files_read || 0);
    var omitted = Object.keys(workspace.omitted || {}).reduce(function (sum, key) {
      return sum + (key === "excluded-directory" ? 0 : Number(workspace.omitted[key] || 0));
    }, 0);
    var totalFiles = filesRead + omitted;
    var workspacePercent = totalFiles ? Math.round(filesRead * 100 / totalFiles) : 0;
    var ruleHits = Number(coverage.rule_hits || 0);
    var dataflowHits = Number(coverage.dataflow_hits || 0);
    var rows = [
      ["工作区文件", filesRead + " / " + (totalFiles || filesRead), workspacePercent],
      ["规则命中", ruleHits + " 条", ruleHits ? 76 : 0],
      ["数据流候选", dataflowHits + " 条", dataflowHits ? 62 : 0],
      ["人工复核队列", Number(coverage.findings || 0) + " 条", coverage.findings ? 52 : 0],
    ];
    document.getElementById("coverage-list").innerHTML = rows.map(function (row) {
      return '<div class="coverage-row"><span class="coverage-label">' + escapeHtml(row[0]) + '</span><div class="coverage-track"><div class="coverage-fill" style="width:' + row[2] + '%"></div></div><span class="coverage-value">' + escapeHtml(row[1]) + "</span></div>";
    }).join("");
  }

  function renderSignals(findings) {
    var target = document.getElementById("signal-list");
    if (!findings.length) {
      target.innerHTML = '<div class="empty-state">本轮没有待复核候选。</div>';
      return;
    }
    target.innerHTML = findings.slice(0, 4).map(function (finding) {
      return '<div class="signal-item"><span class="signal-bar ' + escapeHtml(finding.severity || "medium") + '"></span><div><div class="signal-title">' + escapeHtml(finding.title || "未命名候选") + '</div><div class="signal-meta">' + escapeHtml((finding.file || "unknown") + ":" + (finding.line || "?") + " · " + (finding.confidence || "unknown")) + '</div></div><span class="signal-kind">' + escapeHtml((finding.kind || "unknown").toUpperCase()) + "</span></div>";
    }).join("");
  }

  function renderWorkspace(analysis) {
    var workspace = (analysis.scan && analysis.scan.coverage && analysis.scan.coverage.workspace) || {};
    document.querySelector("#workspace-card .workspace-path").textContent = analysis.root || "等待分析";
    document.querySelector("#workspace-card .workspace-hash").innerHTML = '<span class="hash-dot"></span>' + escapeHtml((workspace.files_read || 0) + " 个文件已建立证据哈希");
  }

  function renderAssets(assets) {
    var target = document.getElementById("asset-groups");
    var groups = [
      ["URL", assets.urls || []],
      ["HOST", assets.hosts || []],
      ["IP", assets.ips || []],
    ];
    if (!groups.some(function (group) { return group[1].length; })) {
      target.innerHTML = '<div class="empty-state">没有识别到资产记录。</div>';
      return;
    }
    target.innerHTML = groups.map(function (group) {
      var values = group[1];
      return '<div class="asset-group"><div class="asset-group-title"><span>' + group[0] + '</span><strong>' + values.length + '</strong></div><div class="item-list">' + values.slice(0, 80).map(function (value) {
        return '<div class="data-item">' + escapeHtml(value) + "</div>";
      }).join("") + (values.length > 80 ? '<div class="data-item">+' + (values.length - 80) + " more</div>" : "") + "</div></div>";
    }).join("");
  }

  function renderOsint(osint) {
    var target = document.getElementById("osint-groups");
    var grouped = {};
    (osint.observations || []).forEach(function (observation) {
      if (!grouped[observation.category]) grouped[observation.category] = [];
      grouped[observation.category].push(observation);
    });
    var categories = Object.keys(grouped);
    if (!categories.length) {
      target.innerHTML = '<div class="empty-state">没有识别到本地 OSINT 观察。</div>';
      return;
    }
    target.innerHTML = categories.map(function (category) {
      return '<div class="osint-group"><div class="osint-group-title"><span>' + escapeHtml(categoryLabel(category)) + '</span><strong>' + grouped[category].length + '</strong></div>' + grouped[category].map(function (observation) {
        var evidence = observation.evidence && observation.evidence[0];
        return '<div class="osint-observation"><div class="osint-value">' + escapeHtml(observation.display_value || "—") + '</div><div class="osint-evidence">' + escapeHtml(evidence ? evidence.file + ":" + evidence.line : "evidence unavailable") + "</div></div>";
      }).join("") + "</div>";
    }).join("");
  }

  function renderFindings(findings) {
    var target = document.getElementById("finding-list");
    updateFindingSelectionSummary(findings);
    if (!findings.length) {
      target.innerHTML = '<div class="empty-state">本轮没有待人工复核候选。</div>';
      return;
    }
    target.innerHTML = findings.map(function (finding) {
      var review = state.review[finding.fingerprint] || { status: "needs-review", note: "" };
      var checked = state.selectedFindings[finding.fingerprint] ? " checked" : "";
      return '<article class="finding-item"><div class="finding-top"><label class="finding-select"><input type="checkbox" data-finding-select="' + escapeHtml(finding.fingerprint) + '"' + checked + '><span>提交给 AI</span></label><div class="finding-title">' + escapeHtml(finding.title || "未命名候选") + '</div><span class="severity ' + escapeHtml(finding.severity || "info") + '">' + escapeHtml((finding.severity || "info").toUpperCase()) + '</span></div><div class="finding-meta"><span>' + escapeHtml(finding.kind || "unknown") + '</span><span>' + escapeHtml(finding.cwe || "CWE pending") + '</span><span>' + escapeHtml((finding.file || "unknown") + ":" + (finding.line || "?")) + '</span><span>confidence=' + escapeHtml(finding.confidence || "unknown") + "</span></div><div class=\"finding-why\">" + escapeHtml(finding.why || "需要人工核对。") + '</div><details class="finding-evidence"><summary>展开证据链（' + escapeHtml(String((finding.evidence || []).length)) + '）</summary>' + (finding.evidence || []).map(function (evidence) { return '<div class="evidence-line"><span>' + escapeHtml(evidence.file + ":" + evidence.line) + '</span><code>' + escapeHtml(evidence.snippet) + '</code></div>'; }).join("") + '</details><div class="finding-review"><label>复核状态<select data-finding-status="' + escapeHtml(finding.fingerprint) + '"><option value="needs-review"' + (review.status === "needs-review" ? " selected" : "") + '>待复核</option><option value="confirmed"' + (review.status === "confirmed" ? " selected" : "") + '>确认候选</option><option value="false-positive"' + (review.status === "false-positive" ? " selected" : "") + '>误报</option><option value="accepted-risk"' + (review.status === "accepted-risk" ? " selected" : "") + '>可接受风险</option></select></label><label class="finding-note">复核备注<textarea data-finding-note="' + escapeHtml(finding.fingerprint) + '" maxlength="2000" placeholder="记录依据、待补证据或处置建议">' + escapeHtml(review.note || "") + '</textarea></label></div></article>';
    }).join("");
  }

  function handleFindingChange(event) {
    var element = event.target;
    var fingerprint = element.getAttribute("data-finding-select") || element.getAttribute("data-finding-status") || element.getAttribute("data-finding-note");
    if (!fingerprint) return;
    if (element.hasAttribute("data-finding-select")) state.selectedFindings[fingerprint] = element.checked;
    if (element.hasAttribute("data-finding-status")) getReview(fingerprint).status = element.value;
    if (element.hasAttribute("data-finding-note")) getReview(fingerprint).note = element.value.slice(0, 2000);
    updateFindingSelectionSummary(state.analysis?.scan?.findings || []);
  }

  function getReview(fingerprint) {
    if (!state.review[fingerprint]) state.review[fingerprint] = { status: "needs-review", note: "" };
    return state.review[fingerprint];
  }

  function getSelectedFindings() {
    return (state.analysis?.scan?.findings || []).filter(function (finding) { return state.selectedFindings[finding.fingerprint]; });
  }

  function selectAllFindings() {
    (state.analysis?.scan?.findings || []).forEach(function (finding) { state.selectedFindings[finding.fingerprint] = true; });
    renderFindings(state.analysis?.scan?.findings || []);
  }

  function clearFindings() {
    state.selectedFindings = {};
    renderFindings(state.analysis?.scan?.findings || []);
  }

  function updateFindingSelectionSummary(findings) {
    var selected = findings.filter(function (finding) { return state.selectedFindings[finding.fingerprint]; }).length;
    setText("finding-selection-summary", "已选 " + selected + " 条");
  }

  function activateTab(name) {
    document.querySelectorAll(".tab").forEach(function (button) {
      button.classList.toggle("active", button.getAttribute("data-tab") === name);
    });
    document.querySelectorAll(".tab-panel").forEach(function (panel) {
      panel.classList.toggle("active", panel.id === "panel-" + name);
    });
  }

  function setStatus(text, tone) {
    elements.statusText.textContent = text;
    elements.statusDot.className = "status-dot " + (tone === "ready" ? "" : tone === "error" ? "error" : "muted");
    elements.statusText.style.color = tone === "error" ? "var(--red)" : tone === "ready" ? "var(--green)" : "";
    elements.runTime.textContent = tone === "ready" ? "刚刚完成 · " + new Date().toLocaleTimeString("zh-CN") : "请检查路径和 brief 配置";
  }

  function setText(id, value) {
    var element = document.getElementById(id);
    if (element) element.textContent = value;
  }

  function showError(message) {
    elements.error.textContent = message || "分析失败";
    elements.error.classList.remove("hidden");
  }

  function hideError() {
    elements.error.classList.add("hidden");
  }

  function categoryLabel(category) {
    return { email: "邮箱", phone: "电话", "social-profile": "社交资料", "person-name": "姓名字段", username: "用户名" }[category] || category;
  }

  function formatNumber(value) {
    return Number(value || 0).toLocaleString("zh-CN");
  }

  function formatTime(value) {
    try {
      return new Date(value).toLocaleString("zh-CN");
    } catch {
      return value;
    }
  }

  function escapeHtml(value) {
    return String(value == null ? "" : value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }
})();
