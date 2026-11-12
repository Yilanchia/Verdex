// explain — 面向非研究员的大白话解释层。
//
// 只做翻译,不做判定:拿一个规则 id / 扫描 kind / secrets 规则 / CWE / impact_proof
// 漏洞类,返回三句人话(这是什么 / 为什么要紧 / 该怎么办)+ 一段给复核者的技术
// 细节。解释按"规则"维护,不写进 finding schema——这样不会牵动证据指纹与快照。
//
// 内容红线:不写利用步骤、不给可直接粘贴的攻击载荷;只说机制、条件、修复方向。
// 静态命中一律是"候选",why 用条件句式,不承诺可利用。

const CWE_URL = (cwe) => {
  const id = String(cwe || "").replace(/^CWE-?/i, "");
  return id ? `https://cwe.mitre.org/data/definitions/${id}.html` : null;
};

function makeRule({ id, aliases = [], severity, cwe, title, zh, en, verifyZh, verifyEn, references }) {
  return {
    id,
    aliases,
    severity,
    cwe,
    title: { zh: title[0], en: title[1] },
    plain: { zh, en },
    verify: { zh: verifyZh, en: verifyEn },
    references: references && references.length ? references : [CWE_URL(cwe)].filter(Boolean),
  };
}

// 扫描器 kind 与 secrets 规则 id 都在这里;aliases 让同一个条目能从
// kind / 规则 id / CWE / impact_proof 漏洞类 任一入口命中。
const RULES = [
  makeRule({
    id: "secret",
    aliases: ["hardcoded-secret", "hardcoded-credential", "hardcoded-cred", "credential", "cwe-798"],
    severity: "high",
    cwe: "CWE-798",
    title: ["硬编码密钥", "Hardcoded secret"],
    zh: {
      what: "代码或配置里直接写死了密钥、口令或令牌。",
      why: "如果这个仓库或安装包会被别人看到,拿到密钥的人就可能用它访问对应服务,能做什么取决于这把密钥的权限。",
      fix: "先确认是不是真密钥:是真的就立刻轮换,改从环境变量或密钥管理服务读取,再从提交历史里清掉。",
    },
    en: {
      what: "A secret, password or token is written directly into code or configuration.",
      why: "Anyone who can read the repository or the shipped app may reuse it against the service, with whatever permissions that credential carries.",
      fix: "Confirm it is real, rotate it immediately, move it to an environment variable or secret manager, and purge it from git history.",
    },
    verifyZh: ["回到 file:line 看这个值是占位符/示例值还是真凭据。", "确认它是否随构建产物、安装包或前端 bundle 一起发布。"],
    verifyEn: ["Check the file:line value: placeholder/example or a real credential.", "Check whether it ships in a build artifact, installer or client bundle."],
  }),
  makeRule({
    id: "sql",
    aliases: ["sqli", "sql-injection", "sql注入", "cwe-89"],
    severity: "high",
    cwe: "CWE-89",
    title: ["SQL 注入", "SQL injection"],
    zh: {
      what: "代码把外部输入拼进了 SQL 语句。",
      why: "如果这段输入真的来自请求参数、又没有参数化,对方可能读到或改到数据库里的数据——但静态命中只说明'有可能',要先确认输入可达。",
      fix: "改用参数化查询或预编译,不要在 SQL 里拼字符串,并确认入口有权限校验。",
    },
    en: {
      what: "External input is concatenated into a SQL statement.",
      why: "If that input is reachable from a request and not parameterized, an attacker may read or change database data — but a static hit only proves the pattern, not reachability.",
      fix: "Use parameterized queries or prepared statements, never string concatenation, and confirm the endpoint checks authorization.",
    },
    verifyZh: ["沿 source→sink 确认输入是否真的来自请求参数。", "确认 SQL 是否是字符串拼接或模板生成,而不是参数化。"],
    verifyEn: ["Follow the source→sink chain: is the input really request-derived?", "Check whether the SQL is concatenated/templated instead of parameterized."],
  }),
  makeRule({
    id: "cmd",
    aliases: ["command-injection", "os-command-injection", "shell-injection", "cwe-78"],
    severity: "high",
    cwe: "CWE-78",
    title: ["命令注入", "Command injection"],
    zh: {
      what: "代码把外部输入交给了系统命令执行。",
      why: "如果输入可控,对方可能执行任意命令,直接拿到服务器控制权。",
      fix: "用参数数组替代整条 shell 字符串,对参数做白名单,并让进程以最小权限运行。",
    },
    en: {
      what: "External input is passed to a system command.",
      why: "If the input is controllable, an attacker may execute arbitrary commands and take over the host.",
      fix: "Pass argument arrays instead of shell strings, whitelist arguments, and run the process with least privilege.",
    },
    verifyZh: ["确认命令参数是否包含请求来源的字符串。", "确认是否启用了 shell(如 shell=True / system() / sh -c)。"],
    verifyEn: ["Check whether command arguments include request-derived strings.", "Check whether a shell is enabled (shell=True / system() / sh -c)."],
  }),
  makeRule({
    id: "eval",
    aliases: ["code-injection", "dynamic-code-execution", "cwe-95"],
    severity: "high",
    cwe: "CWE-95",
    title: ["动态代码执行", "Dynamic code execution"],
    zh: {
      what: "代码动态执行一段字符串(如 eval/exec/Function)。",
      why: "如果这段字符串能被外部影响,就等于把代码执行权交给了输入方。",
      fix: "去掉动态执行,改成显式解析或白名单映射。",
    },
    en: {
      what: "A string is executed dynamically (eval/exec/Function).",
      why: "If an attacker can influence that string, they effectively control code execution.",
      fix: "Remove dynamic execution; use explicit parsing or a whitelist map instead.",
    },
    verifyZh: ["确认被执行字符串是否含外部输入。", "确认是否已有白名单/沙箱限制。"],
    verifyEn: ["Check whether the executed string contains external input.", "Check whether a whitelist or sandbox constrains it."],
  }),
  makeRule({
    id: "deser",
    aliases: ["deserialization", "insecure-deserialization", "cwe-502"],
    severity: "high",
    cwe: "CWE-502",
    title: ["不安全反序列化", "Insecure deserialization"],
    zh: {
      what: "代码反序列化外部数据(如 pickle / yaml.load / unserialize)。",
      why: "不安全反序列化经常直接导致远程代码执行,是最高危的入口之一。",
      fix: "只反序列化可信数据,改用 JSON 等纯数据格式,并对数据做签名校验。",
    },
    en: {
      what: "External data is deserialized (pickle / yaml.load / unserialize).",
      why: "Insecure deserialization frequently leads directly to remote code execution.",
      fix: "Deserialize only trusted data, prefer plain formats such as JSON, and verify signatures.",
    },
    verifyZh: ["确认反序列化的数据是否来自外部/不可信来源。", "确认是否用了安全加载器(safe_load / JSON)。"],
    verifyEn: ["Check whether the data comes from an untrusted source.", "Check whether a safe loader (safe_load / JSON) is used."],
  }),
  makeRule({
    id: "xss",
    aliases: ["cross-site-scripting", "cwe-79"],
    severity: "medium",
    cwe: "CWE-79",
    title: ["跨站脚本", "Cross-site scripting"],
    zh: {
      what: "代码把内容直接当成 HTML 渲染。",
      why: "如果里面混进用户输入,可能在其他用户的浏览器里执行脚本,偷会话或冒用操作。",
      fix: "改用文本渲染或转义输出,并加 CSP 兜底。",
    },
    en: {
      what: "Content is rendered directly as HTML.",
      why: "If user input reaches that sink, script may run in other users' browsers and steal sessions or perform actions as them.",
      fix: "Render as text or escape output, and add a CSP as defense in depth.",
    },
    verifyZh: ["确认渲染内容里是否有用户可控字段。", "确认是否已有转义/净化(模板默认转义、DOMPurify)。"],
    verifyEn: ["Check whether user-controlled fields reach the sink.", "Check for escaping/sanitization (auto-escaping templates, DOMPurify)."],
  }),
  makeRule({
    id: "ssrf",
    aliases: ["server-side-request-forgery", "cwe-918"],
    severity: "high",
    cwe: "CWE-918",
    title: ["服务端请求伪造", "Server-side request forgery"],
    zh: {
      what: "服务端按外部给的地址去发请求。",
      why: "攻击者可能诱导服务器访问内网或云元数据,拿到本不该暴露的信息。",
      fix: "对目标域名做白名单,禁止内网地址和非常规协议。",
    },
    en: {
      what: "The server fetches a URL supplied from outside.",
      why: "An attacker may make it reach internal services or cloud metadata that should not be exposed.",
      fix: "Whitelist destination hosts, block private address ranges, and restrict protocols.",
    },
    verifyZh: ["确认请求 URL 是否来自请求参数。", "确认是否有域名白名单/内网地址拦截。"],
    verifyEn: ["Check whether the URL is request-derived.", "Check for a host whitelist and private-range blocking."],
  }),
  makeRule({
    id: "path",
    aliases: ["path-traversal", "directory-traversal", "lfi", "cwe-22"],
    severity: "high",
    cwe: "CWE-22",
    title: ["路径穿越", "Path traversal"],
    zh: {
      what: "文件路径可能直接来自外部输入。",
      why: "可能读到或写到预期之外的文件(路径穿越),比如配置文件或系统文件。",
      fix: "规范化路径并校验仍在允许目录内,文件名用白名单。",
    },
    en: {
      what: "A file path may come straight from external input.",
      why: "An attacker may read or write files outside the intended directory (path traversal), such as configs or system files.",
      fix: "Normalize the path, verify it stays under an allowed root, and whitelist filenames.",
    },
    verifyZh: ["确认路径参数是否来自请求且未规范化。", "确认是否有基于 realpath 的前缀校验。"],
    verifyEn: ["Check whether the path is request-derived and unnormalized.", "Check for a realpath-based prefix check."],
  }),
  makeRule({
    id: "ssti",
    aliases: ["template-injection", "server-side-template-injection", "cwe-1336"],
    severity: "high",
    cwe: "CWE-1336",
    title: ["服务端模板注入", "Server-side template injection"],
    zh: {
      what: "模板里拼进了外部输入。",
      why: "服务端模板注入可能一路升级到任意代码执行。",
      fix: "模板和数据分开,不要把用户输入当模板内容。",
    },
    en: {
      what: "External input is concatenated into a template.",
      why: "Server-side template injection can escalate to arbitrary code execution.",
      fix: "Keep templates and data separate; never treat user input as template source.",
    },
    verifyZh: ["确认模板字符串是否由外部输入拼接。", "确认模板引擎是否在沙箱/受限上下文里执行。"],
    verifyEn: ["Check whether the template string is built from external input.", "Check whether the engine runs in a sandboxed context."],
  }),
  makeRule({
    id: "redirect",
    aliases: ["open-redirect", "cwe-601"],
    severity: "medium",
    cwe: "CWE-601",
    title: ["开放重定向", "Open redirect"],
    zh: {
      what: "跳转地址来自外部输入。",
      why: "可被用来做借用可信域名的钓鱼跳转,或绕过登录回跳校验。",
      fix: "跳转目标用白名单,或只允许站内相对路径。",
    },
    en: {
      what: "A redirect target comes from external input.",
      why: "It can be used for phishing via a trusted domain, or to bypass login return-URL checks.",
      fix: "Whitelist redirect targets, or allow only same-site relative paths.",
    },
    verifyZh: ["确认 Location/跳转参数是否来自请求。", "确认是否校验了目标域或只允许相对路径。"],
    verifyEn: ["Check whether the Location/redirect value is request-derived.", "Check whether the target host is validated or relative-only."],
  }),
  makeRule({
    id: "cors",
    aliases: ["cors-misconfiguration", "cwe-942"],
    severity: "medium",
    cwe: "CWE-942",
    title: ["CORS 配置过宽", "Permissive CORS"],
    zh: {
      what: "接口允许任意来源跨域读取(CORS 通配)。",
      why: "如果同时允许携带凭证,任何网站都能替用户读你的接口数据。",
      fix: "固定可信来源白名单,不要用 * 搭配 credentials。",
    },
    en: {
      what: "The API allows any origin to read it cross-origin (wildcard CORS).",
      why: "With credentials enabled, any website could read your API data on behalf of the user.",
      fix: "Use a fixed origin whitelist; never combine * with credentials.",
    },
    verifyZh: ["确认 Access-Control-Allow-Origin 是否回显任意来源。", "确认是否同时允许 credentials。"],
    verifyEn: ["Check whether Access-Control-Allow-Origin reflects arbitrary origins.", "Check whether credentials are also allowed."],
  }),
  makeRule({
    id: "crypto",
    aliases: ["weak-crypto", "weak-hash", "insecure-random", "cwe-327"],
    severity: "medium",
    cwe: "CWE-327",
    title: ["弱加密/弱随机", "Weak crypto or randomness"],
    zh: {
      what: "用了弱的哈希、加密或不安全随机数。",
      why: "MD5/SHA1/ECB/Math.random 不适合安全用途,可能被碰撞或预测。",
      fix: "换成 SHA-256 以上的哈希、AEAD 加密和密码学安全随机数。",
    },
    en: {
      what: "Weak hashing, encryption or randomness is used.",
      why: "MD5/SHA1/ECB/Math.random are unsuitable for security and may be collided or predicted.",
      fix: "Use SHA-256+, AEAD encryption, and a cryptographically secure RNG.",
    },
    verifyZh: ["确认这段密码学代码是否用于安全用途(口令、签名、令牌)。", "确认是否只是非安全的校验和/缓存键。"],
    verifyEn: ["Check whether the crypto is used for security (passwords, signatures, tokens).", "Check whether it is only a non-security checksum/cache key."],
  }),
  makeRule({
    id: "xxe",
    aliases: ["xml-external-entity", "cwe-611"],
    severity: "high",
    cwe: "CWE-611",
    title: ["XML 外部实体", "XML external entity"],
    zh: {
      what: "XML 解析可能启用了外部实体。",
      why: "攻击者可能借它读服务器文件或让服务器访问内网。",
      fix: "禁用 DTD/外部实体,用安全默认配置解析。",
    },
    en: {
      what: "XML parsing may allow external entities.",
      why: "An attacker may use it to read server files or make the server reach internal networks.",
      fix: "Disable DTDs/external entities and parse with secure defaults.",
    },
    verifyZh: ["确认解析器是否显式关闭了外部实体/DTD。", "确认 XML 输入是否来自不可信来源。"],
    verifyEn: ["Check whether external entities/DTDs are explicitly disabled.", "Check whether the XML input is untrusted."],
  }),
  makeRule({
    id: "proto",
    aliases: ["prototype-pollution", "cwe-1321"],
    severity: "medium",
    cwe: "CWE-1321",
    title: ["原型链污染", "Prototype pollution"],
    zh: {
      what: "外部对象可能被合并进程序对象,改动原型链。",
      why: "原型链污染能篡改全局行为,极端情况下升级为代码执行。",
      fix: "用无原型对象、字段白名单,显式拒绝 __proto__/constructor。",
    },
    en: {
      what: "External objects may be merged into program objects and alter the prototype chain.",
      why: "Prototype pollution can change global behavior and, in some paths, escalate to code execution.",
      fix: "Use null-prototype objects, whitelist fields, and reject __proto__/constructor keys.",
    },
    verifyZh: ["确认合并/赋值的来源是否不可信。", "确认是否过滤了 __proto__/constructor/prototype 键。"],
    verifyEn: ["Check whether the merge source is untrusted.", "Check whether __proto__/constructor/prototype keys are filtered."],
  }),
  makeRule({
    id: "idor",
    aliases: ["bola", "broken-object-level-authorization", "cwe-639"],
    severity: "high",
    cwe: "CWE-639",
    title: ["对象级越权", "IDOR / object-level authorization"],
    zh: {
      what: "接口靠请求里的对象 ID 取数据,服务端可能没校验'这条数据是不是你的'。",
      why: "把 ID 改成别人的,就可能读到或改到别人的数据(水平越权)。",
      fix: "每次访问对象都校验当前用户的归属,不要只靠 ID 难猜。",
    },
    en: {
      what: "An endpoint loads objects by an ID from the request, possibly without checking ownership.",
      why: "Changing the ID may read or modify another user's data (horizontal privilege escalation).",
      fix: "Check ownership of every object access; do not rely on unguessable IDs.",
    },
    verifyZh: ["确认查询是否带当前用户/租户条件。", "确认 ID 是否可被枚举或替换。"],
    verifyEn: ["Check whether queries are scoped to the current user/tenant.", "Check whether IDs can be enumerated or swapped."],
  }),
  makeRule({
    id: "auth-bypass",
    aliases: ["broken-access-control", "missing-authorization", "cwe-862"],
    severity: "high",
    cwe: "CWE-862",
    title: ["鉴权缺失/越权", "Missing authorization"],
    zh: {
      what: "低权限或未登录的请求,可能访问到了高权限功能。",
      why: "鉴权缺失会让越权变成常态,影响面取决于这个功能能做什么。",
      fix: "默认拒绝、统一鉴权中间件,并在服务端逐个接口校验权限。",
    },
    en: {
      what: "A low-privilege or anonymous request may reach a high-privilege function.",
      why: "Missing authorization makes privilege escalation routine; impact depends on what the function can do.",
      fix: "Deny by default, centralize authorization middleware, and check permissions per endpoint on the server.",
    },
    verifyZh: ["确认该路由是否挂了鉴权中间件。", "确认权限判断是否在服务端而非仅前端隐藏。"],
    verifyEn: ["Check whether the route is behind authorization middleware.", "Check whether enforcement is server-side, not just hidden in the UI."],
  }),

  // ---- secrets: provider signatures -------------------------------------
  makeRule({
    id: "aws-access-key-id",
    aliases: ["aws-access-key", "aws-ak"],
    severity: "high",
    cwe: "CWE-798",
    title: ["AWS Access Key ID", "AWS access key ID"],
    zh: {
      what: "代码里写死了一个 AWS Access Key ID。",
      why: "它通常和对应的 Secret Key 成对出现,拿到就能按这把密钥的权限调用云资源,比如列桶、读数据、开机器。",
      fix: "立刻在 AWS 控制台禁用/轮换这对密钥,检查 CloudTrail 有无异常调用,再改从环境变量或 IAM 角色读取。",
    },
    en: {
      what: "An AWS access key ID is hardcoded.",
      why: "It usually pairs with a secret key, so anyone holding both can use cloud resources with that key's permissions.",
      fix: "Disable and rotate the pair in the AWS console, review CloudTrail for abuse, then load credentials from env vars or an IAM role.",
    },
    verifyZh: ["确认 ID 后面是否还有成对的 Secret Key。", "核对这把密钥对应哪个 IAM 用户/角色及其权限。"],
    verifyEn: ["Check whether the paired secret key is also present.", "Identify the IAM user/role and its permissions."],
  }),
  makeRule({
    id: "aws-secret-access-key",
    aliases: ["aws-secret-key", "aws-sk"],
    severity: "high",
    cwe: "CWE-798",
    title: ["AWS Secret Access Key", "AWS secret access key"],
    zh: {
      what: "代码里写死了 AWS Secret Access Key。",
      why: "Secret Key 是签名调用的核心,配合 Access Key ID 就能直接操作云资源。",
      fix: "立即轮换该 IAM 用户的密钥,排查调用日志,并从代码与历史提交中删除。",
    },
    en: {
      what: "An AWS secret access key is hardcoded.",
      why: "It is the signing half of the credential; with the access key ID it can operate cloud resources directly.",
      fix: "Rotate the IAM user's key now, review call logs, and remove it from code and git history.",
    },
    verifyZh: ["确认同一文件/配置里是否有 Access Key ID。", "确认这把密钥属于哪个 IAM 用户及其权限。"],
    verifyEn: ["Check whether the matching access key ID is nearby.", "Identify the IAM user and its permissions."],
  }),
  makeRule({
    id: "github-token",
    aliases: ["github-pat", "gh-token"],
    severity: "high",
    cwe: "CWE-798",
    title: ["GitHub Token", "GitHub token"],
    zh: {
      what: "代码里写死了一个 GitHub 令牌。",
      why: "令牌能做的事取决于它的 scope,可能读写仓库、issue、Actions,进而影响供应链。",
      fix: "到 GitHub 设置里吊销该令牌,重新签发更小权限的,并检查近期审计日志。",
    },
    en: {
      what: "A GitHub token is hardcoded.",
      why: "Its scope decides the damage: it may read/write repos, issues or Actions, which can become a supply-chain risk.",
      fix: "Revoke it in GitHub settings, reissue a least-privilege token, and review the audit log.",
    },
    verifyZh: ["确认令牌是否还有效、scope 是什么。", "确认它出现在哪个仓库/构建产物里。"],
    verifyEn: ["Check whether the token is still valid and what scopes it has.", "Identify which repo or artifact contains it."],
  }),
  makeRule({
    id: "github-fine-grained",
    aliases: ["github-fine-grained-pat"],
    severity: "high",
    cwe: "CWE-798",
    title: ["GitHub fine-grained PAT", "GitHub fine-grained PAT"],
    zh: {
      what: "代码里写死了一个 GitHub fine-grained PAT。",
      why: "它限定仓库与权限,但仍可能读写关键仓库或触发 workflow。",
      fix: "吊销并重新签发最小权限令牌;优先用 GitHub App/OIDC 代替长期 PAT。",
    },
    en: {
      what: "A GitHub fine-grained PAT is hardcoded.",
      why: "It is scoped to specific repos/permissions but can still modify critical repos or trigger workflows.",
      fix: "Revoke and reissue with least privilege; prefer a GitHub App or OIDC over long-lived PATs.",
    },
    verifyZh: ["确认它授权了哪些仓库与权限。", "确认它是否出现在构建/CI 产物里。"],
    verifyEn: ["Check which repos and permissions it grants.", "Check whether it leaks into build/CI artifacts."],
  }),
  makeRule({
    id: "google-api-key",
    aliases: ["google-key", "gcp-api-key"],
    severity: "medium",
    cwe: "CWE-798",
    title: ["Google API Key", "Google API key"],
    zh: {
      what: "代码里写死了一个 Google API Key。",
      why: "如果这把 key 没限制来源、包名或 API,别人可以盗用刷配额或访问付费接口。",
      fix: "在 GCP 给 key 加 HTTP referrer/包名/API 白名单,必要时轮换;客户端 key 也要限制。",
    },
    en: {
      what: "A Google API key is hardcoded.",
      why: "Without referrer/package/API restrictions, others can abuse it to burn quota or hit paid APIs.",
      fix: "Add referrer/package/API restrictions in GCP, rotate if needed; client keys still need limits.",
    },
    verifyZh: ["确认 key 是否配置了应用限制与 API 限制。", "确认它是客户端 key 还是服务端 key。"],
    verifyEn: ["Check whether application and API restrictions are set.", "Check whether it is a client-side or server-side key."],
  }),
  makeRule({
    id: "slack-token",
    aliases: ["slack-bot-token"],
    severity: "high",
    cwe: "CWE-798",
    title: ["Slack Token", "Slack token"],
    zh: {
      what: "代码里写死了一个 Slack 令牌。",
      why: "按 scope 可能读历史消息、发消息或管理 workspace。",
      fix: "在 Slack 后台吊销并重新签发,检查是否有异常调用。",
    },
    en: {
      what: "A Slack token is hardcoded.",
      why: "Depending on scopes it may read message history, post messages or administer the workspace.",
      fix: "Revoke and reissue in Slack admin, then review recent API activity.",
    },
    verifyZh: ["确认令牌前缀与 scope(xoxb/xoxp 等)。", "确认它出现在哪些仓库或部署配置里。"],
    verifyEn: ["Check the token prefix and scopes (xoxb/xoxp...).", "Check which repos or deploy configs contain it."],
  }),
  makeRule({
    id: "stripe-secret",
    aliases: ["stripe-live-secret", "sk-live"],
    severity: "critical",
    cwe: "CWE-798",
    title: ["Stripe 线上密钥", "Stripe live secret key"],
    zh: {
      what: "代码里写死了一个 Stripe 线上密钥(sk_live)。",
      why: "它能发起支付、退款、读取客户数据,直接对应资金与用户数据风险。",
      fix: "立刻在 Stripe 控制台轮换,检查支付/退款日志,并把密钥移到服务端密钥管理。",
    },
    en: {
      what: "A Stripe live secret key (sk_live) is hardcoded.",
      why: "It can create payments, issue refunds and read customer data — direct financial and privacy risk.",
      fix: "Rotate it in the Stripe dashboard now, review payment/refund logs, and move it to a server-side secret manager.",
    },
    verifyZh: ["确认是 live 还是 test 密钥。", "确认它是否出现在前端 bundle 里。"],
    verifyEn: ["Check whether it is a live or test key.", "Check whether it ships in a front-end bundle."],
  }),
  makeRule({
    id: "stripe-restricted",
    aliases: ["stripe-restricted-key", "rk-live"],
    severity: "high",
    cwe: "CWE-798",
    title: ["Stripe 受限密钥", "Stripe restricted key"],
    zh: {
      what: "代码里写死了一个 Stripe 受限密钥(rk_live)。",
      why: "虽然权限受限,仍可能按权限动支付或客户数据。",
      fix: "轮换密钥,确认最小权限,并改从服务端配置读取。",
    },
    en: {
      what: "A Stripe restricted key (rk_live) is hardcoded.",
      why: "Even restricted, it may still move payments or customer data within its permissions.",
      fix: "Rotate it, confirm least privilege, and load it from server-side config.",
    },
    verifyZh: ["确认这把 key 的具体权限范围。", "确认它是否在服务端配置之外暴露。"],
    verifyEn: ["Check the key's exact permission set.", "Check whether it is exposed outside server config."],
  }),
  makeRule({
    id: "private-key",
    aliases: ["pem-private-key", "private-key-pem", "cwe-321"],
    severity: "critical",
    cwe: "CWE-321",
    title: ["PEM 私钥", "PEM private key"],
    zh: {
      what: "代码或仓库里放了一把 PEM 私钥。",
      why: "拿到私钥可以冒充服务、解密流量或签名,影响取决于这把钥匙的用途。",
      fix: "作废并重新签发证书/密钥,确认历史提交里也清掉。",
    },
    en: {
      what: "A PEM private key is stored in the code or repository.",
      why: "Whoever holds it may impersonate the service, decrypt traffic or sign data, depending on its use.",
      fix: "Revoke and reissue the certificate/key, and purge it from git history.",
    },
    verifyZh: ["确认私钥对应哪个服务/证书。", "确认它是否被提交进历史或打进安装包。"],
    verifyEn: ["Identify which service/certificate the key belongs to.", "Check whether it is committed to history or packaged."],
  }),
  makeRule({
    id: "jwt",
    aliases: ["jwt-token", "token-forgery", "cwe-522"],
    severity: "medium",
    cwe: "CWE-522",
    title: ["JWT 令牌", "JWT token"],
    zh: {
      what: "代码里出现了一个 JWT 字符串。",
      why: "如果它是长期有效的高权 token,可能被重放;也可能只是示例或公开 token,要核对。",
      fix: "确认有效期与权限,必要时吊销;不要把真实 token 写进代码或日志。",
    },
    en: {
      what: "A JWT string appears in the code.",
      why: "A long-lived, high-privilege token could be replayed; it may also be a sample or public token — verify.",
      fix: "Check expiry and claims, revoke if needed, and never put real tokens in code or logs.",
    },
    verifyZh: ["解码 payload 看 exp/权限/主体。", "确认它是真实会话 token 还是示例。"],
    verifyEn: ["Decode the payload to inspect exp/claims/subject.", "Check whether it is a real session token or a sample."],
  }),
  makeRule({
    id: "slack-webhook",
    aliases: ["slack-incoming-webhook"],
    severity: "high",
    cwe: "CWE-798",
    title: ["Slack Webhook", "Slack webhook"],
    zh: {
      what: "代码里写死了 Slack Webhook 地址。",
      why: "任何拿到它的人都能往对应频道发消息,可用来钓鱼或刷屏。",
      fix: "删除并重新生成 webhook,限制调用来源。",
    },
    en: {
      what: "A Slack webhook URL is hardcoded.",
      why: "Anyone with it can post messages to the channel, which enables phishing or spam.",
      fix: "Delete and regenerate the webhook, and restrict who can call it.",
    },
    verifyZh: ["确认 webhook 是否仍可用。", "确认它在哪个客户端/服务端配置里。"],
    verifyEn: ["Check whether the webhook is still live.", "Check which client/server config contains it."],
  }),
  makeRule({
    id: "generic-assignment",
    aliases: ["generic-secret", "generic-key"],
    severity: "medium",
    cwe: "CWE-798",
    title: ["疑似密钥赋值", "Possible secret assignment"],
    zh: {
      what: "代码里有一个高熵的'像密钥'的赋值。",
      why: "可能是真密钥,也可能是测试数据或占位符;要回上下文确认它用在哪。",
      fix: "确认是真实凭据就轮换并移出源码;是占位符就标注清楚。",
    },
    en: {
      what: "A high-entropy value that looks like a secret is assigned.",
      why: "It may be a real key, or test data/placeholder — check its context and usage.",
      fix: "If it is real, rotate and remove it from source; if it is a placeholder, label it clearly.",
    },
    verifyZh: ["看变量名、默认值与调用点。", "确认它是否被用于认证/签名。"],
    verifyEn: ["Inspect the variable name, default value and call sites.", "Check whether it is used for auth/signing."],
  }),
  makeRule({
    id: "named-key-constant",
    aliases: ["app-key", "client-secret", "named-key"],
    severity: "medium",
    cwe: "CWE-798",
    title: ["命名密钥常量", "Named key constant"],
    zh: {
      what: "代码里有命名像密钥的常量(如 APP_KEY / CLIENT_ID / APP_SECRET)。",
      why: "多数是客户端 app key,危害取决于服务端是否信任它;只证明'它在包里'通常会被判理论风险。",
      fix: "确认服务端如何校验;别把客户端 key 当服务端凭据,需要时用 impact_proof 做最小验证。",
    },
    en: {
      what: "A constant with a key-like name (APP_KEY / CLIENT_ID / APP_SECRET) is assigned.",
      why: "Most are client-side app keys; impact depends on whether the server trusts them. Proving it is in the bundle alone is usually treated as theoretical.",
      fix: "Check how the server validates it; do not treat a client key as a server credential, and use impact_proof for a minimal proof when needed.",
    },
    verifyZh: ["确认这个常量是客户端还是服务端在用。", "确认服务端是否用它做签名/信任判断。"],
    verifyEn: ["Check whether the constant is used client-side or server-side.", "Check whether the server trusts it for signing/authorization."],
  }),
  makeRule({
    id: "signing-salt",
    aliases: ["signing-forgery", "app-secret", "signing-key"],
    severity: "medium",
    cwe: "CWE-798",
    title: ["签名盐/密钥", "Signing salt or key"],
    zh: {
      what: "代码里出现了签名盐或密钥(如 appSecret、key=)。",
      why: "如果能用它离线复算签名、且服务端接受,就能伪造请求;但静态看到盐不等于服务端信任伪造签名。",
      fix: "把盐迁到服务端安全存储,加时间戳/nonce 防重放,并用 impact_proof 在自己账号上验证最小影响。",
    },
    en: {
      what: "A signing salt or key (appSecret, key=) appears in the code.",
      why: "If you can recompute signatures offline and the server accepts them, requests can be forged — but seeing the salt statically does not prove the server trusts forgeries.",
      fix: "Move the salt to server-side secure storage, add timestamp/nonce replay protection, and use impact_proof to prove minimal impact on your own account.",
    },
    verifyZh: ["确认签名算法与参数拼接方式。", "确认服务端是否校验时间戳/重放,再决定是否需要动态验证。"],
    verifyEn: ["Check the signing algorithm and parameter ordering.", "Check whether the server validates timestamps/replay before attempting dynamic proof."],
  }),
];

const FALLBACK = {
  id: "generic-candidate",
  aliases: [],
  severity: "info",
  cwe: null,
  title: { zh: "待分类的静态候选", en: "Unclassified static candidate" },
  plain: {
    zh: {
      what: "这是一条按规则或数据流命中的静态候选,还没有被归入已知漏洞类。",
      why: "静态命中只说明'代码里出现了值得看的模式',不代表真的可被利用,需要回到原文件确认输入来源和权限边界。",
      fix: "先看 file:line 的上下文和证据链,再决定是人工复核、确认误报,还是转给对应负责人。",
    },
    en: {
      what: "This is a static rule/dataflow candidate that does not map to a known vulnerability class yet.",
      why: "A static hit only says the pattern is worth a look; it does not mean it is exploitable. Confirm input sources and permission boundaries in the original file.",
      fix: "Read the file:line context and evidence chain, then decide: human review, false positive, or handoff to the owner.",
    },
  },
  verify: {
    zh: ["读 file:line 的完整上下文。", "确认输入来源、调用方与权限边界。"],
    en: ["Read the full context at file:line.", "Confirm input sources, callers and authorization boundaries."],
  },
  references: [],
};

const RULE_IDS = [...RULES.map((rule) => rule.id), FALLBACK.id];

function normalize(value) {
  return String(value || "")
    .trim()
    .toLowerCase()
    .replace(/^cwe[\s_-]*(\d+)$/i, "cwe-$1")
    .replace(/[\s_]+/g, "-");
}

const INDEX = new Map();
for (const rule of [...RULES, FALLBACK]) {
  INDEX.set(normalize(rule.id), rule);
  for (const alias of rule.aliases) INDEX.set(normalize(alias), rule);
}

export function resolveRule(value) {
  const key = normalize(value);
  if (!key) return null;
  if (INDEX.has(key)) return INDEX.get(key);
  // A finding may carry "cwe: CWE-89"; try the bare CWE number too.
  if (/^\d+$/.test(key)) return INDEX.get(`cwe-${key}`) || null;
  return null;
}

export function explain(ruleId, options = {}) {
  const lang = options.lang === "en" ? "en" : "zh";
  const other = lang === "zh" ? "en" : "zh";
  const query = typeof ruleId === "string" ? ruleId : "";
  const rule = resolveRule(query) || FALLBACK;
  const matched = rule !== FALLBACK;
  const result = {
    schema: "VerdexExplain/v1",
    tool: "explain",
    query: query.trim(),
    lang,
    matched,
    rule_id: rule.id,
    severity_hint: rule.severity,
    title: rule.title[lang],
    plain: { ...rule.plain[lang] },
    technical: {
      cwe: rule.cwe,
      signals: [...rule.verify[lang]],
      references: [...rule.references],
    },
    translations: {
      [other]: { title: rule.title[other], plain: { ...rule.plain[other] } },
    },
    limitations: [
      "解释按'规则类'维护,不是对某一条发现的可利用性判定;静态命中仍需回原文件核对。",
      "本解释不含利用步骤;需要在授权范围内验证影响时,用 impact_proof 生成最小验证方案。",
    ],
  };
  if (!matched) {
    result.supported = RULE_IDS;
    result.hint = "传一个支持的 rule_id / kind / CWE / 漏洞类;也可以直接传 finding 里的 kind 或 rule。";
  }
  return result;
}

// Presentation helper for reports: returns the Chinese plain triad for a
// finding (or any rule id/kind/CWE), never throws.
export function plainExplanation(value) {
  if (typeof value === "string") {
    const rule = resolveRule(value);
    if (!rule) return { ...FALLBACK.plain.zh, rule_id: FALLBACK.id, matched: false };
    return { ...rule.plain.zh, rule_id: rule.id, matched: true };
  }
  const finding = value || {};
  for (const query of [finding.rule, finding.kind, finding.cwe]) {
    const rule = resolveRule(query);
    if (rule) return { ...rule.plain.zh, rule_id: rule.id, matched: true };
  }
  return { ...FALLBACK.plain.zh, rule_id: FALLBACK.id, matched: false };
}

export const EXPLAIN_TOOLS = [
  {
    name: "explain",
    description:
      "Explain a finding class in plain language: what it is, why it matters, and what to do — plus CWE, verification signals and references for reviewers. Accepts a scanner kind, a secrets rule id, a CWE, or an impact_proof class. Read-only, offline, no exploit steps. | 中文:把一条发现的类别翻译成大白话(这是什么 / 为什么要紧 / 该怎么办),并附 CWE、复核信号与参考链接。输入可以是扫描 kind、secrets 规则 id、CWE 或 impact_proof 漏洞类;只读、不联网、不含利用步骤。",
    inputSchema: {
      type: "object",
      required: ["rule_id"],
      properties: {
        rule_id: {
          type: "string",
          description:
            "Scanner kind, secrets rule id, CWE or vuln class, e.g. sql, aws-access-key-id, signing-forgery, CWE-89. | 中文:扫描 kind、secrets 规则 id、CWE 或漏洞类,如 sql、aws-access-key-id、signing-forgery、CWE-89。",
        },
        lang: {
          type: "string",
          enum: ["zh", "en"],
          description: "Output language for the plain explanation; default zh, the other language is returned under translations. | 中文:大白话的输出语言;默认 zh,另一语言放在 translations 里。",
        },
      },
    },
    run: ({ rule_id, lang }) => explain(rule_id, { lang }),
  },
];

// Exposed for tests: verify every entry is complete and bilingual.
export const EXPLAIN_RULES = [...RULES];
