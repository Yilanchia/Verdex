// impact_proof —— 把"条件性理论风险"升级成"审核可复核的已证影响"。
//
// 这是追 ARTEX 的"智力"(攻击链推理)那一步:不是把 Verdex 变成攻击器,
// 而是给每一类候选发现,产出一份【最小影响 + 数据安全 + 点到为止】的验证
// 方案——证到"影响成立"的第一刻就停,全程只碰你自己拥有的账号/资源/canary。
//
// 为什么需要:静态扫出"硬编码 appSecret / 签名盐 / client_secret"常被 SRC
// 判"理论风险"驳回(就像 yuaneuro 那次),因为没证明"拿这个真能越权/冒充/
// 影响业务"。这工具告诉你:用你自己的两个测试账号,走最小一步把"能伪造签名"
// 变成"伪造签名被服务端接受并执行",证到即停,不碰任何真实用户数据。
//
// Verdex 只产方案文本,从不发请求、不执行——方案由你在授权范围内亲自跑。

// 贯穿所有漏洞类的铁律(数据安全)——任何方案都挂这条。
const DATA_SAFETY_LAW = [
  "① 只用你自己注册/拥有的测试账号(演示越权时:账号A访问账号B,A、B都是你的)。",
  "② 带外(SSRF/XXE/盲注回显)只打你自己控制的 canary(自建 DNS/HTTP 日志),绝不打真实内网。",
  "③ 注入只做存在性判定(布尔差异/时间延迟),绝不 dump 真实库表、绝不读/改他人数据。",
  "④ 证到'影响成立'的第一刻立即停——不扩大、不横向、不深入、不留持久化、不影响业务可用性。",
  "⑤ 全程记录你的每一步(便于自证'只碰自己数据'),发现越权能触及他人数据时:停、脱敏、只描述、立即上报。",
];

// stop-at-first-proof —— 点到为止的统一定义。
const STOP_RULE =
  "点到为止 = 证到'这个漏洞能产生真实影响'即停。能读到自己B账号一条数据 → 停(不遍历);能让服务端接受一次伪造签名 → 停(不批量);盲注能判出true/false → 停(不脱库)。";

const STRATEGIES = {
  "signing-forgery": {
    aka: ["签名盐", "appSecret", "sign 伪造", "client_secret"],
    why_rejected:
      "只证明'密钥/盐在公开资源里、能离线复算签名'是静态事实——审核要的是'服务端信任这个签名',即伪造一个签名、服务端真的接受并执行了一个你没权限的动作。",
    minimal_proof: [
      "1. 注册你自己的两个账号 A、B(都是你的,后续'越权'发生在自己账号之间)。",
      "2. 用 A 发一个正常业务请求,记下它原始的合法签名(作为对照)。",
      "3. 用逆向拿到的 appSecret/盐,离线对'改了一个无害字段(如把 A 自己的昵称改成 VERDEX-TEST)'的请求重算签名。",
      "4. 把这个【伪造签名 + 改动】发给真实接口,只针对 A 自己的资源。",
      "5. 看服务端是否接受伪造签名并执行 → 接受=签名是真实信任边界,伪造有实际影响(不再是理论)。证到即停。",
      "(可选升级,仍只碰自己)把请求里的对象ID从A换成B(你的另一个账号),证明伪造签名+换ID能动到'另一个账号'——坐实越权,目标全程是你自己的账号。",
    ],
    evidence: ["A 的原始合法请求+签名", "你的离线重算签名脚本/过程", "伪造签名的请求原文", "服务端接受并执行的响应(截图/HAR)"],
    report_framing:
      "把结论从'密钥硬编码(事实)'推进到'用该密钥伪造签名,服务端接受并执行了未授权动作(影响)',附完整链:密钥来源→离线复算→伪造请求→服务端接受。强调演示全程只在自己账号 A/B 间进行,未碰任何真实用户数据。",
    stop_point: "服务端第一次接受伪造签名并执行 → 停。不批量、不对他人账号发。",
  },

  idor: {
    aka: ["越权", "未授权访问对象", "水平越权", "BOLA"],
    why_rejected: "只证明'参数ID可改'不够——要证明'改了ID就读到/改到了不属于当前账号的对象'。",
    minimal_proof: [
      "1. 注册你自己的两个账号 A、B。用 B 创建一条可识别数据(如备注 VERDEX-OWNED-B)。",
      "2. 用 A 的会话发请求,把对象ID换成 B 那条数据的ID。",
      "3. 响应里出现了 B 的数据(VERDEX-OWNED-B)→ 水平越权成立。证到一条即停,绝不遍历他人ID。",
    ],
    evidence: ["A 的会话(脱敏)", "改了ID的请求原文", "响应里出现B账号数据的片段(标注 A、B 均为自己账号)"],
    report_framing: "明确写'A、B 均为我本人注册的测试账号',展示 A 的会话读到了 B 的对象。绝不展示真实用户ID被遍历——那既越红线也会被判违规。",
    stop_point: "读到自己B账号的一条数据 → 停。不自增遍历、不碰真实用户ID区间。",
  },

  "hardcoded-cred": {
    aka: ["硬编码凭据", "AK/SK", "服务端token", "API key 生效性"],
    why_rejected: "key 在包里是事实,审核要'它是不是活的、真能调通'。",
    minimal_proof: [
      "1. 用这把凭据做一次最小、只读、只针对你自己资源的调用(如 STS whoami / 列自己 bucket / 查自己账户信息)。",
      "2. 返回200+你自己的身份信息 → 凭据有效。证到即停,绝不列/读他人资源。",
      "(云元数据场景:只取无害公开字段如 region 证明可达,绝不拉真实 IAM 临时凭据。)",
    ],
    evidence: ["凭据来源(文件:行,脱敏)", "最小只读调用命令", "返回的自己身份/资源信息(证明key活的)"],
    report_framing: "从'key存在'推进到'key有效、具备X权限(以只读自证调用为证)',不展开实际能触及的他人数据范围——点出权限即可。",
    stop_point: "一次自证调用返回成功 → 停。不枚举、不访问他人资源。",
  },

  ssrf: {
    aka: ["服务端请求伪造", "带外"],
    why_rejected: "'参数像个URL'不够,要证明'服务端真的替你发了请求'。",
    minimal_proof: [
      "1. 把参数指向你自己控制的 canary(自建 http/dns 日志端点,带唯一随机子域)。",
      "2. canary 收到服务端来的请求 → SSRF 成立(服务端IP/时间为证)。证到即停。",
      "(可达性演示:只访问无害公开端点或你自己的canary,绝不打真实内网/元数据凭据。)",
    ],
    evidence: ["含canary的请求", "canary 侧收到的服务端访问日志(源IP、UA、唯一子域)"],
    report_framing: "'服务端代为请求了我控制的外部地址'即证实SSRF,附canary日志。不实际探测内网资产——点出'可发起内网请求的风险'由审核评级。",
    stop_point: "canary 收到一次服务端回连 → 停。不扫内网、不拉元数据。",
  },

  sqli: {
    aka: ["SQL注入", "注入"],
    why_rejected: "要证注入点真实存在,但不能脱库。",
    minimal_proof: [
      "1. 布尔:构造 true/false 两个条件,看响应是否出现稳定差异。",
      "2. 或时间:注入 SLEEP(n),看响应是否可控延迟 n 秒。",
      "3. 差异/延迟稳定复现 → 注入点存在。证到即停。",
    ],
    evidence: ["true/false 两请求+响应差异,或 SLEEP 的时延对照"],
    report_framing: "用布尔/时间盲注证明注入点存在即可,明确声明'未读取/导出任何数据'。绝不 union dump、不读表、不碰真实数据。",
    stop_point: "布尔差异或时间延迟稳定复现 → 停。绝不 dump、不读表。",
  },

  "auth-bypass": {
    aka: ["越权访问", "垂直越权", "鉴权绕过"],
    why_rejected: "要证'低权/无权身份实际访问到了高权功能',且只在自己账号上。",
    minimal_proof: [
      "1. 用你自己的低权账号(或未登录)请求高权端点。",
      "2. 返回了本不该给该身份的功能/数据(限你自己账号范围)→ 绕过成立。证到即停。",
    ],
    evidence: ["低权/无 token 的请求", "返回高权内容的响应(限自己账号)"],
    report_framing: "展示身份与可及功能的落差,全程自己账号。不用越权能力去访问他人数据。",
    stop_point: "一次拿到越权功能/自己数据 → 停。",
  },

  "open-redirect": {
    aka: ["开放重定向", "任意跳转"],
    why_rejected: "要证真能跳到外部可控域。",
    minimal_proof: ["把跳转参数设为你自己的 canary 域,看响应是否 3xx 跳到它。证到即停。"],
    evidence: ["含canary域的请求", "3xx + Location 指向canary的响应"],
    report_framing: "跳到我控制的域即证实,附响应。",
    stop_point: "一次成功跳转到自己canary → 停。",
  },

  xss: {
    aka: ["跨站脚本", "反射/存储 XSS"],
    why_rejected: "要证脚本真的在浏览器未转义执行,且只在自己会话。",
    minimal_proof: ["用唯一标记 payload(如 <vx-你的随机>)在你自己的会话/页面触发,确认未转义执行。证到即停。"],
    evidence: ["payload", "在你自己会话里执行/弹出的证据(截图)"],
    report_framing: "只在自己会话演示执行。绝不针对真实用户、不偷cookie、不蠕虫式传播。",
    stop_point: "自己会话里确认执行 → 停。",
  },

  jwt: {
    aka: ["JWT", "token伪造", "alg:none"],
    why_rejected: "要证'服务端接受了被篡改/伪造的token',且只改自己账号的声明。",
    minimal_proof: [
      "1. alg:none 或用破出的密钥自签一个 token,只改你自己账号的无害声明。",
      "2. 带上它请求,看服务端是否接受。接受 → 校验缺陷成立。证到即停。",
    ],
    evidence: ["原token", "你改/签的token", "服务端接受的响应(限自己账号)"],
    report_framing: "证明服务端接受伪造token即可,只动自己账号声明。不冒充真实用户。",
    stop_point: "服务端接受一次伪造token → 停。",
  },
};

export function impactProof(vulnClass, options = {}) {
  const key = String(vulnClass || "").trim().toLowerCase();
  const strat = STRATEGIES[key];
  const target = typeof options.target === "string" ? options.target.trim() : "";
  if (!strat) {
    return {
      schema: "VerdexProof/v1",
      tool: "impact_proof",
      error: `未知漏洞类 "${vulnClass || ""}"。`,
      supported: Object.keys(STRATEGIES),
      hint: "传其中一个 vuln_class;每个都给'最小影响+数据安全+点到为止'的验证方案。",
    };
  }
  return {
    schema: "VerdexProof/v1",
    tool: "impact_proof",
    vuln_class: key,
    aka: strat.aka,
    authorized_target: target || null,
    why_theoretical_rejected: strat.why_rejected,
    minimal_proof: strat.minimal_proof,
    data_safety_law: DATA_SAFETY_LAW,
    stop_point: strat.stop_point,
    stop_rule: STOP_RULE,
    evidence_to_capture: strat.evidence,
    report_framing: strat.report_framing,
    limitations: [
      "Verdex 只产验证方案文本,从不发请求、不执行——方案由你在授权范围内亲自运行。",
      "所有'越权/冒充'演示的对象必须是你自己拥有的账号/资源/canary;触及他人数据时立即停止、脱敏、上报。",
      "本方案是'点到为止'的最小影响证明;证到影响成立即停,不得扩大、横向、深入或影响业务可用性。",
    ],
  };
}

export const PROOF_TOOLS = [
  {
    name: "impact_proof",
    description:
      "把'条件性理论风险'(硬编码密钥/签名盐/IDOR 候选等)升级成'审核可复核的已证影响'的验证方案(仅文本,Verdex 不发请求)。给一个 vuln_class(signing-forgery/idor/hardcoded-cred/ssrf/sqli/auth-bypass/open-redirect/xss/jwt),产出:为何单纯静态会被判理论风险、最小影响验证步骤、数据安全铁律(越权演示只用你自己的第二账号、带外只打自己canary、盲注只判存在不dump)、取证清单、怎么写报告才会被收录、以及点到为止的停止点。追 ARTEX 攻击链智力,但锁死数据安全+证到即停。",
    inputSchema: {
      type: "object",
      required: ["vuln_class"],
      properties: {
        vuln_class: { type: "string", description: "漏洞类:signing-forgery/idor/hardcoded-cred/ssrf/sqli/auth-bypass/open-redirect/xss/jwt。" },
        target: { type: "string", description: "可选:你声明授权的目标(写进方案上下文)。" },
      },
    },
    run: (args) => impactProof(args.vuln_class, { target: args.target }),
  },
];
