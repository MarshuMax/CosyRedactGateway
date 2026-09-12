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

## 10. 未解决问题 / 待验证

1. **【P2 · 待验证】GLiNER 类 NER 组件**：本机 4 核无 GPU，长文本实测推理在几十秒量级，直接整段送模型不可接受；可行方向是只对候选 span 截取 ±100~300 字符窗口送模型。待验证项：窗口大小与 p50 / p95 延迟曲线、窗口截断对召回的影响、模型体积在 Workers 运行时的可行性（CPU / WASM 限制）。
   **硬性约束：任何 ML 组件不得对低熵、无结构上下文的候选做终裁**——`PIN=0000`、短密码、裸 hex 之类在缺少 key 名 / 容器证据时只能作为 SOFT_SIGNAL 参与排序，最终动作必须由确定性规则或 policy 给出。
2. **【待验证】** Helm / Go template 与旧 `{{ }}` 定界符的冲突需实测（3.2）。
3. **【待验证】** schema 类型受限位置（number / boolean / enum）的替换策略需要真实 API server 或 provider schema 验证，当前只有"fail-closed"这一个保守选项。
4. **【待验证】** 跨层归属的显式声明机制：网关与外层 DLP 如何协商 EXCLUSIVE / PASS_THROUGH（响应头、部署配置或共享清单），以及不一致时的检测点。
5. **【待验证】** infra golden corpus 的来源与规模：需要覆盖 AWS / K8s / Git / 追踪 ID 的真实样本集，才能把"零误删"作为 HARD 的准入条件。
6. **【待验证】** Parser 覆盖率下限：YAML block scalar（`|` / `>`）、锚点别名、shell 引号与转义、URL percent-encoding、多行 `.env` 目前只有设计描述，无实现数据。
7. **【待验证】** 流式场景下 base64 surrogate 的跨 chunk 还原，以及新 token 变长后 `SseRestorer` 的后缀保留上界取值。
8. **【待统一】测试夹具与语法的两处不一致**：`test/k8s-surrogate.test.js` 的 `surrogate length is independent of plaintext length` 使用了三段 token `CRG_7K2M9Q_E9999_T8F4N6P3`，与 6.5 的两段语法及 `token-syntax` 的 `parts.length === 2` 断言冲突，需改成两段夹具；该用例注释写"surrogate 长度泄露明文长度"，但断言与行为是"长度只跟踪 token"，若同请求内 token 定长则不泄露明文长度，注释应按断言修正。
9. **【待替换】测试内的实现占位**：`token-syntax` 的 `targetToken()`（`djb2(明文)` 派生 entity slot）与 `k8s-surrogate` 的 `base64Surrogate()`、`restore-miss` 的 `classifyRestore()` 都是形态占位；前者的派生方式正是 8.1 所禁止的 checksum oracle 形态，worker.js 实现时必须用 CSPRNG，不得复用测试里的推导。
