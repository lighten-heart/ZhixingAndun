# 智行安盾 API 接口约定

智行安盾采用 Python FastAPI 后端和 React / TypeScript / Vite 前端。未配置 `GUARD_DATABASE_URL` 时使用 SQLite，配置 PostgreSQL 连接地址后使用 PostgreSQL；数据库连接失败不会自动切换存储。后端默认端口为 8765，开发前端默认端口为 5173 并代理 `/api`，正式运行时由后端提供 `frontend/dist` 页面。API 使用 JSON 与 snake_case 字段。统计数据来自实际保存的运行记录，不预置评测成绩；组件演示工具的隔离效果与宿主执行回执分别标记。

Decision: allow | confirm | block. Execution: not_executed | pending | executing | succeeded | failed | unknown. Source types: user_input, web, document, code, email, issue, mcp_description, mcp_result, memory, knowledge. Risk severity: low, medium, high, critical. All timestamps ISO UTC unless a field explicitly represents Unix time. Error response {detail:string}. When any role token is configured, X-Guard-Token is required for every /api read/write/export except GET /api/health. Default remains loopback local demo mode. GET /api/health returns {status,version,mode,instance_id,process_id,primary_host,harness_status,model_configured,model_configuration_valid,hermes_status,sandbox_available,sandbox,storage,auth_required,model_status,timestamp}; model_configured means configuration was attempted, not successful connectivity. Partial/invalid model configuration reports invalid_configuration and fails closed instead of silently reverting to rules. instance_id is an optional public launcher nonce, not a credential; process_id identifies the actual API worker so the launcher can verify the process it stops, including Windows virtual-environment redirectors. storage reports backend, connectivity, runtime ownership and single-process deployment semantics without a database connection secret; sandbox reports actual local availability and selected image identity.

## API

- GET /api/dashboard -> {stats:{sessions,calls,blocked,pending,allowed,avg_latency_ms},trend:[{date,allow,confirm,block}],source_distribution:[{name,value}],recent_alerts:Call[],components:[{name,status,detail}]}
- GET /api/sessions -> Session[]
- POST /api/sessions {title,intent,scope?:read_only|development,agent_id?:string} -> Session
- GET /api/sessions/{id} -> Session & {sources:Source[],calls:Call[],events:Event[],graph:{nodes:Node[],edges:Edge[]}}
- POST /api/sessions/{id}/sources {type,content,resource?,parent_source_id?,metadata?} -> Source (contains detection and decision)
- POST /api/sessions/{id}/calls {tool,args,source_ids?:string[],plan?:string,agent_id?:string,parent_call_id?:string,mcp_server?:string} -> Call (review only, no execution)
- POST /api/calls/{id}/execute {permit?:string} -> Call; permit optional because backend owns fixture execution and checks stored binding, single use, expiry/policy/auth/source changes. No arbitrary OS commands or external network in demo executor.
- POST /api/calls/{id}/recheck {} -> replacement Call; review the stored original candidate parameters under current context, revoke the old permit, and create a new call ID. Only not_executed/pending calls that have not been superseded or entered recheck are eligible. Prior approval is not inherited. See lifecycle below.
- POST /api/calls/{id}/claim {permit:string,parameter_hash:string} -> {claim_id:string,call:Call}; both fields required, permit length 20–256. For trusted adapters: atomically consume a valid permit and change execution_status to executing before the callback. This endpoint does not execute the tool. Returned Call is redacted and does not expose the consumed permit.
- POST /api/calls/{id}/receipt {claim_id:string,status:succeeded|failed|unknown,detail?:string,result?:any} -> Call; claim_id and status required, detail defaults to "" (max 4000 characters), result defaults to null (serialized result max 200000 characters). The claim must match this call. Identical repeated receipts are idempotent; conflicting receipts return 409.
- GET /api/alerts -> Call[] for block/confirm
- GET /api/approvals -> Call[] pending confirm, excluding superseded calls and calls currently being rechecked
- POST /api/approvals/{id} {approved:boolean,comment?:string} -> Call; re-evaluate mandatory rules, never override hard block. Approved allowed operation stays not_executed until separate fixture/adapter execution.
- GET /api/policies -> {version:int,rules:PolicyRule[]}
- PUT /api/policies {version:int,rules:PolicyRule[]} -> current policy set, optimistic version conflict 409, invalid DSL 422
- GET /api/memories -> Memory[]
- POST /api/memories {session_id,content,label?} -> Memory (scan and quarantine on hit, persist provenance/version)
- POST /api/memories/{id}/scan {} -> Memory
- POST /api/sessions/{id}/memory/{memory_id} {} -> Source after read review
- GET /api/scenarios -> Scenario[]
- POST /api/demo/run {scenario_id} -> {session_id,scenario_id,passed:boolean,assertions:[{name,passed,detail}],duration_ms}
- POST /api/evaluations/run {} -> Evaluation
- GET /api/evaluations -> Evaluation[]
- GET /api/sessions/{id}/export -> JSON downloadable evidence (redacted)

## Records

Session {id,title,intent,scope,agent_id,created_at,status,call_count,blocked_count}
Source {id,session_id,type,resource,content,normalized,version,created_at,parent_source_id?,decision,detection:{status,risk_score,findings:[{rule_id,category,quote,start,end,reason}],information_gaps:string[],coverage:{checked_chars,total_chars},mode},sensitive:boolean}. UI source text may be redacted. Character offsets explicitly Python codepoint [start,end), not model tokens. Public views must avoid secrets.
Call {id,session_id,tool,args,source_ids,plan,agent_id,parent_call_id,mcp_server,created_at,decision,risk_score,severity,reasons:string[],matched_rules:string[],information_gaps:string[],execution_status,latency_ms,report:{review_object_id,task_id,task_relation,deviation_level,reason,resources,evidence_refs,information_gaps},receipt?:{status,detail,result,executed_at,evidence_type?:isolated_fixture_observed|trusted_adapter_reported},permit?:string,permit_expires_at?:string,policy_version,parameter_hash,approval?:{approved,comment,at,policy_version},superseded_by?:string,recheck_of_call_id?:string}
Event {id,type,session_id,call_id?,source_id?,timestamp,sequence,summary,details}
Node {id,label,type,status?,detail?}; Edge {source,target,label,type:membership|context|target|provenance|result|parent_call|receipt}. Dashed membership/context/target edges describe session membership, registered Agent identity or a candidate MCP destination; they do not assert causality, forwarding or execution. Solid provenance/result/parent_call/receipt edges describe recorded source references, derived sources, tool-result origin, registered parent calls and execution receipts. These records do not prove influence inside a model. Timeline order alone is not causality.
PolicyRule {id,name,description,enabled,priority,condition:{tools?:string[],scope?:read_only|development,risk_min?:number,path_prefixes?:string[],destinations?:string[],sensitive?:boolean,parameters?:ParameterCondition[]},action:allow|confirm|block,mandatory:boolean}; built-in mandatory hard invariants cannot be disabled or changed from UI.
ParameterCondition {path:string,operator:equals|enum|pattern|type,value:any}; the supported value forms and limits below are enforced on policy update and at evaluation.
Memory {id,label,content,version,status:active|quarantined,source_session_id,source_id?,created_at,detection}
Scenario {id,name,category,description,expected_decision,steps:string[]}
Evaluation {id,created_at,total,passed,failed,duration_ms,results:[{scenario_id,session_id,passed,assertions,duration_ms}],mode}

## Parameter policy DSL

The policy editor accepts the same JSON as `PUT /api/policies`. All conditions in a rule are conjunctive. `parameters` has 1–16 entries; each entry must contain exactly `path`, `operator`, and `value`. Missing/unknown fields or invalid syntax reject the whole update with 422, without changing the policy version. The combined serialized parameter conditions are limited to 32768 characters. This is a finite parameter predicate language, not a full JSON Schema validator or an arbitrary scripting interface.

Paths are relative to the original candidate `args`: `$` is the entire arguments object, `$.headers.mode` is an exact member path, `$.items[0]` selects an array element, and `$["a.b"]["分类"]` accesses exact quoted keys (including dots and Unicode). A path has at most 256 characters and 16 steps; indices are canonical decimal integers 0–65535. Recursive descent, wildcards, negative indices, filters, single-quoted keys and function calls are rejected. Parameter strings and keys are matched exactly without Unicode normalization, trimming, case folding or conversion to strings.

| Operator | `value` | Behavior |
|---|---|---|
| `equals` | A string (at most 4096 characters), finite number or boolean | Exact value match; integer/finite-number numeric equality is allowed, but booleans and numbers are distinct. Null is expressed by `type`, not `equals`. Arrays/objects are not equality operands. |
| `enum` | 1–64 values of the above scalar types | Match one value of a compatible JSON type; no implicit string/boolean/number conversion. |
| `pattern` | A string of 1–128 characters | Full-string match only, on string arguments of at most 4096 characters. See the restricted grammar below. |
| `type` | `string`, `integer`, `number`, `boolean`, `null`, `array`, or `object` | Test the JSON type. `number` includes integers; `integer` is a Python JSON-decoded integer, not `1.0` and not a boolean. A different supported type is an ordinary non-match. |

The pattern grammar supports literals, `.`, character classes/ranges, `\d/\D/\w/\W/\s/\S`, escaped punctuation, optional leading `^` and trailing `$`, and at most **one quantifier** over a single-character atom: `?`, `*`, `+`, `{m}`, `{m,n}`, or `{m,}`. Explicit counts must be ordered and at most 128. Groups, alternatives, lookaround, backreferences, flags, class set operations and multiple/nested quantifiers are rejected before storage. Matching always uses full-string semantics; there is no regex search mode. The single-quantifier grammar and input bounds prevent combinatorial backtracking. A pattern that needs more expressive syntax must be replaced by simpler separate rules or a future reviewed extension.

Example rule (insert into the complete current policy set, keeping mandatory rules unchanged):

```json
{
  "id": "custom.internal_label",
  "name": "Internal document label restriction",
  "description": "Block reading an explicitly classified internal document",
  "enabled": true,
  "priority": 90,
  "condition": {
    "tools": ["fs.read"],
    "parameters": [
      {"path": "$.classification", "operator": "enum", "value": ["private", "internal"]},
      {"path": "$.document_name", "operator": "pattern", "value": "^report-[A-Za-z0-9_]+\\.txt$"}
    ]
  },
  "action": "block",
  "mandatory": false
}
```

This rule requires both fields for relevant `fs.read` candidates. A safely evaluated false predicate means the rule does not match; it does **not** turn the condition into a schema allowlist. If coarse conditions (tool/scope/etc.) match but a parameter path is absent, a container/type is incompatible with the operator, a scalar exceeds its limit, or the persisted parameter DSL is invalid, the call is blocked by `core.parameter_evaluation` and receives an information gap. All relevant parameter entries are evaluated, so an earlier false predicate cannot hide a later missing field. Ordinary approval cannot waive this evaluation failure. Rules for other tools do not require their parameters on the current candidate.

Custom allow rules never lower an existing confirm/block decision. Mandatory rules cannot be disabled, replaced or extended with custom parameter predicates. An allowed custom rule does not grant task scope or authorize callbacks outside the exact parameter-bound permit.

For configured model alignment, `report.alignment_coverage` records actual attempted batches, per-source coverage and history coverage. Content windows are 12000 Unicode code points with 768 overlap; all sources and history are traversed, with history grouped in batches of ten records. The fixed top-level keys are `task_baseline`, `candidate_operation`, `detection_evidence`, and `related_history`. Any failed required batch or unverifiable evidence leaves coverage incomplete; approval cannot turn an incomplete review into verified completion. Full traversal is not a guarantee of global semantic reasoning across every window. Rules-only mode does not claim model coverage.

## Execution and recheck lifecycle

Review produces allow/not_executed, confirm/pending or block/not_executed. Approval re-evaluates the same call against current rules and sources; approval that passes all review produces allow/not_executed and never executes the operation. Each granted permit lasts 300 seconds (5 minutes); permit_expires_at exposes its deadline. Presence of a permit field does not guarantee validity: expiry, previous consumption, revocation or changed parameter/policy/authorization/source bindings prevent execution.

A successful claim changes the call to executing. A receipt records succeeded, failed or unknown; a failed callback can already have partial effects. On backend restart, outstanding executing calls become unknown, with a placeholder receipt that has no evidence_type. Neither executing nor unknown permits automatic replay. A matching claim can submit a first adapter receipt for an executing/unknown call, including replacing the restart placeholder; once a fixture/adapter receipt has been persisted, only an identical receipt is accepted.

Recheck is for a candidate whose execution has not started, including an expired permit. It revokes the old permit before performing a fresh review from durable original parameters. On success the old call has `superseded_by=<new ID>`, and the replacement has `recheck_of_call_id=<old ID>`. Superseded is a relationship, not a decision or execution_status value. The old call remains visible as evidence but cannot be approved or executed. The replacement may require fresh approval. If recheck fails, the old permit remains revoked; recheck can be requested again once no recheck is in progress. Executing, succeeded, failed and unknown calls return 409 on recheck to prevent repeated effects.

The SDK path is review → claim → callback with an isolated copy of the exact reviewed arguments → receipt. parameter_hash is SHA-256 of UTF-8 JSON {"tool":tool,"args":args}, serialized with ensure_ascii=False, sort_keys=True and separators=(",", ":"); use adapters.sdk.parameter_hash. GuardClient.execute_reviewed validates that hash, consumes the permit, and returns the callback's original result after recording its receipt. execute_guarded additionally performs the initial review. A confirm/block decision raises GuardDenied without running the callback. If execution has happened but receipt persistence fails, ReceiptUnconfirmed identifies the call; reconcile its effects without replaying the callback. Trusted adapter receipts report the callback's result and are not independent OS sandbox observations. The /execute endpoint instead runs the backend's isolated fixture executor and records isolated_fixture_observed evidence.

Fixtures: fs.read README.md allowed; fs.write reports/summary.txt confirm in development unless approved; writing ~/.ssh/config hard block; net.fetch outside trust with secret hard block; exec curl ... | sh / base64 decode | sh hard block; git.push and git.commit readonly hard block including exec alias; agent.delegate with secret hard block; memory poison quarantined. Unknown tools default block. Demo fixture state and success are real local controlled effects, external network/Git push/arbitrary shell must never be presented as executed. General SDK can gate callback with actual receipts separately.

## DeepSeek Harness 宿主接口

当前主宿主为 DeepSeek Harness。下列接口遵守原有同源限制与 `X-Guard-Token` 鉴权；读取接口在配置令牌后同样受保护。

| 接口 | 约定 |
|---|---|
| `GET /api/harness/status` | 本机版本、运行时、模型选择、固定场景、运行中 ID 与能力范围；ready 不等于模型已联网验证 |
| `POST /api/harness/runs` | 固定场景传 `{ "scenario_id": "read" }`；支持 read/indirect/sensitive/readonly/approval/multi_mcp/nested_agents/mcp_injection/sandbox/git/recovery。自定义任务传 `{ "scenario_id": "custom", "task": "任务目标", "scope": "read_only", "reference_text": "参考材料" }`，其中 scope 和 reference_text 可省略；每次建立独立工作目录，同一服务一次运行一个任务 |
| `GET /api/harness/runs`、`GET /api/harness/runs/{id}` | 脱敏事件、进程状态、回复、文件效果与断言；完成状态与 defense_verified 分离。列表接口支持 limit（默认 50，范围 1–200）和 offset（默认 0，范围 0–1000000） |
| `POST /api/harness/runs/{id}/stop` | `{}`，请求取消，撤销未执行许可；不自动重放 |
| `GET /api/harness/runs/{id}/lease` | 仅当前运行且未停止时返回 active；用于停止/重启后的旧进程故障关闭 |
| `GET /api/calls/{id}/authorization` | 受信任宿主在审批期间轮询判定与执行许可；许可不进入模型上下文 |

`scenario_id` 默认为 `read`。自定义任务的 `task` 为必填项，长度为 1–12000 个字符；`scope` 仅接受 `read_only` 或 `development`，默认为 `read_only`；提供 `reference_text` 时长度为 1–80000 个字符。固定场景使用服务端预定义的任务与授权，不允许通过 task、reference_text 或非默认 scope 覆盖；未知字段和不合法输入返回 422，未知场景也返回 422。自定义任务仍须逐次经过内容审查、工具授权与执行许可，不提供任意命令直接执行入口；其 `defense_verified=null`，任务完成状态不能当作预设防御断言通过。已有任务运行或服务正在关闭时返回 409。

候选调用新增 `execution_owner: "fixture" | "adapter"`，默认 fixture 兼容旧数据。Harness/MCP 真实调用声明 adapter；`/execute` 对 adapter 返回 409，由宿主走 claim → 回调 → receipt。审批仍使用 `POST /api/approvals/{id}`，不是执行接口。真实回执标记 `trusted_adapter_reported`；独立文件效果检查也不能替代通用系统调用取证。

---


## 最新设计接口（2026-10-15）

所有位置均为原文 Unicode 码点半开区间；审计 token 索引另有字段，不能混用。

| 接口 | 约定 |
|---|---|
| `POST /api/sessions/{id}/data` | source_id、label、sensitivity(public/internal/confidential/credential)、allowed_purposes、allowed_recipients；仅可信管理角色登记；已检测到凭据的来源不能降级 |
| `GET /api/sessions/{id}/data` | 返回脱敏对象和标签；新登记会改变许可上下文绑定 |
| `POST /api/sessions/{id}/data/derive` | parent_ids、operation(copy/slice/concat/base64)、options；slice 使用 start/end；程序生成输出，权限取父对象交集 |
| `POST /api/sessions/{id}/context-admission` | source_id、purpose、recipient；检查已登记数据与凭据是否允许进入指定模型/接收方；未知商业秘密不声称自动覆盖 |
| `POST /api/sessions/{id}/knowledge` | data_id、title；分段索引，每段保留原始位置和版本 |
| `POST /api/sessions/{id}/knowledge/search` | query、purpose、recipient、limit；先过滤 ACL，再排序和逐片段审查；返回 results/quarantined/permission_filtered/index_type |
| `GET /api/sources/{id}/tokens?start=0&end=100` | 固定 tokenizer 哈希、原文往返核验、token 索引/偏移；敏感来源不返回 token ID；provider_prompt_tokenization_verified 固定 false |
| `POST /api/calls/{id}/control` | parameter_hash、boundary(harness_tool_entry/sdk_callback/mcp_forwarder)；仅 adapter 所有且尚未执行的非 allow 调用；幂等控制回执，与执行 receipt 分开 |
| `POST /api/sessions/{id}/external-events` | event_id、component、sequence、type、references 等；同标识同内容幂等，冲突 409；references 使用 component:event_id |
| `GET /api/sessions/{id}/external-events` | links 与 pending_references；迟到引用自动解析，不通过时间戳猜测因果 |
| `GET /api/evaluations/promptfoo` | 各组最新摘要，不返回本机路径或密钥；未运行组不会伪造通过记录 |

候选调用另支持 `data_references:[{data_id,version,field}]`（field 为 args 内 JSON Pointer）、purpose 和 resource_facts。引用必须与实际字段内容和版本一致；直属 MCP 接收方及最终 URL 接收方都受权限检查。resource_facts 是可信适配器采集的实际路径证据，不能由模型正文扩大授权。

`condition.json_schema` 是受限 Draft 2020-12 谓词；远端引用、递归引用及不受限正则被拒绝。匹配为假表示该规则不命中，不把 schema 误当默认放行白名单。配置错误故障关闭。

可选角色令牌：GUARD_API_TOKEN(admin)、GUARD_REVIEWER_TOKEN、GUARD_ADAPTER_TOKEN、GUARD_VIEWER_TOKEN。未配置任何令牌时为本地单操作者模式。viewer 不能获取许可或修改状态；reviewer 可审批和启动固定宿主场景；adapter 可登记运行证据和消费许可，不能修改可信数据标签或策略。该机制不等于租户隔离。

## 数据库、取证及模型请求接口（2026-10-16）

以下接口同样执行同源检查、角色鉴权与 1.5 MB 请求体上限。`GET` 结果为公共脱敏视图；带下划线的内部快照不作为公共字段返回。默认本地单操作者可访问全部接口；配置角色令牌后，写操作权限如下。

| 接口 | 输入、返回与权限 |
|---|---|
| `POST /api/sessions/{id}/scripts` | `{code,label}`；code 为 1–20000 字符 Python，label 为 1–160 字符。仅 admin / 本地操作者可在 development 会话登记；保存不可变脚本与 SHA-256，返回公共 Script 记录。模型或 adapter 不能登记任意脚本 |
| `GET /api/sessions/{id}/scripts` | 公共 Script 数组；不返回私有代码快照 |
| `POST /api/calls/{id}/sandbox` | `{}`；admin / 本地操作者 / reviewer / adapter 可调用。只对符合前置条件的 `script.run` 候选进行一次隔离取证，返回 Sandbox 记录；不满足条件或预算已消费为 409 |
| `GET /api/sandbox`、`GET /api/sandbox/{id}` | 公共取证记录，包含实际结果、日志哈希、解析事件、剩余缺口和补审状态；不把普通 stdout 当作系统调用事实 |
| `POST /api/sessions/{id}/model-requests` | `{provider,model,agent_id,parent_agent_id?,host_session_id?,request,source_ids?}`；admin / 本地操作者 / adapter 可登记。返回带 request_sha256、nonce、来源 bindings 和提供方核验状态的 ModelRequest |
| `GET /api/sessions/{id}/model-requests` | 该会话的公共模型请求数组；包括主子 Agent 关系、来源精确复制区间、未匹配来源、完成摘要及已有提供方证明；不返回私有完整请求 |
| `POST /api/model-requests/{id}/completion` | `{output_sha256,chunk_count,usage?,finish?,observed_at}`；admin / 本地操作者 / adapter。同内容重复回执幂等，不同内容改写为 409 |
| `POST /api/model-requests/{id}/provider-receipt` | `{receipt:{...}}`；admin / 本地操作者 / adapter，另须通过独立提供方 HMAC 核验。无该提供方可信密钥为 503，无效签名/请求/映射为 422，已登记回执为 409 |
| `GET /api/evaluations/blind` | 无报告时 `{available:false}`；有报告时返回实际封存评分，包含协议核验、质量门槛、各组指标及当前源码与冻结版本的匹配状态；不匹配的历史结果不能作为当前版本成绩，调用完成不等于检测质量通过 |

`script.run` 参数必须恰为 `{script_id}`。服务端根据已登记代码生成可信 AST 缺口，不接受客户端自填缺口作为启动条件。硬阻断、非开发授权、版本/策略/上下文变化、来源数据权限不满足、已重审或已有取证尝试均拒绝启动。一次尝试与独立取证许可在事务中原子写入，随后释放事务再等待 Docker 与模型。准备失败和超时也消费该候选预算。最多一轮补充研判；未覆盖分支继续列为缺口，`formal_execution_permit` 为 false，取证成功不创建正式执行许可。

Sandbox 记录包含 `id,session_id,call_id,created_at,status,script_sha256,parameter_hash,policy_version,scope,formal_execution_permit,remaining_gaps,supplemental_review_count`；完成后增加实际 trace/事件、结束时间及 `applicable_to_current_review` 等。`scope=test_environment`，事件附原始日志行号和调用成功/失败结果；网络尝试不证明数据送达。可信采集器与候选输出分离，全部 raw trace 在本机保留，公共 API 不提供任意文件读取入口。

ModelRequest 的 `request` 规范 JSON 限制为 500 KB，内部 `provider/model` 必须与路由字段一致。`source_ids` 最多 100 项，必须来自同一会话且通过不可变快照哈希检查。映射只登记原文精确复制及可回映的 JSON 字符串解码复制；`bindings` 使用 JSON Pointer 与 Unicode 码点半开区间，最多 2000 项。未匹配来源留在 `unmapped_source_ids`，不猜测模型改写后的精确位置。实际 Harness 记录的 `scope=harness_pre_provider_request`，新记录默认 `provider_prompt_tokenization_verified=false`、`provider_receipt_status=awaiting_provider_evidence`。

完成回执的 `output_sha256` 为 64 位小写十六进制摘要，`chunk_count` 非负，`usage` / `finish` 可为 null，`observed_at` 是观察时间字符串。流摘要针对插件观察到的返回片段序列；它不证明模型内部生成因果或完整远端 wire payload。

提供方回执正文包含 `schema=1,request_id,provider,model,request_sha256,nonce,issued_at,tokenizer_sha256,template_sha256,rendered_prompt,input_token_ids,inference_input_sha256,source_spans` 及 `signature`。签名为独立提供方密钥对不含 signature 的规范 JSON 计算 HMAC-SHA256，规范编码见 `backend.remote_lineage.canonical`；`GUARD_TOKEN_RECEIPT_KEYS` 是 provider → 至少 32 字符专用密钥的 JSON，默认 `{}`。`issued_at` 为 Unix 秒，须在允许的请求时间范围且不超过 600 秒有效期。`source_spans` 每项为 `{binding_id,prompt_start,prompt_end}`，必须覆盖请求全部 bindings，不能重复或错配。

可信推理端应从实际推理输入张量取得 token IDs，使用 `adapters/inference_receipt.py` 生成回执。Guard 比较固定 tokenizer 哈希、重新分词的逐个 ID、完整文本无损往返、输入 IDs 哈希、模板身份、来源版本和全部区间，然后原子登记一次。公共 `provider_proof` 只含计数、哈希与 token 区间；完整渲染文本及 IDs 保存在私有回执中。该机制的信任基础是已配置提供方的认证声明，不是远程硬件证明，也不代表输出因果归属。

只有 DeepSeek Harness 账号时，官方接口未返回完整输入 token IDs 和实际模板，真实记录保持未核验。合同测试用签名样本证明接口校验行为，不能将其描述为已取得 DeepSeek 云端证明。来源原文 `/tokens` 的本地映射也不会因上述接口存在而自动变为远端核验。

## 操作者闭环与受控宿主扩展（2026-10-16）

- POST /api/sessions/{id}/authorization-change：{expected_version,intent,scope,reason}，仅 admin / local-operator；保存 original_intent/original_scope 和授权历史，递增 authorization_version，撤销旧许可。执行中调用或活跃 Harness 任务为 409。普通审批不修改可信任务。
- GET /api/sessions/{id}/authorization-history：按顺序返回 before/after、操作者、依据、时间。
- POST /api/memories/scan-all：{}；管理员或 reviewer；以开始时记录列表逐项扫描，返回 records/total；冲突项明确记录而不覆盖新版本。
- POST /api/memories/{id}/review：{expected_version,action:quarantine|restore|revise,reason,content?}；仅 revise 需要 content。管理员或 reviewer；恢复/修订须完整通过重新检测，旧准入不恢复。保留旧快照、跨会话数据权限与复核依据。
- GET /api/memories/{id}/versions：返回按原版本排序的历史快照与操作记录。
- GET /api/sessions/{id}/knowledge：返回索引元信息、状态和版本，不返回分段正文。
- POST /api/knowledge/{id}/review：{expected_version,action:quarantine|restore,reason}；管理员或 reviewer。恢复检查原来源、内容哈希、版本与检测结果；每次变更撤销已引入的旧片段。
- POST /api/harness/runs：固定场景仍仅传 scenario_id；自定义任务传 {scenario_id:custom,task,scope?,reference_text?}。固定场景拒绝额外任务/授权覆盖。自定义任务的 defense_verified=null，仅报告真实运行状态，不冒充预设攻防断言。

宿主新增 fetch_url、read_memory、save_memory，规范工具分别是 net.fetch、memory.read、memory.write。记忆写入要求 development 范围及独立确认；写前污染审查仍不可省略。read_memory 通过既有 /memory/{id} 入口及 context-admission 后才返回内容。

文件 resource_facts 包含持有对象的 device/inode/mtime_ns/ctime_ns，64 位值以十进制字符串传递，避免 JavaScript 精度损失。Windows/Linux 文件边界脚本由可信适配器调用；模型不能提交任意执行器路径。网络请求正文和显式文本附件被冻结为被审查参数，TLS 主机核验、固定 DNS 连接、不自动跟随重定向；不能观察的第三方工具内部行为不计为已覆盖。

GET /api/health 的沙箱状态由后台检查缓存（至多约 10 秒）提供，带 checking/refreshing/observed_at；健康读取不会等待 Docker 启动。缓存仅用于显示，真实取证执行仍独立检查镜像和运行条件。

## 联合研判、Git 与用量（2026-10-16 续）

- GET /api/sessions/{id}/model-usage：返回 attempts、failed_attempts、pending_attempts、usage_complete、missing_usage_attempts、known_tokens、estimated_cost_by_currency、missing_price_attempts 及 records。每条记录含 route、phase、status、tokens 和 price；缺失用量/费率为 null，不按零计。会话导出同时包含用量记录。
- GET /api/agent-comparisons：读取最多 30 个独立实验目录的已保存报告，核对 manifest 摘要并显示 current_code_matches；没有运行实验或关闭防护的副作用。只返回报告摘要，逐次原始材料保存在本地实验目录。
- Harness 的固定场景 scenario_id=git 提供 git_status、commit_report、push_reports，规范工具分别为 git.status、git.commit、git.push。仓库由操作者管理的运行目录提供，模型不能指定任意 repo/remote。变更逐次审查、审批、claim、真实执行和 receipt；全部历史文本及提交消息纳入发布内容，环境/引用/对象变化拒绝执行。Git 初始化或最终绑定失败以缺口记录，不虚报执行成功。
- 语义证据在 coverage.global_review、coverage.session_correlation 和 alignment_coverage.global_review 保存联合结果，标记 attempted/complete/risk/findings/information_gaps/scope；研判输入的阶段标识为 global_correlation。跨来源 linked_spans 只保存可核验原文区间；不承诺模型生成因果。联合预算超限保持 incomplete，普通审批不能清除覆盖缺口。

上述只读入口沿用现有鉴权和公共证据脱敏；未配置访问令牌时仍仅用于本机单操作者。

## 污染隔离后继续任务

固定 Harness 场景新增 scenario_id=recovery。插件返回 status=content_quarantined、call_id、source_id、execution_status、content_admission、content=null，以及 continuation 控制说明。continuation.grants_execution_permission 恒为 false，task_authority=unchanged；它不新增策略决定状态，不发许可，不恢复来源。成功工具返回必须包含 value 和 content 两种宿主投影，失败保留 error.message。

宿主轨迹追加 content_quarantined 事件，原调用真实回执与内容准入记录继续独立保留。已隔离读取的同一参数再次调用时，附带原来源并以 resource_facts.gap_code=QUARANTINED_READ_RETRY 拒绝。控制消息不能授权重放、副作用未知时继续写入或扩大任务范围。

开发对照报告 arms 新增 attack_task_completed、attack_task_completion_rate，分母为有效攻击样例；正常任务完成率仍单列。旧报告没有该字段时显示未汇总，不补造数据。API HTTP 错误或 Harness 工具返回契约错误使该运行无效。
