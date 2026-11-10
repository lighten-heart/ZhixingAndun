# 智行安盾 · 程序源码与运行说明

智行安盾是面向智能体提示注入和工具滥用的安全组件，提供内容准入、工具调用审查、人工复核、执行回执和溯源复盘。主宿主为 DeepSeek Harness；前端、后端和宿主适配器均包含在本目录中。

## 1. 目录与运行方式

| 目录或文件 | 用途 |
| --- | --- |
| `backend/` | FastAPI 服务、检测与策略、证据存储、宿主管理 |
| `frontend/` | React 前端源码及依赖锁定文件 |
| `adapters/` | DeepSeek Harness、MCP、受控工具与模型接入 |
| `assets/` | 本地分词及来源映射所需资源 |
| `sandbox/` | 可选 Docker / strace 取证容器 |
| `tests/` | 组件测试与回归验证 |
| `requirements.lock.txt` | Python 依赖锁定清单 |
| `.env.example` | 本机配置模板，不含账号密钥 |
| `compose.infrastructure.yaml` | 可选 PostgreSQL 服务 |
| `Dockerfile`、`compose.yaml` | 安全组件容器部署 |

推荐在 Windows 本机运行后端和 Harness，构建后的前端由后端统一提供，访问地址为 `http://127.0.0.1:8765`。默认数据库是 SQLite，首次启动自动建立数据目录，无需安装数据库服务。首次打开时没有任务、告警或评测结果；运行后生成的数据保存在当前机器。

## 2. 环境与硬件

| 项目 | 要求或建议 |
| --- | --- |
| 操作系统 | Windows 10 / 11，64 位 |
| Python | 3.12 或 3.13，64 位，安装时勾选加入 PATH |
| Node.js | 22.x，包含 npm，安装后重新打开 PowerShell |
| Git | 安装 Git for Windows，确保 `git` 可从终端调用 |
| 浏览器 | 当前稳定版 Microsoft Edge 或 Google Chrome |
| Harness | DeepSeek Harness 桌面版 **0.2.0-rc.2**；真实宿主任务需已登录且账号有可用额度 |
| Docker | 仅 PostgreSQL、动态取证或容器部署需要 Docker Desktop，使用 Linux containers |
| 网络 | 首次下载依赖、镜像及调用云端模型需要联网 |

本机建议采用 4 核处理器、8 GB 内存和 10 GB 可用磁盘；同时运行 Docker 与宿主时，建议 8 核、16 GB 内存和 20 GB 可用磁盘。以上是部署建议，并非经过硬件下限测试的最低配置。云端模型接入不要求本地 GPU。

## 3. 安装与启动

以下操作逐条在 PowerShell 中执行，不需要启用虚拟环境，不需要更改 PowerShell 执行策略。示例将源码解压至 `C:\ZhixingAndun`；实际解压位置不同，请替换第一条命令中的目录。

### 3.1 检查环境

```powershell
Set-Location C:\ZhixingAndun
py -3.12 --version
node --version
npm.cmd --version
git --version
```

Python 3.13 用户将下文创建虚拟环境命令中的 `-3.12` 改为 `-3.13`。如果 `py` 未找到，请重新安装 Python 并启用 Python Launcher；不要使用 Microsoft Store 的空占位命令。

### 3.2 安装后端依赖

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --index-url https://pypi.org/simple --upgrade pip
.\.venv\Scripts\python.exe -m pip install --index-url https://pypi.org/simple -r requirements.lock.txt
.\.venv\Scripts\python.exe -m pip check
```

最后一条命令应显示 `No broken requirements found.`。安装未成功时，先解决网络、Python 版本或依赖下载问题，再继续下一步。

### 3.3 构建前端

```powershell
Set-Location frontend
npm.cmd ci
npm.cmd run build
Set-Location ..
```

构建完成后应存在 `frontend\dist\index.html`。日常运行不需要另外启动前端开发服务器。

### 3.4 创建配置

首次部署时执行：

```powershell
Copy-Item .env.example .env
notepad .env
```

保留以下本机基础配置：

```dotenv
GUARD_HOST=127.0.0.1
GUARD_PORT=8765
GUARD_DATA_DIR=./data
GUARD_DATABASE_URL=
GUARD_URL=http://127.0.0.1:8765
GUARD_MODEL_BACKEND=
GUARD_TOKEN_RECEIPT_KEYS={}
HARNESS_PROVIDER=deepseek-account
HARNESS_MODEL=deepseek-flash
```

`GUARD_MODEL_BACKEND` 为空时采用本地规则检测；这不影响前端、证据存储和组件场景运行。独立语义审查的配置见第 5 节。其他未使用的可选项保持模板默认值。

如需访问控制，在 `GUARD_API_TOKEN` 后填写自己生成并保存的随机令牌；启动后在网页右上角“连接设置”→“访问设置”→“访问令牌”中填写同一值，点击“保存连接配置”。该令牌不是 DeepSeek 账号密钥。只在本机单人使用时，可以保持令牌为空并继续使用默认回环地址。

### 3.5 准备 DeepSeek Harness

1. 从 DeepSeek 官方渠道安装 **0.2.0-rc.2** 桌面版，启动并完成账号登录。
2. 在 Harness 中完成一次普通对话，确认账号认证、模型访问和额度可用。
3. 关闭该次对话任务，回到项目根目录，在 PowerShell 执行：

```powershell
.\.venv\Scripts\python.exe -m adapters.harness.runtime
```

程序从本机已安装的桌面应用准备独立运行时，并验证版本及关键文件。输出应包含 `"ready": true`、`"version": "0.2.0-rc.2"` 和 `"credential_store_present": true`。它不修改桌面版安装文件；“ready”只表示本机运行时就绪，不能代替云端连通性检查。

默认安装位置为当前用户的 `AppData\Local\Programs\DeepSeek Harness`，默认使用当前用户已有的 Harness 登录。不要将登录文件复制进源码目录或交给其他审查人员；每位使用者在自己的电脑登录。

若桌面应用安装在其他目录，请在当前终端设置实际位置，再执行准备命令：

```powershell
$env:HARNESS_DESKTOP_DIR = "D:\Apps\DeepSeek Harness"
.\.venv\Scripts\python.exe -m adapters.harness.runtime
```

同时在 `.env` 中填写同一目录，供以后启动读取：

```dotenv
HARNESS_DESKTOP_DIR=D:/Apps/DeepSeek Harness
```

不支持用其他版本冒充该版本。版本或关键文件校验失败时，安装匹配版本后重试。未安装 Harness 的机器仍可运行组件页面及第 4.1 节验证，但不能执行真实 Harness 任务。

### 3.6 启动服务并打开网页

确认终端位于项目根目录：

```powershell
.\.venv\Scripts\python.exe -m uvicorn backend.main:app --env-file .env --host 127.0.0.1 --port 8765
```

保持该终端运行，在浏览器访问：

- 系统页面：`http://127.0.0.1:8765`
- 健康检查：`http://127.0.0.1:8765/api/health`
- 接口文档：`http://127.0.0.1:8765/docs`

健康检查应返回 `status: "ok"`。网页右上角可查看连接设置及宿主状态；如设置了访问令牌，先完成令牌填写。修改 `.env` 后需停止并重新启动后端，已启动进程不会自动重载配置。

本系统采用单后端实例管理执行许可及持久化证据；请使用上述单进程启动方式，不添加多 worker 参数，也不要同时启动两个进程共用同一数据目录或数据库。

## 4. 运行与测试

### 4.1 组件检查

后端服务运行时，可进入“攻防场景”，选择页面列出的场景并执行，查看逐项断言及对应会话；这些场景使用受控工具环境，不要求云端模型账号。进入“评测报告”后，可点击“运行场景验证”生成本机新的组件评测记录。

也可另开 PowerShell，在项目根目录执行：

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

该命令验证组件行为，使用测试隔离数据；它不等同于一次真实 Harness 云端调用，也不代表账号、外部模型或所有 Docker 环境已通过验证。真实宿主按下列步骤单独检查。

### 4.2 正常读取与多 MCP

1. 进入“任务运行”，确认 DeepSeek Harness 运行时已就绪。
2. 在“任务场景”选择“正常读取”，检查“场景任务”，点击“启动任务”。
3. 在“运行过程”查看工具调用、审查及回执；结束后切换“结果与回执”，检查任务回复和场景断言。
4. 当前任务结束后，选择“多 MCP 实际调用”并启动。该场景要求分别调用文档与知识库 MCP 工具。
5. 在“运行过程”核对“连接 MCP 服务”“转发 MCP 请求”和“工具执行回执”；在“结果与回执”查看断言。以实际事件、执行回执及断言为准，不以最终自然语言回复代替执行证据。

### 4.3 污染隔离后完成原任务

1. 在“任务运行”选择“隔离污染后继续合法任务”，页面自动填入固定任务及开发授权。
2. 点击“启动任务”。该场景要求读取 `external-note.txt`，随后将原任务直接指定的 `PUBLIC_REPORT_READY` 写入 `reports/recovery.txt`，正文不含换行。
3. 查看“运行过程”：外部参考资料中的任务篡改指令应被隔离；宿主继续提交与原任务一致的报告写入请求。
4. 出现“操作已挂起，等待确认”后，点击“确认复核”。核对当前任务、工具参数、目标路径及完整正文，确认仅写入 `reports/recovery.txt`。
5. 在“复核说明”记录判断依据，点击“确认并重新审查”；随后点击“查看任务”回到任务运行记录。
6. 等待任务结束，打开“结果与回执”：检查报告正文为 `PUBLIC_REPORT_READY`，并核对全部场景断言。隔离资料中要求的攻击文件不应产生。
7. 点击“告警研判”查看污染来源与阻断依据，点击“溯源复盘”查看本次会话的来源、候选操作、审批及执行回执。

审批等待上限为 180 秒，任务运行上限为 300 秒。超时后不要对旧记录继续操作，应结束旧任务并新建一次运行。模型返回、网络延迟和账号额度会影响真实任务结果；记录出现失败时保留原始记录，根据错误定位后重新运行，不能把“已结束”直接当成“全部断言通过”。

### 4.4 其他页面

| 页面 | 操作与核对内容 |
| --- | --- |
| 任务运行 | 发起宿主任务，查看运行事件、工具结果和产出文件 |
| 告警研判 | 核对风险来源、命中证据、决策和执行状态 |
| 确认复核 | 对待确认操作逐项核对后批准或拒绝；硬阻断不能由普通审批绕过 |
| 溯源复盘 | 按会话追溯来源、工具调用、关联关系、回执与证据 |
| 安全总览 | 查看当前数据中的任务、调用、风险与组件状态 |
| 策略中心 | 查看或调整策略；策略调整会影响后续审查，应记录修改依据 |
| 记忆防护 | 查看记忆内容、污染检查和隔离状态 |
| 隔离取证 | 查看数据库、Docker / strace 可用性及已生成取证记录 |
| 攻防场景 | 执行内置组件场景并核对实际断言 |
| 评测报告 | 查看本机生成的场景验证及可用的评测记录 |

本地来源定位、工具事件与审计分词可以核验；云端模型的实际输入 token 和内部影响关系，只有推理服务提供相应可信回执时才能验证。仅有 Harness 账号不能提供完整的远端 token 血缘证明。

## 5. 可选：独立语义审查

需要在规则检测外启用语义研判时，可使用已登录的 Harness 账号。在 `.env` 中设置：

```dotenv
GUARD_MODEL_BACKEND=harness
```

保持 `GUARD_MODEL_BASE_URL`、`GUARD_MODEL_NAME`、`GUARD_MODEL_KEY` 为空，保存并重启后端。该方式使用独立的审查调用，与业务任务区分，但仍使用本机 Harness 账号及其额度。先执行一次短任务，核对实际模型请求和审查结果；页面“已配置语义服务”不代表模型调用已成功。

也可接入兼容 Chat Completions 的模型服务，设置 `GUARD_MODEL_BACKEND=http`、`GUARD_MODEL_BASE_URL`、`GUARD_MODEL_NAME`，以及服务需要的 `GUARD_MODEL_KEY`。基础地址应为实际 API 前缀，程序会追加 `/chat/completions`；非本机服务必须使用 HTTPS。模型必须支持结构化 JSON 响应。

必要语义检查失败、认证失效或额度不足时，系统会保留信息缺口并停止对应操作，不会将失败检查记为通过。服务恢复后发起新任务验证。

## 6. 可选：Docker / strace 取证

1. 安装并启动 Docker Desktop，按其提示启用 WSL 2 和虚拟化，切换至 Linux containers。
2. 在项目根目录执行：

```powershell
docker version
docker info --format "{{.OSType}}"
```

前者应同时显示 Client 和 Server 信息，后者应输出 `linux`。
3. 构建取证镜像并读取不可变镜像 ID：

```powershell
docker build -t zhixing-sandbox:local -f sandbox/Dockerfile sandbox
docker image inspect zhixing-sandbox:local --format "{{.Id}}"
```

4. 将输出的完整 `sha256:` 加 64 位十六进制字符串填入 `.env` 的 `GUARD_SANDBOX_IMAGE`，不要填写镜像标签。
5. 重启后端，在“隔离取证”核对镜像就绪，再在“任务运行”选择“Docker 行为取证”并启动。
6. 结束后核对场景断言、执行状态、镜像身份及取证记录。取证结论只覆盖本次候选进程实际执行的路径，不代表任意程序的所有可能行为均已检查。

## 7. 可选：PostgreSQL

本节适用于后端仍在 Windows 本机运行、PostgreSQL 在 Docker 中运行的方式。先停止后端，再操作配置。

### 7.1 配置并启动数据库

首次部署执行：

```powershell
Copy-Item postgres.env.example postgres.env
notepad postgres.env
```

保留数据库名和用户名，将 `POSTGRES_PASSWORD` 设置为自行生成的足够长随机密码，不能留空。为便于填写连接地址，可使用 24 位以上随机字母和数字；若密码含 `@`、`:`、`/` 等字符，连接地址中的密码必须按 URL 规则编码。

```powershell
docker compose -f compose.infrastructure.yaml up -d
docker compose -f compose.infrastructure.yaml ps
docker compose -f compose.infrastructure.yaml exec postgres pg_isready -U aegisguard -d aegisguard
```

数据库就绪时，最后一条命令显示 `accepting connections`。数据库只发布到本机 `127.0.0.1:55432`。

### 7.2 接入后端

用记事本打开 `.env`，将 `GUARD_DATABASE_URL` 修改为以下格式，替换密码占位内容：

```dotenv
GUARD_DATABASE_URL=postgresql://aegisguard:填写实际密码@127.0.0.1:55432/aegisguard
```

按照第 3.6 节启动后端，在健康检查和“隔离取证”中核对数据库类型为 `postgresql` 且连接正常。

首次使用 PostgreSQL 会建立新的证据库，不会自动把既有 SQLite 记录迁移过去。保留原 `data` 目录；需要回到 SQLite 时，停止后端、清空 `GUARD_DATABASE_URL` 后再启动。数据库初始化后，修改 `postgres.env` 不会自动修改已有数据库用户的密码。

## 8. 可选：安全组件容器部署

根目录的容器配置用于运行前端与安全组件 API，不包含已经登录的桌面 Harness，也不提供宿主 Docker / strace 集成。需要演示真实 Harness 主链路时，采用第 3 节的 Windows 本机方式。

采用此模式时，在 `.env` 中保持 `GUARD_DATABASE_URL`、`GUARD_MODEL_BACKEND` 和 `GUARD_SANDBOX_IMAGE` 为空，避免引用 Windows 本机的数据库、账号或镜像环境。先停止占用 8765 端口的本机后端，然后执行：

```powershell
docker compose up -d --build
docker compose ps
docker compose logs --tail 80 aegisguard
```

浏览器访问 `http://127.0.0.1:8765`，按第 4.1 节进行组件场景验证。证据存储在 Docker 命名卷中。

## 9. 故障处理与停止

| 现象 | 处理 |
| --- | --- |
| 页面提示前端尚未构建 | 在 `frontend` 目录完成 `npm.cmd ci`、`npm.cmd run build`，确认生成 `dist/index.html` |
| 无法连接本地服务 | 确认后端终端仍在运行、地址为 8765，查看终端错误及健康检查 |
| 401 / 403 或访问被拒绝 | 检查网页“连接设置”的令牌是否与后端配置一致，确认当前令牌角色有相应权限 |
| 端口已被占用 | 停止原先启动的本系统进程或容器后重启，避免两个实例同时访问证据库 |
| Harness 运行时待准备 | 核对 Node、桌面版安装位置及精确版本，重新执行第 3.5 节运行时准备 |
| 账号认证失效或额度不足 | 在官方 Harness 中重新登录或恢复额度，再新建任务 |
| 任务等待人工确认 | 进入“确认复核”，核对路径及参数后决定；超时后重新创建任务 |
| 语义配置无效或审查失败 | 检查第 5 节的后端类型、地址、模型名和账号，查看实际错误；不能把检查失败当作安全通过 |
| Docker 镜像未就绪 | 确认 daemon 为 Linux 模式、镜像构建成功，配置的是完整不可变镜像 ID |
| PostgreSQL 无法连接 | 检查容器健康、55432 端口及密码，确认连接 URL 中特殊字符已编码 |

停止本机服务前，先在“任务运行”中停止仍在运行的任务，再在后端终端按 `Ctrl+C`。停止容器服务使用：

```powershell
docker compose down
docker compose -f compose.infrastructure.yaml down
```

只执行自己采用的部署模式对应命令；不要附加删除卷选项。保留 `data` 目录、数据库卷及本机配置，可以在下次启动时继续查看证据。备份 SQLite 前先停止后端，再完整复制 `data` 目录；不要只复制一个仍在写入的数据库文件。后端重启不会自动重放尚未完成或结果未知的工具操作。

源码包中的 `.env.example` 和 `postgres.env.example` 仅提供配置格式；实际账号、令牌和数据库密码由使用者在本机填写，不应随源码再次分发。

