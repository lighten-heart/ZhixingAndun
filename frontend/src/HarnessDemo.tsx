import { useEffect, useState } from "react";
import {
  ArrowRight,
  CheckCircle2,
  ChevronDown,
  Circle,
  Clock3,
  FileText,
  GitBranch,
  Loader2,
  Play,
  RefreshCw,
  ShieldCheck,
  Square,
  Terminal,
  Workflow,
  XCircle,
} from "lucide-react";
import { api, post } from "./api";
import { useResource } from "./hooks/useResource";
import "./task-workspace.css";

type Scenario = {
  id: string;
  name: string;
  description: string;
  task: string;
  scope: string;
};
type HostStatus = {
  ready: boolean;
  installed: boolean;
  version: string | null;
  expected_version: string;
  provider: string;
  model: string;
  scenarios: Scenario[];
  limitations: string[];
  active_run_ids?: string[];
};
type RunEvent = Record<string, unknown>;
type Run = {
  id: string;
  session_id: string;
  scenario_id: string;
  scenario_name: string;
  task: string;
  scope: string;
  status: string;
  host_version: string;
  model: string;
  created_at: string;
  answer: string;
  message?: string;
  waiting_call_id?: string;
  events: RunEvent[];
  effects?: Record<string, { bytes: number; text: string }>;
  checks?: { name: string; passed: boolean }[];
  defense_verified?: boolean;
  evidence?: {
    calls: number;
    blocked_calls: number;
    blocked_sources: number;
    succeeded_calls: number;
  };
};
type Props = {
  tick: number;
  nav: (route: string) => void;
  notify: (text: string, type?: "success" | "error") => void;
  selectedSessionId?: string;
};

const activeStates = new Set([
  "starting",
  "running",
  "waiting_approval",
  "stopping",
]);
const labels: Record<string, string> = {
  starting: "准备中",
  running: "运行中",
  waiting_approval: "待确认",
  stopping: "停止中",
  completed: "已结束",
  failed: "运行失败",
  cancelled: "已停止",
  timed_out: "超时",
  interrupted: "已中断",
};
const decisionLabels: Record<string, string> = {
  allow: "放行决定",
  confirm: "询问确认",
  block: "阻断决定",
};
const eventLabels: Record<string, string> = {
  content_quarantined: "参考材料已隔离",
  host_context: "核验宿主上下文",
  mcp_connected: "连接 MCP 服务",
  mcp_forwarded: "转发 MCP 请求",
  mcp_quarantined: "隔离 MCP 工具描述",
  child_started: "启动子 Agent",
  child_finished: "子 Agent 返回",
  plugin_ready: "防护插件就绪",
  session: "建立宿主会话",
  review: "执行前审查",
  waiting_approval: "挂起操作，等待确认",
  approval_finished: "取得复核结果",
  execution: "工具执行回执",
  result_admission: "返回内容准入",
  input_blocked: "输入内容已隔离",
  step: "模型任务步骤",
  guard_error: "安全边界停止执行",
  final: "最终回复",
  tool_call: "提出工具调用",
  tool_result: "收到工具结果",
  status: "宿主状态",
  text: "模型回复",
  model_request_recorded: "记录模型输入",
  sandbox_evidence: "沙箱行为取证",
  review_recovery: "重新审查调用",
  halted: "宿主停止执行",
  tool_protocol_recovery: "恢复工具调用协议",
  tool_protocol_unresolved: "工具协议未恢复",
};
const filters = [
  { id: "all", name: "全部事件" },
  { id: "agent", name: "Agent" },
  { id: "mcp", name: "MCP" },
  { id: "tool", name: "工具与审查" },
  { id: "memory", name: "记忆" },
] as const;
type EventFilter = (typeof filters)[number]["id"];
const dateLabel = (value: string) => {
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? value
    : date.toLocaleString("zh-CN", {
        month: "2-digit",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
        hour12: false,
      });
};
const scopeLabel = (scope: string) =>
  scope === "development"
    ? "开发 · 写入需逐项确认"
    : scope === "read_only"
      ? "只读"
      : scope;
function eventMatches(event: RunEvent, filter: EventFilter) {
  const type = String(event.type || "");
  if (filter === "all") return true;
  if (filter === "agent")
    return (
      type.startsWith("child_") ||
      ["step", "session", "host_context", "model_request_recorded"].includes(
        type,
      )
    );
  if (filter === "mcp") return type.startsWith("mcp_") || Boolean(event.server);
  if (filter === "memory")
    return /memory|记忆/.test(
      `${type} ${String(event.tool || "")} ${String(event.resource || "")}`,
    );
  return [
    "tool_call",
    "tool_result",
    "review",
    "waiting_approval",
    "approval_finished",
    "execution",
    "result_admission",
    "content_quarantined",
    "input_blocked",
    "guard_error",
    "sandbox_evidence",
    "review_recovery",
  ].includes(type);
}

export default function HarnessDemo({
  tick,
  nav,
  notify,
  selectedSessionId,
}: Props) {
  const host = useResource<HostStatus>("/harness/status", tick);
  const [historyView, setHistoryView] = useState<"recent" | "all">("recent");
  const [historyOffset, setHistoryOffset] = useState(0);
  const historyPageSize = historyView === "recent" ? 10 : 50;
  const runs = useResource<Run[]>(
    `/harness/runs?limit=${historyPageSize}&offset=${historyOffset}`,
    tick,
  );
  const [scenarioId, setScenarioId] = useState("custom");
  const [customTask, setCustomTask] = useState("");
  const [customScope, setCustomScope] = useState("read_only");
  const [referenceText, setReferenceText] = useState("");
  const [selectedId, setSelectedId] = useState("");
  const [starting, setStarting] = useState(false);
  const [stopping, setStopping] = useState(false);
  const [lastStarted, setLastStarted] = useState<Run | null>(null);
  const [eventFilter, setEventFilter] = useState<EventFilter>("all");
  const [detailTab, setDetailTab] = useState<"events" | "output">("events");
  const [linkLookup, setLinkLookup] = useState({ loading: false, error: "" });
  const [linkedRunId, setLinkedRunId] = useState("");
  const [linkedRun, setLinkedRun] = useState<Run | null>(null);
  const linkedSelection = selectedSessionId && !selectedId;
  const selected = selectedId
    ? runs.data?.find((run) => run.id === selectedId) ||
      (lastStarted?.id === selectedId ? lastStarted : null) ||
      (linkedRun?.id === selectedId ? linkedRun : null)
    : linkedSelection
      ? runs.data?.find((run) => run.session_id === selectedSessionId)
      : runs.data?.[0];
  const running =
    host.data?.active_run_ids?.some(
      (id) =>
        !runs.data?.some((run) => run.id === id) ||
        runs.data.some((run) => run.id === id && activeStates.has(run.status)),
    ) ||
    runs.data?.some((run) => activeStates.has(run.status)) ||
    (!!lastStarted && !runs.data?.some((run) => run.id === lastStarted.id));
  const scenario = host.data?.scenarios.find((item) => item.id === scenarioId);
  const draftScope =
    scenarioId === "custom" ? customScope : scenario?.scope || "";
  const error = host.error || runs.error;
  const events = selected?.events || [];
  const visibleEvents = events
    .map((event, index) => ({ event, index }))
    .filter(({ event }) => eventMatches(event, eventFilter));
  const outputCount = Object.keys(selected?.effects || {}).length;

  useEffect(() => {
    if (runs.error || runs.loading) return;
    const timer = window.setTimeout(
      () => {
        if (document.visibilityState === "visible") {
          runs.refresh();
          host.refresh();
        }
      },
      running ? 1600 : 8000,
    );
    return () => clearTimeout(timer);
  }, [
    runs.refresh,
    host.refresh,
    runs.error,
    runs.loading,
    runs.updatedAt,
    running,
  ]);
  useEffect(() => {
    if (runs.error) setLastStarted(null);
  }, [runs.error]);
  useEffect(() => {
    setEventFilter("all");
    setDetailTab("events");
  }, [selected?.id]);
  useEffect(() => {
    if (!selectedSessionId) {
      setLinkLookup({ loading: false, error: "" });
      setLinkedRunId("");
      setLinkedRun(null);
      return;
    }
    const controller = new AbortController();
    setSelectedId("");
    setLastStarted(null);
    setLinkedRunId("");
    setLinkedRun(null);
    setLinkLookup({ loading: true, error: "" });
    async function locate() {
      // The API pages runs, not sessions. Locate the actual run before selecting it.
      for (let offset = 0; offset <= 1000000; offset += 50) {
        const page = await api<Run[]>(
          `/harness/runs?limit=50&offset=${offset}`,
          { signal: controller.signal },
        );
        if (controller.signal.aborted) return;
        const match = page.find((run) => run.session_id === selectedSessionId);
        if (match) {
          setLinkedRun(match);
          setHistoryView("all");
          setHistoryOffset(offset);
          setSelectedId(match.id);
          setLinkedRunId(match.id);
          setLinkLookup({ loading: false, error: "" });
          return;
        }
        if (page.length < 50) break;
      }
      if (!controller.signal.aborted)
        setLinkLookup({
          loading: false,
          error: "未找到该会话关联的 Harness 运行记录，可直接查看会话溯源。",
        });
    }
    locate().catch((cause) => {
      if (!controller.signal.aborted)
        setLinkLookup({
          loading: false,
          error:
            cause instanceof Error ? cause.message : "关联运行记录读取失败",
        });
    });
    return () => controller.abort();
  }, [selectedSessionId, tick]);

  async function start() {
    setStarting(true);
    try {
      const run = await post<Run>("/harness/runs", {
        scenario_id: scenarioId,
        ...(scenarioId === "custom"
          ? {
              task: customTask,
              scope: customScope,
              ...(referenceText ? { reference_text: referenceText } : {}),
            }
          : {}),
      });
      setHistoryView("recent");
      setHistoryOffset(0);
      setLastStarted(run);
      setSelectedId(run.id);
      if (selectedSessionId) nav("tasks");
      runs.refresh();
      host.refresh();
      notify("任务已提交，正在启动 DeepSeek Harness。");
    } catch (cause) {
      notify((cause as Error).message, "error");
    } finally {
      setStarting(false);
    }
  }
  async function stop() {
    if (!selected || stopping) return;
    setStopping(true);
    try {
      await post(`/harness/runs/${selected.id}/stop`);
      runs.refresh();
      host.refresh();
    } catch (cause) {
      notify((cause as Error).message, "error");
    } finally {
      setStopping(false);
    }
  }
  function changePage(offset: number) {
    if (selectedSessionId) nav("tasks");
    setHistoryOffset(offset);
    setSelectedId("");
    setLastStarted(null);
  }
  function changeHistoryView(view: "recent" | "all") {
    if (selectedSessionId) nav("tasks");
    setHistoryView(view);
    setHistoryOffset(0);
    setSelectedId("");
  }
  const startDisabled =
    historyOffset > 0 ||
    starting ||
    !!running ||
    !host.data?.installed ||
    !!error ||
    linkLookup.loading ||
    (scenarioId === "custom" && !customTask.trim());

  return (
    <div className="task-workspace">
      <header className="page-title tw-title">
        <div>
          <h1>任务运行</h1>
        </div>
        <button
          className="button"
          onClick={() => {
            host.refresh();
            runs.refresh();
          }}
        >
          <RefreshCw size={15} />
          刷新
        </button>
      </header>
      {error && (
        <div className="warning-box" role="alert">
          {error}
        </div>
      )}
      <div className="tw-runtime" aria-label="宿主状态">
        <span
          className={`tw-host-dot ${host.data?.installed ? "available" : ""}`}
        />
        <strong>DeepSeek Harness</strong>
        <span>
          {host.data?.version || host.data?.expected_version || "版本读取中"}
        </span>
        <span className="tw-runtime-divider" />
        <span>模型</span>
        <strong>{host.data?.model || "等待服务响应"}</strong>
        {!host.loading && host.data && !host.data.installed && (
          <span className="tw-runtime-state">宿主未就绪</span>
        )}
      </div>

      <section className="tw-composer" aria-labelledby="new-task-title">
        <div className="tw-panel-heading">
          <div>
            <h2 id="new-task-title">发起任务</h2>
          </div>
        </div>
        <div className="tw-composer-grid">
          <div className="tw-task-fields">
            <label className="tw-field">
              <span>任务场景</span>
              <select
                value={scenarioId}
                onChange={(event) => setScenarioId(event.target.value)}
              >
                <option value="custom">自定义业务任务</option>
                {host.data?.scenarios.map((item) => (
                  <option key={item.id} value={item.id}>
                    {item.name}
                  </option>
                ))}
              </select>
            </label>
            <label className="tw-field">
              <span>{scenarioId === "custom" ? "业务任务" : "场景任务"}</span>
              {scenarioId === "custom" ? (
                <textarea
                  value={customTask}
                  onChange={(event) => setCustomTask(event.target.value)}
                  maxLength={12000}
                  rows={3}
                  placeholder="填写任务目标、允许使用的资料和需要产出的结果"
                />
              ) : (
                <div className="tw-scenario-task">
                  {scenario?.task || "正在读取场景任务…"}
                </div>
              )}
            </label>
            {scenarioId === "custom" && (
              <details className="tw-reference">
                <summary>
                  <FileText size={14} />
                  外部参考资料
                  <span>
                    {referenceText
                      ? `${referenceText.length.toLocaleString()} 字符`
                      : "可选 · external-note.txt"}
                  </span>
                  <ChevronDown size={14} />
                </summary>
                <label className="tw-field">
                  <span className="tw-sr-only">外部参考资料</span>
                  <textarea
                    value={referenceText}
                    onChange={(event) => setReferenceText(event.target.value)}
                    maxLength={80000}
                    rows={5}
                    placeholder="粘贴参考资料"
                  />
                </label>
                <p className="tw-field-help">
                  资料不构成授权；留空使用预置参考文件。
                </p>
              </details>
            )}
          </div>
          <aside className="tw-authorization">
            <div className="tw-authorization-title">
              <ShieldCheck size={16} />
              <h3>任务授权</h3>
            </div>
            {scenarioId === "custom" ? (
              <label className="tw-field">
                <span>授权范围</span>
                <select
                  value={customScope}
                  onChange={(event) => setCustomScope(event.target.value)}
                >
                  <option value="read_only">只读</option>
                  <option value="development">开发 · 写入需逐项确认</option>
                </select>
              </label>
            ) : (
              <div className="tw-scope-label">{scopeLabel(draftScope)}</div>
            )}
            <p>
              {draftScope === "development"
                ? "写入、提交及发布需逐项确认。"
                : "仅允许读取，禁止写入。"}
            </p>
            <dl className="tw-constraints">
              <div>
                <dt>执行目录</dt>
                <dd>每次运行独立目录</dd>
              </div>
              <div>
                <dt>运行上限</dt>
                <dd>5 分钟</dd>
              </div>
            </dl>
            <button
              className="button primary tw-start"
              disabled={startDisabled}
              onClick={start}
            >
              {starting ? (
                <Loader2 size={15} className="spin" />
              ) : (
                <Play size={15} />
              )}
              启动任务
            </button>
            {(historyOffset > 0 || running) && (
              <small>
                {historyOffset > 0
                  ? "返回最新记录页后可启动任务"
                  : "已有任务运行，请完成或停止后再启动"}
              </small>
            )}
          </aside>
        </div>
      </section>

      <div className="tw-execution-grid">
        <aside className="tw-history" aria-label="任务运行记录">
          <div className="tw-history-heading">
            <h2>运行记录</h2>
            <select
              aria-label="运行记录范围"
              value={historyView}
              onChange={(event) =>
                changeHistoryView(event.target.value as "recent" | "all")
              }
              disabled={linkLookup.loading}
            >
              <option value="recent">最近 10 条</option>
              <option value="all">全部历史</option>
            </select>
          </div>
          <div className="tw-history-list">
            {runs.loading && !runs.data ? (
              <p className="tw-empty-inline">正在读取运行记录…</p>
            ) : !runs.data?.length ? (
              <p className="tw-empty-inline">暂无运行记录</p>
            ) : (
              runs.data.map((run) => (
                <button
                  key={run.id}
                  className={`tw-run-item ${run.id === selected?.id ? "selected" : ""}`}
                  onClick={() => {
                    if (selectedSessionId) nav("tasks");
                    setSelectedId(run.id);
                  }}
                  aria-pressed={run.id === selected?.id}
                >
                  <span className="tw-run-name">{run.scenario_name}</span>
                  <span
                    className={`tw-run-state ${run.status === "waiting_approval" ? "waiting" : activeStates.has(run.status) ? "running" : ["failed", "timed_out", "interrupted"].includes(run.status) ? "failed" : ""}`}
                  >
                    {labels[run.status] || run.status}
                  </span>
                  <time dateTime={run.created_at}>
                    {dateLabel(run.created_at)}
                  </time>
                  <span className="tw-run-id">{run.id}</span>
                </button>
              ))
            )}
          </div>
          <div className="tw-pagination">
            {historyView === "recent" ? (
              <button
                className="button"
                disabled={linkLookup.loading}
                onClick={() => changeHistoryView("all")}
              >
                查看全部历史
              </button>
            ) : (
              <>
                <button
                  className="button"
                  disabled={
                    runs.loading || historyOffset === 0 || linkLookup.loading
                  }
                  onClick={() => changePage(Math.max(0, historyOffset - 50))}
                >
                  较新
                </button>
                <span>第 {Math.floor(historyOffset / 50) + 1} 页</span>
                <button
                  className="button"
                  disabled={
                    runs.loading ||
                    (runs.data?.length || 0) < 50 ||
                    linkLookup.loading
                  }
                  onClick={() => changePage(historyOffset + 50)}
                >
                  更早
                </button>
              </>
            )}
          </div>
        </aside>
        <section className="tw-run-detail" aria-label="当前任务详情">
          {linkLookup.loading ? (
            <div className="tw-empty">
              <Loader2 size={26} className="spin" />
              <h3>查找关联运行记录</h3>
            </div>
          ) : selected && !runs.error ? (
            <>
              <header className="tw-run-header">
                <div>
                  <span className="tw-overline">当前任务</span>
                  <h2>{selected.scenario_name}</h2>
                  <p>
                    <Clock3 size={13} />
                    {dateLabel(selected.created_at)}
                    <span>·</span>
                    {selected.model}
                  </p>
                </div>
                <span
                  className={`tw-status ${activeStates.has(selected.status) ? "active" : ""}`}
                >
                  {activeStates.has(selected.status) ? (
                    <Loader2 size={13} className="spin" />
                  ) : (
                    <Circle size={8} fill="currentColor" />
                  )}
                  {labels[selected.status] || selected.status}
                </span>
              </header>
              {linkedRunId === selected.id && (
                <div className="tw-linked-note">已定位关联会话的运行记录</div>
              )}
              <div className="tw-run-identity">
                <span>
                  任务 <code>{selected.id}</code>
                </span>
                <span>
                  会话 <code>{selected.session_id}</code>
                </span>
              </div>
              <details className="tw-original-task">
                <summary>
                  <FileText size={14} />
                  原始任务与有效授权
                  <ChevronDown size={14} />
                </summary>
                <p>{selected.task}</p>
                <span className="tw-authorized-scope">
                  <ShieldCheck size={13} />
                  {scopeLabel(selected.scope)}
                </span>
              </details>
              {selected.status === "waiting_approval" && (
                <div className="tw-pending" role="status">
                  <div>
                    <strong>操作已挂起，等待确认</strong>
                    <p>请核对参数与目标后再确认。</p>
                  </div>
                  <button
                    className="button"
                    onClick={() =>
                      nav(
                        selected.waiting_call_id
                          ? `approvals/${selected.waiting_call_id}/${selected.session_id}`
                          : "approvals",
                      )
                    }
                  >
                    确认复核
                    <ArrowRight size={14} />
                  </button>
                </div>
              )}
              <div className="tw-run-actions">
                <button
                  className="button"
                  onClick={() => nav(`alerts/${selected.session_id}`)}
                >
                  告警研判
                  <ArrowRight size={14} />
                </button>
                <button
                  className="button"
                  onClick={() => nav(`traces/${selected.session_id}`)}
                >
                  <GitBranch size={14} />
                  溯源复盘
                </button>
                {activeStates.has(selected.status) && (
                  <button
                    className="button tw-stop"
                    disabled={stopping || selected.status === "stopping"}
                    onClick={stop}
                  >
                    {stopping ? (
                      <Loader2 size={14} className="spin" />
                    ) : (
                      <Square size={13} />
                    )}
                    停止任务
                  </button>
                )}
              </div>
              {selected.evidence && (
                <div className="tw-evidence-summary">
                  <div>
                    <span>工具调用</span>
                    <strong>{selected.evidence.calls}</strong>
                  </div>
                  <div>
                    <span>执行成功</span>
                    <strong>{selected.evidence.succeeded_calls}</strong>
                  </div>
                  <div>
                    <span>调用阻断决定</span>
                    <strong>{selected.evidence.blocked_calls}</strong>
                  </div>
                  <div>
                    <span>来源阻断决定</span>
                    <strong>{selected.evidence.blocked_sources}</strong>
                  </div>
                </div>
              )}
              <div className="tw-tabs" role="tablist" aria-label="运行详情">
                <button
                  id="tw-events-tab"
                  role="tab"
                  aria-selected={detailTab === "events"}
                  aria-controls="tw-events-panel"
                  className={detailTab === "events" ? "selected" : ""}
                  onClick={() => setDetailTab("events")}
                >
                  <Workflow size={15} />
                  运行过程<span>{events.length}</span>
                </button>
                <button
                  id="tw-output-tab"
                  role="tab"
                  aria-selected={detailTab === "output"}
                  aria-controls="tw-output-panel"
                  className={detailTab === "output" ? "selected" : ""}
                  onClick={() => setDetailTab("output")}
                >
                  <FileText size={15} />
                  结果与回执
                  {outputCount > 0 && <span>{outputCount} 个文件</span>}
                </button>
              </div>
              {detailTab === "events" ? (
                <div
                  id="tw-events-panel"
                  role="tabpanel"
                  aria-labelledby="tw-events-tab"
                >
                  <div className="tw-event-toolbar">
                    <div className="tw-event-filters" aria-label="事件类别">
                      {filters.map((filter) => (
                        <button
                          key={filter.id}
                          className={
                            eventFilter === filter.id ? "selected" : ""
                          }
                          aria-pressed={eventFilter === filter.id}
                          onClick={() => setEventFilter(filter.id)}
                        >
                          {filter.name}
                        </button>
                      ))}
                    </div>
                    <span>最多显示最近 150 条回执</span>
                  </div>
                  <div className="tw-event-list">
                    {visibleEvents.map(({ event, index }) => (
                      <details
                        className="tw-event"
                        key={`${selected.id}-${index}`}
                      >
                        <summary>
                          <span
                            className={`tw-event-dot ${event.decision === "block" ? "blocked" : event.decision === "confirm" || event.type === "waiting_approval" ? "pending" : ""}`}
                          />
                          <span className="tw-event-number">
                            {String(index + 1).padStart(2, "0")}
                          </span>
                          <span className="tw-event-body">
                            <strong>
                              {eventLabels[String(event.type)] ||
                                String(event.type || "宿主事件")}
                            </strong>
                            <small>
                              {[
                                event.tool,
                                event.server,
                                event.child_agent_id
                                  ? `子 Agent ${String(event.child_agent_id)}`
                                  : event.agent_id
                                    ? `Agent ${String(event.agent_id)}`
                                    : "",
                                event.type === "step"
                                  ? `第 ${String(event.step)} 步`
                                  : "",
                                event.status,
                              ]
                                .filter(Boolean)
                                .map(String)
                                .join(" · ")}
                            </small>
                          </span>
                          {event.decision != null && (
                            <span
                              className={`tw-decision ${String(event.decision)}`}
                            >
                              {decisionLabels[String(event.decision)] ||
                                String(event.decision)}
                            </span>
                          )}
                          <ChevronDown size={14} />
                        </summary>
                        <div className="tw-event-expanded">
                          {(event.call_id != null ||
                            event.source_id != null) && (
                            <div className="tw-event-call">
                              <code>
                                {String(event.call_id || event.source_id)}
                              </code>
                              <button
                                className="tw-text-button"
                                onClick={() =>
                                  nav(
                                    `alerts/${selected.session_id}/${String(event.call_id || event.source_id)}`,
                                  )
                                }
                              >
                                查看关联研判
                                <ArrowRight size={12} />
                              </button>
                            </div>
                          )}
                          <pre>{JSON.stringify(event, null, 2)}</pre>
                        </div>
                      </details>
                    ))}
                    {!visibleEvents.length && (
                      <div className="tw-empty-inline">
                        {events.length ? "暂无此类事件。" : "等待运行回执…"}
                      </div>
                    )}
                  </div>
                </div>
              ) : (
                <div
                  id="tw-output-panel"
                  className="tw-output"
                  role="tabpanel"
                  aria-labelledby="tw-output-tab"
                >
                  <section>
                    <h3>任务回复</h3>
                    {selected.answer ? (
                      <p className="tw-answer">{selected.answer}</p>
                    ) : (
                      <p className="tw-muted">尚未收到最终回复。</p>
                    )}
                  </section>
                  {selected.checks && (
                    <section>
                      <h3>
                        {selected.scenario_id === "custom"
                          ? "运行状态核验"
                          : "场景断言"}
                      </h3>
                      <p className="tw-muted">
                        {selected.scenario_id === "custom"
                          ? "自定义任务不预设攻防成绩。"
                          : selected.defense_verified
                            ? "全部预设断言通过。"
                            : "预设断言未全部通过。"}
                      </p>
                      <div className="tw-checks">
                        {selected.checks.map((check, index) => (
                          <div key={`${check.name}-${index}`}>
                            {check.passed ? (
                              <CheckCircle2
                                size={16}
                                className="tw-check-pass"
                              />
                            ) : (
                              <XCircle size={16} className="tw-check-fail" />
                            )}
                            <span>{check.name}</span>
                            <strong>{check.passed ? "通过" : "未通过"}</strong>
                          </div>
                        ))}
                      </div>
                    </section>
                  )}
                  {selected.effects &&
                    Object.entries(selected.effects).map(([name, value]) => (
                      <section key={name} className="tw-file-result">
                        <h3>
                          <FileText size={15} />
                          {name}
                          <span>{value.bytes.toLocaleString()} 字节</span>
                        </h3>
                        <pre>{value.text}</pre>
                      </section>
                    ))}
                  {!outputCount && (
                    <p className="tw-muted">当前记录未报告产出文件。</p>
                  )}
                </div>
              )}
              {selected.message && (
                <div className="tw-run-message" role="status">
                  {selected.message}
                </div>
              )}
            </>
          ) : (
            <div className="tw-empty">
              <Terminal size={28} />
              <h3>
                {linkLookup.error ? "关联任务未载入" : "选择一条运行记录"}
              </h3>
              {linkLookup.error && <p>{linkLookup.error}</p>}
              {selectedSessionId && (
                <button
                  className="button"
                  onClick={() => nav(`traces/${selectedSessionId}`)}
                >
                  查看会话溯源
                  <ArrowRight size={14} />
                </button>
              )}
            </div>
          )}
        </section>
      </div>
    </div>
  );
}
