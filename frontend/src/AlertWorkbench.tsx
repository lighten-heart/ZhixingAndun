import { useMemo, useState, type ReactNode } from "react";
import {
  ArrowRight,
  CheckCircle2,
  ChevronRight,
  Clock3,
  FileText,
  GitBranch,
  Link2,
  Loader2,
  RefreshCw,
  Search,
  ShieldAlert,
  Terminal,
  TriangleAlert,
} from "lucide-react";
import { useResource } from "./hooks/useResource";
import Pagination, { pageSlice } from "./components/Pagination";
import type {
  Decision,
  GuardCall,
  Session,
  SessionDetail,
  Source,
} from "./types";
import "./alert-workbench.css";

type Props = {
  tick: number;
  sessionId?: string;
  itemId?: string;
  nav: (path: string) => void;
  renderCall: (call: GuardCall, onChanged: () => void) => ReactNode;
  renderSource: (source: Source) => ReactNode;
};

const sourceNames: Record<string, string> = {
  user_input: "用户输入",
  web: "网页",
  document: "外部文档",
  email: "邮件",
  code: "代码",
  issue: "Issue / PR",
  mcp_description: "MCP 工具描述",
  mcp_result: "MCP 返回",
  tool_result: "工具返回",
  memory: "记忆",
  knowledge: "知识库",
};
const decisions: Record<Decision, string> = {
  allow: "放行",
  confirm: "待确认",
  block: "阻断决定",
};
const short = (value: string) =>
  value.length > 24 ? `${value.slice(0, 12)}…${value.slice(-6)}` : value;
const time = (value: string) =>
  new Date(value).toLocaleString("zh-CN", {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  });
const pathPart = (value: string) => encodeURIComponent(value);

function DecisionTag({ value }: { value: Decision }) {
  return <span className={`aw-decision ${value}`}>{decisions[value]}</span>;
}

function ReadError({ text, retry }: { text: string; retry: () => void }) {
  return (
    <div className="aw-error" role="alert">
      <TriangleAlert size={19} />
      <span>{text}</span>
      <button className="button" onClick={retry}>
        重新读取
      </button>
    </div>
  );
}

export default function AlertWorkbench(props: Props) {
  const sessions = useResource<Session[]>("/sessions", props.tick);
  const alerts = useResource<GuardCall[]>("/alerts", props.tick);
  const [detailRevision, setDetailRevision] = useState(0);
  const [sessionRange, setSessionRange] = useState<"recent" | "all">("recent");
  const orderedSessions = useMemo(
    () =>
      [...(sessions.data || [])].sort((a, b) =>
        b.created_at.localeCompare(a.created_at),
      ),
    [sessions.data],
  );
  const newestAlert = useMemo(
    () =>
      [...(alerts.data || [])].sort((a, b) =>
        b.created_at.localeCompare(a.created_at),
      )[0],
    [alerts.data],
  );
  const selectedSession =
    props.sessionId || newestAlert?.session_id || orderedSessions[0]?.id;
  const pendingCalls = alerts.data?.filter(
    (call) =>
      call.decision === "confirm" &&
      call.execution_status === "pending" &&
      !call.superseded_by &&
      !call.control_receipt,
  );
  const pending = pendingCalls?.length;
  const retainedSessionIds = new Set(
    [
      props.sessionId,
      selectedSession,
      ...(pendingCalls || []).map((call) => call.session_id),
    ].filter((id): id is string => !!id),
  );
  const recentSessionIds = new Set(
    orderedSessions.slice(0, 20).map((s) => s.id),
  );
  const visibleSessions =
    sessionRange === "all"
      ? orderedSessions
      : orderedSessions.filter(
          (session) =>
            recentSessionIds.has(session.id) ||
            retainedSessionIds.has(session.id),
        );
  const knownSessionIds = new Set(orderedSessions.map((session) => session.id));
  const missingSessionIds = [...retainedSessionIds].filter(
    (id) => !knownSessionIds.has(id),
  );
  const visibleSessionCount = visibleSessions.length + missingSessionIds.length;
  const refresh = () => {
    sessions.refresh();
    alerts.refresh();
  };
  const error = sessions.error || alerts.error;

  return (
    <div className="aw-page">
      <div className="page-heading">
        <div>
          <h1>告警研判</h1>
        </div>
        <button
          className="button"
          onClick={() => {
            refresh();
            setDetailRevision((value) => value + 1);
          }}
        >
          <RefreshCw size={15} />
          刷新任务
        </button>
      </div>
      <section className="aw-session-bar" aria-label="研判任务选择">
        <div className="aw-session-select">
          <div className="aw-session-picker-heading">
            <label htmlFor="aw-current-session">当前任务</label>
            <div
              className="aw-session-range"
              role="group"
              aria-label="会话显示范围"
            >
              <button
                type="button"
                aria-pressed={sessionRange === "recent"}
                onClick={() => setSessionRange("recent")}
              >
                最近 20 个
              </button>
              <button
                type="button"
                aria-pressed={sessionRange === "all"}
                onClick={() => setSessionRange("all")}
              >
                全部历史
              </button>
            </div>
          </div>
          <select
            id="aw-current-session"
            value={selectedSession || ""}
            onChange={(event) =>
              props.nav(`alerts/${pathPart(event.target.value)}`)
            }
            disabled={!!error || !visibleSessionCount}
          >
            {!selectedSession && <option value="">尚无任务记录</option>}
            {missingSessionIds.map((id) => (
              <option key={id} value={id}>
                {id === selectedSession ? "指定会话" : "待确认会话"} ·{" "}
                {short(id)}
              </option>
            ))}
            {visibleSessions.map((session) => (
              <option key={session.id} value={session.id}>
                {session.title} · {short(session.id)}
              </option>
            ))}
          </select>
          {sessions.data && (
            <small className="aw-session-range-count">
              显示 {visibleSessionCount} 个会话
              {sessionRange === "recent" && " · 包含当前与待确认会话"}
            </small>
          )}
        </div>
        <div className="aw-global-number">
          <span>全局风险调用记录</span>
          <strong>{alerts.data ? alerts.data.length : "—"}</strong>
        </div>
        <div className="aw-global-number">
          <span>全局待确认调用</span>
          <strong>{pending ?? "—"}</strong>
        </div>
      </section>
      {error ? (
        <ReadError text={error} retry={refresh} />
      ) : !selectedSession ? (
        sessions.loading || alerts.loading ? (
          <div className="aw-empty">
            <Loader2 className="spin" size={25} />
            <p>正在读取任务与告警记录…</p>
          </div>
        ) : (
          <div className="aw-empty">
            <ShieldAlert size={30} />
            <h2>暂无可研判的任务</h2>
            <button
              className="button primary"
              onClick={() => props.nav("tasks")}
            >
              前往任务运行
              <ArrowRight size={15} />
            </button>
          </div>
        )
      ) : (
        <SessionInvestigation
          key={selectedSession}
          {...props}
          sessionId={selectedSession}
          tick={props.tick + detailRevision}
          onChanged={refresh}
        />
      )}
    </div>
  );
}

type ReviewItem =
  | {
      id: string;
      kind: "call";
      value: GuardCall;
      sourceTypes: string[];
      title: string;
      summary: string;
      risk: number;
      searchable: string;
    }
  | {
      id: string;
      kind: "source";
      value: Source;
      sourceTypes: string[];
      title: string;
      summary: string;
      risk: number;
      searchable: string;
    };

function SessionInvestigation({
  sessionId,
  itemId,
  tick,
  nav,
  renderCall,
  renderSource,
  onChanged,
}: Props & { sessionId: string; onChanged: () => void }) {
  const detail = useResource<SessionDetail>(
    `/sessions/${pathPart(sessionId)}`,
    tick,
  );
  const [kind, setKind] = useState("all");
  const [decision, setDecision] = useState(itemId ? "all" : "risk");
  const [sourceType, setSourceType] = useState("all");
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(15);
  const sourcesById = useMemo(
    () => new Map(detail.data?.sources.map((source) => [source.id, source])),
    [detail.data?.sources],
  );
  const items: ReviewItem[] = useMemo(() => {
    if (!detail.data) return [];
    const calls: ReviewItem[] = detail.data.calls.map((call) => ({
      id: call.id,
      kind: "call",
      value: call,
      sourceTypes: [
        ...new Set(
          call.source_ids.map(
            (id) => sourcesById.get(id)?.type || "unresolved",
          ),
        ),
      ],
      title: call.tool,
      summary: call.reasons[0] || call.report.reason || "已完成调用审查",
      risk: call.risk_score,
      searchable: [
        call.id,
        call.tool,
        call.agent_id,
        call.plan,
        ...call.reasons,
        JSON.stringify(call.args),
      ]
        .join(" ")
        .toLowerCase(),
    }));
    const sources: ReviewItem[] = detail.data.sources.map((source) => ({
      id: source.id,
      kind: "source",
      value: source,
      sourceTypes: [source.type],
      title: source.resource || sourceNames[source.type] || source.type,
      summary:
        source.detection.findings[0]?.reason ||
        source.detection.information_gaps[0] ||
        "未发现明确风险证据",
      risk: source.detection.risk_score,
      searchable: [
        source.id,
        source.resource,
        source.content,
        sourceNames[source.type] || source.type,
        ...source.detection.findings.map(
          (finding) =>
            `${finding.rule_id} ${finding.category} ${finding.reason}`,
        ),
      ]
        .join(" ")
        .toLowerCase(),
    }));
    return [...sources, ...calls].sort((a, b) =>
      b.value.created_at.localeCompare(a.value.created_at),
    );
  }, [detail.data, sourcesById]);
  const needle = query.trim().toLowerCase();
  const filtered = items.filter(
    (item) =>
      (kind === "all" || item.kind === kind) &&
      (decision === "all" ||
        (decision === "risk"
          ? item.value.decision !== "allow"
          : item.value.decision === decision)) &&
      (sourceType === "all" ||
        (sourceType === "none"
          ? item.sourceTypes.length === 0
          : item.sourceTypes.includes(sourceType))) &&
      (!needle || item.searchable.includes(needle)),
  );
  const selected = itemId
    ? items.find((item) => item.id === itemId)
    : filtered[0];
  const selectedIsFiltered =
    selected && !filtered.some((item) => item.id === selected.id);
  const sourceOptions = [
    ...new Set(items.flatMap((item) => item.sourceTypes)),
  ].sort();
  const select = (id: string) =>
    nav(`alerts/${pathPart(sessionId)}/${pathPart(id)}`);
  const reset = () => {
    setKind("all");
    setDecision("all");
    setSourceType("all");
    setQuery("");
    setPage(1);
  };
  const refresh = () => {
    detail.refresh();
    onChanged();
  };

  if (detail.error)
    return <ReadError text={detail.error} retry={detail.refresh} />;
  if (!detail.data)
    return (
      <div className="aw-empty">
        <Loader2 className="spin" size={25} />
        <p>正在读取当前任务的证据…</p>
      </div>
    );

  const task = detail.data;
  const riskSources = task.sources.filter(
    (source) => source.decision !== "allow",
  ).length;
  const riskCalls = task.calls.filter(
    (call) => call.decision !== "allow",
  ).length;
  return (
    <>
      <section className="aw-task-context">
        <div>
          <span className="aw-overline">当前有效任务</span>
          <h2>{task.title}</h2>
          <p>{task.intent}</p>
          {task.original_intent && task.original_intent !== task.intent && (
            <details>
              <summary>查看最初任务</summary>
              <p>{task.original_intent}</p>
            </details>
          )}
          <div className="aw-task-meta">
            <span>
              {task.scope === "read_only" ? "只读授权" : "开发授权"}
              {" · "}v{task.authorization_version || 1}
            </span>
            <span>{task.agent_id}</span>
            <span title={task.id}>会话 {short(task.id)}</span>
          </div>
        </div>
        <div className="aw-task-counts">
          <span>
            <strong>{riskSources}</strong>风险来源
          </span>
          <span>
            <strong>{riskCalls}</strong>风险调用
          </span>
          <button
            className="button"
            onClick={() => nav(`traces/${pathPart(sessionId)}`)}
          >
            <GitBranch size={15} />
            溯源复盘
          </button>
        </div>
      </section>
      <section className="aw-workspace">
        <aside className="aw-queue" aria-label="当前任务研判队列">
          <div className="aw-queue-heading">
            <h2>当前任务记录</h2>
            <button
              className="icon-button"
              aria-label="刷新当前任务证据"
              onClick={refresh}
            >
              <RefreshCw size={15} className={detail.loading ? "spin" : ""} />
            </button>
          </div>
          <div className="aw-filters">
            <label className="aw-search">
              <Search size={15} />
              <input
                value={query}
                onChange={(event) => {
                  setQuery(event.target.value);
                  setPage(1);
                }}
                aria-label="搜索当前任务的来源与调用"
                placeholder="搜索原文、工具或记录 ID"
              />
            </label>
            <div className="aw-filter-pair">
              <label>
                记录类型
                <select
                  value={kind}
                  onChange={(event) => {
                    setKind(event.target.value);
                    setPage(1);
                  }}
                >
                  <option value="all">来源与调用</option>
                  <option value="source">内容来源</option>
                  <option value="call">工具调用</option>
                </select>
              </label>
              <label>
                策略决定
                <select
                  value={decision}
                  onChange={(event) => {
                    setDecision(event.target.value);
                    setPage(1);
                  }}
                >
                  <option value="risk">风险记录</option>
                  <option value="block">阻断决定</option>
                  <option value="confirm">待确认</option>
                  <option value="allow">放行记录</option>
                  <option value="all">所有决定</option>
                </select>
              </label>
            </div>
            <label>
              来源渠道
              <select
                value={sourceType}
                onChange={(event) => {
                  setSourceType(event.target.value);
                  setPage(1);
                }}
              >
                <option value="all">所有来源渠道</option>
                {sourceOptions.map((type) => (
                  <option key={type} value={type}>
                    {sourceNames[type] ||
                      (type === "unresolved" ? "来源未包含在当前会话" : type)}
                  </option>
                ))}
                {items.some((item) => item.sourceTypes.length === 0) && (
                  <option value="none">未登记输入来源</option>
                )}
              </select>
            </label>
            <p className="aw-filter-summary" aria-live="polite">
              {filtered.length} 条匹配 / 当前任务共 {items.length} 条
              <button onClick={reset}>清除筛选</button>
            </p>
          </div>
          <div className="aw-queue-items">
            {pageSlice(filtered, page, pageSize).map((item) => (
              <button
                className={`aw-queue-item ${selected?.id === item.id ? "selected" : ""}`}
                key={item.id}
                onClick={() => select(item.id)}
                aria-pressed={selected?.id === item.id}
              >
                <span className="aw-item-heading">
                  {item.kind === "call" ? (
                    <Terminal size={16} />
                  ) : (
                    <FileText size={16} />
                  )}
                  <strong>{item.title}</strong>
                  <ChevronRight size={15} />
                </span>
                <span className="aw-item-summary">{item.summary}</span>
                <span className="aw-item-footer">
                  <DecisionTag value={item.value.decision} />
                  <span>风险 {item.risk}</span>
                  <time dateTime={item.value.created_at}>
                    {time(item.value.created_at)}
                  </time>
                </span>
                <span className="aw-item-id">
                  {item.kind === "call" ? "调用" : "来源"} · {short(item.id)}
                </span>
              </button>
            ))}
            {!filtered.length && (
              <div className="aw-queue-empty">
                <CheckCircle2 size={24} />
                <strong>
                  {items.length ? "没有符合筛选条件的记录" : "尚无审查记录"}
                </strong>
                {!!items.length && (
                  <button className="button" onClick={reset}>
                    显示当前任务所有记录
                  </button>
                )}
              </div>
            )}
          </div>
          {!!filtered.length && (
            <Pagination
              label="研判记录"
              page={page}
              pageSize={pageSize}
              total={filtered.length}
              onPageChange={setPage}
              onPageSizeChange={setPageSize}
            />
          )}
        </aside>
        <div className="aw-detail">
          {selected ? (
            <>
              <div className="aw-detail-heading">
                <div>
                  <span className="aw-overline">
                    {selected.kind === "call" ? "调用行为研判" : "来源内容研判"}
                  </span>
                  <h2>{selected.title}</h2>
                  <p>{selected.id}</p>
                </div>
                <button
                  className="button"
                  onClick={() =>
                    nav(
                      `traces/${pathPart(sessionId)}/${pathPart(selected.id)}`,
                    )
                  }
                >
                  <GitBranch size={15} />
                  查看关联路径
                </button>
              </div>
              {selectedIsFiltered && (
                <div className="aw-selection-note">
                  当前打开的记录不在筛选结果内。
                  <button onClick={reset}>显示所有记录</button>
                </div>
              )}
              {selected.kind === "call" ? (
                <>
                  {renderCall(selected.value, refresh)}
                  {selected.value.decision === "confirm" &&
                    selected.value.execution_status === "pending" &&
                    !selected.value.superseded_by && (
                      <div className="aw-review-link">
                        <Clock3 size={18} />
                        <p>
                          {selected.value.control_receipt
                            ? "本次执行尝试已结束。"
                            : "等待人工确认。"}
                        </p>
                        <button
                          className="button"
                          onClick={() =>
                            nav(
                              `approvals/${pathPart(selected.id)}/${pathPart(sessionId)}`,
                            )
                          }
                        >
                          确认复核
                          <ArrowRight size={14} />
                        </button>
                      </div>
                    )}
                  <section className="aw-related">
                    <h3>
                      <Link2 size={16} />
                      调用引用的来源
                    </h3>
                    {selected.value.source_ids.length ? (
                      selected.value.source_ids.map((id) => {
                        const source = sourcesById.get(id);
                        return source ? (
                          <button key={id} onClick={() => select(id)}>
                            <FileText size={16} />
                            <span>
                              <strong>
                                {source.resource ||
                                  sourceNames[source.type] ||
                                  source.type}
                              </strong>
                              <small>
                                {sourceNames[source.type] || source.type}
                                {" · "}v{source.version} · {short(source.id)}
                              </small>
                            </span>
                            <DecisionTag value={source.decision} />
                            <ChevronRight size={15} />
                          </button>
                        ) : (
                          <p key={id}>当前会话缺少来源 {id}。</p>
                        );
                      })
                    ) : (
                      <p>未关联输入来源。</p>
                    )}
                  </section>
                </>
              ) : (
                <>
                  <div className="aw-source-detail">
                    {renderSource(selected.value)}
                  </div>
                  <section className="aw-related">
                    <h3>
                      <Link2 size={16} />
                      引用此来源的调用
                    </h3>
                    {task.calls
                      .filter((call) => call.source_ids.includes(selected.id))
                      .map((call) => (
                        <button key={call.id} onClick={() => select(call.id)}>
                          <Terminal size={16} />
                          <span>
                            <strong>{call.tool}</strong>
                            <small>
                              {call.agent_id} · {short(call.id)}
                            </small>
                          </span>
                          <DecisionTag value={call.decision} />
                          <ChevronRight size={15} />
                        </button>
                      ))}
                    {!task.calls.some((call) =>
                      call.source_ids.includes(selected.id),
                    ) && <p>暂无关联调用。</p>}
                  </section>
                </>
              )}
            </>
          ) : (
            <div className="aw-empty">
              {itemId ? <TriangleAlert size={28} /> : <FileText size={28} />}
              <h2>{itemId ? "未找到指定记录" : "选择一条记录开始研判"}</h2>
              {itemId && (
                <button
                  className="button"
                  onClick={() => nav(`alerts/${pathPart(sessionId)}`)}
                >
                  返回当前任务队列
                </button>
              )}
            </div>
          )}
        </div>
      </section>
    </>
  );
}
