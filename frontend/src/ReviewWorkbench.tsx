import {
  useCallback,
  useEffect,
  useRef,
  useState,
  type ReactNode,
} from "react";
import {
  ArrowRight,
  Check,
  CheckCheck,
  ClipboardCheck,
  Clock3,
  Loader2,
  RefreshCw,
  ShieldCheck,
  X,
} from "lucide-react";
import { api } from "./api";
import type { GuardCall, Session, SessionDetail } from "./types";
import "./review-workbench.css";

type Props = {
  tick: number;
  nav: (route: string) => void;
  notify: (message: string, type?: "success" | "error") => void;
  focusedCallId?: string;
  sessionId?: string;
  renderCall: (call: GuardCall, refresh: () => void) => ReactNode;
};
type Snapshot<T> = {
  path: string | null;
  data: T | null;
  error: string;
  loading: boolean;
};

function useReviewRead<T>(path: string | null, tick: number) {
  const [revision, setRevision] = useState(0);
  const [snapshot, setSnapshot] = useState<Snapshot<T>>({
    path,
    data: null,
    error: "",
    loading: !!path,
  });
  const refresh = useCallback(() => {
    setSnapshot((previous) => ({
      ...previous,
      data: null,
      error: "",
      loading: !!previous.path,
    }));
    setRevision((value) => value + 1);
  }, []);
  useEffect(() => {
    const controller = new AbortController();
    if (!path) {
      setSnapshot({ path, data: null, error: "", loading: false });
      return () => controller.abort();
    }
    setSnapshot((previous) => ({
      path,
      data: previous.path === path ? previous.data : null,
      error: "",
      loading: true,
    }));
    api<T>(path, { signal: controller.signal })
      .then((data) => {
        if (!controller.signal.aborted)
          setSnapshot({ path, data, error: "", loading: false });
      })
      .catch((error: unknown) => {
        if (!controller.signal.aborted)
          setSnapshot({
            path,
            data: null,
            error:
              error instanceof Error ? error.message : "读取失败，请重试。",
            loading: false,
          });
      });
    return () => controller.abort();
  }, [path, tick, revision]);
  return {
    ...(snapshot.path === path
      ? snapshot
      : { path, data: null, error: "", loading: !!path }),
    refresh,
  };
}

const date = (value?: string) =>
  value ? new Date(value).toLocaleString("zh-CN", { hour12: false }) : "—";
const short = (value: string) =>
  value.length > 22 ? `${value.slice(0, 13)}…${value.slice(-5)}` : value;
const display = (value: unknown) =>
  typeof value === "string" ? value : JSON.stringify(value, null, 2);
const executionLabels: Record<string, string> = {
  pending: "等待执行",
  not_executed: "尚无执行回执",
  executing: "执行中",
  succeeded: "执行成功",
  failed: "执行失败",
  unknown: "执行结果待核对",
};
const decisionLabels: Record<string, string> = {
  allow: "允许",
  confirm: "待确认",
  block: "阻断",
};

export default function ReviewWorkbench({
  tick,
  nav,
  notify,
  focusedCallId,
  sessionId,
  renderCall,
}: Props) {
  const [poll, setPoll] = useState(0);
  const [historySessionId, setHistorySessionId] = useState("");
  const [comment, setComment] = useState("");
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState("");
  const actionRef = useRef<AbortController | null>(null);
  const queue = useReviewRead<GuardCall[]>("/approvals", tick + poll);
  const sessions = useReviewRead<Session[]>("/sessions", tick + poll);
  const readError = queue.error || sessions.error;
  const pending = !readError
    ? queue.data?.find((call) => call.id === focusedCallId) ||
      (!focusedCallId && !historySessionId ? queue.data?.[0] : undefined)
    : undefined;
  const selectedSessionId =
    sessionId ||
    historySessionId ||
    pending?.session_id ||
    sessions.data?.[0]?.id ||
    "";
  const detail = useReviewRead<SessionDetail>(
    !readError && selectedSessionId
      ? `/sessions/${encodeURIComponent(selectedSessionId)}`
      : null,
    tick + poll,
  );
  const error = readError || detail.error;
  const selected = !error
    ? detail.data?.calls.find(
        (call) => call.id === (focusedCallId || pending?.id),
      )
    : undefined;
  const history = !error
    ? detail.data?.calls
        .filter((call) => call.approval)
        .sort((a, b) =>
          (b.approval?.at || b.created_at).localeCompare(
            a.approval?.at || a.created_at,
          ),
        ) || []
    : [];
  const task = !error ? detail.data : null;

  useEffect(() => {
    if (error) return;
    const timer = window.setInterval(() => {
      if (document.visibilityState === "visible" && !actionRef.current)
        setPoll((value) => value + 1);
    }, 7000);
    return () => clearInterval(timer);
  }, [error]);
  useEffect(() => {
    setComment("");
    setActionError("");
    actionRef.current?.abort();
    actionRef.current = null;
    setBusy(false);
  }, [focusedCallId, sessionId, historySessionId]);
  useEffect(() => {
    if (error) {
      setComment("");
      setActionError("");
    }
  }, [error]);
  useEffect(() => () => actionRef.current?.abort(), []);

  const refresh = () => {
    setActionError("");
    queue.refresh();
    sessions.refresh();
    detail.refresh();
  };
  const navigateCall = (call: GuardCall) => {
    if (actionRef.current) return;
    setHistorySessionId(call.session_id);
    nav(`approvals/${call.id}/${call.session_id}`);
  };
  const canDecide =
    !!selected &&
    !!task &&
    !selected.control_receipt &&
    !selected.approval &&
    !selected.superseded_by &&
    selected.decision === "confirm" &&
    selected.execution_status === "pending" &&
    !!queue.data?.some((call) => call.id === selected.id) &&
    !error &&
    !actionError &&
    !detail.loading &&
    !queue.loading &&
    !sessions.loading;

  async function decide(approved: boolean) {
    if (!selected || !canDecide || actionRef.current) return;
    const target = selected;
    const controller = new AbortController();
    actionRef.current = controller;
    setBusy(true);
    setActionError("");
    try {
      await api<GuardCall>(`/approvals/${encodeURIComponent(target.id)}`, {
        method: "POST",
        body: JSON.stringify({ approved, comment }),
        signal: controller.signal,
      });
      if (controller.signal.aborted) return;
      setComment("");
      queue.refresh();
      detail.refresh();
      sessions.refresh();
      nav(`approvals/${target.id}/${target.session_id}`);
      notify(approved ? "确认已提交。" : "已拒绝本次操作。");
    } catch (cause) {
      if (controller.signal.aborted) return;
      const message =
        cause instanceof Error
          ? cause.message
          : "提交失败，请刷新后核对处理结果。";
      setActionError(message);
      setComment("");
      queue.refresh();
      detail.refresh();
      sessions.refresh();
      notify(message, "error");
    } finally {
      if (actionRef.current === controller) {
        actionRef.current = null;
        setBusy(false);
      }
    }
  }

  return (
    <div className="review-workbench">
      <header className="review-heading">
        <div>
          <h1>确认复核</h1>
        </div>
        <button className="review-button" onClick={refresh} disabled={busy}>
          <RefreshCw size={15} />
          刷新
        </button>
      </header>
      <div className="review-summary">
        <div>
          <Clock3 size={18} />
          <span>待确认</span>
          <strong>{queue.data && !error ? queue.data.length : "—"}</strong>
        </div>
        <div>
          <CheckCheck size={18} />
          <span>当前任务已处理</span>
          <strong>{task ? history.length : "—"}</strong>
        </div>
      </div>
      {(error || actionError) && (
        <div className="review-error" role="alert">
          <span>{error || actionError}</span>
          <button className="review-button" onClick={refresh} disabled={busy}>
            重新读取
          </button>
        </div>
      )}
      <div className="review-layout">
        <aside className="review-panel review-queue" aria-label="待确认操作">
          <div className="review-panel-heading">
            <h2>待办队列</h2>
            <span>{queue.data && !error ? queue.data.length : "—"}</span>
          </div>
          {!error && queue.data?.length ? (
            queue.data.map((call) => (
              <button
                key={call.id}
                className={`review-queue-item ${call.id === selected?.id ? "selected" : ""}`}
                aria-pressed={call.id === selected?.id}
                onClick={() => navigateCall(call)}
                disabled={busy}
              >
                <span className="review-queue-title">
                  <strong>{call.tool}</strong>
                  <span>风险 {call.risk_score}</span>
                </span>
                <span className="review-queue-task">
                  {sessions.data?.find((item) => item.id === call.session_id)
                    ?.title || short(call.session_id)}
                </span>
                <span className="review-queue-reason">
                  {call.reasons[0] || "此操作需要确认"}
                </span>
                <small>{date(call.created_at)}</small>
              </button>
            ))
          ) : (
            <div className="review-empty">
              <ClipboardCheck size={25} />
              <strong>
                {queue.loading && !queue.data
                  ? "正在读取待办"
                  : error
                    ? "待办暂不可读"
                    : "暂无待确认操作"}
              </strong>
            </div>
          )}
        </aside>
        <section
          className="review-panel review-detail"
          aria-label="操作复核详情"
        >
          {!error && !actionError && task && selected ? (
            <>
              <div className="review-detail-heading">
                <div>
                  <span className="review-kicker">
                    {selected.approval ? "处置记录" : "待确认操作"}
                  </span>
                  <h2>{selected.tool}</h2>
                  <code>{selected.id}</code>
                </div>
                <span className={`review-decision ${selected.decision}`}>
                  {decisionLabels[selected.decision]}
                </span>
              </div>
              <div className="review-task">
                <h3>{task.title}</h3>
                <dl>
                  <div>
                    <dt>原始任务</dt>
                    <dd>{task.original_intent || task.intent}</dd>
                  </div>
                  <div>
                    <dt>当前有效任务</dt>
                    <dd>{task.intent}</dd>
                  </div>
                  <div>
                    <dt>授权范围</dt>
                    <dd>
                      {task.scope === "read_only"
                        ? "只读"
                        : "开发 · 写入逐项确认"}
                      <span className="review-inline-note">
                        授权 v{task.authorization_version || 1}
                      </span>
                    </dd>
                  </div>
                  <div>
                    <dt>关联标识</dt>
                    <dd>
                      <code>{task.id}</code>
                      <span className="review-inline-note">
                        {selected.agent_id}
                        {selected.mcp_server ? ` · ${selected.mcp_server}` : ""}
                      </span>
                    </dd>
                  </div>
                </dl>
              </div>
              <div className="review-two-columns">
                <section>
                  <h3>实际参数</h3>
                  <pre>{display(selected.args)}</pre>
                </section>
                <section>
                  <h3>目标与影响</h3>
                  <dl>
                    <div>
                      <dt>目标对象</dt>
                      <dd>
                        {selected.report?.resources &&
                        display(selected.report.resources) !== "[]" ? (
                          <pre>{display(selected.report.resources)}</pre>
                        ) : (
                          "未登记目标对象"
                        )}
                      </dd>
                    </div>
                    <div>
                      <dt>与任务关系</dt>
                      <dd>{selected.report?.task_relation || "未提供"}</dd>
                    </div>
                    <div>
                      <dt>行为说明</dt>
                      <dd>
                        {selected.plan || selected.report?.reason || "未提供"}
                      </dd>
                    </div>
                  </dl>
                  {selected.resource_facts &&
                    Object.keys(selected.resource_facts).length > 0 && (
                      <details>
                        <summary>资源核验记录</summary>
                        <pre>{display(selected.resource_facts)}</pre>
                      </details>
                    )}
                </section>
              </div>
              <section className="review-reasons">
                <h3>确认依据</h3>
                <ul>
                  {selected.reasons.map((reason, index) => (
                    <li key={index}>{reason}</li>
                  ))}
                </ul>
                {!!selected.information_gaps?.length && (
                  <div className="review-gap">
                    <strong>待核实事项</strong>
                    <ul>
                      {selected.information_gaps.map((gap, index) => (
                        <li key={index}>{gap}</li>
                      ))}
                    </ul>
                  </div>
                )}
                <div className="review-policy">
                  <span>策略 v{selected.policy_version}</span>
                  <span>风险分数 {selected.risk_score}</span>
                  {selected.matched_rules.map((rule) => (
                    <code key={rule}>{rule}</code>
                  ))}
                </div>
              </section>
              {selected.control_receipt && (
                <p className="review-ended" role="status">
                  本次执行尝试已结束（{selected.control_receipt.status}
                  ），当前记录不可再次处理。
                </p>
              )}
              {selected.superseded_by && (
                <p className="review-ended">
                  已被新审查替代：{selected.superseded_by}。
                </p>
              )}
              {selected.approval ? (
                <section className="review-result">
                  <h3>处理结果</h3>
                  <dl>
                    <div>
                      <dt>操作意见</dt>
                      <dd>
                        {selected.approval.approved ? "确认" : "拒绝"} ·{" "}
                        {selected.approval.actor} · {date(selected.approval.at)}
                      </dd>
                    </div>
                    <div>
                      <dt>复核说明</dt>
                      <dd>{selected.approval.comment || "未填写"}</dd>
                    </div>
                    <div>
                      <dt>最终决定</dt>
                      <dd>
                        {decisionLabels[selected.decision]} ·{" "}
                        {executionLabels[selected.execution_status] ||
                          selected.execution_status}
                      </dd>
                    </div>
                    {selected.receipt && (
                      <div>
                        <dt>执行回执</dt>
                        <dd>
                          {selected.receipt.detail || selected.receipt.status}
                        </dd>
                      </div>
                    )}
                  </dl>
                </section>
              ) : (
                <form
                  className="review-actions"
                  onSubmit={(event) => {
                    event.preventDefault();
                    void decide(true);
                  }}
                >
                  <label htmlFor="review-comment">
                    复核说明<span>可选</span>
                  </label>
                  <textarea
                    id="review-comment"
                    value={comment}
                    onChange={(event) => setComment(event.target.value)}
                    maxLength={2000}
                    disabled={busy || !canDecide}
                    placeholder="记录本次判断依据"
                    rows={3}
                  />
                  <div>
                    <button
                      className="review-button danger"
                      type="button"
                      onClick={() => void decide(false)}
                      disabled={busy || !canDecide}
                    >
                      <X size={15} />
                      拒绝
                    </button>
                    <button
                      className="review-button primary"
                      type="submit"
                      disabled={busy || !canDecide}
                    >
                      {busy ? (
                        <Loader2 size={15} className="spin" />
                      ) : (
                        <Check size={15} />
                      )}
                      确认并重新审查
                    </button>
                  </div>
                </form>
              )}
              <div className="review-links">
                <button
                  className="review-button"
                  onClick={() => nav(`tasks/${task.id}`)}
                >
                  查看任务
                  <ArrowRight size={14} />
                </button>
                <button
                  className="review-button"
                  onClick={() => nav(`alerts/${task.id}/${selected.id}`)}
                >
                  告警研判
                  <ArrowRight size={14} />
                </button>
                <button
                  className="review-button"
                  onClick={() => nav(`traces/${task.id}/${selected.id}`)}
                >
                  溯源复盘
                  <ArrowRight size={14} />
                </button>
              </div>
              <details className="review-complete-call">
                <summary>调用报告与执行证据</summary>
                {renderCall(selected, refresh)}
              </details>
            </>
          ) : (
            <div className="review-empty review-detail-empty">
              <ShieldCheck size={30} />
              <strong>
                {detail.loading
                  ? "正在读取任务与调用"
                  : error || actionError
                    ? "请重新读取操作记录"
                    : focusedCallId
                      ? "当前任务中未找到此调用"
                      : "选择一项操作开始复核"}
              </strong>
            </div>
          )}
        </section>
      </div>
      <section className="review-panel review-history">
        <div className="review-history-heading">
          <div>
            <h2>已处理记录</h2>
          </div>
          <label>
            选择任务
            <select
              value={error || actionError ? "" : selectedSessionId}
              disabled={busy || !!error || !!actionError || !sessions.data}
              onChange={(event) => {
                setHistorySessionId(event.target.value);
                nav(`approvals//${event.target.value}`);
              }}
            >
              {(error || actionError || !sessions.data?.length) && (
                <option value="">
                  {error || actionError ? "请重新读取任务" : "暂无任务"}
                </option>
              )}
              {!error &&
                !actionError &&
                sessions.data?.map((session) => (
                  <option key={session.id} value={session.id}>
                    {session.title} · {short(session.id)}
                  </option>
                ))}
            </select>
          </label>
        </div>
        {!error && !actionError && history.length ? (
          <div className="review-history-scroll">
            <table>
              <thead>
                <tr>
                  <th>操作 / 调用</th>
                  <th>处理意见</th>
                  <th>最终决定</th>
                  <th>执行状态</th>
                  <th>处理时间</th>
                  <th>
                    <span className="review-sr-only">详情</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {history.map((call) => (
                  <tr
                    key={call.id}
                    className={selected?.id === call.id ? "selected" : ""}
                  >
                    <td>
                      <strong>{call.tool}</strong>
                      <code>{short(call.id)}</code>
                    </td>
                    <td>
                      {call.approval?.approved ? "确认" : "拒绝"}
                      <small>{call.approval?.actor}</small>
                    </td>
                    <td>
                      <span className={`review-decision ${call.decision}`}>
                        {decisionLabels[call.decision]}
                      </span>
                    </td>
                    <td>
                      {executionLabels[call.execution_status] ||
                        call.execution_status}
                    </td>
                    <td>{date(call.approval?.at)}</td>
                    <td>
                      <button
                        className="review-button"
                        onClick={() => navigateCall(call)}
                        disabled={busy}
                        aria-label={`查看调用 ${call.id}`}
                      >
                        查看
                        <ArrowRight size={14} />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="review-history-empty">
            {error || actionError
              ? "处理记录暂不可读。"
              : detail.loading
                ? "正在读取处理记录…"
                : "此任务暂无人工处理记录。"}
          </div>
        )}
      </section>
    </div>
  );
}
