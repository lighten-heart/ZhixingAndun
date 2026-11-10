import DataEvidence from "./DataEvidence";
import {
  AuthorizationControl,
  MemoryControl,
  KnowledgeControl,
} from "./OperatorControls";
import ForensicEvidence, { ModelRequestEvidence } from "./ForensicEvidence";
import PromptfooReports from "./PromptfooReports";
import AgentComparisonReports from "./AgentComparisonReports";
import CampaignReports from "./CampaignReports";
import TokenEvidence from "./TokenEvidence";
import {
  useState,
  useEffect,
  useCallback,
  useRef,
  type ReactNode,
  type FormEvent,
} from "react";
import {
  Activity,
  ArrowDownToLine,
  ArrowLeft,
  ArrowRight,
  Bell,
  BookOpen,
  Check,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  ClipboardCheck,
  Clock3,
  Database,
  Eye,
  FileJson2,
  FileText,
  Filter,
  Fingerprint,
  GitBranch,
  KeyRound,
  Layers3,
  LayoutDashboard,
  Link2,
  Loader2,
  LockKeyhole,
  Maximize2,
  Menu,
  Network,
  Play,
  Plus,
  RefreshCw,
  Search,
  Settings2,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Terminal,
  TriangleAlert,
  Workflow,
  X,
  XCircle,
  Zap,
} from "lucide-react";
import { api, post, getToken, setToken, downloadJSON } from "./api";
import HighlightedText from "./HighlightedText";
import { useResource } from "./hooks/useResource";
import Pagination, { pageSlice } from "./components/Pagination";
import HarnessDemo from "./HarnessDemo";
import AlertWorkbench from "./AlertWorkbench";
import ReviewWorkbench from "./ReviewWorkbench";
import type {
  Decision,
  Health,
  Session,
  SessionDetail,
  Source,
  GuardCall,
  Dashboard,
  Policies,
  Memory,
  Scenario,
  DemoResult,
  Evaluation,
  Graph,
} from "./types";

const sourceNames: Record<string, string> = {
  user_input: "用户输入",
  web: "网页内容",
  document: "外部文档",
  code: "代码仓库",
  email: "邮件内容",
  issue: "Issue / PR",
  mcp_description: "MCP 工具描述",
  mcp_result: "MCP 工具返回",
  tool_result: "工具返回",
  memory: "长期记忆",
  knowledge: "知识库",
};
const decisionNames: Record<Decision, string> = {
  allow: "放行",
  confirm: "待确认",
  block: "阻断决定",
};
const executionNames: Record<string, string> = {
  not_executed: "尚无执行回执",
  pending: "等待执行",
  executing: "执行中",
  unknown: "回执未知",
  succeeded: "执行成功",
  failed: "执行失败",
};
const severityNames: Record<string, string> = {
  low: "低风险",
  medium: "中风险",
  high: "高风险",
  critical: "严重风险",
};
const receiptOrigin = (value?: string) =>
  value === "trusted_adapter_reported"
    ? "可信适配器报告"
    : value === "isolated_fixture_observed"
      ? "隔离工具环境观察"
      : value || "未标注证据类型";
const time = (value: string, full = false) =>
  value
    ? new Date(value).toLocaleString(
        "zh-CN",
        full
          ? {
              month: "2-digit",
              day: "2-digit",
              hour: "2-digit",
              minute: "2-digit",
              second: "2-digit",
              hour12: false,
            }
          : {
              hour: "2-digit",
              minute: "2-digit",
              second: "2-digit",
              hour12: false,
            },
      )
    : "—";
const short = (value: string) =>
  value?.length > 15 ? `${value.slice(0, 8)}…${value.slice(-4)}` : value;
const pretty = (value: unknown) =>
  typeof value === "string" ? value : JSON.stringify(value, null, 2);
type ToastFn = (text: string, type?: "success" | "error") => void;

function Button({
  children,
  onClick,
  variant = "secondary",
  disabled = false,
  className = "",
  type = "button",
  title,
}: {
  children: ReactNode;
  onClick?: () => void;
  variant?: "primary" | "secondary" | "danger" | "ghost";
  disabled?: boolean;
  className?: string;
  type?: "button" | "submit";
  title?: string;
}) {
  return (
    <button
      type={type}
      title={title}
      onClick={onClick}
      disabled={disabled}
      className={`button ${variant} ${className}`}
    >
      {children}
    </button>
  );
}
function Badge({ decision }: { decision: Decision }) {
  return (
    <span className={`badge ${decision}`}>
      {decision === "block" ? (
        <ShieldAlert size={12} />
      ) : decision === "confirm" ? (
        <Clock3 size={12} />
      ) : (
        <CheckCircle2 size={12} />
      )}{" "}
      {decisionNames[decision] || decision}
    </span>
  );
}
function Empty({
  title = "暂无数据",
  detail,
  action,
}: {
  title?: string;
  detail?: string;
  action?: ReactNode;
}) {
  return (
    <div className="empty">
      <div className="empty-icon">
        <Layers3 size={27} />
      </div>
      <strong>{title}</strong>
      {detail && <p>{detail}</p>}
      {action}
    </div>
  );
}
function Loading({ text = "正在读取安全数据…" }: { text?: string }) {
  return (
    <div className="loading">
      <Loader2 className="spin" size={22} />
      <span>{text}</span>
    </div>
  );
}
function ErrorBox({ error, retry }: { error: string; retry?: () => void }) {
  return (
    <div className="error-box">
      <TriangleAlert size={20} />
      <div>
        <strong>请求未完成</strong>
        <p>{error}</p>
      </div>
      {retry && (
        <Button onClick={retry}>
          <RefreshCw size={14} />
          重试
        </Button>
      )}
    </div>
  );
}
function PageTitle({
  title,
  description,
  action,
}: {
  title: string;
  description?: string;
  action?: ReactNode;
}) {
  return (
    <div className="page-heading">
      <div>
        <h1>{title}</h1>
        {description && <p>{description}</p>}
      </div>
      {action && <div className="heading-actions">{action}</div>}
    </div>
  );
}
function SectionTitle({
  icon: Icon,
  title,
  subtitle,
  action,
}: {
  icon: typeof Shield;
  title: string;
  subtitle?: string;
  action?: ReactNode;
}) {
  return (
    <div className="section-heading">
      <div className="section-heading-left">
        <Icon size={18} />
        <div>
          <h2>{title}</h2>
          {subtitle && <p>{subtitle}</p>}
        </div>
      </div>
      {action}
    </div>
  );
}
function Modal({
  title,
  children,
  onClose,
  wide = false,
}: {
  title: string;
  children: ReactNode;
  onClose: () => void;
  wide?: boolean;
}) {
  const dialogRef = useRef<HTMLDivElement>(null);
  const closeRef = useRef(onClose);
  closeRef.current = onClose;
  useEffect(() => {
    const previous = document.activeElement as HTMLElement | null;
    const handler = (e: KeyboardEvent) => {
      if (e.key === "Escape") closeRef.current();
      if (e.key === "Tab" && dialogRef.current) {
        const items = Array.from(
          dialogRef.current.querySelectorAll<HTMLElement>(
            'button:not([disabled]),input,select,textarea,[tabindex="0"]',
          ),
        );
        const first = items[0],
          last = items[items.length - 1];
        if (e.shiftKey && document.activeElement === first) {
          e.preventDefault();
          last?.focus();
        } else if (!e.shiftKey && document.activeElement === last) {
          e.preventDefault();
          first?.focus();
        }
      }
    };
    document.addEventListener("keydown", handler);
    dialogRef.current?.focus();
    return () => {
      document.removeEventListener("keydown", handler);
      previous?.focus();
    };
  }, []);
  return (
    <div
      className="modal-backdrop"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        ref={dialogRef}
        tabIndex={-1}
        className={`modal ${wide ? "wide" : ""}`}
        role="dialog"
        aria-modal="true"
        aria-label={title}
      >
        <div className="modal-heading">
          <h2>{title}</h2>
          <button className="icon-button" onClick={onClose} aria-label="关闭">
            <X size={20} />
          </button>
        </div>
        {children}
      </div>
    </div>
  );
}

const navigation = [
  { id: "tasks", title: "任务运行", icon: Terminal, group: "安全工作台" },
  { id: "alerts", title: "告警研判", icon: ShieldAlert, group: "安全工作台" },
  {
    id: "approvals",
    title: "确认复核",
    icon: ClipboardCheck,
    group: "安全工作台",
  },
  { id: "traces", title: "溯源复盘", icon: GitBranch, group: "安全工作台" },
  {
    id: "overview",
    title: "安全总览",
    icon: LayoutDashboard,
    group: "防护管理",
  },
  { id: "policies", title: "策略中心", icon: Settings2, group: "防护管理" },
  { id: "memories", title: "记忆防护", icon: Database, group: "防护管理" },
  {
    id: "forensics",
    title: "隔离取证",
    icon: Fingerprint,
    group: "验证与评测",
  },
  { id: "demo", title: "攻防场景", icon: Zap, group: "验证与评测" },
  { id: "evaluations", title: "评测报告", icon: FileText, group: "验证与评测" },
];
const canonicalRoute = (path: string) =>
  path
    .replace(/^harness(?=\/|$)/, "tasks")
    .replace(/^sessions(?=\/|$)/, "traces");

export default function App() {
  const [route, setRoute] = useState(
    canonicalRoute(location.hash.slice(1) || "tasks"),
  );
  const [tick, setTick] = useState(0);
  const [authEpoch, setAuthEpoch] = useState(0);
  const [mobile, setMobile] = useState(false);
  const [compactNavigation, setCompactNavigation] = useState(
    () => window.matchMedia("(max-width: 900px)").matches,
  );
  const sidebarRef = useRef<HTMLElement>(null);
  const mainShellRef = useRef<HTMLDivElement>(null);
  const menuButtonRef = useRef<HTMLButtonElement>(null);
  const closeMenuRef = useRef<HTMLButtonElement>(null);
  const [settings, setSettings] = useState(false);
  const [token, setTokenValue] = useState(getToken());
  const [toast, setToast] = useState<{ text: string; type: string } | null>(
    null,
  );
  const timeoutRef = useRef<ReturnType<typeof setTimeout>>();
  const health = useResource<Health>("/health", tick);
  const connected = !!health.data && !health.error;
  const modelInvalid = health.data?.model_status === "invalid_configuration";
  const connectionLabel = health.loading
    ? "正在检查连接"
    : connected
      ? "本地服务已连接"
      : "本地服务连接异常";
  useEffect(() => {
    const media = window.matchMedia("(max-width: 900px)");
    const syncNavigation = () => {
      setCompactNavigation(media.matches);
      if (!media.matches) setMobile(false);
    };
    syncNavigation();
    media.addEventListener("change", syncNavigation);
    return () => media.removeEventListener("change", syncNavigation);
  }, []);
  useEffect(() => {
    if (sidebarRef.current) {
      sidebarRef.current.inert = compactNavigation && !mobile;
    }
  }, [compactNavigation, mobile]);
  useEffect(() => {
    if (!mobile || !compactNavigation) return;
    const mainShell = mainShellRef.current;
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    closeMenuRef.current?.focus();
    if (mainShell) mainShell.inert = true;
    const handleKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        setMobile(false);
      } else if (event.key === "Tab") {
        const controls = sidebarRef.current?.querySelectorAll<HTMLElement>(
          'a[href], button:not([disabled])',
        );
        if (!controls?.length) return;
        const first = controls[0];
        const last = controls[controls.length - 1];
        if (event.shiftKey && document.activeElement === first) {
          event.preventDefault();
          last.focus();
        } else if (!event.shiftKey && document.activeElement === last) {
          event.preventDefault();
          first.focus();
        }
      }
    };
    document.addEventListener("keydown", handleKey);
    return () => {
      document.body.style.overflow = previousOverflow;
      if (mainShell) mainShell.inert = false;
      document.removeEventListener("keydown", handleKey);
      if (menuButtonRef.current?.getClientRects().length) {
        menuButtonRef.current.focus();
      }
    };
  }, [mobile, compactNavigation]);
  useEffect(() => {
    const check = () => {
      if (document.visibilityState === "visible") health.refresh();
    };
    const timer = window.setInterval(check, 30000);
    window.addEventListener("online", check);
    document.addEventListener("visibilitychange", check);
    return () => {
      clearInterval(timer);
      window.removeEventListener("online", check);
      document.removeEventListener("visibilitychange", check);
    };
  }, [health.refresh]);
  useEffect(() => {
    const handler = () => {
      setRoute(canonicalRoute(location.hash.slice(1) || "tasks"));
      setMobile(false);
      window.scrollTo(0, 0);
    };
    window.addEventListener("hashchange", handler);
    return () => window.removeEventListener("hashchange", handler);
  }, []);
  const notify: ToastFn = useCallback((text, type = "success") => {
    setToast({ text, type });
    clearTimeout(timeoutRef.current);
    timeoutRef.current = setTimeout(() => setToast(null), 5000);
  }, []);
  const nav = (path: string) => {
    location.hash = canonicalRoute(path);
  };
  const section = route.split("/")[0];
  const selected = navigation.find((n) => n.id === section) || navigation[0];
  const fullScreen = async () => {
    try {
      if (document.fullscreenElement) await document.exitFullscreen();
      else await document.documentElement.requestFullscreen();
    } catch {
      notify("当前浏览器无法进入全屏模式。", "error");
    }
  };
  return (
    <div className="app-shell">
      {mobile && (
        <button
          className="sidebar-scrim"
          aria-label="关闭导航遮罩"
          tabIndex={-1}
          onClick={() => setMobile(false)}
        />
      )}
      <aside
        id="workspace-navigation"
        ref={sidebarRef}
        className={`sidebar ${mobile ? "open" : ""}`}
        role={compactNavigation && mobile ? "dialog" : undefined}
        aria-modal={compactNavigation && mobile ? true : undefined}
        aria-label="工作空间导航"
        aria-hidden={compactNavigation && !mobile ? true : undefined}
      >
        <button
          ref={closeMenuRef}
          className="icon-button sidebar-close"
          aria-label="关闭导航"
          onClick={() => setMobile(false)}
        >
          <X size={20} />
        </button>
        <a className="brand" href="#tasks" onClick={() => setMobile(false)}>
          <div className="brand-mark">
            <Shield size={26} />
            <span />
          </div>
          <div>
            <strong>智行安盾</strong>
            <small>智能体安全防护平台</small>
          </div>
        </a>
        <div className="workspace-label">
          <span className="dot green" />
          安全工作空间
        </div>
        {["安全工作台", "防护管理", "验证与评测"].map((group) => (
          <div className="nav-group" key={group}>
            <div className="nav-label">{group}</div>
            <nav aria-label={group}>
              {navigation
                .filter((item) => item.group === group)
                .map((item) => (
                  <a
                    key={item.id}
                    href={`#${item.id}`}
                    onClick={() => setMobile(false)}
                    aria-current={section === item.id ? "page" : undefined}
                    className={`nav-item ${section === item.id ? "active" : ""}`}
                  >
                    <item.icon size={18} />
                    <span>{item.title}</span>
                  </a>
                ))}
            </nav>
          </div>
        ))}
        <div className="sidebar-bottom">
          <span className="sidebar-caption">
            <ShieldCheck size={16} />
            智行安盾安全组件
          </span>
          <div className="sidebar-version">
            <span>
              <span className={`dot ${connected ? "green" : "amber-dot"}`} />
              {connectionLabel}
            </span>
            <span>v{health.data?.version || "1.0.0"}</span>
          </div>
        </div>
      </aside>
      <div className="main-shell" ref={mainShellRef}>
        <header className="topbar">
          <div className="breadcrumb">
            <button
              ref={menuButtonRef}
              className="icon-button mobile-menu"
              aria-label="展开导航"
              aria-expanded={mobile}
              aria-controls="workspace-navigation"
              onClick={() => setMobile((v) => !v)}
            >
              <Menu size={20} />
            </button>
            <span className="breadcrumb-root">安全工作台</span>
            <ChevronRight size={14} />
            <strong>{selected.title}</strong>
          </div>
          <div className="topbar-actions">
            <button
              className={`environment connection-trigger ${health.error ? "connection-error" : ""}`}
              onClick={() => setSettings(true)}
              aria-label="系统连接状态"
              title="连接设置"
            >
              <span className={`dot ${connected ? "green" : "amber-dot"}`} />
              {health.loading
                ? "正在检查"
                : connected
                  ? "服务在线"
                  : "连接异常"}
              <ChevronDown size={12} />
            </button>
            <button
              title="刷新数据"
              aria-label="刷新数据"
              className="icon-button"
              onClick={() => setTick((v) => v + 1)}
            >
              <RefreshCw size={17} />
            </button>
            <button
              title="全屏"
              aria-label="全屏"
              className="icon-button"
              onClick={fullScreen}
            >
              <Maximize2 size={17} />
            </button>
            <button
              title="连接设置"
              aria-label="连接设置"
              className="avatar-button"
              onClick={() => setSettings(true)}
            >
              <KeyRound size={17} />
            </button>
          </div>
        </header>
        <main key={authEpoch}>
          {health.error && (
            <ErrorBox error={health.error} retry={health.refresh} />
          )}
          {health.data?.auth_required && !getToken() && (
            <div className="warning-box">
              <KeyRound size={17} />
              <span>服务已启用访问保护，请设置令牌后操作。</span>
              <Button onClick={() => setSettings(true)}>连接设置</Button>
            </div>
          )}
          {section === "overview" ? (
            <Overview tick={tick} nav={nav} />
          ) : section === "tasks" ? (
            <HarnessDemo
              tick={tick}
              nav={nav}
              notify={notify}
              selectedSessionId={route.split("/")[1]}
            />
          ) : section === "alerts" ? (
            <AlertWorkbench
              tick={tick}
              sessionId={route.split("/")[1]}
              itemId={route.split("/")[2]}
              nav={nav}
              renderCall={(call, refresh) => (
                <CallCard
                  key={call.id}
                  call={call}
                  notify={notify}
                  onChanged={refresh}
                  defaultOpen
                />
              )}
              renderSource={(source) => (
                <SourceDetail key={source.id} source={source} />
              )}
            />
          ) : section === "forensics" ? (
            <ForensicEvidence tick={tick} />
          ) : section === "demo" ? (
            <Demo tick={tick} nav={nav} notify={notify} />
          ) : section === "traces" ? (
            <Sessions
              tick={tick}
              selectedId={route.split("/")[1]}
              focusedItem={route.split("/")[2]}
              nav={nav}
              notify={notify}
            />
          ) : section === "approvals" ? (
            <ReviewWorkbench
              tick={tick}
              nav={nav}
              notify={notify}
              focusedCallId={route.split("/")[1]}
              sessionId={route.split("/")[2]}
              renderCall={(call, refresh) => (
                <CallCard
                  key={call.id}
                  call={call}
                  notify={notify}
                  onChanged={refresh}
                  defaultOpen
                />
              )}
            />
          ) : section === "policies" ? (
            <PolicyCenter tick={tick} notify={notify} />
          ) : section === "memories" ? (
            <Memories tick={tick} nav={nav} notify={notify} />
          ) : section === "evaluations" ? (
            <Evaluations tick={tick} nav={nav} notify={notify} />
          ) : (
            <Empty
              title="页面不存在"
              action={
                <Button onClick={() => nav("overview")}>返回安全总览</Button>
              }
            />
          )}
        </main>
      </div>
      {toast && (
        <div className={`toast ${toast.type}`} role="status">
          {toast.type === "error" ? (
            <XCircle size={18} />
          ) : (
            <CheckCircle2 size={18} />
          )}
          <span>{toast.text}</span>
          <button
            className="icon-button"
            aria-label="关闭通知"
            onClick={() => setToast(null)}
          >
            <X size={15} />
          </button>
        </div>
      )}
      {settings && (
        <Modal title="连接设置" onClose={() => setSettings(false)}>
          <form
            className="form-body"
            onSubmit={(event) => {
              event.preventDefault();
              setToken(token);
              setAuthEpoch((value) => value + 1);
              setSettings(false);
              setTick((value) => value + 1);
              notify("连接配置已更新");
            }}
          >
            <div className="service-status-heading">
              <div>
                <span className={`dot ${connected ? "green" : "amber-dot"}`} />
                <strong>{connectionLabel}</strong>
              </div>
              <Button onClick={health.refresh} disabled={health.loading}>
                <RefreshCw size={14} className={health.loading ? "spin" : ""} />
                检查连接
              </Button>
            </div>
            {health.error && <ErrorBox error={health.error} />}
            <dl className="capability-list">
              <div>
                <dt>本地安全服务</dt>
                <dd>
                  {connected ? `可访问 · v${health.data?.version}` : "未确认"}
                </dd>
              </div>
              <div>
                <dt>检测模式</dt>
                <dd>
                  {!connected
                    ? "待获取"
                    : modelInvalid
                      ? "语义服务配置无效"
                      : health.data?.model_configured
                        ? "规则检测 + 已配置语义服务"
                        : "本地规则检测"}
                  <small>
                    {!connected
                      ? "等待连接"
                      : modelInvalid
                        ? "配置异常 · 语义审查将阻断"
                        : health.data?.model_configured
                          ? "模型连通性：未检测"
                          : "语义研判：未启用"}
                  </small>
                </dd>
              </div>
              {connected &&
                health.data?.model_configured &&
                health.data?.model_configuration_valid === false && (
                  <div>
                    <dt>配置检查</dt>
                    <dd className="text-red">语义配置无效 · 执行保护性停止</dd>
                  </div>
                )}
              <div>
                <dt>DeepSeek Harness 宿主</dt>
                <dd>
                  {!connected
                    ? "待获取"
                    : health.data?.harness_status === "running"
                      ? "任务运行中"
                      : health.data?.harness_status === "ready"
                        ? "本机运行时已就绪"
                        : "运行时待准备"}
                </dd>
              </div>
              <div>
                <dt>动态沙箱</dt>
                <dd>
                  {!connected
                    ? "待获取"
                    : health.data?.sandbox_available
                      ? "后端报告可用"
                      : "未启用"}
                </dd>
              </div>
              <div>
                <dt>最近成功连接</dt>
                <dd>
                  {health.updatedAt
                    ? time(health.updatedAt, true)
                    : "尚未取得响应"}
                </dd>
              </div>
            </dl>
            <h3 className="settings-subheading">访问设置</h3>
            <label>
              访问令牌
              <input
                type="password"
                autoComplete="off"
                value={token}
                onChange={(e) => setTokenValue(e.target.value)}
                placeholder="填写 GUARD_API_TOKEN 对应的令牌"
              />
            </label>
            <div className="connection-details">
              <span>
                API 地址<strong>与当前站点同源 /api</strong>
              </span>
              <span>
                服务状态<strong>{connectionLabel}</strong>
              </span>
              <span>
                鉴权状态
                <strong>
                  {!connected
                    ? "待获取"
                    : health.data?.auth_required
                      ? "已启用"
                      : "本地免令牌模式"}
                </strong>
              </span>
            </div>
            <Button variant="primary" type="submit">
              <Check size={16} />
              保存连接配置
            </Button>
          </form>
        </Modal>
      )}
    </div>
  );
}

function Overview({
  tick,
  nav,
}: {
  tick: number;
  nav: (path: string) => void;
}) {
  const { data, error, loading, refresh } = useResource<Dashboard>(
    "/dashboard",
    tick,
  );
  if (loading && !data) return <Loading />;
  if (error) return <ErrorBox error={error} retry={refresh} />;
  if (!data) return null;
  const metrics = [
    {
      label: "累计审查会话",
      value: data.stats.sessions,
      suffix: "个",
      icon: Workflow,
      detail: "全链路可追踪",
      color: "teal",
    },
    {
      label: "累计工具审查",
      value: data.stats.calls,
      suffix: "次",
      icon: Layers3,
      detail: `平均审查 ${data.stats.avg_latency_ms.toFixed(1)} ms`,
      color: "blue",
    },
    {
      label: "累计阻断决定",
      value: data.stats.blocked,
      suffix: "次",
      icon: ShieldAlert,
      detail: "策略决定禁止执行",
      color: "red",
    },
    {
      label: "待人工确认",
      value: data.stats.pending,
      suffix: "项",
      icon: ClipboardCheck,
      detail: "审批通过后重新审查",
      color: "amber",
    },
  ];
  return (
    <>
      <PageTitle
        title="安全总览"
        action={
          <>
            <Button variant="primary" onClick={() => nav("demo")}>
              <Play size={15} />
              运行场景
            </Button>
          </>
        }
      />
      <div className="metrics-grid">
        {metrics.map((m) => (
          <div className={`metric-card ${m.color}`} key={m.label}>
            <div className="metric-top">
              <span>{m.label}</span>
            </div>
            <div className="metric-value">
              {m.value.toLocaleString()}
              <small>{m.suffix}</small>
            </div>
            <div className="metric-bottom">{m.detail}</div>
          </div>
        ))}
      </div>
      <div className="overview-middle">
        <section className="card trend-card">
          <SectionTitle
            icon={Activity}
            title="安全决策趋势"
            action={<span className="quiet-tag">按日期统计</span>}
          />
          <Trend data={data.trend} />
          <div className="chart-legend">
            <span>
              <i className="legend-square teal" />
              放行决定
            </span>
            <span>
              <i className="legend-square amber" />
              人工确认
            </span>
            <span>
              <i className="legend-square red" />
              阻断决定
            </span>
          </div>
        </section>
        <section className="card sources-card">
          <SectionTitle icon={Link2} title="输入来源分布" />
          <SourceDistribution data={data.source_distribution} />
        </section>
      </div>
      <div className="overview-bottom">
        <section className="card alerts-card">
          <SectionTitle
            icon={Bell}
            title="近期风险事件"
            action={
              <button className="text-button" onClick={() => nav("sessions")}>
                查看会话
                <ArrowRight size={14} />
              </button>
            }
          />
          {data.recent_alerts.length ? (
            <div className="table-scroll">
              <table className="alerts-table">
                <thead>
                  <tr>
                    <th>工具 / 事件</th>
                    <th>决策</th>
                    <th>时间</th>
                    <th>
                      <span className="sr-only">详情</span>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {data.recent_alerts.slice(0, 6).map((call) => (
                    <tr key={call.id}>
                      <td>
                        <button
                          className="alert-title"
                          onClick={() => nav(`sessions/${call.session_id}`)}
                        >
                          {call.tool}
                        </button>
                        <p
                          className="alert-reason"
                          title={call.reasons[0] || call.report.reason}
                        >
                          {call.reasons[0] ||
                            call.report.reason ||
                            "工具调用审查"}
                        </p>
                      </td>
                      <td>
                        <Badge decision={call.decision} />
                      </td>
                      <td className="alert-time">{time(call.created_at)}</td>
                      <td>
                        <button
                          className="icon-button"
                          aria-label={`查看事件 ${call.id}`}
                          onClick={() => nav(`sessions/${call.session_id}`)}
                        >
                          <ChevronRight size={16} />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <Empty title="当前没有风险事件" />
          )}
        </section>
        <section className="card components-card">
          <SectionTitle icon={Network} title="防护组件" />
          {data.components.map((component) => (
            <div className="component-row" key={component.name}>
              <div>
                <strong>{component.name}</strong>
                <p>{component.detail}</p>
              </div>
              <span
                title={component.status}
                className={`component-status ${["ok", "active", "ready", "healthy", "available", "enabled"].includes(component.status) ? "good" : "muted"}`}
              >
                <span className="dot" />
                {[
                  "ok",
                  "active",
                  "ready",
                  "healthy",
                  "available",
                  "enabled",
                ].includes(component.status)
                  ? "就绪"
                  : (
                      {
                        not_configured: "未配置",
                        not_connected: "未接入",
                        unavailable: "未启用",
                        limited: "部分可用",
                        configured: "已配置",
                      } as Record<string, string>
                    )[component.status] || component.status}
              </span>
            </div>
          ))}
          {!data.components.length && (
            <Empty title="组件信息尚未就绪" detail="等待服务返回组件状态。" />
          )}
        </section>
      </div>
    </>
  );
}
function Trend({ data }: { data: Dashboard["trend"] }) {
  const width = 680,
    height = 180,
    pad = 28,
    max = Math.max(
      4,
      ...data.map((d) => Math.max(d.allow, d.confirm, d.block)),
    );
  const positions = data.map((d, i) => ({
    ...d,
    x:
      data.length === 1
        ? width / 2
        : pad + (i * (width - pad * 2)) / Math.max(1, data.length - 1),
  }));
  const y = (v: number) => height - 20 - (v / max) * (height - 38);
  const path = (key: "allow" | "confirm" | "block") =>
    positions
      .map((p, i) => `${i === 0 ? "M" : "L"}${p.x},${y(p[key])}`)
      .join(" ");
  return (
    <div className="trend-wrap">
      <svg
        viewBox={`0 0 ${width} ${height + 28}`}
        className="trend-chart"
        role="img"
        aria-label="每日允许、确认与阻断数量趋势"
      >
        {[0, 1, 2, 3, 4].map((i) => (
          <g key={i}>
            <line
              x1={pad}
              y1={y((i * max) / 4)}
              x2={width - pad}
              y2={y((i * max) / 4)}
              stroke="#e8e7e3"
              strokeDasharray="3 5"
            />
            <text x="2" y={y((i * max) / 4) + 4} fill="#777975" fontSize="10">
              {Math.round((i * max) / 4)}
            </text>
          </g>
        ))}
        {positions.length !== 1 &&
          (["allow", "confirm", "block"] as const).map((key, j) => (
            <g key={key}>
              <path
                d={path(key)}
                fill="none"
                stroke={["#67736a", "#b07a28", "#bf4c3d"][j]}
                strokeWidth={2.4}
                strokeLinecap="round"
                strokeLinejoin="round"
              />
              {positions.map((p) => (
                <circle
                  key={p.date}
                  cx={p.x}
                  cy={y(p[key])}
                  r={3}
                  fill="white"
                  stroke={["#67736a", "#b07a28", "#bf4c3d"][j]}
                  strokeWidth={1.8}
                >
                  <title>
                    {p.date} · {decisionNames[key]} {p[key]} 次
                  </title>
                </circle>
              ))}
            </g>
          ))}
        {positions.length === 1 &&
          (["allow", "confirm", "block"] as const).map((key, index) => {
            const value = positions[0][key];
            const x = width / 2 + (index - 1) * 96;
            const color = ["#67736a", "#b07a28", "#bf4c3d"][index];
            return (
              <g key={key}>
                <rect
                  x={x - 23}
                  y={y(value)}
                  width={46}
                  height={y(0) - y(value)}
                  rx={1}
                  fill={color}
                  fillOpacity={0.95}
                />
                <text
                  x={x}
                  y={y(value) - 8}
                  textAnchor="middle"
                  fontSize="12"
                  fontWeight="600"
                  fill={color}
                >
                  {value}
                </text>
                <text
                  x={x}
                  y={height - 3}
                  textAnchor="middle"
                  fontSize="9"
                  fill="#777975"
                >
                  {decisionNames[key]}
                </text>
                <title>
                  {positions[0].date} · {decisionNames[key]} {value} 次
                </title>
              </g>
            );
          })}
        {positions.map((p, i) => (
          <text
            key={p.date}
            x={p.x}
            y={height + 15}
            fill="#777975"
            fontSize="10"
            textAnchor={
              positions.length === 1
                ? "middle"
                : i === 0
                  ? "start"
                  : i === positions.length - 1
                    ? "end"
                    : "middle"
            }
          >
            {p.date.slice(5)}
          </text>
        ))}
      </svg>
      {data.every((d) => !d.allow && !d.confirm && !d.block) && (
        <div className="chart-empty-label">等待首条审查记录</div>
      )}
    </div>
  );
}
function SourceDistribution({
  data,
}: {
  data: Dashboard["source_distribution"];
}) {
  const total = data.reduce((sum, item) => sum + item.value, 0);
  const sorted = [...data].sort((a, b) => b.value - a.value);
  const renderRow = (item: Dashboard["source_distribution"][number]) => (
    <div className="source-breakdown-row" key={item.name}>
      <span>{sourceNames[item.name] || item.name}</span>
      <div className="source-track" aria-hidden="true">
        <i style={{ width: `${total ? (item.value / total) * 100 : 0}%` }} />
      </div>
      <strong>{item.value}</strong>
    </div>
  );
  return (
    <div className="source-breakdown">
      <div className="source-breakdown-header">
        <span>来源类型</span>
        <span>{total} 条记录</span>
      </div>
      {sorted.length ? (
        <>
          {sorted.slice(0, 5).map(renderRow)}
          {sorted.length > 5 && (
            <details className="source-breakdown-more">
              <summary>
                其他 {sorted.length - 5} 类来源 ·{" "}
                {sorted.slice(5).reduce((sum, item) => sum + item.value, 0)} 条
              </summary>
              {sorted.slice(5).map(renderRow)}
            </details>
          )}
        </>
      ) : (
        <p className="muted-text">暂无输入来源记录</p>
      )}
    </div>
  );
}

function Demo({
  tick,
  nav,
  notify,
}: {
  tick: number;
  nav: (path: string) => void;
  notify: ToastFn;
}) {
  const { data, error, loading, refresh } = useResource<Scenario[]>(
    "/scenarios",
    tick,
  );
  const [selected, setSelected] = useState("");
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<DemoResult | null>(null);
  const [runError, setRunError] = useState("");
  const [category, setCategory] = useState("全部场景");
  const [query, setQuery] = useState("");
  const [decision, setDecision] = useState("all");
  const categories = [
    "全部场景",
    ...new Set((data || []).map((s) => s.category)),
  ];
  const visibleScenarios = (data || []).filter(
    (s) =>
      (category === "全部场景" || s.category === category) &&
      (decision === "all" || s.expected_decision === decision) &&
      (!query.trim() ||
        `${s.name} ${s.description} ${s.category} ${s.id}`
          .toLowerCase()
          .includes(query.trim().toLowerCase())),
  );
  const scenario =
    visibleScenarios.find((s) => s.id === selected) || visibleScenarios[0];
  const selectedId = scenario?.id;
  const clearFilters = () => {
    setCategory("全部场景");
    setQuery("");
    setDecision("all");
  };
  useEffect(() => {
    if (result)
      document
        .getElementById("demo-result")
        ?.scrollIntoView({ behavior: "smooth", block: "start" });
  }, [result]);
  const run = async () => {
    if (!scenario) return;
    setRunning(true);
    setResult(null);
    setRunError("");
    try {
      const r = await post<DemoResult>("/demo/run", {
        scenario_id: scenario.id,
      });
      setResult(r);
      notify(
        r.passed ? "场景完成，全部断言通过" : "场景完成，存在未通过的断言",
        r.passed ? "success" : "error",
      );
    } catch (e) {
      setRunError((e as Error).message);
    } finally {
      setRunning(false);
    }
  };
  return (
    <>
      <PageTitle
        title="攻防场景"
        action={
          <span className="quiet-tag">
            <LockKeyhole size={13} />
            隔离环境
          </span>
        }
      />
      {result && (
        <section id="demo-result" className="card demo-result">
          <div
            className={`result-banner ${result.passed ? "passed" : "failed"}`}
          >
            <div>
              {result.passed ? (
                <CheckCircle2 size={27} />
              ) : (
                <XCircle size={27} />
              )}
              <div>
                <h2>
                  {result.passed ? "防护效果已验证" : "场景验证存在失败项"}
                </h2>
                <p>
                  {data?.find((s) => s.id === result.scenario_id)?.name ||
                    result.scenario_id}{" "}
                  · 完成 {result.assertions.length} 项断言检查 · 耗时{" "}
                  {result.duration_ms.toFixed(1)} ms
                </p>
              </div>
            </div>
            <Button onClick={() => nav(`sessions/${result.session_id}`)}>
              查看完整会话
              <ArrowRight size={15} />
            </Button>
          </div>
          <div className="assertions">
            {result.assertions.map((a, i) => (
              <div key={i} className="assertion">
                {a.passed ? (
                  <CheckCircle2 size={18} className="text-teal" />
                ) : (
                  <XCircle size={18} className="text-red" />
                )}
                <div>
                  <strong>{a.name}</strong>
                  <p>{a.detail}</p>
                </div>
                <span className={`test-tag ${a.passed ? "pass" : "fail"}`}>
                  {a.passed ? "PASS" : "FAIL"}
                </span>
              </div>
            ))}
          </div>
        </section>
      )}
      {error && <ErrorBox error={error} retry={refresh} />}{" "}
      {loading && !data ? (
        <Loading />
      ) : !data?.length ? (
        <Empty title="暂无场景" />
      ) : (
        <div className="demo-layout">
          <div className="scenario-browser">
            <div className="scenario-searchbar">
              <div className="search-field">
                <Search size={17} />
                <input
                  aria-label="搜索场景"
                  placeholder="搜索场景、攻击方式或关键字"
                  value={query}
                  disabled={running}
                  onChange={(e) => setQuery(e.target.value)}
                />
                {query && (
                  <button
                    className="icon-button"
                    aria-label="清除场景搜索"
                    disabled={running}
                    onClick={() => setQuery("")}
                  >
                    <X size={14} />
                  </button>
                )}
              </div>
              <div className="select-field">
                <Filter size={15} />
                <select
                  aria-label="筛选预期决策"
                  value={decision}
                  disabled={running}
                  onChange={(e) => setDecision(e.target.value)}
                >
                  <option value="all">全部预期决策</option>
                  <option value="block">预期阻断</option>
                  <option value="confirm">预期确认</option>
                  <option value="allow">预期允许</option>
                </select>
                <ChevronDown size={14} />
              </div>
            </div>
            <div className="demo-category-bar" aria-label="场景分类">
              {categories.map((c) => (
                <button
                  key={c}
                  disabled={running}
                  aria-pressed={category === c}
                  className={category === c ? "active" : ""}
                  onClick={() => setCategory(c)}
                >
                  {c}
                  <span>
                    {c === "全部场景"
                      ? data.length
                      : data.filter((s) => s.category === c).length}
                  </span>
                </button>
              ))}
            </div>
            <div className="scenario-list-heading" aria-hidden="true">
              <span aria-live="polite">
                测试场景 · {visibleScenarios.length} / {data.length}
              </span>
              <span>预期决策</span>
            </div>
            <div
              className="scenario-grid"
              role="region"
              aria-label="场景列表"
              tabIndex={0}
            >
              {visibleScenarios.map((s) => (
                <button
                  key={s.id}
                  disabled={running}
                  aria-pressed={selectedId === s.id}
                  onClick={() => {
                    setSelected(s.id);
                    setResult(null);
                    setRunError("");
                  }}
                  className={`scenario-card ${selectedId === s.id ? "selected" : ""}`}
                >
                  <span className="scenario-index">
                    {String(
                      data.findIndex((item) => item.id === s.id) + 1,
                    ).padStart(2, "0")}
                  </span>
                  <div className="scenario-copy">
                    <h3>{s.name}</h3>
                    <p>{s.description}</p>
                    <span className="scenario-category">{s.category}</span>
                  </div>
                  <Badge decision={s.expected_decision} />
                </button>
              ))}
              {!visibleScenarios.length && (
                <Empty
                  title="没有匹配的场景"
                  detail="试试其他关键词，或调整分类与预期决策。"
                  action={<Button onClick={clearFilters}>清除筛选</Button>}
                />
              )}
            </div>
            <div className="scenario-list-footer">
              {(query || category !== "全部场景" || decision !== "all") && (
                <button
                  className="text-link"
                  disabled={running}
                  onClick={clearFilters}
                >
                  清除筛选
                </button>
              )}
            </div>
          </div>
          <aside className="card run-panel">
            <div className="run-panel-header">
              <Zap size={19} />
              <strong>当前场景</strong>
            </div>
            {scenario && (
              <>
                <h3>{scenario.name}</h3>
                <div className="selected-scenario-meta">
                  <span>预期决策</span>
                  <Badge decision={scenario.expected_decision} />
                </div>
                <p>{scenario.description}</p>
                <Button
                  variant="primary"
                  className="full-width run-scenario-button"
                  disabled={running}
                  onClick={run}
                >
                  {running ? (
                    <Loader2 className="spin" size={17} />
                  ) : (
                    <Play size={17} />
                  )}
                  {running ? "正在运行防护链路…" : "运行此场景"}
                </Button>
                <details className="scenario-steps" open>
                  <summary>
                    执行步骤<span>{scenario.steps.length} 步</span>
                  </summary>
                  <div className="run-steps">
                    {scenario.steps.map((step, i) => (
                      <div key={i}>
                        <span>{i + 1}</span>
                        <p>{step}</p>
                      </div>
                    ))}
                  </div>
                </details>
              </>
            )}
            {!scenario && (
              <p className="unselected-message">
                调整左侧筛选后，选择一个场景开始验证。
              </p>
            )}
            {runError && <ErrorBox error={runError} retry={run} />}
          </aside>
        </div>
      )}
    </>
  );
}

function Sessions({
  tick,
  selectedId,
  focusedItem,
  nav,
  notify,
}: {
  tick: number;
  selectedId?: string;
  focusedItem?: string;
  nav: (path: string) => void;
  notify: ToastFn;
}) {
  const resource = useResource<Session[]>("/sessions", tick);
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState("all");
  const [create, setCreate] = useState(false);
  const [sort, setSort] = useState("newest");
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(15);
  const [historyScope, setHistoryScope] = useState<"recent" | "all">("recent");
  const normalizedQuery = query.trim().toLowerCase();
  const orderedSessions = [...(resource.data || [])].sort(
    (a, b) =>
      b.created_at.localeCompare(a.created_at) || a.id.localeCompare(b.id),
  );
  const scopedSessions =
    historyScope === "recent" ? orderedSessions.slice(0, 20) : orderedSessions;
  const filtered = scopedSessions
    .filter(
      (s) =>
        (!normalizedQuery ||
          `${s.title} ${s.id} ${s.intent} ${s.agent_id}`
            .toLowerCase()
            .includes(normalizedQuery)) &&
        (filter === "all" ||
          (filter === "blocked" && s.blocked_count > 0) ||
          filter === s.scope),
    )
    .sort((a, b) => {
      const byTime =
        b.created_at.localeCompare(a.created_at) || a.id.localeCompare(b.id);
      return sort === "risk"
        ? b.blocked_count - a.blocked_count || byTime
        : sort === "calls"
          ? b.call_count - a.call_count || byTime
          : sort === "oldest"
            ? -byTime
            : byTime;
    });
  const hasFilters = !!query || filter !== "all";
  const resetFilters = () => {
    setQuery("");
    setFilter("all");
    setPage(1);
  };
  const visibleSessions = pageSlice(filtered, page, pageSize);
  if (selectedId)
    return (
      <SessionView
        key={selectedId}
        id={selectedId}
        focusedItem={focusedItem}
        tick={tick}
        nav={nav}
        notify={notify}
      />
    );
  return (
    <>
      <PageTitle
        title="溯源复盘"
        action={
          <Button variant="primary" onClick={() => setCreate(true)}>
            <Plus size={16} />
            登记审查会话
          </Button>
        }
      />
      <section className="card">
        <div className="table-toolbar session-toolbar">
          <div className="search-field">
            <Search size={17} />
            <input
              value={query}
              onChange={(e) => {
                setQuery(e.target.value);
                if (e.target.value.trim()) setHistoryScope("all");
                setPage(1);
              }}
              placeholder="搜索任务、会话 ID 或智能体"
              aria-label="搜索会话"
            />
            {query && (
              <button
                className="icon-button"
                aria-label="清除会话搜索"
                onClick={() => {
                  setQuery("");
                  setPage(1);
                }}
              >
                <X size={14} />
              </button>
            )}
          </div>
          <div className="select-field">
            <select
              aria-label="会话记录范围"
              value={historyScope}
              onChange={(event) => {
                setHistoryScope(event.target.value as "recent" | "all");
                setPage(1);
              }}
            >
              <option value="recent">最近 20 个会话</option>
              <option value="all">全部历史会话</option>
            </select>
            <ChevronDown size={14} />
          </div>
          <div className="select-field">
            <Filter size={15} />
            <select
              value={filter}
              onChange={(e) => {
                setFilter(e.target.value);
                setPage(1);
              }}
              aria-label="筛选会话"
            >
              <option value="all">全部会话</option>
              <option value="blocked">包含阻断</option>
              <option value="read_only">只读任务</option>
              <option value="development">开发任务</option>
            </select>
            <ChevronDown size={14} />
          </div>
          <div className="select-field session-sort">
            <select
              aria-label="会话排序"
              value={sort}
              onChange={(e) => {
                setSort(e.target.value);
                setPage(1);
              }}
            >
              <option value="newest">最近创建优先</option>
              <option value="oldest">最早创建优先</option>
              <option value="risk">阻断次数优先</option>
              <option value="calls">调用次数优先</option>
            </select>
            <ChevronDown size={14} />
          </div>
          {hasFilters && (
            <button className="text-link" onClick={resetFilters}>
              清除筛选
            </button>
          )}
        </div>
        {resource.error ? (
          <ErrorBox error={resource.error} retry={resource.refresh} />
        ) : resource.loading && !resource.data ? (
          <Loading />
        ) : !filtered.length ? (
          <Empty
            title={hasFilters ? "没有匹配的会话" : "暂无会话记录"}
            detail={
              hasFilters
                ? "调整关键词或授权范围后重试。"
                : "可创建一个自定义会话，或运行内置攻防场景。"
            }
            action={
              hasFilters ? (
                <Button onClick={resetFilters}>清除筛选</Button>
              ) : (
                <Button onClick={() => nav("demo")}>
                  <Play size={14} />
                  查看攻防场景
                </Button>
              )
            }
          />
        ) : (
          <>
            <div className="table-scroll">
              <table className="sessions-table">
                <thead>
                  <tr>
                    <th>任务会话</th>
                    <th>授权范围</th>
                    <th>工具调用</th>
                    <th>阻断决定</th>
                    <th>创建时间</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {visibleSessions.map((s) => (
                    <tr
                      key={s.id}
                      onClick={() => nav(`sessions/${s.id}`)}
                      className="clickable-row"
                    >
                      <td>
                        <div className="table-title">
                          <div className="table-file-icon">
                            <Workflow size={18} />
                          </div>
                          <div>
                            <button
                              className="session-title-link"
                              onClick={(e) => {
                                e.stopPropagation();
                                nav(`sessions/${s.id}`);
                              }}
                            >
                              {s.title}
                            </button>
                            <small title={s.id}>
                              {short(s.id)}{" "}
                              <span className="session-agent">
                                · {s.agent_id}
                              </span>
                            </small>
                          </div>
                        </div>
                      </td>
                      <td>
                        <span
                          className={`scope-tag ${s.scope === "read_only" ? "blue" : "teal"}`}
                        >
                          {s.scope === "read_only" ? "只读任务" : "开发任务"}
                        </span>
                      </td>
                      <td>
                        {s.call_count}
                        <span className="unit">次</span>
                      </td>
                      <td>
                        <span
                          className={
                            s.blocked_count ? "text-red" : "muted-text"
                          }
                        >
                          {s.blocked_count}
                        </span>
                        <span className="unit">次</span>
                      </td>
                      <td className="muted-text">{time(s.created_at, true)}</td>
                      <td>
                        <button
                          className="icon-button"
                          aria-label={`打开会话 ${s.title}`}
                          onClick={(e) => {
                            e.stopPropagation();
                            nav(`sessions/${s.id}`);
                          }}
                        >
                          <ChevronRight size={17} />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <Pagination
              label="会话"
              page={page}
              pageSize={pageSize}
              total={filtered.length}
              onPageChange={setPage}
              onPageSizeChange={setPageSize}
            />
          </>
        )}
      </section>
      {create && (
        <CreateSession
          onClose={() => setCreate(false)}
          onCreated={(s) => {
            setCreate(false);
            resource.refresh();
            nav(`sessions/${s.id}`);
          }}
          notify={notify}
        />
      )}
    </>
  );
}
function CreateSession({
  onClose,
  onCreated,
  notify,
}: {
  onClose: () => void;
  onCreated: (s: Session) => void;
  notify: ToastFn;
}) {
  const [title, setTitle] = useState("");
  const [intent, setIntent] = useState("");
  const [scope, setScope] = useState("read_only");
  const [busy, setBusy] = useState(false);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    try {
      const s = await post<Session>("/sessions", { title, intent, scope });
      onCreated(s);
      notify("会话已创建");
    } catch (e) {
      notify((e as Error).message, "error");
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal title="创建任务会话" onClose={onClose}>
      <form className="form-body" onSubmit={submit}>
        <label>
          会话名称
          <input
            required
            maxLength={160}
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            placeholder="例如：阅读项目并生成安全摘要"
          />
        </label>
        <label>
          原始任务意图
          <textarea
            required
            rows={4}
            value={intent}
            onChange={(e) => setIntent(e.target.value)}
            placeholder="描述用户明确授权智能体完成的任务…"
          />
        </label>
        <label>
          授权范围
          <select value={scope} onChange={(e) => setScope(e.target.value)}>
            <option value="read_only">只读任务 · 仅允许读取操作</option>
            <option value="development">开发任务 · 写入需经过审查</option>
          </select>
        </label>
        <div className="form-actions">
          <Button onClick={onClose}>取消</Button>
          <Button variant="primary" type="submit" disabled={busy}>
            {busy && <Loader2 className="spin" size={15} />}创建会话
          </Button>
        </div>
      </form>
    </Modal>
  );
}

function SessionView({
  id,
  focusedItem,
  tick,
  nav,
  notify,
}: {
  id: string;
  focusedItem?: string;
  tick: number;
  nav: (path: string) => void;
  notify: ToastFn;
}) {
  const { data, error, loading, refresh } = useResource<SessionDetail>(
    `/sessions/${encodeURIComponent(id)}`,
    tick,
  );
  const [tab, setTab] = useState("graph");
  const [add, setAdd] = useState<"source" | "call" | null>(null);
  const [sourceId, setSourceId] = useState<string | null>(null);
  const [selectedCallId, setSelectedCallId] = useState<string | null>(null);
  const source = data?.sources.find((item) => item.id === sourceId);
  const selectedCall = data?.calls.find((item) => item.id === selectedCallId);
  const openedItem = useRef<string | undefined>();
  const [exporting, setExporting] = useState(false);
  const locateEvidence = (nodeId: string) => {
    const foundSource = data?.sources.find((item) => item.id === nodeId);
    if (foundSource) {
      setSelectedCallId(null);
      setSourceId(foundSource.id);
      return;
    }
    const callId = nodeId
      .replace(/^(agent:|mcp:|child:)/, "")
      .replace(/:receipt$/, "");
    const call = data?.calls.find((item) => item.id === callId);
    if (call) {
      setSourceId(null);
      setSelectedCallId(call.id);
    }
  };
  useEffect(() => {
    if (!focusedItem) {
      openedItem.current = undefined;
      return;
    }
    if (data && openedItem.current !== focusedItem) {
      setSourceId(null);
      setSelectedCallId(null);
      locateEvidence(focusedItem);
      openedItem.current = focusedItem;
    }
  }, [focusedItem, data]);
  const exportData = async () => {
    setExporting(true);
    try {
      downloadJSON(
        await api(`/sessions/${id}/export`),
        `智行安盾-会话证据-${id}.json`,
      );
      notify("会话脱敏证据已导出");
    } catch (e) {
      notify((e as Error).message, "error");
    } finally {
      setExporting(false);
    }
  };
  if (loading && !data) return <Loading />;
  if (error) return <ErrorBox error={error} retry={refresh} />;
  if (!data) return null;
  return (
    <>
      <button className="back-link" onClick={() => nav("sessions")}>
        <ArrowLeft size={15} />
        返回溯源列表
      </button>
      <PageTitle
        title={data.title}
        description={`会话 ${data.id} · 创建于 ${time(data.created_at, true)}`}
        action={
          <>
            <Button onClick={exportData} disabled={exporting}>
              <ArrowDownToLine size={15} />
              导出证据
            </Button>
            <Button variant="primary" onClick={() => nav(`alerts/${id}`)}>
              <ShieldAlert size={15} />
              告警研判
            </Button>
          </>
        }
      />
      <div className="workflow-links" aria-label="任务关联页面">
        <button onClick={() => nav(`tasks/${id}`)}>
          <Terminal size={15} />
          任务运行
        </button>
        <button onClick={() => nav(`alerts/${id}`)}>
          <ShieldAlert size={15} />
          告警研判
        </button>
        <button onClick={() => nav(`approvals//${id}`)}>
          <ClipboardCheck size={15} />
          确认复核
        </button>
        <span>
          <Fingerprint size={14} />
          <code>{id}</code>
        </span>
      </div>
      <div className="session-context card">
        <div className="context-icon">
          <Fingerprint size={24} />
        </div>
        <div className="context-intent">
          <span>原始任务意图</span>
          <p>{data.original_intent || data.intent}</p>
          <span className="effective-intent">
            当前授权任务 · v{data.authorization_version || 1}
          </span>
          <p>{data.intent}</p>
        </div>
        <div className="context-info">
          <span>
            授权范围
            <strong className="scope-tag blue">
              {data.scope === "read_only" ? "只读任务" : "开发任务"}
            </strong>
          </span>
          <span>
            执行智能体<strong>{data.agent_id}</strong>
          </span>
        </div>
      </div>
      <details className="authorization-disclosure">
        <summary>查看授权版本与变更记录</summary>
        <AuthorizationControl
          key={`auth-${data.id}-${data.authorization_version}`}
          session={data}
          refresh={refresh}
          notify={notify}
        />
      </details>
      <div className="session-stat-strip">
        <span>
          <Layers3 size={16} />
          <strong>{data.calls.length}</strong>次工具审查
        </span>
        <span>
          <Link2 size={16} />
          <strong>{data.sources.length}</strong>条输入来源
        </span>
        <span>
          <ShieldAlert size={16} />
          <strong>
            {data.calls.filter((c) => c.decision === "block").length}
          </strong>
          次阻断决定
        </span>
        <span>
          <Clock3 size={16} />
          <strong>{data.events.length}</strong>条审计事件
        </span>
      </div>
      <section className="card session-body">
        <div className="tabs">
          {[
            { id: "graph", label: "传播路径", icon: GitBranch },
            { id: "timeline", label: "时序链路", icon: Clock3 },
            { id: "calls", label: "调用与回执", icon: Terminal },
            { id: "sources", label: "来源分析", icon: FileText },
            { id: "effects", label: "影响核实", icon: Eye },
            { id: "data", label: "记忆与数据", icon: Database },
          ].map((t) => (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              aria-pressed={tab === t.id}
              className={tab === t.id ? "active" : ""}
            >
              <t.icon size={16} />
              {t.label}
              {t.id === "calls" && <span>{data.calls.length}</span>}
            </button>
          ))}
          <div className="tab-spacer" />
          <button onClick={() => setAdd("source")}>
            <Plus size={15} />
            登记输入来源
          </button>
        </div>
        {tab === "calls" ? (
          data.calls.length ? (
            <CallExplorer
              calls={data.calls}
              notify={notify}
              onChanged={refresh}
            />
          ) : (
            <Empty
              title="此会话尚无工具调用"
              detail="提交工具名称与参数，系统将先审查，再允许独立执行。"
              action={
                <Button onClick={() => setAdd("call")}>审查工具调用</Button>
              }
            />
          )
        ) : tab === "effects" ? (
          <div className="effects-review">
            <div className="section-heading">
              <h2>目标与实际效果</h2>
            </div>
            {data.calls.length ? (
              data.calls.map((call) => (
                <article className="effect-record" key={call.id}>
                  <header>
                    <strong>{call.tool}</strong>
                    <Badge decision={call.decision} />
                    <span>
                      {executionNames[call.execution_status] ||
                        call.execution_status}
                    </span>
                    <button
                      className="text-button"
                      onClick={() => locateEvidence(call.id)}
                    >
                      查看调用
                      <ArrowRight size={14} />
                    </button>
                  </header>
                  <div className="effect-columns">
                    <div>
                      <h4>拟访问对象与参数</h4>
                      <pre>
                        {pretty(
                          call.resource_facts &&
                            Object.keys(call.resource_facts).length
                            ? call.resource_facts
                            : call.args,
                        )}
                      </pre>
                    </div>
                    <div>
                      <h4>执行回执</h4>
                      {call.receipt ? (
                        <>
                          <p>{call.receipt.detail}</p>
                          <pre>{pretty(call.receipt.result)}</pre>
                        </>
                      ) : (
                        <p className="caption">
                          {call.control_receipt?.status ===
                          "withheld_before_execution"
                            ? "入口已确认停止执行，未产生工具效果。"
                            : "尚无执行回执，不能据此认定文件、网络或远端对象已改变。"}
                        </p>
                      )}
                    </div>
                  </div>
                </article>
              ))
            ) : (
              <Empty
                title="暂无工具效果记录"
                detail="调用与执行回执出现后，可在此核实访问对象及实际结果。"
              />
            )}
          </div>
        ) : tab === "data" ? (
          <>
            <DataEvidence key={id} sessionId={id} sources={data.sources} />
            <KnowledgeControl key={`knowledge-${id}`} sessionId={id} />
            <ModelRequestEvidence key={`requests-${id}`} sessionId={id} />
          </>
        ) : tab === "sources" ? (
          data.sources.length ? (
            <div className="sources-grid">
              {data.sources.map((s) => (
                <button
                  className="source-card"
                  key={s.id}
                  aria-label={`查看来源：${sourceNames[s.type] || s.type}，${s.resource || "未命名输入来源"}`}
                  onClick={() => setSourceId(s.id)}
                >
                  <div>
                    <span className="source-type">
                      <FileText size={15} />
                      {sourceNames[s.type] || s.type}
                    </span>
                    <Badge decision={s.decision} />
                  </div>
                  <h3>{s.resource || "未命名输入来源"}</h3>
                  <p>{s.content}</p>
                  <footer>
                    <span>
                      风险 {s.detection.risk_score} · v{s.version}
                    </span>
                    <span>
                      查看证据
                      <ArrowRight size={13} />
                    </span>
                  </footer>
                </button>
              ))}
            </div>
          ) : (
            <Empty
              title="尚未登记输入来源"
              detail="登记网页、文档、邮件或 MCP 返回内容，检查潜在的注入指令。"
            />
          )
        ) : tab === "graph" ? (
          <CausalGraph graph={data.graph} onInspect={locateEvidence} />
        ) : (
          <div className="timeline">
            {data.events.length ? (
              data.events.map((event) => (
                <div className="timeline-item" key={event.id}>
                  <div className="timeline-node" />
                  <div className="timeline-time">
                    <span>{time(event.timestamp)}</span>
                    <small>#{event.sequence}</small>
                  </div>
                  <div className="timeline-content">
                    <strong>{event.summary}</strong>
                    <span>{event.type}</span>
                    {(event.call_id || event.source_id) && (
                      <button
                        className="text-button"
                        onClick={() =>
                          locateEvidence(event.call_id || event.source_id!)
                        }
                      >
                        回查关联证据
                        <ArrowRight size={13} />
                      </button>
                    )}
                    <details>
                      <summary>查看事件详情</summary>
                      <pre>{pretty(event.details)}</pre>
                    </details>
                  </div>
                </div>
              ))
            ) : (
              <Empty title="暂无审计事件" />
            )}
          </div>
        )}
      </section>
      {add && (
        <AddSessionItem
          kind={add}
          session={data}
          notify={notify}
          onClose={() => setAdd(null)}
          onAdded={() => {
            setAdd(null);
            refresh();
            setTab(add === "call" ? "calls" : "sources");
          }}
        />
      )}
      {source && (
        <Modal title="输入来源分析" wide onClose={() => setSourceId(null)}>
          <SourceDetail key={source.id} source={source} />
        </Modal>
      )}
      {selectedCall && (
        <Modal
          title="调用、研判与执行回执"
          wide
          onClose={() => setSelectedCallId(null)}
        >
          <div className="form-body">
            <CallCard
              key={selectedCall.id}
              call={selectedCall}
              notify={notify}
              defaultOpen
              onChanged={() => {
                setSelectedCallId(null);
                refresh();
              }}
            />
            <Button onClick={() => nav(`alerts/${id}/${selectedCall.id}`)}>
              <ShieldAlert size={15} />
              进入告警研判
            </Button>
          </div>
        </Modal>
      )}
    </>
  );
}
function CallExplorer({
  calls,
  notify,
  onChanged,
}: {
  calls: GuardCall[];
  notify: ToastFn;
  onChanged: () => void;
}) {
  const [query, setQuery] = useState("");
  const [decision, setDecision] = useState("all");
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(15);
  const needle = query.trim().toLowerCase();
  const filtered = calls.filter(
    (call) =>
      (decision === "all" || call.decision === decision) &&
      (!needle ||
        `${call.tool} ${call.id} ${call.agent_id} ${call.plan} ${call.reasons.join(" ")} ${JSON.stringify(call.args)}`
          .toLowerCase()
          .includes(needle)),
  );
  const indices = new Map(calls.map((call, index) => [call.id, index + 1]));
  const reset = () => {
    setQuery("");
    setDecision("all");
    setPage(1);
  };
  return (
    <div className="call-explorer">
      <div className="call-filterbar">
        <div className="search-field">
          <Search size={16} />
          <input
            aria-label="搜索工具调用"
            value={query}
            placeholder="工具、参数、判定原因或调用 ID"
            onChange={(event) => {
              setQuery(event.target.value);
              setPage(1);
            }}
          />
          {query && (
            <button
              className="icon-button"
              aria-label="清除调用搜索"
              onClick={() => {
                setQuery("");
                setPage(1);
              }}
            >
              <X size={14} />
            </button>
          )}
        </div>
        <div className="decision-filters" aria-label="工具调用决策筛选">
          {[
            ["all", "全部"],
            ["block", "阻断决定"],
            ["confirm", "待确认"],
            ["allow", "放行"],
          ].map(([value, label]) => (
            <button
              key={value}
              aria-pressed={decision === value}
              className={decision === value ? "active" : ""}
              onClick={() => {
                setDecision(value);
                setPage(1);
              }}
            >
              {label}
              <span>
                {value === "all"
                  ? calls.length
                  : calls.filter((call) => call.decision === value).length}
              </span>
            </button>
          ))}
        </div>
      </div>
      {filtered.length ? (
        <>
          <div className="calls-list">
            {pageSlice(filtered, page, pageSize).map((call) => (
              <CallCard
                key={call.id}
                call={call}
                index={indices.get(call.id)}
                notify={notify}
                onChanged={onChanged}
              />
            ))}
          </div>
          <Pagination
            label="调用"
            page={page}
            pageSize={pageSize}
            total={filtered.length}
            onPageChange={setPage}
            onPageSizeChange={setPageSize}
          />
        </>
      ) : (
        <Empty
          title="没有匹配的工具调用"
          detail="调整关键词或决策筛选后重试。"
          action={<Button onClick={reset}>清除筛选</Button>}
        />
      )}
    </div>
  );
}

function CallCard({
  call,
  index,
  notify,
  onChanged,
  defaultOpen = false,
}: {
  call: GuardCall;
  index?: number;
  notify: ToastFn;
  onChanged: (updatedCall?: GuardCall) => void;
  defaultOpen?: boolean;
}) {
  const [open, setOpen] = useState(defaultOpen);
  const [busy, setBusy] = useState(false);
  const [now, setNow] = useState(Date.now());
  const canRecheck =
    call.execution_owner !== "adapter" &&
    !call.superseded_by &&
    ["not_executed", "pending"].includes(call.execution_status);
  const expired = Boolean(
    call.permit_expires_at && Date.parse(call.permit_expires_at) <= now,
  );
  useEffect(() => {
    if (!open || !call.permit_expires_at || !canRecheck) return;
    setNow(Date.now());
    const timer = setInterval(() => setNow(Date.now()), 10000);
    return () => clearInterval(timer);
  }, [open, call.permit_expires_at, canRecheck]);
  const execute = async () => {
    setBusy(true);
    try {
      const result = await post<GuardCall>(`/calls/${call.id}/execute`, {});
      notify(
        result.execution_status === "succeeded"
          ? "已完成受控工具执行"
          : result.receipt?.detail || "执行状态已更新",
        result.execution_status === "failed" ? "error" : "success",
      );
      onChanged(result);
    } catch (e) {
      notify((e as Error).message, "error");
      onChanged();
    } finally {
      setBusy(false);
    }
  };
  const recheck = async () => {
    setBusy(true);
    try {
      const result = await post<GuardCall>(`/calls/${call.id}/recheck`, {});
      notify(
        `已生成新的审查记录：${decisionNames[result.decision]}。${result.decision === "confirm" ? "请前往确认复核重新确认。" : result.decision === "allow" ? "请在新调用记录中核对并执行。" : "当前规则仍阻止此操作。"}`,
      );
      onChanged(result);
    } catch (e) {
      notify((e as Error).message, "error");
      onChanged();
    } finally {
      setBusy(false);
    }
  };
  return (
    <div id={`guard-call-${call.id}`} className={`call-card ${call.decision}`}>
      <div className="call-header">
        <button
          className="call-expand"
          onClick={() => setOpen((v) => !v)}
          aria-expanded={open}
        >
          <div className="call-index">
            {index ? String(index).padStart(2, "0") : <Terminal size={17} />}
          </div>
          <div className="call-name">
            <strong>{call.tool}</strong>
            <span>
              {short(call.id)}
              <i />
              {time(call.created_at)}
            </span>
          </div>
          <Badge decision={call.decision} />
          <span className={`risk-level ${call.severity}`}>
            {severityNames[call.severity] || call.severity} · {call.risk_score}
          </span>
          <span className="execution-label">
            {call.control_receipt?.status === "withheld_before_execution"
              ? "入口已确认阻断"
              : executionNames[call.execution_status] || call.execution_status}
          </span>
          <ChevronDown className={open ? "rotate" : ""} size={17} />
        </button>
      </div>
      <p className="call-reason">
        {call.reasons.join("；") || call.report.reason || "审查已完成"}
      </p>
      {open && (
        <div className="call-expanded">
          <div className="call-detail-grid">
            <div>
              <h4>调用参数</h4>
              <pre>{pretty(call.args)}</pre>
              <h4>执行计划</h4>
              <p className="body-text">{call.plan || "未提供执行计划"}</p>
            </div>
            <div>
              <h4>行为一致性报告</h4>
              <dl className="report-list">
                <dt>任务关系</dt>
                <dd>
                  {(
                    {
                      aligned_with_constraints: "符合当前授权边界",
                      deviating: "偏离授权任务",
                      uncertain: "需补充确认",
                    } as Record<string, string>
                  )[call.report.task_relation] || call.report.task_relation}
                </dd>
                <dt>偏离程度</dt>
                <dd>
                  {(
                    { low: "低", medium: "中", high: "高" } as Record<
                      string,
                      string
                    >
                  )[call.report.deviation_level] || call.report.deviation_level}
                </dd>
                <dt>审查理由</dt>
                <dd>{call.report.reason}</dd>
                <dt>关联资源</dt>
                <dd>
                  <code>{pretty(call.report.resources)}</code>
                </dd>
                <dt>证据引用</dt>
                <dd>
                  <code>{pretty(call.report.evidence_refs)}</code>
                </dd>
                <dt>策略版本</dt>
                <dd>v{call.policy_version}</dd>
                {call.report.alignment_coverage && (
                  <>
                    <dt>语义关联覆盖</dt>
                    <dd>
                      历史 {call.report.alignment_coverage.history_checked}/
                      {call.report.alignment_coverage.history_total} ·{" "}
                      {call.report.alignment_coverage.complete
                        ? "检查完成"
                        : "存在缺口"}
                      {call.report.alignment_coverage.global_review &&
                        ` · 全局联合审查${call.report.alignment_coverage.global_review.complete ? "完成" : "未完成"}`}
                    </dd>
                  </>
                )}
              </dl>
            </div>
          </div>
          <div className="matched-rules">
            <span>命中规则</span>
            {call.matched_rules.length ? (
              call.matched_rules.map((r) => <code key={r}>{r}</code>)
            ) : (
              <span className="muted-text">无</span>
            )}
          </div>
          {call.information_gaps.length > 0 && (
            <div className="warning-box">
              <TriangleAlert size={17} />
              <p>信息缺口：{call.information_gaps.join("；")}</p>
            </div>
          )}
          <details className="technical-details">
            <summary>绑定与溯源信息</summary>
            <dl className="report-list">
              <dt>参数摘要</dt>
              <dd className="mono wrap">{call.parameter_hash}</dd>
              <dt>输入来源</dt>
              <dd className="mono">{call.source_ids.join(", ") || "无"}</dd>
              <dt>父调用</dt>
              <dd>{call.parent_call_id || "无"}</dd>
              <dt>MCP 服务</dt>
              <dd>{call.mcp_server || "无"}</dd>
            </dl>
          </details>
          {call.receipt && (
            <div
              className={`receipt ${call.execution_status === "failed" ? "failed" : ""}`}
            >
              <div>
                <ClipboardCheck size={18} />
                <strong>执行回执</strong>
                <span>{call.receipt.status}</span>
                <span>{receiptOrigin(call.receipt.evidence_type)}</span>
              </div>
              <p>{call.receipt.detail}</p>
              <pre>{pretty(call.receipt.result)}</pre>
              <small>{time(call.receipt.executed_at, true)}</small>
            </div>
          )}
          {call.approval && (
            <div className="approval-audit">
              <h4>确认复核记录</h4>
              <dl className="report-list">
                <dt>处理结果</dt>
                <dd>{call.approval.approved ? "确认后重新研判" : "已拒绝"}</dd>
                <dt>操作主体</dt>
                <dd>{call.approval.actor}</dd>
                <dt>处理时间</dt>
                <dd>{time(call.approval.at, true)}</dd>
                <dt>复核策略</dt>
                <dd>v{call.approval.policy_version}</dd>
                <dt>处理意见</dt>
                <dd>{call.approval.comment || "未填写"}</dd>
              </dl>
            </div>
          )}
          {call.permit_expires_at &&
            canRecheck &&
            call.decision === "allow" && (
              <div className={`permit-notice ${expired ? "expired" : ""}`}>
                <Clock3 size={13} />
                <span>
                  {expired
                    ? "执行许可已过期，请重新审查后使用新的调用记录。"
                    : `执行许可有效至 ${time(call.permit_expires_at, true)}`}
                </span>
              </div>
            )}
          {call.recheck_of_call_id && (
            <div className="permit-notice">
              <GitBranch size={13} />
              <span>
                重新审查自{" "}
                <a
                  className="text-link"
                  href={`#alerts/${call.session_id}/${call.recheck_of_call_id}`}
                >
                  {short(call.recheck_of_call_id)}
                </a>{" "}
                · 原审批未继承
              </span>
            </div>
          )}
          {call.superseded_by && (
            <div className="permit-notice expired">
              <RefreshCw size={13} />
              <span>
                此记录已被新审查替代，后续操作请使用{" "}
                <a
                  className="text-link"
                  href={`#alerts/${call.session_id}/${call.superseded_by}`}
                >
                  {short(call.superseded_by)}
                </a>
                。
              </span>
            </div>
          )}
          <div className="call-actions">
            <span>审查耗时 {call.latency_ms.toFixed(2)} ms</span>
            {call.decision === "allow" &&
              call.execution_owner !== "adapter" &&
              !call.superseded_by &&
              call.execution_status === "not_executed" && (
                <Button
                  variant="primary"
                  disabled={busy || expired}
                  onClick={execute}
                >
                  {busy ? (
                    <Loader2 className="spin" size={14} />
                  ) : (
                    <Play size={14} />
                  )}
                  执行受控工具
                </Button>
              )}
            {call.execution_owner === "adapter" && (
              <span className="permit-notice">执行方：宿主</span>
            )}
            {call.decision === "block" && (
              <span className="blocked-label">
                <LockKeyhole size={14} />
                当前决定禁止执行
              </span>
            )}
            {canRecheck && (
              <Button
                disabled={busy}
                onClick={recheck}
                title="按原参数重新审查，生成独立记录；原审批不继承"
              >
                <RefreshCw size={14} />
                重新审查
              </Button>
            )}
            {call.decision === "confirm" &&
              canRecheck &&
              call.execution_status === "pending" && (
                <Button
                  disabled={busy}
                  onClick={() => {
                    location.hash = `approvals/${call.id}/${call.session_id}`;
                  }}
                >
                  <ClipboardCheck size={14} />
                  前往确认复核
                </Button>
              )}
          </div>
        </div>
      )}
    </div>
  );
}
function AddSessionItem({
  kind,
  session,
  onClose,
  onAdded,
  notify,
}: {
  kind: "source" | "call";
  session: SessionDetail;
  onClose: () => void;
  onAdded: () => void;
  notify: ToastFn;
}) {
  const [type, setType] = useState("web");
  const [content, setContent] = useState("");
  const [resource, setResource] = useState("");
  const [tool, setTool] = useState("fs.read");
  const [args, setArgs] = useState('{\n  "path": "README.md"\n}');
  const [plan, setPlan] = useState("");
  const [sourceIds, setSourceIds] = useState<string[]>([]);
  const [parentSource, setParentSource] = useState("");
  const [parentCall, setParentCall] = useState("");
  const [agent, setAgent] = useState(session.agent_id);
  const [server, setServer] = useState("local-fixture");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError("");
    setBusy(true);
    try {
      if (kind === "source")
        await post(`/sessions/${session.id}/sources`, {
          type,
          content,
          resource,
          parent_source_id: parentSource || undefined,
        });
      else {
        let parsed;
        try {
          parsed = JSON.parse(args);
        } catch {
          throw new Error("调用参数必须是有效的 JSON 对象。");
        }
        if (!parsed || Array.isArray(parsed) || typeof parsed !== "object")
          throw new Error("调用参数必须是 JSON 对象。");
        await post(`/sessions/${session.id}/calls`, {
          tool,
          args: parsed,
          source_ids: sourceIds,
          plan,
          agent_id: agent,
          parent_call_id: parentCall || undefined,
          mcp_server: server,
        });
      }
      notify(
        kind === "source" ? "输入来源已登记并完成检测" : "工具调用审查已完成",
      );
      onAdded();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal
      title={kind === "source" ? "登记不可信输入来源" : "审查工具调用"}
      wide
      onClose={onClose}
    >
      <form className="form-body" onSubmit={submit}>
        {kind === "source" ? (
          <>
            <div className="form-grid">
              <label>
                来源类型
                <select value={type} onChange={(e) => setType(e.target.value)}>
                  {Object.entries(sourceNames).map(([k, v]) => (
                    <option key={k} value={k}>
                      {v}
                    </option>
                  ))}
                </select>
              </label>
              <label>
                来源位置 / 资源标识
                <input
                  value={resource}
                  onChange={(e) => setResource(e.target.value)}
                  placeholder="例如 docs/requirements.md"
                />
              </label>
            </div>
            <label>
              输入内容
              <textarea
                rows={9}
                required
                value={content}
                onChange={(e) => setContent(e.target.value)}
                placeholder="粘贴需要检测的外部内容…"
              />
            </label>
            {session.sources.length > 0 && (
              <label>
                上游来源（可选）
                <select
                  value={parentSource}
                  onChange={(e) => setParentSource(e.target.value)}
                >
                  <option value="">独立来源</option>
                  {session.sources.map((s) => (
                    <option key={s.id} value={s.id}>
                      {sourceNames[s.type]} · {s.resource || short(s.id)}
                    </option>
                  ))}
                </select>
              </label>
            )}
            <div className="info-box small">
              <Eye size={16} />
              <p>
                内容在进入智能体上下文前扫描，检测结果会保留来源与字符级证据。
              </p>
            </div>
          </>
        ) : (
          <>
            <label>
              工具名称
              <input
                required
                value={tool}
                onChange={(e) => setTool(e.target.value)}
                list="supported-tools"
              />
              <datalist id="supported-tools">
                {[
                  "fs.read",
                  "fs.write",
                  "net.fetch",
                  "exec",
                  "git.commit",
                  "git.push",
                  "agent.delegate",
                ].map((t) => (
                  <option key={t} value={t} />
                ))}
              </datalist>
            </label>
            <label>
              参数 JSON
              <textarea
                rows={6}
                className="code-input"
                required
                spellCheck={false}
                value={args}
                onChange={(e) => setArgs(e.target.value)}
              />
            </label>
            <label>
              执行计划 / 调用目的
              <textarea
                rows={2}
                value={plan}
                onChange={(e) => setPlan(e.target.value)}
                placeholder="说明此调用如何完成原始任务"
              />
            </label>
            <fieldset>
              <legend>关联输入来源</legend>
              {session.sources.length ? (
                <div className="source-checkboxes">
                  {session.sources.map((s) => (
                    <label key={s.id}>
                      <input
                        type="checkbox"
                        checked={sourceIds.includes(s.id)}
                        onChange={(e) =>
                          setSourceIds(
                            e.target.checked
                              ? [...sourceIds, s.id]
                              : sourceIds.filter((id) => id !== s.id),
                          )
                        }
                      />
                      <span>
                        {sourceNames[s.type]} · {s.resource || short(s.id)}
                      </span>
                      <Badge decision={s.decision} />
                    </label>
                  ))}
                </div>
              ) : (
                <p className="muted-text">暂无输入来源，可先登记后建立关联。</p>
              )}
            </fieldset>
            <details className="advanced-form">
              <summary>智能体与调用链设置（可选）</summary>
              <div className="form-grid">
                <label>
                  执行智能体
                  <input
                    required
                    maxLength={120}
                    value={agent}
                    onChange={(e) => setAgent(e.target.value)}
                  />
                </label>
                <label>
                  MCP 服务标识
                  <input
                    maxLength={200}
                    value={server}
                    onChange={(e) => setServer(e.target.value)}
                  />
                </label>
              </div>
              <label>
                父调用
                <select
                  value={parentCall}
                  onChange={(e) => setParentCall(e.target.value)}
                >
                  <option value="">无父调用</option>
                  {session.calls.map((c) => (
                    <option key={c.id} value={c.id}>
                      {c.tool} · {short(c.id)}
                    </option>
                  ))}
                </select>
              </label>
            </details>
            <div className="info-box small">
              <Shield size={16} />
              <p>此操作只执行审查。通过后，可在调用详情中单独执行受控工具。</p>
            </div>
          </>
        )}
        {error && <ErrorBox error={error} />}
        <div className="form-actions">
          <Button onClick={onClose}>取消</Button>
          <Button variant="primary" type="submit" disabled={busy}>
            {busy && <Loader2 className="spin" size={15} />}提交
            {kind === "source" ? "检测" : "审查"}
          </Button>
        </div>
      </form>
    </Modal>
  );
}
function SourceDetail({ source }: { source: Source }) {
  const [normalized, setNormalized] = useState(false);
  const [findingIndex, setFindingIndex] = useState(0);
  const text = normalized ? source.normalized : source.content;
  const findings = source.detection.findings;
  const activeFinding = findings[findingIndex];
  const highlight =
    !normalized || source.content === source.normalized ? findings : [];
  return (
    <div className="form-body">
      <div className="source-detail-header">
        <span className="source-type">
          <FileText size={15} />
          {sourceNames[source.type] || source.type}
        </span>
        <Badge decision={source.decision} />
        <span className="quiet-tag">
          风险分数 {source.detection.risk_score}
        </span>
      </div>
      <div className="source-location">
        <strong>资源位置</strong>
        <span>{source.resource || "未提供"}</span>
        <strong>来源版本</strong>
        <span>v{source.version}</span>
      </div>
      <div className="segmented">
        <button
          className={!normalized ? "active" : ""}
          onClick={() => setNormalized(false)}
        >
          原始输入与证据
        </button>
        <button
          className={normalized ? "active" : ""}
          onClick={() => setNormalized(true)}
        >
          规范化内容
        </button>
      </div>
      <pre className="source-text">
        <HighlightedText text={text} findings={highlight} />
      </pre>
      <p className="caption">位置单位：Unicode 字符 · 区间 [start, end)</p>
      {findings.length > 1 && (
        <label>
          定位证据范围
          <select
            value={findingIndex}
            onChange={(event) => setFindingIndex(Number(event.target.value))}
          >
            {findings.map((finding, index) => (
              <option key={index} value={index}>
                {index + 1}. {finding.category} [{finding.start}, {finding.end})
              </option>
            ))}
          </select>
        </label>
      )}
      <TokenEvidence
        key={`${source.id}-${findingIndex}`}
        sourceId={source.id}
        start={activeFinding?.start ?? 0}
        end={
          (activeFinding?.end || 0) > (activeFinding?.start || 0)
            ? activeFinding.end
            : Math.min(Array.from(source.content).length, 512)
        }
      />
      <div className="findings">
        {findings.length ? (
          findings.map((f, i) => (
            <div className="finding" key={i}>
              <div>
                <ShieldAlert size={16} />
                <strong>{f.category}</strong>
                <code>{f.rule_id}</code>
                <span>
                  [{f.start}, {f.end})
                </span>
              </div>
              <blockquote>{f.quote}</blockquote>
              <p>{f.reason}</p>
              {f.linked_spans && (
                <details>
                  <summary>联合研判引用</summary>
                  {f.linked_spans.map((s, j) => (
                    <p key={j}>
                      <code>
                        {s.source_id} [{s.start}, {s.end})
                      </code>
                      {s.quote && <span> · {s.quote}</span>}
                    </p>
                  ))}
                </details>
              )}
            </div>
          ))
        ) : (
          <div className="info-box">
            <CheckCircle2 size={18} />
            <p>未命中注入规则</p>
          </div>
        )}
      </div>
      {source.detection.information_gaps.length > 0 && (
        <div className="warning-box">
          <TriangleAlert size={17} />
          <p>{source.detection.information_gaps.join("；")}</p>
        </div>
      )}
      <p className="caption">
        扫描覆盖 {source.detection.coverage.checked_chars} /{" "}
        {source.detection.coverage.total_chars} 字符 · 检测模式{" "}
        {source.detection.mode}
        {source.detection.coverage.model_checked_chars !== undefined &&
          ` · 模型覆盖 ${source.detection.coverage.model_checked_chars} 字符`}
        {source.detection.coverage.global_review &&
          ` · 全文联合审查${source.detection.coverage.global_review.complete ? "完成" : "存在缺口"}`}
        {source.detection.coverage.session_correlation &&
          ` · 跨来源联合审查${source.detection.coverage.session_correlation.complete ? "完成" : "存在缺口"}`}
      </p>
    </div>
  );
}
function CausalGraph({
  graph,
  onInspect,
}: {
  graph: Graph;
  onInspect?: (id: string) => void;
}) {
  const [selected, setSelected] = useState<string | null>(null);
  if (!graph.nodes.length)
    return (
      <Empty
        title="暂无传播关系"
        detail="登记来源和调用后可查看明确记录的关联。"
      />
    );
  const typeOrder = [
    "session",
    "task",
    "source",
    "memory",
    "agent",
    "mcp",
    "call",
    "tool_call",
    "decision",
    "child_agent",
    "execution",
    "receipt",
  ];
  const types = Array.from(new Set(graph.nodes.map((n) => n.type))).sort(
    (a, b) => typeOrder.indexOf(a) - typeOrder.indexOf(b),
  );
  const groups = types.map((t) => graph.nodes.filter((n) => n.type === t));
  const width = Math.max(760, types.length * 230 + 40),
    height = Math.max(250, Math.max(...groups.map((g) => g.length)) * 86 + 75);
  const positions = new Map(
    graph.nodes.map((n) => {
      const col = types.indexOf(n.type),
        row = groups[col].indexOf(n);
      return [n.id, { x: 35 + col * 230, y: 60 + row * 86 }];
    }),
  );
  const node = graph.nodes.find((n) => n.id === selected);
  return (
    <div className="graph-area">
      <div className="graph-edge-legend">
        <span>
          <i />
          溯源 / 结果 / 父子调用
        </span>
        <span>
          <i className="dashed" />
          归属 / 上下文 / 候选目标
        </span>
      </div>
      <div className="graph-scroll">
        <svg
          viewBox={`0 0 ${width} ${height}`}
          className="relationship-graph"
          style={{ width, minWidth: width }}
          preserveAspectRatio="xMinYMin meet"
          role="group"
          aria-label="会话传播关系图"
        >
          <defs>
            <marker
              id="arrow"
              markerWidth="7"
              markerHeight="7"
              refX="6"
              refY="3.5"
              orient="auto"
            >
              <path d="M0,0 L7,3.5 L0,7" fill="#9b9d98" />
            </marker>
          </defs>
          {types.map((t, i) => (
            <text key={t} x={35 + i * 230} y={23} fill="#71736d" fontSize="11">
              {(
                {
                  session: "任务会话",
                  task: "原始任务",
                  source: "输入来源",
                  memory: "记忆记录",
                  agent: "智能体上下文",
                  mcp: "MCP 服务上下文",
                  call: "工具调用",
                  tool_call: "工具调用",
                  decision: "审查决策",
                  child_agent: "候选子智能体",
                  execution: "受控执行",
                  receipt: "执行回执",
                } as Record<string, string>
              )[t] || t}
            </text>
          ))}
          {graph.edges.map((e, i) => {
            const a = positions.get(e.source),
              b = positions.get(e.target);
            if (!a || !b) return null;
            const d =
              a.x === b.x
                ? `M${a.x + 170},${a.y + 24} C${a.x + 220},${a.y + 24} ${b.x + 220},${b.y + 24} ${b.x + 170},${b.y + 24}`
                : b.x < a.x
                  ? `M${a.x},${a.y + 24} C${a.x - 33},${a.y + 24} ${b.x + 203},${b.y + 24} ${b.x + 170},${b.y + 24}`
                  : `M${a.x + 170},${a.y + 24} C${a.x + 203},${a.y + 24} ${b.x - 33},${b.y + 24} ${b.x},${b.y + 24}`;
            const contextual = ["membership", "context", "target"].includes(
              e.type || "",
            );
            return (
              <g key={i}>
                <path
                  d={d}
                  fill="none"
                  stroke={contextual ? "#c5c6c1" : "#94978f"}
                  strokeWidth="1.4"
                  strokeDasharray={contextual ? "4 4" : undefined}
                  markerEnd="url(#arrow)"
                />
                <title>{e.label}</title>
              </g>
            );
          })}
          {graph.nodes.map((n) => {
            const p = positions.get(n.id)!;
            const blocked =
              n.status === "block" ||
              n.status === "blocked" ||
              n.status === "quarantined";
            return (
              <g
                key={n.id}
                className="graph-node"
                role="button"
                tabIndex={0}
                aria-label={`查看节点 ${n.label}`}
                onClick={() => {
                  setSelected(n.id);
                  onInspect?.(n.id);
                }}
                onKeyDown={(e) => {
                  if (e.key === "Enter" || e.key === " ") {
                    e.preventDefault();
                    setSelected(n.id);
                    onInspect?.(n.id);
                  }
                }}
              >
                <rect
                  x={p.x}
                  y={p.y}
                  width="170"
                  height="48"
                  rx="7"
                  fill={
                    selected === n.id
                      ? "#eef3ff"
                      : blocked
                        ? "#fff2f2"
                        : "white"
                  }
                  stroke={
                    blocked
                      ? "#efb5b6"
                      : selected === n.id
                        ? "#315bd6"
                        : "#deded8"
                  }
                />
                <circle
                  cx={p.x + 14}
                  cy={p.y + 24}
                  r="4"
                  fill={blocked ? "#db6770" : "#67736a"}
                />
                <foreignObject
                  x={p.x + 26}
                  y={p.y + 8}
                  width="132"
                  height="17"
                  pointerEvents="none"
                >
                  <div
                    style={{
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                      fontSize: "11px",
                      lineHeight: "17px",
                      color: "#30322f",
                    }}
                  >
                    {n.label}
                  </div>
                </foreignObject>
                <text x={p.x + 26} y={p.y + 36} fontSize="9" fill="#899c9f">
                  {short(n.id)}
                </text>
                <title>{n.label}</title>
              </g>
            );
          })}
        </svg>
      </div>
      {node && (
        <div className="graph-inspector">
          <div>
            <strong>{node.label}</strong>
            <span>
              {node.type} · {node.status || "已记录"}
            </span>
          </div>
          <p>{node.detail || node.id}</p>
        </div>
      )}
    </div>
  );
}

function PolicyCenter({ tick, notify }: { tick: number; notify: ToastFn }) {
  const { data, error, loading, refresh } = useResource<Policies>(
    "/policies",
    tick,
  );
  const [draft, setDraft] = useState("");
  const [baseVersion, setBaseVersion] = useState(0);
  const [busy, setBusy] = useState(false);
  const [validation, setValidation] = useState("");
  const [editing, setEditing] = useState(false);
  useEffect(() => {
    if (data && !editing) {
      setDraft(JSON.stringify(data.rules, null, 2));
      setBaseVersion(data.version);
    }
  }, [data, editing]);
  const validate = () => {
    const rules = JSON.parse(draft);
    if (!Array.isArray(rules)) throw new Error("策略必须是规则数组。");
    for (const rule of data?.rules.filter((r) => r.mandatory) || []) {
      const updated = rules.find((r: { id: string }) => r.id === rule.id);
      if (!updated || JSON.stringify(updated) !== JSON.stringify(rule))
        throw new Error(`强制规则 ${rule.id} 不可删除或修改。`);
    }
    for (const rule of rules) {
      if (
        !rule.id ||
        !rule.name ||
        !["allow", "confirm", "block"].includes(rule.action) ||
        typeof rule.enabled !== "boolean" ||
        typeof rule.priority !== "number" ||
        !rule.condition
      )
        throw new Error(
          "规则需包含 id、name、enabled、priority、condition 与有效 action。",
        );
    }
    return rules;
  };
  const save = async () => {
    setBusy(true);
    setValidation("");
    try {
      const rules = validate();
      const result = await api<Policies>("/policies", {
        method: "PUT",
        body: JSON.stringify({ version: baseVersion, rules }),
      });
      setEditing(false);
      setDraft(JSON.stringify(result.rules, null, 2));
      setBaseVersion(result.version);
      refresh();
      notify(`策略已保存为 v${result.version}`);
    } catch (e) {
      setValidation((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <>
      <PageTitle
        title="策略中心"
        action={
          data && (
            <span className="version-pill">
              <GitBranch size={14} />
              当前生效 v{data.version}
            </span>
          )
        }
      />
      {error && <ErrorBox error={error} retry={refresh} />}{" "}
      {loading && !data ? (
        <Loading />
      ) : (
        data && (
          <div className="policy-layout">
            <section className="card policy-catalog">
              <SectionTitle
                icon={Shield}
                title="生效规则"
                subtitle={`${data.rules.length} 条规则 · ${data.rules.filter((r) => r.mandatory).length} 条强制边界`}
              />
              <div>
                {data.rules.map((rule) => (
                  <div className="policy-rule" key={rule.id}>
                    <div className="policy-rule-top">
                      <span
                        className={`rule-dot ${rule.enabled ? "enabled" : ""}`}
                      />
                      <strong>{rule.name}</strong>
                      {rule.mandatory && <LockKeyhole size={13} />}
                    </div>
                    <p>{rule.description}</p>
                    <div>
                      <code>{rule.id}</code>
                      <Badge decision={rule.action} />
                    </div>
                    <small>
                      优先级 {rule.priority} ·{" "}
                      {rule.mandatory ? "强制规则" : "可配置规则"} ·{" "}
                      {rule.enabled ? "启用" : "停用"}
                    </small>
                  </div>
                ))}
              </div>
            </section>
            <section className="card policy-editor">
              <SectionTitle
                icon={FileJson2}
                title="策略 DSL 编辑器"
                action={<span className="quiet-tag">JSON · rules[]</span>}
              />
              <div className="info-box small">
                <LockKeyhole size={17} />
                <p>强制规则不可修改或禁用。</p>
              </div>
              <label className="sr-only" htmlFor="policy-json">
                策略 JSON
              </label>
              <textarea
                id="policy-json"
                className="code-input policy-textarea"
                spellCheck={false}
                value={draft}
                onChange={(e) => {
                  setDraft(e.target.value);
                  setEditing(true);
                  setValidation("");
                }}
              />
              {validation && <ErrorBox error={validation} />}
              <div className="editor-toolbar">
                <span>
                  <span className={`dot ${editing ? "amber-dot" : "green"}`} />
                  {editing ? "有未保存修改" : `与 v${baseVersion} 保持一致`}
                </span>
                <Button
                  disabled={busy}
                  onClick={() => {
                    try {
                      validate();
                      setValidation("");
                      notify(
                        "JSON 结构与强制规则检查通过；保存时进行完整语义校验。",
                      );
                    } catch (e) {
                      setValidation((e as Error).message);
                    }
                  }}
                >
                  <Check size={14} />
                  校验
                </Button>
                <Button
                  disabled={busy}
                  onClick={() => {
                    setEditing(false);
                    setValidation("");
                    refresh();
                  }}
                >
                  <RefreshCw size={14} />
                  重新加载
                </Button>
                <Button
                  variant="primary"
                  disabled={busy || !editing}
                  onClick={save}
                >
                  {busy ? (
                    <Loader2 className="spin" size={14} />
                  ) : (
                    <CheckCircle2 size={14} />
                  )}
                  保存策略
                </Button>
              </div>
            </section>
          </div>
        )
      )}
    </>
  );
}

function Memories({
  tick,
  nav,
  notify,
}: {
  tick: number;
  nav: (path: string) => void;
  notify: ToastFn;
}) {
  const { data, error, loading, refresh } = useResource<Memory[]>(
    "/memories",
    tick,
  );
  const sessions = useResource<Session[]>("/sessions", tick);
  const [create, setCreate] = useState(false);
  const [label, setLabel] = useState("");
  const [content, setContent] = useState("");
  const [session, setSession] = useState("");
  const [busy, setBusy] = useState("");
  const [target, setTarget] = useState<Memory | null>(null);
  const [filter, setFilter] = useState("all");
  const write = async (e: FormEvent) => {
    e.preventDefault();
    setBusy("write");
    try {
      const result = await post<Memory>("/memories", {
        session_id: session,
        content,
        label,
      });
      notify(
        result.status === "quarantined"
          ? "已检测到污染风险，记忆已隔离。"
          : "记忆已通过检测并保存。",
      );
      setCreate(false);
      setContent("");
      setLabel("");
      refresh();
    } catch (e) {
      notify((e as Error).message, "error");
    } finally {
      setBusy("");
    }
  };
  const scan = async (m: Memory) => {
    setBusy(m.id);
    try {
      const result = await post<Memory>(`/memories/${m.id}/scan`);
      notify(
        `复检完成：${result.status === "quarantined" ? "保持隔离" : "可用"}`,
      );
      refresh();
    } catch (e) {
      notify((e as Error).message, "error");
    } finally {
      setBusy("");
    }
  };
  const load = async () => {
    if (!target || !session) return;
    setBusy(target.id);
    try {
      const result = await post<Source>(
        `/sessions/${session}/memory/${target.id}`,
      );
      notify(`已完成读取审查：${decisionNames[result.decision]}`);
      setTarget(null);
      nav(`sessions/${session}`);
    } catch (e) {
      notify((e as Error).message, "error");
    } finally {
      setBusy("");
    }
  };
  const filtered = (data || []).filter(
    (m) => filter === "all" || m.status === filter,
  );
  return (
    <>
      <PageTitle
        title="记忆防护"
        action={
          <Button
            variant="primary"
            onClick={() => {
              setSession(sessions.data?.[0]?.id || "");
              setCreate(true);
            }}
          >
            <Plus size={15} />
            写入记忆
          </Button>
        }
      />
      <div className="memory-stats">
        <div>
          <Database size={21} />
          <span>
            记忆总量<strong>{data?.length || 0}</strong>
          </span>
        </div>
        <div>
          <ShieldCheck size={21} />
          <span>
            可用记忆
            <strong>
              {data?.filter((m) => m.status === "active").length || 0}
            </strong>
          </span>
        </div>
        <div>
          <ShieldAlert size={21} />
          <span>
            已隔离污染
            <strong>
              {data?.filter((m) => m.status === "quarantined").length || 0}
            </strong>
          </span>
        </div>
      </div>
      <section className="card memory-library">
        <div className="table-toolbar">
          <SectionTitle icon={BookOpen} title="记忆库" />
          <Button
            disabled={!!busy || !data?.length}
            onClick={async () => {
              setBusy("scan-all");
              try {
                const result = await post<{ total: number }>(
                  "/memories/scan-all",
                );
                notify(`存量记忆复检完成：${result.total} 条`);
                refresh();
              } catch (e) {
                notify((e as Error).message, "error");
              } finally {
                setBusy("");
              }
            }}
          >
            {busy === "scan-all" ? (
              <Loader2 className="spin" size={14} />
            ) : (
              <RefreshCw size={14} />
            )}
            全库存量复检
          </Button>
          <div className="segmented compact">
            {[
              { id: "all", name: "全部" },
              { id: "active", name: "可用" },
              { id: "quarantined", name: "已隔离" },
            ].map((f) => (
              <button
                key={f.id}
                className={filter === f.id ? "active" : ""}
                onClick={() => setFilter(f.id)}
              >
                {f.name}
              </button>
            ))}
          </div>
        </div>
        {error ? (
          <ErrorBox error={error} retry={refresh} />
        ) : loading && !data ? (
          <Loading />
        ) : !filtered.length ? (
          <Empty title="暂无符合条件的记忆" />
        ) : (
          <div className="memory-grid">
            {filtered.map((m) => (
              <article className={`memory-card ${m.status}`} key={m.id}>
                <div className="memory-card-top">
                  <span className="memory-symbol">
                    <Database size={19} />
                  </span>
                  <div>
                    <h3>{m.label || "未命名记忆"}</h3>
                    <small>
                      v{m.version} · {time(m.created_at, true)}
                    </small>
                  </div>
                  <span className={`memory-status ${m.status}`}>
                    {m.status === "active" ? "可用" : "已隔离"}
                  </span>
                </div>
                <p className="memory-content">{m.content}</p>
                {m.detection.findings.length > 0 && (
                  <div className="memory-findings">
                    <ShieldAlert size={14} />
                    {m.detection.findings.map((f) => f.reason).join("；")}
                  </div>
                )}
                <div className="memory-provenance">
                  <Link2 size={13} />
                  <button
                    onClick={() => nav(`sessions/${m.source_session_id}`)}
                  >
                    来源会话 {short(m.source_session_id)}
                  </button>
                  <span>风险 {m.detection.risk_score}</span>
                </div>
                <MemoryControl
                  key={`${m.id}-${m.version}`}
                  memory={m}
                  refresh={refresh}
                  notify={notify}
                />
                <div className="memory-actions">
                  <Button disabled={!!busy} onClick={() => scan(m)}>
                    {busy === m.id ? (
                      <Loader2 className="spin" size={14} />
                    ) : (
                      <RefreshCw size={14} />
                    )}
                    重新检测
                  </Button>
                  <Button
                    disabled={
                      m.status === "quarantined" ||
                      !!busy ||
                      !sessions.data?.length
                    }
                    onClick={() => {
                      setTarget(m);
                      setSession(sessions.data?.[0]?.id || "");
                    }}
                  >
                    <ArrowRight size={14} />
                    载入会话
                  </Button>
                </div>
              </article>
            ))}
          </div>
        )}
      </section>
      {(create || target) && (
        <Modal
          title={create ? "写入长期记忆" : "读取记忆并载入会话"}
          onClose={() => {
            setCreate(false);
            setTarget(null);
          }}
        >
          <form
            className="form-body"
            onSubmit={(e) => {
              if (create) void write(e);
              else {
                e.preventDefault();
                void load();
              }
            }}
          >
            {sessions.error && (
              <ErrorBox error={sessions.error} retry={sessions.refresh} />
            )}
            <label>
              {create ? "来源会话" : "目标会话"}
              <select
                required
                value={session}
                onChange={(e) => setSession(e.target.value)}
              >
                <option value="">选择任务会话</option>
                {sessions.data?.map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.title}
                  </option>
                ))}
              </select>
            </label>
            {!sessions.data?.length && (
              <p className="caption">
                需要先运行任务，或在「溯源复盘」中登记审查会话。
              </p>
            )}
            {create ? (
              <>
                <label>
                  记忆名称
                  <input
                    value={label}
                    onChange={(e) => setLabel(e.target.value)}
                    placeholder="例如：项目工作规范"
                  />
                </label>
                <label>
                  记忆内容
                  <textarea
                    required
                    rows={7}
                    value={content}
                    onChange={(e) => setContent(e.target.value)}
                    placeholder="填写待保存的长期记忆…"
                  />
                </label>
              </>
            ) : (
              <div className="info-box">
                <ShieldCheck size={18} />
                <p>
                  读取时将再次审查内容及当前策略。被隔离或无法通过审查的记忆不可载入。
                </p>
              </div>
            )}
            <div className="form-actions">
              <Button
                onClick={() => {
                  setCreate(false);
                  setTarget(null);
                }}
              >
                取消
              </Button>
              <Button
                variant="primary"
                type="submit"
                disabled={!!busy || !session}
              >
                {busy && <Loader2 className="spin" size={14} />}{" "}
                {create ? "检测并写入" : "审查并载入"}
              </Button>
            </div>
          </form>
        </Modal>
      )}
    </>
  );
}

function Evaluations({
  tick,
  nav,
  notify,
}: {
  tick: number;
  nav: (path: string) => void;
  notify: ToastFn;
}) {
  const { data, error, loading, refresh } = useResource<Evaluation[]>(
    "/evaluations",
    tick,
  );
  const scenarios = useResource<Scenario[]>("/scenarios", tick);
  const [selected, setSelected] = useState("");
  const [historyExpanded, setHistoryExpanded] = useState(false);
  const [running, setRunning] = useState(false);
  const [runError, setRunError] = useState("");
  const report = data?.find((e) => e.id === selected) || data?.[0];
  const run = async () => {
    setRunning(true);
    setRunError("");
    try {
      const result = await post<Evaluation>("/evaluations/run");
      setSelected(result.id);
      setHistoryExpanded(true);
      refresh();
      notify(
        `评测完成：${result.passed} / ${result.total} 个场景通过。`,
        result.failed ? "error" : "success",
      );
    } catch (e) {
      setRunError((e as Error).message);
    } finally {
      setRunning(false);
    }
  };
  return (
    <>
      <PageTitle
        title="评测报告"
        action={
          <Button variant="primary" disabled={running} onClick={run}>
            {running ? (
              <Loader2 className="spin" size={16} />
            ) : (
              <Play size={16} />
            )}{" "}
            {running ? "正在验证场景…" : "运行场景验证"}
          </Button>
        }
      />
      <CampaignReports tick={tick} />
      {runError && <ErrorBox error={runError} retry={run} />}
      <details
        className="evaluation-history"
        open={historyExpanded}
        onToggle={(event) => setHistoryExpanded(event.currentTarget.open)}
      >
        <summary>历史评测与专项报告</summary>
        {historyExpanded && (
          <div className="evaluation-history-body">
            <PromptfooReports tick={tick} />
            <AgentComparisonReports tick={tick} />
            {error && <ErrorBox error={error} retry={refresh} />}{" "}
            {loading && !data ? (
              <Loading />
            ) : !report ? (
              <section className="card">
                <Empty
                  title="还没有评测报告"
                  detail="运行全量评测，将生成逐场景断言、运行耗时与可追溯会话。"
                  action={
                    <Button variant="primary" disabled={running} onClick={run}>
                      <Play size={15} />
                      开始首次评测
                    </Button>
                  }
                />
              </section>
            ) : (
              <>
                <div className="report-header">
                  <div className="select-field">
                    <FileText size={16} />
                    <select
                      value={report.id}
                      onChange={(e) => setSelected(e.target.value)}
                      aria-label="选择评测报告"
                    >
                      {data?.map((e) => (
                        <option key={e.id} value={e.id}>
                          {time(e.created_at, true)} · {e.passed}/{e.total}{" "}
                          场景通过
                        </option>
                      ))}
                    </select>
                    <ChevronDown size={14} />
                  </div>
                  <span className="quiet-tag">{report.mode}</span>
                  <Button
                    onClick={() => {
                      downloadJSON(
                        report,
                        `智行安盾-评测报告-${report.id}.json`,
                      );
                      notify("评测报告已导出");
                    }}
                  >
                    <ArrowDownToLine size={15} />
                    导出报告 JSON
                  </Button>
                </div>
                <div className="evaluation-summary">
                  <div className="evaluation-main">
                    <div
                      className={`evaluation-ring ${report.failed ? "has-fail" : ""}`}
                    >
                      <strong>
                        {report.total
                          ? Math.round((report.passed / report.total) * 100)
                          : 0}
                        <small>%</small>
                      </strong>
                      <span>场景通过率</span>
                    </div>
                    <div>
                      <h2>
                        {report.failed
                          ? "存在需要检查的场景"
                          : "全部场景验证通过"}
                      </h2>
                      <p>
                        评测 {report.total} 个场景 · 运行耗时{" "}
                        {(report.duration_ms / 1000).toFixed(2)} s
                      </p>
                      <small>
                        {time(report.created_at, true)} · {short(report.id)}
                      </small>
                    </div>
                  </div>
                  <div className="evaluation-numbers">
                    <div>
                      <CheckCircle2 size={22} />
                      <strong>{report.passed}</strong>
                      <span>通过场景</span>
                    </div>
                    <div>
                      <XCircle size={22} />
                      <strong>{report.failed}</strong>
                      <span>失败场景</span>
                    </div>
                  </div>
                </div>
                <section className="card">
                  <SectionTitle icon={ClipboardCheck} title="场景验证明细" />
                  <div className="evaluation-results">
                    {report.results.map((r, i) => (
                      <details
                        key={`${r.scenario_id}-${i}`}
                        className="evaluation-result"
                      >
                        <summary>
                          <span className="evaluation-index">
                            {String(i + 1).padStart(2, "0")}
                          </span>
                          <div>
                            <strong>
                              {scenarios.data?.find(
                                (s) => s.id === r.scenario_id,
                              )?.name || r.scenario_id}
                            </strong>
                            <small>
                              {r.assertions.length} 项断言 ·{" "}
                              {r.duration_ms.toFixed(1)} ms
                            </small>
                          </div>
                          <span
                            className={`test-tag ${r.passed ? "pass" : "fail"}`}
                          >
                            {r.passed ? "PASS" : "FAIL"}
                          </span>
                          <ChevronDown size={17} />
                        </summary>
                        <div className="assertions">
                          {r.assertions.map((a, j) => (
                            <div className="assertion" key={j}>
                              {a.passed ? (
                                <CheckCircle2 size={17} className="text-teal" />
                              ) : (
                                <XCircle size={17} className="text-red" />
                              )}
                              <div>
                                <strong>{a.name}</strong>
                                <p>{a.detail}</p>
                              </div>
                            </div>
                          ))}
                          <Button
                            onClick={() => nav(`sessions/${r.session_id}`)}
                          >
                            追溯完整会话
                            <ArrowRight size={14} />
                          </Button>
                        </div>
                      </details>
                    ))}
                  </div>
                </section>
              </>
            )}
          </div>
        )}
      </details>
    </>
  );
}
