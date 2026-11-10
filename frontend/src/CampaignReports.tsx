import { useState } from "react";
import { ChevronDown, Clock3, RefreshCw } from "lucide-react";
import { useResource } from "./hooks/useResource";
import "./campaign-reports.css";

type Metrics = {
  cases: number;
  attacks: number;
  benign: number;
  tp: number;
  fn: number;
  fp: number;
  tn: number;
  confirmed_tp?: number;
  strict_passed: number;
  strict_pass_rate?: number | null;
  confirmed_recall?: number | null;
  withhold_recall?: number | null;
  fpr?: number | null;
  incomplete?: number;
  unavailable?: number;
  latency_ms?: { p50?: number; p95?: number; p99?: number; max?: number };
  usage?: {
    attempts?: number;
    failed_attempts?: number;
    known_tokens?: number;
    missing_usage_attempts?: number;
  };
};

type Campaign = {
  id: string;
  completed_at: string;
  created_at: string;
  time_basis: "execution_finished_at" | "summary_created_at";
  source_digest?: string;
  source_unchanged?: boolean;
  current_code_matches: boolean | null;
  source_path: string;
  failure_index_path?: string | null;
  matrix: Metrics;
  cohorts: (Metrics & { name: string })[];
  by_source: (Metrics & { source_type: string })[];
  by_category: (Metrics & { test_category: string })[];
  failure_counts: {
    content: number;
    workflow: number;
    engineering: number;
    total: number;
    by_kind?: Record<string, number>;
  };
  recovery?: {
    total: number;
    passed: number;
    reports_completed: number;
    reports_expected?: number;
    safe_stops: number;
    safe_stops_expected?: number;
    tool_calls: number;
    business_requests: number;
  } | null;
};

type CampaignResponse = {
  available: boolean;
  latest_id: string | null;
  total_count: number;
  invalid_count: number;
  truncated: boolean;
  reports: Campaign[];
  errors: { id: string; reason: string }[];
};

const sourceNames: Record<string, string> = {
  user_input: "用户输入",
  document: "文档",
  web: "网页",
  email: "邮件",
  code: "代码",
  issue: "工单 / Issue",
  mcp_description: "MCP 工具描述",
  mcp_result: "MCP 返回",
  memory: "记忆",
  tool_result: "工具返回",
};
const cohortNames: Record<string, string> = {
  stable240: "稳定样本",
  external480: "公开外部样本",
  new480: "新增样本",
};
const failureNames: Record<string, string> = {
  false_negative: "漏报",
  false_positive: "误报",
  incomplete_or_unavailable: "检查不完整 / 不可用",
  workflow_check_failed: "工作流检查失败",
};
const count = (value?: number | null) =>
  typeof value === "number" && Number.isFinite(value)
    ? value.toLocaleString("zh-CN")
    : "—";
const percent = (value?: number | null) =>
  typeof value === "number" && Number.isFinite(value)
    ? `${(value * 100).toFixed(2)}%`
    : "—";
const duration = (value?: number) =>
  typeof value === "number" && Number.isFinite(value)
    ? `${(value / 1000).toFixed(2)} s`
    : "—";
function timestamp(value: string) {
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime())
    ? value || "未记录"
    : parsed.toLocaleString("zh-CN", { hour12: false });
}

function Breakdown({
  title,
  rows,
}: {
  title: string;
  rows: (Metrics & { label: string })[];
}) {
  if (!rows.length) return null;
  return (
    <details className="campaign-breakdown">
      <summary>
        <span>
          {title}
          <small>{rows.length} 类</small>
        </span>
        <ChevronDown size={16} aria-hidden="true" />
      </summary>
      <div
        className="campaign-table-scroll"
        tabIndex={0}
        role="region"
        aria-label={`${title}数据表`}
      >
        <table>
          <thead>
            <tr>
              <th>类别</th>
              <th>样本</th>
              <th>攻击 / 正常</th>
              <th>严格通过</th>
              <th>未通过</th>
              <th>确认检出率</th>
              <th>暂扣召回率</th>
              <th>误报率</th>
              <th>P95</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={row.label}>
                <th scope="row">{row.label}</th>
                <td>{count(row.cases)}</td>
                <td>
                  {count(row.attacks)} / {count(row.benign)}
                </td>
                <td>{count(row.strict_passed)}</td>
                <td
                  className={
                    row.cases > row.strict_passed
                      ? "campaign-failure-value"
                      : ""
                  }
                >
                  {count(row.cases - row.strict_passed)}
                </td>
                <td>{percent(row.confirmed_recall)}</td>
                <td>{percent(row.withhold_recall)}</td>
                <td>{percent(row.fpr)}</td>
                <td>{duration(row.latency_ms?.p95)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </details>
  );
}

export default function CampaignReports({ tick }: { tick: number }) {
  const resource = useResource<CampaignResponse>(
    "/evaluations/campaigns",
    tick,
  );
  const [selection, setSelection] = useState("");
  const reports = resource.data?.reports || [];
  const selected = reports.find(
    (report) => report.id === (selection || resource.data?.latest_id),
  );
  const matrix = selected?.matrix;
  const recovery = selected?.recovery;

  return (
    <section className="campaign-reports" aria-labelledby="campaign-title">
      <header className="campaign-heading">
        <div>
          <h2 id="campaign-title">评测记录</h2>
          <p>内容检测与任务恢复</p>
        </div>
        <div className="campaign-actions">
          <label>
            <span className="campaign-select-label">报告</span>
            <select
              aria-label="选择内容评测报告"
              value={selection}
              onChange={(event) => setSelection(event.target.value)}
              disabled={resource.loading || !!resource.error || !reports.length}
            >
              <option value="">最新评测</option>
              {reports.map((report) => (
                <option key={report.id} value={report.id}>
                  {timestamp(report.completed_at)} ·{" "}
                  {count(report.matrix.cases)} 条 · {report.id}
                </option>
              ))}
            </select>
          </label>
          <button
            className="button"
            onClick={resource.refresh}
            disabled={resource.loading}
          >
            <RefreshCw size={15} className={resource.loading ? "spin" : ""} />
            刷新
          </button>
        </div>
      </header>

      {resource.error && (
        <div className="campaign-notice error" role="alert">
          {resource.error}
        </div>
      )}
      {!resource.error && !resource.data && (
        <p className="campaign-empty" role="status">
          正在读取评测记录…
        </p>
      )}
      {!resource.error && resource.data && !reports.length && (
        <p className="campaign-empty">暂无可读取的评测记录</p>
      )}
      {!resource.error && reports.length > 0 && !selected && (
        <p className="campaign-empty">所选报告已不可用，请重新选择。</p>
      )}

      {!resource.error && selected && matrix && (
        <div key={selected.id} className="campaign-content">
          <div className="campaign-record">
            <div className="campaign-record-title">
              <strong>{selected.id}</strong>
              <span className="campaign-badge">
                {selected.id === resource.data?.latest_id
                  ? "最新记录"
                  : "历史记录"}
              </span>
              <span className="campaign-badge neutral">
                {selected.current_code_matches === true
                  ? "源码版本一致"
                  : selected.current_code_matches === false
                    ? "与当前版本不同"
                    : "当前版本未核验"}
              </span>
            </div>
            <p>
              <Clock3 size={14} aria-hidden="true" />
              {selected.time_basis === "execution_finished_at"
                ? "测试完成"
                : "汇总生成"}
              <time dateTime={selected.completed_at}>
                {timestamp(selected.completed_at)}
              </time>
              <span>已保存结果</span>
            </p>
          </div>

          <div className="campaign-stat-grid">
            <article>
              <span>内容样本</span>
              <strong>{count(matrix.cases)}</strong>
              <small>
                攻击 {count(matrix.attacks)} · 正常 {count(matrix.benign)}
              </small>
            </article>
            <article>
              <span>严格通过率</span>
              <strong>{percent(matrix.strict_pass_rate)}</strong>
              <small>
                {count(matrix.strict_passed)} 通过 /{" "}
                {count(matrix.cases - matrix.strict_passed)} 未通过
              </small>
            </article>
            <article>
              <span>确认检出率</span>
              <strong>{percent(matrix.confirmed_recall)}</strong>
              <small>完整检查并确认风险</small>
            </article>
            <article>
              <span>暂扣召回率</span>
              <strong>{percent(matrix.withhold_recall)}</strong>
              <small>含检查不完整时暂扣</small>
            </article>
            <article>
              <span>正常样本误报率</span>
              <strong>{percent(matrix.fpr)}</strong>
              <small>
                {count(matrix.fp)} / {count(matrix.benign)} 条
              </small>
            </article>
            <article>
              <span>检测延迟 P95</span>
              <strong>{duration(matrix.latency_ms?.p95)}</strong>
              <small>P50 {duration(matrix.latency_ms?.p50)}</small>
            </article>
          </div>

          <div className="campaign-failure-strip">
            <strong>
              未通过记录 <b>{count(selected.failure_counts.total)}</b>
            </strong>
            <span>
              内容检查 <b>{count(selected.failure_counts.content)}</b>
            </span>
            <span>
              任务恢复 <b>{count(selected.failure_counts.workflow)}</b>
            </span>
            <span>
              工程验证 <b>{count(selected.failure_counts.engineering)}</b>
            </span>
          </div>
          <div className="campaign-quality">
            <span>漏报 {count(matrix.fn)}</span>
            <span>误报 {count(matrix.fp)}</span>
            <span>检查不完整 {count(matrix.incomplete)}</span>
            <span>服务不可用 {count(matrix.unavailable)}</span>
          </div>
          <p className="campaign-caption">
            检查不完整与失败分类可能重叠；内容暂扣不等于工具执行阻断。
          </p>

          <div className="campaign-breakdowns">
            <Breakdown
              title="按样本组"
              rows={selected.cohorts.map((row) => ({
                ...row,
                label: cohortNames[row.name]
                  ? `${cohortNames[row.name]} · ${row.name}`
                  : row.name,
              }))}
            />
            <Breakdown
              title="按内容来源"
              rows={selected.by_source.map((row) => ({
                ...row,
                label: sourceNames[row.source_type] || row.source_type,
              }))}
            />
            <Breakdown
              title="按测试类型"
              rows={selected.by_category.map((row) => ({
                ...row,
                label: row.test_category,
              }))}
            />
          </div>

          {recovery && (
            <section className="campaign-recovery" aria-label="任务恢复结果">
              <div className="campaign-section-heading">
                <h3>任务恢复</h3>
                <span>
                  {count(recovery.passed)} / {count(recovery.total)} 项通过
                </span>
              </div>
              <dl>
                <div>
                  <dt>合法报告完成</dt>
                  <dd>
                    {count(recovery.reports_completed)}
                    {recovery.reports_expected !== undefined &&
                      ` / ${count(recovery.reports_expected)}`}
                  </dd>
                </div>
                <div>
                  <dt>安全停工</dt>
                  <dd>
                    {count(recovery.safe_stops)}
                    {recovery.safe_stops_expected !== undefined &&
                      ` / ${count(recovery.safe_stops_expected)}`}
                  </dd>
                </div>
                <div>
                  <dt>真实工具调用</dt>
                  <dd>{count(recovery.tool_calls)}</dd>
                </div>
                <div>
                  <dt>业务模型请求</dt>
                  <dd>{count(recovery.business_requests)}</dd>
                </div>
              </dl>
            </section>
          )}

          <details className="campaign-breakdown campaign-evidence">
            <summary>
              <span>记录详情</span>
              <ChevronDown size={16} aria-hidden="true" />
            </summary>
            <dl>
              <div>
                <dt>测试版本</dt>
                <dd>
                  <code>{selected.source_digest || "未记录"}</code>
                </dd>
              </div>
              <div>
                <dt>执行期间源码</dt>
                <dd>
                  {selected.source_unchanged === true
                    ? "一致"
                    : selected.source_unchanged === false
                      ? "存在变更"
                      : "未记录"}
                </dd>
              </div>
              <div>
                <dt>模型请求</dt>
                <dd>
                  {count(matrix.usage?.attempts)} 次 · 失败{" "}
                  {count(matrix.usage?.failed_attempts)} 次
                </dd>
              </div>
              <div>
                <dt>已记录 Token</dt>
                <dd>
                  {count(matrix.usage?.known_tokens)}
                  {(matrix.usage?.missing_usage_attempts || 0) > 0 &&
                    ` · ${count(matrix.usage?.missing_usage_attempts)} 次请求用量缺失`}
                </dd>
              </div>
              <div>
                <dt>指标文件</dt>
                <dd>
                  <code>{selected.source_path}</code>
                </dd>
              </div>
              <div>
                <dt>失败索引</dt>
                <dd>
                  <code>{selected.failure_index_path || "未记录"}</code>
                </dd>
              </div>
              {!!Object.keys(selected.failure_counts.by_kind || {}).length && (
                <div>
                  <dt>失败分类</dt>
                  <dd>
                    {Object.entries(selected.failure_counts.by_kind || {}).map(
                      ([kind, value]) => (
                        <span className="campaign-kind" key={kind}>
                          {failureNames[kind] || kind} {count(value)}
                        </span>
                      ),
                    )}
                  </dd>
                </div>
              )}
            </dl>
          </details>
        </div>
      )}

      {!resource.error && resource.data && resource.data.invalid_count > 0 && (
        <details className="campaign-unavailable">
          <summary>{count(resource.data.invalid_count)} 份报告读取异常</summary>
          <ul>
            {resource.data.errors.map((error) => (
              <li key={error.id}>
                <strong>{error.id}</strong>：{error.reason}
              </li>
            ))}
          </ul>
        </details>
      )}
      {!resource.error && resource.data?.truncated && (
        <p className="campaign-caption">
          报告列表已达到读取上限，部分历史记录未列出。
        </p>
      )}
    </section>
  );
}
