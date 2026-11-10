import { useState } from 'react';
import { Database, Search, ShieldCheck } from 'lucide-react';
import { post } from './api';
import { useResource } from './hooks/useResource';
type Data = { id: string; label: string; version: number; sensitivity: string; source_id: string; allowed_purposes: string[]; allowed_recipients: string[]; derivation: { operation: string; verified: boolean } | null };
type SearchResult = { results: { document_id: string; title: string; content: string; start: number; end: number; version: number }[]; quarantined: unknown[]; permission_filtered: number; index_type: string };
export default function DataEvidence({ sessionId, sources }: { sessionId: string; sources: { id: string; resource: string; type: string }[] }) {
  const records = useResource<Data[]>(`/sessions/${sessionId}/data`);
  const [sourceId, setSource] = useState(sources[0]?.id || '');
  const [label, setLabel] = useState('项目资料');
  const [sensitivity, setSensitivity] = useState('internal');
  const [recipients, setRecipients] = useState('local');
  const [query, setQuery] = useState('安全组件');
  const [recipient, setRecipient] = useState('knowledge');
  const [result, setResult] = useState<SearchResult | null>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  async function action(fn: () => Promise<void>) { setBusy(true); setError(''); try { await fn(); } catch (e) { setResult(null); setError(e instanceof Error ? e.message : '操作失败'); } finally { setBusy(false); } }
  return <div className="data-evidence">
    <div className="info-box"><ShieldCheck size={19} /><p>可信标签决定数据可用于什么任务、可交给谁。可核验的复制、截取和编码继承原始权限；未获准的知识片段不进入检索结果。</p></div>
    {(error || records.error) && <p role="alert" className="text-red">{error || records.error}</p>}
    <details className="data-register"><summary>登记可信数据标签</summary><form onSubmit={e => { e.preventDefault(); void action(async () => { await post(`/sessions/${sessionId}/data`, {source_id: sourceId, label, sensitivity, allowed_purposes: ['task'], allowed_recipients: recipients.split(',').map(s => s.trim()).filter(Boolean)}); records.refresh(); }); }}>
      <label>输入来源<select value={sourceId} onChange={e => setSource(e.target.value)}>{sources.map(s => <option key={s.id} value={s.id}>{s.resource || s.type} · {s.id.slice(-6)}</option>)}</select></label>
      <label>数据名称<input required value={label} onChange={e => setLabel(e.target.value)} /></label>
      <label>敏感等级<select value={sensitivity} onChange={e => setSensitivity(e.target.value)}><option value="public">公开</option><option value="internal">内部</option><option value="confidential">机密</option><option value="credential">凭据</option></select></label>
      <label>允许接收方（逗号分隔）<input required value={recipients} onChange={e => setRecipients(e.target.value)} placeholder="local,knowledge,deepseek-account" /></label>
      <p className="caption">用途固定为当前任务 task。local 为本地处理；knowledge 为知识服务；deepseek-account 为业务模型。登记操作需要管理权限。</p>
      <button className="button primary" disabled={busy || !sourceId}>保存标签</button></form></details>
    <div className="data-records">{records.data?.map(d => <article key={d.id}><header><Database size={17} /><strong>{d.label}</strong><span className="quiet-tag">{({public:'公开',internal:'内部',confidential:'机密',credential:'凭据'} as Record<string,string>)[d.sensitivity]} · v{d.version}</span></header>
      <p>允许用途：{d.allowed_purposes.join('、') || '无'}<br />允许接收方：{d.allowed_recipients.join('、') || '无'}</p>
      <small>{d.derivation ? `程序核验派生：${d.derivation.operation}` : '可信操作者登记'} · {d.id}</small>
      <button className="button" disabled={busy} onClick={() => void action(async () => { await post(`/sessions/${sessionId}/knowledge`, {data_id:d.id,title:d.label}); setError(''); })}>加入知识索引</button>
    </article>)}{records.data?.length === 0 && <p className="muted">尚未登记数据标签。</p>}</div>
    <form className="knowledge-search" onSubmit={e => { e.preventDefault(); void action(async () => setResult(await post<SearchResult>(`/sessions/${sessionId}/knowledge/search`, {query, purpose:'task',recipient,limit:5}))); }}>
      <label>知识检索<input value={query} onChange={e => setQuery(e.target.value)} required /></label><label>实际接收方<select value={recipient} onChange={e => setRecipient(e.target.value)}><option value="knowledge">知识服务</option><option value="deepseek-account">DeepSeek 业务模型</option><option value="local">本地处理</option></select></label><button className="button primary" disabled={busy}><Search size={16} />检索并审查</button>
    </form>
    {result && <div className="knowledge-results"><p>获准片段 {result.results.length} · 隔离片段 {result.quarantined.length} · 权限过滤文档 {result.permission_filtered}</p>{result.results.map((r,i) => <article key={i}><strong>{r.title} · v{r.version}</strong><pre>{r.content}</pre><small>原文位置 [{r.start}, {r.end}) · {r.document_id}</small></article>)}<p className="caption">使用可复现的稀疏 TF-IDF 向量排序，先核对用途与接收方权限，再逐片段检查内容。</p></div>}
  </div>;
}
