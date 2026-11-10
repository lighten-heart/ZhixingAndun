import { useEffect, useState } from 'react';
import { Fingerprint, Loader2 } from 'lucide-react';
import { api } from './api';

type Mapping = { token_count: number; verified_roundtrip: boolean; tokenizer: { repository: string; sha256: string }; tokens: { index: number; start: number; end: number }[]; range: { start: number; end: number } };
export default function TokenEvidence({ sourceId, start, end }: { sourceId: string; start: number; end: number }) {
  const [result, setResult] = useState<Mapping | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  useEffect(() => { setResult(null); setError(''); }, [sourceId, start, end]);
  async function inspect() {
    setBusy(true); setError(''); setResult(null);
    try { setResult(await api<Mapping>(`/sources/${sourceId}/tokens?start=${start}&end=${end}`)); }
    catch (e) { setError(e instanceof Error ? e.message : '映射读取失败'); }
    finally { setBusy(false); }
  }
  return <section className="token-evidence">
    <button className="button" onClick={inspect} disabled={busy}>{busy ? <Loader2 className="spin" size={16} /> : <Fingerprint size={16} />}核验本地 token 位置</button>
    {error && <p role="alert" className="text-red">{error}</p>}
    {result && <><p>原文核验：{result.verified_roundtrip ? '通过' : '未通过'} · 全文 {result.token_count} 个本地审计 token · 字符区间 [{result.range.start}, {result.range.end})</p>
      <div className="token-offsets">{result.tokens.slice(0, 150).map(t => <span key={t.index} title={`原文字符 ${t.start} 至 ${t.end}`}><strong>#{t.index}</strong> [{t.start}, {t.end})</span>)}</div>
      <p className="caption">本地分词器：{result.tokenizer.repository} · SHA-256 {result.tokenizer.sha256.slice(0, 16)}…<br />远端模板及分词未核验；此处为本地映射，非完整模型输入。当前区间最多 150 项。</p></>}
  </section>;
}
