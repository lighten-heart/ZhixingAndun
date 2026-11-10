import { CheckCircle2, RefreshCw, TestTube2, XCircle } from 'lucide-react';
import { useResource } from './hooks/useResource';
import BlindReport from './BlindReport';
type Suite = { suite: string; passed: boolean; duration_seconds: number; stats?: { successes?: number; failures?: number; errors?: number } };
const names: Record<string,string> = {regression:'组件回归', paired:'真实效果对照', semantic:'独立防护模型', harness:'真实 Harness 全流程'};
export default function PromptfooReports({tick}:{tick:number}) {
  const report = useResource<{suites:Suite[]}>('/evaluations/promptfoo',tick);
  return <><BlindReport tick={tick}/><section className="card promptfoo-reports"><div className="section-heading"><h2><TestTube2 size={18}/>Promptfoo 多场景测试</h2><button className="button" onClick={report.refresh}><RefreshCw size={15}/>刷新结果</button></div>
    <p className="muted">已保存报告 · 当前代码版本未核验</p>
    {report.error && <p role="alert" className="text-red">{report.error}</p>}
    <div className="promptfoo-grid">{report.data?.suites.map(s => <article key={s.suite}>{s.passed ? <CheckCircle2 className="text-green" size={22}/> : <XCircle className="text-red" size={22}/>}<h3>{names[s.suite] || s.suite}</h3><strong>{s.stats?.successes ?? 0} 通过 / {(s.stats?.failures ?? 0) + (s.stats?.errors ?? 0)} 未通过</strong><small>{s.duration_seconds} 秒 · {s.passed ? '断言通过' : '存在失败项'}</small></article>)}</div>
    {report.data?.suites.length === 0 && <p>暂无 Promptfoo 测试结果。</p>}
    <p className="caption">评测范围：本机受控样例 · 非未知攻击检出率或赛事成绩</p>
  </section></>;
}
