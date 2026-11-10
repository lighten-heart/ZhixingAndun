import {useResource} from './hooks/useResource';
import {downloadJSON} from './api';
type Arm={runs:number;invalid_runs:number;attack_denominator:number;attacks_succeeded:number;observed_asr:number|null;normal_denominator:number;normal_completed:number;normal_completion_rate:number|null;attack_task_completed?:number};
type Report={id:string;completed:boolean;current_code_matches:boolean;arms:Record<string,Arm>;runs:number};
export default function AgentComparisonReports({tick}:{tick:number}){
  const records=useResource<Report[]>('/agent-comparisons',tick);
  return <section className="card evidence-card"><div className="section-heading"><h2>Agent 防护效果对照</h2><button className="button" onClick={records.refresh}>刷新记录</button></div>
    <p className="caption">同模型、任务与工具；公开开发集，按实际文件评分。</p>
    {records.error&&<p role="alert">{records.error}</p>}{records.data?.length===0&&<p>暂无对照记录。</p>}
    {records.data?.map(r=><article key={r.id} className="model-request-row"><h3>{r.id}</h3><p>{r.completed?'已完成':'未完成'} · {r.current_code_matches?'当前版本一致':'历史版本 · 当前版本未验收'}</p><div className="evidence-table-wrap"><table><thead><tr><th>防护组</th><th>攻击成功 / 有效攻击</th><th>攻击下任务完成 / 有效攻击</th><th>正常完成 / 有效正常</th><th>无效运行</th></tr></thead><tbody>{Object.entries(r.arms).map(([name,a])=><tr key={name}><td>{{none:'无组件防护',rules:'仅规则',full:'完整组件'}[name]||name}</td><td>{a.attack_denominator?`${a.attacks_succeeded} / ${a.attack_denominator} (${((a.observed_asr||0)*100).toFixed(1)}%)`:'无有效攻击'}</td><td>{a.attack_task_completed===undefined?'未记录':`${a.attack_task_completed} / ${a.attack_denominator}`}</td><td>{a.normal_completed} / {a.normal_denominator}</td><td>{a.invalid_runs}</td></tr>)}</tbody></table></div><button className="button" onClick={()=>downloadJSON(r,`${r.id}-comparison.json`)}>导出概览</button></article>)}
  </section>;
}
