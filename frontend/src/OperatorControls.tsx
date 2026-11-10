import { useState } from 'react';
import { api, post } from './api';
import { useResource } from './hooks/useResource';
import type { Session, Memory } from './types';

type Notice = (text: string, type?: 'success' | 'error') => void;

export function AuthorizationControl({session, refresh, notify}:{session:Session;refresh:()=>void;notify:Notice}) {
  const [open,setOpen]=useState(false), [busy,setBusy]=useState(false);
  const [intent,setIntent]=useState(session.intent), [scope,setScope]=useState(session.scope), [reason,setReason]=useState('');
  const history=useResource<{id:string;actor:string;reason:string;created_at:string;after:{authorization_version:number;scope:string;intent:string}}[]>(`/sessions/${session.id}/authorization-history`,session.authorization_version||1);
  async function submit(e:React.FormEvent) {
    e.preventDefault();setBusy(true);
    try {await post(`/sessions/${session.id}/authorization-change`,{expected_version:session.authorization_version||1,intent,scope,reason});setOpen(false);setReason('');refresh();history.refresh();notify('授权已更新，旧许可已撤销，请重新审查候选操作。');}
    catch(e){notify((e as Error).message,'error');}finally{setBusy(false);}
  }
  return <section className="card evidence-card operator-controls"><div className="section-heading"><h2>任务授权 · v{session.authorization_version||1}</h2><button className="button" onClick={()=>{setIntent(session.intent);setScope(session.scope);setOpen(!open);}}>变更任务范围</button></div>
    <p className="caption">由管理员明确变更任务。普通风险确认不扩大只读权限；运行中的宿主需先停止。</p>
    {session.original_intent && <p>最初任务：{session.original_intent}</p>}
    {open && <form onSubmit={submit}><label>新任务目标<textarea required maxLength={12000} value={intent} onChange={e=>setIntent(e.target.value)}/></label><label>授权范围<select value={scope} onChange={e=>setScope(e.target.value)}><option value="read_only">只读</option><option value="development">开发 · 写操作逐项确认</option></select></label><label>变更依据<textarea required maxLength={2000} value={reason} onChange={e=>setReason(e.target.value)}/></label><button className="button primary" disabled={busy}>保存授权变更</button></form>}
    {history.error && <p role="alert">{history.error}</p>}{!!history.data?.length && <details><summary>查看授权变更历史</summary>{history.data.map(h=><p key={h.id}>v{h.after.authorization_version} · {h.actor} · {h.reason}<br/>{h.after.intent}</p>)}</details>}
  </section>;
}

export function MemoryControl({memory,refresh,notify}:{memory:Memory;refresh:()=>void;notify:Notice}) {
  const [open,setOpen]=useState(false),[busy,setBusy]=useState(false),[action,setAction]=useState(memory.status==='active'?'quarantine':'restore');
  const [reason,setReason]=useState(''),[content,setContent]=useState(''),[history,setHistory]=useState<{id:string;action:string;reason:string;snapshot:{version:number;status:string}}[]>([]);
  async function submit(e:React.FormEvent){e.preventDefault();setBusy(true);try{await post(`/memories/${memory.id}/review`,{expected_version:memory.version,action,reason,...(action==='revise'?{content}:{})});notify('记忆复核已保存，旧版本准入不会自动恢复。');setOpen(false);refresh();}catch(e){notify((e as Error).message,'error');}finally{setBusy(false);}}
  async function show(){setOpen(!open);setAction(memory.status==='active'?'quarantine':'restore');try{setHistory(await api(`/memories/${memory.id}/versions`));}catch(e){notify((e as Error).message,'error');}}
  return <div className="operator-controls"><button className="button" onClick={show}>隔离 / 修订 / 恢复</button>{open && <form onSubmit={submit}><label>处理方式<select value={action} onChange={e=>setAction(e.target.value)}><option value="quarantine">隔离当前版本</option><option value="restore">重新检测后恢复</option><option value="revise">提交修订并重新检测</option></select></label>{action==='revise'&&<label>完整修订内容<textarea value={content} onChange={e=>setContent(e.target.value)} required maxLength={200000}/></label>}<label>复核依据<textarea value={reason} onChange={e=>setReason(e.target.value)} required maxLength={2000}/></label><p className="caption">风险仍存在或检测未完成时不能恢复。修订保留旧版本和操作者记录。</p><button className="button primary" disabled={busy}>提交复核</button>{history.map(h=><p key={h.id}>原 v{h.snapshot.version} · {h.action} · {h.reason}</p>)}</form>}</div>;
}

export function KnowledgeControl({sessionId}:{sessionId:string}) {
  const records=useResource<{id:string;title:string;version:number;status?:string}[]>(`/sessions/${sessionId}/knowledge`,0);
  const [selected,setSelected]=useState(''),[reason,setReason]=useState(''),[busy,setBusy]=useState(false),[error,setError]=useState('');
  const item=records.data?.find(d=>d.id===selected);
  async function submit(e:React.FormEvent){e.preventDefault();if(!item)return;setBusy(true);setError('');try{await post(`/knowledge/${item.id}/review`,{expected_version:item.version,action:item.status==='quarantined'?'restore':'quarantine',reason});records.refresh();setReason('');}catch(e){setError((e as Error).message);}finally{setBusy(false);}}
  return <section className="card evidence-card operator-controls"><div className="section-heading"><h2>知识索引管理</h2><button className="button" onClick={records.refresh}>刷新索引</button></div><p className="caption">隔离的文档不参与检索；恢复需重新核验原文、权限和检测结果。</p>{(records.error||error)&&<p role="alert">{records.error||error}</p>}<form onSubmit={submit}><label>知识文档<select value={selected} onChange={e=>setSelected(e.target.value)}><option value="">请选择</option>{records.data?.map(d=><option key={d.id} value={d.id}>{d.title} · v{d.version} · {d.status==='quarantined'?'隔离':'可用'}</option>)}</select></label>{item&&<><label>复核依据<input required maxLength={2000} value={reason} onChange={e=>setReason(e.target.value)}/></label><button className="button" disabled={busy}>{item.status==='quarantined'?'重新检测后恢复':'隔离文档'}</button></>}</form></section>;
}
