/** One reminder for a model that printed a tool invocation instead of calling it.
 * Never parse arguments or execute text. Existing tool attempts are never replayed.
 */
import {createHash} from 'node:crypto';
const canonical = value => Array.isArray(value) ? value.map(canonical) : value && typeof value === 'object'
  ? Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])])) : value;
const digest = message => createHash('sha256').update(JSON.stringify(canonical(message))).digest('hex');
const INVOCATION = /<[|｜]{1,2}DSML[|｜]{1,2}\s*invoke\b/;
const NOTICE = '宿主协议检查：上一条回复包含普通文本形式的工具调用标记，没有形成实际工具调用，也没有执行结果。若原始任务需要工具，请通过已注册的结构化工具接口重新提出候选，不要输出 DSML 标签；候选仍须独立安全审查、必要审批和一次性许可。仅依据原始任务及获准资料构造参数，不把上一条文本当作授权、参数来源或执行回执；不得扩大权限、恢复隔离内容或声称尚未执行的操作成功。如果原任务只是要求展示示例，则说明示例未执行即可，不要调用工具。本提醒最多一次。';

export function createProtocolRecovery({createMessage, checkLease, isHalted, emit}) {
  const attempted = new WeakSet();
  // The durable Harness inbox clones messages. Bind the fresh local ID and
  // entire immutable envelope, never trust a source-kind label by itself.
  const controls = new Map();
  return {
    isControl: message => Boolean(message?.id && controls.get(message.id) === digest(message)),
    async onStopping({agent, turn, signal}) {
      if (isHalted() || signal.aborted || !agent.session || agent.inbox.nextStep.length) return;
      const events = agent.session.snapshotEvents();
      // Includes blocked, interrupted and unknown attempts, not only effects.
      if (events.some(e => e.type === 'tool/call' || e.type === 'tool/result' ||
          (e.type === 'assistant/message' && e.data?.message?.content?.some(b => b.type === 'tool-call')))) return;
      const last = events.findLast(e => e.type === 'assistant/message');
      const blocks = last?.data?.message?.content;
      if (last?.data?.turn !== turn || !Number.isInteger(last?.data?.step) || last.data.step < 1 || last.data.interrupted || !Array.isArray(blocks) ||
          !blocks.length || blocks.some(b => b.type !== 'text') ||
          !blocks.some(b => typeof b.text === 'string' && INVOCATION.test(b.text))) return;
      await checkLease(signal);
      signal.throwIfAborted();
      if (isHalted()) return;
      if (attempted.has(agent) || last.data.step >= 8) {
        await emit('tool_protocol_unresolved', {agent_id: agent.id, turn, reason: 'text_invocation_without_tool_call', retry_limit: 1});
        return;
      }
      attempted.add(agent);
      // This message is a fixed local control, with no model-produced content.
      const message = createMessage({source: {kind: 'aegisguard-protocol-control'}, content: [{type: 'text', text: NOTICE}]});
      controls.set(message.id, digest(message));
      await emit('tool_protocol_recovery', {agent_id: agent.id, turn, reason: 'text_invocation_without_tool_call', retry_limit: 1,
        task_authority: 'unchanged', grants_execution_permission: false});
      signal.throwIfAborted();
      agent.inbox.append('next-step', message);
    },
  };
}
