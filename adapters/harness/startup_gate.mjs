/** Independent of the main plugin's activation/disposal scope. */
export const name = 'aegisguard-startup-gate';
export const inject = ['llm', 'tools'];
let ready = false;

// Only local plugin code can change this state. Tool metadata and model text
// cannot grant readiness; no file, input field or model-produced flag is read.
export const markGuardReady = () => { ready = true; };
export const revokeGuardReady = () => { ready = false; };

export function apply(ctx) {
  ctx.tools.guard(() => ready ? undefined : 'AEGIS_GUARD_NOT_READY: 防护插件尚未就绪，禁止执行工具');
  ctx.on('llm/stream', (_options, next) => (async function* () {
    if (!ready) throw new Error('AEGIS_GUARD_NOT_READY: 防护插件尚未就绪，禁止业务模型调用');
    yield* next();
  })(), {prepend: true});
}
