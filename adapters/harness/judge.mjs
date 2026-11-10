/** Independent no-tool LLM route. No task agent, tool executor, or business history. */
import {createInterface} from 'node:readline';
import {join} from 'node:path';
import {pathToFileURL} from 'node:url';
import {parseReviewResponse, providerFailure, reviewFailureCode} from './judge_response.mjs';
export const name = 'aegisguard-judge';
export const inject = ['llm', 'tools'];
export async function apply(ctx, config) {
  const {BlockAssembler, createUserMessage} = await import(pathToFileURL(join(process.env.AEGIS_DSH_RUNTIME, 'node_modules/@deepseek-ai/dsh-llm/lib/index.js')));
  ctx.tools.guard(() => 'Independent safety reviewer has no tools');
  void (async () => {
    await ctx.get('loader')?.await();
    const input = createInterface({input: process.stdin});
    let queue = Promise.resolve();
    const send = value => process.stdout.write('AEGIS_JUDGE ' + JSON.stringify(value) + '\n');
    input.on('line', line => {
      queue = queue.then(async () => {
        let request;
        const finishes = [];
        let usage;
        try {
          if (line.length > 400000) throw new Error('review input too large');
          request = JSON.parse(line);
          const assembly = new BlockAssembler();
          const options = {provider: config.provider, model: config.model,
            system: request.system,
            messages: [createUserMessage({content: [{type: 'text', text: JSON.stringify(request.payload)}], source: {kind: 'security-review-data'}})],
            maxTokens: 4096, reasoningEffort: 'off', purpose: 'security-review', signal: AbortSignal.timeout(90000)};
          for await (const chunk of ctx.llm.stream(options)) {
            if (chunk.type === 'finish') finishes.push(chunk.reason);
            if (chunk.type === 'usage') usage = chunk.usage;
            assembly.push(chunk);
          }
          const blocks = assembly.blocks();
          const answer = parseReviewResponse(blocks, finishes);
          send({id: request.id, answer, route: {provider: config.provider, model: config.model}, tools: 0, usage});
        } catch (error) {send({id: request?.id, error: 'Independent model response unavailable or invalid', error_type: reviewFailureCode(error) ? 'ReviewResponseError' : 'Error', review_failure_code: reviewFailureCode(error), finish_kinds: finishes.map(f => f?.kind), provider_failure: providerFailure(finishes), usage});}
      });
    });
    input.on('close', () => process.exit(0));
    send({ready: true});
  })();
}
