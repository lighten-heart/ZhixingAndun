/** Strict framing only: never repair a malformed security decision into an allow. */
class ReviewResponseError extends Error {
  constructor(code) { super(code); this.name = 'ReviewResponseError'; this.code = code; }
}

export function reviewFailureCode(error) {
  return error instanceof ReviewResponseError ? error.code : undefined;
}

export function providerFailure(finishes) {
  // Only typed provider finish metadata can suppress an immediate retry.
  // Never inspect generated text or forward arbitrary error messages.
  if (finishes.length !== 1 || finishes[0]?.kind !== 'error') return undefined;
  const failure = finishes[0].failure;
  const statuses = {ACCOUNT_QUOTA: 402, ACCOUNT_TOKEN_INVALID: 401};
  if (!failure || typeof failure.code !== 'string' || !Object.hasOwn(statuses, failure.code) || statuses[failure.code] !== failure.status) return undefined;
  return {code: failure.code, status: failure.status};
}

export function parseReviewResponse(blocks, finishes) {
  if (finishes.length !== 1 || finishes[0]?.kind !== 'stop') {
    throw new ReviewResponseError('REVIEW_STREAM_INCOMPLETE');
  }
  if (blocks.some(block => block.type === 'tool-call')) throw new ReviewResponseError('REVIEW_TOOL_CALL');
  let text = blocks.filter(block => block.type === 'text').map(block => block.text).join('').trim();
  if (!text || text.length > 100000) throw new ReviewResponseError('REVIEW_RESPONSE_SIZE');
  const fence = /^```(?:json)?\s*\n?([\s\S]*?)\n?```$/i.exec(text);
  if (fence) text = fence[1].trim();
  let answer;
  try { answer = JSON.parse(text); }
  catch { throw new ReviewResponseError('REVIEW_JSON_INVALID'); }
  if (!answer || typeof answer !== 'object' || Array.isArray(answer)) throw new ReviewResponseError('REVIEW_OBJECT_REQUIRED');
  return answer;
}
