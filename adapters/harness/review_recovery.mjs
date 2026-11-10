/** Re-review a candidate only when a failed judge is its sole blocker.
 * No tool is replayed. The replacement needs its own approval and permit.
 */
export function canRecoverReview(call) {
  const rules = call?.matched_rules;
  const actions = call?.report?.rule_actions;
  // Legacy responses are eligible only when they carry exactly one rule.
  // With action evidence, confirmation rules may coexist but remain mandatory
  // on the replacement. Never infer a rule's action from its name.
  const soleBlocker = Array.isArray(rules) && (actions && typeof actions === 'object' ?
    Object.keys(actions).length === rules.length &&
    rules.every(r => ['allow', 'confirm', 'block'].includes(actions[r])) &&
    rules.filter(r => actions[r] === 'block').length === 1 && actions['core.model_unavailable'] === 'block' :
    rules.length === 1 && rules[0] === 'core.model_unavailable');
  return call?.decision === 'block' && call.execution_status === 'not_executed' &&
    call.execution_owner === 'adapter' && !call.permit &&
    soleBlocker &&
    call.report?.alignment_coverage?.provider_failure?.retryable !== false &&
    call.report?.alignment_coverage?.model_attempted === true &&
    call.report.alignment_coverage.complete === false;
}

export async function recoverReviewOnce(call, {control, recheck, emit}) {
  if (!canRecoverReview(call)) return call;
  await control(call);
  const replacement = await recheck(call);
  if (!replacement?.id || replacement.id === call.id ||
      replacement.recheck_of_call_id !== call.id || replacement.session_id !== call.session_id ||
      replacement.parameter_hash !== call.parameter_hash || replacement.execution_owner !== 'adapter' ||
      !['allow', 'confirm', 'block'].includes(replacement.decision) ||
      replacement.execution_status !== (replacement.decision === 'confirm' ? 'pending' : 'not_executed') ||
      (replacement.decision !== 'allow' && replacement.permit) || replacement.approval?.approved === true) {
    throw new Error('Re-review changed the candidate identity or inherited execution/approval');
  }
  await emit('review_recovery', {previous_call_id: call.id, call_id: replacement.id,
    decision: replacement.decision, reason: 'sole_reviewer_unavailability', retry_limit: 1});
  return replacement;
}
