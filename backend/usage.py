"""Durable per-attempt usage. Missing provider accounting is never reported as zero."""
from contextvars import ContextVar
from contextlib import contextmanager
from functools import wraps
from inspect import signature
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
import hashlib
import json
import os
import time
import uuid

_scope = ContextVar('usage_scope', default=None)
_attempt = ContextVar('usage_attempt', default=None)


@contextmanager
def review_scope(store, sid, phase):
    token = _scope.set((store, sid, phase))
    try:
        yield
    finally:
        _scope.reset(token)


def audited(kind='session'):
    def decorate(fn):
        sig = signature(fn)
        key = list(sig.parameters)[1]
        @wraps(fn)
        def call(self, *args, **kwargs):
            identifier = sig.bind(self, *args, **kwargs).arguments[key]
            item = self.require(kind, identifier) if kind != 'session' else None
            sid = identifier if item is None else item.get('session_id', item.get('source_session_id'))
            token = _scope.set((self.store, sid, fn.__name__))
            try:
                return fn(self, *args, **kwargs)
            finally:
                _scope.reset(token)
        return call
    return decorate


def observe_provider(route, usage, convention='harness_exclusive'):
    current = _attempt.get()
    if current is not None:
        current.update(route=route, raw_usage=usage, convention=convention)


def normalize_usage(raw, convention='harness_exclusive'):
    if isinstance(raw, dict) and raw.get('type') == 'usage':
        raw = raw.get('usage')
    if not isinstance(raw, dict):
        return None
    if convention == 'openai_inclusive':
        values = {'input': raw.get('prompt_tokens'), 'output': raw.get('completion_tokens'),
                  'cache_read': (raw.get('prompt_tokens_details') or {}).get('cached_tokens', 0), 'cache_write': 0}
    else:
        values = {key: raw.get(field) for key, field in (
            ('input', 'inputTokens'), ('output', 'outputTokens'), ('cache_read', 'cacheReadTokens'), ('cache_write', 'cacheWriteTokens'))}
    if any(type(v) is not int or v < 0 for v in values.values()):
        return None
    if convention == 'openai_inclusive':
        values['input'] -= values['cache_read']
        if values['input'] < 0:
            return None
    values['total'] = sum(values.values())
    provided_total = raw.get('totalTokens', raw.get('total_tokens'))
    if provided_total is not None and (type(provided_total) is not int or provided_total != values['total']):
        return None
    return values


def price(route, tokens):
    """Operator-specified dated rates, not an assumed subscription cash charge."""
    try:
        config = json.loads(os.getenv('GUARD_MODEL_PRICING_JSON', '[]'))
        rate = next(r for r in config if r['provider'] == route['provider'] and r['model'] == route['model'])
        if not tokens or not rate.get('currency') or not rate.get('as_of'):
            return None
        cost = Decimal(0)
        for field in ('input', 'output', 'cache_read', 'cache_write'):
            amount = Decimal(str(rate[field + '_per_million']))
            if not amount.is_finite() or amount < 0:
                return None
            cost += tokens[field] * amount / Decimal(1000000)
        return {'estimated_amount': str(cost), 'currency': rate['currency'], 'rate_as_of': rate['as_of'],
                'rate_sha256': hashlib.sha256(json.dumps(rate, sort_keys=True).encode()).hexdigest(),
                'basis': 'operator_rate_estimate_not_provider_invoice'}
    except (ValueError, TypeError, KeyError, StopIteration, InvalidOperation):
        return None


def record(store, sid, identifier, route, raw_usage, *, phase, status, duration_ms=None, convention='harness_exclusive'):
    tokens = normalize_usage(raw_usage, convention)
    row = {'id': identifier, 'session_id': sid, 'created_at': datetime.now(timezone.utc).isoformat(),
           'route': route, 'phase': phase, 'status': status, 'duration_ms': duration_ms,
           'tokens': tokens, 'usage_complete': tokens is not None, 'price': price(route, tokens),
           'accounting_scope': 'observed_provider_attempt_hidden_provider_retries_not_exposed'}
    store.put('model_usage', row)
    return row


def track_review(fn, payload):
    scope = _scope.get()
    state = {'route': {'provider': os.getenv('GUARD_HARNESS_PROVIDER', 'deepseek-account') if os.getenv('GUARD_MODEL_BACKEND') == 'harness' else os.getenv('GUARD_MODEL_BASE_URL', 'unconfigured'),
                       'model': os.getenv('GUARD_HARNESS_MODEL', 'deepseek-flash') if os.getenv('GUARD_MODEL_BACKEND') == 'harness' else os.getenv('GUARD_MODEL_NAME', '')},
             'raw_usage': None, 'convention': 'harness_exclusive'}
    token = _attempt.set(state)
    start, status = time.perf_counter(), 'failed'
    identifier = 'usage_' + uuid.uuid4().hex
    try:
        if scope:
            record(scope[0], scope[1], identifier, state['route'], None, phase=scope[2], status='pending')
        answer, error = fn(payload)
        status = 'valid_response' if answer and not error else 'failed'
        return answer, error
    finally:
        _attempt.reset(token)
        if scope:
            record(scope[0], scope[1], identifier, state['route'], state['raw_usage'],
                   phase=scope[2], status=status, duration_ms=round((time.perf_counter()-start)*1000, 3), convention=state['convention'])


def summarize(store, session_id):
    rows = store.all('model_usage', session_id)
    for request in store.all('model_request', session_id):
        if not request.get('completion'):
            rows.append({'id': 'usage_' + request['id'], 'phase': 'business_model', 'status': 'pending',
                         'tokens': None, 'usage_complete': False, 'price': None})
    totals = {k: sum((r.get('tokens') or {}).get(k, 0) for r in rows) for k in ('input', 'output', 'cache_read', 'cache_write', 'total')}
    amounts = {}
    for r in rows:
        if r.get('price'):
            currency = r['price']['currency']
            amounts[currency] = amounts.get(currency, Decimal(0)) + Decimal(r['price']['estimated_amount'])
    missing = sum(not r['usage_complete'] for r in rows)
    return {'attempts': len(rows), 'failed_attempts': sum(r['status'] == 'failed' for r in rows),
            'pending_attempts': sum(r['status'] == 'pending' for r in rows),
            'usage_complete': bool(rows) and not missing, 'missing_usage_attempts': missing,
            'known_tokens': totals, 'estimated_cost_by_currency': {k: str(v) for k, v in amounts.items()},
            'missing_price_attempts': sum(r.get('price') is None for r in rows), 'records': rows,
            'scope': 'observed_attempts_only_no_assumed_zero_cost'}
