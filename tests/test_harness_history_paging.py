import pytest
from fastapi.testclient import TestClient
from backend.main import create_app


def test_history_pages_are_bounded_complete_and_redacted(tmp_path, monkeypatch):
    app = create_app(tmp_path)
    with TestClient(app) as client:
        store = app.state.service.store
        with store.transaction():
            for i in range(123):
                store.put('harness_run', {'id': f'run-{i:03}', 'created_at': f'2026-01-01T00:{i:03}',
                    'status': 'completed', 'events': [{'sequence': n} for n in range(180)],
                    '_private': 'never-public', 'message': 'api_key=fixture-secret-history-123'})
        original = store._execute
        queries = []
        def execute(sql, args=()):
            if 'FROM records' in sql and args and args[0] == 'harness_run': queries.append((sql, args))
            return original(sql, args)
        monkeypatch.setattr(store, '_execute', execute)
        pages = [client.get('/api/harness/runs' + query) for query in ('', '?offset=50', '?offset=100', '?offset=150')]
        assert [len(r.json()) for r in pages] == [50, 50, 23, 0]
        rows = [item for page in pages for item in page.json()]
        assert [r['id'] for r in rows] == [f'run-{i:03}' for i in range(122, -1, -1)]
        assert all('LIMIT' in sql and 'OFFSET' in sql for sql, _ in queries)
        assert all('_private' not in r and len(r['events']) == 150 and r['events'][0]['sequence'] == 30 for r in rows)
        assert all('fixture-secret-history-123' not in r.text and 'never-public' not in r.text for r in pages)
        assert client.get('/api/harness/runs/run-000').json()['id'] == 'run-000'
        for query in ('?limit=0', '?limit=201', '?offset=-1', '?offset=1000001', '?limit=oops'):
            assert client.get('/api/harness/runs' + query).status_code == 422


def test_paged_store_validates_parameters_and_stable_ties(tmp_path):
    from backend.storage import Store
    store = Store(tmp_path, database_url='')
    try:
        for i in range(8): store.put('harness_run', {'id': str(i), 'created_at': 'same', 'status': 'completed'})
        assert [r['id'] for r in store.page('harness_run', 3, 0)] == ['7', '6', '5']
        assert [r['id'] for r in store.page('harness_run', 3, 3)] == ['4', '3', '2']
        for limit, offset in ((0, 0), (201, 0), (1, -1), (True, 0), (1, True)):
            with pytest.raises(ValueError): store.page('harness_run', limit, offset)
    finally: store.close()
