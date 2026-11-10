"""Trusted image entrypoint; untrusted child cannot write root-owned evidence."""
import base64
import json
from pathlib import Path
import resource
import subprocess

MAX = 1024 * 1024
resource.setrlimit(resource.RLIMIT_FSIZE, (MAX, MAX))
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
root = Path('/evidence')
root.mkdir(mode=0o700, exist_ok=True)
with (root / 'stdout').open('wb') as out, (root / 'stderr').open('wb') as err:
    proc = subprocess.run(['strace', '-f', '-qq', '-yy', '-s', '128',
        '-e', 'trace=%file,%process,%network,read,write', '-o', '/evidence/trace.log',
        '-u', 'sandbox', 'python3', '-I', '/materials/program.py'],
        stdin=subprocess.DEVNULL, stdout=out, stderr=err, timeout=12)
trace = (root / 'trace.log').read_bytes()
print(json.dumps({'schema': 1, 'exit_code': proc.returncode,
    'trace_b64': base64.b64encode(trace).decode(), 'truncated': len(trace) >= MAX,
    'stdout': (root / 'stdout').read_bytes()[:4000].decode('utf-8', errors='replace'),
    'stderr': (root / 'stderr').read_bytes()[:4000].decode('utf-8', errors='replace')}), flush=True)
