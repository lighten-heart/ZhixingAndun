"""Real Git with explicit refs, isolated configuration and frozen report objects.

Only operator-created managed repositories are supported. This is not a shell,
credential helper, or a way to publish arbitrary repositories from a model.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

if __package__ in {None, ''}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from adapters.file_boundary import BoundFile


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def environment(home):
    # Do not inherit GIT_CONFIG_COUNT, alternate object paths, helpers, SSH or hooks.
    env = {k: v for k, v in os.environ.items() if k in {'SystemRoot', 'WINDIR', 'TEMP', 'TMP', 'LANG'}}
    env.update(HOME=str(home), USERPROFILE=str(home), GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull,
               GIT_TERMINAL_PROMPT='0', GIT_OPTIONAL_LOCKS='0', GIT_PAGER='cat', LC_ALL='C',
               GIT_AUTHOR_NAME='AegisGuard', GIT_AUTHOR_EMAIL='aegisguard@example.invalid',
               GIT_COMMITTER_NAME='AegisGuard', GIT_COMMITTER_EMAIL='aegisguard@example.invalid')
    return env


def run(git, cwd, home, *args, data=None, raw=False):
    command = [git, '-c', 'core.hooksPath=' + str(home / 'empty-hooks'), '-c', 'commit.gpgsign=false',
               '-c', 'tag.gpgsign=false', '-c', 'core.fsmonitor=false', '-c', 'core.autocrlf=false', '-c', 'core.longpaths=true',
               '-c', 'protocol.allow=never', '-c', 'protocol.file.allow=always', '-c', 'gc.auto=0', *args]
    result = subprocess.run(command, cwd=cwd, env=environment(home), input=data, capture_output=True,
                            timeout=20, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    if result.returncode:
        raise RuntimeError('Managed Git command failed: ' + args[0])
    if len(result.stdout) > 300000:
        raise RuntimeError('Git output exceeded evidence limit')
    decoded = result.stdout.decode('utf-8', errors='strict')
    return decoded if raw else decoded.strip()


def provision(directory):
    """Called by the trusted operator host setup, never by an Agent tool."""
    directory = Path(directory).resolve()
    workspace, remote, home = directory / 'workspace', directory / 'git-remote.git', directory / 'git-control'
    git = str(Path(shutil.which('git') or '').resolve())
    if not Path(git).is_file() or (workspace / '.git').exists() or remote.exists():
        raise ValueError('Git unavailable or managed repository already exists')
    home.mkdir()
    (home / 'empty-hooks').mkdir()
    run(git, workspace, home, 'init', '--initial-branch=main', '--template=' + str(home / 'empty-hooks'))
    run(git, directory, home, 'init', '--bare', '--initial-branch=main', '--template=' + str(home / 'empty-hooks'), str(remote))
    # The receiving process does not inherit the sender's -c options. Persist
    # this setting only in the operator-owned bare repository before hashing it.
    run(git, remote, home, 'config', '--local', 'core.longpaths', 'true')
    run(git, workspace, home, 'commit', '--allow-empty', '-m', 'Initialize controlled report repository')
    policy = {'workspace': str(workspace), 'remote': str(remote), 'branch': 'refs/heads/main', 'git': git,
              'git_sha256': sha(Path(git).read_bytes()), 'git_version': run(git, workspace, home, '--version'),
              'config_sha256': sha((workspace / '.git/config').read_bytes()),
              'remote_config_sha256': sha((remote / 'config').read_bytes())}
    exec_path = Path(run(git, workspace, home, '--exec-path'))
    dependencies = {Path(git), *[p for p in exec_path.glob('git-receive-pack*') if p.is_file()],
                    *[p for p in exec_path.glob('git.exe') if p.is_file()]}
    for base in (Path(git).parent, exec_path.parents[1] / 'bin'):
        dependencies.update(base.glob('*.dll'))
    # Git for Windows can launch its bundled shell for local receive-pack.
    # Bind these observed helpers too; shell=False describes our launcher,
    # not a promise that Git never starts its own helper processes.
    if os.name == 'nt':
        install = exec_path.parents[2]
        for relative in ('mingw64/bin/git.exe', 'usr/bin/sh.exe', 'usr/bin/msys-2.0.dll'):
            helper = install / relative
            if helper.is_file():
                dependencies.add(helper)
    policy['dependencies'] = {str(p): sha(p.read_bytes()) for p in sorted(dependencies)}
    (home / 'policy.json').write_text(json.dumps(policy), encoding='utf-8')
    return policy


class BoundGit:
    def __init__(self, directory, tool, args):
        self.directory = Path(directory).resolve()
        self.home = self.directory / 'git-control'
        self.policy = json.loads((self.home / 'policy.json').read_text(encoding='utf-8'))
        self.tool, self.original, self.used = tool, dict(args), False
        self.workspace, self.remote = Path(self.policy['workspace']), Path(self.policy['remote'])
        if self.workspace != self.directory / 'workspace' or self.remote != self.directory / 'git-remote.git':
            raise ValueError('Git policy target mismatch')
        # Git for Windows cannot initialize a quarantine object directory
        # once its absolute prefix exceeds internal setup buffers, even with
        # core.longpaths. Reject before preparing a publication or any effect.
        if os.name == 'nt' and tool == 'git.push' and len(str(self.remote).encode('utf-16-le')) // 2 > 208:
            raise ValueError('Managed Git publishing path is too long on Windows; use a shorter project directory')
        self.git = self.policy['git']
        self.check_environment()
        if tool not in {'git.status', 'git.commit', 'git.push'}:
            raise ValueError('Unsupported Git operation')
        if (tool == 'git.commit' and (set(args) != {'path', 'message'} or not re.fullmatch(r'reports/[A-Za-z0-9_.-]+\.txt', args['path'])
                                     or not isinstance(args['message'], str) or not 1 <= len(args['message']) <= 2000)) or (tool != 'git.commit' and args):
            raise ValueError('Invalid Git operation arguments')
        if self.command('symbolic-ref', 'HEAD') != self.policy['branch']:
            raise ValueError('Branch changed')
        self.head = self.command('rev-parse', 'HEAD')
        self.remote_head = self.remote_ref()
        self.bound = None
        self.content = None
        if tool == 'git.commit':
            self.bound = BoundFile(self.workspace, args['path'])
            try:
                self.content = self.bound.execute()['content']
            except Exception:
                self.bound.close()
                raise
        # Every published blob is part of the reviewed payload, not just a ref name.
        manifest = self.publication_manifest() if tool == 'git.push' else []
        self.snapshot = self.state()
        self.args = {**args, 'repository': str(self.workspace), 'branch': self.policy['branch'],
                     'head': self.head, **({'content': self.content} if self.content is not None else {}),
                     **({'remote': str(self.remote), 'expected_remote_head': self.remote_head, 'publication': manifest} if tool == 'git.push' else {})}
        self.facts = {'evidence_type': 'managed_git_snapshot', 'snapshot_sha256': self.snapshot,
                      'environment': self.policy, 'hooks_disabled': True, 'shell': False,
                      'shell_scope': 'python_launcher_only_git_may_launch_bound_helpers',
                      'environment_keys': sorted(environment(self.home)), 'scope': 'operator_owned_managed_repository'}

    def command(self, *args, data=None, raw=False):
        return run(self.git, self.workspace, self.home, *args, data=data, raw=raw)

    def check_environment(self):
        for path in (self.workspace, self.workspace / '.git', self.remote, self.home):
            if path.is_symlink() or path.resolve() != path or getattr(path, 'is_junction', lambda: False)():
                raise ValueError('Git repository aliases are forbidden')
        for path, expected in ((Path(self.git), self.policy['git_sha256']),
                               (self.workspace / '.git/config', self.policy['config_sha256']),
                               (self.remote / 'config', self.policy['remote_config_sha256'])):
            if path.is_symlink() or sha(path.read_bytes()) != expected:
                raise ValueError('Git executable or configuration changed')
        for name, expected in self.policy['dependencies'].items():
            if sha(Path(name).read_bytes()) != expected:
                raise ValueError('Git runtime dependency changed')
        # Repo attributes, linked worktrees, alternate object databases and hooks
        # have no place in this explicitly scoped publication profile.
        for path in (self.workspace / '.gitattributes', self.workspace / '.git/info/attributes',
                     self.workspace / '.git/objects/info/alternates', self.workspace / '.git/commondir',
                     self.remote / 'objects/info/alternates'):
            if path.exists():
                raise ValueError('Unreviewed Git environment extension')
        if any((self.home / 'empty-hooks').iterdir()):
            raise ValueError('Hook environment changed')
        for hooks in (self.workspace / '.git/hooks', self.remote / 'hooks'):
            if hooks.exists() and any(hooks.iterdir()):
                raise ValueError('Repository hook is not allowed')

    def remote_ref(self):
        raw = self.command('ls-remote', '--refs', str(self.remote), self.policy['branch'])
        if not raw:
            return ''
        oid, ref = raw.split('\t')
        if ref != self.policy['branch'] or not re.fullmatch('[0-9a-f]{40}', oid):
            raise ValueError('Unexpected remote ref')
        return oid

    def state(self):
        self.check_environment()
        files = {}
        for directory in (self.workspace / '.git', self.remote):
            for path in sorted(directory.rglob('*')):
                if path.is_symlink() or getattr(path, 'is_junction', lambda: False)():
                    raise ValueError('Git object alias detected')
                if path.is_file():
                    files[str(path.relative_to(self.directory))] = sha(path.read_bytes())
        if len(files) > 4000:
            raise ValueError('Managed Git repository size limit')
        return sha(json.dumps(files, sort_keys=True).encode())

    def tree_manifest(self):
        result = []
        raw = self.command('ls-tree', '-r', '-z', self.head)
        for entry in raw.split('\0'):
            if not entry:
                continue
            info, path = entry.split('\t', 1)
            mode, kind, oid = info.split(' ')
            if mode != '100644' or kind != 'blob' or not re.fullmatch(r'reports/[A-Za-z0-9_.-]+\.txt', path):
                raise ValueError('Only approved text reports may be published')
            content = self.command('cat-file', 'blob', oid, raw=True)
            result.append({'path': path, 'blob': oid, 'content': content})
            if len(json.dumps(result, ensure_ascii=False)) > 150000:
                raise ValueError('Git publication exceeds review limit')
        return result

    def publication_manifest(self):
        # A push sends reachable history, including removed files and commit
        # messages. Reviewing only the current tree would leak older content.
        commits = self.command('rev-list', '--max-count=201', self.head).splitlines()
        if len(commits) > 200:
            raise ValueError('Git history exceeds review limit')
        output, seen = [], set()
        for commit in commits:
            raw = self.command('ls-tree', '-r', '-z', commit)
            for entry in raw.split('\0'):
                if not entry:
                    continue
                info, path = entry.split('\t', 1)
                mode, kind, oid = info.split(' ')
                if mode != '100644' or kind != 'blob' or not re.fullmatch(r'reports/[A-Za-z0-9_.-]+\.txt', path):
                    raise ValueError('Unreviewed file in publication history')
                if oid not in seen:
                    output.append({'path': path, 'blob': oid, 'content': self.command('cat-file', 'blob', oid, raw=True), 'kind': 'blob'})
                    seen.add(oid)
            output.append({'commit': commit, 'content': self.command('cat-file', 'commit', commit, raw=True), 'kind': 'commit'})
            if len(json.dumps(output, ensure_ascii=False)) > 150000:
                raise ValueError('Publication history exceeds review limit')
        return output

    def execute(self):
        if self.used:
            raise ValueError('Git binding already consumed')
        self.used = True
        if self.state() != self.snapshot or self.command('rev-parse', 'HEAD') != self.head or self.remote_ref() != self.remote_head:
            raise ValueError('Git review environment changed; new review required')
        if self.tool == 'git.status':
            return {'status': self.command('status', '--short', '--untracked-files=normal'), 'head': self.head, 'execution': 'real_git'}
        if self.tool == 'git.commit':
            # Build immutable Git objects from reviewed bytes, independent of mutable worktree/index.
            blob = self.command('hash-object', '-w', '--stdin', data=self.content.encode('utf-8'))
            old = self.tree_manifest()
            entries = {item['path'].split('/', 1)[1]: item['blob'] for item in old}
            entries[self.original['path'].split('/', 1)[1]] = blob
            subtree = self.command('mktree', data=''.join(f'100644 blob {oid}\t{name}\n' for name, oid in sorted(entries.items())).encode())
            tree = self.command('mktree', data=f'040000 tree {subtree}\treports\n'.encode())
            commit = self.command('commit-tree', tree, '-p', self.head, '-F', '-', data=self.original['message'].encode('utf-8'))
            self.command('update-ref', self.policy['branch'], commit, self.head)
            self.command('read-tree', commit)
            return {'head': commit, 'previous_head': self.head, 'blob': blob, 'path': self.original['path'], 'execution': 'real_git_commit'}
        self.command('push', '--porcelain', '--force-with-lease=' + self.policy['branch'] + ':' + self.remote_head,
                     str(self.remote), self.head + ':' + self.policy['branch'])
        actual = self.remote_ref()
        if actual != self.head:
            raise RuntimeError('Remote ref receipt mismatch')
        return {'head': self.head, 'remote_head': actual, 'remote': str(self.remote), 'branch': self.policy['branch'], 'execution': 'real_git_push'}

    def close(self):
        if getattr(self, 'bound', None):
            self.bound.close()

    def __del__(self):
        self.close()


def main():
    bound = None
    sys.stdin.reconfigure(encoding='utf-8'); sys.stdout.reconfigure(encoding='utf-8')
    try:
        while line := sys.stdin.readline(250001):
            if len(line) > 250000:
                break
            req = json.loads(line)
            try:
                if req['method'] == 'prepare' and bound is None:
                    bound = BoundGit(**req['params'])
                    result = {'args': bound.args, 'facts': bound.facts}
                elif req['method'] == 'execute' and bound:
                    result = bound.execute()
                else:
                    raise ValueError('Invalid boundary state')
                response = {'jsonrpc': '2.0', 'id': req['id'], 'result': result}
            except Exception as exc:
                response = {'jsonrpc': '2.0', 'id': req['id'], 'error': {'code': -32000, 'message': type(exc).__name__ + ': Git boundary rejected operation'}}
            print(json.dumps(response, ensure_ascii=False), flush=True)
    finally:
        if bound:
            bound.close()


if __name__ == '__main__':
    main()
