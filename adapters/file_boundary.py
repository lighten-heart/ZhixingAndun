"""Hold the reviewed file/parent object until effect completion.

Linux requires openat2 (no insecure fallback). Windows pins each directory with
non-delete-sharing handles. The workspace is operator-owned; arbitrary processes
with operator/debug privileges are outside this cooperative adapter boundary.
Only UTF-8 regular files and exclusive creation of new reports are supported.
"""
from __future__ import annotations
import ctypes
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import stat
import sys


def _openat2(directory, name, flags, mode=0):
    if platform.machine().lower() not in {"x86_64", "amd64", "aarch64", "arm64"}:
        raise OSError("Unsupported openat2 architecture")
    class How(ctypes.Structure):
        _fields_ = [("flags", ctypes.c_uint64), ("mode", ctypes.c_uint64), ("resolve", ctypes.c_uint64)]
    # RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_XDEV
    how = How(flags | os.O_CLOEXEC, mode, 0x08 | 0x04 | 0x01)
    libc = ctypes.CDLL(None, use_errno=True)
    fd = libc.syscall(ctypes.c_long(437), ctypes.c_int(directory), ctypes.c_char_p(os.fsencode(name)),
                      ctypes.byref(how), ctypes.sizeof(how))
    if fd < 0:
        raise OSError(ctypes.get_errno(), "openat2 refused target")
    return fd


def _win_open(path, directory=False, create=False):
    from ctypes import wintypes
    import msvcrt
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                  ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    # No FILE_SHARE_DELETE. Files also exclude writers until close.
    access = 0x80000000 if directory else (0x40000000 if create else 0x80000000)
    handle = kernel.CreateFileW(str(path), access, 3 if directory else 1, None,
                                1 if create else 3, 0x00200000 | (0x02000000 if directory else 0), None)
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        fd = msvcrt.open_osfhandle(handle, os.O_RDONLY if not create else os.O_WRONLY)
    except BaseException:
        kernel.CloseHandle(handle)
        raise
    if getattr(os.fstat(fd), "st_file_attributes", 0) & 0x400:
        os.close(fd)
        raise OSError("Reparse points are not supported")
    return fd


def identity(fd):
    info = os.fstat(fd)
    # 64-bit identities and nanoseconds must survive JavaScript JSON round trips.
    return {"device": str(info.st_dev), "inode": str(info.st_ino), "mode": info.st_mode,
            "links": info.st_nlink, "size": info.st_size, "mtime_ns": str(info.st_mtime_ns), "ctime_ns": str(info.st_ctime_ns)}


class BoundFile:
    def __init__(self, workspace, path, write=False):
        self.fds, self.file, self.used = [], None, False
        self.write, self.path = write, path
        self.root = Path(os.path.abspath(workspace))
        parts = path.split("/") if isinstance(path, str) else []
        if (not parts or any(not p or p in {".", ".."} or p.endswith((".", " ")) for p in parts)
                or any(c in path for c in "\\:\x00") or Path(path).is_absolute()
                or any(re.fullmatch(r"(?i)(CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9])(?:\..*)?", p) for p in parts)):
            raise ValueError("Invalid workspace-relative path")
        if write and not re.fullmatch(r"reports/[A-Za-z0-9_.-]+\.txt", path):
            raise ValueError("Only new reports/*.txt files may be created")
        self.target = self.root.joinpath(*parts)
        try:
            if os.name == "nt":
                # Pin ancestors too, including the workspace's own name.
                for parent in [*reversed(self.target.parent.parents), self.target.parent]:
                    self.fds.append(_win_open(parent, directory=True))
                self.parent = self.fds[-1]
                if write:
                    if os.path.lexists(self.target):
                        raise FileExistsError("Reports cannot overwrite existing objects")
                else:
                    self.file = _win_open(self.target)
            elif sys.platform == "linux":
                root = os.open(self.root, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
                self.fds.append(root)
                self.parent = _openat2(root, "/".join(parts[:-1]) or ".", os.O_PATH | os.O_DIRECTORY)
                self.fds.append(self.parent)
                if write:
                    try:
                        os.stat(parts[-1], dir_fd=self.parent, follow_symlinks=False)
                    except FileNotFoundError:
                        pass
                    else:
                        raise FileExistsError("Reports cannot overwrite existing objects")
                else:
                    self.file = _openat2(root, path, os.O_RDONLY | os.O_NONBLOCK)
            else:
                raise OSError("File binding unsupported on this platform")
            if self.file is not None:
                self.fds.append(self.file)
                info = os.fstat(self.file)
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 100000:
                    raise ValueError("Only bounded regular files with one link are supported")
            self.facts = {"requested_path": path, "actual_path": str(self.target),
                          "existing_parent": str(self.target.parent), "workspace": str(self.root),
                          "parent_identity": identity(self.parent),
                          "file_identity": identity(self.file) if self.file is not None else None,
                          "creation": "exclusive_new" if write else None,
                          "evidence_type": "held_windows_handles" if os.name == "nt" else "held_openat2_handles"}
        except BaseException:
            self.close()
            raise

    def execute(self, content=None):
        if self.used:
            raise ValueError("File binding has already been consumed")
        self.used = True
        if self.write:
            if not isinstance(content, str) or len(content.encode("utf-8")) > 100000:
                raise ValueError("Text output exceeds limit")
            # No create/truncate occurs until the caller has claimed its permit.
            if os.name == "nt":
                self.file = _win_open(self.target, create=True)
            else:
                current = _openat2(self.fds[0], str(Path(self.path).parent), os.O_PATH | os.O_DIRECTORY)
                try:
                    if identity(current)["inode"] != self.facts["parent_identity"]["inode"]:
                        raise OSError("Reviewed parent changed")
                finally:
                    os.close(current)
                self.file = _openat2(self.parent, self.target.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            self.fds.append(self.file)
            payload = content.encode("utf-8")
            view = memoryview(payload)
            while view:
                written = os.write(self.file, view)
                if written <= 0:
                    raise OSError("Short write")
                view = view[written:]
            os.fsync(self.file)
            return {"path": self.path, "bytes": len(payload), "sha256": hashlib.sha256(payload).hexdigest(),
                    "identity": identity(self.file), "execution": "bound_exclusive_file_write"}
        if identity(self.file) != self.facts["file_identity"]:
            raise OSError("Reviewed file changed")
        chunks, size = [], 0
        while size <= 100000:
            block = os.read(self.file, min(65536, 100001 - size))
            if not block:
                break
            chunks.append(block)
            size += len(block)
        payload = b"".join(chunks)
        if size > 100000 or identity(self.file) != self.facts["file_identity"]:
            raise OSError("File changed during read or exceeds limit")
        return {"path": self.path, "content": payload.decode("utf-8"),
                "sha256": hashlib.sha256(payload).hexdigest(), "identity": identity(self.file),
                "execution": "bound_file_read"}

    def close(self):
        while self.fds:
            os.close(self.fds.pop())

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def main():
    bound = None
    sys.stdin.reconfigure(encoding="utf-8")
    sys.stdout.reconfigure(encoding="utf-8")
    try:
        while line := sys.stdin.readline(250001):
            if len(line) > 250000:
                break
            request = json.loads(line)
            try:
                params = request.get("params", {})
                if request["method"] == "prepare" and bound is None:
                    bound = BoundFile(**params)
                    result = bound.facts
                elif request["method"] == "execute" and bound is not None:
                    result = bound.execute(**params)
                else:
                    raise ValueError("Invalid boundary state")
                response = {"jsonrpc": "2.0", "id": request["id"], "result": result}
            except (OSError, ValueError, TypeError):
                response = {"jsonrpc": "2.0", "id": request["id"], "error": {"code": -32000, "message": "File boundary rejected operation"}}
            print(json.dumps(response, ensure_ascii=False), flush=True)
    finally:
        if bound:
            bound.close()


if __name__ == "__main__":
    main()
