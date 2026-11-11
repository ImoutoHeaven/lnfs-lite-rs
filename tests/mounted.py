#!/usr/bin/env python3
"""Required mounted acceptance tests. Missing privileges/capabilities are failures."""
import argparse
import concurrent.futures
import ctypes
import errno
import hashlib
import json
import mmap
import os
import resource
from pathlib import Path
import signal
import struct
import subprocess
import tempfile
import time

LIBC = ctypes.CDLL(None, use_errno=True)
LIBC.renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
LIBC.renameat2.restype = ctypes.c_int
LIBC.getdents64.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t]
LIBC.getdents64.restype = ctypes.c_ssize_t


def renameat2(source, destination, flags):
    if LIBC.renameat2(-100, source, -100, destination, flags) != 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))


def expect_errno(expected, function, *args, **kwargs):
    try:
        result = function(*args, **kwargs)
    except OSError as error:
        assert error.errno in expected, (function, error, expected)
    else:
        if function is os.open:
            os.close(result)
        raise AssertionError(f"{function.__name__} unexpectedly succeeded")


def write_file(path, data=b"payload", mode=0o600):
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR, mode)
    try:
        assert os.write(fd, data) == len(data)
    finally:
        os.close(fd)


def read_file(path):
    with open(path, "rb") as stream:
        return stream.read()


class Mount:
    def __init__(self, binary, root, backend=None, extra=(), fd_limit=None, inherited_fds=(), env=None):
        self.binary = str(Path(binary).resolve())
        self.root = Path(root)
        self.backend = Path(backend) if backend else self.root / "backend"
        self.path = self.root / "mount"
        self.backend.mkdir(exist_ok=True)
        self.path.mkdir(exist_ok=True)
        self.path = self.path.resolve()
        self.log_path = self.root / "daemon.log"
        self.extra = list(extra)
        self.fd_limit = fd_limit
        self.inherited_fds = inherited_fds
        self.env = env
        self.log_start = 0
        self.artifact_name = f"{self.root.name}-{time.monotonic_ns()}"
        self.expected_exit = 0
        self.process = None
        self.log = None

    def is_mounted(self):
        # stat-based ismount() returns false when a faulted FUSE root returns EIO.
        # Kernel mount records remain authoritative even when lookup/getattr fail.
        target = os.fspath(self.path)
        for line in Path("/proc/self/mountinfo").read_text(errors="surrogateescape").splitlines():
            encoded = line.split()[4]
            decoded = (encoded.replace(r"\040", " ").replace(r"\011", "\t")
                       .replace(r"\012", "\n").replace(r"\134", "\\"))
            if decoded == target:
                return True
        return False

    def __enter__(self):
        self.log_start = self.log_path.stat().st_size if self.log_path.exists() else 0
        self.log = self.log_path.open("ab", buffering=0)
        def set_limit():
            resource.setrlimit(resource.RLIMIT_NOFILE, (self.fd_limit, self.fd_limit))
        self.process = subprocess.Popen(
            [self.binary, "--backend", str(self.backend), str(self.path), *self.extra],
            stdout=self.log, stderr=self.log, pass_fds=self.inherited_fds,
            env={**os.environ, **self.env} if self.env is not None else None,
            preexec_fn=set_limit if self.fd_limit is not None else None,
        )
        try:
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                if self.process.poll() is not None:
                    raise AssertionError(f"mount failed: {self.log_path.read_text(errors='replace')}")
                if self.is_mounted():
                    os.stat(self.path)
                    assert b"lnfs-lite: FUSE passthrough negotiated" in self.session_log(), self.session_log()
                    return self
                time.sleep(0.025)
            raise AssertionError("mount did not become ready within 15 seconds")
        except BaseException:
            cleanup = self.abort()
            self.archive_failure("startup_failure", cleanup)
            raise

    def session_log(self):
        return self.log_path.read_bytes()[self.log_start:] if self.log_path.exists() else b""

    def archive(self, outcome, cleanup=()):
        destination = os.environ.get("LNFS_TEST_ARTIFACTS")
        if not destination:
            return
        destination = Path(destination)
        destination.mkdir(parents=True, exist_ok=True)
        data = self.session_log()
        (destination / f"{self.artifact_name}.log").write_bytes(data)
        report = {
            "outcome": outcome, "binary": self.binary, "backend": str(self.backend),
            "mount": str(self.path), "pid": self.process.pid if self.process else None,
            "expected_exit": self.expected_exit,
            "actual_exit": self.process.poll() if self.process else None,
            "mount_remaining": self.is_mounted(),
            "daemon_remaining": self.process is not None and self.process.poll() is None,
            "cleanup_errors": list(cleanup),
            "log_sha256": hashlib.sha256(data).hexdigest(),
        }
        (destination / f"{self.artifact_name}.json").write_text(json.dumps(report, indent=2) + "\n")

    def archive_failure(self, outcome, cleanup):
        # Evidence and cleanup failures must not replace the first failing assertion.
        try:
            self.archive(outcome, cleanup)
        except BaseException as error:
            print(f"artifact failure: {error!r}", flush=True)
        if cleanup:
            print(f"cleanup failures: {cleanup!r}", flush=True)
        try:
            print(self.session_log().decode(errors="replace"), flush=True)
        except BaseException as error:
            print(f"daemon log read failed: {error!r}", flush=True)

    def abort(self):
        # Failure cleanup is restricted to this test's private mount and daemon.
        errors = []
        try:
            if self.is_mounted():
                result = subprocess.run(["umount", "-l", str(self.path)],
                                        capture_output=True, timeout=10)
                if result.returncode:
                    errors.append(f"umount: {result.returncode}: {result.stderr!r}")
        except BaseException as error:
            errors.append(f"umount: {error!r}")
        try:
            if self.process is not None and self.process.poll() is None:
                self.process.terminate()
                try:
                    self.process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=3)
        except BaseException as error:
            errors.append(f"daemon: {error!r}")
        try:
            if self.log is not None:
                self.log.close()
            if self.is_mounted():
                errors.append("owned FUSE mount remains")
        except BaseException as error:
            errors.append(f"final cleanup state: {error!r}")
        return errors

    def close(self):
        if self.is_mounted():
            subprocess.run(["umount", str(self.path)], check=True, timeout=10)
        if self.process is not None:
            assert self.process.wait(timeout=10) == self.expected_exit, self.session_log()
        if self.log is not None:
            self.log.close()
        assert not self.is_mounted(), "owned FUSE mount remains"
        assert b"unexpected userspace read" not in self.session_log(), self.session_log()
        assert b"unexpected userspace write" not in self.session_log(), self.session_log()

    def __exit__(self, kind, error, traceback):
        if kind is not None:
            cleanup = self.abort()
            self.archive_failure("test_failure", cleanup)
            return False
        try:
            self.close()
        except BaseException:
            cleanup = self.abort()
            self.archive_failure("close_failure", cleanup)
            raise
        self.archive("pass")


def check_files(root):
    names = [b"short", b"x" * 255, b"l" * 256, b"a" * 508, b"b" * 509, b"c" * 1016, b"d" * 1017, b"m" * 1024, b"raw-\xff", b"\xfe" * 300]
    for i, name in enumerate(names):
        path = root + b"/" + name
        write_file(path, str(i).encode())
        assert read_file(path) == str(i).encode()
        listed = next(item for item in os.scandir(root) if item.name == name)
        assert listed.inode() == os.stat(path).st_ino
    assert set(os.listdir(root)) == set(names)
    expect_errno({errno.ENAMETOOLONG}, os.open, root + b"/" + b"z" * 1025, os.O_CREAT | os.O_RDWR, 0o600)
    expect_errno({errno.EINVAL, errno.EPERM}, os.open, root + b"/.__lnl_reserved", os.O_CREAT | os.O_RDWR, 0o600)
    for name in names:
        os.unlink(root + b"/" + name)

    path = root + b"/data"
    write_file(path, b"A" * 8192)
    ro = os.open(path, os.O_RDONLY)
    wo = os.open(path, os.O_WRONLY)
    rw = os.open(path, os.O_RDWR)
    try:
        expect_errno({errno.EBADF}, os.pwrite, ro, b"X", 0)
        expect_errno({errno.EBADF}, os.pread, wo, 1, 0)
        assert os.pwrite(wo, b"B", 0) == 1
        assert os.pread(ro, 1, 0) == b"B"
        os.fsync(wo)
        os.fdatasync(rw)
        append = os.open(path, os.O_WRONLY | os.O_APPEND)
        os.lseek(append, 0, os.SEEK_SET)
        os.write(append, b"tail")
        os.close(append)
        assert os.stat(path).st_size == 8196
        before = os.stat(path).st_mtime_ns
        mapping = mmap.mmap(rw, 8192)
        os.close(rw)
        rw = -1
        time.sleep(0.02)
        mapping[4096:4100] = b"mmap"
        mapping.flush()
        assert os.pread(ro, 4, 4096) == b"mmap"
        mapping.close()
        time.sleep(1.1)
        assert os.stat(path).st_mtime_ns > before
        os.ftruncate(wo, 32)
        assert os.stat(path).st_size == 32
        os.posix_fallocate(wo, 0, 16384)
        assert os.stat(path).st_size == 16384
        os.unlink(path)
        assert os.pread(ro, 1, 0) == b"B"
        os.pwrite(wo, b"C", 0)
        assert os.pread(ro, 1, 0) == b"C"
    finally:
        for fd in (ro, wo, rw):
            if fd >= 0:
                os.close(fd)

    for _ in range(100):
        write_file(path, b"reopen")
        with open(path, "rb") as stream:
            assert stream.read() == b"reopen"
        os.unlink(path)


def check_rename(root):
    a, b = root + b"/a", root + b"/b"
    os.mkdir(a)
    os.mkdir(b)
    os.mkdir(a + b"/child")
    expect_errno({errno.EINVAL}, os.rename, a, a + b"/child/new")
    write_file(a + b"/after-cycle", b"still writable")
    assert read_file(a + b"/after-cycle") == b"still writable"
    os.unlink(a + b"/after-cycle")
    os.rmdir(a + b"/child")
    short = a + b"/short"
    long_a = a + b"/" + b"a" * 300
    long_b = b + b"/" + b"b" * 600
    final = b + b"/final"
    write_file(short, b"source")
    opened = os.open(short, os.O_RDWR)
    for source, target in [(short, long_a), (long_a, long_b), (long_b, final)]:
        os.rename(source, target)
        assert not os.path.exists(source)
        assert read_file(target) == b"source"
        assert os.fstat(opened).st_ino == os.stat(target).st_ino
    os.chmod(final, 0)
    os.rename(final, long_a)
    assert read_file(long_a) == b"source"
    os.chmod(long_a, 0o600)
    write_file(long_b, b"target")
    target_fd = os.open(long_b, os.O_RDONLY)
    expect_errno({errno.EEXIST}, renameat2, long_a, long_b, 1)
    assert read_file(long_a) == b"source"
    assert read_file(long_b) == b"target"
    renameat2(long_a, long_b, 2)
    assert read_file(long_a) == b"target" and read_file(long_b) == b"source"
    renameat2(long_a, long_b, 2)
    expect_errno({errno.EOPNOTSUPP, errno.EINVAL}, renameat2, long_a, long_b, 4)
    expect_errno({errno.EINVAL}, renameat2, long_a, long_b, 8)
    os.replace(long_a, long_b)
    assert os.pread(target_fd, 6, 0) == b"target"
    assert read_file(long_b) == b"source"
    os.close(target_fd)
    os.close(opened)
    os.rename(long_b, long_b)
    os.unlink(long_b)
    long_dir = a + b"/" + b"d" * 700
    os.mkdir(long_dir)
    write_file(long_dir + b"/child")
    moved = b + b"/" + b"e" * 1024
    os.rename(long_dir, moved)
    assert read_file(moved + b"/child") == b"payload"
    expect_errno({errno.ENOTEMPTY, errno.EEXIST}, os.rmdir, moved)
    os.unlink(moved + b"/child")
    os.rmdir(moved)
    os.rmdir(a)
    os.rmdir(b)


def check_directory_streams(root):
    directory = root + b"/entries"
    os.mkdir(directory)
    expect_errno({errno.EISDIR}, os.truncate, directory, 0)
    names = [f"{i:05d}-".encode() + b"q" * (300 if i % 3 == 0 else 10) for i in range(600)]
    for name in names:
        write_file(directory + b"/" + name)
    retained = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    for _ in range(3):
        assert len(os.listdir(retained)) == len(names)
        entries = list(os.scandir(directory))
        assert len(entries) == len(names)
        assert {entry.name for entry in entries} == set(names)
        assert all(entry.inode() == entry.stat().st_ino for entry in entries)
    write_file(directory + b"/new")
    assert b"new" in os.listdir(directory)
    assert "new" in os.listdir(retained)
    os.unlink(directory + b"/new")
    assert b"new" not in os.listdir(directory)
    assert "new" not in os.listdir(retained)
    os.rename(directory + b"/" + names[0], directory + b"/renamed")
    assert b"renamed" in os.listdir(directory) and names[0] not in os.listdir(directory)
    assert "renamed" in os.listdir(retained)
    os.close(retained)
    os.rename(directory + b"/renamed", directory + b"/" + names[0])
    for name in names:
        os.unlink(directory + b"/" + name)
    os.rmdir(directory)



def directory_batch(fd, size=4096):
    buffer = ctypes.create_string_buffer(size)
    count = LIBC.getdents64(fd, buffer, len(buffer))
    if count < 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))
    raw, offset, result = buffer.raw[:count], 0, []
    while offset < len(raw):
        ino, cookie, length, kind = struct.unpack_from("<QqHB", raw, offset)
        assert length >= 20 and offset + length <= len(raw)
        name = raw[offset + 19:offset + length].split(b"\0", 1)[0]
        result.append((name, ino, cookie, kind))
        offset += length
    return result


def directory_all(fd, rewind=True):
    if rewind:
        os.lseek(fd, 0, os.SEEK_SET)
    result = []
    while True:
        batch = directory_batch(fd)
        if not batch:
            return result
        result.extend(batch)


def check_directory_generations(root):
    directory = root + b"/generations"
    os.mkdir(directory)
    names = [f"{i:05d}-".encode() + b"q" * (300 if i % 2 == 0 else 12) for i in range(240)]
    for name in names:
        write_file(directory + b"/" + name)
    expected = set(names)
    old = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    fresh = -1
    try:
        first = directory_batch(old, 2048)
        assert first and first[-1][0] != names[-1]
        os.unlink(directory + b"/" + names[-2])
        expected.remove(names[-2])
        added = b"99999-added-" + b"z" * 300
        write_file(directory + b"/" + added)
        expected.add(added)
        fresh = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        assert directory_batch(fresh, 2048)
        # An old nonzero-cookie handle must not finish the shared kernel cache
        # with its obsolete view after a new handle started the new generation.
        directory_all(old, rewind=False)
        verify = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            entries = directory_all(verify)
            assert {e[0] for e in entries} == expected | {b".", b".."}
            assert len(entries) == len(expected) + 2
            assert all(ino == os.stat(directory + b"/" + name).st_ino
                       for name, ino, _, _ in entries if name not in (b".", b".."))
        finally:
            os.close(verify)
        os.lseek(fresh, first[-1][2], os.SEEK_SET)
        directory_all(fresh, rewind=False)
        assert {e[0] for e in directory_all(old)} == expected | {b".", b".."}
    finally:
        os.close(old)
        if fresh >= 0:
            os.close(fresh)
    for name in expected:
        os.unlink(directory + b"/" + name)
    os.rmdir(directory)


def check_logical_parents_and_sync(root):
    a, b = root + b"/parents-a", root + b"/parents-b"
    os.mkdir(a)
    os.mkdir(b)
    left, right = a + b"/" + b"d" * 700, b + b"/" + b"e" * 1024
    os.mkdir(left)
    child = b"child-" + b"c" * 503
    write_file(left + b"/" + child)
    retained = os.open(left, os.O_RDONLY | os.O_DIRECTORY)
    try:
        assert os.fstat(retained).st_nlink == 1
        before = dict((n, ino) for n, ino, _, _ in directory_all(retained))
        assert before[b".."] == os.stat(a).st_ino
        assert dict((n, ino) for n, ino, _, _ in directory_all(retained)) == before
        current, target = left, right
        for _ in range(12):
            old_time = 1_600_000_000_000_000_000
            for parent in (a, b):
                os.utime(parent, ns=(old_time, old_time))
            os.rename(current, target)
            current, target = target, current
            parent = a if current == left else b
            expected = os.stat(parent).st_ino
            assert dict((n, ino) for n, ino, _, _ in directory_all(retained))[b".."] == expected
            opened = os.open(current, os.O_RDONLY | os.O_DIRECTORY)
            try:
                assert dict((n, ino) for n, ino, _, _ in directory_all(opened))[b".."] == expected
                os.fsync(opened)
            finally:
                os.close(opened)
            assert all(os.stat(p).st_mtime_ns > old_time for p in (a, b))
        os.unlink(current + b"/" + child)
        assert os.stat(current).st_nlink == 1
        os.fsync(retained)
        os.rmdir(current)
        assert os.fstat(retained).st_nlink == 0
    finally:
        os.close(retained)

    # Empty logical directories may still own advisory metadata/private roots.
    source, target = a + b"/source", b + b"/target"
    for directory in (source, target):
        os.mkdir(directory)
        long_child = directory + b"/" + b"x" * 1017
        old_time = 1_600_000_000_000_000_000
        os.utime(directory, ns=(old_time, old_time))
        write_file(long_child)
        assert os.stat(directory).st_mtime_ns > old_time
        os.utime(directory, ns=(old_time, old_time))
        os.unlink(long_child)
        assert os.stat(directory).st_mtime_ns > old_time
        assert os.listdir(directory) == []
    held_target = os.open(target, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.replace(source, target)
        assert os.listdir(target) == []
        assert os.fstat(held_target).st_nlink == 0
    finally:
        os.close(held_target)
    os.rmdir(target)
    for parent in (a, b):
        opened = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(opened)
        finally:
            os.close(opened)
        os.rmdir(parent)


def check_metadata_and_scope(root):
    path = root + b"/metadata"
    write_file(path)
    os.chmod(path, 0o640)
    assert os.stat(path).st_mode & 0o777 == 0o640
    os.utime(path, ns=(1_600_000_000_000_000_000, 1_600_000_001_000_000_000))
    assert os.stat(path).st_mtime_ns == 1_600_000_001_000_000_000
    os.setxattr(path, b"user.test", b"value")
    assert os.getxattr(path, b"user.test") == b"value"
    assert "user.test" in os.listxattr(path)
    os.removexattr(path, b"user.test")
    for key in [b"user.lnfs_lite.name", b"user.lnfs_lite.format", b"user.lnfs_lite.session"]:
        expect_errno({errno.EPERM, errno.EACCES, errno.EOPNOTSUPP}, os.setxattr, path, key, b"corrupt")
        expect_errno({errno.ENODATA, errno.EPERM, errno.EACCES}, os.getxattr, path, key)
        expect_errno({errno.EPERM, errno.EACCES, errno.EOPNOTSUPP}, os.removexattr, path, key)
    expect_errno({errno.ENODATA}, os.getxattr, path, b"security.capability")
    expect_errno({errno.ENODATA}, os.getxattr, path, b"user.lnfs_lite.format")
    expect_errno({errno.EOPNOTSUPP, errno.EPERM}, os.link, path, root + b"/hard")
    os.mkfifo(root + b"/fifo", 0o600)
    os.unlink(root + b"/fifo")
    symlink = root + b"/symlink"
    os.symlink(b"metadata", symlink)
    assert os.readlink(symlink) == b"metadata"
    assert read_file(symlink) == b"payload"
    rawlink = root + b"/rawlink"
    os.symlink(b"target-\xff", rawlink)
    assert os.readlink(rawlink) == b"target-\xff"
    longlink = root + b"/" + b"s" * 256
    os.symlink(b"target", longlink)
    assert os.readlink(longlink) == b"target"
    os.unlink(longlink)
    movedlink = root + b"/" + b"s" * 300
    os.rename(symlink, movedlink)
    assert read_file(movedlink) == b"payload"
    os.rename(movedlink, symlink)
    os.unlink(rawlink)
    os.unlink(symlink)
    os.unlink(path)
    assert os.statvfs(root).f_namemax == 1024


def check_concurrency(root):
    def worker(index):
        directory = root + b"/" + str(index).encode()
        os.mkdir(directory)
        for counter in range(30):
            name = str(counter).encode() + b"x" * 260
            path = directory + b"/" + name
            write_file(path, b"parallel")
            fd1 = os.open(path, os.O_RDONLY)
            fd2 = os.open(path, os.O_WRONLY)
            try:
                os.pwrite(fd2, b"P", 0)
                os.rename(path, directory + b"/renamed")
                os.unlink(directory + b"/renamed")
                assert os.pread(fd1, 8, 0) == b"Parallel"
            finally:
                os.close(fd1)
                os.close(fd2)
        os.rmdir(directory)
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(worker, range(8)))


def check_busy_unmount(mounted):
    # A cwd is a definite busy reference, unlike an already-open passthrough FD.
    previous = os.open(".", os.O_RDONLY | os.O_DIRECTORY)
    start = len(mounted.session_log())
    try:
        os.chdir(mounted.path)
        mounted.process.send_signal(signal.SIGTERM)
        deadline = time.monotonic() + 5
        while b"cannot unmount after signal" not in mounted.session_log()[start:]:
            assert time.monotonic() < deadline, mounted.session_log()
            assert mounted.process.poll() is None, mounted.session_log()
            time.sleep(0.01)
        assert b"os error 16" in mounted.session_log()[start:], mounted.session_log()
        assert mounted.is_mounted() and mounted.process.poll() is None
        write_file(mounted.path / "busy-still-serving", b"live")
        assert read_file(mounted.path / "busy-still-serving") == b"live"
        os.unlink(mounted.path / "busy-still-serving")
    finally:
        os.fchdir(previous)
        os.close(previous)
    print("PASS busy SIGTERM unmount keeps serving", flush=True)


def check_startup_rejections(binary, root):
    root = Path(root)
    mountpoint = root / "reject-mount"
    mountpoint.mkdir()
    legacy = root / "legacy"
    legacy.mkdir()
    (legacy / ".ln2_fs_index").write_bytes(b"old")
    result = subprocess.run([binary, "--backend", str(legacy), str(mountpoint)], capture_output=True, timeout=10)
    assert result.returncode != 0
    assert (legacy / ".ln2_fs_index").read_bytes() == b"old"
    assert not os.path.ismount(mountpoint)
    invalid = subprocess.run([binary, "--backend", str(legacy), str(mountpoint), "--threads", "0"], capture_output=True, timeout=10)
    assert invalid.returncode != 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary")
    parser.add_argument("--root", default=os.environ.get("LNFS_TEST_ROOT"))
    args = parser.parse_args()
    assert os.geteuid() == 0, "mounted acceptance requires root with CAP_SYS_ADMIN"
    assert Path("/dev/fuse").exists(), "/dev/fuse is required; skipping is not permitted"
    binary = str(Path(args.binary).resolve())
    if args.root is None:
        args.root = str(Path(__file__).resolve().parents[1] / "target" / "mounted")
    Path(args.root).mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="lnfs-mounted-", dir=args.root) as temporary:
        with Mount(binary, temporary) as mounted:
            root = os.fsencode(mounted.path)
            for test in [check_files, check_rename, check_directory_streams, check_directory_generations, check_logical_parents_and_sync, check_metadata_and_scope, check_concurrency]:
                test(root)
                print(f"PASS {test.__name__}", flush=True)
            long_name = b"persist-" + b"r" * 1000
            write_file(root + b"/" + long_name, b"survives remount")
            (Path(temporary) / "other").mkdir()
            duplicate = subprocess.run([binary, "--backend", str(mounted.backend), str(Path(temporary) / "other")], capture_output=True, timeout=10)
            assert duplicate.returncode != 0
            assert b"temporarily unavailable" in duplicate.stderr or b"WouldBlock" in duplicate.stderr
        with Mount(binary, temporary) as mounted:
            root = os.fsencode(mounted.path)
            assert read_file(root + b"/" + long_name) == b"survives remount"
            assert os.listdir(root) == [long_name]
            os.unlink(root + b"/" + long_name)
            check_busy_unmount(mounted)
            mounted.process.send_signal(signal.SIGTERM)
            assert mounted.process.wait(timeout=10) == 0
            assert not os.path.ismount(mounted.path)
        check_startup_rejections(binary, temporary)
        print("PASS remount, shutdown and startup rejection", flush=True)
    print("PASS mounted acceptance (no skipped mandatory tests)", flush=True)


if __name__ == "__main__":
    main()
