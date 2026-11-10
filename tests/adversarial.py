#!/usr/bin/env python3
"""Failure and restart checks against real mounts; never silently skip a prerequisite."""
import argparse
import concurrent.futures
import errno
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import threading
import time

from mounted import Mount, expect_errno, read_file, write_file


def native_path(backend, name):
    """Independent byte encoding for controlled backend fault injection."""
    base = os.fsencode(backend)
    if len(name) <= 255:
        return Path(os.fsdecode(base + b"/" + name))
    chunks = [name[i:i + 254] for i in range(0, len(name), 254)]
    parts = [b".__lnl_names"] + [b"d" + piece for piece in chunks[:-1]] + [b"e" + chunks[-1]]
    return Path(os.fsdecode(base + b"/" + b"/".join(parts)))


def private_object_rejection(binary, root):
    name = b"n" * 600
    with Mount(binary, root) as mounted:
        write_file(os.fsencode(mounted.path) + b"/" + name)
        assert os.listdir(os.fsencode(mounted.path)) == [name]
    backend = root / "backend"
    tree = backend / ".__lnl_names"
    assert not (tree / ".index").exists()

    empty = tree / ("d" + "q" * 254)
    empty.mkdir()
    with Mount(binary, root) as mounted:
        assert os.listdir(os.fsencode(mounted.path)) == [name]
    empty.rmdir()

    for invalid in [backend / ".__lnl_bad", tree / "dshort", tree / ".index",
                    tree / ".index.tmp.0000000000000000",
                    tree / ".index.tmp.0123456789abcdef", tree / ".index.tmp.NOT-VALID"]:
        invalid.write_bytes(b"must be preserved")
        with Mount(binary, root) as mounted:
            expect_errno({errno.EIO}, os.listdir, mounted.path)
            assert read_file(os.fsencode(mounted.path) + b"/" + name) == b"payload"
        assert invalid.read_bytes() == b"must be preserved"
        invalid.unlink()

    # Rmdir must validate the complete private tree before deleting any branch.
    with Mount(binary, root) as mounted:
        (mounted.path / "empty-holder").mkdir()
    holder_tree = backend / "empty-holder" / ".__lnl_names"
    holder_tree.mkdir()
    branch = holder_tree / ("d" + "z" * 254)
    branch.mkdir()
    for old_cache in (".index", ".index.tmp.0000000000000000"):
        invalid = holder_tree / old_cache
        invalid.write_bytes(b"preserve during rmdir")
        with Mount(binary, root) as mounted:
            expect_errno({errno.EIO}, os.listdir, mounted.path / "empty-holder")
            expect_errno({errno.EIO}, os.rmdir, mounted.path / "empty-holder")
        assert invalid.read_bytes() == b"preserve during rmdir"
        assert branch.is_dir()
        invalid.unlink()
    with Mount(binary, root) as mounted:
        assert os.listdir(mounted.path / "empty-holder") == []
        os.rmdir(mounted.path / "empty-holder")
        assert read_file(os.fsencode(mounted.path) + b"/" + name) == b"payload"
        os.unlink(os.fsencode(mounted.path) + b"/" + name)
        for ordinary in (".index", ".index.tmp.0000000000000000"):
            write_file(mounted.path / ordinary, b"ordinary user name")
    with Mount(binary, root) as mounted:
        assert sorted(os.listdir(mounted.path)) == [".index", ".index.tmp.0000000000000000"]
        for ordinary in (".index", ".index.tmp.0000000000000000"):
            assert read_file(mounted.path / ordinary) == b"ordinary user name"
            os.unlink(mounted.path / ordinary)
    print("PASS private old-cache rejection, raw prefix grammar and preserved unknown objects", flush=True)


def canonical_reconstruction(binary, root):
    first, second = b"a" * 300, b"b" * 509
    with Mount(binary, root) as mounted:
        write_file(os.fsencode(mounted.path) + b"/" + first, b"old")
        assert os.listdir(os.fsencode(mounted.path)) == [first]
    backend = root / "backend"
    assert os.getxattr(backend, "user.lnfs_lite.format") == b"lnfs-lite:3\n"
    expect_errno({errno.ENODATA}, os.getxattr, backend, "user.lnfs_lite.session")
    assert not (backend / ".__lnl_names" / ".index").exists()
    with Mount(binary, root) as mounted:
        prefix = os.fsencode(mounted.path) + b"/"
        assert os.listdir(os.fsencode(mounted.path)) == [first]
        assert read_file(prefix + first) == b"old"
        write_file(prefix + second, b"current")
        os.unlink(prefix + first)
        mounted.expected_exit = -signal.SIGKILL
        mounted.process.kill()
        mounted.process.wait(timeout=5)
        subprocess.run(["umount", str(mounted.path)], check=True, timeout=10)
    with Mount(binary, root) as mounted:
        assert os.listdir(os.fsencode(mounted.path)) == [second]
        assert read_file(os.fsencode(mounted.path) + b"/" + second) == b"current"
    expect_errno({errno.ENODATA}, os.getxattr, backend, "user.lnfs_lite.session")
    assert not (backend / ".__lnl_names" / ".index").exists()
    with Mount(binary, root) as mounted:
        assert os.listdir(os.fsencode(mounted.path)) == [second]
        assert read_file(os.fsencode(mounted.path) + b"/" + second) == b"current"
        os.unlink(os.fsencode(mounted.path) + b"/" + second)
    print("PASS canonical reconstruction after normal exit and SIGKILL (not a power-loss test)", flush=True)


def rejected_old_formats(binary, root):
    backend = root / "backend"
    mountpoint = root / "mount"
    backend.mkdir()
    mountpoint.mkdir()
    for marker in (b"lnfs-lite:1\n", b"lnfs-lite:2\n"):
        os.setxattr(backend, "user.lnfs_lite.format", marker)
        result = subprocess.run([binary, "--backend", str(backend), str(mountpoint)],
                                capture_output=True, timeout=10)
        assert result.returncode != 0 and b"unsupported Lnfs-Lite format" in result.stderr, result.stderr
        assert not os.path.ismount(mountpoint)
        assert os.getxattr(backend, "user.lnfs_lite.format") == marker
        assert os.listdir(backend) == []
    print("PASS exact format-1/format-2 rejection without marker or namespace changes", flush=True)


def startup_probe_recovery(binary, root):
    with Mount(binary, root) as mounted:
        write_file(mounted.path / ".__LNL_PROBE", b"legal case-distinct user name")
    backend = root / "backend"
    probe = backend / ".__lnl_probe"
    for names in [("file",), ("before",), ("after",), ("file", "before", "after")]:
        probe.mkdir()
        for name in names:
            if name == "file":
                (probe / name).write_bytes(b"unfinished probe")
            else:
                (probe / name).mkdir()
        with Mount(binary, root) as mounted:
            assert read_file(mounted.path / ".__LNL_PROBE") == b"legal case-distinct user name"
            assert not probe.exists()
    probe.mkdir()
    (probe / "file").write_bytes(b"known but preserve on validation failure")
    (probe / "unknown").write_bytes(b"unknown must survive")
    result = subprocess.run([binary, "--backend", str(backend), str(root / "mount")],
                            capture_output=True, timeout=10)
    assert result.returncode != 0 and not os.path.ismount(root / "mount")
    assert (probe / "file").read_bytes() == b"known but preserve on validation failure"
    assert (probe / "unknown").read_bytes() == b"unknown must survive"
    (probe / "unknown").unlink()
    with Mount(binary, root) as mounted:
        assert not probe.exists()
        os.unlink(mounted.path / ".__LNL_PROBE")
    print("PASS bounded startup-probe recovery and legal uppercase user entry", flush=True)


def nested_mount(binary, root):
    outside = root / "outside"
    outside.mkdir()
    (outside / "private").write_bytes(b"outside")
    with Mount(binary, root) as mounted:
        (mounted.path / "nested").mkdir()
    nested = root / "backend" / "nested"
    subprocess.run(["mount", "--bind", str(outside), str(nested)], check=True)
    try:
        with Mount(binary, root) as mounted:
            expect_errno({errno.EXDEV}, os.stat, mounted.path / "nested")
            expect_errno({errno.EXDEV}, os.stat, mounted.path / "nested" / "private")
    finally:
        subprocess.run(["umount", str(nested)], check=True, timeout=10)
    assert (outside / "private").read_bytes() == b"outside"
    print("PASS same-filesystem bind-mount traversal rejection", flush=True)


def encoded_mount_boundary(binary, root):
    name = b"encoded-mount-" + b"x" * 300
    outside = root / "outside-file"
    outside.write_bytes(b"outside must survive")
    with Mount(binary, root) as mounted:
        logical = os.fsencode(mounted.path) + b"/" + name
        write_file(logical, b"original")
        backend = native_path(mounted.backend, name)
        # Controlled fault injection keeps the frontend dentry hot so unlink
        # exercises its own name-only mount check, independently of lookup.
        os.stat(logical)
        subprocess.run(["mount", "--bind", str(outside), str(backend)], check=True)
        try:
            expect_errno({errno.EXDEV}, os.unlink, logical)
        finally:
            subprocess.run(["umount", str(backend)], check=True, timeout=10)
        assert outside.read_bytes() == b"outside must survive"
        assert read_file(logical) == b"original"
        os.unlink(logical)
    print("PASS encoded same-device bind mount rejected by unlink", flush=True)


def unsupported_encoded_objects(binary, root):
    name = b"unsupported-" + b"x" * 300
    with Mount(binary, root) as mounted:
        write_file(os.fsencode(mounted.path) + b"/" + name)
    backend = native_path(root / "backend", name)
    alias = root / "backend" / "alias"
    os.link(backend, alias)
    with Mount(binary, root) as mounted:
        expect_errno({errno.EOPNOTSUPP}, os.unlink, os.fsencode(mounted.path) + b"/" + name)
        expect_errno({errno.EOPNOTSUPP}, os.listdir, mounted.path)
    alias.unlink()
    for make in (lambda: os.symlink("missing", backend), lambda: os.mkfifo(backend)):
        backend.unlink()
        make()
        with Mount(binary, root) as mounted:
            expect_errno({errno.EOPNOTSUPP}, os.unlink, os.fsencode(mounted.path) + b"/" + name)
            expect_errno({errno.EOPNOTSUPP}, os.listdir, mounted.path)
        backend.unlink()
        backend.write_bytes(b"payload")
    print("PASS canonical long terminals reject hardlinks, symlinks and FIFO", flush=True)


def intermediate_boundary(binary, root):
    name = b"prefix-" + b"i" * 600
    outside = root / "outside-prefix"
    outside.mkdir()
    (outside / "keep").write_bytes(b"outside must survive")
    with Mount(binary, root) as mounted:
        write_file(os.fsencode(mounted.path) + b"/" + name)
    tree = root / "backend" / ".__lnl_names"
    prefix = tree / os.fsdecode(b"d" + name[:254])
    saved = root / "saved-prefix"
    prefix.rename(saved)
    os.symlink(outside, prefix)
    try:
        with Mount(binary, root) as mounted:
            logical = os.fsencode(mounted.path) + b"/" + name
            expect_errno({errno.ELOOP, errno.EOPNOTSUPP, errno.EIO}, os.stat, logical)
            expect_errno({errno.ELOOP, errno.ENOTDIR, errno.EOPNOTSUPP, errno.EIO}, os.listdir, mounted.path)
    finally:
        prefix.unlink()
        saved.rename(prefix)
    subprocess.run(["mount", "--bind", str(outside), str(prefix)], check=True)
    try:
        with Mount(binary, root) as mounted:
            expect_errno({errno.EXDEV}, os.stat, os.fsencode(mounted.path) + b"/" + name)
            expect_errno({errno.EXDEV}, os.listdir, mounted.path)
    finally:
        subprocess.run(["umount", str(prefix)], check=True, timeout=10)
    assert (outside / "keep").read_bytes() == b"outside must survive"
    with Mount(binary, root) as mounted:
        os.unlink(os.fsencode(mounted.path) + b"/" + name)
    print("PASS intermediate symlink and same-device mount traversal rejection", flush=True)



def descriptor_exhaustion(binary, root):
    with Mount(binary, root, fd_limit=128) as mounted:
        opened = []
        reached_limit = False
        try:
            for index in range(200):
                path = mounted.path / f"file-{index}"
                try:
                    opened.append(os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600))
                except OSError as error:
                    assert error.errno in (errno.EMFILE, errno.ENFILE), error
                    reached_limit = True
                    break
            assert reached_limit, "the daemon's 128-FD budget was not exercised"
        finally:
            for fd in opened:
                os.close(fd)
        write_file(mounted.path / "after-limit", b"still works")
        assert read_file(mounted.path / "after-limit") == b"still works"
        assert mounted.process.poll() is None
    print("PASS EMFILE propagation and recovery after closing handles", flush=True)


def inherited_descriptor(binary, root):
    target = 127
    expect_errno({errno.EBADF}, os.fstat, target)
    sentinel = root / "inherited-file"
    sentinel.write_bytes(b"preserve inherited descriptor")
    original = os.open(sentinel, os.O_RDONLY)
    os.dup2(original, target, inheritable=True)
    os.close(original)
    try:
        with Mount(binary, root, fd_limit=128, inherited_fds=(target,)) as mounted:
            assert os.readlink(f"/proc/{mounted.process.pid}/fd/{target}") == str(sentinel.resolve())
            assert os.pread(target, 64, 0) == b"preserve inherited descriptor"
            write_file(mounted.path / "works")
    finally:
        os.close(target)
    print("PASS occupied FD reservation target preserves inherited descriptor", flush=True)


def restart_after_kill(binary, root):
    first, second, third = b"a" * 300, b"b" * 600, b"c" * 800
    for iteration in range(6):
        with Mount(binary, root) as mounted:
            prefix = os.fsencode(mounted.path) + b"/"
            write_file(prefix + first, b"durable payload")
            data = os.open(prefix + first, os.O_RDWR)
            os.fsync(data)
            os.close(data)
            ready = threading.Event()
            stop = threading.Event()
            def rename_loop():
                source, target = first, second
                while not stop.is_set():
                    try:
                        os.rename(prefix + source, prefix + target)
                    except OSError as error:
                        assert error.errno in (errno.EIO, errno.ENOTCONN, errno.ECONNABORTED), error
                        return
                    source, target = target, source
                    ready.set()
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                worker = pool.submit(rename_loop)
                assert ready.wait(timeout=5)
                time.sleep(0.001 * (iteration + 1))
                mounted.expected_exit = -signal.SIGKILL
                mounted.process.kill()
                mounted.process.wait(timeout=5)
                stop.set()
                worker.result(timeout=5)
            subprocess.run(["umount", str(mounted.path)], check=True, timeout=10)
        with Mount(binary, root) as mounted:
            prefix = os.fsencode(mounted.path) + b"/"
            names = os.listdir(os.fsencode(mounted.path))
            assert len(names) == 1 and names[0] in (first, second), names
            assert read_file(prefix + names[0]) == b"durable payload"
            os.rename(prefix + names[0], prefix + third)
            assert read_file(prefix + third) == b"durable payload"
            os.unlink(prefix + third)
    print("PASS six daemon-kill/remount/next-rename cycles (not a power-loss test)", flush=True)


def rejected_privileges_and_backend(binary, root):
    backend = root / "backend"
    mountpoint = root / "mount"
    backend.mkdir()
    mountpoint.mkdir()
    result = subprocess.run([
        "setpriv", "--bounding-set=-sys_admin", binary,
        "--backend", str(backend), str(mountpoint),
    ], capture_output=True, timeout=10)
    assert result.returncode != 0 and b"CAP_SYS_ADMIN" in result.stderr, result.stderr
    assert not os.path.ismount(mountpoint)
    assert not os.listdir(backend)
    with tempfile.TemporaryDirectory(prefix="lnfs-unsupported-", dir="/dev/shm") as unsupported:
        result = subprocess.run([binary, "--backend", unsupported, str(mountpoint)], capture_output=True, timeout=10)
        assert result.returncode != 0 and b"backend must be" in result.stderr, result.stderr
        assert not os.listdir(unsupported)
    print("PASS missing capability and unsupported-backend startup rejection", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary")
    parser.add_argument("--root", required=True)
    args = parser.parse_args()
    assert os.geteuid() == 0
    binary = str(Path(args.binary).resolve())
    for test in [private_object_rejection, canonical_reconstruction, rejected_old_formats, startup_probe_recovery, nested_mount, encoded_mount_boundary, unsupported_encoded_objects, intermediate_boundary, descriptor_exhaustion, inherited_descriptor, restart_after_kill, rejected_privileges_and_backend]:
        with tempfile.TemporaryDirectory(prefix="lnfs-failure-", dir=args.root) as temporary:
            test(binary, Path(temporary))
    print("PASS adversarial mounted acceptance", flush=True)


if __name__ == "__main__":
    main()
