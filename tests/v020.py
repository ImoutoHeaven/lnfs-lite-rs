#!/usr/bin/env python3
"""Required v0.2 native operations and cold-identity lifecycle acceptance."""
import argparse
import concurrent.futures
import errno
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import tempfile
import time

from mounted import (Mount, directory_all, expect_errno, read_file,
                     renameat2, write_file)


def copy_ranges(binary, root):
    with Mount(binary, root) as mounted:
        source, target = mounted.path / "source", mounted.path / "target"
        payload = bytes(range(256)) * 32
        write_file(source, payload)
        write_file(target, b"")
        old = 1_600_000_000_000_000_000
        os.utime(target, ns=(old, old))
        src = os.open(source, os.O_RDWR)
        dst = os.open(target, os.O_RDWR)
        readonly = os.open(target, os.O_RDONLY)
        try:
            os.lseek(src, 13, os.SEEK_SET)
            os.lseek(dst, 23, os.SEEK_SET)
            copied = os.copy_file_range(src, dst, 4096, 100, 200)
            assert copied == 4096
            assert os.pread(dst, copied, 200) == payload[100:4196]
            assert os.lseek(src, 0, os.SEEK_CUR) == 13
            assert os.lseek(dst, 0, os.SEEK_CUR) == 23
            assert os.copy_file_range(src, dst, 0, 0, 0) == 0
            assert os.copy_file_range(src, dst, 100, len(payload), 0) == 0
            assert os.copy_file_range(src, dst, 100, len(payload) - 2, 5000) == 2
            assert os.pread(dst, 2, 5000) == payload[-2:]
            expect_errno({errno.EINVAL}, os.copy_file_range, src, src, 100, 0, 1)
            expect_errno({errno.EBADF}, os.copy_file_range, src, readonly, 1, 0, 0)
            os.unlink(source)
            os.unlink(target)
            assert os.copy_file_range(src, dst, 128, 256, 6000) == 128
            assert os.pread(dst, 128, 6000) == payload[256:384]
            result = os.fstat(dst)
            assert result.st_size == 6128 and result.st_nlink == 0
            assert result.st_mtime_ns > old and result.st_ctime_ns > old
            os.fsync(dst)
        finally:
            for fd in (src, dst, readonly):
                os.close(fd)
    print("PASS native copy range offsets, zero/EOF/short result, errors and unlinked handles", flush=True)


def long_symlinks(binary, root):
    with Mount(binary, root) as mounted:
        base = os.fsencode(mounted.path)
        write_file(base + b"/target", b"logical target")
        directory = base + b"/links"
        os.mkdir(directory)
        names = [b"s" * length for length in (255, 256, 300, 508, 509, 1016, 1017, 1024)]
        names.append(b"raw-\xff" + b"r" * 295)
        for name in names:
            link = directory + b"/" + name
            for target in (b"../target", base + b"/target", b"missing-\xfe"):
                os.symlink(target, link)
                observed = os.lstat(link)
                assert stat.S_ISLNK(observed.st_mode) and observed.st_nlink == 1
                assert os.readlink(link) == target
                if target.startswith(b"missing"):
                    expect_errno({errno.ENOENT}, os.stat, link)
                else:
                    assert read_file(link) == b"logical target"
                short = directory + b"/short"
                os.rename(link, short)
                assert os.readlink(short) == target
                os.rename(short, link)
                assert os.readlink(link) == target
                os.unlink(link)
        os.rmdir(directory)
        os.unlink(base + b"/target")
        assert os.listdir(base) == []
    print("PASS long/raw symlink names, logical relative/absolute/dangling targets and rename", flush=True)


def exchange(binary, root):
    with Mount(binary, root) as mounted:
        base = os.fsencode(mounted.path)
        parents = (base + b"/left", base + b"/right")
        for parent in parents:
            os.mkdir(parent)
        for cross in (False, True):
            for length in (5, 300, 1024):
                for kinds in (("file", "file"), ("file", "dir"), ("dir", "file"), ("dir", "dir")):
                    left = parents[0] + b"/" + b"a" * length
                    right_parent = parents[1] if cross else parents[0]
                    right = right_parent + b"/" + b"b" * length
                    paths = (left, right)
                    held = []
                    identities = []
                    try:
                        for index, (path, kind) in enumerate(zip(paths, kinds)):
                            if kind == "dir":
                                os.mkdir(path)
                                write_file(path + b"/child", bytes([65 + index]))
                                fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
                                expected_parent = parents[0] if index == 0 else right_parent
                                assert dict((n, ino) for n, ino, _, _ in directory_all(fd))[b".."] == os.stat(expected_parent).st_ino
                                held.append((fd, index))
                            else:
                                write_file(path, bytes([65 + index]))
                            identities.append(os.lstat(path).st_ino)
                        renameat2(left, right, 2)
                        assert [os.lstat(path).st_ino for path in paths] == identities[::-1]
                        for index, (path, kind) in enumerate(zip(paths[::-1], kinds)):
                            assert read_file(path + b"/child" if kind == "dir" else path) == bytes([65 + index])
                        for fd, old_index in held:
                            new_parent = right_parent if old_index == 0 else parents[0]
                            expected = os.stat(new_parent).st_ino
                            assert os.stat(b"..", dir_fd=fd).st_ino == expected
                            assert dict((n, ino) for n, ino, _, _ in directory_all(fd))[b".."] == expected
                        renameat2(left, right, 2)
                        for path, kind in zip(paths, kinds):
                            if kind == "dir":
                                os.unlink(path + b"/child")
                                os.rmdir(path)
                            else:
                                os.unlink(path)
                    finally:
                        for fd, _ in held:
                            os.close(fd)
        same, missing = parents[0] + b"/same", parents[1] + b"/missing"
        write_file(same)
        renameat2(same, same, 2)
        for flags in (3, 6, 18, 0x80000000):
            expect_errno({errno.EINVAL}, renameat2, same, same, flags)
        expect_errno({errno.ENOENT}, renameat2, same, missing, 2)
        expect_errno({errno.ENOENT}, renameat2, missing, same, 2)
        os.unlink(same)
        for length in (5, 300):
            ancestor = parents[0] + b"/" + b"d" * length
            child = ancestor + b"/child"
            os.mkdir(ancestor)
            os.mkdir(child)
            expect_errno({errno.EINVAL}, os.rename, ancestor, child + b"/descendant")
            expect_errno({errno.EINVAL}, renameat2, ancestor, child, 2)
            write_file(ancestor + b"/still-live")
            os.unlink(ancestor + b"/still-live")
            os.rmdir(child)
            os.rmdir(ancestor)
        for parent in parents:
            os.rmdir(parent)
    print("PASS EXCHANGE type/name/parent matrix, both held dotdots, flags and ancestor rejection", flush=True)


def special_nodes(binary, root):
    with Mount(binary, root) as mounted:
        base = os.fsencode(mounted.path)
        for length in (5, 300, 1024):
            path = base + b"/" + b"f" * length
            os.mkfifo(path, 0o640)
            result = os.lstat(path)
            assert stat.S_ISFIFO(result.st_mode) and result.st_mode & 0o777 == 0o640
            expect_errno({errno.ENXIO}, os.open, path, os.O_WRONLY | os.O_NONBLOCK)
            reader = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
            writer = -1
            try:
                assert os.read(reader, 16) == b""
                writer = os.open(path, os.O_WRONLY | os.O_NONBLOCK)
                expect_errno({errno.EAGAIN}, os.read, reader, 1)
                assert os.write(writer, b"fifo") == 4
                assert os.read(reader, 4) == b"fifo"
                os.unlink(path)
                assert os.write(writer, b"held") == 4
                assert os.read(reader, 4) == b"held"
                os.close(writer)
                writer = -1
                assert os.read(reader, 1) == b""
            finally:
                os.close(reader)
                if writer >= 0:
                    os.close(writer)
        blocking = base + b"/blocking"
        os.mkfifo(blocking, 0o600)
        child = subprocess.Popen(
            [sys.executable, "-c",
             "import os,sys; f=os.open(sys.argv[1],os.O_RDONLY); b=os.read(f,4); os.close(f); sys.stdout.buffer.write(b)",
             os.fsdecode(blocking)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            time.sleep(0.05)
            assert child.poll() is None, "blocking reader returned without a writer"
            deadline = time.monotonic() + 5
            while True:
                try:
                    fd = os.open(blocking, os.O_WRONLY | os.O_NONBLOCK)
                    break
                except OSError as error:
                    assert error.errno == errno.ENXIO and time.monotonic() < deadline
                    time.sleep(0.01)
            try:
                assert os.write(fd, b"sync") == 4
            finally:
                os.close(fd)
            out, err = child.communicate(timeout=5)
            assert child.returncode == 0 and out == b"sync", (out, err)
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=5)
            os.unlink(blocking)
        # A filesystem socket node may have a long name; sockaddr_un does not.
        for length in (300, 1024):
            path = base + b"/" + b"s" * length
            os.mknod(path, stat.S_IFSOCK | 0o600)
            assert stat.S_ISSOCK(os.lstat(path).st_mode)
            os.unlink(path)
        path, moved = base + b"/socket", base + b"/moved"
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
            server.bind(path)
            os.chmod(path, 0o600)
            assert os.lstat(path).st_mode & 0o777 == 0o600
            server.listen(1)
            os.chmod(path, 0)
            denied = subprocess.run([
                "setpriv", "--bounding-set=-dac_override,-dac_read_search",
                sys.executable, "-c",
                "import errno,socket,sys\n"
                "with socket.socket(socket.AF_UNIX) as s:\n"
                " try: s.connect(sys.argv[1])\n"
                " except OSError as e: sys.exit(0 if e.errno == errno.EACCES else 2)\n"
                " sys.exit(1)\n",
                os.fsdecode(path),
            ], capture_output=True, timeout=5)
            assert denied.returncode == 0, denied.stderr
            os.chmod(path, 0o600)
            os.rename(path, moved)
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.settimeout(5)
                client.connect(moved)
                accepted, _ = server.accept()
                with accepted:
                    accepted.settimeout(5)
                    client.sendall(b"native ipc")
                    assert accepted.recv(10) == b"native ipc"
                    accepted.sendall(b"reply")
                    assert client.recv(5) == b"reply"
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stale:
            expect_errno({errno.ECONNREFUSED}, stale.connect, moved)
        os.unlink(moved)
        for kind in (stat.S_IFCHR, stat.S_IFBLK):
            expect_errno({errno.EOPNOTSUPP, errno.EPERM}, os.mknod,
                         base + b"/device", kind | 0o600, os.makedev(1, 7))
        assert os.listdir(base) == []
    print("PASS FIFO blocking/nonblocking/EOF/unlink, native socket communication, device rejection", flush=True)


def cold_lifetimes(binary, root):
    with Mount(binary, root) as mounted:
        path, victim = mounted.path / "file", mounted.path / "victim"
        write_file(path, b"old")
        held = os.open(path, os.O_PATH)
        try:
            ino = os.fstat(held).st_ino
            os.unlink(path)
            write_file(path, b"replacement")
            before = os.fstat(held)
            assert before.st_ino == ino and before.st_nlink == 0 and before.st_size == 3
            assert read_file(path) == b"replacement"
        finally:
            os.close(held)
        write_file(victim, b"victim")
        held = os.open(victim, os.O_PATH)
        try:
            ino = os.fstat(held).st_ino
            os.replace(path, victim)
            before = os.fstat(held)
            assert before.st_ino == ino and before.st_nlink == 0 and before.st_size == 6
            assert read_file(victim) == b"replacement"
        finally:
            os.close(held)
        held = os.open(victim, os.O_RDWR)
        try:
            os.unlink(victim)
            assert os.pwrite(held, b"R", 0) == 1
            assert os.pread(held, 11, 0) == b"Replacement"
        finally:
            os.close(held)

        def churn(index):
            current = mounted.path / f"churn-{index}"
            for _ in range(125):
                write_file(current, b"old")
                fd = os.open(current, os.O_PATH)
                try:
                    old = os.fstat(fd).st_ino
                    os.unlink(current)
                    write_file(current, b"new identity")
                    prior = os.fstat(fd)
                    assert prior.st_ino == old and prior.st_size == 3 and prior.st_nlink == 0
                    assert os.stat(current).st_size == 12
                finally:
                    os.close(fd)
                os.unlink(current)
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(churn, range(4)))
        assert os.listdir(mounted.path) == []
    print("PASS O_PATH unlink/overwrite, first open-unlink write and 500 concurrent identity churn rounds", flush=True)


def rejected_rename_budget(binary, root):
    report = {}
    with Mount(binary, root, fd_limit=128) as mounted:
        targets = [os.fsencode(mounted.path / f"t{i}") for i in range(3000)]
        for target in targets:
            write_file(target, b"x")
        source, directory, missing = [os.fsencode(mounted.path / name)
                                      for name in ("source", "dir", "missing")]
        write_file(source, b"original")
        os.mkdir(directory)

        def count():
            return len(list(Path(f"/proc/{mounted.process.pid}/fd").iterdir()))
        report["initial_fd"] = count()
        for case, path, flags, expected in (
            ("noreplace", source, 1, errno.EEXIST),
            ("invalid_flags", source, 16, errno.EINVAL),
            ("missing_source", missing, 0, errno.ENOENT),
            ("type_mismatch", directory, 0, errno.ENOTDIR),
        ):
            for target in targets:
                os.stat(target)
                expect_errno({expected}, renameat2, path, target, flags)
            report[case] = {"attempts": len(targets), "fd": count()}
            assert report[case]["fd"] <= report["initial_fd"] + 8, report
        assert read_file(source) == b"original"
        # EXCHANGE does not delete objects and must not retain temporary victim pins.
        for target in targets:
            renameat2(source, target, 2)
            renameat2(source, target, 2)
        report["exchange"] = {"attempts": 2 * len(targets), "fd": count()}
        assert report["exchange"]["fd"] <= report["initial_fd"] + 8, report
        assert read_file(source) == b"original"
        for target in targets:
            os.unlink(target)
        os.unlink(source)
        os.rmdir(directory)
        report["cleanup_fd"] = count()
    print("PASS 12000 rejected renames and 6000 exchanges under RLIMIT_NOFILE=128 " +
          json.dumps(report, sort_keys=True), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary")
    parser.add_argument("--root", required=True)
    args = parser.parse_args()
    assert os.geteuid() == 0, "required mounted tests need root and both capabilities"
    binary = str(Path(args.binary).resolve())
    for test in (copy_ranges, long_symlinks, exchange, special_nodes,
                 cold_lifetimes, rejected_rename_budget):
        with tempfile.TemporaryDirectory(prefix="lnfs-v020-", dir=args.root) as temporary:
            test(binary, Path(temporary))
    print("PASS v0.2 mounted acceptance (no skipped mandatory tests)", flush=True)


if __name__ == "__main__":
    main()
