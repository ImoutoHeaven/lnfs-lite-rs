#!/usr/bin/env python3
"""Fixed absolute-cost measurements; no reference engine or speed acceptance gate."""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import random
import resource
import shutil
import subprocess
import sys
import tempfile
import time
import traceback

from mounted import Mount

SAMPLES = 3
GROUPS = (("short", 256, 16), ("long", 256, 300), ("maximum", 64, 1024))
BLOCK = 4096
DATA_BYTES = 32 * 1024 * 1024
RANDOM_READS = 1024


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def distribution(values):
    if not values:
        return {"count": 0}
    ordered = sorted(values)
    return {
        "count": len(values),
        "p50_ns": ordered[math.ceil(len(values) * 0.50) - 1],
        "p95_ns": ordered[math.ceil(len(values) * 0.95) - 1],
        "p99_ns": ordered[math.ceil(len(values) * 0.99) - 1],
        "min_ns": ordered[0],
        "max_ns": ordered[-1],
    }


def names(count, length, prefix):
    return [
        (prefix.encode() + f"{index:04d}".encode()).ljust(length, b"x")
        for index in range(count)
    ]


def data_block(index):
    return index.to_bytes(8, "little") + b"x" * (BLOCK - 8)


def phase(sample, label, started, latencies=(), byte_count=None):
    elapsed = time.perf_counter_ns() - started
    item = {
        "name": label, "elapsed_ns": elapsed,
        "latencies_ns": list(latencies), **distribution(latencies),
    }
    if latencies:
        item["operations_per_second"] = len(latencies) * 1e9 / elapsed
    if byte_count is not None:
        item["bytes"] = byte_count
        item["bytes_per_second"] = byte_count * 1e9 / elapsed
    sample["phases"].append(item)


def snapshot(sample, mounted, label):
    status = {}
    for line in Path(f"/proc/{mounted.process.pid}/status").read_text().splitlines():
        key, _, value = line.partition(":")
        if key in ("VmRSS", "VmHWM", "VmSize", "RssAnon", "FDSize", "Threads"):
            status[key] = value.strip()
    fields = Path(f"/proc/{mounted.process.pid}/stat").read_text().rsplit(") ", 1)[1].split()
    ticks = os.sysconf("SC_CLK_TCK")
    status.update({
        "label": label, "pid": mounted.process.pid,
        "since_sample_start_ns": time.perf_counter_ns() - sample["started_counter_ns"],
        "user_cpu_seconds": int(fields[11]) / ticks,
        "system_cpu_seconds": int(fields[12]) / ticks,
        "fd_count": len(list(Path(f"/proc/{mounted.process.pid}/fd").iterdir())),
        "open_file_limit": next(
            line.strip() for line in Path(f"/proc/{mounted.process.pid}/limits").read_text().splitlines()
            if line.startswith("Max open files")
        ),
    })
    sample["resources"].append(status)


def footprint(sample, backend, label, logical_files, logical_directories):
    objects = list(backend.rglob("*"))
    records = [(path, path.lstat()) for path in [backend, *objects]]
    directories = [path for path, _ in records if path.is_dir()]
    fragments = [
        path for path in directories
        if len(os.fsencode(path.name)) == 255 and os.fsencode(path.name).startswith(b"d")
    ]
    sample["footprints"].append({
        "label": label, "native_objects": len(records),
        "native_unique_inodes": len({(stat.st_dev, stat.st_ino) for _, stat in records}),
        "native_directories_including_root": len(directories),
        "fragment_directories": len(fragments),
        "private_tree_roots": sum(path.name == ".__lnl_names" for path in directories),
        "native_allocated_bytes_from_st_blocks": sum(stat.st_blocks * 512 for _, stat in records),
        "logical_files": logical_files, "logical_directories_including_root": logical_directories + 1,
        "native_objects_per_logical_object": len(records) / (logical_files + logical_directories + 1),
    })


def batch(sample, label, entries, action):
    started = time.perf_counter_ns()
    latencies = []
    for entry in entries:
        tick = time.perf_counter_ns()
        action(entry)
        latencies.append(time.perf_counter_ns() - tick)
    phase(sample, label, started, latencies)


def create_file(path):
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
    try:
        assert os.write(fd, b"payload") == 7
    finally:
        os.close(fd)


def io_work(sample, mounted):
    path = os.fsencode(mounted.path / "data")
    started = time.perf_counter_ns()
    latencies = []
    expected = hashlib.sha256()
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
    try:
        for group in range(DATA_BYTES // (256 * BLOCK)):
            chunk = b"".join(data_block(group * 256 + index) for index in range(256))
            expected.update(chunk)
            tick = time.perf_counter_ns()
            written = 0
            while written < len(chunk):
                count = os.write(fd, chunk[written:])
                assert count > 0
                written += count
            latencies.append(time.perf_counter_ns() - tick)
        tick = time.perf_counter_ns()
        os.fdatasync(fd)
        sample["data_fdatasync_ns"] = time.perf_counter_ns() - tick
    finally:
        os.close(fd)
    phase(sample, "sequential_write_with_fdatasync", started, latencies, DATA_BYTES)
    started = time.perf_counter_ns()
    latencies = []
    actual = hashlib.sha256()
    fd = os.open(path, os.O_RDONLY)
    try:
        received = 0
        while received < DATA_BYTES:
            tick = time.perf_counter_ns()
            chunk = os.read(fd, min(1024 * 1024, DATA_BYTES - received))
            latencies.append(time.perf_counter_ns() - tick)
            assert chunk
            actual.update(chunk)
            received += len(chunk)
        assert os.read(fd, 1) == b""
    finally:
        os.close(fd)
    assert actual.digest() == expected.digest()
    phase(sample, "sequential_read_warm_with_verification", started, latencies, DATA_BYTES)
    started = time.perf_counter_ns()
    latencies = []
    offsets = random.Random(20261110).sample(range(DATA_BYTES // BLOCK), RANDOM_READS)
    fd = os.open(path, os.O_RDONLY)
    try:
        for index in offsets:
            tick = time.perf_counter_ns()
            chunk = os.pread(fd, BLOCK, index * BLOCK)
            latencies.append(time.perf_counter_ns() - tick)
            assert chunk == data_block(index)
    finally:
        os.close(fd)
    phase(sample, "random_read_warm_with_verification", started, latencies, RANDOM_READS * BLOCK)
    sample["data_sha256"] = expected.hexdigest()


def handle_lifetimes(sample, mounted):
    started = time.perf_counter_ns()
    held = []
    regular_names = names(64, 16, "s")
    snapshot(sample, mounted, "distinct_data_handles_0_before")
    try:
        for count in (32, 64):
            while len(held) < count:
                path = os.fsencode(mounted.path / "short") + b"/" + regular_names[len(held)]
                held.append(os.open(path, os.O_RDONLY))
            snapshot(sample, mounted, f"distinct_data_handles_{count}")
    finally:
        for fd in held:
            os.close(fd)
    snapshot(sample, mounted, "distinct_data_handles_0_after_close")

    # Unique, never-listed directory inodes cannot reuse another handle's readdir cache.
    cohort = mounted.path / "view-cohort"
    os.mkdir(cohort)
    entries = names(8, 16, "s") + names(8, 300, "l")
    directories = [cohort / f"view-{index:02d}" for index in range(64)]
    for directory in directories:
        os.mkdir(directory)
        base = os.fsencode(directory)
        for entry in entries:
            create_file(base + b"/" + entry)
    expected = set(entries)
    baseline_files = sum(count for _, count, _ in GROUPS) + 1
    footprint(sample, mounted.backend, "view_cohort_setup",
              baseline_files + 64 * len(entries), len(GROUPS) + 65)
    held = []
    snapshot(sample, mounted, "distinct_directory_views_0_before")
    try:
        for count in (32, 64):
            while len(held) < count:
                fd = os.open(directories[len(held)], os.O_RDONLY | os.O_DIRECTORY)
                held.append(fd)
                assert set(os.fsencode(name) for name in os.listdir(fd)) == expected
            snapshot(sample, mounted, f"distinct_directory_views_{count}")
    finally:
        for fd in held:
            os.close(fd)
    snapshot(sample, mounted, "distinct_directory_views_0_after_close")
    for directory in directories:
        base = os.fsencode(directory)
        for entry in entries:
            os.unlink(base + b"/" + entry)
        os.rmdir(directory)
    os.rmdir(cohort)
    footprint(sample, mounted.backend, "view_cohort_removed", baseline_files, len(GROUPS))
    phase(sample, "retained_handle_and_view_full_lifetimes_with_cohort_setup_cleanup", started)


def session_result(mounted):
    log = mounted.session_log()
    return {
        "pid": mounted.process.pid if mounted.process else None,
        "exit_code": mounted.process.poll() if mounted.process else None,
        "mount_remaining": mounted.is_mounted(),
        "daemon_remaining": mounted.process is not None and mounted.process.poll() is None,
        "passthrough_negotiated": b"lnfs-lite: FUSE passthrough negotiated" in log,
        "unexpected_userspace_data_callback": (
            b"unexpected userspace read" in log or b"unexpected userspace write" in log
        ),
        "log_sha256": hashlib.sha256(log).hexdigest(),
        "artifact_name": mounted.artifact_name,
    }


def run_sample(binary, root, sample):
    sample["started_counter_ns"] = time.perf_counter_ns()
    usage_before = resource.getrusage(resource.RUSAGE_CHILDREN)
    scratch = Path(tempfile.mkdtemp(prefix="lnfs-absolute-", dir=root))
    sample["owned_scratch"] = str(scratch)
    mounts = []
    success = False
    try:
        sets = [(label, names(count, length, label[0]))
                for label, count, length in GROUPS]
        started = time.perf_counter_ns()
        first = Mount(binary, scratch, extra=("--threads", "4"))
        mounts.append(first)
        with first:
            phase(sample, "initial_mount", started)
            snapshot(sample, first, "initial_mount")
            setup = time.perf_counter_ns()
            for label, _ in sets:
                os.mkdir(first.path / label)
            phase(sample, "logical_directory_setup", setup)
            total = 0
            for label, group in sets:
                base = os.fsencode(first.path / label)
                paths = [base + b"/" + name for name in group]
                batch(sample, "create_" + label, paths, create_file)
                total += len(group)
                snapshot(sample, first, "after_create_" + label)
                footprint(sample, first.backend, "after_create_" + label, total, len(sets))

                def lookup(path):
                    assert os.stat(path).st_size == 7
                batch(sample, "lookup_postcreate_" + label, paths, lookup)
                started = time.perf_counter_ns()
                observed = set(os.listdir(base))
                elapsed = time.perf_counter_ns() - started
                assert observed == set(group)
                phase(sample, "list_" + label, started, [elapsed])
            io_work(sample, first)
            handle_lifetimes(sample, first)
            footprint(sample, first.backend, "populated", total + 1, len(sets))
            snapshot(sample, first, "before_populated_shutdown")
            started = time.perf_counter_ns()
        phase(sample, "populated_shutdown", started)
        sample["sessions"].append(session_result(first))
        started = time.perf_counter_ns()
        second = Mount(binary, scratch, extra=("--threads", "4"))
        mounts.append(second)
        with second:
            phase(sample, "fresh_daemon_remount", started)
            snapshot(sample, second, "fresh_daemon_before_scan")
            for label, group in sets:
                base = os.fsencode(second.path / label)
                started = time.perf_counter_ns()
                observed = set(os.listdir(base))
                elapsed = time.perf_counter_ns() - started
                assert observed == set(group)
                phase(sample, "fresh_daemon_scan_" + label, started, [elapsed])
            snapshot(sample, second, "fresh_daemon_after_scan")
            for label, group in sets:
                base = os.fsencode(second.path / label)
                pairs = [(base + b"/" + name, base + b"/r" + name[1:]) for name in group]
                batch(sample, "rename_" + label, pairs, lambda pair: os.rename(*pair))
                assert set(os.listdir(base)) == {b"r" + name[1:] for name in group}
                batch(sample, "unlink_" + label, [target for _, target in pairs], os.unlink)
                assert os.listdir(base) == []
                total -= len(group)
                footprint(sample, second.backend, "after_unlink_" + label, total + 1, len(sets))
            started = time.perf_counter_ns()
            os.unlink(second.path / "data")
            for label, _ in sets:
                os.rmdir(second.path / label)
            assert os.listdir(second.path) == []
            footprint(sample, second.backend, "complete_cleanup", 0, 0)
            assert list(second.backend.iterdir()) == []
            phase(sample, "complete_namespace_cleanup", started)
            snapshot(sample, second, "before_empty_shutdown")
            started = time.perf_counter_ns()
        phase(sample, "empty_shutdown", started)
        sample["sessions"].append(session_result(second))
        assert all(item["exit_code"] == 0 and not item["mount_remaining"]
                   and not item["daemon_remaining"] for item in sample["sessions"])
        started = time.perf_counter_ns()
        shutil.rmtree(scratch)
        phase(sample, "owned_fixture_removal", started)
        success = True
    except BaseException as error:
        sample["error"] = repr(error)
        sample["traceback"] = traceback.format_exc()
        raise
    finally:
        sample["status"] = "pass" if success else "fail"
        if not success:
            sample["sessions"] = [session_result(mounted) for mounted in mounts]
        sample["cleanup"] = {
            "scratch_preserved": scratch.exists(),
            "sessions": [{
                "pid": mounted.process.pid if mounted.process else None,
                "exit_code": mounted.process.poll() if mounted.process else None,
                "mount_remaining": mounted.is_mounted(),
                "daemon_remaining": mounted.process is not None and mounted.process.poll() is None,
            } for mounted in mounts],
        }
        usage_after = resource.getrusage(resource.RUSAGE_CHILDREN)
        sample["all_owned_child_cpu_seconds"] = {
            "user": usage_after.ru_utime - usage_before.ru_utime,
            "system": usage_after.ru_stime - usage_before.ru_stime,
            "scope": "daemon lifetimes and owned unmount helpers, not daemon-only CPU",
        }
        sample["full_lifecycle_elapsed_ns"] = time.perf_counter_ns() - sample.pop("started_counter_ns")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--root", required=True, type=Path, help="existing owned ext4 test filesystem")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    args.output = args.output.resolve()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    artifacts = args.output.parent / (args.output.stem + "-artifacts")
    artifacts.mkdir(exist_ok=True)
    os.environ["LNFS_TEST_ARTIFACTS"] = str(artifacts)
    report = {
        "status": "running", "samples": [],
        "policy": "No relative or absolute speed gate. Pass means execution, assertions and cleanup succeeded.",
        "method": {
            "samples": SAMPLES, "workers": 4, "groups": GROUPS,
            "sequential_bytes": DATA_BYTES, "random_reads": RANDOM_READS,
            "random_block_bytes": BLOCK, "random_seed": 20261110,
            "handle_and_view_levels": [0, 32, 64, 0],
            "data_handle_cohort": "one read handle for each of 64 distinct existing short files; successful mandatory-passthrough opens imply active per-inode backing registrations, not directly counted kernel allocations",
            "directory_view_cohort": "64 unique never-listed directories, 8 short plus 8 300-byte names each (1024 additional files); retain one FD after each directory's first listing; all cohort creation and removal is included in lifecycle timing",
            "percentiles": "nearest-rank within each operation batch; small-sample p99 is near or at maximum",
            "timing": "monotonic perf_counter_ns; phase elapsed includes Python loop/generation/verification, per-operation samples time named syscalls; complete lifecycle includes resource sampling, fixture setup/removal, cleanup and both shutdowns",
            "cache_conditions": "postcreate lookup may hit FUSE entry/attribute caches; sequential/random reads follow writes and are warm; fresh-daemon scan resets daemon/FUSE state only, host backend caches remain warm",
            "observability": "daemon /proc snapshots are point samples, not peak FD guarantees; RSS/HWM omit kernel caches/backings and other processes; live inode/in-flight pins and backing registrations are not individually observable; FDSize is kernel FD-table capacity; closing client FDs may precede asynchronous FUSE release, final unmount/drain and process exit establish release",
            "footprint": "native objects include backend root; st_blocks excludes unreported filesystem metadata; fresh unique long prefixes expose native fragment amplification",
        },
    }
    result = 1
    try:
        binary, root = args.binary.resolve(strict=True), args.root.resolve(strict=True)
        assert os.geteuid() == 0, "root is required"
        assert root.is_dir() and os.access(binary, os.X_OK)
        mount = json.loads(subprocess.check_output(
            ["findmnt", "--json", "--target", str(root), "--output", "TARGET,SOURCE,FSTYPE,OPTIONS"],
            text=True))["filesystems"][0]
        assert mount["fstype"] == "ext4", mount
        repo = Path(__file__).resolve().parent.parent
        inputs = [*sorted((repo / "src").glob("*.rs")), repo / "Cargo.toml", repo / "Cargo.lock",
                  Path(__file__).resolve(), Path(__file__).resolve().with_name("mounted.py")]
        report["inputs_sha256"] = {str(path.relative_to(repo)): digest(path) for path in inputs}
        report["environment"] = {
            "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "uname": platform.uname()._asdict(), "backend_mount": mount,
            "binary": str(binary), "binary_sha256": digest(binary),
            "binary_version": subprocess.check_output([str(binary), "--version"], text=True).strip(),
            "cpu_affinity": sorted(os.sched_getaffinity(0)), "cpu_count": os.cpu_count(),
            "client_fd_limits": resource.getrlimit(resource.RLIMIT_NOFILE),
            "loadavg": list(os.getloadavg()),
            "cgroup": Path("/proc/self/cgroup").read_text(),
            "cgroup_limits": {
                name: (Path("/sys/fs/cgroup") / name).read_text().strip()
                for name in ("cpu.max", "cpuset.cpus.effective", "memory.max")
                if (Path("/sys/fs/cgroup") / name).exists()
            },
            "constraint_caveat": "shared host; recorded visible cgroup/affinity is not proof of no ancestor or host contention",
        }
        for index in range(SAMPLES):
            sample = {"number": index + 1, "phases": [], "resources": [], "footprints": [], "sessions": []}
            report["samples"].append(sample)
            try:
                run_sample(binary, root, sample)
            finally:
                args.output.write_text(json.dumps(report, indent=2) + "\n")
            print(f"sample {index + 1}/{SAMPLES}: pass, full lifecycle {sample['full_lifecycle_elapsed_ns'] / 1e9:.3f}s",
                  flush=True)
        report["status"] = "pass"
        result = 0
    except BaseException as error:
        report["status"] = "fail"
        report["error"] = repr(error)
        report["traceback"] = traceback.format_exc()
        print(report["traceback"], file=sys.stderr, flush=True)
    finally:
        if "inputs_sha256" in report:
            try:
                after = {str(path.relative_to(repo)): digest(path) for path in inputs}
                binary_after = digest(binary)
                report["integrity"] = {
                    "inputs_sha256_after": after, "binary_sha256_after": binary_after,
                    "unchanged": after == report["inputs_sha256"]
                    and binary_after == report["environment"]["binary_sha256"],
                }
                if not report["integrity"]["unchanged"]:
                    report["status"] = "fail"
                    report.setdefault("error", "measurement inputs changed during execution")
                    result = 1
            except BaseException as error:
                report["integrity"] = {"unchanged": False, "error": repr(error)}
                report["status"] = "fail"
                report.setdefault("error", repr(error))
                result = 1
        report["finished_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        args.output.write_text(json.dumps(report, indent=2) + "\n")
        print(f"{report['status']}: {args.output}", flush=True)
    return result


if __name__ == "__main__":
    raise SystemExit(main())
