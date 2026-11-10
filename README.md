# lnfs-lite-rs

A thin Linux FUSE filesystem for raw filenames up to **1024 bytes**.
Short names stay native. Longer names are represented by reversible native
directory fragments; the terminal entry is the actual file or directory.
Regular-file data uses **mandatory kernel FUSE passthrough**.

There is no database, userspace WAL, persistent name index or background storage
service. Directory listings belong to their open handles; no cross-handle name
cache is maintained.

## Build and mount

Requires Rust 1.92+, Linux 6.12+ with enabled FUSE passthrough and O_PATH backing
registration, `/dev/fuse`, `/proc/self/fd`, effective root with `CAP_SYS_ADMIN`,
and a dedicated, case-sensitive ext4, XFS or Btrfs backend. Passthrough negotiation and backing
registration are checked and fail explicitly when unavailable.

```sh
cargo +1.92.0 build --release --locked
mkdir -p /srv/lnfs-backend /mnt/lnfs
sudo target/release/lnfs-lite --backend /srv/lnfs-backend /mnt/lnfs
```

The process stays in the foreground. Use `sudo umount /mnt/lnfs` to stop it.
SIGINT/SIGTERM requests a normal unmount; a busy mount continues serving.
`--threads COUNT` accepts 1–64 and defaults to 4.

The backend and mountpoint must be disjoint directories; the mountpoint must
be empty. First use requires an empty backend. Keep all backend changes behind
the mounted view, including between mounts. Nested mounts are unsupported.

## Supported behavior

- Regular files and directories support short and long names, including
  non-UTF-8 bytes. Names starting with `.__lnl_` are reserved.
- Short symlinks, native overwrite/`RENAME_NOREPLACE`, ordinary user xattrs,
  append, mmap and open-unlink are supported.
- Only the mounting owner (root) is served. Hardlinks, special-file creation,
  long symlinks, ACL/security xattrs, NFS/export and online migration are
  outside this release's scope.
- File data bypasses the daemon. Entry/attribute caching can delay metadata
  visibility by up to one second.
- Open inode pins, data handles and directory views consume resources according
  to live client activity. There is no claim of a fixed total memory or FD bound.

Durability requires explicit file and directory fsync. Sync both logical parents
after a cross-directory rename, and file data separately. Unsynchronized changes
need not survive power loss. Normal shutdown drains requests; it does not force
backend durability.

Lite format 3 is independent of longnamefs-rs v2 and unreleased Lite formats 1/2.
Unknown formats and unmarked nonempty backends are rejected without migration.
Use a verified copy through mounted views into a fresh backend when migrating.

See [the design and operating contract](docs/lnfs-lite-design.md) for failure
semantics, native representation, resource costs and validation.

## Validate

```sh
cargo +1.92.0 fmt --all -- --check
cargo +1.92.0 clippy --locked --all-targets -- -D warnings
cargo +1.92.0 test --locked --all-targets
cargo +1.92.0 build --locked --release
sudo bash tests/backend.sh ext4 target/release/lnfs-lite
sudo bash tests/backend.sh xfs target/release/lnfs-lite
sudo bash tests/backend.sh btrfs target/release/lnfs-lite
```

Install the corresponding filesystem tools first. Mounted suites require real
passthrough and fail if prerequisites are absent. CI runs all three backends.
Release archives target Linux x86-64 GNU with glibc 2.39 or later; source builds
use the host toolchain and libc. Kernel capabilities are checked at runtime.

Licensed under [MIT](LICENSE). Release archives include the locked dependencies'
license texts. The architecture was re-derived with access to earlier project
research; no legally isolated clean-room development claim is made.
