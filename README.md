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
registration, `/dev/fuse`, `/proc/self/fd`, and effective root with both
`CAP_SYS_ADMIN` and `CAP_DAC_READ_SEARCH`. Use a dedicated, case-sensitive ext4,
XFS or Btrfs backend. Startup checks actual native file-handle capture, reopen
and device/inode identity on that mount, then negotiates passthrough. Each regular
create/open requires a usable backing registration, shared while it remains
active. Missing capabilities or unsupported operations fail
explicitly; there is no fallback to permanently pinned ordinary files.

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
- Symlink names support the same 1024-byte limit; raw relative, absolute and
  dangling target strings are preserved. Native overwrite, `RENAME_NOREPLACE`
  and `RENAME_EXCHANGE` are supported, including exchanging nonempty directories.
- FIFOs and Unix socket nodes use native kernel communication. A long socket
  node name does not enlarge Linux's `sockaddr_un` address limit.
- `copy_file_range` forwards one native call with explicit offsets and returns
  its actual result, including short copies and backend errors. It does not
  promise reflink, cross-filesystem copying or a userspace copy fallback.
- Ordinary user xattrs, append, mmap and open-unlink remain supported. Only the
  mounting owner (root) is served. Hardlinks, device nodes, `RENAME_WHITEOUT`,
  ACL/security xattrs, NFS/export, multiuser serving and online migration are
  outside this release's scope.
- File data bypasses the daemon. Entry/attribute caching can delay metadata
  visibility by up to one second.
- Plain READDIR returns name/type hints. Authoritative operations still validate
  objects and routes; fsyncdir strictly validates encoded terminals before sync.
- Linked cold regular files retain opaque native file handles. Active requests,
  data handles, unlinked live files, directories and other objects still need
  FDs. Resources scale with live client activity; there is no fixed total FD or
  memory bound. Reopening cold identities adds native syscalls.

Durability requires explicit file and directory fsync. Sync both logical parents
after a cross-directory rename, and file data separately. Unsynchronized changes
need not survive power loss. Normal shutdown drains requests; it does not force
backend durability.

Lite format 3 is independent of longnamefs-rs v2 and unreleased Lite formats 1/2.
Unknown formats and unmarked nonempty backends are rejected without migration.
Use a verified copy through mounted views into a fresh backend when migrating.

## Upgrade from 0.1.0

The on-disk encoding remains format 3. Stop the old daemon normally before
starting 0.2.0. Update service/container capability policies to retain both
`CAP_SYS_ADMIN` and **`CAP_DAC_READ_SEARCH`**; the former does not imply the latter.
Do not replace the service's other required root capabilities with this pair.
The [systemd example](examples/lnfs-lite.service) keeps ordinary root capabilities
and waits for a normal unmount. Close busy clients before stopping the service.
If a stop reports a busy mount, close those clients and run `sudo umount /mnt/lnfs`
or send SIGTERM again; closing clients alone does not retry the failed unmount.

Older releases reject long symlink, FIFO and socket terminals accepted by 0.2.0.
Before a downgrade, remove or copy those unsupported objects through the mounted
0.2.0 view. Do not edit encoded backend fragments to perform a downgrade.
ZFS has not been tested or certified; the supported matrix remains ext4/XFS/Btrfs.

See [the release changes](CHANGELOG.md) and
[the design and operating contract](docs/lnfs-lite-design.md) for failure
semantics, native representation, resource costs and validation.

## Validate

```sh
cargo +1.92.0 fmt --all -- --check
cargo +1.92.0 clippy --locked --all-targets -- -D warnings
sudo env CARGO_HOME="$HOME/.cargo" RUSTUP_HOME="$HOME/.rustup" "$(command -v cargo)" +1.92.0 test --locked --all-targets
cargo +1.92.0 build --locked --release
sudo bash tests/backend.sh ext4 target/release/lnfs-lite
sudo bash tests/backend.sh xfs target/release/lnfs-lite
sudo bash tests/backend.sh btrfs target/release/lnfs-lite
```

Install the corresponding filesystem tools first. Unit tests exercise actual
native handles and require root with `CAP_DAC_READ_SEARCH` on a supported backend.
Mounted suites additionally require real passthrough and fail if prerequisites
are absent. CI runs all three backends, including the v0.2 operation and lifecycle
regressions; no required test is skipped.
Release archives target Linux x86-64 GNU with glibc 2.39 or later; source builds
use the host toolchain and libc. Kernel capabilities are checked at runtime.

Licensed under [MIT](LICENSE). Release archives include the locked dependencies'
license texts. The architecture was re-derived with access to earlier project
research; no legally isolated clean-room development claim is made.
