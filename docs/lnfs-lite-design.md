# Lnfs-Lite design and operating contract

## Purpose

Lnfs-Lite is an owner-only Linux filename shim for raw components up to 1024
bytes. Native directory entries own names; native terminal inodes own object
identity, attributes and data. Regular-file data must use kernel FUSE
passthrough. There is no database, userspace WAL, persistent name index or
background storage maintenance.

This architecture was re-derived from native filesystem capabilities after
reviewing earlier project research, including
[longnamefs-rs v2](https://github.com/ImoutoHeaven/longnamefs-rs/tree/b603782ef85f1b0988fb4c440b863506ab4e6e5e).
It is MIT licensed; this is not a claim of legally isolated clean-room
development. Historical relative-performance gates are retired. Correctness,
resource recovery and real passthrough validation remain required.

## Supported system and operations

Require effective root with CAP_SYS_ADMIN and CAP_DAC_READ_SEARCH, /dev/fuse,
/proc/self/fd and Linux 6.12+ with enabled FUSE passthrough and O_PATH backing registration. Upstream
Linux added O_PATH registration in 6.12; earlier passthrough support alone is
insufficient for this implementation. Distribution backports are not certified.
The upstream binding is fuser 0.17.0. Negotiation and backing registration must
succeed; unexpected userspace read/write callbacks return EIO. Startup also
captures and reopens a native handle on the actual backend and checks device/inode
identity. CAP_SYS_ADMIN does not imply CAP_DAC_READ_SEARCH; service policies must
retain both, along with their other required root capabilities. There is no
cold-handle fallback. Writeback cache is disabled. Four blocking request receivers are
the default, with cloned FUSE descriptors; --threads accepts 1 through 64.

The mount uses owner-only access, default_permissions, nosuid and nodev. The
backend must be one case-sensitive ext4, XFS or Btrfs filesystem. Backend and
mountpoint are disjoint canonical directories, and the mountpoint is empty.
Nested mounts and direct backend modifications, including between mounts,
are unsupported. A nonblocking exclusive flock on the backend root excludes
cooperating daemons; it cannot stop external root changes.

| Operation | Contract |
| --- | --- |
| Regular files and directories | Raw names up to 1024 bytes |
| Symlinks | Names up to 1024 bytes; relative/absolute/dangling target bytes preserved |
| FIFO / Unix socket nodes | Names up to 1024 bytes; kernel communication; socket addresses retain Linux sockaddr_un limit |
| Hardlinks and character/block device nodes | EOPNOTSUPP |
| Rename | Native overwrite, RENAME_NOREPLACE and RENAME_EXCHANGE |
| WHITEOUT / invalid combinations | EOPNOTSUPP / EINVAL |
| copy_file_range | One native call, explicit checked offsets, no userspace fallback |
| Ordinary user xattrs | Forwarded except private Lnfs-Lite keys |
| ACL/security/trusted xattr changes | Unsupported |
| NFS/export, multiuser serving, online migration | Unsupported |

Entry and attribute TTL is one second. Native passthrough supplies file data and
size; cached metadata, including timestamps after mmap writes, may lag within
that interval. Release archives target Linux x86-64 GNU and require glibc 2.39
or later. Build-time ABI inspection checks this floor; runtime negotiation
checks the required kernel capabilities. This does not certify every kernel or
distribution with those version numbers.

## Canonical format 3

| Item | Value |
| --- | --- |
| Reserved logical prefix | `.__lnl_` |
| Root format xattr | `user.lnfs_lite.format` |
| Exact format bytes | `lnfs-lite:3\n` |
| Private name-tree root | `.__lnl_names` inside each logical directory |
| Root-only startup probe | `.__lnl_probe` |

Names are raw bytes, with no Unicode normalization. Reject empty names, dot,
dotdot, NUL, slash, the reserved prefix and names longer than 1024 bytes.
Names of at most 255 bytes remain direct native entries.

Long names split into 254-byte pieces beneath the private tree root.
Intermediate components are byte `d` plus exactly 254 name bytes; the terminal
is byte `e` plus the final 1–254 bytes. A reconstructed name must contain
256–1024 bytes and one to four intermediate components. The terminal is the
actual user inode. This representation is injective and reversible without a
hash collision table or separate name-to-object transaction.

A unique 300-byte name needs one intermediate directory; a unique 1024-byte
name needs four. Shared prefixes reduce that cost. The private root is separate.
Valid empty prefixes contain no logical object. Unknown or malformed private
objects, excessive depth and unsupported terminal types cause errors and are
preserved. Authoritative operations reject multiply linked nondirectories and
nested mounts. READDIR may list otherwise-supported terminal d_type hints before
link-count/mount checks; listing is not certification of an object's validity. Historical `.index`
and `.index.tmp.*` objects are unknown inside a private tree; ordinary short
logical names such as `.index` remain legal.

Private `user.lnfs_lite.*` xattrs are hidden and cannot be changed through
the mount. An unmarked nonempty backend or any other format marker is rejected
without modifying it. Format 3 is independent of v2 and unreleased Lite formats
1/2. Migration is a verified copy through mounted views into a fresh backend;
there is no format guessing or in-place migration. Version 0.2.0 retains this
encoding but accepts long symlink/FIFO/socket terminals that 0.1.0 rejects.
Remove or copy those objects through the 0.2.0 mount before downgrading. ZFS has
not received the required complete validation and is not certified.

## FD-relative access and native work

Resolution starts from a stable logical-directory FD. openat2 uses
RESOLVE_BENEATH, RESOLVE_NO_XDEV and RESOLVE_NO_SYMLINKS, without fallback.
Final O_PATH|O_NOFOLLOW preserves symlink identity; intermediate symlinks
remain forbidden. Full logical ancestor paths are never reconstructed.

A borrowed Directory pairs a validated FD with its native device/inode identity.
The owning Node, namespace root or test Entry supplies both values together.
The wrapper checks immutable directory type and adds no FD or state. Mutable
permissions, timestamps and link counts are read live. Anchors used only as
*at bases can be O_PATH; enumeration, validation and directory sync use fresh
readable directory FDs.

Name borrows validated input and encodes into a fixed 1047-byte buffer.
Canonical walking reuses initialized 32 KiB buffers by fragment depth, at most
five for the private tree. Each stream has a fresh owned FD and independent
cursor. getdents64 parsing validates record size, alignment and NUL termination.
ENOENT on an already-open removed directory is EOF; other errors remain errors.

| Operation | Necessary native work and ownership |
| --- | --- |
| Lookup | Strict relative open, native identity/type/link/mount checks; a directory also pins its logical parent |
| Create/mkdir/symlink/mknod | Prepare missing canonical prefixes, one terminal creation, validation/publication; long names touch logical-parent timestamps |
| Rename | Validate both routes, prepare moved directory parents, one terminal renameat2, parent updates and ordinary-rename old-prefix pruning |
| EXCHANGE | Both endpoints exist; prepare both directory parents, one native exchange, update both parents; no empty-target cleanup, prefix creation or pruning |
| Unlink/rmdir | One terminal removal after validation, then eager empty-prefix pruning; directories validate private branches before removal |
| READDIR | Fresh scan for each new/rewound/changed view, strict fragment grammar/routes, terminal hints and one byte-order sort |
| Open | Materialize a linked cold regular identity if necessary, reopen in requested mode, register backing only when no live registration exists |
| copy_file_range | Retain source/target data handles across one native call; handle-table locks end before the call |
| File fsync | One native fsync/fdatasync on the handle's data FD |
| Directory fsync | Bottom-up private-fragment sync, private root, then logical directory |

Path depth, existing prefixes and listing size determine the exact syscall and
allocation counts. No constant count is claimed for recursive operations.
Short and encoded-terminal READDIR entries are native inode/type hints; unknown
d_type requires a strict stat. Supported types are regular, directory, symlink,
FIFO and socket. Actual lookup/open/removal still validates objects and routes.
The complete private-fragment grammar, depth and intermediate directory routes
are checked before the first listing reply; a late error discards that reply.
ListingHints and StrictDurability are distinct traversal purposes. fsyncdir
strictly checks every encoded terminal and syncs private fragments bottom-up;
it does not recursively stat every ordinary short child. Reconstructed names
allocate their exact prefix-plus-suffix capacity once, without a new cache.

## Namespace and mutation outcomes

One namespace read/write guard coordinates resolution, publication, logical
parent updates and directory generations. Lookup holds its read guard through
inode interning; creation holds its write guard through publication and first
intern. The handle-table mutex only retrieves strong references. The inode-table mutex
serializes cold materialization and pin removal, including the required native
handle reopen/identity check and pin fstat; it must not release a token before
reopen and let deletion overtake it. Namespace mutation remains globally
serialized. There are no per-directory locks or new notification protocols.

Long changes touch logical-parent mtime/ctime without changing atime. Touch
once for a same-parent change, both parents for a cross-parent move.
Before moving a directory, duplicate its new logical-parent FD. After known
native success, update the live Node before any fallible follow-up work.

Track mutation outcome as Unchanged, Committed or Unknown. Mark Committed
immediately after known terminal success. Later timestamp, registration or
cleanup errors do not justify deleting a successfully created object or
rolling back a rename.

Only these dispatched terminal-syscall errors establish no publication:

| Mutator | Known rejection errno values |
| --- | --- |
| Exclusive regular create/open | EEXIST, EMFILE, ENFILE |
| Mkdir, mknod or symlink | EEXIST, ENOENT, ENOTDIR |
| File unlink | ENOENT, EISDIR, ENOTDIR |
| Rmdir | ENOENT, ENOTEMPTY, ENOTDIR |
| Rename | ENOENT, EEXIST, ENOTEMPTY, ENOTDIR, EISDIR, EXDEV |

Other dispatched errors are Unknown, including unlisted permission, quota,
allocation and I/O failures. Native create may precede a failing open/security
hook. Explicit validation and private-prefix preparation failures before
terminal dispatch remain ordinary errors.

Unknown latches namespace writes EROFS and namespace-derived reads/new opens
EIO until remount. It never guesses a moved directory's parent or invokes the
known-success reparent callback. A known postcommit storage fault latches
namespace writes and directory fsync; readable state remains usable when cache
repair succeeds. Transient backing-registration/resource errors can recover
through repair without a permanent storage fault.

Ordinary unlink/rename eagerly prune proven-empty fragment directories.
Rmdir and overwrite of a directory validate the private tree and remove only
verified empty implementation branches. Unknown/nonempty objects are preserved.
Preparation interruption or cleanup failure can leave valid empty prefixes;
there is no global residue bound across arbitrary repeated crashes.

## Kernel cache repair and retained handles

Successful cross-parent directory moves invalidate the moved directory's
cached listing, including dotdot. Committed/Unknown error replies need explicit
repair because the kernel does not perform success-path invalidation.

1. Prepare at most two owned parent/name notifications before mutation.
   Under the write guard, update known state or poison Unknown state and
   reserve the single notification-pending slot.
2. Drop namespace/table guards and invalidate affected directory mappings,
   including up to two deduplicated moved/removed directories for EXCHANGE.
3. For errors, reply before nonblocking submission of the dentry batch to one
   independent notifier worker. Never call inval_entry inline in its related
   FUSE callback or wait there for queue capacity.
4. Pending repair makes new namespace writers return EAGAIN before mutation,
   unless permanent failure requires EROFS. Clear pending only after all
   notifications succeed.
5. Failed enqueue or non-benign notification failure latches failure and poisons
   namespace reads/new opens. It does not pretend that repair completed.

Already-absent entries are benign. ENODEV after connection teardown leaves no
kernel namespace cache to repair. Shutdown drains request callbacks before
joining notification ownership. Permanent fault, poison or failed pending
repair prevents a successful exit.

Retained regular-file data and sync handles keep their underlying results;
release and FORGET remain available. Metadata can bypass poison only with a
validated regular-file protocol handle. A caller's FD does not guarantee that
Linux supplies such a handle: cold inode-only GETATTR may return EIO.

Unsupported/private xattr reads return the constant ENODATA answer before
checking namespace poison, including security.capability queries preceding
a first write. Supported user xattr reads remain gated. An initiating data
syscall may wait for a metadata callback; kernel data passthrough does not make
all surrounding metadata independent of the daemon.

## Required lifetimes and resource costs

Root protocol ID is 1; other IDs use checked native inode plus 2 under the
single-filesystem contract. Linked cold regular-file slots retain variable-length
opaque native file handles, never an inode number used as a reopen token. Handle,
native device/inode and immutable type checks reject stale or aliased identities.
Directories, symlinks and special nodes retain FDs. Each materialized NodeRef owns
an Arc FD independently of the slot pin, data FD and kernel backing registration.

Before unlink or ordinary flags=0 overwrite, an existing live slot temporarily
pins the authoritative victim while the namespace write guard excludes readers.
After the native operation, fstat under the inode mutex clears that slot pin only
when nlink remains positive; nlink=0 or failed fstat retains it conservatively.
This applies to known and unknown outcomes without reclassifying the mutation.
Nonzero rename flags do not pre-pin victims: NOREPLACE and EXCHANGE delete none.
An active NodeRef keeps its FD even after a linked slot pin is cleared.

Lookup references, open-handle references and in-flight references have distinct
lifetimes. FORGET cannot close active references; deleted-object pins remain
until lookup/open/in-flight ownership ends. These are semantic lifetimes, not
an LRU cache or a guarantee of constant resources for arbitrary client activity.

Simultaneous opens share one kernel backing registration. The Node keeps a weak
reference; active file handles keep strong references. Register the materialized stable
O_PATH FD, which the kernel reopens in the frontend access mode. Each file handle
also owns a requested-mode data FD for sync, flush, fallocate and FD attributes.
There is no idle backing cache.

Every nonroot directory Node pins its logical parent separately. Dotdot uses
that parent; root's dotdot is root. Linked directories report nlink 1 as an
unknown-subdirectory-count convention; an unlinked open directory retains
native nlink 0. Directory size is implementation-defined.

A directory handle owns a sorted full listing and sequential cookies, with
dot/dotdot first. A fresh handle, rewind or Node-generation change rebuilds it
from canonical native names. Rebuilding temporarily retains the previous view
and its replacement until validation succeeds. First nonzero-cookie requests
also initialize a view. Unchanged continuations reuse that handle's view. Mutations can cause
normal skips/duplicates; known older generations are not deliberately emitted.
Generation saturation disables reuse. Plain READDIR creates no lookup refs;
READDIRPLUS is neither negotiated nor implemented.

There is no LongIndex, cross-handle listing cache, LRU, optional directory pin,
admission budget, persistent snapshot or startup enumeration.

| Resource | Lifetime and scaling |
| --- | --- |
| Cold linked regular identity | Variable-length opaque handle per live slot; no idle identity FD |
| Active/deleted regular identity FD | Active NodeRefs own materialized FDs; a removed live slot retains its pin |
| Other inode identity FD | Directory/symlink/special-node slots retain their FD |
| Logical-parent FD | One additional FD per live nonroot directory Node |
| Data FD | One per open regular-file handle |
| Kernel backing | Shared per inode while active file handles exist; separate from daemon FD count/RSS |
| Directory view | One full listing per open directory handle that has enumerated; released with that handle |
| Walker scratch | Operation-local buffers/FDs bounded by fragment depth |
| Notification batch | At most one pending batch containing at most two names/parent pins |
| Backend fragments | Up to four intermediate directories per unique 1024-byte name, plus private roots |

Total memory and FD use scale with client activity and are not globally bounded.
Daemon RSS omits kernel dentries, pages, backing registrations and FD tables.
Physical backend inode amplification is measured separately.

Startup raises the soft FD limit toward 65,536 within the hard limit without
lowering an existing larger limit; at least 128 is required. Before threads
start, a temporary owned CLOEXEC duplicate reserves FD-table capacity through
min(soft limit, 65536)-1, then closes. An inherited occupied target is untouched.
At the default limit the kernel pointer table is about 512 KiB plus bitmaps.
EMFILE/ENFILE are real recoverable errors when their publication outcome permits.

Explicit scratch reservations can return ENOMEM. Ordinary Rust allocation
exhaustion can terminate the daemon; universal graceful OOM recovery is not
promised. Fail-stop termination releases process resources, and remount rebuilds
from canonical names subject to the native durability contract.

## Durability, startup and shutdown

Durability is caller-managed native filesystem durability. Unsynchronized
create/rename need not survive power loss. File fsync/fdatasync covers native
file data and metadata. Directory fsync holds the read guard, syncs private
prefixes bottom-up, stops at user terminals, then syncs the private root and
logical directory. A pruned branch is covered by its nearest surviving parent.
Sync both logical parents after a cross-directory move, plus file data.

Fresh initialization writes the exact format marker. Every accepted startup
fsyncs the root before probe recovery/creation, including a retry after marker
write succeeded but its prior sync failed. Startup checks xattrs, case sensitivity, proc-fd access, native rename and
directory sync. It reuses the linked ordinary probe file to capture a native
handle, reopen it with open_by_handle_at and verify device/inode identity. Missing
capture/reopen support or permissions, stale handles and identity mismatch reject
startup with an operation-specific diagnostic. This preflight adds no alternate
mode, persistent index or background recovery service.

The root-only probe recognizes only single-link regular `file` and empty
`before`/`after` directories; `FILE` is an absence-only case check.
A root `.__LNL_PROBE` alias of the private probe inode is rejected; a distinct
legal user entry is preserved. Validate the entire leftover set before deleting
recognized objects. Unknown contents remain intact and prevent service.

Block SIGINT/SIGTERM before threads, finish Session initialization, then install
the sigwait unmount handler. A failed busy unmount keeps serving. Normal exit
drains FUSE and notifier workers and checks fault state; it performs no global
syncfs or shutdown certificate. Success is not a durability certificate.
Daemon-kill and injected-error tests are not hardware power-loss tests.

## Validation and publication

Use locked Rust 1.92.0 format, warnings-as-errors Clippy, privileged all-target
tests (actual native-handle preflight, no bypass) and release build. tests/backend.sh runs real ext4/XFS/Btrfs mounted validation;
missing tools, privileges, backend or passthrough is failure, never a skip.
Suites cover name boundaries/non-UTF-8, canonical rejection and preservation,
namespace moves, directory cookies, retained data handles, fsync, low FDs,
single-worker progress, busy unmount and kill/remount recovery. The v0.2 suite
adds native copy results, long/raw symlinks, the EXCHANGE type/parent/name matrix,
FIFO/socket communication, O_PATH unlink/overwrite, concurrent inode churn,
12,000 rejected renames and 6,000 exchanges under RLIMIT_NOFILE=128. Frontend VFS
can reject requests before FUSE; direct unit/fault tests independently validate
pin reconciliation, failed fstat and FORGET/materialization races.

Final runtime fault evidence is built from frozen isolated copies, with hooks
after actual native success and before outcome classification for Unknown.
Cover file/directory overwrite at one and four workers, notifier failure,
real post-publication EMFILE at soft/hard 128, and first retained pwrite before
truncate/fallocate. Release source contains no runtime fault hooks.

Bounded absolute measurements report their input sizes, backend, kernel,
threads, cache conditions, timings/percentiles, daemon CPU/RSS/FDs, native
fragments and full cleanup/shutdown. Small-sample p99 is near the maximum.
Fresh-daemon scans do not imply cold physical storage. No v2 comparison or
relative-performance threshold gates publication.

Only this design is tracked beneath docs; historical experiments, review
records, raw results and progress remain outside the release tree. Historical
16/18 and 8/10 results remain failures under retired rules and are not claimed
as new passes. Every release decision requires primary and independent review
of exact design and source/evidence hashes.

The initial release history is one commit after preserving original history.
Review staged tree, verify identical final whole tree, push main and require
that exact SHA's CI to pass before tagging its matching release version. The release workflow reruns
required CI, checks version, packages executable/documentation/MIT/dependency
license texts and publishes checksums. Downloaded public assets must match
checksums, permissions, declared architecture/ABI and version/help output.

## References

- [Linux FUSE passthrough](https://www.kernel.org/doc/html/latest/filesystems/fuse/fuse-passthrough.html)
- [Linux O_PATH backing registration change](https://github.com/torvalds/linux/commit/efad7153bf93db8565128f7567aab1d23e221098)
- [fuser 0.17.0](https://docs.rs/fuser/0.17.0/fuser/)
- [fsync(2)](https://man7.org/linux/man-pages/man2/fsync.2.html)
- [rename(2)](https://man7.org/linux/man-pages/man2/rename.2.html)
