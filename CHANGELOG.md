# Changes

## 0.2.0

The Linux x86-64 GNU archive requires glibc 2.39+ and Linux 6.12+ with enabled
FUSE passthrough and O_PATH backing registration, plus the capabilities below.

- Forward regular-file `copy_file_range` through one native call with checked
  offsets, full-width flag validation and actual short-copy results.
- Support symlink names up to 1024 raw bytes without changing their targets.
- Support `RENAME_EXCHANGE`, including file/directory and nonempty directory
  pairs, with both logical parents and directory caches updated.
- Support native FIFO and Unix socket nodes. Device nodes remain unsupported;
  Linux's Unix socket address-length limit still applies.
- Use terminal `d_type` hints for READDIR. Unknown types and authoritative object
  operations retain strict validation; encoded-terminal directory fsync remains
  strict. Plain READDIR creates no lookup references.
- Retain opaque native handles for linked cold regular files. Requests own their
  materialized FDs; unlink and ordinary overwrite preserve live removed objects.
  Failed or nondeleting renames do not accumulate unnecessary identity pins.
- Require `CAP_DAC_READ_SEARCH` in addition to root and `CAP_SYS_ADMIN`. Startup
  captures and reopens a probe on the actual backend and verifies native identity.
  Unsupported backends or missing capabilities fail explicitly.

The disk encoding remains format 3. Release 0.1.0 cannot serve the newly supported
long symlink/FIFO/socket terminals. See README before downgrade or service upgrade.

The global namespace lock, owner-only access, mandatory regular-file passthrough,
native durability contract and fail-closed handling of unknown mutations remain.
There is no userspace WAL/database/name index, data fallback, owner proxy or
offline maintenance command. Cold-handle FD savings trade against extra reopen
syscalls; no universal performance improvement or physical reflink is promised.

Validation targets ext4, XFS and Btrfs with real mounted passthrough. ZFS, hardware
power loss and exhaustive allocator failure are not certified by this release.
