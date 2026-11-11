#!/usr/bin/env bash
set -euo pipefail

if [[ $# != 2 || $EUID != 0 ]]; then
  echo 'usage (as root): tests/backend.sh ext4|xfs|btrfs /path/to/lnfs-lite' >&2
  exit 2
fi
family=$1
binary=$(realpath "$2")
case "$family" in
  ext4|xfs|btrfs) ;;
  *) echo "unsupported test filesystem: $family" >&2; exit 2 ;;
esac
repo=$(cd "$(dirname "$0")/.." && pwd)
artifacts=${LNFS_TEST_ARTIFACTS:-"$repo/target/backend-artifacts/$family-$(date -u +%Y%m%dT%H%M%S)-$$"}
mkdir -p "$artifacts"
artifacts=$(realpath "$artifacts")
export LNFS_TEST_ARTIFACTS="$artifacts"
scratch=
loop=
cleanup() {
  local original=$? cleanup_status=0 remaining= current=
  trap - EXIT
  set +e
  if [[ -n "$scratch" ]] && mountpoint -q "$scratch/fs"; then
    umount "$scratch/fs" >>"$artifacts/cleanup.log" 2>&1 || cleanup_status=1
  fi
  if [[ -n "$scratch" ]]; then
    remaining=$(python3 - "$scratch" <<'PY'
from pathlib import Path
import sys
prefix = sys.argv[1] + "/"
for line in Path("/proc/self/mountinfo").read_text().splitlines():
    path = line.split()[4]
    for escaped, raw in ((r"\040", " "), (r"\011", "\t"), (r"\012", "\n"), (r"\134", "\\")):
        path = path.replace(escaped, raw)
    if path.startswith(prefix):
        print(path)
PY
)
    if [[ $? != 0 ]]; then cleanup_status=1; fi
    if [[ -n "$remaining" ]]; then
      echo "Owned mount cleanup incomplete: $remaining" >>"$artifacts/cleanup.log"
      cleanup_status=1
    fi
  fi
  if [[ -n "$loop" && $cleanup_status == 0 ]]; then
    current=$(losetup --noheadings --output BACK-FILE "$loop" 2>>"$artifacts/cleanup.log")
    if [[ "$current" == "$scratch/backing.img" ]]; then
      losetup --detach "$loop" >>"$artifacts/cleanup.log" 2>&1 || cleanup_status=1
    else
      echo "Refusing loop cleanup: $loop no longer names the owned image" >>"$artifacts/cleanup.log"
      cleanup_status=1
    fi
  fi
  if [[ -n "$scratch" && $original == 0 && $cleanup_status == 0 ]]; then
    rm -rf -- "$scratch" || cleanup_status=1
  elif [[ -n "$scratch" ]]; then
    echo "Preserved test scratch: $scratch" >&2
  fi
  chmod -R a+rX "$artifacts" || cleanup_status=1
  python3 - "$artifacts" "$original" "$cleanup_status" "$scratch" "$loop" "$remaining" <<'PY'
import json, sys
from pathlib import Path
directory, original, cleanup, scratch, loop, remaining = sys.argv[1:]
report = {
    "test_exit": int(original), "cleanup_exit": int(cleanup),
    "scratch": scratch, "owned_loop": loop,
    "remaining_mounts": remaining.splitlines(),
    "scratch_preserved": bool(scratch) and Path(scratch).exists(),
}
Path(directory, "result.json").write_text(json.dumps(report, indent=2) + "\n")
PY
  if [[ $? != 0 ]]; then cleanup_status=1; fi
  echo "Test exit=$original cleanup exit=$cleanup_status artifacts=$artifacts"
  if [[ $original != 0 ]]; then exit "$original"; fi
  exit "$cleanup_status"
}
trap cleanup EXIT

for command in "mkfs.$family" python3 mount umount mountpoint losetup sha256sum; do
  command -v "$command" >/dev/null
done
test -c /dev/fuse
test -x "$binary"
{
  uname -a
  "$binary" --version
  sha256sum "$binary"
} >"$artifacts/environment.txt"
scratch=$(mktemp -d -p "${TMPDIR:-/tmp}" lnfs-backend-XXXXXX)
scratch=$(realpath "$scratch")
mkdir "$scratch/fs"
truncate -s 1G "$scratch/backing.img"
case "$family" in
  ext4) mkfs.ext4 -q -F "$scratch/backing.img" ;;
  xfs) mkfs.xfs -q -f "$scratch/backing.img" ;;
  btrfs) mkfs.btrfs -q -f "$scratch/backing.img" ;;
esac
loop=$(losetup --find --show "$scratch/backing.img")
mount "$loop" "$scratch/fs"
python3 "$repo/tests/mounted.py" "$binary" --root "$scratch/fs" 2>&1 | tee "$artifacts/mounted.log"
python3 "$repo/tests/adversarial.py" "$binary" --root "$scratch/fs" 2>&1 | tee "$artifacts/adversarial.log"
python3 "$repo/tests/v020.py" "$binary" --root "$scratch/fs" 2>&1 | tee "$artifacts/v020.log"
