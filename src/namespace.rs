use crate::name::{
    FORMAT, FORMAT_XATTR, FRAGMENT, MAX_NAME, Name, PATH_CAPACITY, PREFIX, PROBE, TREE, error,
    validate, validate_long,
};
use crate::sys;
use parking_lot::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::ffi::{CStr, CString, OsStr, OsString};
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct DirKey {
    pub dev: u64,
    pub ino: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListedEntry {
    pub name: OsString,
    pub native_ino: u64,
    pub kind: u8,
}

/// A borrowed native directory identity paired with the FD that pins it.
#[derive(Clone, Copy, Debug)]
pub struct Directory<'a> {
    fd: BorrowedFd<'a>,
    key: DirKey,
}

impl<'a> Directory<'a> {
    /// The caller pairs these values from one already validated, still-owned inode.
    /// Only NodeRef, Namespace's root and test Entry owners construct this value.
    /// Identity and file type stay immutable while that owner keeps the FD alive.
    pub(crate) fn from_validated(fd: BorrowedFd<'a>, key: DirKey, mode: u32) -> io::Result<Self> {
        if mode & libc::S_IFMT != libc::S_IFDIR {
            return Err(error(libc::ENOTDIR));
        }
        Ok(Self { fd, key })
    }

    pub fn key(self) -> DirKey {
        self.key
    }
}

impl AsFd for Directory<'_> {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd
    }
}

pub struct Entry {
    pub fd: OwnedFd,
    pub stat: libc::stat,
    pub parent: Option<OwnedFd>,
}

impl Entry {
    pub fn from_fd(fd: OwnedFd) -> io::Result<Self> {
        let stat = sys::stat(fd.as_fd())?;
        Ok(Self {
            fd,
            stat,
            parent: None,
        })
    }

    #[cfg(test)]
    pub(crate) fn directory(&self) -> io::Result<Directory<'_>> {
        Directory::from_validated(self.fd.as_fd(), key(&self.stat), self.stat.st_mode)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mutator {
    Create,
    Mkdir,
    Symlink,
    Unlink,
    Rmdir,
    Rename,
}

fn known_rejection(op: Mutator, errno: Option<i32>) -> bool {
    matches!(
        (op, errno),
        (
            Mutator::Create,
            Some(libc::EEXIST | libc::EMFILE | libc::ENFILE)
        ) | (
            Mutator::Mkdir | Mutator::Symlink,
            Some(libc::EEXIST | libc::ENOENT | libc::ENOTDIR)
        ) | (
            Mutator::Unlink,
            Some(libc::ENOENT | libc::EISDIR | libc::ENOTDIR)
        ) | (
            Mutator::Rmdir,
            Some(libc::ENOENT | libc::ENOTEMPTY | libc::ENOTDIR)
        ) | (
            Mutator::Rename,
            Some(
                libc::ENOENT
                    | libc::EEXIST
                    | libc::ENOTEMPTY
                    | libc::ENOTDIR
                    | libc::EISDIR
                    | libc::EXDEV
            )
        )
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Outcome {
    Unchanged,
    Committed,
    Unknown,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fault {
    Native(Mutator),
    Touch,
    Prune,
}

pub struct Namespace {
    root: OwnedFd,
    root_key: DirKey,
    mount_id: u64,
    gate: RwLock<()>,
    failed: AtomicBool,
    poisoned: AtomicBool,
    notification_pending: AtomicBool,
    #[cfg(test)]
    fault: parking_lot::Mutex<Option<(Fault, i32)>>,
}

pub struct ReadGuard<'a> {
    namespace: &'a Namespace,
    _guard: RwLockReadGuard<'a, ()>,
}

pub struct WriteGuard<'a> {
    namespace: &'a Namespace,
    _guard: RwLockWriteGuard<'a, ()>,
    outcome: Outcome,
    directory: Option<u64>,
}

fn dots(name: &CStr) -> bool {
    matches!(name.to_bytes(), b"." | b"..")
}
fn key(stat: &libc::stat) -> DirKey {
    DirKey {
        dev: stat.st_dev,
        ino: stat.st_ino,
    }
}
fn kind(mode: u32) -> io::Result<u8> {
    match mode & libc::S_IFMT {
        libc::S_IFREG => Ok(libc::DT_REG),
        libc::S_IFDIR => Ok(libc::DT_DIR),
        libc::S_IFLNK => Ok(libc::DT_LNK),
        _ => Err(error(libc::EOPNOTSUPP)),
    }
}
impl Namespace {
    pub fn open(path: &Path) -> io::Result<Self> {
        Self::open_with_format_sync(path, sys::sync)
    }

    fn open_with_format_sync(
        path: &Path,
        sync_format: impl FnOnce(BorrowedFd<'_>) -> io::Result<()>,
    ) -> io::Result<Self> {
        let root = sys::open_root(path)?;
        sys::cvt(unsafe { libc::flock(root.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) })?;
        if !matches!(
            sys::statfs(root.as_fd())?.f_type as u64,
            0xef53 | 0x5846_5342 | 0x9123_683e
        ) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "backend must be ext4, XFS or Btrfs",
            ));
        }
        let root_key = key(&sys::stat(root.as_fd())?);
        let mount_id = sys::statx_name(root.as_fd(), c"", libc::AT_EMPTY_PATH)?.stx_mnt_id;
        let fresh = match sys::read_xattr(root.as_fd(), FORMAT_XATTR, 64) {
            Ok(marker) if marker == FORMAT => false,
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unsupported Lnfs-Lite format",
                ));
            }
            Err(err) if err.raw_os_error() == Some(libc::ENODATA) => true,
            Err(err) => return Err(err),
        };
        if fresh {
            let fd = sys::open_dir_at(root.as_fd(), c".")?;
            let mut buffer = Vec::new();
            let mut stream = sys::DirectoryStream::new(fd, &mut buffer)?;
            while let Some(entry) = stream.next_entry()? {
                if !dots(&entry.name) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "unmarked backend is not empty; copy through a mounted view",
                    ));
                }
            }
        }
        if fresh {
            sys::set_xattr(root.as_fd(), FORMAT_XATTR, FORMAT)?;
        }
        // A previous marker write may have succeeded before its sync failed.
        // Every accepted startup establishes the marker before touching probes.
        sync_format(root.as_fd())?;
        let namespace = Self {
            root,
            root_key,
            mount_id,
            gate: RwLock::new(()),
            failed: AtomicBool::new(false),
            poisoned: AtomicBool::new(false),
            notification_pending: AtomicBool::new(false),
            #[cfg(test)]
            fault: parking_lot::Mutex::new(None),
        };
        namespace.cleanup_probe()?;
        namespace.probe()?;
        Ok(namespace)
    }

    pub fn root_fd(&self) -> BorrowedFd<'_> {
        self.root.as_fd()
    }

    pub fn root_directory(&self) -> Directory<'_> {
        Directory::from_validated(self.root_fd(), self.root_key, libc::S_IFDIR)
            .expect("validated root directory")
    }

    pub fn read(&self) -> io::Result<ReadGuard<'_>> {
        let guard = self.gate.read();
        if self.poisoned.load(Ordering::Acquire) {
            return Err(error(libc::EIO));
        }
        Ok(ReadGuard {
            namespace: self,
            _guard: guard,
        })
    }

    pub fn write(&self) -> io::Result<WriteGuard<'_>> {
        let guard = self.gate.write();
        if self.failed.load(Ordering::Acquire) {
            return Err(error(libc::EROFS));
        }
        if self.notification_pending.load(Ordering::Acquire) {
            return Err(error(libc::EAGAIN));
        }
        Ok(WriteGuard {
            namespace: self,
            _guard: guard,
            outcome: Outcome::Unchanged,
            directory: None,
        })
    }

    pub fn is_faulted(&self) -> bool {
        self.failed.load(Ordering::Acquire)
    }

    pub fn finish_notifications(&self, success: bool) {
        let _guard = self.gate.write();
        if !success {
            self.poisoned.store(true, Ordering::Release);
            self.failed.store(true, Ordering::Release);
        } else if !self.failed.load(Ordering::Acquire) && !self.poisoned.load(Ordering::Acquire) {
            self.notification_pending.store(false, Ordering::Release);
        }
    }

    pub fn finish(&self) -> io::Result<()> {
        let _guard = self.gate.write();
        if self.poisoned.load(Ordering::Acquire) {
            return Err(error(libc::EIO));
        }
        if self.failed.load(Ordering::Acquire) || self.notification_pending.load(Ordering::Acquire)
        {
            return Err(error(libc::EROFS));
        }
        Ok(())
    }

    #[cfg(test)]
    fn inject(&self, point: Fault) -> io::Result<()> {
        let mut fault = self.fault.lock();
        if fault.as_ref().is_some_and(|(at, _)| *at == point) {
            let (_, errno) = fault.take().expect("matched fault");
            Err(error(errno))
        } else {
            Ok(())
        }
    }

    fn check_object(&self, stat: &libc::stat, long: bool) -> io::Result<()> {
        let kind = kind(stat.st_mode)?;
        if (kind != libc::DT_DIR && stat.st_nlink != 1) || (long && kind == libc::DT_LNK) {
            return Err(error(libc::EOPNOTSUPP));
        }
        Ok(())
    }

    fn stat_entry(
        &self,
        parent: BorrowedFd<'_>,
        name: &CStr,
        long: bool,
    ) -> io::Result<libc::statx> {
        let stat = sys::statx_name(parent, name, 0)?;
        if stat.stx_mnt_id != self.mount_id {
            return Err(error(libc::EXDEV));
        }
        let kind = kind(stat.stx_mode as u32)?;
        if (kind != libc::DT_DIR && stat.stx_nlink != 1) || (long && kind == libc::DT_LNK) {
            return Err(error(libc::EOPNOTSUPP));
        }
        Ok(stat)
    }

    fn open_entry(
        &self,
        parent: BorrowedFd<'_>,
        name: &Name<'_>,
        with_parent: bool,
    ) -> io::Result<Entry> {
        let mut entry = Entry::from_fd(sys::open_path_at(parent, name.path())?)?;
        self.check_object(&entry.stat, name.is_long())?;
        if with_parent && entry.stat.st_mode & libc::S_IFMT == libc::S_IFDIR {
            entry.parent = Some(sys::duplicate(parent)?);
        }
        Ok(entry)
    }

    fn private_file(&self, parent: BorrowedFd<'_>, name: &CStr) -> io::Result<()> {
        let stat = self.stat_entry(parent, name, true)?;
        if stat.stx_mode as u32 & libc::S_IFMT != libc::S_IFREG {
            return Err(error(libc::EOPNOTSUPP));
        }
        Ok(())
    }

    fn probe_alias(&self, probe: BorrowedFd<'_>) -> io::Result<()> {
        match sys::open_path_at(self.root_fd(), c".__LNL_PROBE") {
            Ok(alias) => {
                if key(&sys::stat(alias.as_fd())?) == key(&sys::stat(probe)?) {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "backend is not case-sensitive",
                    ));
                }
                Ok(())
            }
            Err(err) if err.raw_os_error() == Some(libc::ENOENT) => Ok(()),
            Err(err) => Err(err),
        }
    }

    fn cleanup_probe(&self) -> io::Result<()> {
        let fd = match sys::open_dir_at(self.root_fd(), PROBE) {
            Ok(fd) => fd,
            Err(err) if err.raw_os_error() == Some(libc::ENOENT) => return Ok(()),
            Err(err) => return Err(err),
        };
        self.probe_alias(fd.as_fd())?;
        let mut buffer = Vec::new();
        let mut stream = sys::DirectoryStream::new(fd, &mut buffer)?;
        let mut children = Vec::new();
        while let Some(entry) = stream.next_entry()? {
            if dots(&entry.name) {
                continue;
            }
            match entry.name.to_bytes() {
                b"file" => self.private_file(stream.fd(), &entry.name)?,
                b"before" | b"after" => {
                    let child_fd = sys::open_dir_at(stream.fd(), &entry.name)?;
                    let mut child_buffer = Vec::new();
                    let mut child = sys::DirectoryStream::new(child_fd, &mut child_buffer)?;
                    while let Some(entry) = child.next_entry()? {
                        if !dots(&entry.name) {
                            return Err(error(libc::ENOTEMPTY));
                        }
                    }
                }
                _ => return Err(error(libc::EIO)),
            }
            children.push(entry.name);
        }
        // Validate the entire bounded leftover set before deleting any child.
        for name in children {
            sys::unlink_at(stream.fd(), &name, name.to_bytes() != b"file")?;
        }
        drop(stream);
        sys::unlink_at(self.root_fd(), PROBE, true)
    }

    fn probe(&self) -> io::Result<()> {
        sys::mkdir_at(self.root_fd(), PROBE, 0o700)?;
        let result = (|| {
            let area = sys::open_dir_at(self.root_fd(), PROBE)?;
            self.probe_alias(area.as_fd())?;
            let file = sys::open_beneath(
                area.as_fd(),
                c"file",
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
                0o600,
            )?;
            match sys::open_path_at(area.as_fd(), c"FILE") {
                Err(err) if err.raw_os_error() == Some(libc::ENOENT) => (),
                Ok(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "backend is not case-sensitive",
                    ));
                }
                Err(err) => return Err(err),
            }
            sys::set_xattr(file.as_fd(), c"user.lnfs_lite.probe", b"probe")?;
            if sys::read_xattr(file.as_fd(), c"user.lnfs_lite.probe", 5)? != b"probe" {
                return Err(error(libc::EIO));
            }
            sys::remove_xattr(file.as_fd(), c"user.lnfs_lite.probe")?;
            let path = sys::reopen(file.as_fd(), libc::O_PATH)?;
            let reopened = sys::reopen(path.as_fd(), libc::O_RDONLY)?;
            if key(&sys::stat(file.as_fd())?) != key(&sys::stat(reopened.as_fd())?) {
                return Err(error(libc::EIO));
            }
            sys::sync(file.as_fd())?;
            sys::mkdir_at(area.as_fd(), c"before", 0o700)?;
            sys::rename_at(
                area.as_fd(),
                c"before",
                area.as_fd(),
                c"after",
                libc::RENAME_NOREPLACE,
            )?;
            sys::mkdir_at(area.as_fd(), c"before", 0o700)?;
            match sys::rename_at(
                area.as_fd(),
                c"before",
                area.as_fd(),
                c"after",
                libc::RENAME_NOREPLACE,
            ) {
                Err(err) if err.raw_os_error() == Some(libc::EEXIST) => (),
                Err(err) => return Err(err),
                Ok(()) => return Err(error(libc::EOPNOTSUPP)),
            }
            sys::sync(area.as_fd())
        })();
        let cleanup = self.cleanup_probe();
        result?;
        cleanup?;
        sys::sync(self.root_fd())
    }

    fn ensure_parent(&self, parent: Directory<'_>, name: &Name<'_>) -> io::Result<OwnedFd> {
        let parent = parent.fd;
        let mut scratch = [0; PATH_CAPACITY];
        let path = name
            .parent_path(&mut scratch)
            .expect("long name has private parents");
        match sys::open_dir_anchor_at(parent, path) {
            Ok(fd) => return Ok(fd),
            Err(err) if err.raw_os_error() == Some(libc::ENOENT) => (),
            Err(err) => return Err(err),
        }
        match sys::mkdir_at(parent, TREE, 0o700) {
            Ok(()) => (),
            Err(err) if err.raw_os_error() == Some(libc::EEXIST) => (),
            Err(err) => return Err(err),
        }
        let mut current = sys::open_dir_anchor_at(parent, TREE)?;
        let mut raw = name.raw();
        let mut component = [0; FRAGMENT + 2];
        component[0] = b'd';
        while raw.len() > FRAGMENT {
            component[1..=FRAGMENT].copy_from_slice(&raw[..FRAGMENT]);
            let component_name =
                CStr::from_bytes_with_nul(&component).expect("validated raw fragment");
            match sys::mkdir_at(current.as_fd(), component_name, 0o700) {
                Ok(()) => (),
                Err(err) if err.raw_os_error() == Some(libc::EEXIST) => (),
                Err(err) => return Err(err),
            }
            current = sys::open_dir_anchor_at(current.as_fd(), component_name)?;
            raw = &raw[FRAGMENT..];
        }
        Ok(current)
    }

    fn prune(&self, parent: BorrowedFd<'_>, name: &Name<'_>) -> io::Result<()> {
        #[cfg(test)]
        self.inject(Fault::Prune)?;
        let mut scratch = [0; PATH_CAPACITY];
        if name.parent_path(&mut scratch).is_none() {
            return Ok(());
        }
        for &end in name.prefix_ends().iter().skip(1).rev() {
            scratch[end] = 0;
            let prefix = CStr::from_bytes_with_nul(&scratch[..=end]).expect("validated prefix");
            match sys::unlink_at(parent, prefix, true) {
                Ok(()) => (),
                Err(err) if err.raw_os_error() == Some(libc::ENOTEMPTY) => break,
                Err(err) => return Err(err),
            }
        }
        Ok(())
    }

    fn walk_prefix<F>(
        &self,
        fd: OwnedFd,
        prefix: &mut Vec<u8>,
        sync: bool,
        visit: &mut F,
    ) -> io::Result<()>
    where
        F: FnMut(Vec<u8>, libc::statx) -> io::Result<()>,
    {
        let mut buffers: [Vec<u8>; 5] = std::array::from_fn(|_| Vec::new());
        self.walk_prefix_with_buffers(fd, prefix, sync, visit, &mut buffers)
    }

    fn walk_prefix_with_buffers<F>(
        &self,
        fd: OwnedFd,
        prefix: &mut Vec<u8>,
        sync: bool,
        visit: &mut F,
        buffers: &mut [Vec<u8>],
    ) -> io::Result<()>
    where
        F: FnMut(Vec<u8>, libc::statx) -> io::Result<()>,
    {
        let (buffer, children) = buffers.split_first_mut().ok_or_else(|| error(libc::EIO))?;
        let mut stream = sys::DirectoryStream::new(fd, buffer)?;
        while let Some(entry) = stream.next_entry()? {
            let bytes = entry.name.to_bytes();
            if dots(&entry.name) {
                continue;
            }
            if bytes.len() == 255 && bytes[0] == b'd' && prefix.len() + FRAGMENT < MAX_NAME {
                if prefix.is_empty() && bytes[1..].starts_with(PREFIX) {
                    return Err(error(libc::EIO));
                }
                let child = sys::open_dir_at(stream.fd(), &entry.name)?;
                prefix.extend_from_slice(&bytes[1..]);
                self.walk_prefix_with_buffers(child, prefix, sync, visit, children)?;
                prefix.truncate(prefix.len() - FRAGMENT);
            } else if (2..=255).contains(&bytes.len()) && bytes[0] == b'e' {
                let mut raw = prefix.clone();
                raw.extend_from_slice(&bytes[1..]);
                validate_long(&raw).map_err(|_| error(libc::EIO))?;
                let stat = self.stat_entry(stream.fd(), &entry.name, true)?;
                visit(raw, stat)?;
            } else {
                return Err(error(libc::EIO));
            }
        }
        if sync {
            sys::sync(stream.fd())?;
        }
        Ok(())
    }

    fn long_listing(&self, parent: BorrowedFd<'_>) -> io::Result<Vec<ListedEntry>> {
        let tree = sys::open_dir_at(parent, TREE)?;
        let mut out = Vec::new();
        self.walk_prefix(tree, &mut Vec::new(), false, &mut |raw, stat| {
            out.push(ListedEntry {
                name: OsString::from_vec(raw),
                native_ino: stat.stx_ino,
                kind: kind(stat.stx_mode as u32)?,
            });
            Ok(())
        })?;
        Ok(out)
    }

    fn remove_empty_tree(&self, fd: OwnedFd) -> io::Result<()> {
        let mut buffer = Vec::new();
        let mut stream = sys::DirectoryStream::new(fd, &mut buffer)?;
        while let Some(entry) = stream.next_entry()? {
            if dots(&entry.name) {
                continue;
            }
            if entry.name.to_bytes().len() == 255 && entry.name.to_bytes()[0] == b'd' {
                self.remove_empty_tree(sys::open_dir_at(stream.fd(), &entry.name)?)?;
                sys::unlink_at(stream.fd(), &entry.name, true)?;
            } else {
                return Err(error(libc::EIO));
            }
        }
        Ok(())
    }

    fn clean_logical_directory(&self, parent: BorrowedFd<'_>) -> io::Result<()> {
        let fd = sys::open_dir_at(parent, c".")?;
        let mut buffer = Vec::new();
        let mut stream = sys::DirectoryStream::new(fd, &mut buffer)?;
        let mut has_tree = false;
        while let Some(entry) = stream.next_entry()? {
            if dots(&entry.name) {
                continue;
            }
            if entry.name != TREE {
                return Err(error(libc::ENOTEMPTY));
            }
            has_tree = true;
        }
        if has_tree {
            // Prove the complete tree contains only known empty branches first.
            self.walk_prefix(
                sys::open_dir_at(parent, TREE)?,
                &mut Vec::new(),
                false,
                &mut |_, _| Err(error(libc::ENOTEMPTY)),
            )?;
            self.remove_empty_tree(sys::open_dir_at(parent, TREE)?)?;
            sys::unlink_at(parent, TREE, true)?;
        }
        Ok(())
    }

    fn touch(&self, parent: BorrowedFd<'_>) -> io::Result<()> {
        #[cfg(test)]
        self.inject(Fault::Touch)?;
        sys::touch_directory(parent)
    }
}

impl ReadGuard<'_> {
    pub fn lookup(&self, parent: BorrowedFd<'_>, raw: &OsStr) -> io::Result<Entry> {
        self.namespace.open_entry(parent, &Name::new(raw)?, true)
    }

    pub fn list(&self, parent: Directory<'_>) -> io::Result<Vec<ListedEntry>> {
        let fd = sys::open_dir_at(parent.fd, c".")?;
        let mut buffer = Vec::new();
        let mut stream = sys::DirectoryStream::new(fd, &mut buffer)?;
        let mut out = Vec::new();
        let mut has_tree = false;
        while let Some(entry) = stream.next_entry()? {
            if dots(&entry.name) {
                continue;
            }
            if entry.name == TREE {
                has_tree = true;
                continue;
            }
            validate(entry.name.to_bytes()).map_err(|_| error(libc::EIO))?;
            let entry_kind = match entry.kind {
                libc::DT_REG | libc::DT_DIR | libc::DT_LNK => entry.kind,
                libc::DT_UNKNOWN => kind(
                    self.namespace
                        .stat_entry(stream.fd(), &entry.name, false)?
                        .stx_mode as u32,
                )?,
                _ => return Err(error(libc::EOPNOTSUPP)),
            };
            out.push(ListedEntry {
                name: OsString::from_vec(entry.name.into_bytes()),
                native_ino: entry.native_ino,
                kind: entry_kind,
            });
        }
        if has_tree {
            out.extend(self.namespace.long_listing(parent.fd)?);
        }
        out.sort_unstable_by(|a, b| a.name.as_bytes().cmp(b.name.as_bytes()));
        Ok(out)
    }

    pub fn fsync_dir(&self, parent: BorrowedFd<'_>) -> io::Result<()> {
        if self.namespace.failed.load(Ordering::Acquire) {
            return Err(error(libc::EIO));
        }
        match sys::open_dir_at(parent, TREE) {
            Ok(tree) => self
                .namespace
                .walk_prefix(tree, &mut Vec::new(), true, &mut |_, _| Ok(()))?,
            Err(err) if err.raw_os_error() == Some(libc::ENOENT) => (),
            Err(err) => return Err(err),
        }
        let logical = sys::open_dir_at(parent, c".")?;
        sys::sync(logical.as_fd())
    }
}

impl WriteGuard<'_> {
    pub fn did_commit(&self) -> bool {
        self.outcome == Outcome::Committed
    }
    pub fn needs_invalidation(&self) -> bool {
        self.outcome != Outcome::Unchanged
    }
    pub fn directory_to_invalidate(&self) -> Option<u64> {
        self.directory
    }

    pub fn mark_notification_pending(&mut self) {
        self.namespace
            .notification_pending
            .store(true, Ordering::Release);
    }

    fn logical<T>(&mut self, op: Mutator, result: io::Result<T>) -> io::Result<T> {
        #[cfg(test)]
        let result =
            result.and_then(|value| self.namespace.inject(Fault::Native(op)).map(|()| value));
        match result {
            Ok(value) => {
                self.outcome = Outcome::Committed;
                Ok(value)
            }
            Err(err) => {
                if !known_rejection(op, err.raw_os_error()) {
                    self.outcome = Outcome::Unknown;
                    self.namespace.poisoned.store(true, Ordering::Release);
                    self.namespace.failed.store(true, Ordering::Release);
                }
                Err(err)
            }
        }
    }

    fn after_commit<T>(&self, result: io::Result<T>) -> io::Result<T> {
        if result.is_err() {
            self.namespace.failed.store(true, Ordering::Release);
        }
        result
    }

    pub fn create_file<T>(
        &mut self,
        parent: Directory<'_>,
        raw: &OsStr,
        mode: u32,
        flags: i32,
        prepare: impl FnOnce(&Entry, &OwnedFd) -> io::Result<T>,
    ) -> io::Result<(Entry, OwnedFd, T)> {
        let name = Name::new(raw)?;
        if flags & (libc::O_PATH | libc::O_DIRECTORY) != 0 {
            return Err(error(libc::EINVAL));
        }
        let physical = if name.is_long() {
            Some(self.namespace.ensure_parent(parent, &name)?)
        } else {
            None
        };
        let at = physical.as_ref().map_or(parent.fd, AsFd::as_fd);
        let flags = flags & !(libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW);
        let file = self.logical(
            Mutator::Create,
            sys::open_beneath(
                at,
                name.leaf(),
                flags | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW,
                mode & 0o7777,
            ),
        )?;
        let entry = match sys::reopen(file.as_fd(), libc::O_PATH).and_then(Entry::from_fd) {
            Ok(entry) => entry,
            Err(err) => {
                if name.is_long() {
                    self.after_commit(self.namespace.touch(parent.fd))?;
                }
                return Err(err);
            }
        };
        if name.is_long() {
            self.after_commit(self.namespace.touch(parent.fd))?;
        }
        let prepared = prepare(&entry, &file)?;
        Ok((entry, file, prepared))
    }

    pub fn mkdir(&mut self, parent: Directory<'_>, raw: &OsStr, mode: u32) -> io::Result<Entry> {
        let name = Name::new(raw)?;
        let logical_parent = sys::duplicate(parent.fd)?;
        let physical = if name.is_long() {
            Some(self.namespace.ensure_parent(parent, &name)?)
        } else {
            None
        };
        let at = physical.as_ref().map_or(parent.fd, AsFd::as_fd);
        self.logical(Mutator::Mkdir, sys::mkdir_at(at, name.leaf(), mode))?;
        let mut entry = match sys::open_path_at(at, name.leaf()).and_then(Entry::from_fd) {
            Ok(entry) => entry,
            Err(err) => {
                if name.is_long() {
                    self.after_commit(self.namespace.touch(parent.fd))?;
                }
                return Err(err);
            }
        };
        entry.parent = Some(logical_parent);
        if name.is_long() {
            self.after_commit(self.namespace.touch(parent.fd))?;
        }
        Ok(entry)
    }

    pub fn symlink(
        &mut self,
        parent: Directory<'_>,
        raw: &OsStr,
        target: &OsStr,
    ) -> io::Result<Entry> {
        let name = Name::new(raw)?;
        if name.is_long() {
            return Err(error(libc::EOPNOTSUPP));
        }
        let target = CString::new(target.as_bytes()).map_err(|_| error(libc::EINVAL))?;
        self.logical(
            Mutator::Symlink,
            sys::symlink_at(parent.fd, name.path(), &target),
        )?;
        self.namespace.open_entry(parent.fd, &name, false)
    }

    pub fn unlink(
        &mut self,
        parent: Directory<'_>,
        raw: &OsStr,
        directory: bool,
    ) -> io::Result<()> {
        let name = Name::new(raw)?;
        let physical = if name.is_long() {
            let mut scratch = [0; PATH_CAPACITY];
            let path = name
                .parent_path(&mut scratch)
                .expect("long name has private parents");
            Some(sys::open_dir_anchor_at(parent.fd, path)?)
        } else {
            None
        };
        let at = physical.as_ref().map_or(parent.fd, AsFd::as_fd);
        let stat = self.namespace.stat_entry(at, name.leaf(), name.is_long())?;
        let is_dir = stat.stx_mode as u32 & libc::S_IFMT == libc::S_IFDIR;
        if directory && !is_dir {
            return Err(error(libc::ENOTDIR));
        }
        if !directory && is_dir {
            return Err(error(libc::EISDIR));
        }
        if directory {
            self.directory = Some(stat.stx_ino);
            let child = sys::open_path_at(at, name.leaf())?;
            self.namespace.clean_logical_directory(child.as_fd())?;
        }
        self.logical(
            if directory {
                Mutator::Rmdir
            } else {
                Mutator::Unlink
            },
            sys::unlink_at(at, name.leaf(), directory),
        )?;
        if name.is_long() {
            self.after_commit(self.namespace.touch(parent.fd))?;
            self.after_commit(self.namespace.prune(parent.fd, &name))?;
        }
        Ok(())
    }

    pub fn rename(
        &mut self,
        old_parent: Directory<'_>,
        old_raw: &OsStr,
        new_parent: Directory<'_>,
        new_raw: &OsStr,
        flags: u32,
        directory_commit: impl FnOnce(u64, OwnedFd),
    ) -> io::Result<()> {
        let known = libc::RENAME_NOREPLACE | libc::RENAME_EXCHANGE | libc::RENAME_WHITEOUT;
        if flags & !known != 0 {
            return Err(error(libc::EINVAL));
        }
        if flags & (libc::RENAME_EXCHANGE | libc::RENAME_WHITEOUT) != 0 {
            return Err(error(libc::EOPNOTSUPP));
        }
        let old = Name::new(old_raw)?;
        let new = Name::new(new_raw)?;
        let source = self.namespace.open_entry(old_parent.fd, &old, false)?;
        let same_parent = old_parent.key == new_parent.key;
        if same_parent && old.raw() == new.raw() {
            return if flags == libc::RENAME_NOREPLACE {
                Err(error(libc::EEXIST))
            } else {
                Ok(())
            };
        }
        let source_kind = kind(source.stat.st_mode)?;
        if source_kind == libc::DT_LNK && new.is_long() {
            return Err(error(libc::EOPNOTSUPP));
        }
        let target = match self.namespace.open_entry(new_parent.fd, &new, false) {
            Ok(entry) => Some(entry),
            Err(err) if err.raw_os_error() == Some(libc::ENOENT) => None,
            Err(err) => return Err(err),
        };
        if target.is_some() && flags == libc::RENAME_NOREPLACE {
            return Err(error(libc::EEXIST));
        }
        if let Some(target) = &target {
            let target_dir = target.stat.st_mode & libc::S_IFMT == libc::S_IFDIR;
            if source_kind == libc::DT_DIR && !target_dir {
                return Err(error(libc::ENOTDIR));
            }
            if source_kind != libc::DT_DIR && target_dir {
                return Err(error(libc::EISDIR));
            }
            if target_dir {
                self.namespace.clean_logical_directory(target.fd.as_fd())?;
            }
        }
        let next_parent = if source_kind == libc::DT_DIR {
            self.directory = Some(source.stat.st_ino);
            Some(sys::duplicate(new_parent.fd)?)
        } else {
            None
        };
        let physical = if new.is_long() {
            Some(self.namespace.ensure_parent(new_parent, &new)?)
        } else {
            None
        };
        let at = physical.as_ref().map_or(new_parent.fd, AsFd::as_fd);
        self.logical(
            Mutator::Rename,
            sys::rename_at(old_parent.fd, old.path(), at, new.leaf(), flags),
        )?;
        if let Some(parent) = next_parent {
            directory_commit(source.stat.st_ino, parent);
        }
        if old.is_long() || new.is_long() {
            self.after_commit(self.namespace.touch(old_parent.fd))?;
            if !same_parent {
                self.after_commit(self.namespace.touch(new_parent.fd))?;
            }
        }
        if old.is_long()
            && !(same_parent && new.is_long() && old.parent_bytes() == new.parent_bytes())
        {
            self.after_commit(self.namespace.prune(old_parent.fd, &old))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::collections::BTreeMap;
    use std::fs;
    use std::os::unix::fs::symlink;

    fn fixture() -> (tempfile::TempDir, Namespace) {
        let temp = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).unwrap();
        let namespace = Namespace::open(temp.path()).unwrap();
        (temp, namespace)
    }
    fn long(byte: u8, len: usize) -> OsString {
        OsString::from_vec(vec![byte; len])
    }
    fn create(ns: &Namespace, parent: Directory<'_>, name: &OsStr) -> Entry {
        let (entry, _, ()) = ns
            .write()
            .unwrap()
            .create_file(parent, name, libc::S_IFREG | 0o600, libc::O_RDWR, |_, _| {
                Ok(())
            })
            .unwrap();
        entry
    }
    fn native_path(root: &Path, name: &OsStr) -> std::path::PathBuf {
        root.join(OsStr::from_bytes(
            Name::new(name).unwrap().path().to_bytes(),
        ))
    }
    fn assert_unknown(ns: &Namespace) {
        assert_eq!(ns.read().err().unwrap().raw_os_error(), Some(libc::EIO));
        assert_eq!(ns.write().err().unwrap().raw_os_error(), Some(libc::EROFS));
        assert!(ns.finish().is_err());
        assert_eq!(
            sys::read_xattr(ns.root_fd(), FORMAT_XATTR, 64).unwrap(),
            FORMAT
        );
    }

    #[test]
    fn fresh_listing_recovers_from_emfile_without_retained_descriptor_pins() {
        const CHILD: &str = "LNFS_NAMESPACE_FD_TEST";
        if std::env::var_os(CHILD).is_none() {
            let result = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "namespace::tests::fresh_listing_recovers_from_emfile_without_retained_descriptor_pins",
                    "--test-threads=1",
                ])
                .env(CHILD, "1")
                .output()
                .unwrap();
            assert!(
                result.status.success(),
                "stdout: {}\nstderr: {}",
                String::from_utf8_lossy(&result.stdout),
                String::from_utf8_lossy(&result.stderr)
            );
            assert!(String::from_utf8_lossy(&result.stdout).contains("1 passed"));
            return;
        }
        // Only this child process owns the reduced limits and exhaustion descriptors.
        let limit = libc::rlimit {
            rlim_cur: 128,
            rlim_max: 128,
        };
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) }, 0);
        let (_temp, ns) = fixture();
        let mut expected = vec![
            OsString::from("short"),
            long(0x80, 256),
            long(0x81, 509),
            long(0x82, 1024),
        ];
        for name in &expected {
            drop(create(&ns, ns.root_directory(), name));
        }
        expected.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        let fd_count = || fs::read_dir("/proc/self/fd").unwrap().count();
        let before = fd_count();
        let mut held = Vec::new();
        loop {
            match sys::duplicate(ns.root_fd()) {
                Ok(fd) => held.push(fd),
                Err(err) => {
                    assert_eq!(err.raw_os_error(), Some(libc::EMFILE));
                    break;
                }
            }
        }
        assert_eq!(
            ns.read()
                .unwrap()
                .list(ns.root_directory())
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EMFILE)
        );
        assert!(!ns.is_faulted());
        drop(held);
        for _ in 0..3 {
            let first = ns.read().unwrap().list(ns.root_directory()).unwrap();
            let second = ns.read().unwrap().list(ns.root_directory()).unwrap();
            assert_eq!(first, second);
            assert_eq!(
                first.iter().map(|entry| &entry.name).collect::<Vec<_>>(),
                expected.iter().collect::<Vec<_>>()
            );
            assert_eq!(fd_count(), before);
            drop((first, second));
            assert_eq!(fd_count(), before);
        }
        ns.finish().unwrap();
    }

    #[test]
    fn walk_scratch_initializes_only_encountered_depths() {
        for (length, depth) in [(None, 1), (Some(300), 2), (Some(MAX_NAME), 5)] {
            let (_temp, ns) = fixture();
            let expected = if let Some(length) = length {
                let name = long(0x80, length);
                let entry = create(&ns, ns.root_directory(), &name);
                vec![(name.into_vec(), entry.stat.st_ino)]
            } else {
                sys::mkdir_at(ns.root_fd(), TREE, 0o700).unwrap();
                Vec::new()
            };
            let _guard = ns.read().unwrap();
            let tree = sys::open_dir_at(ns.root_fd(), TREE).unwrap();
            let mut buffers: [Vec<u8>; 5] = std::array::from_fn(|_| Vec::new());
            let mut seen = Vec::new();
            ns.walk_prefix_with_buffers(
                tree,
                &mut Vec::new(),
                false,
                &mut |name, stat| {
                    seen.push((name, stat.stx_ino));
                    Ok(())
                },
                &mut buffers,
            )
            .unwrap();
            assert_eq!(seen, expected);
            for (index, buffer) in buffers.iter().enumerate() {
                assert_eq!(buffer.len(), if index < depth { 32 * 1024 } else { 0 });
                if index >= depth {
                    assert_eq!(buffer.capacity(), 0);
                }
            }
        }
    }

    #[test]
    fn recursive_scratch_preserves_batches_and_closes_fds_after_late_error() {
        let (temp, ns) = fixture();
        let mut expected = BTreeMap::new();
        // 132 distinct 255-byte prefix dirents exceed one 32 KiB TREE batch.
        for index in 0..132 {
            let mut raw = vec![0x80; MAX_NAME];
            raw[..4].copy_from_slice(format!("{index:04}").as_bytes());
            let name = OsString::from_vec(raw.clone());
            let entry = create(&ns, ns.root_directory(), &name);
            assert!(expected.insert(raw, entry.stat.st_ino).is_none());
        }
        let _guard = ns.read().unwrap();
        let live_fds = || {
            fs::read_dir("/proc/self/fd")
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .filter_map(|path| fs::read_link(path).ok())
                .filter(|path| path.starts_with(temp.path()))
                .count()
        };
        let before = live_fds();
        let mut buffers: [Vec<u8>; 5] = std::array::from_fn(|_| Vec::new());
        for errno in [libc::EIO, libc::ENOMEM] {
            let mut visited = 0;
            let failure = ns.walk_prefix_with_buffers(
                sys::open_dir_at(ns.root_fd(), TREE).unwrap(),
                &mut Vec::new(),
                false,
                &mut |_, _| {
                    visited += 1;
                    if visited == 2 {
                        Err(error(errno))
                    } else {
                        Ok(())
                    }
                },
                &mut buffers,
            );
            assert_eq!(failure.unwrap_err().raw_os_error(), Some(errno));
            assert_eq!(visited, 2);
            assert_eq!(live_fds(), before);
        }
        let pointers = buffers.each_ref().map(|buffer| buffer.as_ptr());
        assert!(buffers.iter().all(|buffer| buffer.len() == 32 * 1024));
        let mut seen = BTreeMap::new();
        ns.walk_prefix_with_buffers(
            sys::open_dir_at(ns.root_fd(), TREE).unwrap(),
            &mut Vec::new(),
            false,
            &mut |name, stat| {
                assert!(seen.insert(name, stat.stx_ino).is_none());
                Ok(())
            },
            &mut buffers,
        )
        .unwrap();
        assert_eq!(seen, expected);
        assert_eq!(buffers.each_ref().map(|buffer| buffer.as_ptr()), pointers);
        assert_eq!(live_fds(), before);
    }

    #[test]
    fn shared_prefix_pruning_stops_then_retires_without_removing_tree() {
        let (temp, ns) = fixture();
        let first = long(b'a', MAX_NAME);
        let mut raw = first.as_bytes().to_vec();
        raw[2 * FRAGMENT..].fill(b'b');
        let second = OsString::from_vec(raw);
        let removed = create(&ns, ns.root_directory(), &first);
        let survivor = create(&ns, ns.root_directory(), &second);
        let leaf = native_path(temp.path(), &first);
        let deepest = leaf.parent().unwrap();
        let third = deepest.parent().unwrap();
        let shared = third.parent().unwrap();
        ns.write()
            .unwrap()
            .unlink(ns.root_directory(), &first, false)
            .unwrap();
        assert!(!deepest.exists());
        assert!(!third.exists());
        assert!(shared.is_dir());
        assert_eq!(sys::stat(removed.fd.as_fd()).unwrap().st_nlink, 0);
        assert_eq!(
            ns.read()
                .unwrap()
                .lookup(ns.root_fd(), &second)
                .unwrap()
                .stat
                .st_ino,
            survivor.stat.st_ino
        );
        assert!(!ns.is_faulted());
        ns.write()
            .unwrap()
            .unlink(ns.root_directory(), &second, false)
            .unwrap();
        assert!(!shared.exists());
        let tree = temp.path().join(TREE.to_str().unwrap());
        assert!(tree.is_dir());
        assert_eq!(fs::read_dir(tree).unwrap().count(), 0);
        assert!(
            ns.read()
                .unwrap()
                .list(ns.root_directory())
                .unwrap()
                .is_empty()
        );
        ns.finish().unwrap();
    }

    #[test]
    fn early_prefix_errors_preserve_errno_and_existing_branches() {
        let (temp, ns) = fixture();
        let tree = temp.path().join(TREE.to_str().unwrap());
        fs::create_dir(&tree).unwrap();
        let blocked = long(b'x', MAX_NAME);
        let file = tree.join(format!("d{}", "x".repeat(FRAGMENT)));
        fs::write(&file, b"preserve").unwrap();
        let mut guard = ns.write().unwrap();
        assert_eq!(
            guard
                .create_file(
                    ns.root_directory(),
                    &blocked,
                    0o600,
                    libc::O_RDWR,
                    |_, _| Ok(())
                )
                .err()
                .unwrap()
                .raw_os_error(),
            Some(libc::ENOTDIR)
        );
        assert!(!guard.did_commit());
        assert!(!guard.needs_invalidation());
        drop(guard);
        assert_eq!(fs::read(file).unwrap(), b"preserve");
        let partial = long(b'p', MAX_NAME);
        let prefix = tree.join(format!("d{}", "p".repeat(FRAGMENT)));
        fs::create_dir(&prefix).unwrap();
        let name = Name::new(&partial).unwrap();
        let _guard = ns.write().unwrap();
        assert_eq!(
            ns.prune(ns.root_fd(), &name).unwrap_err().raw_os_error(),
            Some(libc::ENOENT)
        );
        assert!(prefix.is_dir());
        assert!(tree.is_dir());
        assert!(!ns.is_faulted());
    }

    #[test]
    fn canonical_boundaries_rebuild_after_finish_and_drop() {
        let (temp, ns) = fixture();
        let mut expected = Vec::new();
        for (i, len) in [255, 256, 508, 509, 1016, 1017, 1024]
            .into_iter()
            .enumerate()
        {
            let name = long(128 + i as u8, len);
            let entry = create(&ns, ns.root_directory(), &name);
            assert_eq!(
                ns.read()
                    .unwrap()
                    .lookup(ns.root_fd(), &name)
                    .unwrap()
                    .stat
                    .st_ino,
                entry.stat.st_ino
            );
            expected.push(name);
        }
        expected.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        let list = ns.read().unwrap().list(ns.root_directory()).unwrap();
        assert_eq!(
            list.into_iter().map(|e| e.name).collect::<Vec<_>>(),
            expected
        );
        ns.read().unwrap().fsync_dir(ns.root_fd()).unwrap();
        ns.finish().unwrap();
        drop(ns);
        let ns = Namespace::open(temp.path()).unwrap();
        assert_eq!(
            ns.read()
                .unwrap()
                .list(ns.root_directory())
                .unwrap()
                .into_iter()
                .map(|e| e.name)
                .collect::<Vec<_>>(),
            expected
        );
        drop(ns); // no finish call is needed to reconstruct canonical names
        let ns = Namespace::open(temp.path()).unwrap();
        assert_eq!(
            ns.read().unwrap().list(ns.root_directory()).unwrap().len(),
            expected.len()
        );
    }

    #[test]
    fn rename_updates_parent_and_preserves_open_inode_then_prunes() {
        let (temp, ns) = fixture();
        let left = ns
            .write()
            .unwrap()
            .mkdir(ns.root_directory(), OsStr::new("left"), 0o700)
            .unwrap();
        let right = ns
            .write()
            .unwrap()
            .mkdir(ns.root_directory(), OsStr::new("right"), 0o700)
            .unwrap();
        let old = long(b'a', 300);
        let new = long(b'b', 1024);
        let moved = ns
            .write()
            .unwrap()
            .mkdir(left.directory().unwrap(), &old, 0o700)
            .unwrap();
        create(&ns, moved.directory().unwrap(), OsStr::new("payload"));
        let callback = Cell::new(false);
        ns.write()
            .unwrap()
            .rename(
                left.directory().unwrap(),
                &old,
                right.directory().unwrap(),
                &new,
                0,
                |ino, parent| {
                    assert_eq!(ino, moved.stat.st_ino);
                    assert_eq!(key(&sys::stat(parent.as_fd()).unwrap()), key(&right.stat));
                    callback.set(true);
                },
            )
            .unwrap();
        assert!(callback.get());
        let entry = ns.read().unwrap().lookup(right.fd.as_fd(), &new).unwrap();
        assert_eq!(entry.stat.st_ino, moved.stat.st_ino);
        assert_eq!(
            key(&sys::stat(entry.parent.as_ref().unwrap().as_fd()).unwrap()),
            key(&right.stat)
        );
        assert_eq!(
            ns.read().unwrap().list(moved.directory().unwrap()).unwrap()[0].name,
            "payload"
        );
        assert!(!native_path(&temp.path().join("left"), &old).exists());
        let old_name = Name::new(&old).unwrap();
        let old_prefix = &old_name.path().to_bytes()[..old_name.prefix_ends()[1]];
        assert!(
            !temp
                .path()
                .join("left")
                .join(OsStr::from_bytes(old_prefix))
                .exists()
        );
        ns.write()
            .unwrap()
            .unlink(moved.directory().unwrap(), OsStr::new("payload"), false)
            .unwrap();
        ns.write()
            .unwrap()
            .unlink(right.directory().unwrap(), &new, true)
            .unwrap();
        assert_eq!(sys::stat(moved.fd.as_fd()).unwrap().st_nlink, 0);
    }

    #[test]
    fn same_name_rename_is_a_true_timestamp_noop() {
        let (_temp, ns) = fixture();
        let duplicate = Entry::from_fd(sys::duplicate(ns.root_fd()).unwrap()).unwrap();
        let root = duplicate.directory().unwrap();
        assert_ne!(root.as_fd().as_raw_fd(), ns.root_fd().as_raw_fd());
        assert_eq!(root.key(), ns.root_directory().key());
        let name = long(b'n', 300);
        create(&ns, ns.root_directory(), &name);
        let times = [libc::timespec {
            tv_sec: 7,
            tv_nsec: 0,
        }; 2];
        sys::cvt(unsafe {
            libc::utimensat(
                ns.root_fd().as_raw_fd(),
                c"".as_ptr(),
                times.as_ptr(),
                libc::AT_EMPTY_PATH,
            )
        })
        .unwrap();
        let before = sys::stat(ns.root_fd()).unwrap();
        let mut guard = ns.write().unwrap();
        guard
            .rename(root, &name, ns.root_directory(), &name, 0, |_, _| {
                panic!("no move")
            })
            .unwrap();
        assert!(!guard.needs_invalidation());
        assert_eq!(
            guard
                .rename(
                    root,
                    &name,
                    ns.root_directory(),
                    &name,
                    libc::RENAME_NOREPLACE,
                    |_, _| ()
                )
                .err()
                .unwrap()
                .raw_os_error(),
            Some(libc::EEXIST)
        );
        drop(guard);
        let after = sys::stat(ns.root_fd()).unwrap();
        assert_eq!(
            (
                before.st_mtime,
                before.st_mtime_nsec,
                before.st_ctime,
                before.st_ctime_nsec
            ),
            (
                after.st_mtime,
                after.st_mtime_nsec,
                after.st_ctime,
                after.st_ctime_nsec
            )
        );
    }

    #[test]
    fn native_success_then_error_is_unknown_without_guessed_reparent() {
        for errno in [libc::EIO, libc::ENOMEM] {
            let (temp, ns) = fixture();
            let left = ns
                .write()
                .unwrap()
                .mkdir(ns.root_directory(), OsStr::new("left"), 0o700)
                .unwrap();
            let right = ns
                .write()
                .unwrap()
                .mkdir(ns.root_directory(), OsStr::new("right"), 0o700)
                .unwrap();
            let old = long(b'o', 300);
            let new = long(b'p', 300);
            let child = ns
                .write()
                .unwrap()
                .mkdir(left.directory().unwrap(), &old, 0o700)
                .unwrap();
            ns.read().unwrap().list(left.directory().unwrap()).unwrap();
            let placeholder = long(b'k', 300);
            create(&ns, right.directory().unwrap(), &placeholder);
            ns.write()
                .unwrap()
                .unlink(right.directory().unwrap(), &placeholder, false)
                .unwrap();
            assert!(
                ns.read()
                    .unwrap()
                    .list(right.directory().unwrap())
                    .unwrap()
                    .is_empty()
            );
            assert_ne!(
                left.directory().unwrap().key(),
                right.directory().unwrap().key()
            );
            *ns.fault.lock() = Some((Fault::Native(Mutator::Rename), errno));
            let called = Cell::new(false);
            let mut guard = ns.write().unwrap();
            let result = guard.rename(
                left.directory().unwrap(),
                &old,
                right.directory().unwrap(),
                &new,
                0,
                |_, _| called.set(true),
            );
            assert_eq!(result.err().unwrap().raw_os_error(), Some(errno));
            assert!(!called.get());
            assert!(!guard.did_commit());
            assert!(guard.needs_invalidation());
            assert_eq!(guard.directory_to_invalidate(), Some(child.stat.st_ino));
            drop(guard);
            assert_unknown(&ns);
            ns.finish_notifications(true);
            assert_unknown(&ns);
            assert!(native_path(&temp.path().join("right"), &new).is_dir());
            assert!(!native_path(&temp.path().join("left"), &old).exists());
            drop(child);
            drop(left);
            drop(right);
            drop(ns);
            let ns = Namespace::open(temp.path()).unwrap();
            let right = ns
                .read()
                .unwrap()
                .lookup(ns.root_fd(), OsStr::new("right"))
                .unwrap();
            assert_eq!(
                ns.read().unwrap().list(right.directory().unwrap()).unwrap()[0].name,
                new
            );
        }
    }

    #[test]
    fn exclusive_create_late_permission_error_does_not_blindly_unlink() {
        let (temp, ns) = fixture();
        let name = long(b'q', 300);
        *ns.fault.lock() = Some((Fault::Native(Mutator::Create), libc::EACCES));
        let mut guard = ns.write().unwrap();
        let result = guard.create_file(ns.root_directory(), &name, 0o600, libc::O_RDWR, |_, _| {
            Ok(())
        });
        assert_eq!(result.err().unwrap().raw_os_error(), Some(libc::EACCES));
        assert!(guard.needs_invalidation());
        assert!(!guard.did_commit());
        drop(guard);
        assert_unknown(&ns);
        assert!(native_path(temp.path(), &name).is_file());
        drop(ns);
        let ns = Namespace::open(temp.path()).unwrap();
        assert!(ns.read().unwrap().lookup(ns.root_fd(), &name).is_ok());
    }

    #[test]
    fn known_postcommit_followup_fault_keeps_the_readable_result() {
        for point in [Fault::Touch, Fault::Prune] {
            let (_temp, ns) = fixture();
            let old = long(b'r', 300);
            let new = long(b's', 300);
            create(&ns, ns.root_directory(), &old);
            *ns.fault.lock() = Some((point, libc::EIO));
            let mut guard = ns.write().unwrap();
            assert_eq!(
                guard
                    .rename(
                        ns.root_directory(),
                        &old,
                        ns.root_directory(),
                        &new,
                        0,
                        |_, _| ()
                    )
                    .err()
                    .unwrap()
                    .raw_os_error(),
                Some(libc::EIO)
            );
            assert!(guard.did_commit());
            drop(guard);
            assert!(ns.read().unwrap().lookup(ns.root_fd(), &new).is_ok());
            assert_eq!(
                ns.read()
                    .unwrap()
                    .lookup(ns.root_fd(), &old)
                    .err()
                    .unwrap()
                    .raw_os_error(),
                Some(libc::ENOENT)
            );
            assert_eq!(ns.write().err().unwrap().raw_os_error(), Some(libc::EROFS));
            assert_eq!(
                ns.read()
                    .unwrap()
                    .fsync_dir(ns.root_fd())
                    .unwrap_err()
                    .raw_os_error(),
                Some(libc::EIO)
            );
            ns.finish_notifications(true);
            assert!(ns.read().is_ok());
            assert_eq!(ns.finish().unwrap_err().raw_os_error(), Some(libc::EROFS));
        }
    }

    #[test]
    fn registration_failure_is_committed_but_not_a_permanent_storage_fault() {
        let (_temp, ns) = fixture();
        let name = long(b't', 300);
        let mut guard = ns.write().unwrap();
        let result = guard.create_file(ns.root_directory(), &name, 0o600, libc::O_RDWR, |_, _| {
            Err::<(), _>(error(libc::EMFILE))
        });
        assert_eq!(result.err().unwrap().raw_os_error(), Some(libc::EMFILE));
        assert!(guard.did_commit());
        guard.mark_notification_pending();
        drop(guard);
        assert_eq!(ns.write().err().unwrap().raw_os_error(), Some(libc::EAGAIN));
        assert!(ns.read().unwrap().lookup(ns.root_fd(), &name).is_ok());
        assert_eq!(ns.finish().unwrap_err().raw_os_error(), Some(libc::EROFS));
        ns.finish_notifications(true);
        assert!(ns.write().is_ok());
        ns.finish().unwrap();
        ns.finish_notifications(false);
        assert_unknown(&ns);
        ns.finish_notifications(true);
        assert_unknown(&ns);
    }

    #[test]
    fn mutator_rejection_tables_are_small_and_operation_specific() {
        let cases: &[(Mutator, &[i32])] = &[
            (Mutator::Create, &[libc::EEXIST, libc::EMFILE, libc::ENFILE]),
            (Mutator::Mkdir, &[libc::EEXIST, libc::ENOENT, libc::ENOTDIR]),
            (
                Mutator::Symlink,
                &[libc::EEXIST, libc::ENOENT, libc::ENOTDIR],
            ),
            (
                Mutator::Unlink,
                &[libc::ENOENT, libc::EISDIR, libc::ENOTDIR],
            ),
            (
                Mutator::Rmdir,
                &[libc::ENOENT, libc::ENOTEMPTY, libc::ENOTDIR],
            ),
            (
                Mutator::Rename,
                &[
                    libc::ENOENT,
                    libc::EEXIST,
                    libc::ENOTEMPTY,
                    libc::ENOTDIR,
                    libc::EISDIR,
                    libc::EXDEV,
                ],
            ),
        ];
        for (op, expected) in cases {
            for errno in 1..=133 {
                assert_eq!(
                    known_rejection(*op, Some(errno)),
                    expected.contains(&errno),
                    "{op:?} errno {errno}"
                );
            }
            assert!(!known_rejection(*op, None));
        }
    }

    #[test]
    fn malformed_private_objects_are_errors_and_never_removed() {
        for name in [
            c".index",
            c".index.tmp.0000000000000000",
            c".index.tmp.0123456789abcdef",
            c".index.tmp.bad",
            c"bad",
            c"eabc",
        ] {
            let (temp, ns) = fixture();
            fs::create_dir(temp.path().join(TREE.to_str().unwrap())).unwrap();
            fs::write(
                temp.path()
                    .join(TREE.to_str().unwrap())
                    .join(OsStr::from_bytes(name.to_bytes())),
                b"x",
            )
            .unwrap();
            assert!(ns.read().unwrap().list(ns.root_directory()).is_err());
            assert!(
                temp.path()
                    .join(TREE.to_str().unwrap())
                    .join(OsStr::from_bytes(name.to_bytes()))
                    .exists()
            );
        }
        for special in ["directory", "symlink", "hardlink"] {
            let (temp, ns) = fixture();
            let tree = temp.path().join(TREE.to_str().unwrap());
            fs::create_dir(&tree).unwrap();
            let cache = tree.join(".index");
            match special {
                "directory" => fs::create_dir(&cache).unwrap(),
                "symlink" => symlink("missing", &cache).unwrap(),
                _ => {
                    fs::write(&cache, b"x").unwrap();
                    fs::hard_link(&cache, temp.path().join("link")).unwrap();
                }
            }
            assert!(
                ns.read().unwrap().list(ns.root_directory()).is_err(),
                "{special}"
            );
            assert!(fs::symlink_metadata(cache).is_ok());
        }
    }

    #[test]
    fn real_leaf_checks_reject_hardlinks_and_long_symlinks() {
        let (temp, ns) = fixture();
        let name = long(b'u', 300);
        create(&ns, ns.root_directory(), &name);
        fs::hard_link(native_path(temp.path(), &name), temp.path().join("alias")).unwrap();
        assert_eq!(
            ns.read()
                .unwrap()
                .lookup(ns.root_fd(), &name)
                .err()
                .unwrap()
                .raw_os_error(),
            Some(libc::EOPNOTSUPP)
        );
        assert_eq!(
            ns.write()
                .unwrap()
                .unlink(ns.root_directory(), &name, false)
                .err()
                .unwrap()
                .raw_os_error(),
            Some(libc::EOPNOTSUPP)
        );
        symlink("target", temp.path().join("symbol")).unwrap();
        fs::hard_link(temp.path().join("symbol"), temp.path().join("symbol2")).unwrap();
        assert_eq!(
            ns.read()
                .unwrap()
                .lookup(ns.root_fd(), OsStr::new("symbol"))
                .err()
                .unwrap()
                .raw_os_error(),
            Some(libc::EOPNOTSUPP)
        );
        assert_eq!(
            ns.write()
                .unwrap()
                .unlink(ns.root_directory(), OsStr::new("symbol"), false)
                .err()
                .unwrap()
                .raw_os_error(),
            Some(libc::EOPNOTSUPP)
        );
        assert_eq!(
            ns.write()
                .unwrap()
                .symlink(ns.root_directory(), &long(b'v', 300), OsStr::new("target"))
                .err()
                .unwrap()
                .raw_os_error(),
            Some(libc::EOPNOTSUPP)
        );
        assert!(!ns.is_faulted());
    }

    #[test]
    fn empty_private_branches_do_not_block_rmdir() {
        let (_temp, ns) = fixture();
        let dir = ns
            .write()
            .unwrap()
            .mkdir(ns.root_directory(), OsStr::new("directory"), 0o700)
            .unwrap();
        sys::mkdir_at(dir.fd.as_fd(), TREE, 0o700).unwrap();
        let tree = sys::open_dir_at(dir.fd.as_fd(), TREE).unwrap();
        let branch = CString::new([b"d".as_slice(), &[b'x'; 254]].concat()).unwrap();
        sys::mkdir_at(tree.as_fd(), &branch, 0o700).unwrap();
        assert!(
            ns.read()
                .unwrap()
                .list(dir.directory().unwrap())
                .unwrap()
                .is_empty()
        );
        ns.write()
            .unwrap()
            .unlink(ns.root_directory(), OsStr::new("directory"), true)
            .unwrap();
        assert_eq!(sys::stat(dir.fd.as_fd()).unwrap().st_nlink, 0);
    }

    #[test]
    fn old_cache_objects_prevent_rmdir_without_partial_cleanup() {
        for old_cache in [".index", ".index.tmp.0000000000000000"] {
            let (temp, ns) = fixture();
            let dir = ns
                .write()
                .unwrap()
                .mkdir(ns.root_directory(), OsStr::new("directory"), 0o700)
                .unwrap();
            let tree = temp.path().join("directory").join(TREE.to_str().unwrap());
            fs::create_dir(&tree).unwrap();
            let branch = tree.join(format!("d{}", "x".repeat(FRAGMENT)));
            fs::create_dir(&branch).unwrap();
            fs::write(tree.join(old_cache), b"preserve").unwrap();
            assert!(ns.read().unwrap().list(dir.directory().unwrap()).is_err());
            assert_eq!(
                ns.write()
                    .unwrap()
                    .unlink(ns.root_directory(), OsStr::new("directory"), true)
                    .unwrap_err()
                    .raw_os_error(),
                Some(libc::EIO)
            );
            assert_eq!(fs::read(tree.join(old_cache)).unwrap(), b"preserve");
            assert!(branch.is_dir());
            assert!(!ns.is_faulted());
        }
    }

    #[test]
    fn probe_recovery_validates_every_child_before_deleting_anything() {
        let (temp, ns) = fixture();
        drop(ns);
        let probe = temp.path().join(PROBE.to_str().unwrap());
        fs::create_dir(&probe).unwrap();
        fs::write(probe.join("file"), b"probe").unwrap();
        fs::create_dir(probe.join("before")).unwrap();
        fs::write(probe.join("unknown"), b"preserve").unwrap();
        assert!(Namespace::open(temp.path()).is_err());
        assert!(probe.join("file").exists());
        assert!(probe.join("before").exists());
        assert!(probe.join("unknown").exists());
        fs::remove_file(probe.join("unknown")).unwrap();
        fs::write(temp.path().join(".__LNL_PROBE"), b"legal user file").unwrap();
        let ns = Namespace::open(temp.path()).unwrap();
        assert!(!probe.exists());
        assert_eq!(
            fs::read(temp.path().join(".__LNL_PROBE")).unwrap(),
            b"legal user file"
        );
        assert!(
            ns.read()
                .unwrap()
                .list(ns.root_directory())
                .unwrap()
                .iter()
                .any(|e| e.name == ".__LNL_PROBE")
        );
    }

    #[test]
    fn every_startup_syncs_the_marker_before_creating_or_recovering_probes() {
        let temp = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).unwrap();
        let calls = Cell::new(0);
        // The first failure leaves a marker. Its retry must still sync it.
        for _ in 0..2 {
            let result = Namespace::open_with_format_sync(temp.path(), |root| {
                calls.set(calls.get() + 1);
                assert_eq!(sys::read_xattr(root, FORMAT_XATTR, 64).unwrap(), FORMAT);
                assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 0);
                Err(error(libc::EIO))
            });
            assert_eq!(result.err().unwrap().raw_os_error(), Some(libc::EIO));
        }
        assert_eq!(calls.get(), 2);
        let probe = temp.path().join(PROBE.to_str().unwrap());
        fs::create_dir(&probe).unwrap();
        fs::write(probe.join("file"), b"probe").unwrap();
        fs::create_dir(probe.join("before")).unwrap();
        let result = Namespace::open_with_format_sync(temp.path(), |root| {
            calls.set(calls.get() + 1);
            assert_eq!(sys::read_xattr(root, FORMAT_XATTR, 64).unwrap(), FORMAT);
            assert_eq!(fs::read(probe.join("file")).unwrap(), b"probe");
            assert!(probe.join("before").is_dir());
            Err(error(libc::EIO))
        });
        assert_eq!(result.err().unwrap().raw_os_error(), Some(libc::EIO));
        assert_eq!(calls.get(), 3);
        assert_eq!(fs::read(probe.join("file")).unwrap(), b"probe");
        assert!(probe.join("before").is_dir());
        let ns = Namespace::open(temp.path()).unwrap();
        assert!(!probe.exists());
        assert!(
            ns.read()
                .unwrap()
                .list(ns.root_directory())
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn finish_does_not_publish_private_metadata() {
        let (temp, ns) = fixture();
        create(&ns, ns.root_directory(), &long(b'w', 300));
        assert_eq!(
            ns.read().unwrap().list(ns.root_directory()).unwrap().len(),
            1
        );
        let tree = temp.path().join(TREE.to_str().unwrap());
        let before: Vec<_> = fs::read_dir(&tree)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        ns.finish().unwrap();
        let after: Vec<_> = fs::read_dir(&tree)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(before, after);
        assert_eq!(after.len(), 1);
        assert_eq!(
            sys::read_xattr(ns.root_fd(), c"user.lnfs_lite.session", 64)
                .unwrap_err()
                .raw_os_error(),
            Some(libc::ENODATA)
        );
    }

    #[test]
    fn unmarked_nonempty_and_foreign_formats_are_never_adopted() {
        let temp = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).unwrap();
        fs::write(temp.path().join("user"), b"keep").unwrap();
        assert!(Namespace::open(temp.path()).is_err());
        assert_eq!(fs::read(temp.path().join("user")).unwrap(), b"keep");
        fs::remove_file(temp.path().join("user")).unwrap();
        let root = sys::open_root(temp.path()).unwrap();
        for foreign in [b"lnfs-lite:1\n", b"lnfs-lite:2\n"] {
            sys::set_xattr(root.as_fd(), FORMAT_XATTR, foreign).unwrap();
            assert!(Namespace::open(temp.path()).is_err());
            assert_eq!(
                sys::read_xattr(root.as_fd(), FORMAT_XATTR, 64).unwrap(),
                foreign
            );
            assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 0);
        }
    }
}
