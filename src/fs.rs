use std::{
    ffi::{CString, OsStr},
    io,
    os::{
        fd::{AsFd, AsRawFd, BorrowedFd},
        unix::ffi::OsStrExt,
    },
    path::Path,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use fuser::{
    AccessFlags, BackingId, BsdFileFlags, CopyFileRangeFlags, Errno, FileAttr, FileHandle as Fh,
    FileType, Filesystem, FopenFlags, Generation, INodeNo, InitFlags, KernelConfig, LockOwner,
    OpenFlags, RenameFlags, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory, ReplyEmpty,
    ReplyEntry, ReplyLseek, ReplyOpen, ReplyStatfs, ReplyWrite, ReplyXattr, Request, TimeOrNow,
    WriteFlags,
};
use parking_lot::Mutex;

use crate::{
    handle::{DirectoryHandle, DirectoryView, FileHandle, Handles},
    inode::{Inodes, NodeRef},
    name,
    namespace::{Entry, Namespace, WriteGuard},
    notify::{InvalidationBatch, Invalidations},
    sys,
};

/// Entry/attribute timestamps may be cached for this bounded interval.
pub const TTL: Duration = Duration::from_secs(1);

pub struct LiteFs {
    namespace: Arc<Namespace>,
    invalidations: Arc<Invalidations>,
    inodes: Inodes,
    handles: Handles,
}

impl LiteFs {
    pub fn new(namespace: Arc<Namespace>, invalidations: Arc<Invalidations>) -> io::Result<Self> {
        let root = namespace.root_fd().try_clone_to_owned()?;
        let stat = sys::stat(root.as_fd())?;
        Ok(Self {
            namespace,
            invalidations,
            inodes: Inodes::new(root, stat),
            handles: Handles::default(),
        })
    }

    fn entry_attr(&self, entry: Entry) -> io::Result<FileAttr> {
        let stat = entry.stat;
        let node = self.inodes.intern(entry, 1)?;
        Ok(file_attr(&stat, node.ino))
    }

    fn entry_reply(&self, result: io::Result<FileAttr>, reply: ReplyEntry) {
        match result {
            Ok(attr) => reply.entry(&TTL, &attr, Generation(0)),
            Err(err) => reply.error(err.into()),
        }
    }

    /// Finish the write guard before directory notifications; the caller replies
    /// before submitting the returned dentry batch to the independent worker.
    fn finish_mutation<T>(
        &self,
        mut namespace: WriteGuard<'_>,
        mut result: io::Result<T>,
        batch: InvalidationBatch,
        cross_parent: bool,
    ) -> (io::Result<T>, Option<InvalidationBatch>) {
        let repair = result.is_err() && namespace.needs_invalidation();
        let directories = namespace.directories_to_invalidate();
        let moved =
            cross_parent && namespace.did_commit() && directories.iter().any(Option::is_some);
        if !repair && !moved {
            return (result, None);
        }
        namespace.mark_notification_pending();
        drop(namespace);

        let mut failure = None;
        if repair {
            let mut previous = None;
            for parent in batch.parents() {
                if previous != Some(parent.ino) {
                    if let Err(err) = self.invalidations.directory(parent.ino) {
                        failure.get_or_insert(err);
                    }
                    previous = Some(parent.ino);
                }
            }
        }
        for native_ino in directories.into_iter().flatten() {
            if let Err(err) = self
                .inodes
                .number(native_ino)
                .and_then(|ino| self.invalidations.directory(ino))
            {
                failure.get_or_insert(err);
            }
        }
        if let Some(err) = failure {
            self.namespace.finish_notifications(false);
            eprintln!("lnfs-lite: directory cache repair failed; remount required: {err}");
            result = Err(io::Error::from_raw_os_error(libc::EIO));
        }
        if result.is_err() {
            (result, Some(batch))
        } else {
            // Successful cross-parent directory moves need no dentry repair.
            self.namespace.finish_notifications(true);
            (result, None)
        }
    }

    fn submit_repair(&self, batch: Option<InvalidationBatch>) {
        if let Some(batch) = batch
            && let Err(err) = self.invalidations.submit(batch, &self.namespace)
        {
            eprintln!("lnfs-lite: {err}");
        }
    }

    fn dot_attr(&self, node: &NodeRef, parent: bool) -> io::Result<FileAttr> {
        let stat = if !parent || node.ino == 1 {
            sys::stat(node.fd.as_fd())?
        } else {
            let parent = node.parent.lock();
            let fd = parent
                .as_ref()
                .ok_or_else(|| io::Error::from_raw_os_error(libc::EIO))?;
            sys::stat(fd.as_fd())?
        };
        Ok(file_attr(&stat, self.inodes.number(stat.st_ino)?))
    }

    fn remove_entry(&self, parent: INodeNo, name: &OsStr, directory: bool, reply: ReplyEmpty) {
        let mut repair = None;
        let result = (|| {
            let parent = self.inodes.get(parent.0)?;
            let batch = InvalidationBatch::one(parent.clone(), name);
            let mut namespace = self.namespace.write()?;
            parent.changed();
            let entry = namespace.lookup(parent.fd.as_fd(), name)?;
            let victim = self.inodes.pin_removed(entry)?;
            let result = namespace.unlink(parent.directory()?, name, directory);
            self.inodes.release_linked_pin(victim);
            let (result, pending) = self.finish_mutation(namespace, result, batch, false);
            repair = pending;
            result
        })();
        empty_reply(reply, result);
        self.submit_repair(repair);
    }

    fn registered(
        &self,
        node: &NodeRef,
        register: impl FnOnce(BorrowedFd<'_>) -> io::Result<BackingId>,
    ) -> io::Result<Arc<BackingId>> {
        let mut slot = node.backing.lock();
        if let Some(backing) = slot.upgrade() {
            return Ok(backing);
        }
        let backing = Arc::new(register(node.fd.as_fd())?);
        *slot = Arc::downgrade(&backing);
        Ok(backing)
    }

    fn xattr_node(&self, ino: u64, key: Option<&OsStr>, write: bool) -> io::Result<NodeRef> {
        if let Some(key) = key {
            let bytes = key.as_bytes();
            if name::is_internal_xattr(bytes) || !bytes.starts_with(b"user.") {
                return Err(io::Error::from_raw_os_error(if write {
                    libc::EPERM
                } else {
                    libc::ENODATA
                }));
            }
        }
        let node = self.inodes.get(ino)?;
        if !matches!(node.mode & libc::S_IFMT, libc::S_IFREG | libc::S_IFDIR) {
            return Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP));
        }
        Ok(node)
    }
}

impl Filesystem for LiteFs {
    fn init(&mut self, _req: &Request, config: &mut KernelConfig) -> io::Result<()> {
        config
            .set_max_stack_depth(1)
            .map_err(|_| io::Error::other("FUSE stacking depth 1 is unavailable"))?;
        config
            .add_capabilities(
                InitFlags::FUSE_PASSTHROUGH
                    | InitFlags::FUSE_PARALLEL_DIROPS
                    | InitFlags::FUSE_AUTO_INVAL_DATA,
            )
            .map_err(|missing| {
                io::Error::other(format!(
                    "required FUSE capabilities unavailable: {missing:?}"
                ))
            })?;
        eprintln!("lnfs-lite: FUSE passthrough negotiated");
        Ok(())
    }

    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        let result = (|| {
            let parent = self.inodes.get(parent.0)?;
            let namespace = self.namespace.read()?;
            self.entry_attr(namespace.lookup(parent.fd.as_fd(), name)?)
        })();
        self.entry_reply(result, reply);
    }

    fn forget(&self, _req: &Request, ino: INodeNo, count: u64) {
        self.inodes.forget(ino.0, count);
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, fh: Option<Fh>, reply: ReplyAttr) {
        let result: io::Result<FileAttr> = (|| {
            let node = self.inodes.get(ino.0)?;
            if node.mode & libc::S_IFMT == libc::S_IFREG
                && let Some(fh) = fh
            {
                let handle = self.handles.file(fh.0, ino.0)?;
                return Ok(file_attr(&sys::stat(handle.fd.as_fd())?, ino.0));
            }
            let _namespace = self.namespace.read()?;
            if let Some(fh) = fh {
                self.handles.directory(fh.0, ino.0)?;
            }
            Ok(file_attr(&sys::stat(node.fd.as_fd())?, ino.0))
        })();
        match result {
            Ok(attr) => reply.attr(&TTL, &attr),
            Err(err) => reply.error(err.into()),
        }
    }

    fn setattr(
        &self,
        _req: &Request,
        ino: INodeNo,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        fh: Option<Fh>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        flags: Option<BsdFileFlags>,
        reply: ReplyAttr,
    ) {
        let result = (|| {
            let _namespace = if fh.is_none() {
                Some(self.namespace.read()?)
            } else {
                None
            };
            if flags.is_some_and(|flags| !flags.is_empty()) {
                return Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP));
            }
            let node = self.inodes.get(ino.0)?;
            let handle = fh.map(|fh| self.handles.file(fh.0, ino.0)).transpose()?;
            if let Some(mode) = mode {
                if node.mode & libc::S_IFMT == libc::S_IFLNK {
                    return Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP));
                }
                let path = sys::proc_path(node.fd.as_fd());
                sys::cvt(unsafe { libc::chmod(path.as_ptr(), mode & 0o7777) })?;
            }
            if uid.is_some() || gid.is_some() {
                sys::cvt(unsafe {
                    libc::fchownat(
                        node.fd.as_raw_fd(),
                        c"".as_ptr(),
                        uid.unwrap_or(u32::MAX),
                        gid.unwrap_or(u32::MAX),
                        libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
                    )
                })?;
            }
            if let Some(size) = size {
                if node.mode & libc::S_IFMT != libc::S_IFREG {
                    return Err(io::Error::from_raw_os_error(
                        if node.mode & libc::S_IFMT == libc::S_IFDIR {
                            libc::EISDIR
                        } else {
                            libc::EINVAL
                        },
                    ));
                }
                let size = size
                    .try_into()
                    .map_err(|_| io::Error::from_raw_os_error(libc::EFBIG))?;
                let reopened;
                let fd = if let Some(handle) = &handle {
                    handle.fd.as_fd()
                } else {
                    reopened = sys::reopen(node.fd.as_fd(), libc::O_WRONLY)?;
                    reopened.as_fd()
                };
                sys::cvt(unsafe { libc::ftruncate(fd.as_raw_fd(), size) })?;
            }
            if atime.is_some() || mtime.is_some() {
                let times = [timespec(atime)?, timespec(mtime)?];
                sys::cvt(unsafe {
                    libc::utimensat(
                        node.fd.as_raw_fd(),
                        c"".as_ptr(),
                        times.as_ptr(),
                        libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
                    )
                })?;
            }
            Ok(file_attr(&sys::stat(node.fd.as_fd())?, ino.0))
        })();
        match result {
            Ok(attr) => reply.attr(&TTL, &attr),
            Err(err) => reply.error(err.into()),
        }
    }

    fn readlink(&self, _req: &Request, ino: INodeNo, reply: ReplyData) {
        let result = (|| {
            let _namespace = self.namespace.read()?;
            let node = self.inodes.get(ino.0)?;
            let mut bytes = vec![0u8; 4096];
            let size = unsafe {
                libc::readlinkat(
                    node.fd.as_raw_fd(),
                    c"".as_ptr(),
                    bytes.as_mut_ptr().cast(),
                    bytes.len(),
                )
            };
            if size < 0 {
                return Err(io::Error::last_os_error());
            }
            if size as usize == bytes.len() {
                return Err(io::Error::from_raw_os_error(libc::ENAMETOOLONG));
            }
            bytes.truncate(size as usize);
            Ok(bytes)
        })();
        match result {
            Ok(bytes) => reply.data(&bytes),
            Err(err) => reply.error(err.into()),
        }
    }

    fn mkdir(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        umask: u32,
        reply: ReplyEntry,
    ) {
        let mut repair = None;
        let result = (|| {
            let parent = self.inodes.get(parent.0)?;
            let batch = InvalidationBatch::one(parent.clone(), name);
            let mut namespace = self.namespace.write()?;
            parent.changed();
            let result = namespace
                .mkdir(parent.directory()?, name, mode & !umask)
                .and_then(|entry| self.entry_attr(entry));
            let (result, pending) = self.finish_mutation(namespace, result, batch, false);
            repair = pending;
            result
        })();
        self.entry_reply(result, reply);
        self.submit_repair(repair);
    }

    fn mknod(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        umask: u32,
        _rdev: u32,
        reply: ReplyEntry,
    ) {
        let mut repair = None;
        let result = (|| {
            let parent = self.inodes.get(parent.0)?;
            let batch = InvalidationBatch::one(parent.clone(), name);
            let mut namespace = self.namespace.write()?;
            parent.changed();
            let result = namespace
                .mknod(parent.directory()?, name, mode & !umask)
                .and_then(|entry| self.entry_attr(entry));
            let (result, pending) = self.finish_mutation(namespace, result, batch, false);
            repair = pending;
            result
        })();
        self.entry_reply(result, reply);
        self.submit_repair(repair);
    }

    fn symlink(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        target: &Path,
        reply: ReplyEntry,
    ) {
        let mut repair = None;
        let result = (|| {
            let parent = self.inodes.get(parent.0)?;
            let batch = InvalidationBatch::one(parent.clone(), name);
            let mut namespace = self.namespace.write()?;
            parent.changed();
            let result = namespace
                .symlink(parent.directory()?, name, target.as_os_str())
                .and_then(|entry| self.entry_attr(entry));
            let (result, pending) = self.finish_mutation(namespace, result, batch, false);
            repair = pending;
            result
        })();
        self.entry_reply(result, reply);
        self.submit_repair(repair);
    }

    fn unlink(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        self.remove_entry(parent, name, false, reply);
    }

    fn rmdir(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        self.remove_entry(parent, name, true, reply);
    }

    fn rename(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        newparent: INodeNo,
        newname: &OsStr,
        flags: RenameFlags,
        reply: ReplyEmpty,
    ) {
        let mut repair = None;
        let result = (|| {
            let parent = self.inodes.get(parent.0)?;
            let newparent = self.inodes.get(newparent.0)?;
            let old_directory = parent.directory()?;
            let new_directory = newparent.directory()?;
            let cross_parent = old_directory.key() != new_directory.key();
            let batch = InvalidationBatch::two(parent.clone(), name, newparent.clone(), newname);
            let mut namespace = self.namespace.write()?;
            parent.changed();
            if cross_parent {
                newparent.changed();
            }
            let victim = if flags.is_empty() {
                match namespace.lookup(newparent.fd.as_fd(), newname) {
                    Ok(entry) => Some(self.inodes.pin_removed(entry)?),
                    Err(error) if error.raw_os_error() == Some(libc::ENOENT) => None,
                    Err(error) => return Err(error),
                }
            } else {
                None
            };
            let result = namespace.rename(
                old_directory,
                name,
                new_directory,
                newname,
                flags.bits(),
                |native_ino, parent| self.inodes.reparent_native(native_ino, parent),
            );
            if let Some(victim) = victim {
                self.inodes.release_linked_pin(victim);
            }
            let (result, pending) = self.finish_mutation(namespace, result, batch, cross_parent);
            repair = pending;
            result
        })();
        empty_reply(reply, result);
        self.submit_repair(repair);
    }

    fn link(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _newparent: INodeNo,
        _newname: &OsStr,
        reply: ReplyEntry,
    ) {
        reply.error(Errno::EOPNOTSUPP);
    }

    fn open(&self, _req: &Request, ino: INodeNo, flags: OpenFlags, reply: ReplyOpen) {
        let result = (|| {
            let _namespace = self.namespace.read()?;
            let node = self.inodes.get(ino.0)?;
            if node.mode & libc::S_IFMT != libc::S_IFREG {
                return Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP));
            }
            let fd = sys::reopen(
                node.fd.as_fd(),
                flags.0 & !(libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW),
            )?;
            let backing = self.registered(&node, |fd| reply.open_backing(fd))?;
            let fh = self.handles.insert_file(FileHandle {
                fd,
                node,
                _backing: backing.clone(),
            })?;
            Ok((fh, backing))
        })();
        match result {
            Ok((fh, backing)) => reply.opened_passthrough(Fh(fh), FopenFlags::empty(), &backing),
            Err(err) => reply.error(err.into()),
        }
    }

    fn create(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        umask: u32,
        flags: i32,
        reply: ReplyCreate,
    ) {
        let mut repair = None;
        let result = (|| {
            let parent = self.inodes.get(parent.0)?;
            let batch = InvalidationBatch::one(parent.clone(), name);
            let mut namespace = self.namespace.write()?;
            parent.changed();
            let result = (|| {
                let (entry, fd, registration) = namespace.create_file(
                    parent.directory()?,
                    name,
                    mode & !umask,
                    flags,
                    |entry, _| reply.open_backing(entry.fd.as_fd()).map(Arc::new),
                )?;
                let stat = entry.stat;
                let node = self.inodes.intern(entry, 0)?;
                let backing = {
                    let mut slot = node.backing.lock();
                    match slot.upgrade() {
                        Some(backing) => backing,
                        None => {
                            *slot = Arc::downgrade(&registration);
                            registration
                        }
                    }
                };
                let fh = self.handles.insert_file(FileHandle {
                    fd,
                    node: node.clone(),
                    _backing: backing.clone(),
                })?;
                if let Err(err) = self.inodes.add_lookup(&node) {
                    self.handles.remove_file(fh, node.ino)?;
                    return Err(err);
                }
                Ok((fh, backing, file_attr(&stat, node.ino)))
            })();
            let (result, pending) = self.finish_mutation(namespace, result, batch, false);
            repair = pending;
            result
        })();
        match result {
            Ok((fh, backing, attr)) => reply.created_passthrough(
                &TTL,
                &attr,
                Generation(0),
                Fh(fh),
                FopenFlags::empty(),
                &backing,
            ),
            Err(err) => reply.error(err.into()),
        }
        self.submit_repair(repair);
    }

    fn read(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: Fh,
        _offset: u64,
        _size: u32,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyData,
    ) {
        eprintln!("lnfs-lite: unexpected userspace read; passthrough is required");
        reply.error(Errno::EIO);
    }

    fn write(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: Fh,
        _offset: u64,
        _data: &[u8],
        _write_flags: WriteFlags,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyWrite,
    ) {
        eprintln!("lnfs-lite: unexpected userspace write; passthrough is required");
        reply.error(Errno::EIO);
    }

    fn release(
        &self,
        _req: &Request,
        ino: INodeNo,
        fh: Fh,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        empty_reply(reply, self.handles.remove_file(fh.0, ino.0));
    }

    fn flush(
        &self,
        _req: &Request,
        ino: INodeNo,
        fh: Fh,
        _lock_owner: LockOwner,
        reply: ReplyEmpty,
    ) {
        // Passthrough has no daemon-side buffered writes; durability is explicit fsync.
        empty_reply(reply, self.handles.file(fh.0, ino.0).map(|_| ()));
    }

    fn fsync(&self, _req: &Request, ino: INodeNo, fh: Fh, data: bool, reply: ReplyEmpty) {
        empty_reply(
            reply,
            self.handles.file(fh.0, ino.0).and_then(|handle| {
                sys::cvt(unsafe {
                    if data {
                        libc::fdatasync(handle.fd.as_raw_fd())
                    } else {
                        libc::fsync(handle.fd.as_raw_fd())
                    }
                })
            }),
        );
    }

    fn fallocate(
        &self,
        _req: &Request,
        ino: INodeNo,
        fh: Fh,
        offset: u64,
        length: u64,
        mode: i32,
        reply: ReplyEmpty,
    ) {
        empty_reply(
            reply,
            (|| {
                let handle = self.handles.file(fh.0, ino.0)?;
                let offset = offset
                    .try_into()
                    .map_err(|_| io::Error::from_raw_os_error(libc::EFBIG))?;
                let length = length
                    .try_into()
                    .map_err(|_| io::Error::from_raw_os_error(libc::EFBIG))?;
                sys::cvt(unsafe { libc::fallocate(handle.fd.as_raw_fd(), mode, offset, length) })
            })(),
        );
    }

    fn copy_file_range(
        &self,
        _req: &Request,
        ino_in: INodeNo,
        fh_in: Fh,
        offset_in: u64,
        ino_out: INodeNo,
        fh_out: Fh,
        offset_out: u64,
        len: u64,
        flags: CopyFileRangeFlags,
        reply: ReplyWrite,
    ) {
        let result = (|| {
            let source = self.handles.file(fh_in.0, ino_in.0)?;
            let target = self.handles.file(fh_out.0, ino_out.0)?;
            sys::copy_file_range(
                source.fd.as_fd(),
                offset_in,
                target.fd.as_fd(),
                offset_out,
                len,
                flags.bits(),
            )
        })();
        match result {
            Ok(copied) => reply.written(copied),
            Err(err) => reply.error(err.into()),
        }
    }

    fn lseek(
        &self,
        _req: &Request,
        ino: INodeNo,
        fh: Fh,
        offset: i64,
        whence: i32,
        reply: ReplyLseek,
    ) {
        let result = (|| {
            let handle = self.handles.file(fh.0, ino.0)?;
            let result = unsafe { libc::lseek(handle.fd.as_raw_fd(), offset, whence) };
            if result < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(result)
            }
        })();
        match result {
            Ok(offset) => reply.offset(offset),
            Err(err) => reply.error(err.into()),
        }
    }

    fn opendir(&self, _req: &Request, ino: INodeNo, _flags: OpenFlags, reply: ReplyOpen) {
        let result = (|| {
            let _namespace = self.namespace.read()?;
            let node = self.inodes.get(ino.0)?;
            if node.mode & libc::S_IFMT != libc::S_IFDIR {
                return Err(io::Error::from_raw_os_error(libc::ENOTDIR));
            }
            self.handles.insert_directory(DirectoryHandle {
                node,
                view: Mutex::new(DirectoryView::default()),
            })
        })();
        match result {
            // Only directories use KEEP_CACHE; it is invalid for data passthrough.
            Ok(fh) => reply.opened(
                Fh(fh),
                FopenFlags::FOPEN_CACHE_DIR | FopenFlags::FOPEN_KEEP_CACHE,
            ),
            Err(err) => reply.error(err.into()),
        }
    }

    fn readdir(
        &self,
        _req: &Request,
        ino: INodeNo,
        fh: Fh,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        let result: io::Result<()> = (|| {
            let handle = self.handles.directory(fh.0, ino.0)?;
            let namespace = self.namespace.read()?;
            let mut view = handle.view.lock();
            view.refresh(handle.node.generation(), offset == 0, || {
                namespace.list(handle.node.directory()?)
            })?;
            let mut position = view.position(offset)?;
            while position < 2 {
                let attr = self.dot_attr(&handle.node, position == 1)?;
                let name = if position == 0 { "." } else { ".." };
                if reply.add(attr.ino, position as u64 + 1, FileType::Directory, name) {
                    return Ok(());
                }
                position += 1;
            }
            for (index, entry) in view.entries.iter().enumerate().skip(position - 2) {
                if reply.add(
                    INodeNo(self.inodes.number(entry.native_ino)?),
                    directory_cookie(index)?,
                    dirent_type(entry.kind)?,
                    &entry.name,
                ) {
                    break;
                }
            }
            Ok(())
        })();
        match result {
            Ok(()) => reply.ok(),
            Err(err) => reply.error(err.into()),
        }
    }

    fn releasedir(
        &self,
        _req: &Request,
        ino: INodeNo,
        fh: Fh,
        _flags: OpenFlags,
        reply: ReplyEmpty,
    ) {
        empty_reply(reply, self.handles.remove_directory(fh.0, ino.0));
    }

    fn fsyncdir(&self, _req: &Request, ino: INodeNo, fh: Fh, _datasync: bool, reply: ReplyEmpty) {
        empty_reply(
            reply,
            (|| {
                let handle = self.handles.directory(fh.0, ino.0)?;
                self.namespace.read()?.fsync_dir(handle.node.fd.as_fd())
            })(),
        );
    }

    fn getxattr(&self, _req: &Request, ino: INodeNo, key: &OsStr, size: u32, reply: ReplyXattr) {
        let result = (|| {
            // Unsupported keys have a constant answer, including first-write capability checks.
            let node = self.xattr_node(ino.0, Some(key), false)?;
            let _namespace = self.namespace.read()?;
            let path = sys::proc_path(node.fd.as_fd());
            let key = CString::new(key.as_bytes())?;
            if size == 0 {
                let count =
                    unsafe { libc::getxattr(path.as_ptr(), key.as_ptr(), std::ptr::null_mut(), 0) };
                return xattr_count(count).map(|count| (count, Vec::new()));
            }
            let mut bytes = vec![0; size as usize];
            let count = unsafe {
                libc::getxattr(
                    path.as_ptr(),
                    key.as_ptr(),
                    bytes.as_mut_ptr().cast(),
                    bytes.len(),
                )
            };
            let count = xattr_count(count)?;
            bytes.truncate(count as usize);
            Ok((count, bytes))
        })();
        match result {
            Ok((count, _)) if size == 0 => reply.size(count),
            Ok((_, bytes)) => reply.data(&bytes),
            Err(err) => reply.error(err.into()),
        }
    }

    fn listxattr(&self, _req: &Request, ino: INodeNo, size: u32, reply: ReplyXattr) {
        let result = (|| {
            let _namespace = self.namespace.read()?;
            let node = self.xattr_node(ino.0, None, false)?;
            let path = sys::proc_path(node.fd.as_fd());
            let count =
                xattr_count(unsafe { libc::listxattr(path.as_ptr(), std::ptr::null_mut(), 0) })?;
            let mut bytes = vec![0u8; count as usize];
            if count != 0 {
                let actual = xattr_count(unsafe {
                    libc::listxattr(path.as_ptr(), bytes.as_mut_ptr().cast(), bytes.len())
                })?;
                bytes.truncate(actual as usize);
            }
            let mut visible = Vec::new();
            for key in bytes.split(|byte| *byte == 0).filter(|key| !key.is_empty()) {
                if key.starts_with(b"user.") && !name::is_internal_xattr(key) {
                    visible.extend_from_slice(key);
                    visible.push(0);
                }
            }
            if size != 0 && visible.len() > size as usize {
                return Err(io::Error::from_raw_os_error(libc::ERANGE));
            }
            Ok(visible)
        })();
        match result {
            Ok(bytes) if size == 0 => reply.size(bytes.len() as u32),
            Ok(bytes) => reply.data(&bytes),
            Err(err) => reply.error(err.into()),
        }
    }

    fn setxattr(
        &self,
        _req: &Request,
        ino: INodeNo,
        key: &OsStr,
        value: &[u8],
        flags: i32,
        position: u32,
        reply: ReplyEmpty,
    ) {
        empty_reply(
            reply,
            (|| {
                let _namespace = self.namespace.read()?;
                if position != 0 {
                    return Err(io::Error::from_raw_os_error(libc::EINVAL));
                }
                let node = self.xattr_node(ino.0, Some(key), true)?;
                let path = sys::proc_path(node.fd.as_fd());
                let key = CString::new(key.as_bytes())?;
                sys::cvt(unsafe {
                    libc::setxattr(
                        path.as_ptr(),
                        key.as_ptr(),
                        value.as_ptr().cast(),
                        value.len(),
                        flags,
                    )
                })
            })(),
        );
    }

    fn removexattr(&self, _req: &Request, ino: INodeNo, key: &OsStr, reply: ReplyEmpty) {
        empty_reply(
            reply,
            (|| {
                let _namespace = self.namespace.read()?;
                let node = self.xattr_node(ino.0, Some(key), true)?;
                let path = sys::proc_path(node.fd.as_fd());
                let key = CString::new(key.as_bytes())?;
                sys::cvt(unsafe { libc::removexattr(path.as_ptr(), key.as_ptr()) })
            })(),
        );
    }

    fn access(&self, _req: &Request, ino: INodeNo, mask: AccessFlags, reply: ReplyEmpty) {
        empty_reply(
            reply,
            (|| {
                let _namespace = self.namespace.read()?;
                let node = self.inodes.get(ino.0)?;
                sys::cvt(unsafe {
                    libc::faccessat(
                        node.fd.as_raw_fd(),
                        c"".as_ptr(),
                        mask.bits(),
                        libc::AT_EMPTY_PATH | libc::AT_EACCESS | libc::AT_SYMLINK_NOFOLLOW,
                    )
                })
            })(),
        );
    }

    fn statfs(&self, _req: &Request, _ino: INodeNo, reply: ReplyStatfs) {
        let mut stats = std::mem::MaybeUninit::uninit();
        let result =
            unsafe { libc::fstatvfs(self.namespace.root_fd().as_raw_fd(), stats.as_mut_ptr()) };
        if result < 0 {
            reply.error(io::Error::last_os_error().into());
            return;
        }
        let stats = unsafe { stats.assume_init() };
        reply.statfs(
            stats.f_blocks,
            stats.f_bfree,
            stats.f_bavail,
            stats.f_files,
            stats.f_ffree,
            stats.f_bsize as u32,
            name::MAX_NAME as u32,
            stats.f_frsize as u32,
        );
    }
}

fn directory_cookie(index: usize) -> io::Result<u64> {
    index
        .checked_add(3)
        .and_then(|next| next.try_into().ok())
        .ok_or_else(|| io::Error::from_raw_os_error(libc::EOVERFLOW))
}

fn xattr_count(result: isize) -> io::Result<u32> {
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        result
            .try_into()
            .map_err(|_| io::Error::from_raw_os_error(libc::EOVERFLOW))
    }
}

fn empty_reply(reply: ReplyEmpty, result: io::Result<()>) {
    match result {
        Ok(()) => reply.ok(),
        Err(err) => reply.error(err.into()),
    }
}

fn file_type(mode: u32) -> FileType {
    match mode & libc::S_IFMT {
        libc::S_IFDIR => FileType::Directory,
        libc::S_IFLNK => FileType::Symlink,
        libc::S_IFIFO => FileType::NamedPipe,
        libc::S_IFSOCK => FileType::Socket,
        libc::S_IFCHR => FileType::CharDevice,
        libc::S_IFBLK => FileType::BlockDevice,
        _ => FileType::RegularFile,
    }
}

fn dirent_type(kind: u8) -> io::Result<FileType> {
    match kind {
        libc::DT_REG => Ok(FileType::RegularFile),
        libc::DT_DIR => Ok(FileType::Directory),
        libc::DT_LNK => Ok(FileType::Symlink),
        libc::DT_FIFO => Ok(FileType::NamedPipe),
        libc::DT_SOCK => Ok(FileType::Socket),
        libc::DT_CHR => Ok(FileType::CharDevice),
        libc::DT_BLK => Ok(FileType::BlockDevice),
        _ => Err(io::Error::from_raw_os_error(libc::EIO)),
    }
}

fn system_time(seconds: i64, nanos: i64) -> SystemTime {
    if seconds >= 0 {
        UNIX_EPOCH + Duration::new(seconds as u64, nanos as u32)
    } else {
        UNIX_EPOCH - Duration::from_secs(seconds.unsigned_abs())
            + Duration::from_nanos(nanos as u64)
    }
}

fn file_attr(stat: &libc::stat, ino: u64) -> FileAttr {
    FileAttr {
        ino: INodeNo(ino),
        size: stat.st_size as u64,
        blocks: stat.st_blocks as u64,
        atime: system_time(stat.st_atime, stat.st_atime_nsec),
        mtime: system_time(stat.st_mtime, stat.st_mtime_nsec),
        ctime: system_time(stat.st_ctime, stat.st_ctime_nsec),
        crtime: UNIX_EPOCH,
        kind: file_type(stat.st_mode),
        perm: (stat.st_mode & 0o7777) as u16,
        nlink: if stat.st_mode & libc::S_IFMT == libc::S_IFDIR {
            u32::from(stat.st_nlink != 0)
        } else {
            stat.st_nlink as u32
        },
        uid: stat.st_uid,
        gid: stat.st_gid,
        rdev: stat.st_rdev as u32,
        blksize: stat.st_blksize as u32,
        flags: 0,
    }
}

fn timespec(time: Option<TimeOrNow>) -> io::Result<libc::timespec> {
    let (tv_sec, tv_nsec) = match time {
        None => (0, libc::UTIME_OMIT),
        Some(TimeOrNow::Now) => (0, libc::UTIME_NOW),
        Some(TimeOrNow::SpecificTime(time)) => match time.duration_since(UNIX_EPOCH) {
            Ok(delta) => (
                delta
                    .as_secs()
                    .try_into()
                    .map_err(|_| io::Error::from_raw_os_error(libc::EOVERFLOW))?,
                delta.subsec_nanos() as i64,
            ),
            Err(delta) => {
                let delta = delta.duration();
                let seconds: i64 = delta
                    .as_secs()
                    .try_into()
                    .map_err(|_| io::Error::from_raw_os_error(libc::EOVERFLOW))?;
                if delta.subsec_nanos() == 0 {
                    (-seconds, 0)
                } else {
                    (-seconds - 1, 1_000_000_000 - delta.subsec_nanos() as i64)
                }
            }
        },
    };
    Ok(libc::timespec { tv_sec, tv_nsec })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn directory_attributes_preserve_unlinked_zero() {
        let temp = tempfile::tempdir().unwrap();
        let directory = std::fs::File::open(temp.path()).unwrap();
        let mut stat = sys::stat(directory.as_fd()).unwrap();
        stat.st_nlink = 8;
        assert_eq!(file_attr(&stat, 1).nlink, 1);
        stat.st_nlink = 0;
        assert_eq!(file_attr(&stat, 1).nlink, 0);
        assert_eq!(directory_cookie(0).unwrap(), 3);
        assert!(directory_cookie(usize::MAX).is_err());
    }

    #[test]
    fn timestamps_before_epoch_round_trip() {
        let value = UNIX_EPOCH - Duration::from_millis(1500);
        let ts = timespec(Some(TimeOrNow::SpecificTime(value))).unwrap();
        assert_eq!((ts.tv_sec, ts.tv_nsec), (-2, 500_000_000));
        assert_eq!(system_time(ts.tv_sec, ts.tv_nsec), value);
        assert_eq!(timespec(None).unwrap().tv_nsec, libc::UTIME_OMIT);
    }
}
