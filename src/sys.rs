use std::ffi::{CStr, CString};
use std::io;
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

pub fn cvt(value: libc::c_int) -> io::Result<()> {
    if value == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn owned(fd: libc::c_int) -> io::Result<OwnedFd> {
    if fd == -1 {
        Err(io::Error::last_os_error())
    } else {
        // The successful syscall transfers exactly one descriptor to this owner.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}

pub fn proc_path(fd: BorrowedFd<'_>) -> CString {
    CString::new(format!("/proc/self/fd/{}", fd.as_raw_fd())).expect("numeric FD contains no NUL")
}

pub fn open_root(path: &Path) -> io::Result<OwnedFd> {
    let path =
        CString::new(path.as_os_str().as_bytes()).map_err(|_| crate::name::error(libc::EINVAL))?;
    // The C string is live through the syscall; no pointer is retained.
    owned(unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    })
}

pub fn open_beneath(
    parent: BorrowedFd<'_>,
    name: &CStr,
    flags: i32,
    mode: u32,
) -> io::Result<OwnedFd> {
    #[repr(C)]
    struct OpenHow {
        flags: u64,
        mode: u64,
        resolve: u64,
    }
    let how = OpenHow {
        flags: (flags | libc::O_CLOEXEC) as u64,
        mode: mode as u64,
        resolve: 0x01 | 0x04 | 0x08, // NO_XDEV | NO_SYMLINKS | BENEATH.
    };
    // open_how is the stable 24-byte Linux ABI. Linux 6.9+ is required, no fallback.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            parent.as_raw_fd(),
            name.as_ptr(),
            &how as *const OpenHow,
            std::mem::size_of::<OpenHow>(),
        )
    };
    owned(fd as libc::c_int)
}

pub fn open_path_at(parent: BorrowedFd<'_>, name: &CStr) -> io::Result<OwnedFd> {
    open_beneath(parent, name, libc::O_PATH | libc::O_NOFOLLOW, 0)
}

/// A strict directory handle used only as an *at base, never for reads or fsync.
pub fn open_dir_anchor_at(parent: BorrowedFd<'_>, name: &CStr) -> io::Result<OwnedFd> {
    open_beneath(
        parent,
        name,
        libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW,
        0,
    )
}

pub fn open_dir_at(parent: BorrowedFd<'_>, name: &CStr) -> io::Result<OwnedFd> {
    open_beneath(
        parent,
        name,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW,
        0,
    )
}

pub fn duplicate(fd: BorrowedFd<'_>) -> io::Result<OwnedFd> {
    // F_DUPFD_CLOEXEC returns an independently owned reference to the same object.
    owned(unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) })
}

pub fn reopen(fd: BorrowedFd<'_>, flags: i32) -> io::Result<OwnedFd> {
    let path = proc_path(fd);
    // Follow the proc magic link to the pinned inode, not a reconstructed path.
    owned(unsafe { libc::open(path.as_ptr(), flags | libc::O_CLOEXEC) })
}

pub fn stat(fd: BorrowedFd<'_>) -> io::Result<libc::stat> {
    let mut stat = MaybeUninit::<libc::stat>::uninit();
    // fstat initializes the complete struct on success.
    cvt(unsafe { libc::fstat(fd.as_raw_fd(), stat.as_mut_ptr()) })?;
    Ok(unsafe { stat.assume_init() })
}

pub fn statx_name(parent: BorrowedFd<'_>, name: &CStr, flags: i32) -> io::Result<libc::statx> {
    const FIELDS: u32 = libc::STATX_TYPE | libc::STATX_NLINK | libc::STATX_INO | libc::STATX_MNT_ID;
    let mut stat = MaybeUninit::<libc::statx>::uninit();
    // This single component is inspected without following its final symlink or automount.
    cvt(unsafe {
        libc::statx(
            parent.as_raw_fd(),
            name.as_ptr(),
            flags | libc::AT_SYMLINK_NOFOLLOW | libc::AT_NO_AUTOMOUNT,
            FIELDS,
            stat.as_mut_ptr(),
        )
    })?;
    // A successful syscall initializes the struct; the mask still governs field validity.
    let stat = unsafe { stat.assume_init() };
    if stat.stx_mask & FIELDS != FIELDS {
        return Err(crate::name::error(libc::EOPNOTSUPP));
    }
    Ok(stat)
}

pub fn statfs(fd: BorrowedFd<'_>) -> io::Result<libc::statfs> {
    let mut stat = MaybeUninit::<libc::statfs>::uninit();
    // fstatfs initializes the complete struct on success.
    cvt(unsafe { libc::fstatfs(fd.as_raw_fd(), stat.as_mut_ptr()) })?;
    Ok(unsafe { stat.assume_init() })
}

pub fn sync(fd: BorrowedFd<'_>) -> io::Result<()> {
    // The borrowed descriptor remains valid until fsync returns.
    cvt(unsafe { libc::fsync(fd.as_raw_fd()) })
}

pub fn mkdir_at(parent: BorrowedFd<'_>, name: &CStr, mode: u32) -> io::Result<()> {
    // The string and borrowed FD remain live until mkdirat returns.
    cvt(unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), mode as libc::mode_t) })
}

pub fn unlink_at(parent: BorrowedFd<'_>, name: &CStr, directory: bool) -> io::Result<()> {
    let flags = if directory { libc::AT_REMOVEDIR } else { 0 };
    // The string and borrowed FD remain live until unlinkat returns.
    cvt(unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), flags) })
}

pub fn rename_at(
    old_parent: BorrowedFd<'_>,
    old_name: &CStr,
    new_parent: BorrowedFd<'_>,
    new_name: &CStr,
    flags: u32,
) -> io::Result<()> {
    // Both strings and directory FDs remain live until renameat2 returns.
    cvt(unsafe {
        libc::renameat2(
            old_parent.as_raw_fd(),
            old_name.as_ptr(),
            new_parent.as_raw_fd(),
            new_name.as_ptr(),
            flags,
        )
    })
}

pub fn symlink_at(parent: BorrowedFd<'_>, name: &CStr, target: &CStr) -> io::Result<()> {
    // Both C strings and the borrowed directory FD remain live.
    cvt(unsafe { libc::symlinkat(target.as_ptr(), parent.as_raw_fd(), name.as_ptr()) })
}

pub fn read_xattr(fd: BorrowedFd<'_>, name: &CStr, max_len: usize) -> io::Result<Vec<u8>> {
    let path = proc_path(fd);
    let mut value = vec![0; max_len];
    // The proc magic link follows the pinned object; the output allocation is writable.
    let count = unsafe {
        libc::getxattr(
            path.as_ptr(),
            name.as_ptr(),
            value.as_mut_ptr().cast(),
            value.len(),
        )
    };
    if count == -1 {
        return Err(io::Error::last_os_error());
    }
    value.truncate(count as usize);
    Ok(value)
}

pub fn set_xattr(fd: BorrowedFd<'_>, name: &CStr, value: &[u8]) -> io::Result<()> {
    let path = proc_path(fd);
    // The kernel copies the value before return; following proc targets the inode.
    cvt(unsafe {
        libc::setxattr(
            path.as_ptr(),
            name.as_ptr(),
            value.as_ptr().cast(),
            value.len(),
            0,
        )
    })
}

pub fn remove_xattr(fd: BorrowedFd<'_>, name: &CStr) -> io::Result<()> {
    let path = proc_path(fd);
    // Both path strings are NUL-terminated and remain live.
    cvt(unsafe { libc::removexattr(path.as_ptr(), name.as_ptr()) })
}

pub fn touch_directory(fd: BorrowedFd<'_>) -> io::Result<()> {
    let times = [
        libc::timespec {
            tv_sec: 0,
            tv_nsec: libc::UTIME_OMIT,
        },
        libc::timespec {
            tv_sec: 0,
            tv_nsec: libc::UTIME_NOW,
        },
    ];
    // AT_EMPTY_PATH addresses the pinned directory, including an O_PATH FD.
    cvt(unsafe {
        libc::utimensat(
            fd.as_raw_fd(),
            c"".as_ptr(),
            times.as_ptr(),
            libc::AT_EMPTY_PATH,
        )
    })
}

pub struct DirectoryEntry {
    pub name: CString,
    pub native_ino: u64,
    pub kind: u8,
}

const DIRECTORY_BUFFER: usize = 32 * 1024;

/// Owns a fresh readable CLOEXEC directory description and borrows initialized scratch.
pub struct DirectoryStream<'a> {
    fd: OwnedFd,
    buffer: &'a mut [u8],
    filled: usize,
    cursor: usize,
}

impl<'a> DirectoryStream<'a> {
    pub fn new(fd: OwnedFd, buffer: &'a mut Vec<u8>) -> io::Result<Self> {
        if buffer.is_empty() {
            buffer
                .try_reserve_exact(DIRECTORY_BUFFER)
                .map_err(|_| crate::name::error(libc::ENOMEM))?;
            // getdents64 leaves padding untouched; initialize each depth only once.
            buffer.resize(DIRECTORY_BUFFER, 0);
        } else if buffer.len() != DIRECTORY_BUFFER {
            return Err(crate::name::error(libc::EINVAL));
        }
        Ok(Self {
            fd,
            buffer: buffer.as_mut_slice(),
            filled: 0,
            cursor: 0,
        })
    }

    pub fn fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }

    pub fn next_entry(&mut self) -> io::Result<Option<DirectoryEntry>> {
        if self.cursor == self.filled {
            // The owned FD and exclusively borrowed initialized buffer stay live.
            let count = unsafe {
                libc::syscall(
                    libc::SYS_getdents64,
                    self.fd.as_raw_fd(),
                    self.buffer.as_mut_ptr(),
                    self.buffer.len(),
                )
            };
            self.filled = directory_read_size(count, self.buffer.len())?;
            self.cursor = 0;
            if self.filled == 0 {
                return Ok(None);
            }
        }
        let (entry, length) = decode_dirent(&self.buffer[self.cursor..self.filled])?;
        self.cursor += length;
        Ok(Some(entry))
    }
}

fn directory_read_size(count: libc::c_long, capacity: usize) -> io::Result<usize> {
    if count < 0 {
        let err = io::Error::last_os_error();
        // Match glibc readdir for already-open deleted directories.
        return if err.raw_os_error() == Some(libc::ENOENT) {
            Ok(0)
        } else {
            Err(err)
        };
    }
    let count = count as usize;
    if count > capacity {
        return Err(crate::name::error(libc::EIO));
    }
    Ok(count)
}

fn decode_dirent(bytes: &[u8]) -> io::Result<(DirectoryEntry, usize)> {
    if bytes.len() < 19 {
        return Err(crate::name::error(libc::EIO));
    }
    let length = u16::from_ne_bytes([bytes[16], bytes[17]]) as usize;
    if length < 24 || !length.is_multiple_of(8) || length > bytes.len() {
        return Err(crate::name::error(libc::EIO));
    }
    let region = &bytes[19..length];
    let end = region
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| crate::name::error(libc::EIO))?;
    let name = &region[..end];
    if name.is_empty() || name.contains(&b'/') {
        return Err(crate::name::error(libc::EIO));
    }
    Ok((
        DirectoryEntry {
            name: CString::new(name).expect("name ends before the first NUL"),
            native_ino: u64::from_ne_bytes(bytes[..8].try_into().expect("checked header")),
            kind: bytes[18],
        },
        length,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::fs::File;
    use std::os::unix::ffi::OsStringExt;

    fn record(name: &[u8], ino: u64, kind: u8, offset: i64) -> Vec<u8> {
        let length = (19 + name.len() + 1 + 7) & !7;
        let mut bytes = vec![0xa5; length];
        bytes[..8].copy_from_slice(&ino.to_ne_bytes());
        bytes[8..16].copy_from_slice(&offset.to_ne_bytes());
        bytes[16..18].copy_from_slice(&(length as u16).to_ne_bytes());
        bytes[18] = kind;
        bytes[19..19 + name.len()].copy_from_slice(name);
        bytes[19 + name.len()] = 0;
        bytes
    }

    #[test]
    fn directory_anchors_are_path_only_strict_and_usable_as_at_bases() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir(temp.path().join("directory")).unwrap();
        std::fs::write(temp.path().join("file"), b"preserve").unwrap();
        std::os::unix::fs::symlink("directory", temp.path().join("symbol")).unwrap();
        let parent = File::open(temp.path()).unwrap();
        let anchor = open_dir_anchor_at(parent.as_fd(), c"directory").unwrap();
        let flags = unsafe { libc::fcntl(anchor.as_raw_fd(), libc::F_GETFL) };
        assert!(flags >= 0);
        let expected = libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW;
        assert_eq!(flags & expected, expected);
        let descriptor_flags = unsafe { libc::fcntl(anchor.as_raw_fd(), libc::F_GETFD) };
        assert_eq!(descriptor_flags, libc::FD_CLOEXEC);
        mkdir_at(anchor.as_fd(), c"child", 0o700).unwrap();
        let mut buffer = Vec::new();
        let mut stream =
            DirectoryStream::new(open_dir_at(anchor.as_fd(), c".").unwrap(), &mut buffer).unwrap();
        let mut found = false;
        while let Some(entry) = stream.next_entry().unwrap() {
            found |= entry.name == c"child";
        }
        assert!(found);
        sync(stream.fd()).unwrap();
        assert_eq!(
            sync(anchor.as_fd()).unwrap_err().raw_os_error(),
            Some(libc::EBADF)
        );
        unlink_at(anchor.as_fd(), c"child", true).unwrap();
        for name in [c"file", c"symbol", c"symbol/child"] {
            let errno = open_dir_anchor_at(parent.as_fd(), name)
                .unwrap_err()
                .raw_os_error();
            assert!(
                matches!(errno, Some(libc::ENOTDIR | libc::ELOOP)),
                "{name:?}: {errno:?}"
            );
        }
        assert_eq!(
            open_dir_anchor_at(parent.as_fd(), c"..")
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EXDEV)
        );
        assert_eq!(
            std::fs::read(temp.path().join("file")).unwrap(),
            b"preserve"
        );
    }

    #[test]
    fn dirent_parser_preserves_raw_names_hints_and_opaque_offsets() {
        for (name, ino, kind, offset) in [
            (b".".as_slice(), 1, libc::DT_DIR, i64::MAX),
            (b"..".as_slice(), 0, libc::DT_UNKNOWN, -42),
            (b"\xff\xfe".as_slice(), u64::MAX, libc::DT_REG, 0),
            (&[0x80; 255], 9, libc::DT_LNK, 1),
        ] {
            let bytes = record(name, ino, kind, offset);
            let (entry, consumed) = decode_dirent(&bytes).unwrap();
            assert_eq!(consumed, bytes.len());
            assert_eq!(entry.name.to_bytes(), name);
            assert_eq!(entry.native_ino, ino);
            assert_eq!(entry.kind, kind);
        }
    }

    #[test]
    fn dirent_parser_checks_each_record_at_an_exact_batch_boundary() {
        let mut batch = Vec::new();
        for _ in 0..1362 {
            batch.extend(record(b"a", 1, libc::DT_REG, 0));
        }
        batch.extend(record(&[b'b'; 60], 2, libc::DT_REG, -1));
        assert_eq!(batch.len(), DIRECTORY_BUFFER);
        let mut cursor = 0;
        let mut count = 0;
        while cursor < batch.len() {
            let (_, length) = decode_dirent(&batch[cursor..]).unwrap();
            cursor += length;
            count += 1;
        }
        assert_eq!(cursor, DIRECTORY_BUFFER);
        assert_eq!(count, 1363);
    }

    #[test]
    fn dirent_parser_rejects_malformed_records_without_reading_the_next_one() {
        let valid = record(b"name", 1, libc::DT_REG, 0);
        let mut invalid = vec![vec![0; 18], valid[..valid.len() - 1].to_vec()];
        for length in [0u16, 16, 20, 25, 40] {
            let mut bytes = valid.clone();
            bytes[16..18].copy_from_slice(&length.to_ne_bytes());
            invalid.push(bytes);
        }
        let mut no_nul = valid.clone();
        no_nul[19..].fill(0xaa);
        invalid.push(no_nul.clone());
        no_nul.extend(record(b"later", 2, libc::DT_REG, 0));
        invalid.push(no_nul);
        invalid.push(record(b"", 1, libc::DT_REG, 0));
        invalid.push(record(b"a/b", 1, libc::DT_REG, 0));
        for bytes in invalid {
            assert_eq!(
                decode_dirent(&bytes).err().unwrap().raw_os_error(),
                Some(libc::EIO)
            );
        }
    }

    #[test]
    fn directory_reads_preserve_errors_and_deleted_directory_eof() {
        assert_eq!(directory_read_size(0, DIRECTORY_BUFFER).unwrap(), 0);
        assert_eq!(
            directory_read_size(DIRECTORY_BUFFER as libc::c_long, DIRECTORY_BUFFER).unwrap(),
            DIRECTORY_BUFFER
        );
        assert_eq!(
            directory_read_size(DIRECTORY_BUFFER as libc::c_long + 1, DIRECTORY_BUFFER)
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EIO)
        );
        for errno in [
            libc::ENOENT,
            libc::EINTR,
            libc::EBADF,
            libc::ENOTDIR,
            libc::EIO,
        ] {
            // errno is thread-local; no intervening call can replace this test value.
            unsafe { *libc::__errno_location() = errno };
            let result = directory_read_size(-1, DIRECTORY_BUFFER);
            if errno == libc::ENOENT {
                assert_eq!(result.unwrap(), 0);
            } else {
                assert_eq!(result.unwrap_err().raw_os_error(), Some(errno));
            }
        }
    }

    #[test]
    fn native_stream_reads_owned_names_without_shared_cursors() {
        let temp = tempfile::tempdir().unwrap();
        let mut expected = HashSet::from([c".".to_owned(), c"..".to_owned()]);
        for i in 0..300 {
            let mut name = format!("{i:04}").into_bytes();
            name.extend(std::iter::repeat_n(0x80 + (i % 127) as u8, 251));
            let path = temp.path().join(std::ffi::OsString::from_vec(name.clone()));
            File::create(path).unwrap();
            expected.insert(CString::new(name).unwrap());
        }
        let first_fd = File::open(temp.path()).unwrap().into();
        let second_fd = File::open(temp.path()).unwrap().into();
        let mut first_buffer = Vec::new();
        let mut second_buffer = Vec::new();
        let mut first = DirectoryStream::new(first_fd, &mut first_buffer).unwrap();
        let mut second = DirectoryStream::new(second_fd, &mut second_buffer).unwrap();
        let mut first_names = HashSet::new();
        let mut second_names = HashSet::new();
        loop {
            let a = first.next_entry().unwrap();
            let b = second.next_entry().unwrap();
            if a.is_none() && b.is_none() {
                break;
            }
            if let Some(entry) = a {
                assert!(first_names.insert(entry.name));
            }
            if let Some(entry) = b {
                assert!(second_names.insert(entry.name));
            }
        }
        assert_eq!(first_names, expected);
        assert_eq!(second_names, expected);
    }

    #[test]
    fn reused_stream_buffer_discards_unread_directory_records() {
        let temp = tempfile::tempdir().unwrap();
        let first_dir = temp.path().join("first");
        let second_dir = temp.path().join("second");
        std::fs::create_dir(&first_dir).unwrap();
        std::fs::create_dir(&second_dir).unwrap();
        File::create(first_dir.join("old")).unwrap();
        let fresh = std::ffi::OsString::from_vec(b"fresh\xff".to_vec());
        File::create(second_dir.join(&fresh)).unwrap();
        let mut buffer = Vec::new();
        {
            let fd = File::open(&first_dir).unwrap().into();
            let mut stream = DirectoryStream::new(fd, &mut buffer).unwrap();
            assert!(stream.next_entry().unwrap().is_some());
            assert!(stream.cursor < stream.filled);
        }
        let pointer = buffer.as_ptr();
        let capacity = buffer.capacity();
        let mut names = HashSet::new();
        {
            let fd = File::open(&second_dir).unwrap().into();
            let mut stream = DirectoryStream::new(fd, &mut buffer).unwrap();
            while let Some(entry) = stream.next_entry().unwrap() {
                assert!(names.insert(entry.name));
            }
        }
        assert_eq!(
            names,
            HashSet::from([c".".to_owned(), c"..".to_owned(), c"fresh\xff".to_owned()])
        );
        assert_eq!(buffer.len(), DIRECTORY_BUFFER);
        assert_eq!(buffer.capacity(), capacity);
        assert_eq!(buffer.as_ptr(), pointer);
    }

    #[test]
    fn stream_buffers_reject_nonempty_wrong_lengths() {
        let temp = tempfile::tempdir().unwrap();
        for length in [1, DIRECTORY_BUFFER - 1, DIRECTORY_BUFFER + 1] {
            let fd = File::open(temp.path()).unwrap().into();
            let mut buffer = vec![0; length];
            assert_eq!(
                DirectoryStream::new(fd, &mut buffer)
                    .err()
                    .unwrap()
                    .raw_os_error(),
                Some(libc::EINVAL)
            );
            assert_eq!(buffer.len(), length);
        }
    }

    #[test]
    fn invalid_stream_descriptors_propagate_native_read_errors() {
        let file = tempfile::tempfile().unwrap();
        let mut buffer = Vec::new();
        let mut stream = DirectoryStream::new(file.into(), &mut buffer).unwrap();
        assert_eq!(
            stream.next_entry().err().unwrap().raw_os_error(),
            Some(libc::ENOTDIR)
        );
        let temp = tempfile::tempdir().unwrap();
        let parent = File::open(temp.path()).unwrap();
        let path = open_path_at(parent.as_fd(), c".").unwrap();
        drop(stream);
        let mut stream = DirectoryStream::new(path, &mut buffer).unwrap();
        assert_eq!(
            stream.next_entry().err().unwrap().raw_os_error(),
            Some(libc::EBADF)
        );
    }
}
