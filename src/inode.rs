use std::{
    collections::HashMap,
    io,
    ops::Deref,
    os::fd::{AsFd, OwnedFd},
    sync::{
        Arc, Weak,
        atomic::{AtomicU64, Ordering},
    },
};

use fuser::BackingId;
use parking_lot::Mutex;

use crate::{
    namespace::{DirKey, Directory, Entry},
    sys::{self, NativeHandle},
};

pub struct Node {
    pub ino: u64,
    handle: Option<NativeHandle>,
    pub mode: u32,
    native_key: DirKey,
    pub backing: Mutex<Weak<BackingId>>,
    pub parent: Mutex<Option<OwnedFd>>,
    generation: AtomicU64,
}

impl Node {
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Relaxed)
    }

    /// The namespace write guard excludes readers while a generation changes.
    pub fn changed(&self) {
        // Exhaustion permanently disables handle-view reuse rather than wrapping.
        let _ = self
            .generation
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |old| {
                old.checked_add(1)
            });
    }
}

struct Slot {
    node: Arc<Node>,
    pin: Option<Arc<OwnedFd>>,
    lookups: u64,
}

struct State {
    slots: HashMap<u64, Slot>,
    #[cfg(test)]
    pin_stat_error: Option<i32>,
}

pub struct Inodes {
    state: Arc<Mutex<State>>,
    mount: Arc<OwnedFd>,
    root_dev: u64,
    root_ino: u64,
}

/// Every request and open handle owns its FD independently of the slot's pin.
pub struct NodeRef {
    pub fd: Arc<OwnedFd>,
    node: Option<Arc<Node>>,
    state: Weak<Mutex<State>>,
}

impl NodeRef {
    pub fn directory(&self) -> io::Result<Directory<'_>> {
        Directory::from_validated(self.fd.as_fd(), self.native_key, self.mode)
    }
}

impl Clone for NodeRef {
    fn clone(&self) -> Self {
        Self {
            fd: self.fd.clone(),
            node: self.node.clone(),
            state: self.state.clone(),
        }
    }
}

impl Deref for NodeRef {
    type Target = Node;

    fn deref(&self) -> &Node {
        self.node.as_deref().expect("live inode reference")
    }
}

impl Drop for NodeRef {
    fn drop(&mut self) {
        let Some(state) = self.state.upgrade() else {
            return;
        };
        let removed = {
            let mut state = state.lock();
            let node = self.node.take().expect("live inode reference");
            let ino = node.ino;
            // Drop under the table lock: simultaneous last-pin drops must reap once.
            drop(node);
            reap(&mut state, ino)
        };
        // Closing the inode and parent FDs does not occupy the table mutex.
        drop(removed);
    }
}

fn reap(state: &mut State, ino: u64) -> Option<Slot> {
    if ino != 1
        && state
            .slots
            .get(&ino)
            .is_some_and(|slot| slot.lookups == 0 && Arc::strong_count(&slot.node) == 1)
    {
        state.slots.remove(&ino)
    } else {
        None
    }
}

impl Inodes {
    pub fn new(fd: OwnedFd, stat: libc::stat) -> Self {
        let fd = Arc::new(fd);
        let node = Arc::new(Node {
            ino: 1,
            handle: None,
            mode: stat.st_mode,
            native_key: DirKey {
                dev: stat.st_dev,
                ino: stat.st_ino,
            },
            backing: Mutex::new(Weak::new()),
            parent: Mutex::new(None),
            generation: AtomicU64::new(0),
        });
        Self {
            mount: fd.clone(),
            root_dev: stat.st_dev,
            root_ino: stat.st_ino,
            state: Arc::new(Mutex::new(State {
                slots: HashMap::from([(
                    1,
                    Slot {
                        node,
                        pin: Some(fd),
                        lookups: 0,
                    },
                )]),
                #[cfg(test)]
                pin_stat_error: None,
            })),
        }
    }

    /// The single-filesystem contract makes native inode numbers unambiguous.
    pub fn number(&self, native_ino: u64) -> io::Result<u64> {
        if native_ino == self.root_ino {
            Ok(1)
        } else {
            native_ino
                .checked_add(2)
                .ok_or_else(|| io::Error::from_raw_os_error(libc::EOVERFLOW))
        }
    }

    pub fn get(&self, ino: u64) -> io::Result<NodeRef> {
        // Reopening and clearing a destructive-operation pin share this lock.
        let state = self.state.lock();
        let slot = state
            .slots
            .get(&ino)
            .ok_or_else(|| io::Error::from_raw_os_error(libc::ESTALE))?;
        let fd = match &slot.pin {
            Some(fd) => fd.clone(),
            None => {
                let fd = slot
                    .node
                    .handle
                    .as_ref()
                    .expect("unpinned regular inode has a native handle")
                    .open(self.mount.as_fd())?;
                let stat = sys::stat(fd.as_fd())?;
                if slot.node.native_key
                    != (DirKey {
                        dev: stat.st_dev,
                        ino: stat.st_ino,
                    })
                    || stat.st_mode & libc::S_IFMT != slot.node.mode & libc::S_IFMT
                {
                    return Err(io::Error::from_raw_os_error(libc::ESTALE));
                }
                Arc::new(fd)
            }
        };
        Ok(NodeRef {
            fd,
            node: Some(slot.node.clone()),
            state: Arc::downgrade(&self.state),
        })
    }

    /// The caller retains its namespace guard through parent initialization.
    pub fn intern(&self, entry: Entry, lookups: u64) -> io::Result<NodeRef> {
        if entry.stat.st_dev != self.root_dev {
            return Err(io::Error::from_raw_os_error(libc::EXDEV));
        }
        let ino = self.number(entry.stat.st_ino)?;
        let handle =
            if entry.stat.st_mode & libc::S_IFMT == libc::S_IFREG && entry.stat.st_nlink > 0 {
                Some(NativeHandle::capture(entry.fd.as_fd())?)
            } else {
                None
            };
        let native_key = DirKey {
            dev: entry.stat.st_dev,
            ino: entry.stat.st_ino,
        };
        let fd = Arc::new(entry.fd);
        let mut state = self.state.lock();
        let slot = match state.slots.entry(ino) {
            std::collections::hash_map::Entry::Occupied(slot) => {
                let slot = slot.into_mut();
                if slot.node.native_key != native_key
                    || slot.node.mode & libc::S_IFMT != entry.stat.st_mode & libc::S_IFMT
                    || slot.node.handle != handle
                {
                    return Err(io::Error::from_raw_os_error(libc::ESTALE));
                }
                slot
            }
            std::collections::hash_map::Entry::Vacant(slot) => slot.insert(Slot {
                pin: handle.is_none().then(|| fd.clone()),
                node: Arc::new(Node {
                    ino,
                    handle,
                    mode: entry.stat.st_mode,
                    native_key,
                    backing: Mutex::new(Weak::new()),
                    parent: Mutex::new(entry.parent),
                    generation: AtomicU64::new(0),
                }),
                lookups: 0,
            }),
        };
        slot.lookups = slot
            .lookups
            .checked_add(lookups)
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EOVERFLOW))?;
        Ok(NodeRef {
            fd,
            node: Some(slot.node.clone()),
            state: Arc::downgrade(&self.state),
        })
    }

    /// Pin only a live victim, before unlink or flags=0 overwrite, under the write guard.
    pub fn pin_removed(&self, entry: Entry) -> io::Result<u64> {
        if entry.stat.st_dev != self.root_dev {
            return Err(io::Error::from_raw_os_error(libc::EXDEV));
        }
        let ino = self.number(entry.stat.st_ino)?;
        let mut state = self.state.lock();
        if let Some(slot) = state.slots.get_mut(&ino) {
            if slot.node.native_key
                != (DirKey {
                    dev: entry.stat.st_dev,
                    ino: entry.stat.st_ino,
                })
                || slot.node.mode & libc::S_IFMT != entry.stat.st_mode & libc::S_IFMT
            {
                return Err(io::Error::from_raw_os_error(libc::ESTALE));
            }
            if let Some(handle) = &slot.node.handle {
                if handle != &NativeHandle::capture(entry.fd.as_fd())? {
                    return Err(io::Error::from_raw_os_error(libc::ESTALE));
                }
                if slot.pin.is_none() {
                    slot.pin = Some(Arc::new(entry.fd));
                }
            }
        }
        Ok(ino)
    }

    /// Reconcile under the same write guard, independently of the mutation outcome.
    pub fn release_linked_pin(&self, ino: u64) {
        let released = {
            let mut state = self.state.lock();
            #[cfg(test)]
            let injected = state.pin_stat_error.take();
            let Some(slot) = state.slots.get_mut(&ino) else {
                return;
            };
            if slot.node.handle.is_none() {
                return;
            }
            let Some(fd) = &slot.pin else {
                return;
            };
            let stat = sys::stat(fd.as_fd());
            #[cfg(test)]
            let stat = injected.map_or(stat, |errno| Err(io::Error::from_raw_os_error(errno)));
            if stat.is_ok_and(|stat| stat.st_nlink > 0) {
                slot.pin.take()
            } else {
                None
            }
        };
        drop(released);
    }

    /// Called only after known-success native rename, under the write guard.
    pub fn reparent_native(&self, native_ino: u64, parent: OwnedFd) {
        let Ok(node) = self.number(native_ino).and_then(|ino| self.get(ino)) else {
            return;
        };
        let old = node.parent.lock().replace(parent);
        node.changed();
        drop(old);
    }

    pub fn add_lookup(&self, node: &NodeRef) -> io::Result<()> {
        let mut state = self.state.lock();
        let slot = state
            .slots
            .get_mut(&node.ino)
            .expect("pinned inode is interned");
        slot.lookups = slot
            .lookups
            .checked_add(1)
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EOVERFLOW))?;
        Ok(())
    }

    pub fn forget(&self, ino: u64, count: u64) {
        let removed = {
            let mut state = self.state.lock();
            if let Some(slot) = state.slots.get_mut(&ino) {
                if count > slot.lookups {
                    eprintln!("lnfs-lite: unexpected FORGET count for inode {ino}");
                }
                slot.lookups = slot.lookups.saturating_sub(count);
                reap(&mut state, ino)
            } else {
                None
            }
        };
        drop(removed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs::File, os::fd::AsFd, os::unix::fs::PermissionsExt, sync::Barrier};

    fn fixture() -> (tempfile::TempDir, Inodes, File, libc::stat) {
        let temp = tempfile::tempdir().unwrap();
        let root = File::open(temp.path()).unwrap();
        let stat = crate::sys::stat(root.as_fd()).unwrap();
        let table = Inodes::new(root.into(), stat);
        let file = File::create(temp.path().join("file")).unwrap();
        let stat = crate::sys::stat(file.as_fd()).unwrap();
        (temp, table, file, stat)
    }

    fn entry(file: &File, stat: libc::stat) -> Entry {
        Entry {
            fd: file.try_clone().unwrap().into(),
            stat,
            parent: None,
        }
    }

    #[test]
    fn cold_regular_slots_reopen_without_a_persistent_fd() {
        let (_temp, table, file, stat) = fixture();
        let node = table.intern(entry(&file, stat), 1).unwrap();
        let ino = node.ino;
        assert!(table.state.lock().slots[&ino].pin.is_none());
        drop(node);
        let reopened = table.get(ino).unwrap();
        let actual = sys::stat(reopened.fd.as_fd()).unwrap();
        assert_eq!((actual.st_dev, actual.st_ino), (stat.st_dev, stat.st_ino));
        assert!(table.state.lock().slots[&ino].pin.is_none());
    }

    #[test]
    fn rejected_removal_clears_pin_but_unlinked_lookup_retains_identity() {
        let (temp, table, file, stat) = fixture();
        let node = table.intern(entry(&file, stat), 1).unwrap();
        let ino = node.ino;
        drop(node);
        std::fs::create_dir(temp.path().join("directory")).unwrap();
        for _ in 0..128 {
            assert_eq!(table.pin_removed(entry(&file, stat)).unwrap(), ino);
            assert_eq!(
                sys::rename_at(
                    table.mount.as_fd(),
                    c"directory",
                    table.mount.as_fd(),
                    c"file",
                    0
                )
                .unwrap_err()
                .raw_os_error(),
                Some(libc::ENOTDIR)
            );
            assert!(table.state.lock().slots[&ino].pin.is_some());
            let request = table.get(ino).unwrap();
            table.release_linked_pin(ino);
            assert!(table.state.lock().slots[&ino].pin.is_none());
            assert_eq!(sys::stat(request.fd.as_fd()).unwrap().st_ino, stat.st_ino);
        }
        table.pin_removed(entry(&file, stat)).unwrap();
        std::fs::remove_file(temp.path().join("file")).unwrap();
        table.release_linked_pin(ino);
        assert!(table.state.lock().slots[&ino].pin.is_some());
        drop(file);
        let removed = table.get(ino).unwrap();
        assert_eq!(sys::stat(removed.fd.as_fd()).unwrap().st_nlink, 0);
        table.forget(ino, 1);
        assert!(table.get(ino).is_ok());
        drop(removed);
        assert!(table.get(ino).is_err());
    }

    #[test]
    fn concurrent_forget_and_last_request_drop_reap_an_unlinked_pin() {
        for _ in 0..32 {
            let (temp, table, file, stat) = fixture();
            let node = table.intern(entry(&file, stat), 1).unwrap();
            let ino = node.ino;
            table.pin_removed(entry(&file, stat)).unwrap();
            std::fs::remove_file(temp.path().join("file")).unwrap();
            table.release_linked_pin(ino);
            let released = Arc::downgrade(node.node.as_ref().unwrap());
            let pin = Arc::downgrade(table.state.lock().slots[&ino].pin.as_ref().unwrap());
            drop(file);
            let barrier = Barrier::new(2);
            std::thread::scope(|scope| {
                let barrier = &barrier;
                scope.spawn(move || {
                    barrier.wait();
                    drop(node);
                });
                scope.spawn(|| {
                    barrier.wait();
                    table.forget(ino, 1);
                });
            });
            assert!(released.upgrade().is_none());
            assert!(pin.upgrade().is_none());
            assert_eq!(table.state.lock().slots.len(), 1);
        }
    }

    #[test]
    fn reconciliation_stat_failure_keeps_the_victim_pin() {
        let (_temp, table, file, stat) = fixture();
        let node = table.intern(entry(&file, stat), 1).unwrap();
        table.pin_removed(entry(&file, stat)).unwrap();
        table.state.lock().pin_stat_error = Some(libc::EIO);
        table.release_linked_pin(node.ino);
        assert!(table.state.lock().slots[&node.ino].pin.is_some());
        table.release_linked_pin(node.ino);
        assert!(table.state.lock().slots[&node.ino].pin.is_none());
    }

    #[test]
    fn different_handle_with_same_native_number_is_never_interned_or_pinned() {
        let (temp, table, file, stat) = fixture();
        let node = table.intern(entry(&file, stat), 1).unwrap();
        let other = File::create(temp.path().join("other")).unwrap();
        let mut recycled = sys::stat(other.as_fd()).unwrap();
        recycled.st_ino = stat.st_ino;
        assert_eq!(
            table
                .intern(entry(&other, recycled), 1)
                .err()
                .unwrap()
                .raw_os_error(),
            Some(libc::ESTALE)
        );
        assert_eq!(
            table
                .pin_removed(entry(&other, recycled))
                .unwrap_err()
                .raw_os_error(),
            Some(libc::ESTALE)
        );
        let state = table.state.lock();
        assert_eq!(state.slots[&node.ino].lookups, 1);
        assert!(state.slots[&node.ino].pin.is_none());
    }

    #[test]
    fn cold_materialization_verifies_native_identity() {
        let (_temp, table, file, stat) = fixture();
        let node = table.intern(entry(&file, stat), 1).unwrap();
        let ino = node.ino;
        drop(node);
        {
            let mut state = table.state.lock();
            let slot = state.slots.get_mut(&ino).unwrap();
            Arc::get_mut(&mut slot.node).unwrap().native_key.ino += 1;
        }
        assert_eq!(
            table.get(ino).err().unwrap().raw_os_error(),
            Some(libc::ESTALE)
        );
    }

    #[test]
    fn concurrent_get_and_pin_clear_keep_the_request_fd_live() {
        let (_temp, table, file, stat) = fixture();
        let node = table.intern(entry(&file, stat), 1).unwrap();
        let ino = node.ino;
        drop(node);
        for _ in 0..32 {
            table.pin_removed(entry(&file, stat)).unwrap();
            let barrier = Barrier::new(2);
            std::thread::scope(|scope| {
                let request = scope.spawn(|| {
                    let request = table.get(ino).unwrap();
                    barrier.wait();
                    barrier.wait();
                    assert_eq!(sys::stat(request.fd.as_fd()).unwrap().st_ino, stat.st_ino);
                });
                barrier.wait();
                table.release_linked_pin(ino);
                assert!(table.state.lock().slots[&ino].pin.is_none());
                barrier.wait();
                request.join().unwrap();
            });
        }
    }

    #[test]
    fn directory_capabilities_use_native_identity_and_reject_files() {
        let (_temp, table, file, stat) = fixture();
        let root = table.get(1).unwrap();
        let native = crate::sys::stat(root.fd.as_fd()).unwrap();
        assert_eq!(
            root.directory().unwrap().key(),
            DirKey {
                dev: native.st_dev,
                ino: native.st_ino,
            }
        );
        let entry = entry(&file, stat);
        assert_eq!(
            entry.directory().unwrap_err().raw_os_error(),
            Some(libc::ENOTDIR)
        );
        let node = table.intern(entry, 0).unwrap();
        assert_eq!(
            node.directory().unwrap_err().raw_os_error(),
            Some(libc::ENOTDIR)
        );
    }

    #[test]
    fn directory_identity_survives_chmod_rename_and_unlink() {
        let (temp, table, _file, _stat) = fixture();
        let before = temp.path().join("before");
        let after = temp.path().join("after");
        std::fs::create_dir(&before).unwrap();
        let file = File::open(&before).unwrap();
        let stat = crate::sys::stat(file.as_fd()).unwrap();
        let node = table.intern(entry(&file, stat), 0).unwrap();
        drop(file);
        let directory = node.directory().unwrap();
        let expected = DirKey {
            dev: stat.st_dev,
            ino: stat.st_ino,
        };
        assert_eq!(directory.key(), expected);
        std::fs::set_permissions(&before, std::fs::Permissions::from_mode(0o500)).unwrap();
        std::fs::rename(&before, &after).unwrap();
        assert_eq!(node.directory().unwrap().key(), expected);
        let current = crate::sys::stat(directory.as_fd()).unwrap();
        assert_eq!(current.st_mode & 0o777, 0o500);
        assert_eq!(
            (current.st_dev, current.st_ino),
            (expected.dev, expected.ino)
        );
        std::fs::remove_dir(&after).unwrap();
        assert_eq!(node.directory().unwrap().key(), expected);
        let removed = crate::sys::stat(directory.as_fd()).unwrap();
        assert_eq!(removed.st_nlink, 0);
        assert_eq!(
            (removed.st_dev, removed.st_ino),
            (expected.dev, expected.ino)
        );
    }

    #[test]
    fn forget_preserves_open_and_request_pins() {
        let (_temp, table, file, stat) = fixture();
        let first = table.intern(entry(&file, stat), 1).unwrap();
        let ino = first.ino;
        let open = first.clone();
        table.forget(ino, 1);
        drop(first);
        let same = table.intern(entry(&file, stat), 0).unwrap();
        assert!(Arc::ptr_eq(
            open.node.as_ref().unwrap(),
            same.node.as_ref().unwrap()
        ));
        drop(open);
        assert!(table.get(ino).is_ok());
        drop(same);
        assert!(table.get(ino).is_err());
        assert_eq!(table.state.lock().slots.len(), 1);
    }

    #[test]
    fn unsent_directory_entry_does_not_leak() {
        let (_temp, table, file, stat) = fixture();
        for _ in 0..50 {
            let node = table.intern(entry(&file, stat), 0).unwrap();
            let ino = node.ino;
            drop(node);
            assert!(table.get(ino).is_err());
        }
        let node = table.intern(entry(&file, stat), 0).unwrap();
        table.add_lookup(&node).unwrap();
        let ino = node.ino;
        drop(node);
        assert!(table.get(ino).is_ok());
        table.forget(ino, 1);
        assert!(table.get(ino).is_err());
    }

    #[test]
    fn concurrent_final_pin_drops_reap() {
        let (_temp, table, file, stat) = fixture();
        for _ in 0..50 {
            let node = table.intern(entry(&file, stat), 0).unwrap();
            let other = node.clone();
            let released = Arc::downgrade(node.node.as_ref().unwrap());
            let barrier = Barrier::new(2);
            std::thread::scope(|s| {
                let barrier = &barrier;
                s.spawn(move || {
                    barrier.wait();
                    drop(node);
                });
                s.spawn(move || {
                    barrier.wait();
                    drop(other);
                });
            });
            assert!(released.upgrade().is_none());
            assert_eq!(table.state.lock().slots.len(), 1);
        }
    }

    #[test]
    fn concurrent_interns_share_one_backing_slot() {
        let (_temp, table, file, stat) = fixture();
        let first = entry(&file, stat);
        let second = entry(&file, stat);
        let barrier = Barrier::new(2);
        std::thread::scope(|scope| {
            let a = scope.spawn(|| {
                barrier.wait();
                let node = table.intern(first, 0).unwrap();
                barrier.wait();
                node
            });
            let b = scope.spawn(|| {
                barrier.wait();
                let node = table.intern(second, 0).unwrap();
                barrier.wait();
                node
            });
            let a = a.join().unwrap();
            let b = b.join().unwrap();
            assert!(Arc::ptr_eq(
                a.node.as_ref().unwrap(),
                b.node.as_ref().unwrap()
            ));
        });
        assert_eq!(table.state.lock().slots.len(), 1);
    }

    #[test]
    fn reparent_keeps_identity_and_invalidates_directory_view() {
        let (temp, table, _file, _stat) = fixture();
        std::fs::create_dir(temp.path().join("child")).unwrap();
        std::fs::create_dir(temp.path().join("next")).unwrap();
        let child = File::open(temp.path().join("child")).unwrap();
        let stat = crate::sys::stat(child.as_fd()).unwrap();
        let old_parent = File::open(temp.path()).unwrap();
        let node = table
            .intern(
                Entry {
                    fd: child.into(),
                    stat,
                    parent: Some(old_parent.into()),
                },
                0,
            )
            .unwrap();
        let next = File::open(temp.path().join("next")).unwrap();
        let expected = crate::sys::stat(next.as_fd()).unwrap().st_ino;
        table.reparent_native(stat.st_ino, next.into());
        assert_eq!(node.generation(), 1);
        assert_eq!(
            crate::sys::stat(node.parent.lock().as_ref().unwrap().as_fd())
                .unwrap()
                .st_ino,
            expected
        );
        let again = table.get(node.ino).unwrap();
        assert!(Arc::ptr_eq(
            node.node.as_ref().unwrap(),
            again.node.as_ref().unwrap()
        ));
        node.generation.store(u64::MAX - 1, Ordering::Relaxed);
        node.changed();
        node.changed();
        assert_eq!(node.generation(), u64::MAX);
    }
}
