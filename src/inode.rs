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

use crate::namespace::{DirKey, Directory, Entry};

pub struct Node {
    pub ino: u64,
    pub fd: OwnedFd,
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
    lookups: u64,
}

struct State {
    slots: HashMap<u64, Slot>,
}

pub struct Inodes {
    state: Arc<Mutex<State>>,
    root_dev: u64,
    root_ino: u64,
}

/// A request or open handle pins the same identity even after its last FORGET.
pub struct NodeRef {
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
        let node = Arc::new(Node {
            ino: 1,
            fd,
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
            root_dev: stat.st_dev,
            root_ino: stat.st_ino,
            state: Arc::new(Mutex::new(State {
                slots: HashMap::from([(1, Slot { node, lookups: 0 })]),
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
        let state = self.state.lock();
        let node = state
            .slots
            .get(&ino)
            .ok_or_else(|| io::Error::from_raw_os_error(libc::ESTALE))?
            .node
            .clone();
        Ok(NodeRef {
            node: Some(node),
            state: Arc::downgrade(&self.state),
        })
    }

    /// The caller retains its namespace guard through parent initialization.
    pub fn intern(&self, entry: Entry, lookups: u64) -> io::Result<NodeRef> {
        if entry.stat.st_dev != self.root_dev {
            return Err(io::Error::from_raw_os_error(libc::EXDEV));
        }
        let ino = self.number(entry.stat.st_ino)?;
        let mut unused = Some(entry);
        let result = {
            let mut state = self.state.lock();
            let slot = state.slots.entry(ino).or_insert_with(|| {
                let entry = unused.take().expect("new inode entry");
                Slot {
                    node: Arc::new(Node {
                        ino,
                        fd: entry.fd,
                        mode: entry.stat.st_mode,
                        native_key: DirKey {
                            dev: entry.stat.st_dev,
                            ino: entry.stat.st_ino,
                        },
                        backing: Mutex::new(Weak::new()),
                        parent: Mutex::new(entry.parent),
                        generation: AtomicU64::new(0),
                    }),
                    lookups: 0,
                }
            });
            match slot.lookups.checked_add(lookups) {
                Some(lookups) => {
                    slot.lookups = lookups;
                    Ok(NodeRef {
                        node: Some(slot.node.clone()),
                        state: Arc::downgrade(&self.state),
                    })
                }
                None => Err(io::Error::from_raw_os_error(libc::EOVERFLOW)),
            }
        };
        drop(unused);
        result
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
