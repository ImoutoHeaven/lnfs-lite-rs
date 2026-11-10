use std::{collections::HashMap, io, os::fd::OwnedFd, sync::Arc};

use fuser::BackingId;
use parking_lot::Mutex;

use crate::{inode::NodeRef, namespace::ListedEntry};

pub struct FileHandle {
    pub fd: OwnedFd,
    pub node: NodeRef,
    pub _backing: Arc<BackingId>,
}

pub struct DirectoryHandle {
    pub node: NodeRef,
    pub view: Mutex<DirectoryView>,
}

enum Handle {
    File(Arc<FileHandle>),
    Directory(Arc<DirectoryHandle>),
}

pub struct Handles {
    state: Mutex<(u64, HashMap<u64, Handle>)>,
}

impl Default for Handles {
    fn default() -> Self {
        Self {
            state: Mutex::new((1, HashMap::new())),
        }
    }
}

impl Handles {
    fn insert(&self, handle: Handle) -> io::Result<u64> {
        let mut state = self.state.lock();
        let id = state.0;
        state.0 = id
            .checked_add(1)
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EMFILE))?;
        state.1.insert(id, handle);
        Ok(id)
    }

    pub fn insert_file(&self, file: FileHandle) -> io::Result<u64> {
        self.insert(Handle::File(Arc::new(file)))
    }

    pub fn insert_directory(&self, directory: DirectoryHandle) -> io::Result<u64> {
        self.insert(Handle::Directory(Arc::new(directory)))
    }

    pub fn file(&self, id: u64, ino: u64) -> io::Result<Arc<FileHandle>> {
        match self.state.lock().1.get(&id) {
            Some(Handle::File(handle)) if handle.node.ino == ino => Ok(handle.clone()),
            _ => Err(io::Error::from_raw_os_error(libc::EBADF)),
        }
    }

    pub fn directory(&self, id: u64, ino: u64) -> io::Result<Arc<DirectoryHandle>> {
        match self.state.lock().1.get(&id) {
            Some(Handle::Directory(handle)) if handle.node.ino == ino => Ok(handle.clone()),
            _ => Err(io::Error::from_raw_os_error(libc::EBADF)),
        }
    }

    pub fn remove_file(&self, id: u64, ino: u64) -> io::Result<()> {
        let removed = {
            let mut state = self.state.lock();
            match state.1.get(&id) {
                Some(Handle::File(handle)) if handle.node.ino == ino => state.1.remove(&id),
                _ => return Err(io::Error::from_raw_os_error(libc::EBADF)),
            }
        };
        drop(removed);
        Ok(())
    }

    pub fn remove_directory(&self, id: u64, ino: u64) -> io::Result<()> {
        let removed = {
            let mut state = self.state.lock();
            match state.1.get(&id) {
                Some(Handle::Directory(handle)) if handle.node.ino == ino => state.1.remove(&id),
                _ => return Err(io::Error::from_raw_os_error(libc::EBADF)),
            }
        };
        drop(removed);
        Ok(())
    }
}

/// Sequential cookies index dot, dotdot, then the current byte-sorted listing.
#[derive(Default)]
pub struct DirectoryView {
    generation: Option<u64>,
    pub entries: Vec<ListedEntry>,
}

impl DirectoryView {
    pub fn refresh(
        &mut self,
        generation: u64,
        rewind: bool,
        load: impl FnOnce() -> io::Result<Vec<ListedEntry>>,
    ) -> io::Result<()> {
        if rewind || generation == u64::MAX || self.generation != Some(generation) {
            let entries = load()?;
            self.entries = entries;
            self.generation = Some(generation);
        }
        Ok(())
    }

    pub fn position(&self, offset: u64) -> io::Result<usize> {
        let position =
            usize::try_from(offset).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
        let end = self
            .entries
            .len()
            .checked_add(2)
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EOVERFLOW))?;
        // A valid old cookie may outlive entries deleted from a rebuilt view.
        Ok(position.min(end))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::Cell, ffi::OsString};

    fn names(values: &[&str]) -> Vec<ListedEntry> {
        values
            .iter()
            .enumerate()
            .map(|(i, name)| ListedEntry {
                name: OsString::from(name),
                native_ino: i as u64 + 10,
                kind: libc::DT_REG,
            })
            .collect()
    }

    #[test]
    fn view_rebuilds_on_generation_change_at_nonzero_cookie() {
        let mut view = DirectoryView::default();
        view.refresh(0, false, || Ok(names(&["a", "c"]))).unwrap();
        let position = view.position(3).unwrap();
        assert_eq!(view.entries[position - 2].name, "c");
        view.refresh(1, false, || Ok(names(&["a", "b", "c"])))
            .unwrap();
        // Continuing an old cookie uses the current generation, never stale entries.
        let position = view.position(3).unwrap();
        assert_eq!(view.entries[position - 2].name, "b");
        // Deleting the tail between requests turns an old valid cookie into EOF.
        let old_cookie = view.position(5).unwrap() as u64;
        view.refresh(2, false, || Ok(names(&["a"]))).unwrap();
        assert_eq!(view.position(old_cookie).unwrap(), 3);
    }

    #[test]
    fn unchanged_views_reuse_but_rewind_and_exhaustion_reload() {
        let loads = Cell::new(0);
        let load = || {
            loads.set(loads.get() + 1);
            Ok(names(&["a"]))
        };
        let mut view = DirectoryView::default();
        view.refresh(5, false, load).unwrap();
        view.refresh(5, false, load).unwrap();
        assert_eq!(loads.get(), 1);
        view.refresh(5, true, load).unwrap();
        assert_eq!(loads.get(), 2);
        view.refresh(u64::MAX, false, load).unwrap();
        view.refresh(u64::MAX, false, load).unwrap();
        assert_eq!(loads.get(), 4);
        assert_eq!(view.position(3).unwrap(), 3); // EOF follows the single name.
    }

    #[test]
    fn failed_rebuild_does_not_mark_stale_view_current() {
        let mut view = DirectoryView::default();
        view.refresh(1, false, || Ok(names(&["old"]))).unwrap();
        let failure = view.refresh(2, false, || Err(io::Error::from_raw_os_error(libc::EIO)));
        assert_eq!(failure.unwrap_err().raw_os_error(), Some(libc::EIO));
        view.refresh(2, false, || Ok(names(&["new"]))).unwrap();
        assert_eq!(view.entries[0].name, "new");
    }
}
