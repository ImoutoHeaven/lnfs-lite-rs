use std::{
    ffi::{OsStr, OsString},
    io,
    sync::{
        Arc, OnceLock,
        mpsc::{self, Receiver, SyncSender},
    },
    thread::{self, JoinHandle},
};

use fuser::{INodeNo, Notifier};

use crate::{inode::NodeRef, namespace::Namespace};

struct EntryInvalidation {
    parent: NodeRef,
    name: OsString,
}

/// Owned names and existing inode pins are prepared before native mutation.
pub struct InvalidationBatch {
    entries: [Option<EntryInvalidation>; 2],
}

impl InvalidationBatch {
    pub fn one(parent: NodeRef, name: &OsStr) -> Self {
        Self {
            entries: [
                Some(EntryInvalidation {
                    parent,
                    name: name.to_owned(),
                }),
                None,
            ],
        }
    }

    pub fn two(parent: NodeRef, name: &OsStr, newparent: NodeRef, newname: &OsStr) -> Self {
        Self {
            entries: [
                Some(EntryInvalidation {
                    parent,
                    name: name.to_owned(),
                }),
                Some(EntryInvalidation {
                    parent: newparent,
                    name: newname.to_owned(),
                }),
            ],
        }
    }

    pub fn parents(&self) -> impl Iterator<Item = &NodeRef> {
        self.entries.iter().flatten().map(|entry| &entry.parent)
    }
}

enum Message {
    Batch(InvalidationBatch),
    Stop,
}

pub struct Invalidations {
    notifier: OnceLock<Notifier>,
    sender: SyncSender<Message>,
}

pub struct InvalidationReceiver {
    receiver: Receiver<Message>,
    shared: Arc<Invalidations>,
}

pub struct InvalidationWorker {
    sender: SyncSender<Message>,
    thread: JoinHandle<io::Result<()>>,
    namespace: Arc<Namespace>,
}

impl Invalidations {
    pub fn channel() -> (Arc<Self>, InvalidationReceiver) {
        let (sender, receiver) = mpsc::sync_channel(1);
        let shared = Arc::new(Self {
            notifier: OnceLock::new(),
            sender,
        });
        let receiving = InvalidationReceiver {
            receiver,
            shared: shared.clone(),
        };
        (shared, receiving)
    }

    /// Only directory mappings are invalidated inline, with no userspace locks held.
    pub fn directory(&self, ino: u64) -> io::Result<()> {
        let notifier = self
            .notifier
            .get()
            .ok_or_else(|| io::Error::other("notification worker was not initialized"))?;
        notification_result(notifier.inval_inode(INodeNo(ino), 0, 0))
    }

    /// Called after the FUSE reply. A FUSE worker must never wait on queue space.
    pub fn submit(&self, batch: InvalidationBatch, namespace: &Namespace) -> io::Result<()> {
        if let Err(err) = self.sender.try_send(Message::Batch(batch)) {
            namespace.finish_notifications(false);
            return Err(io::Error::other(format!(
                "cannot queue cache repair; remount required: {err}"
            )));
        }
        Ok(())
    }
}

impl InvalidationReceiver {
    pub fn start(
        self,
        notifier: Notifier,
        namespace: Arc<Namespace>,
    ) -> io::Result<InvalidationWorker> {
        self.shared
            .notifier
            .set(notifier.clone())
            .map_err(|_| io::Error::other("notification worker already initialized"))?;
        let worker_namespace = namespace.clone();
        // The worker owns no sender or Invalidations Arc, so channel shutdown has no cycle.
        let receiver = self.receiver;
        let thread = thread::Builder::new()
            .name("lnfs-notify".into())
            .spawn(move || {
                while let Ok(message) = receiver.recv() {
                    match message {
                        Message::Stop => return Ok(()),
                        Message::Batch(batch) => {
                            for entry in batch.entries.into_iter().flatten() {
                                if let Err(err) = notification_result(
                                    notifier.inval_entry(INodeNo(entry.parent.ino), &entry.name),
                                ) {
                                    worker_namespace.finish_notifications(false);
                                    return Err(io::Error::other(format!(
                                        "kernel cache repair failed; remount required: {err}"
                                    )));
                                }
                            }
                            worker_namespace.finish_notifications(true);
                        }
                    }
                }
                Ok(())
            })?;
        Ok(InvalidationWorker {
            sender: self.shared.sender.clone(),
            thread,
            namespace,
        })
    }
}

impl InvalidationWorker {
    /// Main invokes this only after every FUSE request worker has drained.
    pub fn shutdown(self) -> io::Result<()> {
        let sent = self.sender.send(Message::Stop);
        let joined = self
            .thread
            .join()
            .unwrap_or_else(|_| Err(io::Error::other("notification worker panicked")));
        let result = joined
            .and_then(|()| sent.map_err(|_| io::Error::other("notification worker disconnected")));
        if result.is_err() {
            self.namespace.finish_notifications(false);
        }
        result
    }
}

fn notification_result(result: io::Result<()>) -> io::Result<()> {
    match result {
        // fuser already accepts ENOENT. ENODEV means the FUSE connection is gone;
        // after unmount there is no kernel namespace cache left to repair.
        Err(err) if err.raw_os_error() == Some(libc::ENODEV) => Ok(()),
        other => other,
    }
}
