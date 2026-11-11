use clap::Parser;
use fuser::{Config, MountOption, SessionACL};
use lnfs_lite::{fs::LiteFs, namespace::Namespace, notify::Invalidations};
use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Parser)]
#[command(
    version,
    about = "Long filenames with mandatory Linux FUSE passthrough"
)]
struct Cli {
    #[arg(long, value_name = "DIRECTORY")]
    backend: PathBuf,
    #[arg(value_name = "MOUNTPOINT")]
    mountpoint: PathBuf,
    #[arg(long, default_value_t = 4, value_name = "COUNT")]
    threads: usize,
}

fn validate_paths(backend: &Path, mountpoint: &Path) -> io::Result<(PathBuf, PathBuf)> {
    let backend = backend.canonicalize()?;
    let mountpoint = mountpoint.canonicalize()?;
    if !backend.is_dir() || !mountpoint.is_dir() {
        return Err(io::Error::other(
            "backend and mountpoint must be directories",
        ));
    }
    if backend.starts_with(&mountpoint) || mountpoint.starts_with(&backend) {
        return Err(io::Error::other("backend and mountpoint must be disjoint"));
    }
    if std::fs::read_dir(&mountpoint)?
        .next()
        .transpose()?
        .is_some()
    {
        return Err(io::Error::other("mountpoint must be empty"));
    }
    Ok((backend, mountpoint))
}

fn check_privileges() -> io::Result<()> {
    // The owner-only release deliberately serves root, not a privileged multiuser proxy.
    if unsafe { libc::geteuid() } != 0 {
        return Err(io::Error::other(
            "run as root with CAP_SYS_ADMIN and CAP_DAC_READ_SEARCH",
        ));
    }
    let status = std::fs::read_to_string("/proc/self/status")?;
    let capabilities = status.lines().find_map(|line| {
        line.strip_prefix("CapEff:")
            .and_then(|value| u64::from_str_radix(value.trim(), 16).ok())
    });
    check_capabilities(capabilities)
}

fn check_capabilities(capabilities: Option<u64>) -> io::Result<()> {
    if capabilities.is_none_or(|bits| bits & (1 << 21) == 0) {
        return Err(io::Error::other("FUSE passthrough requires CAP_SYS_ADMIN"));
    }
    if capabilities.is_none_or(|bits| bits & (1 << 2) == 0) {
        return Err(io::Error::other(
            "native file handles require CAP_DAC_READ_SEARCH",
        ));
    }
    Ok(())
}

fn prepare_fd_limit() -> io::Result<()> {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // These calls only read/update this process's descriptor budget.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let target = limit.rlim_max.min(65_536);
    if limit.rlim_cur < target {
        limit.rlim_cur = target;
        if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    if limit.rlim_cur < 128 {
        return Err(io::Error::other(
            "RLIMIT_NOFILE must allow at least 128 descriptors",
        ));
    }
    // Shared fd-table growth waits for RCU; reserve this bounded capacity before threads.
    let highest = (limit.rlim_cur.min(65_536) - 1) as libc::c_int;
    if unsafe { libc::fcntl(highest, libc::F_GETFD) } >= 0 {
        return Ok(()); // An inherited high descriptor already reserved the table.
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() != Some(libc::EBADF) {
        return Err(error);
    }
    let probe = std::fs::File::open("/dev/null")?;
    let duplicate = unsafe { libc::fcntl(probe.as_raw_fd(), libc::F_DUPFD_CLOEXEC, highest) };
    if duplicate < 0 {
        return Err(io::Error::last_os_error());
    }
    // Only the newly owned duplicate is closed; the reserved table keeps its capacity.
    drop(unsafe { OwnedFd::from_raw_fd(duplicate) });
    Ok(())
}

fn block_shutdown_signals() -> io::Result<libc::sigset_t> {
    let mut signals = unsafe { std::mem::zeroed::<libc::sigset_t>() };
    // Block before spawning workers, then consume signals in an ordinary thread.
    unsafe {
        libc::sigemptyset(&mut signals);
        libc::sigaddset(&mut signals, libc::SIGINT);
        libc::sigaddset(&mut signals, libc::SIGTERM);
    }
    let error = unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &signals, std::ptr::null_mut()) };
    if error != 0 {
        return Err(io::Error::from_raw_os_error(error));
    }
    Ok(signals)
}

fn install_shutdown(mountpoint: &Path, signals: libc::sigset_t) -> io::Result<()> {
    let path = CString::new(mountpoint.as_os_str().as_bytes())
        .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
    std::thread::Builder::new()
        .name("unmount".into())
        .spawn(move || {
            loop {
                let mut signal = 0;
                let error = unsafe { libc::sigwait(&signals, &mut signal) };
                if error != 0 {
                    eprintln!(
                        "signal wait failed: {}",
                        io::Error::from_raw_os_error(error)
                    );
                    return;
                }
                // A busy mount keeps serving requests; do not detach active client I/O.
                if unsafe { libc::umount2(path.as_ptr(), 0) } == 0 {
                    return;
                }
                eprintln!(
                    "cannot unmount after signal {signal}: {}",
                    io::Error::last_os_error()
                );
            }
        })?;
    Ok(())
}

fn run() -> io::Result<()> {
    let cli = Cli::parse();
    if !(1..=64).contains(&cli.threads) {
        return Err(io::Error::other("--threads must be between 1 and 64"));
    }
    check_privileges()?;
    let (backend, mountpoint) = validate_paths(&cli.backend, &cli.mountpoint)?;
    prepare_fd_limit()?;
    // FUSE supplies the caller's masked mode; applying the daemon's umask again is wrong.
    unsafe {
        libc::umask(0);
    }
    let signals = block_shutdown_signals()?;
    let namespace = Arc::new(Namespace::open(&backend)?);
    let (invalidations, receiver) = Invalidations::channel();
    let filesystem = LiteFs::new(Arc::clone(&namespace), invalidations)?;
    let mut config = Config::default();
    config.mount_options = vec![
        MountOption::FSName("lnfs-lite".into()),
        MountOption::Subtype("lnfs-lite".into()),
        MountOption::DefaultPermissions,
        MountOption::NoSuid,
        MountOption::NoDev,
    ];
    config.acl = SessionACL::Owner;
    config.n_threads = Some(cli.threads);
    config.clone_fd = true;
    let session = fuser::Session::new(filesystem, &mountpoint, &config)?;
    install_shutdown(&mountpoint, signals)?;
    let notifications = receiver.start(session.notifier(), Arc::clone(&namespace))?;
    let serving = match session.spawn() {
        Ok(background) => background.join(),
        Err(error) => Err(error),
    };
    // Always drain notification ownership before returning a serving error.
    let stopped = notifications.shutdown();
    serving?;
    stopped?;
    namespace.finish()
}

fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("lnfs-lite: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_handles_require_dac_read_search_independently_of_sys_admin() {
        let error = check_capabilities(Some(1 << 21)).unwrap_err();
        assert!(error.to_string().contains("CAP_DAC_READ_SEARCH"));
        assert!(check_capabilities(Some((1 << 21) | (1 << 2))).is_ok());
        assert!(check_capabilities(Some(1 << 2)).is_err());
        assert!(check_capabilities(None).is_err());
    }

    #[test]
    fn rejects_nested_nonempty_and_symlink_alias_mountpoints() {
        let dir = tempfile::tempdir().unwrap();
        let backend = dir.path().join("backend");
        let mountpoint = dir.path().join("mount");
        std::fs::create_dir(&backend).unwrap();
        std::fs::create_dir(&mountpoint).unwrap();
        assert!(validate_paths(&backend, &mountpoint).is_ok());
        assert!(validate_paths(&backend, &backend).is_err());
        std::fs::create_dir(backend.join("nested")).unwrap();
        assert!(validate_paths(&backend, &backend.join("nested")).is_err());
        let alias = dir.path().join("alias");
        std::os::unix::fs::symlink(&backend, &alias).unwrap();
        assert!(validate_paths(&backend, &alias).is_err());
        std::fs::write(mountpoint.join("keep"), "data").unwrap();
        assert!(validate_paths(&backend, &mountpoint).is_err());
    }
}
