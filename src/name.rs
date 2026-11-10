use std::ffi::{CStr, OsStr};
use std::io;
use std::os::unix::ffi::OsStrExt;

pub const MAX_NAME: usize = 1024;
pub const SHORT_NAME: usize = 255;
pub const FRAGMENT: usize = 254;
pub const PREFIX: &[u8] = b".__lnl_";
pub const TREE: &CStr = c".__lnl_names";
pub const PROBE: &CStr = c".__lnl_probe";
pub const FORMAT_XATTR: &CStr = c"user.lnfs_lite.format";
pub const FORMAT: &[u8] = b"lnfs-lite:3\n";

const MAX_CUTS: usize = MAX_NAME.div_ceil(FRAGMENT);
pub(crate) const PATH_CAPACITY: usize = TREE.to_bytes().len() + MAX_NAME + 2 * MAX_CUTS + 1;
const _: () = assert!(PATH_CAPACITY == 1047 && MAX_CUTS == 5);

pub fn is_internal_xattr(name: &[u8]) -> bool {
    name.starts_with(b"user.lnfs_lite.")
}

pub fn error(errno: i32) -> io::Error {
    io::Error::from_raw_os_error(errno)
}

pub fn validate(raw: &[u8]) -> io::Result<()> {
    if raw.len() > MAX_NAME {
        return Err(error(libc::ENAMETOOLONG));
    }
    if raw.is_empty() || raw == b"." || raw == b".." || raw.contains(&0) || raw.contains(&b'/') {
        return Err(error(libc::EINVAL));
    }
    if raw.starts_with(PREFIX) {
        return Err(error(libc::EPERM));
    }
    Ok(())
}

pub fn validate_long(raw: &[u8]) -> io::Result<()> {
    validate(raw)?;
    if raw.len() <= SHORT_NAME {
        return Err(error(libc::EINVAL));
    }
    Ok(())
}

pub struct Name<'a> {
    raw: &'a [u8],
    path: [u8; PATH_CAPACITY],
    len: usize,
    cuts: [usize; MAX_CUTS],
    cut_count: usize,
}

impl<'a> Name<'a> {
    pub fn new(raw: &'a OsStr) -> io::Result<Self> {
        let raw = raw.as_bytes();
        validate(raw)?;
        let mut name = Self {
            raw,
            path: [0; PATH_CAPACITY],
            len: 0,
            cuts: [0; MAX_CUTS],
            cut_count: 0,
        };
        if raw.len() > SHORT_NAME {
            name.append(TREE.to_bytes());
            let mut rest = raw;
            while rest.len() > FRAGMENT {
                name.component(b'd', &rest[..FRAGMENT]);
                rest = &rest[FRAGMENT..];
            }
            name.component(b'e', rest);
        } else {
            name.append(raw);
        }
        Ok(name)
    }

    fn append(&mut self, bytes: &[u8]) {
        let end = self.len + bytes.len();
        self.path[self.len..end].copy_from_slice(bytes);
        self.len = end;
    }

    fn component(&mut self, tag: u8, bytes: &[u8]) {
        self.cuts[self.cut_count] = self.len;
        self.cut_count += 1;
        self.append(&[b'/', tag]);
        self.append(bytes);
    }

    pub fn raw(&self) -> &[u8] {
        self.raw
    }

    pub fn is_long(&self) -> bool {
        self.cut_count != 0
    }

    pub fn path(&self) -> &CStr {
        CStr::from_bytes_with_nul(&self.path[..=self.len])
            .expect("validated encoding retains its terminator")
    }

    pub fn leaf(&self) -> &CStr {
        let start = self.prefix_ends().last().map_or(0, |end| end + 1);
        CStr::from_bytes_with_nul(&self.path[start..=self.len])
            .expect("suffix retains its terminator")
    }

    pub fn parent_bytes(&self) -> Option<&[u8]> {
        self.prefix_ends().last().map(|&end| &self.path[..end])
    }

    pub fn parent_path<'s>(&self, scratch: &'s mut [u8; PATH_CAPACITY]) -> Option<&'s CStr> {
        let parent = self.parent_bytes()?;
        scratch[..parent.len()].copy_from_slice(parent);
        scratch[parent.len()] = 0;
        Some(CStr::from_bytes_with_nul(&scratch[..=parent.len()]).expect("validated prefix"))
    }

    /// Ends of TREE and each intermediate fragment, excluding the terminal.
    pub fn prefix_ends(&self) -> &[usize] {
        &self.cuts[..self.cut_count]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fragments_are_canonical_at_every_boundary() {
        for len in [1, 254, 255, 256, 300, 508, 509, 1016, 1017, 1024] {
            let raw: Vec<_> = (0..len).map(|i| 128 + (i % 127) as u8).collect();
            let name = Name::new(OsStr::from_bytes(&raw)).unwrap();
            if len <= SHORT_NAME {
                assert!(!name.is_long());
                assert_eq!(name.path().to_bytes(), raw);
                assert!(name.prefix_ends().is_empty());
                continue;
            }
            let components: Vec<_> = name.path().to_bytes().split(|b| *b == b'/').collect();
            assert_eq!(components[0], TREE.to_bytes());
            let mut decoded = Vec::new();
            for component in &components[1..components.len() - 1] {
                assert_eq!(component.len(), 255);
                assert_eq!(component[0], b'd');
                decoded.extend_from_slice(&component[1..]);
            }
            let terminal = components.last().unwrap();
            assert_eq!(terminal[0], b'e');
            assert!((2..=255).contains(&terminal.len()));
            decoded.extend_from_slice(&terminal[1..]);
            assert_eq!(decoded, raw);
            assert_eq!(name.leaf().to_bytes(), *terminal);
            assert!(name.path().to_bytes_with_nul().len() <= PATH_CAPACITY);
            if len == MAX_NAME {
                assert_eq!(name.path().to_bytes_with_nul().len(), 1047);
            }
        }
    }

    #[test]
    fn parent_and_prune_paths_match_boundary_grammar() {
        for (len, depth, encoded_len) in [
            (255, 0, 255),
            (256, 1, 272),
            (508, 1, 524),
            (509, 2, 527),
            (1016, 3, 1036),
            (1017, 4, 1039),
            (1024, 4, 1046),
        ] {
            let raw: Vec<_> = (0..len).map(|i| 128 + (i % 128) as u8).collect();
            let name = Name::new(OsStr::from_bytes(&raw)).unwrap();
            assert_eq!(name.path().to_bytes().len(), encoded_len);
            let mut scratch = [0xa5; PATH_CAPACITY];
            if depth == 0 {
                assert!(name.parent_path(&mut scratch).is_none());
                assert!(name.prefix_ends().is_empty());
                continue;
            }
            let mut prefix = TREE.to_bytes().to_vec();
            let mut expected = vec![prefix.clone()];
            for component in raw.chunks_exact(FRAGMENT).take(depth) {
                prefix.extend_from_slice(b"/d");
                prefix.extend_from_slice(component);
                expected.push(prefix.clone());
            }
            let forward: Vec<_> = name
                .prefix_ends()
                .iter()
                .map(|&end| name.path().to_bytes()[..end].to_vec())
                .collect();
            assert_eq!(forward, expected);
            assert_eq!(name.parent_path(&mut scratch).unwrap().to_bytes(), prefix);
            let mut pruned = Vec::new();
            for &end in name.prefix_ends().iter().skip(1).rev() {
                scratch[end] = 0;
                pruned.push(
                    CStr::from_bytes_with_nul(&scratch[..=end])
                        .unwrap()
                        .to_bytes()
                        .to_vec(),
                );
            }
            expected.remove(0);
            expected.reverse();
            assert_eq!(pruned, expected);
        }
    }

    #[test]
    fn prefix_scratch_reuse_restores_separators_and_terminator() {
        let mut scratch = [0xa5; PATH_CAPACITY];
        for (byte, len) in [
            (255, 1024),
            (b'a', 256),
            (b'b', 255),
            (254, 1017),
            (b'c', 508),
            (b'd', 509),
        ] {
            let raw = vec![byte; len];
            let name = Name::new(OsStr::from_bytes(&raw)).unwrap();
            assert_eq!(
                name.parent_path(&mut scratch).map(CStr::to_bytes),
                name.parent_bytes()
            );
            for &end in name.prefix_ends() {
                scratch[end] = 0;
            }
            assert_eq!(
                name.parent_path(&mut scratch).map(CStr::to_bytes),
                name.parent_bytes()
            );
            assert_eq!(name.raw(), raw);
        }
    }

    #[test]
    fn raw_validation_and_private_grammar_are_exact() {
        for raw in [b"".as_slice(), b".", b"..", b"a/b", b"a\0b"] {
            assert_eq!(
                validate(raw).unwrap_err().raw_os_error(),
                Some(libc::EINVAL)
            );
        }
        assert_eq!(
            validate(&[b'x'; 1025]).unwrap_err().raw_os_error(),
            Some(libc::ENAMETOOLONG)
        );
        assert_eq!(
            validate(b".__lnl_anything").unwrap_err().raw_os_error(),
            Some(libc::EPERM)
        );
        assert!(validate(b".__LNL_PROBE").is_ok());
        for raw in [b".index".as_slice(), b".index.tmp.0123456789abcdef"] {
            let name = Name::new(OsStr::from_bytes(raw)).unwrap();
            assert!(!name.is_long());
            assert_eq!(name.path().to_bytes(), raw);
        }
        assert!(is_internal_xattr(b"user.lnfs_lite.session"));
        assert!(!is_internal_xattr(b"user.lnfs_lite"));
    }
}
