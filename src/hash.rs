use crate::LuksError;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// Size of the LUKS2 checksum algorithm ID field in bytes.
pub const LUKS2_CHECKSUM_ALG_ID_LEN: usize = 32;

/// The size of a SHA-256 digest in bytes.
pub const SHA256_DIGEST_SIZE: usize = 32;
/// The size of a SHA-512 digest in bytes.
pub const SHA512_DIGEST_SIZE: usize = 64;

/// SHA-256 hash algorithm identifier.
pub const HASH_SHA256: &str = "sha256";
/// SHA-512 hash algorithm identifier.
pub const HASH_SHA512: &str = "sha512";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Luks2HashAlg {
    Sha256,
    Sha512,
}

impl Luks2HashAlg {
    /// Returns the algorithm name as a byte array padded with null bytes.
    pub fn to_bytes(&self) -> [u8; LUKS2_CHECKSUM_ALG_ID_LEN] {
        let mut res = [0u8; LUKS2_CHECKSUM_ALG_ID_LEN];
        let s = self.to_string();
        let b = s.as_bytes();
        let len = std::cmp::min(b.len(), LUKS2_CHECKSUM_ALG_ID_LEN);
        res[..len].copy_from_slice(&b[..len]);
        res
    }
}

impl fmt::Display for Luks2HashAlg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Luks2HashAlg::Sha256 => write!(f, "sha256"),
            Luks2HashAlg::Sha512 => write!(f, "sha512"),
        }
    }
}

impl FromStr for Luks2HashAlg {
    type Err = LuksError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim_matches('\0') {
            "sha256" => Ok(Luks2HashAlg::Sha256),
            "sha512" => Ok(Luks2HashAlg::Sha512),
            _ => Err(LuksError::UnsupportedChecksumAlg(s.to_string())),
        }
    }
}
