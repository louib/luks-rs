use byteorder::{BigEndian, ReadBytesExt};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt;
use std::io::{Read, Seek};
use std::str::FromStr;
use thiserror::Error;

/// The magic signature for LUKS devices: "LUKS\xBA\xBE".
pub const LUKS_MAGIC: [u8; 6] = *b"LUKS\xBA\xBE";

/// Size of the LUKS magic signature in bytes.
pub const LUKS_MAGIC_SIZE: usize = 6;
/// Size of the LUKS version field in bytes.
pub const LUKS_VERSION_SIZE: usize = 2;

/// Size of the LUKS2 label field in bytes.
pub const LUKS2_LABEL_SIZE: usize = 48;
/// Size of the LUKS2 checksum algorithm field in bytes.
pub const LUKS2_CHECKSUM_ALG_SIZE: usize = 32;
/// Size of the LUKS2 salt field in bytes.
pub const LUKS2_SALT_SIZE: usize = 64;
/// Size of the LUKS2 uuid field in bytes.
pub const LUKS2_UUID_SIZE: usize = 40;
/// Size of the LUKS2 subsystem field in bytes.
pub const LUKS2_SUBSYSTEM_SIZE: usize = 48;
/// Size of the LUKS2 checksum field in bytes.
pub const LUKS2_CHECKSUM_SIZE: usize = 64;

/// The size of a SHA-256 digest in bytes.
pub const SHA256_DIGEST_SIZE: usize = 32;

/// The offset in bytes where the LUKS2 checksum field begins.
pub const LUKS2_CHECKSUM_OFFSET: usize = 448;
/// The size of the LUKS2 binary header area in bytes.
pub const LUKS2_BINARY_HEADER_SIZE: usize = 4096;

#[derive(Error, Debug)]
pub enum LuksError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Invalid LUKS magic: {0:?}")]
    InvalidMagic([u8; LUKS_MAGIC_SIZE]),
    #[error("Unsupported LUKS version: {0}")]
    UnsupportedVersion(u16),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Invalid LUKS2 header: {0}")]
    InvalidHeader(String),
    #[error("Checksum verification failed: expected {expected}, got {actual}")]
    InvalidChecksum { expected: String, actual: String },
    #[error("Unsupported checksum algorithm: {0}")]
    UnsupportedChecksumAlg(String),
}

/// A 64-bit unsigned integer that is represented as a decimal string in JSON.
///
/// This is necessary because JSON's standard number type is a double-precision floating point
/// value (IEEE 754), which cannot accurately represent the full range of 64-bit integers
/// without losing precision. By encoding large integers as strings, LUKS2 ensures that
/// values like offsets and sizes remain exact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Luks2U64(pub u64);

impl Serialize for Luks2U64 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0.to_string())
    }
}

impl<'de> Deserialize<'de> for Luks2U64 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse::<u64>().map(Luks2U64).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(into = "u64", try_from = "u64")]
pub enum Luks2KeySize {
    Size32 = 32,
    Size64 = 64,
}

impl From<Luks2KeySize> for u64 {
    fn from(val: Luks2KeySize) -> Self {
        val as u64
    }
}

impl TryFrom<u64> for Luks2KeySize {
    type Error = String;
    fn try_from(val: u64) -> Result<Self, Self::Error> {
        match val {
            32 => Ok(Luks2KeySize::Size32),
            64 => Ok(Luks2KeySize::Size64),
            _ => Err(format!("Unsupported key size: {}", val)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Luks2AfType {
    Luks1,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Luks2Af {
    #[serde(rename = "type")]
    pub af_type: Luks2AfType,
    pub stripes: u32,
    pub hash: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Luks2AreaEncryption {
    #[serde(rename = "aes-xts-plain64")]
    AesXtsPlain64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum Luks2Area {
    Raw {
        encryption: Luks2AreaEncryption,
        key_size: Luks2KeySize,
        offset: Luks2U64,
        size: Luks2U64,
    },
    None {
        offset: Luks2U64,
        size: Luks2U64,
    },
    Journal {
        offset: Luks2U64,
        size: Luks2U64,
    },
    Checksum {
        offset: Luks2U64,
        size: Luks2U64,
        hash: String,
        sector_size: u32,
    },
    Datashift {
        offset: Luks2U64,
        size: Luks2U64,
        shift_size: Luks2U64,
    },
    #[serde(rename = "datashift-journal")]
    DatashiftJournal {
        offset: Luks2U64,
        size: Luks2U64,
        shift_size: Luks2U64,
    },
    #[serde(rename = "datashift-checksum")]
    DatashiftChecksum {
        offset: Luks2U64,
        size: Luks2U64,
        hash: String,
        sector_size: u32,
        shift_size: Luks2U64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Luks2Kdf {
    Argon2i {
        time: u32,
        memory: u32,
        cpus: u32,
        salt: String,
    },
    Argon2id {
        time: u32,
        memory: u32,
        cpus: u32,
        salt: String,
    },
    Pbkdf2 {
        hash: String,
        iterations: u32,
        salt: String,
    },
}

/// The priority of a LUKS2 keyslot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "i32", into = "i32")]
pub enum Luks2KeyslotPriority {
    /// The keyslot should be ignored except if explicitly stated
    Ignore = 0,
    /// Normal priority.
    Normal = 1,
    /// High priority.
    High = 2,
}

impl TryFrom<i32> for Luks2KeyslotPriority {
    type Error = String;
    fn try_from(val: i32) -> Result<Self, Self::Error> {
        match val {
            0 => Ok(Luks2KeyslotPriority::Ignore),
            1 => Ok(Luks2KeyslotPriority::Normal),
            2 => Ok(Luks2KeyslotPriority::High),
            _ => Err(format!("Unsupported keyslot priority: {}", val)),
        }
    }
}

impl From<Luks2KeyslotPriority> for i32 {
    fn from(val: Luks2KeyslotPriority) -> Self {
        val as i32
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Luks2ReencryptMode {
    Reencrypt,
    Encrypt,
    Decrypt,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Luks2ReencryptDirection {
    Forward,
    Backward,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Luks2Keyslot {
    Luks2 {
        key_size: Luks2KeySize,
        priority: Option<Luks2KeyslotPriority>,
        af: Luks2Af,
        area: Luks2Area,
        kdf: Luks2Kdf,
        #[serde(flatten)]
        extra: HashMap<String, serde_json::Value>,
    },
    Reencrypt {
        mode: Luks2ReencryptMode,
        direction: Luks2ReencryptDirection,
        key_size: String,
        priority: Option<Luks2KeyslotPriority>,
        af: Luks2Af,
        area: Luks2Area,
        kdf: Luks2Kdf,
        #[serde(flatten)]
        extra: HashMap<String, serde_json::Value>,
    },
}

impl Luks2Keyslot {
    /// Validates the keyslot
    pub fn validate(&self) -> Result<(), String> {
        match self {
            Luks2Keyslot::Luks2 { area, .. } => {
                if !matches!(area, Luks2Area::Raw { .. }) {
                    return Err("LUKS2 keyslot must have area type 'raw'".to_string());
                }
            }
            Luks2Keyslot::Reencrypt { area, key_size, .. } => {
                if matches!(area, Luks2Area::Raw { .. }) {
                    return Err("Reencrypt keyslot cannot have area type 'raw'".to_string());
                }
                if key_size != "1" {
                    return Err("Reencrypt keyslot must have key_size 1".to_string());
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Luks2Token {
    #[serde(rename = "luks2-keyring")]
    Keyring {
        keyslots: Vec<String>,
        key_description: String,
        #[serde(flatten)]
        extra: HashMap<String, serde_json::Value>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Luks2SegmentSize {
    U64(u64),
    Dynamic,
}

impl Serialize for Luks2SegmentSize {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Luks2SegmentSize::U64(v) => serializer.serialize_str(&v.to_string()),
            Luks2SegmentSize::Dynamic => serializer.serialize_str("dynamic"),
        }
    }
}

impl<'de> Deserialize<'de> for Luks2SegmentSize {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        if s == "dynamic" {
            Ok(Luks2SegmentSize::Dynamic)
        } else {
            s.parse::<u64>()
                .map(Luks2SegmentSize::U64)
                .map_err(serde::de::Error::custom)
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Luks2Segment {
    Crypt {
        offset: Luks2U64,
        iv_tweak: Luks2U64,
        size: Luks2SegmentSize,
        encryption: String,
        sector_size: u32,
        #[serde(flatten)]
        extra: HashMap<String, serde_json::Value>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Luks2Digest {
    Pbkdf2 {
        keyslots: Vec<String>,
        segments: Vec<String>,
        hash: String,
        iterations: u32,
        salt: String,
        digest: String,
        #[serde(flatten)]
        extra: HashMap<String, serde_json::Value>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Luks2Config {
    pub json_size: Luks2U64,
    pub keyslots_size: Luks2U64,
    pub flags: Option<Vec<String>>,
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

fn deserialize_and_validate_keyslots<'de, D>(deserializer: D) -> Result<HashMap<String, Luks2Keyslot>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let keyslots: HashMap<String, Luks2Keyslot> = HashMap::deserialize(deserializer)?;
    for (id, slot) in &keyslots {
        slot.validate()
            .map_err(|e| serde::de::Error::custom(format!("Validation failed for keyslot {}: {}", id, e)))?;
    }
    Ok(keyslots)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Luks2Metadata {
    #[serde(deserialize_with = "deserialize_and_validate_keyslots")]
    pub keyslots: HashMap<String, Luks2Keyslot>,
    pub tokens: HashMap<String, Luks2Token>,
    pub segments: HashMap<String, Luks2Segment>,
    pub digests: HashMap<String, Luks2Digest>,
    pub config: Luks2Config,
}

/// A LUKS device UUID.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct LuksUuid(String);

impl LuksUuid {
    /// Returns the UUID as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for LuksUuid {
    type Err = LuksError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim_matches('\0');
        if s.is_empty() {
            return Err(LuksError::InvalidHeader("UUID is empty".to_string()));
        }
        if s.len() >= LUKS2_UUID_SIZE {
            return Err(LuksError::InvalidHeader(format!(
                "UUID too long: {} (max {})",
                s.len(),
                LUKS2_UUID_SIZE - 1
            )));
        }
        if !s.chars().all(|c| c.is_ascii_hexdigit() || c == '-') {
            return Err(LuksError::InvalidHeader(format!(
                "UUID contains invalid characters: {}",
                s
            )));
        }
        Ok(LuksUuid(s.to_string()))
    }
}

impl fmt::Display for LuksUuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl PartialEq<&str> for LuksUuid {
    fn eq(&self, other: &&str) -> bool {
        &self.0 == *other
    }
}

#[derive(Debug, Clone)]
pub struct Luks2Header {
    pub version: u16,
    pub hdr_size: u64,
    pub seqid: u64,
    pub label: String,
    pub checksum_alg: String,
    pub salt: [u8; LUKS2_SALT_SIZE],
    pub uuid: LuksUuid,
    pub subsystem: String,
    pub hdr_offset: u64,
    pub checksum: [u8; LUKS2_CHECKSUM_SIZE],
    pub metadata: Luks2Metadata,
}

impl Luks2Header {
    /// Returns the number of configured keyslots.
    pub fn num_keyslots(&self) -> usize {
        self.metadata.keyslots.len()
    }
}

#[derive(Debug, Clone)]
pub enum LuksHeader {
    V1, // Placeholder for LUKS1
    V2(Luks2Header),
}

impl LuksHeader {
    /// Returns the number of configured keyslots.
    pub fn num_keyslots(&self) -> usize {
        match self {
            LuksHeader::V1 => 8, // LUKS1 always has 8 keyslot entries in the header
            LuksHeader::V2(h) => h.num_keyslots(),
        }
    }
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

impl LuksHeader {
    pub fn from_reader<R: Read + Seek>(mut reader: R) -> Result<Self, LuksError> {
        let mut magic = [0u8; LUKS_MAGIC_SIZE];
        reader.read_exact(&mut magic)?;

        if magic != LUKS_MAGIC {
            return Err(LuksError::InvalidMagic(magic));
        }

        let version = reader.read_u16::<BigEndian>()?;
        match version {
            1 => Ok(LuksHeader::V1),
            2 => {
                // Read the rest of the 4096-byte binary header
                let mut binary_header = vec![0u8; LUKS2_BINARY_HEADER_SIZE];
                binary_header[0..LUKS_MAGIC_SIZE].copy_from_slice(&magic);
                binary_header[LUKS_MAGIC_SIZE..LUKS_MAGIC_SIZE + LUKS_VERSION_SIZE]
                    .copy_from_slice(&version.to_be_bytes());

                reader.read_exact(&mut binary_header[LUKS_MAGIC_SIZE + LUKS_VERSION_SIZE..])?;

                let mut cursor = std::io::Cursor::new(&binary_header[LUKS_MAGIC_SIZE + LUKS_VERSION_SIZE..]);

                let hdr_size = cursor.read_u64::<BigEndian>()?;
                let seqid = cursor.read_u64::<BigEndian>()?;

                let mut label_buf = [0u8; LUKS2_LABEL_SIZE];
                cursor.read_exact(&mut label_buf)?;
                let label = String::from_utf8_lossy(&label_buf).trim_matches('\0').to_string();

                let mut checksum_alg_buf = [0u8; LUKS2_CHECKSUM_ALG_SIZE];
                cursor.read_exact(&mut checksum_alg_buf)?;
                let checksum_alg = String::from_utf8_lossy(&checksum_alg_buf)
                    .trim_matches('\0')
                    .to_string();

                let mut salt = [0u8; LUKS2_SALT_SIZE];
                cursor.read_exact(&mut salt)?;

                let mut uuid_buf = [0u8; LUKS2_UUID_SIZE];
                cursor.read_exact(&mut uuid_buf)?;
                let uuid = LuksUuid::from_str(&String::from_utf8_lossy(&uuid_buf))?;

                let mut subsystem_buf = [0u8; LUKS2_SUBSYSTEM_SIZE];
                cursor.read_exact(&mut subsystem_buf)?;
                let subsystem = String::from_utf8_lossy(&subsystem_buf)
                    .trim_matches('\0')
                    .to_string();

                // TODO must match the physical header offset on the device (in bytes). If it does
                // not match, the header is misplaced and must not be used. It is a prevention to
                // partition resize or manipulation with the device start offset.
                let hdr_offset = cursor.read_u64::<BigEndian>()?;

                let mut checksum = [0u8; LUKS2_CHECKSUM_SIZE];
                checksum.copy_from_slice(
                    &binary_header[LUKS2_CHECKSUM_OFFSET..LUKS2_CHECKSUM_OFFSET + LUKS2_CHECKSUM_SIZE],
                );

                // Read JSON area
                if hdr_size < LUKS2_BINARY_HEADER_SIZE as u64 {
                    return Err(LuksError::InvalidHeader(format!(
                        "Header size {} is too small",
                        hdr_size
                    )));
                }
                let json_size = hdr_size - LUKS2_BINARY_HEADER_SIZE as u64;
                let mut json_buf = vec![0u8; json_size as usize];
                reader.read_exact(&mut json_buf)?;

                // Verify checksum
                if checksum_alg == "sha256" {
                    let mut hasher = Sha256::new();

                    // The checksum is calculated with the checksum field itself zeroed out
                    let mut csum_buf = binary_header.clone();
                    for i in 0..LUKS2_CHECKSUM_SIZE {
                        csum_buf[LUKS2_CHECKSUM_OFFSET + i] = 0;
                    }
                    hasher.update(&csum_buf);
                    hasher.update(&json_buf);

                    let calculated = hasher.finalize();
                    // SHA256 is 32 bytes, but the checksum field is 64 bytes (padded with zeros)
                    if calculated.as_slice() != &checksum[0..SHA256_DIGEST_SIZE] {
                        return Err(LuksError::InvalidChecksum {
                            expected: to_hex(&checksum[0..SHA256_DIGEST_SIZE]),
                            actual: to_hex(calculated.as_slice()),
                        });
                    }
                } else {
                    return Err(LuksError::UnsupportedChecksumAlg(checksum_alg));
                }

                // Parse JSON
                let json_str = String::from_utf8_lossy(&json_buf).trim_matches('\0').to_string();
                let metadata: Luks2Metadata = serde_json::from_str(&json_str)?;

                Ok(LuksHeader::V2(Luks2Header {
                    version,
                    hdr_size,
                    seqid,
                    label,
                    checksum_alg,
                    salt,
                    uuid,
                    subsystem,
                    hdr_offset,
                    checksum,
                    metadata,
                }))
            }
            _ => Err(LuksError::UnsupportedVersion(version)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use byteorder::{BigEndian, WriteBytesExt};
    use std::io::{Cursor, Write};

    #[test]
    fn test_detect_luks2_with_checksum() {
        let mut binary_header = vec![0u8; LUKS2_BINARY_HEADER_SIZE];
        let json_data = r#"{
            "keyslots": {},
            "tokens": {},
            "segments": {},
            "digests": {},
            "config": {
                "json_size": "12288",
                "keyslots_size": "4161536"
            }
        }"#;
        let hdr_size = LUKS2_BINARY_HEADER_SIZE as u64 + json_data.len() as u64;

        {
            let mut cursor = Cursor::new(&mut binary_header);
            cursor.write_all(&LUKS_MAGIC).unwrap();
            cursor.write_u16::<BigEndian>(2).unwrap();
            cursor.write_u64::<BigEndian>(hdr_size).unwrap();
            cursor.write_u64::<BigEndian>(1).unwrap(); // seqid

            let mut label = [0u8; LUKS2_LABEL_SIZE];
            label[..4].copy_from_slice(b"test");
            cursor.write_all(&label).unwrap();

            let mut csum_alg = [0u8; LUKS2_CHECKSUM_ALG_SIZE];
            csum_alg[..6].copy_from_slice(b"sha256");
            cursor.write_all(&csum_alg).unwrap();

            cursor.write_all(&[0u8; LUKS2_SALT_SIZE]).unwrap();

            let mut uuid = [0u8; LUKS2_UUID_SIZE];
            uuid[..4].copy_from_slice(b"abcd");
            cursor.write_all(&uuid).unwrap();

            let subsystem = [0u8; LUKS2_SUBSYSTEM_SIZE];
            cursor.write_all(&subsystem).unwrap();

            cursor.write_u64::<BigEndian>(0).unwrap(); // hdr_offset
        }

        // Calculate checksum (with csum field as zeros, which it already is in our buffer)
        let mut hasher = Sha256::new();
        hasher.update(&binary_header);
        hasher.update(json_data.as_bytes());
        let result = hasher.finalize();

        // Put checksum into binary header
        binary_header[LUKS2_CHECKSUM_OFFSET..LUKS2_CHECKSUM_OFFSET + SHA256_DIGEST_SIZE]
            .copy_from_slice(&result);

        let mut buf = binary_header;
        buf.extend_from_slice(json_data.as_bytes());

        let cursor = Cursor::new(buf);
        let header = LuksHeader::from_reader(cursor).unwrap();

        if let LuksHeader::V2(h) = header {
            assert_eq!(h.version, 2);
            assert_eq!(h.label, "test");
            assert_eq!(h.uuid, "abcd");
            assert_eq!(h.num_keyslots(), 0);
        } else {
            panic!("Expected LUKS2 header");
        }
    }

    #[test]
    fn test_num_keyslots() {
        let mut binary_header = vec![0u8; LUKS2_BINARY_HEADER_SIZE];
        let json_data = r#"{
            "keyslots": {
                "0": {
                    "type": "luks2",
                    "key_size": 64,
                    "priority": 1,
                    "af": { "type": "luks1", "stripes": 4000, "hash": "sha256" },
                    "area": { "type": "raw", "encryption": "aes-xts-plain64", "key_size": 64, "offset": "32768", "size": "131072" },
                    "kdf": { "type": "argon2i", "time": 4, "memory": 235980, "cpus": 2, "salt": "z6vz4xK7cjan92rDA5JF8O6Jk2HouV0O8DMB6GlztVk=" }
                },
                "1": {
                    "type": "luks2",
                    "key_size": 64,
                    "priority": 1,
                    "af": { "type": "luks1", "stripes": 4000, "hash": "sha256" },
                    "area": { "type": "raw", "encryption": "aes-xts-plain64", "key_size": 64, "offset": "163840", "size": "131072" },
                    "kdf": { "type": "pbkdf2", "hash": "sha256", "iterations": 1774240, "salt": "vWcwY3rx2fKpXW2Q6oSCNf8j5bvdJyEzB6BNXECGDsI=" }
                }
            },
            "tokens": {},
            "segments": {},
            "digests": {},
            "config": {
                "json_size": "12288",
                "keyslots_size": "4161536"
            }
        }"#;
        let hdr_size = LUKS2_BINARY_HEADER_SIZE as u64 + json_data.len() as u64;

        {
            let mut cursor = Cursor::new(&mut binary_header);
            cursor.write_all(&LUKS_MAGIC).unwrap();
            cursor.write_u16::<BigEndian>(2).unwrap();
            cursor.write_u64::<BigEndian>(hdr_size).unwrap();
            cursor.write_u64::<BigEndian>(1).unwrap();

            let label = [0u8; LUKS2_LABEL_SIZE];
            cursor.write_all(&label).unwrap();

            let mut csum_alg = [0u8; LUKS2_CHECKSUM_ALG_SIZE];
            csum_alg[..6].copy_from_slice(b"sha256");
            cursor.write_all(&csum_alg).unwrap();

            cursor.write_all(&[0u8; LUKS2_SALT_SIZE]).unwrap();

            let mut uuid = [0u8; LUKS2_UUID_SIZE];
            uuid[..4].copy_from_slice(b"abcd");
            cursor.write_all(&uuid).unwrap();

            let subsystem = [0u8; LUKS2_SUBSYSTEM_SIZE];
            cursor.write_all(&subsystem).unwrap();

            cursor.write_u64::<BigEndian>(0).unwrap();
        }

        let mut hasher = Sha256::new();
        hasher.update(&binary_header);
        hasher.update(json_data.as_bytes());
        let result = hasher.finalize();

        binary_header[LUKS2_CHECKSUM_OFFSET..LUKS2_CHECKSUM_OFFSET + SHA256_DIGEST_SIZE]
            .copy_from_slice(&result);

        let mut buf = binary_header;
        buf.extend_from_slice(json_data.as_bytes());

        let cursor = Cursor::new(buf);
        let header = LuksHeader::from_reader(cursor).unwrap();

        assert_eq!(header.num_keyslots(), 2);
    }

    #[test]
    fn test_luks_uuid_parsing() {
        assert!(LuksUuid::from_str("550e8400-e29b-41d4-a716-446655440000").is_ok());
        assert!(LuksUuid::from_str("abcd").is_ok());
        assert!(LuksUuid::from_str("").is_err());
        assert!(LuksUuid::from_str("invalid-char!").is_err());
        assert!(LuksUuid::from_str(&"a".repeat(40)).is_err());
    }

    #[test]
    fn test_parse_full_example_json() {
        let json_data = r#"{
            "keyslots": {
                "0": {
                    "type": "luks2",
                    "key_size": 32,
                    "af": {
                        "type": "luks1",
                        "stripes": 4000,
                        "hash": "sha256"
                    },
                    "area": {
                        "type": "raw",
                        "encryption": "aes-xts-plain64",
                        "key_size": 32,
                        "offset": "32768",
                        "size": "131072"
                    },
                    "kdf": {
                        "type": "argon2i",
                        "time": 4,
                        "memory": 235980,
                        "cpus": 2,
                        "salt": "z6vz4xK7cjan92rDA5JF8O6Jk2HouV0O8DMB6GlztVk="
                    }
                },
                "1": {
                    "type": "luks2",
                    "key_size": 32,
                    "af": {
                        "type": "luks1",
                        "stripes": 4000,
                        "hash": "sha256"
                    },
                    "area": {
                        "type": "raw",
                        "encryption": "aes-xts-plain64",
                        "key_size": 32,
                        "offset": "163840",
                        "size": "131072"
                    },
                    "kdf": {
                        "type": "pbkdf2",
                        "hash": "sha256",
                        "iterations": 1774240,
                        "salt": "vWcwY3rx2fKpXW2Q6oSCNf8j5bvdJyEzB6BNXECGDsI="
                    }
                }
            },
            "tokens": {
                "0": {
                    "type": "luks2-keyring",
                    "keyslots": [
                        "1"
                    ],
                    "key_description": "MyKeyringKeyID"
                }
            },
            "segments": {
                "0": {
                    "type": "crypt",
                    "offset": "4194304",
                    "iv_tweak": "0",
                    "size": "dynamic",
                    "encryption": "aes-xts-plain64",
                    "sector_size": 512
                }
            },
            "digests": {
                "0": {
                    "type": "pbkdf2",
                    "keyslots": [
                        "0",
                        "1"
                    ],
                    "segments": [
                        "0"
                    ],
                    "hash": "sha256",
                    "iterations": 110890,
                    "salt": "G8gqtKhS96IbogHyJLO+t9kmjLkx+DM3HHJqQtgc2Dk=",
                    "digest": "C9JWko5m+oYmjg6R0t/98cGGzLr/4UaG3hImSJMivfc="
                }
            },
            "config": {
                "json_size": "12288",
                "keyslots_size": "4161536",
                "flags": [
                    "allow-discards"
                ]
            }
        }"#;
        let metadata: Luks2Metadata = serde_json::from_str(json_data).unwrap();
        assert_eq!(metadata.keyslots.len(), 2);
        assert_eq!(metadata.tokens.len(), 1);
        assert_eq!(metadata.segments.len(), 1);
        assert_eq!(metadata.digests.len(), 1);
        assert_eq!(metadata.config.json_size, Luks2U64(12288));

        let ks0 = metadata.keyslots.get("0").unwrap();
        let Luks2Keyslot::Luks2 { key_size, kdf, .. } = ks0 else {
            panic!("Expected Luks2 keyslot")
        };
        assert_eq!(*key_size, Luks2KeySize::Size32);
        assert!(matches!(kdf, Luks2Kdf::Argon2i { .. }));

        let ks1 = metadata.keyslots.get("1").unwrap();
        let Luks2Keyslot::Luks2 { kdf, .. } = ks1 else {
            panic!("Expected Luks2 keyslot")
        };
        assert!(matches!(kdf, Luks2Kdf::Pbkdf2 { .. }));

        let token0 = metadata.tokens.get("0").unwrap();
        assert!(matches!(token0, Luks2Token::Keyring { .. }));

        let segment0 = metadata.segments.get("0").unwrap();
        let Luks2Segment::Crypt { size, .. } = segment0;
        assert_eq!(size, &Luks2SegmentSize::Dynamic);

        let digest0 = metadata.digests.get("0").unwrap();
        assert!(matches!(digest0, Luks2Digest::Pbkdf2 { .. }));
    }

    #[test]
    fn test_invalid_keyslot_area_type() {
        let json_data = r#"{
            "keyslots": {
                "0": {
                    "type": "luks2",
                    "key_size": 32,
                    "af": { "type": "luks1", "stripes": 4000, "hash": "sha256" },
                    "area": { "type": "none", "encryption": "aes-xts-plain64", "key_size": 32, "offset": "32768", "size": "131072" },
                    "kdf": { "type": "argon2i", "time": 4, "memory": 235980, "cpus": 2, "salt": "salt" }
                }
            },
            "tokens": {},
            "segments": {},
            "digests": {},
            "config": { "json_size": "12288", "keyslots_size": "4161536" }
        }"#;
        let result: Result<Luks2Metadata, _> = serde_json::from_str(json_data);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("LUKS2 keyslot must have area type 'raw'")
        );
    }

    #[test]
    fn test_parse_reencrypt_keyslot() {
        let json_data = r#"{
            "keyslots": {
                "0": {
                    "type": "reencrypt",
                    "mode": "reencrypt",
                    "direction": "forward",
                    "key_size": "1",
                    "priority": 1,
                    "af": { "type": "luks1", "stripes": 4000, "hash": "sha256" },
                    "area": { "type": "none", "encryption": "aes-xts-plain64", "key_size": 32, "offset": "32768", "size": "131072" },
                    "kdf": { "type": "argon2i", "time": 4, "memory": 235980, "cpus": 2, "salt": "salt" }
                }
            },
            "tokens": {},
            "segments": {},
            "digests": {},
            "config": { "json_size": "12288", "keyslots_size": "4161536" }
        }"#;
        let metadata: Luks2Metadata = serde_json::from_str(json_data).unwrap();
        let slot = metadata.keyslots.get("0").unwrap();
        let Luks2Keyslot::Reencrypt {
            mode,
            direction,
            key_size,
            ..
        } = slot
        else {
            panic!("Expected Reencrypt keyslot")
        };
        assert_eq!(*mode, Luks2ReencryptMode::Reencrypt);
        assert_eq!(*direction, Luks2ReencryptDirection::Forward);
        assert_eq!(key_size, "1");
    }

    #[test]
    fn test_parse_reencrypt_area_types() {
        let json_data = r#"{
            "keyslots": {
                "checksum_slot": {
                    "type": "reencrypt",
                    "mode": "reencrypt",
                    "direction": "forward",
                    "key_size": "1",
                    "af": { "type": "luks1", "stripes": 4000, "hash": "sha256" },
                    "area": { "type": "checksum", "hash": "sha256", "sector_size": 512, "offset": "32768", "size": "131072" },
                    "kdf": { "type": "argon2i", "time": 4, "memory": 235980, "cpus": 2, "salt": "salt" }
                },
                "datashift_slot": {
                    "type": "reencrypt",
                    "mode": "reencrypt",
                    "direction": "forward",
                    "key_size": "1",
                    "af": { "type": "luks1", "stripes": 4000, "hash": "sha256" },
                    "area": { "type": "datashift", "shift_size": "4096", "offset": "32768", "size": "131072" },
                    "kdf": { "type": "argon2i", "time": 4, "memory": 235980, "cpus": 2, "salt": "salt" }
                },
                "datashift_checksum_slot": {
                    "type": "reencrypt",
                    "mode": "reencrypt",
                    "direction": "forward",
                    "key_size": "1",
                    "af": { "type": "luks1", "stripes": 4000, "hash": "sha256" },
                    "area": { "type": "datashift-checksum", "hash": "sha256", "sector_size": 512, "shift_size": "4096", "offset": "32768", "size": "131072" },
                    "kdf": { "type": "argon2i", "time": 4, "memory": 235980, "cpus": 2, "salt": "salt" }
                }
            },
            "tokens": {},
            "segments": {},
            "digests": {},
            "config": { "json_size": "12288", "keyslots_size": "4161536" }
        }"#;
        let metadata: Luks2Metadata = serde_json::from_str(json_data).unwrap();

        let checksum_slot = metadata.keyslots.get("checksum_slot").unwrap();
        if let Luks2Keyslot::Reencrypt { area, .. } = checksum_slot {
            assert!(matches!(area, Luks2Area::Checksum { .. }));
        } else {
            panic!("Expected Reencrypt keyslot")
        }

        let datashift_slot = metadata.keyslots.get("datashift_slot").unwrap();
        if let Luks2Keyslot::Reencrypt { area, .. } = datashift_slot {
            assert!(matches!(area, Luks2Area::Datashift { .. }));
        } else {
            panic!("Expected Reencrypt keyslot")
        }

        let datashift_checksum_slot = metadata.keyslots.get("datashift_checksum_slot").unwrap();
        if let Luks2Keyslot::Reencrypt { area, .. } = datashift_checksum_slot {
            assert!(matches!(area, Luks2Area::DatashiftChecksum { .. }));
        } else {
            panic!("Expected Reencrypt keyslot")
        }
    }

    #[test]
    fn test_parse_argon2id_kdf() {
        let json_data = r#"{
                    "keyslots": {
                        "0": {
                            "type": "luks2",
                            "key_size": 32,
                            "af": { "type": "luks1", "stripes": 4000, "hash": "sha256" },
                            "area": { "type": "raw", "encryption": "aes-xts-plain64", "key_size": 32, "offset": "32768", "size": "131072" },
                            "kdf": { "type": "argon2id", "time": 4, "memory": 235980, "cpus": 2, "salt": "salt" }
                        }
                    },
                    "tokens": {},
                    "segments": {},
                    "digests": {},
                    "config": { "json_size": "12288", "keyslots_size": "4161536" }
                }"#;
        let metadata: Luks2Metadata = serde_json::from_str(json_data).unwrap();
        let slot = metadata.keyslots.get("0").unwrap();
        let Luks2Keyslot::Luks2 { kdf, .. } = slot else {
            panic!("Expected Luks2 keyslot")
        };
        assert!(matches!(
            kdf,
            Luks2Kdf::Argon2id {
                time: 4,
                memory: 235980,
                cpus: 2,
                ..
            }
        ));
    }
}
