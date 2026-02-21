use byteorder::{BigEndian, ReadBytesExt};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{Read, Seek};
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Luks2Metadata {
    pub keyslots: serde_json::Value,
    pub tokens: serde_json::Value,
    pub segments: serde_json::Value,
    pub digests: serde_json::Value,
    pub config: serde_json::Value,
}

#[derive(Debug, Clone)]
pub struct Luks2Header {
    pub version: u16,
    pub hdr_size: u64,
    pub seqid: u64,
    pub label: String,
    pub checksum_alg: String,
    pub salt: [u8; LUKS2_SALT_SIZE],
    pub uuid: String,
    pub subsystem: String,
    pub hdr_offset: u64,
    pub checksum: [u8; LUKS2_CHECKSUM_SIZE],
    pub metadata: Luks2Metadata,
}

#[derive(Debug, Clone)]
pub enum LuksHeader {
    V1, // Placeholder for LUKS1
    V2(Luks2Header),
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
                let uuid = String::from_utf8_lossy(&uuid_buf).trim_matches('\0').to_string();

                let mut subsystem_buf = [0u8; LUKS2_SUBSYSTEM_SIZE];
                cursor.read_exact(&mut subsystem_buf)?;
                let subsystem = String::from_utf8_lossy(&subsystem_buf)
                    .trim_matches('\0')
                    .to_string();

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
        let json_data = r#"{"keyslots":{},"tokens":{},"segments":{},"digests":{},"config":{}}"#;
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
        } else {
            panic!("Expected LUKS2 header");
        }
    }
}
