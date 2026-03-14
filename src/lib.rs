use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt;
use std::io::{Read, Seek, Write};
use std::str::FromStr;
use thiserror::Error;

#[cfg(feature = "_open")]
use {
    aes::cipher::KeyInit,
    base64::Engine as _,
    rand::Rng,
    sha2::Sha512,
    std::io::SeekFrom,
    std::path::Path,
    std::process::{Command, Stdio},
    xts_mode::{Xts128, get_tweak_default},
};

pub mod af;
pub mod hash;
pub mod kdf;
pub mod key;

pub use hash::{
    HASH_SHA256, HASH_SHA512, LUKS2_CHECKSUM_ALG_ID_LEN, Luks2HashAlg, SHA256_DIGEST_SIZE, SHA512_DIGEST_SIZE,
};
pub use kdf::Luks2Kdf;
pub use key::{UnlockKey, VolumeKey};

/// A representation of a LUKS device, including its header and keyslots.
///
/// This structure holds the primary metadata for the encrypted device.
#[cfg(feature = "_open")]
#[derive(Serialize, Deserialize)]
pub struct LuksDevice {
    /// The LUKS header (either version 1 or 2).
    pub header: LuksHeader,
    /// A map of keyslot IDs to their raw, encrypted data area.
    pub keyslots: HashMap<String, Vec<u8>>,
    /// The volume key, if the device has been successfully unlocked.
    #[serde(skip)]
    pub unlocked_key: Option<VolumeKey>,
}

#[cfg(feature = "_open")]
impl LuksDevice {
    /// Unlocks the device with a passphrase, storing the volume key in the device.
    pub fn unlock(&mut self, keyslot_id: &str, key: &UnlockKey) -> Result<(), LuksError> {
        let volume_key = self.get_volume_key(keyslot_id, key)?;
        self.unlocked_key = Some(volume_key);

        if self.verify(keyslot_id)? {
            Ok(())
        } else {
            self.unlocked_key = None;
            Err(LuksError::Kdf("Passphrase verification failed".to_string()))
        }
    }

    /// Writes the LUKS device to a writer.
    pub fn to_writer<W: Write + Seek>(&self, mut writer: W) -> Result<(), LuksError> {
        self.header.to_writer(&mut writer)?;

        match &self.header {
            LuksHeader::V1 => return Err(LuksError::UnsupportedVersion(1)),
            LuksHeader::V2(h) => {
                for (id, slot) in &h.metadata.keyslots {
                    let area = slot.area();
                    let data = self.keyslots.get(id).ok_or_else(|| {
                        LuksError::InvalidHeader(format!("Data for keyslot {} not found", id))
                    })?;
                    writer.seek(std::io::SeekFrom::Start(area.offset()))?;
                    writer.write_all(data)?;
                }
            }
        }

        Ok(())
    }

    /// Verifies that the current unlocked volume key matches a specific keyslot.
    ///
    /// # Errors
    ///
    /// Returns `LuksError::Locked` if the device has not been unlocked.
    pub fn verify(&self, keyslot_id: &str) -> Result<bool, LuksError> {
        let volume_key = self.unlocked_key.as_ref().ok_or(LuksError::Locked)?;

        let h2 = match &self.header {
            LuksHeader::V1 => return Err(LuksError::UnsupportedVersion(1)),
            LuksHeader::V2(h) => h,
        };

        // Find the digest associated with this keyslot
        let (_digest_id, digest) = h2
            .metadata
            .digests
            .iter()
            .find(|(_, d)| match d {
                Luks2Digest::Pbkdf2 { keyslots, .. } => keyslots.contains(&keyslot_id.to_string()),
            })
            .ok_or_else(|| LuksError::InvalidHeader(format!("No digest found for keyslot {}", keyslot_id)))?;

        let (digest_hash, digest_salt, expected_digest, digest_iterations) = match digest {
            Luks2Digest::Pbkdf2 {
                hash,
                salt,
                digest,
                iterations,
                ..
            } => (hash, salt, digest, iterations),
        };

        // 5. Verify the volume key using the digest
        let kdf_digest_salt = base64::engine::general_purpose::STANDARD
            .decode(digest_salt)
            .map_err(|e| LuksError::Kdf(format!("Invalid salt base64 in digest: {}", e)))?;

        let expected_bytes = base64::engine::general_purpose::STANDARD
            .decode(expected_digest)
            .map_err(|e| LuksError::Kdf(format!("Invalid digest base64 in digest: {}", e)))?;

        let mut verification_output = vec![0u8; expected_bytes.len()];
        if digest_hash == &Luks2HashAlg::Sha256 {
            pbkdf2::pbkdf2::<hmac::Hmac<Sha256>>(
                volume_key.expose_bytes(),
                &kdf_digest_salt,
                *digest_iterations,
                &mut verification_output,
            )
            .map_err(|e| LuksError::Kdf(format!("PBKDF2 SHA256 error: {}", e)))?;
        } else if digest_hash == &Luks2HashAlg::Sha512 {
            pbkdf2::pbkdf2::<hmac::Hmac<Sha512>>(
                volume_key.expose_bytes(),
                &kdf_digest_salt,
                *digest_iterations,
                &mut verification_output,
            )
            .map_err(|e| LuksError::Kdf(format!("PBKDF2 SHA512 error: {}", e)))?;
        } else {
            return Err(LuksError::UnsupportedChecksumAlg(digest_hash.to_string()));
        }

        Ok(verification_output == expected_bytes)
    }

    /// Derives the volume key using a passphrase and a specific keyslot.
    pub fn get_volume_key(&self, keyslot_id: &str, key: &UnlockKey) -> Result<VolumeKey, LuksError> {
        let h2 = match &self.header {
            LuksHeader::V1 => return Err(LuksError::UnsupportedVersion(1)),
            LuksHeader::V2(h) => h,
        };

        let keyslot = h2
            .metadata
            .keyslots
            .get(keyslot_id)
            .ok_or_else(|| LuksError::InvalidHeader(format!("Keyslot {} not found", keyslot_id)))?;

        let (kdf, key_size, area, af) = match keyslot {
            Luks2Keyslot::Luks2 {
                kdf,
                key_size,
                area,
                af,
                ..
            } => (kdf, u64::from(*key_size), area, af),
            Luks2Keyslot::Reencrypt { .. } => {
                return Err(LuksError::Kdf(
                    "Verification for reencrypt keyslots not yet supported".to_string(),
                ));
            }
        };

        let Luks2Area::Raw { encryption, .. } = area else {
            return Err(LuksError::InvalidHeader(
                "LUKS2 keyslot must have area type 'raw'".to_string(),
            ));
        };

        // 1. Derive the keyslot key from the passphrase
        let keyslot_key = kdf.derive_key(key, &h2.salt, key_size as usize)?;
        // 2. Get the encrypted data from the captured keyslots
        let encrypted_data = self
            .keyslots
            .get(keyslot_id)
            .ok_or_else(|| LuksError::InvalidHeader(format!("Data for keyslot {} not captured", keyslot_id)))?;

        // 3. Decrypt the area
        if *encryption != Luks2AreaEncryption::AesXtsPlain64 {
            return Err(LuksError::UnsupportedChecksumAlg(format!(
                "Area encryption {} is not supported",
                encryption
            )));
        }

        let mut decrypted_data = encrypted_data.clone();
        if key_size == (AES128_KEY_SIZE as u64 * 2) {
            let cipher_1 = aes::Aes128::new_from_slice(&keyslot_key[0..AES128_KEY_SIZE])
                .map_err(|e| LuksError::Kdf(format!("Cipher error: {}", e)))?;
            let cipher_2 = aes::Aes128::new_from_slice(&keyslot_key[AES128_KEY_SIZE..AES128_KEY_SIZE * 2])
                .map_err(|e| LuksError::Kdf(format!("Cipher error: {}", e)))?;
            let xts = Xts128::new(cipher_1, cipher_2);

            for (i, chunk) in decrypted_data.chunks_mut(SECTOR_SIZE).enumerate() {
                xts.decrypt_area(chunk, SECTOR_SIZE, (i as u64).into(), |t| get_tweak_default(t));
            }
        } else if key_size == (AES256_KEY_SIZE as u64 * 2) {
            let cipher_1 = aes::Aes256::new_from_slice(&keyslot_key[0..AES256_KEY_SIZE])
                .map_err(|e| LuksError::Kdf(format!("Cipher error: {}", e)))?;
            let cipher_2 = aes::Aes256::new_from_slice(&keyslot_key[AES256_KEY_SIZE..AES256_KEY_SIZE * 2])
                .map_err(|e| LuksError::Kdf(format!("Cipher error: {}", e)))?;
            let xts = Xts128::new(cipher_1, cipher_2);

            for (i, chunk) in decrypted_data.chunks_mut(SECTOR_SIZE).enumerate() {
                xts.decrypt_area(chunk, SECTOR_SIZE, (i as u64).into(), |t| get_tweak_default(t));
            }
        } else {
            return Err(LuksError::Kdf(format!(
                "Unsupported key size {} for AES-XTS",
                key_size
            )));
        }

        // 4. Merge AF stripes to get the volume key
        let volume_key_bytes = crate::af::merge(
            &decrypted_data[0..(key_size as u64 * af.stripes as u64) as usize],
            &af.hash,
            af.stripes,
            key_size as usize,
        )?;
        VolumeKey::new(volume_key_bytes)
    }

    /// Maps the LUKS device using dmsetup.
    pub fn map_with_dmsetup(&self, name: &str, backing_device: &Path) -> Result<(), LuksError> {
        let volume_key = self.unlocked_key.as_ref().ok_or(LuksError::Locked)?;

        let h2 = match &self.header {
            LuksHeader::V1 => return Err(LuksError::UnsupportedVersion(1)),
            LuksHeader::V2(h) => h,
        };

        // Find the crypt segment
        let segment = h2
            .metadata
            .segments
            .iter()
            .find_map(|(_, s)| match s {
                Luks2Segment::Crypt { .. } => Some(s),
            })
            .ok_or_else(|| LuksError::InvalidHeader("No crypt segment found".to_string()))?;

        let Luks2Segment::Crypt {
            offset,
            iv_tweak,
            size,
            encryption,
            ..
        } = segment;

        // Calculate sectors
        let num_sectors = match size {
            Luks2SegmentSize::U64(s) => s / SECTOR_SIZE as u64,
            Luks2SegmentSize::Dynamic => {
                let mut file = std::fs::File::open(backing_device)?;
                let total_size = file.seek(SeekFrom::End(0))?;
                (total_size - offset.0) / SECTOR_SIZE as u64
            }
        };

        // Construct the table string
        // Table format: <start> <length> <target_type> <cipher> <key> <iv_offset> <device_path> <offset>
        let table = format!(
            "0 {} crypt {} {} {} {} {}\n",
            num_sectors,
            encryption,
            to_hex(volume_key.expose_bytes()),
            iv_tweak.0,
            backing_device.to_string_lossy(),
            offset.0 / SECTOR_SIZE as u64
        );

        // Call dmsetup create <name>
        let mut child = Command::new("dmsetup")
            .arg("create")
            .arg(name)
            .stdin(Stdio::piped())
            .spawn()?;

        // Pipe the table to stdin
        if let Some(mut child_stdin) = child.stdin.take() {
            child_stdin.write_all(table.as_bytes())?;
        }

        let status = child.wait()?;
        if !status.success() {
            return Err(LuksError::DmSetup(format!("exit code {}", status)));
        }

        Ok(())
    }

    /// Changes the passphrase for a specific keyslot without changing the volume key.
    ///
    /// This only updates the metadata in memory. You must call [`to_writer`] to persist the changes.
    pub fn change_passphrase(
        &mut self,
        keyslot_id: &str,
        old_key: &UnlockKey,
        new_key: &UnlockKey,
    ) -> Result<(), LuksError> {
        let volume_key = self.get_volume_key(keyslot_id, old_key)?;
        self.update_keyslot(keyslot_id, new_key, &volume_key)
    }

    fn update_keyslot(
        &mut self,
        keyslot_id: &str,
        key: &UnlockKey,
        volume_key: &VolumeKey,
    ) -> Result<(), LuksError> {
        let h2 = match &mut self.header {
            LuksHeader::V1 => return Err(LuksError::UnsupportedVersion(1)),
            LuksHeader::V2(h) => h,
        };

        let keyslot = h2
            .metadata
            .keyslots
            .get_mut(keyslot_id)
            .ok_or_else(|| LuksError::InvalidHeader(format!("Keyslot {} not found", keyslot_id)))?;

        let (kdf, key_size, area, af) = match keyslot {
            Luks2Keyslot::Luks2 {
                kdf,
                key_size,
                area,
                af,
                ..
            } => (kdf, u64::from(*key_size), area, af),
            Luks2Keyslot::Reencrypt { .. } => {
                return Err(LuksError::Kdf(
                    "Changing passphrase for reencrypt keyslots not supported".to_string(),
                ));
            }
        };

        let Luks2Area::Raw { encryption, .. } = area else {
            return Err(LuksError::InvalidHeader(
                "LUKS2 keyslot must have area type 'raw'".to_string(),
            ));
        };

        // 1. Generate new KDF salt
        let mut new_salt = vec![0u8; KDF_SALT_SIZE];
        rand::rng().fill(&mut new_salt[..]);
        let new_salt_b64 = base64::engine::general_purpose::STANDARD.encode(new_salt);

        // Update salt in KDF
        match kdf {
            Luks2Kdf::Argon2i { salt, .. } => *salt = new_salt_b64,
            Luks2Kdf::Argon2id { salt, .. } => *salt = new_salt_b64,
            Luks2Kdf::Pbkdf2 { salt, .. } => *salt = new_salt_b64,
        }

        // 2. Derive the new keyslot key
        let keyslot_key = kdf.derive_key(key, &h2.salt, key_size as usize)?;
        // 3. AF-split the volume key
        let mut random_stripes =
            vec![0u8; (volume_key.expose_bytes().len() as u32 * (af.stripes - 1)) as usize];
        rand::rng().fill(&mut random_stripes[..]);
        let split_data = crate::af::split(
            volume_key.expose_bytes(),
            &af.hash,
            af.stripes,
            volume_key.expose_bytes().len(),
            random_stripes,
        )?;

        // 4. Encrypt the area
        if *encryption != Luks2AreaEncryption::AesXtsPlain64 {
            return Err(LuksError::UnsupportedChecksumAlg(format!(
                "Area encryption {} is not supported",
                encryption
            )));
        }

        let mut encrypted_data = split_data.clone();
        if key_size == (AES128_KEY_SIZE as u64 * 2) {
            let cipher_1 = aes::Aes128::new_from_slice(&keyslot_key[0..AES128_KEY_SIZE])
                .map_err(|e| LuksError::Kdf(format!("Cipher error: {}", e)))?;
            let cipher_2 = aes::Aes128::new_from_slice(&keyslot_key[AES128_KEY_SIZE..AES128_KEY_SIZE * 2])
                .map_err(|e| LuksError::Kdf(format!("Cipher error: {}", e)))?;
            let xts = Xts128::new(cipher_1, cipher_2);

            for (i, chunk) in encrypted_data.chunks_mut(SECTOR_SIZE).enumerate() {
                xts.encrypt_area(chunk, SECTOR_SIZE, (i as u64).into(), |t| get_tweak_default(t));
            }
        } else if key_size == (AES256_KEY_SIZE as u64 * 2) {
            let cipher_1 = aes::Aes256::new_from_slice(&keyslot_key[0..AES256_KEY_SIZE])
                .map_err(|e| LuksError::Kdf(format!("Cipher error: {}", e)))?;
            let cipher_2 = aes::Aes256::new_from_slice(&keyslot_key[AES256_KEY_SIZE..AES256_KEY_SIZE * 2])
                .map_err(|e| LuksError::Kdf(format!("Cipher error: {}", e)))?;
            let xts = Xts128::new(cipher_1, cipher_2);

            for (i, chunk) in encrypted_data.chunks_mut(SECTOR_SIZE).enumerate() {
                xts.encrypt_area(chunk, SECTOR_SIZE, (i as u64).into(), |t| get_tweak_default(t));
            }
        } else {
            return Err(LuksError::Kdf(format!(
                "Unsupported key size {} for AES-XTS",
                key_size
            )));
        }

        // 5. Update self.keyslots
        self.keyslots.insert(keyslot_id.to_string(), encrypted_data);

        Ok(())
    }
}

/// Returns true if the device at the given path is a LUKS device.
///
/// This only checks the magic signature at the beginning of the device.
#[cfg(feature = "_open")]
pub fn is_luks_device<P: AsRef<Path>>(path: P) -> Result<bool, LuksError> {
    let mut file = std::fs::File::open(path)?;
    let mut buffer = [0u8; LUKS_MAGIC_SIZE];
    match file.read_exact(&mut buffer) {
        Ok(_) => Ok(buffer == LUKS_MAGIC),
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(false),
        Err(e) => Err(LuksError::Io(e)),
    }
}

/// The magic signature for LUKS devices: "LUKS\xBA\xBE".
pub const LUKS_MAGIC: [u8; 6] = *b"LUKS\xBA\xBE";

/// Size of the LUKS magic signature in bytes.
pub const LUKS_MAGIC_SIZE: usize = 6;
/// Size of the LUKS version field in bytes.
pub const LUKS_VERSION_SIZE: usize = 2;

/// Size of the LUKS2 label field in bytes.
pub const LUKS2_LABEL_SIZE: usize = 48;
/// Size of the LUKS2 salt field in bytes.
pub const LUKS2_SALT_SIZE: usize = 64;
/// Size of the LUKS2 uuid field in bytes.
pub const LUKS2_UUID_SIZE: usize = 40;
/// Size of the LUKS2 subsystem field in bytes.
pub const LUKS2_SUBSYSTEM_SIZE: usize = 48;
/// Size of the LUKS2 checksum field in bytes.
pub const LUKS2_CHECKSUM_SIZE: usize = 64;

/// The standard sector size in bytes.
pub const SECTOR_SIZE: usize = 512;

/// The size of a KDF salt in bytes.
pub const KDF_SALT_SIZE: usize = 32;

/// The offset in bytes where the LUKS2 checksum field begins.
pub const LUKS2_CHECKSUM_OFFSET: usize = 448;
/// The size of the LUKS2 binary header area in bytes.
pub const LUKS2_BINARY_HEADER_SIZE: usize = 4096;

/// The block size for the AES cipher in bytes.
pub const AES_BLOCK_SIZE: usize = 16;
/// The key size for AES-128 in bytes.
pub const AES128_KEY_SIZE: usize = 16;
/// The key size for AES-256 in bytes.
pub const AES256_KEY_SIZE: usize = 32;

/// The number of anti-forensic stripes used by the LUKS1 AF feature.
///
/// For historical reasons, this value is always 4000.
pub const LUKS1_AF_STRIPES: u32 = 4000;

/// Default size of the LUKS2 JSON area in bytes.
pub const LUKS2_DEFAULT_JSON_SIZE: u64 = 12288;
/// Default size of the LUKS2 keyslots area in bytes.
pub const LUKS2_DEFAULT_KEYSLOTS_SIZE: u64 = 4161536;

/// Errors that can occur when working with LUKS devices.
#[derive(Error, Debug)]
pub enum LuksError {
    /// An I/O error occurred.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    /// The LUKS magic signature is invalid or missing.
    #[error("Invalid LUKS magic: {0:?}")]
    InvalidMagic([u8; LUKS_MAGIC_SIZE]),
    /// The LUKS version is not supported by this library.
    #[error("Unsupported LUKS version: {0}")]
    UnsupportedVersion(u16),
    /// An error occurred while parsing JSON metadata.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    /// The LUKS2 header or metadata is malformed or invalid.
    #[error("Invalid LUKS2 header: {0}")]
    InvalidHeader(String),
    /// The header checksum verification failed.
    #[error("Checksum verification failed: expected {expected}, got {actual}")]
    InvalidChecksum { expected: String, actual: String },
    /// The requested checksum or hash algorithm is not supported.
    #[error("Unsupported checksum algorithm: {0}")]
    UnsupportedChecksumAlg(String),
    /// An error occurred during key derivation (KDF).
    #[error("KDF error: {0}")]
    Kdf(String),
    /// An error occurred when interacting with `dmsetup`.
    #[error("dmsetup failed: {0}")]
    DmSetup(String),
    /// The operation requires an unlocked device, but it is currently locked.
    #[error("Device is locked")]
    Locked,
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

/// The size of a LUKS2 key in bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(into = "u64", try_from = "u64")]
pub enum Luks2KeySize {
    /// 32-byte (256-bit) key size.
    Size32 = 32,
    /// 64-byte (512-bit) key size.
    Size64 = 64,
}

impl From<Luks2KeySize> for u64 {
    fn from(val: Luks2KeySize) -> Self {
        val as u64
    }
}

impl fmt::Display for Luks2KeySize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Luks2KeySize::Size32 => write!(f, "32"),
            Luks2KeySize::Size64 => write!(f, "64"),
        }
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

/// The type of anti-forensic (AF) algorithm used in LUKS2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Luks2AfType {
    /// The original LUKS1 AF algorithm.
    Luks1,
}

impl fmt::Display for Luks2AfType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Luks2AfType::Luks1 => write!(f, "luks1"),
        }
    }
}

/// Anti-forensic (AF) settings for a keyslot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Luks2Af {
    /// The type of AF algorithm.
    #[serde(rename = "type")]
    pub af_type: Luks2AfType,
    /// The number of AF stripes.
    pub stripes: u32,
    /// The hash algorithm used for AF.
    pub hash: Luks2HashAlg,
}

/// The encryption algorithm used for the keyslot area.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Luks2AreaEncryption {
    /// AES in XTS mode with 64-bit sector numbers.
    #[serde(rename = "aes-xts-plain64")]
    AesXtsPlain64,
}

impl fmt::Display for Luks2AreaEncryption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Luks2AreaEncryption::AesXtsPlain64 => write!(f, "aes-xts-plain64"),
        }
    }
}

/// A keyslot data area in LUKS2.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum Luks2Area {
    /// A raw data area.
    Raw {
        /// The encryption algorithm used for this area.
        encryption: Luks2AreaEncryption,
        /// The key size for the area encryption.
        key_size: Luks2KeySize,
        /// The offset of the area in bytes.
        offset: Luks2U64,
        /// The size of the area in bytes.
        size: Luks2U64,
    },
    /// No data area.
    None {
        /// The offset of the area in bytes.
        offset: Luks2U64,
        /// The size of the area in bytes.
        size: Luks2U64,
    },
    /// A journal area.
    Journal {
        /// The offset of the area in bytes.
        offset: Luks2U64,
        /// The size of the area in bytes.
        size: Luks2U64,
    },
    /// A checksum area.
    Checksum {
        /// The offset of the area in bytes.
        offset: Luks2U64,
        /// The size of the area in bytes.
        size: Luks2U64,
        /// The hash algorithm used for the checksum.
        hash: Luks2HashAlg,
        /// The sector size in bytes.
        sector_size: u32,
    },
    /// A data shift area.
    Datashift {
        /// The offset of the area in bytes.
        offset: Luks2U64,
        /// The size of the area in bytes.
        size: Luks2U64,
        /// The shift size in bytes.
        shift_size: Luks2U64,
    },
    /// A combined data shift and journal area.
    #[serde(rename = "datashift-journal")]
    DatashiftJournal {
        /// The offset of the area in bytes.
        offset: Luks2U64,
        /// The size of the area in bytes.
        size: Luks2U64,
        /// The shift size in bytes.
        shift_size: Luks2U64,
    },
    /// A combined data shift and checksum area.
    #[serde(rename = "datashift-checksum")]
    DatashiftChecksum {
        /// The offset of the area in bytes.
        offset: Luks2U64,
        /// The size of the area in bytes.
        size: Luks2U64,
        /// The hash algorithm used for the checksum.
        hash: Luks2HashAlg,
        /// The sector size in bytes.
        sector_size: u32,
        /// The shift size in bytes.
        shift_size: Luks2U64,
    },
}

impl Luks2Area {
    /// Returns the offset of the data area in bytes.
    pub fn offset(&self) -> u64 {
        match self {
            Luks2Area::Raw { offset, .. } => offset.0,
            Luks2Area::None { offset, .. } => offset.0,
            Luks2Area::Journal { offset, .. } => offset.0,
            Luks2Area::Checksum { offset, .. } => offset.0,
            Luks2Area::Datashift { offset, .. } => offset.0,
            Luks2Area::DatashiftJournal { offset, .. } => offset.0,
            Luks2Area::DatashiftChecksum { offset, .. } => offset.0,
        }
    }

    /// Returns the size of the data area in bytes.
    pub fn size(&self) -> u64 {
        match self {
            Luks2Area::Raw { size, .. } => size.0,
            Luks2Area::None { size, .. } => size.0,
            Luks2Area::Journal { size, .. } => size.0,
            Luks2Area::Checksum { size, .. } => size.0,
            Luks2Area::Datashift { size, .. } => size.0,
            Luks2Area::DatashiftJournal { size, .. } => size.0,
            Luks2Area::DatashiftChecksum { size, .. } => size.0,
        }
    }
}

/// The priority of a LUKS2 keyslot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "i32", into = "i32")]
pub enum Luks2KeyslotPriority {
    /// The keyslot should be ignored except if explicitly stated.
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

/// The mode of a reencryption operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Luks2ReencryptMode {
    /// Reencrypt an already encrypted device.
    Reencrypt,
    /// Encrypt a plaintext device.
    Encrypt,
    /// Decrypt an encrypted device.
    Decrypt,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
/// The direction of a reencryption operation.
pub enum Luks2ReencryptDirection {
    /// Forward reencryption.
    Forward,
    /// Backward reencryption.
    Backward,
}

/// A LUKS2 keyslot.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Luks2Keyslot {
    /// A standard LUKS2 keyslot.
    Luks2 {
        /// The key size in bytes.
        key_size: Luks2KeySize,
        /// The priority of the keyslot.
        priority: Option<Luks2KeyslotPriority>,
        /// Anti-forensic settings.
        af: Luks2Af,
        /// The data area.
        area: Luks2Area,
        /// KDF settings.
        kdf: Luks2Kdf,
    },
    /// A reencryption keyslot.
    Reencrypt {
        /// The reencryption mode.
        mode: Luks2ReencryptMode,
        /// The reencryption direction.
        direction: Luks2ReencryptDirection,
        /// The key size.
        key_size: String,
        /// The priority of the keyslot.
        priority: Option<Luks2KeyslotPriority>,
        /// Anti-forensic settings.
        af: Luks2Af,
        /// The data area.
        area: Luks2Area,
        /// KDF settings.
        kdf: Luks2Kdf,
    },
}

impl Luks2Keyslot {
    /// Returns a reference to the data area settings for this keyslot.
    pub fn area(&self) -> &Luks2Area {
        match self {
            Luks2Keyslot::Luks2 { area, .. } => area,
            Luks2Keyslot::Reencrypt { area, .. } => area,
        }
    }

    /// Validates the keyslot settings according to the LUKS2 specification.
    ///
    /// # Errors
    ///
    /// Returns an error string if the keyslot settings are invalid.
    pub fn validate(&self) -> Result<(), String> {
        match self {
            Luks2Keyslot::Luks2 { area, af, .. } => {
                if !matches!(area, Luks2Area::Raw { .. }) {
                    return Err("LUKS2 keyslot must have area type 'raw'".to_string());
                }
                if af.stripes != LUKS1_AF_STRIPES {
                    return Err(format!("AF stripes must be {}", LUKS1_AF_STRIPES));
                }
            }
            Luks2Keyslot::Reencrypt {
                area, key_size, af, ..
            } => {
                if matches!(area, Luks2Area::Raw { .. }) {
                    return Err("Reencrypt keyslot cannot have area type 'raw'".to_string());
                }
                if key_size != "1" {
                    return Err("Reencrypt keyslot must have key_size 1".to_string());
                }
                if af.stripes != LUKS1_AF_STRIPES {
                    return Err(format!("AF stripes must be {}", LUKS1_AF_STRIPES));
                }
            }
        }
        Ok(())
    }
}

/// A LUKS2 token, used to store additional metadata or references to external keys.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Luks2Token {
    /// A standard Linux kernel keyring token.
    #[serde(rename = "luks2-keyring")]
    Keyring {
        /// The IDs of the keyslots associated with this token.
        keyslots: Vec<String>,
        /// The description of the key in the keyring.
        key_description: String,
    },
    /// A `luks-rs` specific keyring token.
    #[serde(rename = "luks-rs-keyring")]
    LuksRsKeyring {
        /// The IDs of the keyslots associated with this token.
        keyslots: Vec<String>,
        /// The description of the key in the keyring.
        key_description: String,
    },
}

/// The size of a LUKS2 segment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Luks2SegmentSize {
    /// A fixed size in bytes.
    U64(u64),
    /// A dynamic size that occupies all remaining space on the device.
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

/// A LUKS2 segment, representing a range of data on the device.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Luks2Segment {
    /// A cryptographic segment.
    Crypt {
        /// The offset of the segment in bytes.
        offset: Luks2U64,
        /// The IV tweak for the segment.
        iv_tweak: Luks2U64,
        /// The size of the segment.
        size: Luks2SegmentSize,
        /// The encryption algorithm used for this segment.
        encryption: String,
        /// The sector size in bytes.
        sector_size: u32,
    },
}

/// A LUKS2 digest, used to verify the volume key.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Luks2Digest {
    /// A PBKDF2-based digest.
    Pbkdf2 {
        /// The IDs of the keyslots associated with this digest.
        keyslots: Vec<String>,
        /// The IDs of the segments associated with this digest.
        segments: Vec<String>,
        /// The hash algorithm used.
        hash: Luks2HashAlg,
        /// The number of iterations.
        iterations: u32,
        /// The base64-encoded salt.
        salt: String,
        /// The base64-encoded expected digest.
        digest: String,
    },
}

/// Global configuration for a LUKS2 device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Luks2Config {
    /// The size of the JSON area in bytes.
    pub json_size: Luks2U64,
    /// The size of the keyslots area in bytes.
    pub keyslots_size: Luks2U64,
    /// Any global flags set on the device.
    pub flags: Option<Vec<String>>,
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

/// The complete LUKS2 metadata, typically stored in the JSON area of the header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Luks2Metadata {
    /// A map of keyslot IDs to their settings.
    #[serde(deserialize_with = "deserialize_and_validate_keyslots")]
    pub keyslots: HashMap<String, Luks2Keyslot>,
    /// A map of token IDs to their settings.
    pub tokens: HashMap<String, Luks2Token>,
    /// A map of segment IDs to their settings.
    pub segments: HashMap<String, Luks2Segment>,
    /// A map of digest IDs to their settings.
    pub digests: HashMap<String, Luks2Digest>,
    /// Global device configuration.
    pub config: Luks2Config,
}

/// A LUKS device UUID.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct LuksDeviceUuid(String);

impl LuksDeviceUuid {
    /// Returns the UUID as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for LuksDeviceUuid {
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
        Ok(LuksDeviceUuid(s.to_string()))
    }
}

impl fmt::Display for LuksDeviceUuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl PartialEq<&str> for LuksDeviceUuid {
    fn eq(&self, other: &&str) -> bool {
        &self.0 == *other
    }
}

/// The primary binary header for LUKS2.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Luks2Header {
    /// The LUKS version (should be 2).
    pub version: u16,
    /// The total size of the header, including the binary part and the JSON area.
    pub hdr_size: u64,
    /// The sequence ID, incremented on each header update.
    pub seqid: u64,
    /// An optional label for the device.
    pub label: String,
    /// The hash algorithm used for calculating the header checksum.
    pub checksum_alg: Luks2HashAlg,
    /// The salt used for the header.
    #[serde(with = "serde_arrays")]
    pub salt: [u8; LUKS2_SALT_SIZE],
    /// The UUID of the device.
    pub uuid: LuksDeviceUuid,
    /// An optional subsystem label for the device.
    pub subsystem: String,
    /// The offset of this header in bytes from the start of the device.
    pub hdr_offset: u64,
    /// The header checksum.
    #[serde(with = "serde_arrays")]
    pub checksum: [u8; LUKS2_CHECKSUM_SIZE],
    /// The associated JSON metadata.
    pub metadata: Luks2Metadata,
}

mod serde_arrays {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(bytes: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        bytes.as_slice().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let v: Vec<u8> = Vec::deserialize(deserializer)?;
        v.try_into()
            .map_err(|_| serde::de::Error::custom("expected array of length 64"))
    }
}

impl Luks2Header {
    /// Returns the number of configured keyslots.
    pub fn num_keyslots(&self) -> usize {
        self.metadata.keyslots.len()
    }

    /// Writes the header and its metadata to a writer.
    pub fn to_writer<W: Write + Seek>(&self, mut writer: W) -> Result<(), LuksError> {
        // Serialize JSON metadata
        let json_str = serde_json::to_string(&self.metadata)?;
        let json_bytes = json_str.as_bytes();
        let json_size = json_bytes.len() as u64;

        // Calculate binary header size (fixed at 4096)
        let binary_header_size = LUKS2_BINARY_HEADER_SIZE as u64;

        // Prepare binary header buffer
        let mut binary_header = vec![0u8; LUKS2_BINARY_HEADER_SIZE];
        let mut cursor = std::io::Cursor::new(&mut binary_header);

        // Write magic
        cursor.write_all(&LUKS_MAGIC)?;

        // Write version
        cursor.write_u16::<BigEndian>(self.version)?;

        // Write hdr_size (binary_header_size + JSON size)
        cursor.write_u64::<BigEndian>(binary_header_size + json_size)?;

        // Write seqid
        cursor.write_u64::<BigEndian>(self.seqid)?;

        // Write label (48 bytes)
        let mut label_buf = [0u8; LUKS2_LABEL_SIZE];
        let label_bytes = self.label.as_bytes();
        let label_len = std::cmp::min(label_bytes.len(), LUKS2_LABEL_SIZE);
        label_buf[..label_len].copy_from_slice(&label_bytes[..label_len]);
        cursor.write_all(&label_buf)?;

        // Write checksum algorithm (32 bytes)
        cursor.write_all(&self.checksum_alg.to_bytes())?;

        // Write salt (64 bytes)
        cursor.write_all(&self.salt)?;

        // Write uuid (40 bytes)
        let mut uuid_buf = [0u8; LUKS2_UUID_SIZE];
        let uuid_bytes = self.uuid.as_str().as_bytes();
        let uuid_len = std::cmp::min(uuid_bytes.len(), LUKS2_UUID_SIZE);
        uuid_buf[..uuid_len].copy_from_slice(&uuid_bytes[..uuid_len]);
        cursor.write_all(&uuid_buf)?;

        // Write subsystem (48 bytes)
        let mut subsystem_buf = [0u8; LUKS2_SUBSYSTEM_SIZE];
        let subsystem_bytes = self.subsystem.as_bytes();
        let subsystem_len = std::cmp::min(subsystem_bytes.len(), LUKS2_SUBSYSTEM_SIZE);
        subsystem_buf[..subsystem_len].copy_from_slice(&subsystem_bytes[..subsystem_len]);
        cursor.write_all(&subsystem_buf)?;

        // Write hdr_offset
        cursor.write_u64::<BigEndian>(self.hdr_offset)?;

        // Calculate checksum
        if self.checksum_alg == Luks2HashAlg::Sha256 {
            let mut hasher = Sha256::new();
            // The checksum is calculated with the checksum field zeroed out
            // binary_header already has it as zeroed out because it was initialized with vec![0u8; LUKS2_BINARY_HEADER_SIZE]
            hasher.update(&binary_header);
            hasher.update(json_bytes);
            let calculated = hasher.finalize();

            // Store checksum in the buffer
            binary_header[LUKS2_CHECKSUM_OFFSET..LUKS2_CHECKSUM_OFFSET + SHA256_DIGEST_SIZE]
                .copy_from_slice(calculated.as_slice());
        } else {
            return Err(LuksError::UnsupportedChecksumAlg(self.checksum_alg.to_string()));
        }

        // Write binary header to writer
        writer.seek(std::io::SeekFrom::Start(self.hdr_offset))?;
        writer.write_all(&binary_header)?;

        // Write JSON metadata
        writer.write_all(json_bytes)?;

        Ok(())
    }
}

/// A LUKS header, either version 1 or 2.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LuksHeader {
    /// A LUKS1 header. Currently only used as a placeholder.
    V1,
    /// A LUKS2 header.
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

    /// Writes the header to a writer.
    pub fn to_writer<W: Write + Seek>(&self, writer: W) -> Result<(), LuksError> {
        match self {
            LuksHeader::V1 => Err(LuksError::UnsupportedVersion(1)),
            LuksHeader::V2(h) => h.to_writer(writer),
        }
    }

    /// Opens a LUKS device from a reader.
    ///
    /// This reads the header and all keyslot data areas from the reader.
    #[cfg(feature = "_open")]
    pub fn open<R: Read + Seek>(mut reader: R) -> Result<LuksDevice, LuksError> {
        let header = Self::from_reader(&mut reader)?;
        let mut keyslots = HashMap::new();

        match &header {
            LuksHeader::V1 => return Err(LuksError::UnsupportedVersion(1)),
            LuksHeader::V2(h) => {
                for (id, slot) in &h.metadata.keyslots {
                    let area = slot.area();
                    let mut data = vec![0u8; area.size() as usize];
                    reader.seek(SeekFrom::Start(area.offset()))?;
                    reader.read_exact(&mut data)?;
                    keyslots.insert(id.clone(), data);
                }
            }
        }

        Ok(LuksDevice {
            header,
            keyslots,
            unlocked_key: None,
        })
    }
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

impl LuksHeader {
    /// Reads a LUKS header from a reader.
    ///
    /// This only reads the header metadata, not the keyslot data areas.
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

                let mut checksum_alg_buf = [0u8; LUKS2_CHECKSUM_ALG_ID_LEN];
                cursor.read_exact(&mut checksum_alg_buf)?;
                let checksum_alg = Luks2HashAlg::from_str(&String::from_utf8_lossy(&checksum_alg_buf))?;

                let mut salt = [0u8; LUKS2_SALT_SIZE];
                cursor.read_exact(&mut salt)?;

                let mut uuid_buf = [0u8; LUKS2_UUID_SIZE];
                cursor.read_exact(&mut uuid_buf)?;
                let uuid = LuksDeviceUuid::from_str(&String::from_utf8_lossy(&uuid_buf))?;

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
                if checksum_alg == Luks2HashAlg::Sha256 {
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
                    return Err(LuksError::UnsupportedChecksumAlg(checksum_alg.to_string()));
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
        let json_data = format!(
            r#"{{
            "keyslots": {{}},
            "tokens": {{}},
            "segments": {{}},
            "digests": {{}},
            "config": {{
                "json_size": "{}",
                "keyslots_size": "{}"
            }}
        }}"#,
            LUKS2_DEFAULT_JSON_SIZE, LUKS2_DEFAULT_KEYSLOTS_SIZE
        );
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

            cursor.write_all(&Luks2HashAlg::Sha256.to_bytes()).unwrap();

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

    #[test]
    #[cfg(feature = "_open")]
    fn test_device_roundtrip() {
        use aes::cipher::KeyInit;
        use base64::Engine;
        use rand::Rng;
        use xts_mode::{Xts128, get_tweak_default};
        let mut rng = rand::rng();

        // 1. Setup metadata
        let mut salt = [0u8; LUKS2_SALT_SIZE];
        rng.fill(&mut salt);

        let volume_key_size = AES128_KEY_SIZE * 2;
        let volume_key = vec![0x42u8; volume_key_size];
        let passphrase = "correct horse battery staple";
        let unlock_key = UnlockKey::from(passphrase);

        // Keyslot 0
        let mut keyslot_salt = [0u8; 32];
        rng.fill(&mut keyslot_salt);
        let keyslot_salt_b64 = base64::engine::general_purpose::STANDARD.encode(keyslot_salt);

        let kdf = Luks2Kdf::Pbkdf2 {
            hash: Luks2HashAlg::Sha256,
            iterations: 1000,
            salt: keyslot_salt_b64,
        };

        let keyslot_key = kdf.derive_key(&unlock_key, &salt, volume_key_size).unwrap();

        // AF split the volume key
        let mut random_stripes = vec![0u8; volume_key_size * (LUKS1_AF_STRIPES - 1) as usize];
        rng.fill(&mut random_stripes[..]);
        let encrypted_keyslot_data = crate::af::split(
            &volume_key,
            &Luks2HashAlg::Sha256,
            LUKS1_AF_STRIPES,
            volume_key_size,
            random_stripes,
        )
        .unwrap();

        // Encrypt the AF stripes with the keyslot key
        let mut encrypted_data = encrypted_keyslot_data.clone();
        let cipher_1 = aes::Aes128::new_from_slice(&keyslot_key[0..AES128_KEY_SIZE]).unwrap();
        let cipher_2 = aes::Aes128::new_from_slice(&keyslot_key[AES128_KEY_SIZE..AES128_KEY_SIZE * 2]).unwrap();
        let xts = Xts128::new(cipher_1, cipher_2);
        for (i, chunk) in encrypted_data.chunks_mut(SECTOR_SIZE).enumerate() {
            xts.encrypt_area(chunk, SECTOR_SIZE, (i as u64).into(), |t| get_tweak_default(t));
        }

        let keyslot = Luks2Keyslot::Luks2 {
            key_size: Luks2KeySize::Size32,
            priority: Some(Luks2KeyslotPriority::Normal),
            af: Luks2Af {
                af_type: Luks2AfType::Luks1,
                stripes: LUKS1_AF_STRIPES,
                hash: Luks2HashAlg::Sha256,
            },
            area: Luks2Area::Raw {
                encryption: Luks2AreaEncryption::AesXtsPlain64,
                key_size: Luks2KeySize::Size32,
                offset: Luks2U64(32768),
                size: Luks2U64(encrypted_data.len() as u64),
            },
            kdf,
        };

        // Digest
        let mut digest_salt = [0u8; 32];
        rng.fill(&mut digest_salt);
        let digest_salt_b64 = base64::engine::general_purpose::STANDARD.encode(digest_salt);

        let mut expected_digest = vec![0u8; 32];
        pbkdf2::pbkdf2::<hmac::Hmac<Sha256>>(&volume_key, &digest_salt, 1000, &mut expected_digest).unwrap();
        let expected_digest_b64 = base64::engine::general_purpose::STANDARD.encode(expected_digest);

        let digest = Luks2Digest::Pbkdf2 {
            keyslots: vec!["0".to_string()],
            segments: vec!["0".to_string()],
            hash: Luks2HashAlg::Sha256,
            iterations: 1000,
            salt: digest_salt_b64,
            digest: expected_digest_b64,
        };

        let segment = Luks2Segment::Crypt {
            offset: Luks2U64(16777216), // 16MB offset
            iv_tweak: Luks2U64(0),
            size: Luks2SegmentSize::Dynamic,
            encryption: "aes-xts-plain64".to_string(),
            sector_size: 512,
        };

        let mut keyslots = HashMap::new();
        keyslots.insert("0".to_string(), keyslot);

        let mut digests = HashMap::new();
        digests.insert("0".to_string(), digest);

        let mut segments = HashMap::new();
        segments.insert("0".to_string(), segment);

        let header = Luks2Header {
            version: 2,
            hdr_size: 0, // Will be recalculated
            seqid: 1,
            label: "test".to_string(),
            checksum_alg: Luks2HashAlg::Sha256,
            salt,
            uuid: LuksDeviceUuid::from_str("00000000-0000-0000-0000-000000000000").unwrap(),
            subsystem: "test".to_string(),
            hdr_offset: 0,
            checksum: [0u8; LUKS2_CHECKSUM_SIZE],
            metadata: Luks2Metadata {
                keyslots,
                tokens: HashMap::new(),
                segments,
                digests,
                config: Luks2Config {
                    json_size: Luks2U64(LUKS2_DEFAULT_JSON_SIZE),
                    keyslots_size: Luks2U64(LUKS2_DEFAULT_KEYSLOTS_SIZE),
                    flags: None,
                },
            },
        };

        let mut captured_keyslots = HashMap::new();
        captured_keyslots.insert("0".to_string(), encrypted_data);

        let device = LuksDevice {
            header: LuksHeader::V2(header),
            keyslots: captured_keyslots,
            unlocked_key: None,
        };

        // 2. Write to buffer
        let mut buf = Cursor::new(Vec::new());
        device.to_writer(&mut buf).expect("to_writer failed");

        // 3. Read back and verify
        buf.set_position(0);
        let mut read_device = LuksHeader::open(&mut buf).expect("open failed");

        let key = UnlockKey::from(passphrase);
        read_device.unlock("0", &key).expect("unlock failed");
        assert!(read_device.verify("0").expect("verify failed"));
    }

    #[test]
    #[cfg(feature = "_open")]
    fn test_change_passphrase() {
        use aes::cipher::KeyInit;
        use base64::Engine;
        use rand::Rng;
        use xts_mode::{Xts128, get_tweak_default};
        let mut rng = rand::rng();

        const TEST_ITERATIONS: u32 = 1000;

        // 1. Setup metadata
        let mut salt = [0u8; LUKS2_SALT_SIZE];
        rng.fill(&mut salt);

        let volume_key_size = AES128_KEY_SIZE * 2;
        let volume_key = vec![0x42u8; volume_key_size];
        let old_passphrase = "old passphrase";
        let new_passphrase = "new passphrase";
        let old_key = UnlockKey::from(old_passphrase);
        let new_key = UnlockKey::from(new_passphrase);

        // Keyslot 0
        let mut keyslot_salt = [0u8; KDF_SALT_SIZE];
        rng.fill(&mut keyslot_salt);
        let keyslot_salt_b64 = base64::engine::general_purpose::STANDARD.encode(keyslot_salt);

        let kdf = Luks2Kdf::Pbkdf2 {
            hash: Luks2HashAlg::Sha256,
            iterations: TEST_ITERATIONS,
            salt: keyslot_salt_b64,
        };

        let keyslot_key = kdf.derive_key(&old_key, &salt, volume_key_size).unwrap();

        // AF split the volume key
        let mut random_stripes = vec![0u8; volume_key_size * (LUKS1_AF_STRIPES - 1) as usize];
        rng.fill(&mut random_stripes[..]);
        let encrypted_keyslot_data = crate::af::split(
            &volume_key,
            &Luks2HashAlg::Sha256,
            LUKS1_AF_STRIPES,
            volume_key_size,
            random_stripes,
        )
        .unwrap();

        // Encrypt the AF stripes with the keyslot key
        let mut encrypted_data = encrypted_keyslot_data.clone();
        let cipher_1 = aes::Aes128::new_from_slice(&keyslot_key[0..AES128_KEY_SIZE]).unwrap();
        let cipher_2 = aes::Aes128::new_from_slice(&keyslot_key[AES128_KEY_SIZE..AES128_KEY_SIZE * 2]).unwrap();
        let xts = Xts128::new(cipher_1, cipher_2);
        for (i, chunk) in encrypted_data.chunks_mut(SECTOR_SIZE).enumerate() {
            xts.encrypt_area(chunk, SECTOR_SIZE, (i as u64).into(), |t| get_tweak_default(t));
        }

        let keyslot = Luks2Keyslot::Luks2 {
            key_size: Luks2KeySize::Size32,
            priority: Some(Luks2KeyslotPriority::Normal),
            af: Luks2Af {
                af_type: Luks2AfType::Luks1,
                stripes: LUKS1_AF_STRIPES,
                hash: Luks2HashAlg::Sha256,
            },
            area: Luks2Area::Raw {
                encryption: Luks2AreaEncryption::AesXtsPlain64,
                key_size: Luks2KeySize::Size32,
                offset: Luks2U64(32768),
                size: Luks2U64(encrypted_data.len() as u64),
            },
            kdf,
        };

        // Digest
        let mut digest_salt = [0u8; KDF_SALT_SIZE];
        rng.fill(&mut digest_salt);
        let digest_salt_b64 = base64::engine::general_purpose::STANDARD.encode(digest_salt);

        let mut expected_digest = vec![0u8; SHA256_DIGEST_SIZE];
        pbkdf2::pbkdf2::<hmac::Hmac<Sha256>>(&volume_key, &digest_salt, TEST_ITERATIONS, &mut expected_digest)
            .unwrap();
        let expected_digest_b64 = base64::engine::general_purpose::STANDARD.encode(expected_digest);

        let digest = Luks2Digest::Pbkdf2 {
            keyslots: vec!["0".to_string()],
            segments: vec!["0".to_string()],
            hash: Luks2HashAlg::Sha256,
            iterations: TEST_ITERATIONS,
            salt: digest_salt_b64,
            digest: expected_digest_b64,
        };

        let mut keyslots = HashMap::new();
        keyslots.insert("0".to_string(), keyslot);

        let mut digests = HashMap::new();
        digests.insert("0".to_string(), digest);

        let header = Luks2Header {
            version: 2,
            hdr_size: 0,
            seqid: 1,
            label: "test".to_string(),
            checksum_alg: Luks2HashAlg::Sha256,
            salt,
            uuid: LuksDeviceUuid::from_str("00000000-0000-0000-0000-000000000000").unwrap(),
            subsystem: "test".to_string(),
            hdr_offset: 0,
            checksum: [0u8; LUKS2_CHECKSUM_SIZE],
            metadata: Luks2Metadata {
                keyslots,
                tokens: HashMap::new(),
                segments: HashMap::new(),
                digests,
                config: Luks2Config {
                    json_size: Luks2U64(LUKS2_DEFAULT_JSON_SIZE),
                    keyslots_size: Luks2U64(LUKS2_DEFAULT_KEYSLOTS_SIZE),
                    flags: None,
                },
            },
        };

        let mut captured_keyslots = HashMap::new();
        captured_keyslots.insert("0".to_string(), encrypted_data);

        let mut device = LuksDevice {
            header: LuksHeader::V2(header),
            keyslots: captured_keyslots,
            unlocked_key: None,
        };

        // 2. Change passphrase
        device
            .change_passphrase("0", &old_key, &new_key)
            .expect("change_passphrase failed");

        // 3. Verify
        device.unlock("0", &new_key).expect("unlock failed");
        assert!(device.verify("0").expect("verify with new passphrase failed"));

        device
            .unlock("0", &old_key)
            .expect_err("unlock with old passphrase should fail");

        // 4. Verify volume key is still the same
        let derived_volume_key = device
            .get_volume_key("0", &new_key)
            .expect("get_volume_key failed");
        assert_eq!(volume_key, derived_volume_key.expose_bytes());
    }

    #[test]
    #[cfg(feature = "_open")]
    fn test_unlock() {
        use aes::cipher::KeyInit;
        use base64::Engine;
        use rand::Rng;
        use xts_mode::{Xts128, get_tweak_default};
        let mut rng = rand::rng();

        // 1. Setup metadata
        let mut salt = [0u8; LUKS2_SALT_SIZE];
        rng.fill(&mut salt);

        let volume_key_size = AES128_KEY_SIZE * 2;
        let volume_key = vec![0x42u8; volume_key_size];
        let passphrase = "correct horse battery staple";
        let key = UnlockKey::from(passphrase);

        // Keyslot 0
        let mut keyslot_salt = [0u8; KDF_SALT_SIZE];
        rng.fill(&mut keyslot_salt);
        let keyslot_salt_b64 = base64::engine::general_purpose::STANDARD.encode(keyslot_salt);

        let kdf = Luks2Kdf::Pbkdf2 {
            hash: Luks2HashAlg::Sha256,
            iterations: 1000,
            salt: keyslot_salt_b64,
        };

        let keyslot_key = kdf.derive_key(&key, &salt, volume_key_size).unwrap();

        // AF split the volume key
        let mut random_stripes = vec![0u8; volume_key_size * (LUKS1_AF_STRIPES - 1) as usize];
        rng.fill(&mut random_stripes[..]);
        let encrypted_keyslot_data = crate::af::split(
            &volume_key,
            &Luks2HashAlg::Sha256,
            LUKS1_AF_STRIPES,
            volume_key_size,
            random_stripes,
        )
        .unwrap();

        // Encrypt the AF stripes with the keyslot key
        let mut encrypted_data = encrypted_keyslot_data.clone();
        let cipher_1 = aes::Aes128::new_from_slice(&keyslot_key[0..AES128_KEY_SIZE]).unwrap();
        let cipher_2 = aes::Aes128::new_from_slice(&keyslot_key[AES128_KEY_SIZE..AES128_KEY_SIZE * 2]).unwrap();
        let xts = Xts128::new(cipher_1, cipher_2);
        for (i, chunk) in encrypted_data.chunks_mut(SECTOR_SIZE).enumerate() {
            xts.encrypt_area(chunk, SECTOR_SIZE, (i as u64).into(), |t| get_tweak_default(t));
        }

        let keyslot = Luks2Keyslot::Luks2 {
            key_size: Luks2KeySize::Size32,
            priority: Some(Luks2KeyslotPriority::Normal),
            af: Luks2Af {
                af_type: Luks2AfType::Luks1,
                stripes: LUKS1_AF_STRIPES,
                hash: Luks2HashAlg::Sha256,
            },
            area: Luks2Area::Raw {
                encryption: Luks2AreaEncryption::AesXtsPlain64,
                key_size: Luks2KeySize::Size32,
                offset: Luks2U64(32768),
                size: Luks2U64(encrypted_data.len() as u64),
            },
            kdf,
        };

        // Digest
        let mut digest_salt = [0u8; KDF_SALT_SIZE];
        rng.fill(&mut digest_salt);
        let digest_salt_b64 = base64::engine::general_purpose::STANDARD.encode(digest_salt);

        let mut expected_digest = vec![0u8; SHA256_DIGEST_SIZE];
        pbkdf2::pbkdf2::<hmac::Hmac<Sha256>>(&volume_key, &digest_salt, 1000, &mut expected_digest).unwrap();
        let expected_digest_b64 = base64::engine::general_purpose::STANDARD.encode(expected_digest);

        let digest = Luks2Digest::Pbkdf2 {
            keyslots: vec!["0".to_string()],
            segments: vec!["0".to_string()],
            hash: Luks2HashAlg::Sha256,
            iterations: 1000,
            salt: digest_salt_b64,
            digest: expected_digest_b64,
        };

        let mut keyslots = HashMap::new();
        keyslots.insert("0".to_string(), keyslot);

        let mut digests = HashMap::new();
        digests.insert("0".to_string(), digest);

        let header = Luks2Header {
            version: 2,
            hdr_size: 0,
            seqid: 1,
            label: "test".to_string(),
            checksum_alg: Luks2HashAlg::Sha256,
            salt,
            uuid: LuksDeviceUuid::from_str("00000000-0000-0000-0000-000000000000").unwrap(),
            subsystem: "test".to_string(),
            hdr_offset: 0,
            checksum: [0u8; LUKS2_CHECKSUM_SIZE],
            metadata: Luks2Metadata {
                keyslots,
                tokens: HashMap::new(),
                segments: HashMap::new(),
                digests,
                config: Luks2Config {
                    json_size: Luks2U64(LUKS2_DEFAULT_JSON_SIZE),
                    keyslots_size: Luks2U64(LUKS2_DEFAULT_KEYSLOTS_SIZE),
                    flags: None,
                },
            },
        };

        let mut captured_keyslots = HashMap::new();
        captured_keyslots.insert("0".to_string(), encrypted_data);

        let mut device = LuksDevice {
            header: LuksHeader::V2(header),
            keyslots: captured_keyslots,
            unlocked_key: None,
        };

        // 2. Unlock
        device.unlock("0", &key).expect("unlock failed");

        // 3. Verify
        assert!(device.unlocked_key.is_some());
        assert_eq!(volume_key, device.unlocked_key.as_ref().unwrap().expose_bytes());
    }

    #[test]
    fn test_header_roundtrip() {
        let mut salt = [0u8; LUKS2_SALT_SIZE];
        salt[0..4].copy_from_slice(b"salt");
        let header = Luks2Header {
            version: 2,
            hdr_size: 16384, // Will be recalculated in to_writer anyway
            seqid: 1,
            label: "test".to_string(),
            checksum_alg: Luks2HashAlg::Sha256,
            salt,
            uuid: LuksDeviceUuid::from_str("00000000-0000-0000-0000-000000000000").unwrap(),
            subsystem: "test".to_string(),
            hdr_offset: 0,
            checksum: [0u8; LUKS2_CHECKSUM_SIZE], // Will be calculated in to_writer
            metadata: Luks2Metadata {
                keyslots: HashMap::new(),
                tokens: HashMap::new(),
                segments: HashMap::new(),
                digests: HashMap::new(),
                config: Luks2Config {
                    json_size: Luks2U64(LUKS2_DEFAULT_JSON_SIZE),
                    keyslots_size: Luks2U64(LUKS2_DEFAULT_KEYSLOTS_SIZE),
                    flags: None,
                },
            },
        };

        let mut buf = Cursor::new(Vec::new());
        header.to_writer(&mut buf).expect("to_writer failed");

        buf.set_position(0);
        let read_header = LuksHeader::from_reader(&mut buf).expect("from_reader failed");

        if let LuksHeader::V2(h) = read_header {
            assert_eq!(h.version, header.version);
            assert_eq!(h.label, header.label);
            assert_eq!(h.uuid, header.uuid);
            assert_eq!(h.subsystem, header.subsystem);
            assert_eq!(h.checksum_alg, header.checksum_alg);
            assert_eq!(h.salt, header.salt);
            assert_eq!(h.hdr_offset, header.hdr_offset);
            // hdr_size is recalculated, so check if it's correct
            assert!(h.hdr_size >= LUKS2_BINARY_HEADER_SIZE as u64);
        } else {
            panic!("Expected LUKS2 header");
        }
    }

    #[test]
    fn test_num_keyslots() {
        let mut binary_header = vec![0u8; LUKS2_BINARY_HEADER_SIZE];
        let json_data = format!(
            r#"{{
            "keyslots": {{
                "0": {{
                    "type": "luks2",
                    "key_size": 64,
                    "priority": 1,
                    "af": {{ "type": "luks1", "stripes": 4000, "hash": "{}" }},
                    "area": {{ "type": "raw", "encryption": "aes-xts-plain64", "key_size": 64, "offset": "32768", "size": "131072" }},
                    "kdf": {{ "type": "argon2i", "time": 4, "memory": 235980, "cpus": 2, "salt": "z6vz4xK7cjan92rDA5JF8O6Jk2HouV0O8DMB6GlztVk=" }}
                }},
                "1": {{
                    "type": "luks2",
                    "key_size": 64,
                    "priority": 1,
                    "af": {{ "type": "luks1", "stripes": 4000, "hash": "{}" }},
                    "area": {{ "type": "raw", "encryption": "aes-xts-plain64", "key_size": 64, "offset": "163840", "size": "131072" }},
                    "kdf": {{ "type": "pbkdf2", "hash": "sha256", "iterations": 1774240, "salt": "vWcwY3rx2fKpXW2Q6oSCNf8j5bvdJyEzB6BNXECGDsI=" }}
                }}
            }},
            "tokens": {{}},
            "segments": {{}},
            "digests": {{}},
            "config": {{
                "json_size": "{}",
                "keyslots_size": "{}"
            }}
        }}"#,
            HASH_SHA256, HASH_SHA256, LUKS2_DEFAULT_JSON_SIZE, LUKS2_DEFAULT_KEYSLOTS_SIZE
        );
        let hdr_size = LUKS2_BINARY_HEADER_SIZE as u64 + json_data.len() as u64;

        {
            let mut cursor = Cursor::new(&mut binary_header);
            cursor.write_all(&LUKS_MAGIC).unwrap();
            cursor.write_u16::<BigEndian>(2).unwrap();
            cursor.write_u64::<BigEndian>(hdr_size).unwrap();
            cursor.write_u64::<BigEndian>(1).unwrap();

            let label = [0u8; LUKS2_LABEL_SIZE];
            cursor.write_all(&label).unwrap();

            cursor.write_all(&Luks2HashAlg::Sha256.to_bytes()).unwrap();

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
        assert!(LuksDeviceUuid::from_str("550e8400-e29b-41d4-a716-446655440000").is_ok());
        assert!(LuksDeviceUuid::from_str("abcd").is_ok());
        assert!(LuksDeviceUuid::from_str("").is_err());
        assert!(LuksDeviceUuid::from_str("invalid-char!").is_err());
        assert!(LuksDeviceUuid::from_str(&"a".repeat(40)).is_err());
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
    fn test_parse_luks_rs_keyring_token() {
        let json_data = r#"{
            "keyslots": {},
            "tokens": {
                "0": {
                    "type": "luks-rs-keyring",
                    "keyslots": ["0"],
                    "key_description": "MyLuksRsKey"
                }
            },
            "segments": {},
            "digests": {},
            "config": { "json_size": "12288", "keyslots_size": "4161536" }
        }"#;
        let metadata: Luks2Metadata = serde_json::from_str(json_data).unwrap();
        let token = metadata.tokens.get("0").unwrap();
        if let Luks2Token::LuksRsKeyring {
            keyslots,
            key_description,
        } = token
        {
            assert_eq!(keyslots, &vec!["0".to_string()]);
            assert_eq!(key_description, "MyLuksRsKey");
        } else {
            panic!("Expected LuksRsKeyring token");
        }
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

    #[test]
    #[cfg(feature = "_open")]
    fn test_is_luks_device() {
        let path = std::env::temp_dir().join("test_luks_magic");
        std::fs::write(&path, &LUKS_MAGIC).unwrap();
        assert!(is_luks_device(&path).unwrap());
        std::fs::remove_file(&path).unwrap();

        let path = std::env::temp_dir().join("test_not_luks_magic");
        std::fs::write(&path, b"NOTLUK").unwrap();
        assert!(!is_luks_device(&path).unwrap());
        std::fs::remove_file(&path).unwrap();

        let path = std::env::temp_dir().join("test_short_luks_magic");
        std::fs::write(&path, b"LUKS").unwrap();
        assert!(!is_luks_device(&path).unwrap());
        std::fs::remove_file(&path).unwrap();
    }
}
