use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;

use crate::af::{LUKS1_AF_STRIPES, Luks2Af};
use crate::hash::Luks2HashAlg;

/// A LUKS keyslot identifier.
///
/// In LUKS2, keyslot IDs are stored as strings in the JSON metadata.
/// This type provides a type-safe wrapper around the keyslot identifier.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct KeySlotId(String);

impl KeySlotId {
    /// Creates a new keyslot identifier from a string.
    pub fn new<S: Into<String>>(s: S) -> Self {
        KeySlotId(s.into())
    }
}

impl From<u32> for KeySlotId {
    fn from(n: u32) -> Self {
        KeySlotId(n.to_string())
    }
}

impl From<String> for KeySlotId {
    fn from(s: String) -> Self {
        KeySlotId(s)
    }
}

impl From<&str> for KeySlotId {
    fn from(s: &str) -> Self {
        KeySlotId(s.to_string())
    }
}

impl fmt::Display for KeySlotId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for KeySlotId {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(KeySlotId(s.to_string()))
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
        offset: crate::Luks2U64,
        /// The size of the area in bytes.
        size: crate::Luks2U64,
    },
    /// No data area.
    None {
        /// The offset of the area in bytes.
        offset: crate::Luks2U64,
        /// The size of the area in bytes.
        size: crate::Luks2U64,
    },
    /// A journal area.
    Journal {
        /// The offset of the area in bytes.
        offset: crate::Luks2U64,
        /// The size of the area in bytes.
        size: crate::Luks2U64,
    },
    /// A checksum area.
    Checksum {
        /// The offset of the area in bytes.
        offset: crate::Luks2U64,
        /// The size of the area in bytes.
        size: crate::Luks2U64,
        /// The hash algorithm used for the checksum.
        hash: Luks2HashAlg,
        /// The sector size in bytes.
        sector_size: u32,
    },
    /// A data shift area.
    Datashift {
        /// The offset of the area in bytes.
        offset: crate::Luks2U64,
        /// The size of the area in bytes.
        size: crate::Luks2U64,
        /// The shift size in bytes.
        shift_size: crate::Luks2U64,
    },
    /// A combined data shift and journal area.
    #[serde(rename = "datashift-journal")]
    DatashiftJournal {
        /// The offset of the area in bytes.
        offset: crate::Luks2U64,
        /// The size of the area in bytes.
        size: crate::Luks2U64,
        /// The shift size in bytes.
        shift_size: crate::Luks2U64,
    },
    /// A combined data shift and checksum area.
    #[serde(rename = "datashift-checksum")]
    DatashiftChecksum {
        /// The offset of the area in bytes.
        offset: crate::Luks2U64,
        /// The size of the area in bytes.
        size: crate::Luks2U64,
        /// The hash algorithm used for the checksum.
        hash: Luks2HashAlg,
        /// The sector size in bytes.
        sector_size: u32,
        /// The shift size in bytes.
        shift_size: crate::Luks2U64,
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
        kdf: crate::kdf::Luks2Kdf,
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
        kdf: crate::kdf::Luks2Kdf,
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

pub(crate) fn deserialize_and_validate_keyslots<'de, D>(
    deserializer: D,
) -> Result<HashMap<KeySlotId, Luks2Keyslot>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let keyslots: HashMap<KeySlotId, Luks2Keyslot> = HashMap::deserialize(deserializer)?;
    for (id, slot) in &keyslots {
        slot.validate()
            .map_err(|e| serde::de::Error::custom(format!("Validation failed for keyslot {}: {}", id, e)))?;
    }
    Ok(keyslots)
}
