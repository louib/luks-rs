use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

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
