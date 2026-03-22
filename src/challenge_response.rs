use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// The slot on the challenge-response device to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeResponseSlot {
    /// Slot 1
    Slot1,
    /// Slot 2
    Slot2,
}

impl From<ChallengeResponseSlot> for ::challenge_response::config::Slot {
    fn from(slot: ChallengeResponseSlot) -> Self {
        match slot {
            ChallengeResponseSlot::Slot1 => ::challenge_response::config::Slot::Slot1,
            ChallengeResponseSlot::Slot2 => ::challenge_response::config::Slot::Slot2,
        }
    }
}

impl From<::challenge_response::config::Slot> for ChallengeResponseSlot {
    fn from(slot: ::challenge_response::config::Slot) -> Self {
        match slot {
            ::challenge_response::config::Slot::Slot1 => ChallengeResponseSlot::Slot1,
            ::challenge_response::config::Slot::Slot2 => ChallengeResponseSlot::Slot2,
        }
    }
}

impl Serialize for ChallengeResponseSlot {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let s = match self {
            ChallengeResponseSlot::Slot1 => "1",
            ChallengeResponseSlot::Slot2 => "2",
        };
        serializer.serialize_str(s)
    }
}

impl<'de> Deserialize<'de> for ChallengeResponseSlot {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.as_str() {
            "1" => Ok(ChallengeResponseSlot::Slot1),
            "2" => Ok(ChallengeResponseSlot::Slot2),
            _ => Err(serde::de::Error::custom(format!("Invalid slot: {}", s))),
        }
    }
}
