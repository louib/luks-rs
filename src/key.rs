use secrecy::{ExposeSecret, SecretBox};

/// A LUKS key used to unlock a device, typically provided as a passphrase or password.
///
/// This struct ensures that the sensitive material used to unlock the LUKS container
/// is protected while in memory and is automatically zeroed when no longer needed.
/// It intentionally does not implement `Debug` to prevent accidental exposure of
/// the unlock key in logs or error reports.
pub struct UnlockKey(SecretBox<Vec<u8>>);

impl UnlockKey {
    /// Creates a new LUKS unlock key from a passphrase.
    pub fn from_passphrase(passphrase: String) -> Self {
        Self(SecretBox::new(Box::new(passphrase.into_bytes())))
    }

    /// Unboxes the LUKS key, returning its raw bytes for use in cryptographic operations.
    pub fn expose_bytes(&self) -> &[u8] {
        self.0.expose_secret().as_slice()
    }
}

impl From<String> for UnlockKey {
    fn from(passphrase: String) -> Self {
        Self::from_passphrase(passphrase)
    }
}

impl From<&str> for UnlockKey {
    fn from(passphrase: &str) -> Self {
        Self::from_passphrase(passphrase.to_string())
    }
}

/// A LUKS volume key used to encrypt and decrypt the actual data on the device.
///
/// This key is derived from an `UnlockKey` (passphrase) and a keyslot.
/// It is protected while in memory and is automatically zeroed when no longer needed.
pub struct VolumeKey(SecretBox<Vec<u8>>);

impl VolumeKey {
    /// Creates a new volume key from its raw bytes.
    ///
    /// Returns an error if the provided bytes length is not a valid LUKS volume key size.
    pub fn new(bytes: Vec<u8>) -> Result<Self, crate::LuksError> {
        if bytes.len() != crate::AES128_KEY_SIZE * 2 && bytes.len() != crate::AES256_KEY_SIZE * 2 {
            return Err(crate::LuksError::InvalidHeader(format!(
                "Invalid volume key size: expected {} or {}, got {}",
                crate::AES128_KEY_SIZE * 2,
                crate::AES256_KEY_SIZE * 2,
                bytes.len()
            )));
        }
        Ok(Self(SecretBox::new(Box::new(bytes))))
    }

    /// Unboxes the volume key, returning its raw bytes for use in cryptographic operations.
    pub fn expose_bytes(&self) -> &[u8] {
        self.0.expose_secret().as_slice()
    }
}
