use secrecy::{ExposeSecret, SecretBox};

/// A LUKS key used to unlock a device, typically provided as a passphrase or password.
///
/// This struct ensures that the sensitive material used to unlock the LUKS container
/// is protected while in memory and is automatically zeroed when no longer needed.
/// It intentionally does not implement `Debug` to prevent accidental exposure of
/// the unlock key in logs or error reports.
pub struct Key(SecretBox<Vec<u8>>);

impl Key {
    /// Creates a new LUKS unlock key from a passphrase.
    pub fn from_passphrase(passphrase: String) -> Self {
        Self(SecretBox::new(Box::new(passphrase.into_bytes())))
    }

    /// Unboxes the LUKS key, returning its raw bytes for use in cryptographic operations.
    pub fn expose_bytes(&self) -> &[u8] {
        self.0.expose_secret().as_slice()
    }
}

impl From<String> for Key {
    fn from(passphrase: String) -> Self {
        Self::from_passphrase(passphrase)
    }
}

impl From<&str> for Key {
    fn from(passphrase: &str) -> Self {
        Self::from_passphrase(passphrase.to_string())
    }
}
