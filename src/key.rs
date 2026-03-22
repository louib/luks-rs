use secrecy::{ExposeSecret, SecretBox};

#[cfg(feature = "_challenge_response")]
use crate::challenge_response::ChallengeResponseSlot;
#[cfg(feature = "_challenge_response")]
use crate::hash::SHA256_DIGEST_SIZE;
#[cfg(feature = "_challenge_response")]
use challenge_response::{
    ChallengeResponse,
    config::{Config, Mode},
};
#[cfg(feature = "_challenge_response")]
use hkdf::Hkdf;
#[cfg(feature = "_challenge_response")]
use sha2::Sha256;

#[cfg(feature = "_challenge_response")]
const HKDF_INFO: &[u8] = b"luks-rs challenge-response";

/// A LUKS key used to unlock a device, typically provided as a passphrase or password.
///
/// This struct ensures that the sensitive material used to unlock the LUKS container
/// is protected while in memory and is automatically zeroed when no longer needed.
/// It intentionally does not implement `Debug` to prevent accidental exposure of
/// the unlock key in logs or error reports.
pub struct UnlockKey {
    password: SecretBox<Vec<u8>>,
    #[cfg(feature = "_challenge_response")]
    challenge_response: Option<ChallengeResponseKey>,
}

#[cfg(feature = "_challenge_response")]
/// A LUKS key that uses a challenge-response mechanism.
pub enum ChallengeResponseKey {
    /// Use a hardware device (e.g., YubiKey) for challenge-response.
    Hardware {
        /// The serial number of the challenge-response device.
        serial: Option<u32>,
        /// The slot on the device to use.
        slot: ChallengeResponseSlot,
    },
    /// Use a software secret for challenge-response.
    ///
    /// This is useful for unit testing, simulation, or as a **recovery mechanism**.
    /// If a hardware token is lost, but the user has a secure backup of the
    /// HMAC-SHA1 secret (e.g., in a password manager), this variant allows
    /// unlocking the device by manually providing that secret.
    Software {
        /// The software secret used to perform HMAC-SHA1.
        secret: SecretBox<Vec<u8>>,
    },
}

impl UnlockKey {
    /// Creates a new LUKS unlock key from a passphrase.
    pub fn from_passphrase(passphrase: String) -> Self {
        Self {
            password: SecretBox::new(Box::new(passphrase.into_bytes())),
            #[cfg(feature = "_challenge_response")]
            challenge_response: None,
        }
    }

    #[cfg(feature = "_challenge_response")]
    /// Adds a hardware challenge-response key to the unlock key.
    pub fn with_challenge_response(mut self, serial: Option<u32>, slot: ChallengeResponseSlot) -> Self {
        self.challenge_response = Some(ChallengeResponseKey::Hardware { serial, slot });
        self
    }

    #[cfg(feature = "_challenge_response")]
    /// Adds a software challenge-response key to the unlock key (for testing).
    pub fn with_software_challenge_response(mut self, secret: Vec<u8>) -> Self {
        self.challenge_response = Some(ChallengeResponseKey::Software {
            secret: SecretBox::new(Box::new(secret)),
        });
        self
    }

    /// Unboxes the LUKS key, returning its raw bytes for use in cryptographic operations.
    pub fn expose_bytes(&self) -> &[u8] {
        self.password.expose_secret().as_slice()
    }

    #[cfg(feature = "_challenge_response")]
    /// Returns the challenge-response configuration for this key, if any.
    pub fn challenge_response(&self) -> Option<&ChallengeResponseKey> {
        self.challenge_response.as_ref()
    }

    /// Calculates the effective key material, potentially performing a challenge-response.
    ///
    /// If the `challenge_response` feature is enabled and a challenge-response key is configured,
    /// the final key is derived using HKDF-SHA256 with the password as input keying material (IKM)
    /// and the challenge response as salt.
    ///
    /// Otherwise, it returns the raw password bytes.
    pub fn calculate_effective_key(&self, challenge: &[u8]) -> Result<Vec<u8>, crate::LuksError> {
        #[cfg(feature = "_challenge_response")]
        {
            let cr_key = match &self.challenge_response {
                Some(y) => y,
                None => return Ok(self.password.expose_secret().to_vec()),
            };

            let response = match cr_key {
                ChallengeResponseKey::Hardware { serial, slot } => {
                    // 1. Challenge response from hardware
                    let mut cr = ChallengeResponse::new().map_err(|e| {
                        crate::LuksError::ChallengeResponse(format!(
                            "Failed to initialize challenge-response: {}",
                            e
                        ))
                    })?;

                    let device = match serial {
                        Some(s) => cr.find_device_from_serial(*s).map_err(|e| {
                            crate::LuksError::ChallengeResponse(format!(
                                "Failed to find device with serial {}: {}",
                                s, e
                            ))
                        })?,
                        None => cr.find_device().map_err(|e| {
                            crate::LuksError::ChallengeResponse(format!("Failed to find device: {}", e))
                        })?,
                    };

                    let config = Config::new_from(device)
                        .set_variable_size(true)
                        .set_mode(Mode::Sha1)
                        .set_slot((*slot).into());

                    cr.challenge_response_hmac(challenge, config)
                        .map_err(|e| {
                            crate::LuksError::ChallengeResponse(format!("Challenge-response failed: {}", e))
                        })?
                        .to_vec()
                }
                ChallengeResponseKey::Software { secret } => {
                    // Simulation of HMAC-SHA1 hardware response
                    use hmac::{Hmac, Mac};
                    use sha1::Sha1;
                    let mut mac = Hmac::<Sha1>::new_from_slice(secret.expose_secret())
                        .map_err(|e| crate::LuksError::ChallengeResponse(format!("Invalid HMAC key: {}", e)))?;
                    mac.update(challenge);
                    mac.finalize().into_bytes().to_vec()
                }
            };

            // 2. Use HKDF-SHA256 to combine password and response
            // We use the response as salt and password as IKM
            let hk = Hkdf::<Sha256>::new(Some(&response), self.password.expose_secret());
            let mut derived_key = [0u8; SHA256_DIGEST_SIZE];
            hk.expand(HKDF_INFO, &mut derived_key)
                .map_err(|e| crate::LuksError::ChallengeResponse(format!("HKDF expansion failed: {}", e)))?;

            Ok(derived_key.to_vec())
        }
        #[cfg(not(feature = "_challenge_response"))]
        {
            let _ = challenge;
            Ok(self.password.expose_secret().to_vec())
        }
    }
}

#[cfg(all(test, feature = "_challenge_response"))]
mod tests {
    use super::*;

    #[cfg(feature = "_challenge_response")]
    #[test]
    fn test_software_challenge_response() {
        let password = "test-password".to_string();
        let hardware_secret = vec![0x01, 0x02, 0x03, 0x04];
        let challenge = vec![0xAA, 0xBB, 0xCC, 0xDD];

        let key = UnlockKey::from_passphrase(password.clone())
            .with_software_challenge_response(hardware_secret.clone());

        let effective_key = key.calculate_effective_key(&challenge).unwrap();

        // Manual calculation for verification
        use hmac::{Hmac, Mac};
        use sha1::Sha1;
        let mut mac = Hmac::<Sha1>::new_from_slice(&hardware_secret).unwrap();
        mac.update(&challenge);
        let expected_response = mac.finalize().into_bytes();

        let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(&expected_response), password.as_bytes());
        let mut expected_derived_key = [0u8; SHA256_DIGEST_SIZE];
        hk.expand(HKDF_INFO, &mut expected_derived_key).unwrap();

        assert_eq!(effective_key, expected_derived_key);
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
