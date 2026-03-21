use crate::{Luks2HashAlg, LuksError, UnlockKey};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine as _, engine::general_purpose};
use serde::{Deserialize, Serialize};

/// Key derivation function (KDF) settings for a keyslot.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Luks2Kdf {
    /// Argon2i KDF.
    Argon2i {
        /// The number of iterations (time).
        time: u32,
        /// The amount of memory in KiB.
        memory: u32,
        /// The number of parallel threads.
        cpus: u32,
        /// The base64-encoded salt.
        salt: String,
    },
    /// Argon2id KDF.
    Argon2id {
        /// The number of iterations (time).
        time: u32,
        /// The amount of memory in KiB.
        memory: u32,
        /// The number of parallel threads.
        cpus: u32,
        /// The base64-encoded salt.
        salt: String,
    },
    /// PBKDF2.
    Pbkdf2 {
        /// The hash algorithm used.
        hash: Luks2HashAlg,
        /// The number of iterations.
        iterations: u32,
        /// The base64-encoded salt.
        salt: String,
    },
}

impl Luks2Kdf {
    /// Derives a key from an unlock key using the KDF specified in the LUKS2 header.
    pub fn derive_key(
        &self,
        key: &UnlockKey,
        _header_salt: &[u8],
        key_size: usize,
    ) -> Result<Vec<u8>, LuksError> {
        let salt = match self {
            Luks2Kdf::Argon2i { salt, .. } => salt,
            Luks2Kdf::Argon2id { salt, .. } => salt,
            Luks2Kdf::Pbkdf2 { salt, .. } => salt,
        };

        let salt_bytes = general_purpose::STANDARD
            .decode(salt)
            .map_err(|e| LuksError::Kdf(format!("Invalid salt base64: {}", e)))?;

        let effective_key = key.calculate_effective_key(&salt_bytes)?;

        match self {
            Luks2Kdf::Argon2i {
                time, memory, cpus, ..
            } => {
                let mut output = vec![0u8; key_size];
                let params = Params::new(*memory, *time, *cpus, None)
                    .map_err(|e| LuksError::Kdf(format!("Invalid Argon2 params: {}", e)))?;

                let argon2 = Argon2::new(Algorithm::Argon2i, Version::V0x13, params);
                argon2
                    .hash_password_into(&effective_key, &salt_bytes, &mut output)
                    .map_err(|e| LuksError::Kdf(format!("Argon2 error: {}", e)))?;

                Ok(output)
            }
            Luks2Kdf::Argon2id {
                time, memory, cpus, ..
            } => {
                let mut output = vec![0u8; key_size];
                let params = Params::new(*memory, *time, *cpus, None)
                    .map_err(|e| LuksError::Kdf(format!("Invalid Argon2 params: {}", e)))?;

                let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
                argon2
                    .hash_password_into(&effective_key, &salt_bytes, &mut output)
                    .map_err(|e| LuksError::Kdf(format!("Argon2 error: {}", e)))?;

                Ok(output)
            }
            Luks2Kdf::Pbkdf2 { hash, iterations, .. } => {
                let mut output = vec![0u8; key_size];

                if hash == &Luks2HashAlg::Sha256 {
                    pbkdf2::pbkdf2::<hmac::Hmac<sha2::Sha256>>(
                        &effective_key,
                        &salt_bytes,
                        *iterations,
                        &mut output,
                    )
                    .map_err(|e| LuksError::Kdf(format!("PBKDF2 error: {}", e)))?;
                    Ok(output)
                } else {
                    Err(LuksError::UnsupportedChecksumAlg(hash.to_string()))
                }
            }
        }
    }
}
