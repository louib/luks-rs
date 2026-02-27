use crate::{Luks2Kdf, LuksError};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine as _, engine::general_purpose};

/// Derives a key from a passphrase using the KDF specified in the LUKS2 header.
pub fn derive_key(kdf: &Luks2Kdf, passphrase: &[u8], key_size: usize) -> Result<Vec<u8>, LuksError> {
    match kdf {
        Luks2Kdf::Argon2i {
            time,
            memory,
            cpus,
            salt,
            ..
        } => {
            let salt_bytes = general_purpose::STANDARD
                .decode(salt)
                .map_err(|e| LuksError::Kdf(format!("Invalid salt base64: {}", e)))?;

            let mut output = vec![0u8; key_size];
            let params = Params::new(*memory, *time, *cpus, Some(key_size))
                .map_err(|e| LuksError::Kdf(format!("Invalid Argon2 params: {}", e)))?;

            let argon2 = Argon2::new(Algorithm::Argon2i, Version::V0x13, params);
            argon2
                .hash_password_into(passphrase, &salt_bytes, &mut output)
                .map_err(|e| LuksError::Kdf(format!("Argon2 error: {}", e)))?;

            Ok(output)
        }
        Luks2Kdf::Argon2id {
            time,
            memory,
            cpus,
            salt,
            ..
        } => {
            let salt_bytes = general_purpose::STANDARD
                .decode(salt)
                .map_err(|e| LuksError::Kdf(format!("Invalid salt base64: {}", e)))?;

            let mut output = vec![0u8; key_size];
            let params = Params::new(*memory, *time, *cpus, Some(key_size))
                .map_err(|e| LuksError::Kdf(format!("Invalid Argon2 params: {}", e)))?;

            let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
            argon2
                .hash_password_into(passphrase, &salt_bytes, &mut output)
                .map_err(|e| LuksError::Kdf(format!("Argon2 error: {}", e)))?;

            Ok(output)
        }
        Luks2Kdf::Pbkdf2 { .. } => Err(LuksError::UnsupportedChecksumAlg(
            "PBKDF2 derivation not yet implemented".to_string(),
        )),
    }
}
