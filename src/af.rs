use crate::{HASH_SHA256, LuksError, SHA256_DIGEST_SIZE};
use sha2::{Digest, Sha256};

/// Merges anti-forensic stripes to retrieve the original data.
pub fn merge(data: &[u8], hash_alg: &str, stripes: u32, block_size: usize) -> Result<Vec<u8>, LuksError> {
    if hash_alg != HASH_SHA256 {
        return Err(LuksError::UnsupportedChecksumAlg(format!(
            "AF hash {} is not supported",
            hash_alg
        )));
    }

    if data.len() < block_size * stripes as usize {
        return Err(LuksError::InvalidHeader(format!(
            "AF data size {} is too small for {} stripes of {} bytes",
            data.len(),
            stripes,
            block_size
        )));
    }

    let mut bufblock = vec![0u8; block_size];

    for i in 0..(stripes - 1) {
        let stripe_start = i as usize * block_size;
        let stripe = &data[stripe_start..stripe_start + block_size];

        for (b, s) in bufblock.iter_mut().zip(stripe) {
            *b ^= *s;
        }

        bufblock = diffuse(hash_alg, &bufblock, block_size)?;
    }

    let mut dst = vec![0u8; block_size];
    let last_stripe_start = (stripes - 1) as usize * block_size;
    let last_stripe = &data[last_stripe_start..last_stripe_start + block_size];

    for (d, (b, s)) in dst.iter_mut().zip(bufblock.iter().zip(last_stripe)) {
        *d = *b ^ *s;
    }

    Ok(dst)
}

/// Splits the original data into anti-forensic stripes.
///
/// This is the inverse of [`merge`].
pub fn split(
    data: &[u8],
    hash_alg: &str,
    stripes: u32,
    block_size: usize,
    mut random_stripes: Vec<u8>,
) -> Result<Vec<u8>, LuksError> {
    if hash_alg != HASH_SHA256 {
        return Err(LuksError::UnsupportedChecksumAlg(format!(
            "AF hash {} is not supported",
            hash_alg
        )));
    }

    if random_stripes.len() != block_size * (stripes - 1) as usize {
        return Err(LuksError::InvalidHeader(format!(
            "AF random data size {} is not equal to {} stripes of {} bytes",
            random_stripes.len(),
            stripes - 1,
            block_size
        )));
    }

    let mut bufblock = vec![0u8; block_size];

    for i in 0..(stripes - 1) {
        let stripe_start = i as usize * block_size;
        let stripe = &random_stripes[stripe_start..stripe_start + block_size];

        for (b, s) in bufblock.iter_mut().zip(stripe) {
            *b ^= *s;
        }

        bufblock = diffuse(hash_alg, &bufblock, block_size)?;
    }

    let mut last_stripe = vec![0u8; block_size];
    for (l, (b, d)) in last_stripe.iter_mut().zip(bufblock.iter().zip(data)) {
        *l = *b ^ *d;
    }

    random_stripes.extend_from_slice(&last_stripe);
    Ok(random_stripes)
}

fn diffuse(hash_alg: &str, src: &[u8], block_size: usize) -> Result<Vec<u8>, LuksError> {
    let hash_len = SHA256_DIGEST_SIZE;
    let blocks = block_size / hash_len;
    let padding = block_size % hash_len;
    let mut dst = vec![0u8; block_size];

    for i in 0..blocks {
        let chunk = &src[i * hash_len..(i + 1) * hash_len];
        let hash = hash_buf(hash_alg, chunk, i as u32)?;
        dst[i * hash_len..(i + 1) * hash_len].copy_from_slice(&hash);
    }

    if padding > 0 {
        let chunk = &src[blocks * hash_len..];
        let hash = hash_buf(hash_alg, chunk, blocks as u32)?;
        dst[blocks * hash_len..].copy_from_slice(&hash[..padding]);
    }

    Ok(dst)
}

fn hash_buf(hash_alg: &str, src: &[u8], iv: u32) -> Result<Vec<u8>, LuksError> {
    if hash_alg != HASH_SHA256 {
        return Err(LuksError::UnsupportedChecksumAlg(format!(
            "AF hash {} is not supported",
            hash_alg
        )));
    }

    let mut hasher = Sha256::new();
    hasher.update(&iv.to_be_bytes());
    hasher.update(src);
    Ok(hasher.finalize().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;

    #[test]
    fn test_af_roundtrip() {
        let block_size = 32;
        let stripes = 10;
        let data = vec![0x42u8; block_size];
        let hash_alg = "sha256";

        let mut random_stripes = vec![0u8; block_size * (stripes - 1) as usize];
        rand::thread_rng().fill_bytes(&mut random_stripes);

        let split_data = split(&data, hash_alg, stripes, block_size, random_stripes).expect("Split failed");
        let merged_data = merge(&split_data, hash_alg, stripes, block_size).expect("Merge failed");

        assert_eq!(data, merged_data);
    }
}
