//! Production-side symmetric encryption for vault writes.
//!
//! The `vaultwarden-cli` library exposes `CryptoKeys` for **decryption only**
//! (its `encrypt_bytes_for_test` lives under `#[cfg(test)]` + `pub(crate)` and
//! is therefore unreachable from this crate). We implement the matching
//! encrypt here, using the same well-documented Bitwarden format the library
//! decrypts:
//!
//! `2.{base64(iv)}|{base64(ciphertext)}|{base64(mac)}`
//!
//! - AES-256-CBC with PKCS#7 padding, 16-byte IV drawn from `OsRng`.
//! - HMAC-SHA256 over `iv ‖ ciphertext`, keyed by the 32-byte MAC key.
//! - The leading `2.` marks the encryption-type version, which the upstream
//!   `CryptoKeys::decrypt_with_keys` checks before decrypting.
//!
//! Round-trip is verified by `native/tests/crypto_roundtrip.rs`, which
//! encrypts here and decrypts with the upstream `CryptoKeys::decrypt_to_string`
//! — the same keys the live server uses.

use aes::cipher::{BlockModeEncrypt, KeyIvInit, block_padding::Pkcs7};
use anyhow::Result;
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use cbc::Encryptor as CbcEnc;
use hmac::{Hmac, KeyInit, Mac};
use rand::Rng;
use sha2::Sha256;

type Aes256CbcEnc = CbcEnc<aes::Aes256>;

/// Encrypt `plaintext` with the account symmetric key and return the
/// `2.{iv}|{ct}|{mac}` ciphertext string the Vaultwarden API expects.
///
/// `enc_key` / `mac_key` come from [`vaultwarden_cli::crypto::CryptoKeys`]'s
/// public `enc_key_bytes()` / `mac_key_bytes()` accessors.
pub fn encrypt_string(plaintext: &str, enc_key: &[u8; 32], mac_key: &[u8; 32]) -> Result<String> {
    // 16-byte random IV — critical for semantic security. The upstream test
    // helper uses a fixed IV for determinism; production must not.
    let mut iv = [0u8; 16];
    rand::rng().fill_bytes(&mut iv);

    // PKCS#7 encrypt in place. `buf` is grown to a block-aligned size.
    let mut buf = plaintext.as_bytes().to_vec();
    let msg_len = buf.len();
    buf.resize(msg_len + 16, 0);

    let ciphertext = Aes256CbcEnc::new_from_slices(enc_key.as_slice(), &iv)
        .map_err(|e| anyhow::anyhow!("AES key/iv slice error: {e}"))?
        .encrypt_padded::<Pkcs7>(&mut buf, msg_len)
        .map_err(|e| anyhow::anyhow!("AES encrypt failed: {e}"))?
        .to_vec();

    let mut hmac = Hmac::<Sha256>::new_from_slice(mac_key.as_slice())
        .map_err(|e| anyhow::anyhow!("HMAC key error: {e}"))?;
    hmac.update(&iv);
    hmac.update(&ciphertext);
    let mac = hmac.finalize().into_bytes();

    Ok(format!(
        "2.{}|{}|{}",
        BASE64.encode(iv),
        BASE64.encode(&ciphertext),
        BASE64.encode(mac)
    ))
}

#[cfg(test)]
mod tests {
    // We don't re-derive keys here (the derivation dance is fiddly and lives
    // in tests/common/mod.rs). Instead the real round-trip coverage — our
    // encrypt_string against upstream CryptoKeys::decrypt_to_string — lives
    // in native/tests/crypto_roundtrip.rs where the fixture is already wired.
    // These unit tests only check the format invariants that don't need keys.

    use super::*;

    #[test]
    fn ciphertext_has_version_prefix_and_three_parts() {
        let enc = [0xAAu8; 32];
        let mac = [0xBBu8; 32];
        let ct = encrypt_string("x", &enc, &mac).unwrap();
        assert!(ct.starts_with("2."), "missing version prefix: {ct}");
        let rest = ct.strip_prefix("2.").unwrap();
        assert_eq!(
            rest.split('|').count(),
            3,
            "expected iv|ct|mac, got: {rest}"
        );
    }

    #[test]
    fn distinct_ivs_for_same_plaintext() {
        let enc = [0xAAu8; 32];
        let mac = [0xBBu8; 32];
        let a = encrypt_string("same", &enc, &mac).unwrap();
        let b = encrypt_string("same", &enc, &mac).unwrap();
        assert_ne!(a, b, "random IV must make ciphertexts distinct");
    }
}
