//! Shared test fixtures: derive real `CryptoKeys` from a fixed password/email
//! and encrypt cipher fields the same way Vaultwarden does, so the production
//! decrypt path can be exercised offline (no server, no Docker).
//!
//! Mirrors `vaultwarden_cli::crypto::crypto_keys::tests::test_helpers::encrypt_bytes_for_test`,
//! which is `pub(crate)` in the library and therefore unreachable from here.
//! That helper uses a fixed IV (`64u8..80`); we do the same for determinism.

#![allow(dead_code)]

use aes::cipher::{BlockModeEncrypt, KeyIvInit, block_padding::Pkcs7};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use cbc::Encryptor as CbcEnc;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use vaultwarden_cli::crypto::{CryptoKeys, KdfIterations, MasterKey};
use vaultwarden_cli::models::Cipher;

type Aes256CbcEnc = CbcEnc<aes::Aes256>;

/// Fixed test identity. Not a real account — used only to derive deterministic keys.
pub const TEST_EMAIL: &str = "test@example.com";
pub const TEST_PASSWORD: &str = "test-password-123";
pub const TEST_KDF_ITERATIONS: u32 = 100_000;

/// Derive a real `CryptoKeys` the way `VaultwardenSession::new` does, but from
/// fixed inputs and with no network: derive the master key, stretch it, and
/// decrypt a symmetric key we encrypted ourselves.
///
/// Returns the keys plus the `profile.key` string a real server would send
/// (so Tier 2 can mount it on the mock `/api/sync` response).
pub fn derive_test_keys() -> (CryptoKeys, String) {
    let master_key = MasterKey::derive(
        TEST_PASSWORD,
        TEST_EMAIL,
        KdfIterations::new(TEST_KDF_ITERATIONS).expect("non-zero iterations"),
    );
    let stretched = master_key.stretch().expect("stretch ok");

    // Build a 64-byte symmetric key [enc(32) | mac(32)] and protect it with the
    // stretched master key — exactly what a Vaultwarden profile.Key contains.
    let mut sym_key_bytes = [0u8; 64];
    // Fixed pattern (not rand) so the fixture is fully deterministic.
    for (i, b) in sym_key_bytes.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(7);
    }
    let protected_key = encrypt_bytes(&sym_key_bytes, stretched.enc_key(), stretched.mac_key());

    let keys = master_key
        .stretch()
        .expect("stretch ok")
        .decrypt_symmetric_key(&protected_key)
        .expect("decrypt symmetric key");
    (keys, protected_key)
}

/// Encrypt plaintext into the `2.<iv>|<ct>|<mac>` envelope Vaultwarden uses.
/// Fixed IV (64..80) for deterministic output — test-only, never production.
pub fn encrypt_bytes(plaintext: &[u8], enc_key: &[u8; 32], mac_key: &[u8; 32]) -> String {
    let iv: Vec<u8> = (64u8..80).collect();
    let mut buf = plaintext.to_vec();
    let msg_len = buf.len();
    buf.resize(msg_len + 16, 0);
    let ciphertext = Aes256CbcEnc::new_from_slices(enc_key.as_slice(), &iv)
        .expect("enc key slice")
        .encrypt_padded::<Pkcs7>(&mut buf, msg_len)
        .expect("encrypt")
        .to_vec();
    let mut hmac = Hmac::<Sha256>::new_from_slice(mac_key).expect("mac key slice");
    hmac.update(&iv);
    hmac.update(&ciphertext);
    let mac = hmac.finalize().into_bytes();
    format!(
        "2.{}|{}|{}",
        BASE64.encode(&iv),
        BASE64.encode(&ciphertext),
        BASE64.encode(mac)
    )
}

/// Encrypt a UTF-8 string with the session symmetric key.
pub fn encrypt_str(plaintext: &str, keys: &CryptoKeys) -> String {
    encrypt_bytes(
        plaintext.as_bytes(),
        keys.enc_key_bytes(),
        keys.mac_key_bytes(),
    )
}

/// Build a login `Cipher` with encrypted name/username/password/uri.
pub fn make_login_cipher(
    keys: &CryptoKeys,
    id: &str,
    name: &str,
    username: &str,
    password: &str,
    uri: &str,
) -> Cipher {
    serde_json::from_value(login_cipher_json(keys, id, name, username, password, uri))
        .expect("deserialize login cipher")
}

/// Build the JSON for an encrypted login cipher — for mock `/api/sync` bodies
/// (the `Cipher` struct is Deserialize-only and cannot be serialized back).
pub fn login_cipher_json(
    keys: &CryptoKeys,
    id: &str,
    name: &str,
    username: &str,
    password: &str,
    uri: &str,
) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "type": 1,
        "name": encrypt_str(name, keys),
        "login": {
            "username": encrypt_str(username, keys),
            "password": encrypt_str(password, keys),
            "uris": [{ "uri": encrypt_str(uri, keys), "match": 0 }],
        },
    })
}
