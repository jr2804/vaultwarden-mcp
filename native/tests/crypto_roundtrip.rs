//! Tier 1 — offline crypto round-trip.
//!
//! No network, no server, no Docker. Derives real `CryptoKeys` from fixed
//! inputs, encrypts a known login cipher, feeds it through the *production*
//! `VaultwardenSession::decrypt_ciphers` path, and asserts the decrypted
//! fields match the plaintext. Validates our wiring of the vaultwarden-cli
//! crypto end to end.

mod common;

use vaultwarden_cli::crypto::CryptoKeys;
use vaultwarden_mcp::VaultwardenSession;

use common::{derive_test_keys, encrypt_str, make_login_cipher};

#[test]
fn decrypt_returns_original_plaintext_fields() {
    let (keys, _protected) = derive_test_keys();

    let cipher = make_login_cipher(
        &keys,
        "cipher-1",
        "GitHub",
        "octocat",
        "p@ssw0rd!",
        "https://github.com",
    );

    let entries = VaultwardenSession::decrypt_ciphers(std::slice::from_ref(&cipher), &keys);

    assert_eq!(entries.len(), 1, "exactly one entry");
    let e = &entries[0];
    assert_eq!(e.id, "cipher-1");
    assert_eq!(e.cipher_type, "login");
    assert_eq!(e.name, "GitHub");
    assert_eq!(e.username.as_deref(), Some("octocat"));
    assert_eq!(e.password.as_deref(), Some("p@ssw0rd!"));
    assert_eq!(e.uri.as_deref(), Some("https://github.com"));
}

#[test]
fn multiple_ciphers_each_decrypt_independently() {
    let (keys, _) = derive_test_keys();

    let ciphers = [
        make_login_cipher(&keys, "a", "Site A", "user-a", "pass-a", "https://a.test"),
        make_login_cipher(&keys, "b", "Site B", "user-b", "pass-b", "https://b.test"),
        make_login_cipher(&keys, "c", "Site C", "user-c", "pass-c", "https://c.test"),
    ];

    let entries = VaultwardenSession::decrypt_ciphers(&ciphers, &keys);
    assert_eq!(entries.len(), 3);

    assert_eq!(entries[0].username.as_deref(), Some("user-a"));
    assert_eq!(entries[1].username.as_deref(), Some("user-b"));
    assert_eq!(entries[2].username.as_deref(), Some("user-c"));
}

#[test]
fn wrong_symmetric_key_fails_hmac() {
    // The profile.Key envelope is HMAC-verified. A key derived from a different
    // identity must fail to decrypt it — this is the exact guard
    // VaultwardenSession::new relies on to abort on a wrong password.
    let (_, protected) = derive_test_keys();

    let wrong_master = vaultwarden_cli::crypto::MasterKey::derive(
        "other-password",
        "other@example.com",
        vaultwarden_cli::crypto::KdfIterations::new(100_000).unwrap(),
    );
    let result = wrong_master
        .stretch()
        .unwrap()
        .decrypt_symmetric_key(&protected);
    assert!(
        result.is_err(),
        "wrong password must fail HMAC verification"
    );
}

#[test]
fn empty_cipher_list_yields_empty() {
    let (keys, _) = derive_test_keys();
    let entries = VaultwardenSession::decrypt_ciphers(&[], &keys);
    assert!(entries.is_empty());
}

#[test]
fn encrypt_decrypt_roundtrip_via_library_decrypt() {
    // Direct round-trip sanity: our encrypt_str (test helper) must be readable
    // by the library's public CryptoKeys::decrypt — proving envelope compatibility.
    let (keys, _): (CryptoKeys, _) = derive_test_keys();
    let ct = encrypt_str("round-trip-me", &keys);
    let pt = keys.decrypt(&ct).expect("library decrypt");
    assert_eq!(pt, b"round-trip-me");
}

#[test]
fn production_encrypt_roundtrips_through_library_decrypt() {
    // The real contract: vaultwarden_mcp::crypto::encrypt_string (production,
    // random IV) must be decryptable by the library's public CryptoKeys —
    // this is what the live server relies on for every written field.
    use vaultwarden_mcp::crypto::encrypt_string;

    let (keys, _): (CryptoKeys, _) = derive_test_keys();
    for plaintext in [
        "",
        "x",
        "p@ssw0rd!",
        "🔐 unicode密码",
        std::str::from_utf8(&[b'a'; 256]).unwrap(),
    ] {
        let ct = encrypt_string(plaintext, keys.enc_key_bytes(), keys.mac_key_bytes())
            .expect("production encrypt");
        let pt = keys
            .decrypt_to_string(&ct)
            .expect("library decrypt of production ciphertext");
        assert_eq!(
            pt, plaintext,
            "production round-trip failed for {plaintext:?}"
        );
    }
}
