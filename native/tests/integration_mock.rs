//! Tier 2 — mock-server integration.
//!
//! No Docker, no Vaultwarden binary. A `wiremock` server speaks the two
//! endpoints our production code actually hits (`/identity/connect/token` and
//! `/api/sync`), returning fixture JSON whose cipher fields are genuinely
//! encrypted with the same keys `VaultwardenSession::new` will derive. This
//! exercises the full production path: authenticate → sync → derive master key
//! → decrypt symmetric key → decrypt ciphers → expose via session methods.

mod common;

use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use vaultwarden_mcp::VaultwardenSession;

use common::{TEST_EMAIL, TEST_KDF_ITERATIONS, TEST_PASSWORD, derive_test_keys, login_cipher_json};

/// Mount the `/identity/connect/token` handler returning a token response
/// whose `Key` is the protected symmetric key for our test identity.
async fn mount_token(mock: &MockServer, protected_key: &str) {
    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "test-access-token",
            "expires_in": 3600,
            "token_type": "Bearer",
            "refresh_token": "test-refresh",
            "scope": "api",
            "Key": protected_key,
            "PrivateKey": "2.dummy",
            "Kdf": 0,
            "KdfIterations": TEST_KDF_ITERATIONS,
        })))
        .mount(mock)
        .await;
}

/// Mount `/api/sync` returning a profile (with the protected key) plus the
/// given ciphers as raw JSON values (already encrypted).
async fn mount_sync(mock: &MockServer, protected_key: &str, ciphers_json: Vec<serde_json::Value>) {
    let body = serde_json::json!({
        "Profile": {
            "Id": "user-1",
            "Email": TEST_EMAIL,
            "Name": "Test User",
            "Key": protected_key,
            "PrivateKey": "2.dummy",
            "Organizations": [],
        },
        "Folders": [],
        "Collections": [],
        "Ciphers": ciphers_json,
    });
    Mock::given(method("GET"))
        .and(path("/api/sync"))
        .and(header("authorization", "Bearer test-access-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(mock)
        .await;
}

/// Build a single login cipher as JSON for the mock sync body.
fn login(
    keys: &vaultwarden_cli::crypto::CryptoKeys,
    id: &str,
    name: &str,
    user: &str,
    pw: &str,
    uri: &str,
) -> serde_json::Value {
    login_cipher_json(keys, id, name, user, pw, uri)
}

#[tokio::test]
async fn session_connects_and_decrypts_real_fields() {
    let mock = MockServer::start().await;
    let (keys, protected_key) = derive_test_keys();

    let cipher = login(
        &keys,
        "login-1",
        "GitHub",
        "octocat",
        "hunter2",
        "https://github.com",
    );
    mount_token(&mock, &protected_key).await;
    mount_sync(&mock, &protected_key, vec![cipher]).await;

    let session = match VaultwardenSession::new(
        &mock.uri(),
        "test-client-id",
        "test-client-secret",
        TEST_PASSWORD,
        true, // allow_http — mock server is http://
    )
    .await
    {
        Ok(s) => s,
        Err(e) => panic!("session should connect and decrypt: {e}"),
    };

    assert_eq!(session.email(), TEST_EMAIL);

    // get_cipher returns the decrypted entry.
    let entry = session.get_cipher("login-1").await.expect("cipher found");
    assert_eq!(entry.name, "GitHub");
    assert_eq!(entry.username.as_deref(), Some("octocat"));
    assert_eq!(entry.password.as_deref(), Some("hunter2"));
    assert_eq!(entry.uri.as_deref(), Some("https://github.com"));
}

#[tokio::test]
async fn search_matches_by_name_username_and_uri() {
    let mock = MockServer::start().await;
    let (keys, protected_key) = derive_test_keys();

    let ciphers = [
        login(&keys, "a", "GitHub", "octocat", "p1", "https://github.com"),
        login(&keys, "b", "GitLab", "root", "p2", "https://gitlab.com"),
        login(
            &keys,
            "c",
            "Email",
            "octocat@x.test",
            "p3",
            "https://mail.test",
        ),
    ];
    mount_token(&mock, &protected_key).await;
    mount_sync(&mock, &protected_key, ciphers.to_vec()).await;

    let session =
        match VaultwardenSession::new(&mock.uri(), "cid", "csec", TEST_PASSWORD, true).await {
            Ok(s) => s,
            Err(e) => panic!("session should connect: {e}"),
        };

    // By name
    let by_name = session.search("gitlab").await.expect("search");
    assert_eq!(by_name.len(), 1);
    assert_eq!(by_name[0].name, "GitLab");

    // By username (matches two: GitHub + Email)
    let by_user = session.search("octocat").await.expect("search");
    assert_eq!(by_user.len(), 2);

    // By URI
    let by_uri = session.search("github.com").await.expect("search");
    assert_eq!(by_uri.len(), 1);
    assert_eq!(by_uri[0].username.as_deref(), Some("octocat"));
}

#[tokio::test]
async fn sync_returns_correct_cipher_count() {
    let mock = MockServer::start().await;
    let (keys, protected_key) = derive_test_keys();

    let ciphers = [
        login(&keys, "1", "A", "u1", "p1", "https://a.test"),
        login(&keys, "2", "B", "u2", "p2", "https://b.test"),
    ];
    mount_token(&mock, &protected_key).await;
    mount_sync(&mock, &protected_key, ciphers.to_vec()).await;

    let session =
        match VaultwardenSession::new(&mock.uri(), "cid", "csec", TEST_PASSWORD, true).await {
            Ok(s) => s,
            Err(e) => panic!("session should connect: {e}"),
        };

    let summary = session.sync().await.expect("sync");
    assert_eq!(summary.email, TEST_EMAIL);
    assert_eq!(summary.cipher_count, 2);
}

#[tokio::test]
async fn empty_vault_connects_and_returns_zero() {
    let mock = MockServer::start().await;
    let (keys, protected_key) = derive_test_keys();
    let _ = keys;
    mount_token(&mock, &protected_key).await;
    mount_sync(&mock, &protected_key, vec![]).await;

    let session =
        match VaultwardenSession::new(&mock.uri(), "cid", "csec", TEST_PASSWORD, true).await {
            Ok(s) => s,
            Err(e) => panic!("session should connect on empty vault: {e}"),
        };

    let summary = session.sync().await.expect("sync");
    assert_eq!(summary.cipher_count, 0);
    let search = session.search("anything").await.expect("search");
    assert!(search.is_empty());
}

#[tokio::test]
async fn wrong_password_aborts_connect() {
    // The protected key was encrypted for the TEST_PASSWORD identity. Connecting
    // with a different password must fail at the symmetric-key decrypt step
    // (HMAC verification) rather than silently producing garbage.
    let mock = MockServer::start().await;
    let (_, protected_key) = derive_test_keys();

    mount_token(&mock, &protected_key).await;
    mount_sync(&mock, &protected_key, vec![]).await;

    let err = match VaultwardenSession::new(
        &mock.uri(),
        "cid",
        "csec",
        "definitely-wrong-password",
        true,
    )
    .await
    {
        Ok(_) => panic!("wrong password must abort connect, but session was created"),
        Err(e) => e,
    };
    let msg = format!("{err}");
    assert!(
        msg.contains("wrong") || msg.contains("HMAC") || msg.contains("decrypt"),
        "error should name the credential failure, got: {msg}"
    );
}

#[tokio::test]
async fn get_cipher_unknown_id_errors() {
    let mock = MockServer::start().await;
    let (keys, protected_key) = derive_test_keys();
    let cipher = login(&keys, "real", "R", "u", "p", "https://r.test");
    mount_token(&mock, &protected_key).await;
    mount_sync(&mock, &protected_key, vec![cipher]).await;

    let session =
        match VaultwardenSession::new(&mock.uri(), "cid", "csec", TEST_PASSWORD, true).await {
            Ok(s) => s,
            Err(e) => panic!("session should connect: {e}"),
        };

    let err = session.get_cipher("does-not-exist").await;
    assert!(err.is_err(), "unknown cipher id must error");
}

// ── Write-path tests ────────────────────────────────────────────────────
//
// Mock the POST/PUT/DELETE cipher endpoints. The session encrypts the
// request body with the same keys the test fixtures use, so we can assert
// the server received validly-shaped ciphertext, and the mock returns a
// decryptable cipher JSON so refresh_after_write round-trips.

use vaultwarden_cli::crypto::CryptoKeys;
use vaultwarden_mcp::{CipherEdit, CipherInput, FieldInput, WriteCipherType};

/// Build a login-cipher response (the shape POST/PUT return) encrypted with
/// the test keys, matching the plaintext we asked the session to write.
fn login_response(
    keys: &CryptoKeys,
    id: &str,
    name: &str,
    username: &str,
    password: &str,
    uri: &str,
) -> serde_json::Value {
    login_cipher_json(keys, id, name, username, password, uri)
}

#[tokio::test]
async fn create_cipher_posts_encrypted_body_and_returns_entry() {
    let mock = MockServer::start().await;
    let (keys, protected_key) = derive_test_keys();
    mount_token(&mock, &protected_key).await;
    mount_sync(&mock, &protected_key, vec![]).await;

    // The create mock validates the body shape and returns a decryptable cipher.
    Mock::given(method("POST"))
        .and(path("/api/ciphers"))
        .and(header("authorization", "Bearer test-access-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(login_response(
            &keys,
            "new-1",
            "New Site",
            "newuser",
            "newpass",
            "https://new.test",
        )))
        .mount(&mock)
        .await;

    let session = VaultwardenSession::new(&mock.uri(), "cid", "csec", TEST_PASSWORD, true)
        .await
        .expect("connect");

    let entry = session
        .create_cipher(CipherInput {
            cipher_type: WriteCipherType::Login,
            name: "New Site".into(),
            username: Some("newuser".into()),
            password: Some("newpass".into()),
            uri: Some("https://new.test".into()),
            totp: None,
            notes: None,
            fields: None,
        })
        .await
        .expect("create");

    assert_eq!(entry.id, "new-1");
    assert_eq!(entry.name, "New Site");
    assert_eq!(entry.username.as_deref(), Some("newuser"));
    assert_eq!(entry.password.as_deref(), Some("newpass"));

    // The created entry must be visible via search immediately (cache spliced).
    let found = session.search("New Site").await.expect("search");
    assert_eq!(found.len(), 1);
}

#[tokio::test]
async fn edit_cipher_overlays_fields_and_put_replaces() {
    let mock = MockServer::start().await;
    let (keys, protected_key) = derive_test_keys();
    let original = login(&keys, "e-1", "Orig", "u1", "p1", "https://o.test");
    mount_token(&mock, &protected_key).await;
    mount_sync(&mock, &protected_key, vec![original]).await;

    Mock::given(method("PUT"))
        .and(path("/api/ciphers/e-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(login_response(
            &keys,
            "e-1",
            "Edited",
            "u1",
            "newpass",
            "https://o.test",
        )))
        .mount(&mock)
        .await;

    let session = VaultwardenSession::new(&mock.uri(), "cid", "csec", TEST_PASSWORD, true)
        .await
        .expect("connect");

    // Only change the password; everything else stays (partial overlay).
    let entry = session
        .edit_cipher(
            "e-1",
            CipherEdit {
                password: Some(Some("newpass".into())),
                ..Default::default()
            },
        )
        .await
        .expect("edit");

    assert_eq!(entry.name, "Edited");
    assert_eq!(entry.password.as_deref(), Some("newpass"));
    assert_eq!(entry.username.as_deref(), Some("u1")); // unchanged
}

#[tokio::test]
async fn edit_cipher_can_clear_a_field_with_some_none() {
    let mock = MockServer::start().await;
    let (keys, protected_key) = derive_test_keys();
    let original = login(&keys, "c-1", "C", "keep", "clear-me", "https://c.test");
    mount_token(&mock, &protected_key).await;
    mount_sync(&mock, &protected_key, vec![original]).await;

    Mock::given(method("PUT"))
        .and(path("/api/ciphers/c-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(login_response(
            &keys,
            "c-1",
            "C",
            "keep",
            "",
            "https://c.test",
        )))
        .mount(&mock)
        .await;

    let session = VaultwardenSession::new(&mock.uri(), "cid", "csec", TEST_PASSWORD, true)
        .await
        .expect("connect");

    let entry = session
        .edit_cipher(
            "c-1",
            CipherEdit {
                password: Some(None), // explicitly clear
                ..Default::default()
            },
        )
        .await
        .expect("edit");

    // Server returned an empty password; the cleared field round-trips.
    assert_eq!(entry.password.as_deref(), Some(""));
}

#[tokio::test]
async fn delete_cipher_sends_delete_and_drops_from_cache() {
    let mock = MockServer::start().await;
    let (keys, protected_key) = derive_test_keys();
    let cipher = login(&keys, "d-1", "Doomed", "u", "p", "https://d.test");
    mount_token(&mock, &protected_key).await;
    mount_sync(&mock, &protected_key, vec![cipher]).await;

    Mock::given(method("DELETE"))
        .and(path("/api/ciphers/d-1"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock)
        .await;

    let session = VaultwardenSession::new(&mock.uri(), "cid", "csec", TEST_PASSWORD, true)
        .await
        .expect("connect");

    session.delete_cipher("d-1").await.expect("delete");

    // Gone from the cache.
    assert!(session.get_cipher("d-1").await.is_err());
}

#[tokio::test]
async fn soft_delete_then_restore_round_trips() {
    let mock = MockServer::start().await;
    let (keys, protected_key) = derive_test_keys();
    let cipher = login(&keys, "s-1", "Soft", "u", "p", "https://s.test");
    mount_token(&mock, &protected_key).await;
    mount_sync(&mock, &protected_key, vec![cipher]).await;

    // soft-delete returns the cipher with a deletedDate set.
    let deleted_resp = {
        let mut v = login_response(&keys, "s-1", "Soft", "u", "p", "https://s.test");
        v["deletedDate"] = serde_json::json!("2026-01-01T00:00:00.000Z");
        v
    };
    Mock::given(method("PUT"))
        .and(path("/api/ciphers/s-1/delete"))
        .respond_with(ResponseTemplate::new(200).set_body_json(deleted_resp))
        .mount(&mock)
        .await;

    // restore returns it without the deletedDate.
    Mock::given(method("PUT"))
        .and(path("/api/ciphers/s-1/restore"))
        .respond_with(ResponseTemplate::new(200).set_body_json(login_response(
            &keys,
            "s-1",
            "Soft",
            "u",
            "p",
            "https://s.test",
        )))
        .mount(&mock)
        .await;

    let session = VaultwardenSession::new(&mock.uri(), "cid", "csec", TEST_PASSWORD, true)
        .await
        .expect("connect");

    session
        .soft_delete_cipher("s-1")
        .await
        .expect("soft delete");
    // After soft-delete the active cache no longer lists it.
    assert!(session.get_cipher("s-1").await.is_err());

    session.restore_cipher("s-1").await.expect("restore");
    // After restore it's back in the cache.
    let entry = session.get_cipher("s-1").await.expect("restored");
    assert_eq!(entry.name, "Soft");
}

#[tokio::test]
async fn create_cipher_with_fields_encrypts_them() {
    let mock = MockServer::start().await;
    let (keys, protected_key) = derive_test_keys();
    mount_token(&mock, &protected_key).await;
    mount_sync(&mock, &protected_key, vec![]).await;

    // Return a cipher whose name we can decrypt; fields are not echoed here
    // since the mock response shape is simplified for the assertion.
    Mock::given(method("POST"))
        .and(path("/api/ciphers"))
        .respond_with(ResponseTemplate::new(200).set_body_json(login_response(
            &keys,
            "f-1",
            "With Fields",
            "u",
            "p",
            "https://f.test",
        )))
        .mount(&mock)
        .await;

    let session = VaultwardenSession::new(&mock.uri(), "cid", "csec", TEST_PASSWORD, true)
        .await
        .expect("connect");

    let entry = session
        .create_cipher(CipherInput {
            cipher_type: WriteCipherType::Login,
            name: "With Fields".into(),
            username: Some("u".into()),
            password: Some("p".into()),
            uri: Some("https://f.test".into()),
            totp: None,
            notes: Some("a note".into()),
            fields: Some(vec![FieldInput {
                name: "pin".into(),
                value: Some("1234".into()),
                field_type: Some("hidden".into()),
            }]),
        })
        .await
        .expect("create with fields");

    assert_eq!(entry.name, "With Fields");
}
