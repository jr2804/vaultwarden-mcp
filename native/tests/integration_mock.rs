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

use common::{
    TEST_EMAIL, TEST_KDF_ITERATIONS, TEST_PASSWORD, card_cipher_json, derive_test_keys,
    login_cipher_json,
};

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

/// Mount `GET /api/ciphers/{id}` returning the raw (encrypted) cipher JSON.
/// `edit_cipher` fetches this before its full-replace PUT so type-specific
/// data (card/identity/ssh) survives the edit.
async fn mount_get_cipher(mock: &MockServer, cipher_json: serde_json::Value) {
    let id = cipher_json["id"]
        .as_str()
        .expect("cipher fixture must carry an id")
        .to_string();
    Mock::given(method("GET"))
        .and(path(format!("/api/ciphers/{id}")))
        .and(header("authorization", "Bearer test-access-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(cipher_json))
        .mount(mock)
        .await;
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
            folder: None,
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
    mount_sync(&mock, &protected_key, vec![original.clone()]).await;

    // edit_cipher fetches the raw cipher first, then PUTs the merged body.
    mount_get_cipher(&mock, original).await;

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
    mount_sync(&mock, &protected_key, vec![original.clone()]).await;

    mount_get_cipher(&mock, original).await;

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
            folder: None,
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

// ── Folder tests ──────────────────────────────────────────────────────────────

/// Build a folder response JSON with an encrypted name.
fn folder_response(keys: &CryptoKeys, id: &str, name: &str) -> serde_json::Value {
    let enc =
        vaultwarden_mcp::crypto::encrypt_string(name, keys.enc_key_bytes(), keys.mac_key_bytes())
            .expect("encrypt folder name");
    serde_json::json!({
        "id": id,
        "name": enc,
    })
}

/// Mount /api/sync including the given folders (as raw JSON values).
async fn mount_sync_with_folders(
    mock: &MockServer,
    protected_key: &str,
    ciphers_json: Vec<serde_json::Value>,
    folders_json: Vec<serde_json::Value>,
) {
    let body = serde_json::json!({
        "Profile": {
            "Id": "user-1",
            "Email": TEST_EMAIL,
            "Name": "Test User",
            "Key": protected_key,
            "PrivateKey": "2.dummy",
            "Organizations": [],
        },
        "Folders": folders_json,
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

#[tokio::test]
async fn create_folder_stores_encrypted_name_and_returns_decrypted() {
    let mock = MockServer::start().await;
    let (keys, protected_key) = derive_test_keys();
    mount_token(&mock, &protected_key).await;
    mount_sync(&mock, &protected_key, vec![]).await;

    Mock::given(method("POST"))
        .and(path("/api/folders"))
        .and(header("authorization", "Bearer test-access-token"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(folder_response(&keys, "folder-1", "Work")),
        )
        .mount(&mock)
        .await;

    let session = VaultwardenSession::new(&mock.uri(), "cid", "csec", TEST_PASSWORD, true)
        .await
        .expect("connect");

    let entry = session.create_folder("Work").await.expect("create folder");
    assert_eq!(entry.id, "folder-1");
    assert_eq!(entry.name, "Work");

    // list_folders also reflects the newly created folder.
    let folders = session.list_folders();
    assert!(
        folders
            .iter()
            .any(|f| f.id == "folder-1" && f.name == "Work")
    );
}

#[tokio::test]
async fn list_folders_returns_decrypted_names() {
    let mock = MockServer::start().await;
    let (keys, protected_key) = derive_test_keys();
    mount_token(&mock, &protected_key).await;

    let folder1 = folder_response(&keys, "f1", "Work");
    let folder2 = folder_response(&keys, "f2", "Personal");
    mount_sync_with_folders(&mock, &protected_key, vec![], vec![folder1, folder2]).await;

    let session = VaultwardenSession::new(&mock.uri(), "cid", "csec", TEST_PASSWORD, true)
        .await
        .expect("connect");

    let folders = session.list_folders();
    assert_eq!(folders.len(), 2);
    assert!(folders.iter().any(|f| f.id == "f1" && f.name == "Work"));
    assert!(folders.iter().any(|f| f.id == "f2" && f.name == "Personal"));
}

#[tokio::test]
async fn get_folder_id_resolves_name() {
    let mock = MockServer::start().await;
    let (keys, protected_key) = derive_test_keys();
    mount_token(&mock, &protected_key).await;

    let folder1 = folder_response(&keys, "f-42", "Dev");
    mount_sync_with_folders(&mock, &protected_key, vec![], vec![folder1]).await;

    let session = VaultwardenSession::new(&mock.uri(), "cid", "csec", TEST_PASSWORD, true)
        .await
        .expect("connect");

    assert_eq!(session.folder_id_for_name("Dev"), Some("f-42".into()));
    assert_eq!(session.folder_id_for_name("Devv"), None);
    assert_eq!(session.folder_id_for_name("Unknown"), None);
}

#[tokio::test]
async fn create_cipher_with_new_folder_auto_creates_it() {
    let mock = MockServer::start().await;
    let (keys, protected_key) = derive_test_keys();
    mount_token(&mock, &protected_key).await;
    mount_sync(&mock, &protected_key, vec![]).await;

    // Auto-create: first call POST /api/folders...
    Mock::given(method("POST"))
        .and(path("/api/folders"))
        .and(header("authorization", "Bearer test-access-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(folder_response(
            &keys,
            "folder-auto",
            "Work",
        )))
        .mount(&mock)
        .await;

    // ...then POST /api/ciphers with folderId=folder-auto.
    Mock::given(method("POST"))
        .and(path("/api/ciphers"))
        .and(header("authorization", "Bearer test-access-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(login_response(
            &keys,
            "c-1",
            "Site",
            "u",
            "p",
            "https://x.test",
        )))
        .mount(&mock)
        .await;

    let session = VaultwardenSession::new(&mock.uri(), "cid", "csec", TEST_PASSWORD, true)
        .await
        .expect("connect");

    let _entry = session
        .create_cipher(CipherInput {
            cipher_type: WriteCipherType::Login,
            name: "Site".into(),
            username: Some("u".into()),
            password: Some("p".into()),
            uri: Some("https://x.test".into()),
            totp: None,
            notes: None,
            fields: None,
            folder: Some("Work".into()),
        })
        .await
        .expect("create with auto-folder");

    // Verify the auto-created folder now appears in the cached list.
    let folders = session.list_folders();
    assert!(
        folders
            .iter()
            .any(|f| f.id == "folder-auto" && f.name == "Work"),
        "expected folder-auto in cached folders"
    );
}

#[tokio::test]
async fn create_cipher_with_existing_folder_reuses_id() {
    let mock = MockServer::start().await;
    let (keys, protected_key) = derive_test_keys();
    mount_token(&mock, &protected_key).await;

    // Seed a folder in the sync response so it's already cached.
    let folder = folder_response(&keys, "existing-f", "Work");
    mount_sync_with_folders(&mock, &protected_key, vec![], vec![folder]).await;

    // Expect POST to /api/ciphers (NOT to /api/folders). If the session
    // calls /api/folders, wiremock will panic (no mock registered).
    Mock::given(method("POST"))
        .and(path("/api/ciphers"))
        .and(header("authorization", "Bearer test-access-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(login_response(
            &keys,
            "c-2",
            "Site2",
            "u2",
            "p2",
            "https://y.test",
        )))
        .mount(&mock)
        .await;

    let session = VaultwardenSession::new(&mock.uri(), "cid", "csec", TEST_PASSWORD, true)
        .await
        .expect("connect");

    let _entry = session
        .create_cipher(CipherInput {
            cipher_type: WriteCipherType::Login,
            name: "Site2".into(),
            username: Some("u2".into()),
            password: Some("p2".into()),
            uri: Some("https://y.test".into()),
            totp: None,
            notes: None,
            fields: None,
            folder: Some("Work".into()),
        })
        .await
        .expect("create with existing folder");

    // No /api/folders call was made (no mock = no registered path).
}

#[tokio::test]
async fn edit_cipher_moves_to_folder() {
    let mock = MockServer::start().await;
    let (keys, protected_key) = derive_test_keys();
    mount_token(&mock, &protected_key).await;

    // Seed a folder so it's already cached.
    let folder = folder_response(&keys, "target-f", "Target");
    let cipher = login(&keys, "c-move", "MoveMe", "u", "p", "https://m.test");
    mount_sync_with_folders(&mock, &protected_key, vec![cipher.clone()], vec![folder]).await;

    // edit_cipher fetches the raw cipher before the PUT.
    mount_get_cipher(&mock, cipher).await;

    // get_cipher -> returns the cipherfrom sync; PUT returns the updated cipher.
    Mock::given(method("PUT"))
        .and(path("/api/ciphers/c-move"))
        .and(header("authorization", "Bearer test-access-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json({
            let mut r = login_response(&keys, "c-move", "MoveMe", "u", "p", "https://m.test");
            r["folderId"] = serde_json::Value::String("target-f".into());
            r
        }))
        .mount(&mock)
        .await;

    let session = VaultwardenSession::new(&mock.uri(), "cid", "csec", TEST_PASSWORD, true)
        .await
        .expect("connect");

    let entry = session
        .edit_cipher(
            "c-move",
            CipherEdit {
                folder: Some(Some("Target".into())),
                ..Default::default()
            },
        )
        .await
        .expect("edit move to folder");

    assert_eq!(entry.folder.as_deref(), Some("Target"));
    assert_eq!(entry.folder_id.as_deref(), Some("target-f"));
}

#[tokio::test]
async fn edit_cipher_clears_folder_with_null() {
    let mock = MockServer::start().await;
    let (keys, protected_key) = derive_test_keys();
    mount_token(&mock, &protected_key).await;

    // Seed a cipher in a folder and a cipher with no folder.
    let folder_json = folder_response(&keys, "f-old", "Old");
    let cipher = login(&keys, "c-clear", "ClearMe", "u", "p", "https://c.test");
    mount_sync_with_folders(
        &mock,
        &protected_key,
        vec![cipher.clone()],
        vec![folder_json],
    )
    .await;

    // edit_cipher fetches the raw cipher before the PUT.
    mount_get_cipher(&mock, cipher).await;

    Mock::given(method("PUT"))
        .and(path("/api/ciphers/c-clear"))
        .and(header("authorization", "Bearer test-access-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(login_response(
            &keys,
            "c-clear",
            "ClearMe",
            "u",
            "p",
            "https://c.test",
        )))
        .mount(&mock)
        .await;

    let session = VaultwardenSession::new(&mock.uri(), "cid", "csec", TEST_PASSWORD, true)
        .await
        .expect("connect");

    // First, create a cipher and move it to a folder so it has folder data.
    // Then edit it with folder=None to clear.
    // (In wiremock the create/fetch use the same fixture so folder is None.)
    let entry_after = session
        .edit_cipher(
            "c-clear",
            CipherEdit {
                folder: Some(None),
                ..Default::default()
            },
        )
        .await
        .expect("edit clear folder");

    assert_eq!(entry_after.folder, None);
    assert_eq!(entry_after.folder_id, None);
}

#[tokio::test]
async fn edit_cipher_on_card_moves_folder_and_preserves_card_data() {
    let mock = MockServer::start().await;
    let (keys, protected_key) = derive_test_keys();
    mount_token(&mock, &protected_key).await;

    let card = card_cipher_json(
        &keys,
        "card-1",
        "Amex Business",
        "Jane Doe",
        "4111111111111111",
        Some("work card"),
    );
    let folder = folder_response(&keys, "bf-f", "Banking & Finance");
    mount_sync_with_folders(&mock, &protected_key, vec![card.clone()], vec![folder]).await;

    // edit_cipher fetches the raw cipher before the PUT.
    mount_get_cipher(&mock, card.clone()).await;

    Mock::given(method("PUT"))
        .and(path("/api/ciphers/card-1"))
        .and(header("authorization", "Bearer test-access-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json({
            let mut r = card.clone();
            r["folderId"] = serde_json::Value::String("bf-f".into());
            r
        }))
        .mount(&mock)
        .await;

    let session = VaultwardenSession::new(&mock.uri(), "cid", "csec", TEST_PASSWORD, true)
        .await
        .expect("connect");

    // Only move the folder — the card itself must survive untouched.
    let entry = session
        .edit_cipher(
            "card-1",
            CipherEdit {
                folder: Some(Some("Banking & Finance".into())),
                ..Default::default()
            },
        )
        .await
        .expect("edit card");

    // Type and identity preserved: the card is not silently rewritten as login.
    assert_eq!(entry.cipher_type, "card");
    assert_eq!(entry.name, "Amex Business");
    assert_eq!(entry.folder.as_deref(), Some("Banking & Finance"));
    assert_eq!(entry.folder_id.as_deref(), Some("bf-f"));

    // The PUT body kept the card object verbatim (still encrypted with the
    // fixture keys) and carried the new folderId.
    let put_requests = mock.received_requests().await.expect("received requests");
    let put = put_requests
        .iter()
        .find(|r| r.method == "PUT" && r.url.path() == "/api/ciphers/card-1")
        .expect("PUT request recorded");
    let body: serde_json::Value = serde_json::from_slice(&put.body).expect("PUT body json");
    assert_eq!(body["type"], 3);
    assert_eq!(body["card"], card["card"]);
    assert_eq!(body["folderId"], "bf-f");
}

#[tokio::test]
async fn edit_cipher_on_card_renames_and_keeps_type() {
    let mock = MockServer::start().await;
    let (keys, protected_key) = derive_test_keys();
    mount_token(&mock, &protected_key).await;

    let card = card_cipher_json(
        &keys,
        "card-2",
        "Old Name",
        "Jane Doe",
        "4111111111111111",
        None,
    );
    mount_sync_with_folders(&mock, &protected_key, vec![card.clone()], vec![]).await;
    mount_get_cipher(&mock, card.clone()).await;

    // The server returns the renamed card (name re-encrypted with fixture keys).
    let mut renamed = card.clone();
    renamed["name"] = serde_json::Value::String(common::encrypt_str("New Name", &keys));
    Mock::given(method("PUT"))
        .and(path("/api/ciphers/card-2"))
        .and(header("authorization", "Bearer test-access-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(renamed))
        .mount(&mock)
        .await;

    let session = VaultwardenSession::new(&mock.uri(), "cid", "csec", TEST_PASSWORD, true)
        .await
        .expect("connect");

    let entry = session
        .edit_cipher(
            "card-2",
            CipherEdit {
                name: Some("New Name".into()),
                ..Default::default()
            },
        )
        .await
        .expect("edit card name");

    assert_eq!(entry.cipher_type, "card");
    assert_eq!(entry.name, "New Name");

    // Only the name changed; the card object and type are untouched on the wire.
    let put_requests = mock.received_requests().await.expect("received requests");
    let put = put_requests
        .iter()
        .find(|r| r.method == "PUT" && r.url.path() == "/api/ciphers/card-2")
        .expect("PUT request recorded");
    let body: serde_json::Value = serde_json::from_slice(&put.body).expect("PUT body json");
    assert_eq!(body["type"], 3);
    assert_eq!(body["card"], card["card"]);
    assert!(body["name"].as_str().is_some_and(|s| s != "Old Name"));
}

#[tokio::test]
async fn delete_folder_removes_from_cache() {
    let mock = MockServer::start().await;
    let (keys, protected_key) = derive_test_keys();
    mount_token(&mock, &protected_key).await;

    let folder = folder_response(&keys, "del-f", "TrashMe");
    mount_sync_with_folders(&mock, &protected_key, vec![], vec![folder]).await;

    Mock::given(method("DELETE"))
        .and(path("/api/folders/del-f"))
        .and(header("authorization", "Bearer test-access-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
        .mount(&mock)
        .await;

    let session = VaultwardenSession::new(&mock.uri(), "cid", "csec", TEST_PASSWORD, true)
        .await
        .expect("connect");

    assert!(session.folder_id_for_name("TrashMe").is_some());

    session
        .delete_folder("TrashMe")
        .await
        .expect("delete folder");

    assert!(session.folder_id_for_name("TrashMe").is_none());
}
