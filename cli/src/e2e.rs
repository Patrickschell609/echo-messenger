//! E2E test — compile with `cargo build -p echo-cli --features e2e`
//! Run: `echo --server https://echo.biotwin.io -i _test test-e2e --invite1 CODE1 --invite2 CODE2`
//!
//! Creates two temp identities, tests short code lookup, bidirectional messaging.
//! All temp files cleaned up on exit. This entire module compiles out without the flag.

use anyhow::{bail, Result};

use echo_client::http::HttpClient;
use echo_client::identity::{self, IdentityStore};

use crate::{cmd_recv, cmd_send, cmd_session};

/// Colored pass/fail for terminal output.
fn pass(step: &str) { println!("  \x1b[32m✓\x1b[0m {step}"); }
fn fail(step: &str, e: &str) { println!("  \x1b[31m✗\x1b[0m {step}: {e}"); }

pub async fn run_e2e(server: &str, invite1: &str, invite2: &str) -> Result<()> {
    println!("\n\x1b[1m══ ECHO E2E Test ══\x1b[0m\n");

    // Temp directories — auto-cleaned when dropped
    let dir_a = tempfile::tempdir()?;
    let dir_b = tempfile::tempdir()?;

    let store_a = IdentityStore::with_base_dir("alice", dir_a.path())?;
    let store_b = IdentityStore::with_base_dir("bob", dir_b.path())?;

    let http = HttpClient::new(server);
    let mut passed = 0u32;
    let mut failed = 0u32;

    // ── Step 1: Register Alice ──
    let alice_device;
    let alice_short_code;
    match register_identity(&http, &store_a, invite1).await {
        Ok((dev, code)) => {
            alice_device = dev;
            alice_short_code = code;
            pass(&format!("Register Alice → {} (code: {})", alice_device, alice_short_code.as_deref().unwrap_or("none")));
            passed += 1;
        }
        Err(e) => {
            fail("Register Alice", &e.to_string());
            failed += 1;
            bail!("Cannot continue without Alice");
        }
    }

    // ── Step 2: Register Bob ──
    let bob_device;
    let bob_short_code;
    match register_identity(&http, &store_b, invite2).await {
        Ok((dev, code)) => {
            bob_device = dev;
            bob_short_code = code;
            pass(&format!("Register Bob → {} (code: {})", bob_device, bob_short_code.as_deref().unwrap_or("none")));
            passed += 1;
        }
        Err(e) => {
            fail("Register Bob", &e.to_string());
            failed += 1;
            bail!("Cannot continue without Bob");
        }
    }

    // ── Step 3: Short code lookup ──
    if let Some(ref code) = alice_short_code {
        let state_b = store_b.load()?;
        let mut ed = [0u8; 32];
        ed.copy_from_slice(&state_b.identity_ed_private);
        let auth_http = HttpClient::with_auth(server, state_b.device_id, &ed);

        match auth_http.lookup_by_code(code).await {
            Ok(resp) => {
                let resolved: uuid::Uuid = resp.device_id.parse().unwrap_or_default();
                if resolved == alice_device {
                    pass(&format!("Lookup code {} → {}", code, alice_device));
                    passed += 1;
                } else {
                    fail("Lookup code", &format!("resolved {} but expected {}", resp.device_id, alice_device));
                    failed += 1;
                }
            }
            Err(e) => {
                fail("Lookup code", &e.to_string());
                failed += 1;
            }
        }
    } else {
        fail("Lookup code", "Alice has no short code");
        failed += 1;
    }

    // ── Step 4: Alice establishes session with Bob ──
    {
        let state_a = store_a.load()?;
        let mut ed = [0u8; 32];
        ed.copy_from_slice(&state_a.identity_ed_private);
        let auth_http = HttpClient::with_auth(server, state_a.device_id, &ed);

        match cmd_session(&auth_http, &store_a, &bob_device.to_string()).await {
            Ok(()) => { pass("Alice → Bob session"); passed += 1; }
            Err(e) => { fail("Alice → Bob session", &e.to_string()); failed += 1; }
        }
    }

    // ── Step 5: Alice sends message to Bob ──
    let test_msg = format!("e2e-test-{}", std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap().as_millis());
    match cmd_send(&http, &store_a, &bob_device.to_string(), &test_msg).await {
        Ok(()) => { pass("Alice sends prekey message"); passed += 1; }
        Err(e) => { fail("Alice sends", &e.to_string()); failed += 1; }
    }

    // ── Step 6: Bob receives and decrypts ──
    {
        let state_b = store_b.load()?;
        let mut ed = [0u8; 32];
        ed.copy_from_slice(&state_b.identity_ed_private);
        let auth_http = HttpClient::with_auth(server, state_b.device_id, &ed);

        match cmd_recv(&auth_http, &store_b).await {
            Ok(()) => { pass("Bob receives + decrypts"); passed += 1; }
            Err(e) => { fail("Bob receives", &e.to_string()); failed += 1; }
        }
    }

    // ── Step 7: Bob replies (using session from recv, NO session command) ──
    let reply_msg = format!("reply-{}", std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap().as_millis());
    match cmd_send(&http, &store_b, &alice_device.to_string(), &reply_msg).await {
        Ok(()) => { pass("Bob replies (same ratchet)"); passed += 1; }
        Err(e) => { fail("Bob replies", &e.to_string()); failed += 1; }
    }

    // ── Step 8: Alice receives reply ──
    {
        let state_a = store_a.load()?;
        let mut ed = [0u8; 32];
        ed.copy_from_slice(&state_a.identity_ed_private);
        let auth_http = HttpClient::with_auth(server, state_a.device_id, &ed);

        match cmd_recv(&auth_http, &store_a).await {
            Ok(()) => { pass("Alice receives reply"); passed += 1; }
            Err(e) => { fail("Alice receives reply", &e.to_string()); failed += 1; }
        }
    }

    // ── Step 9: Second round (normal messages, not prekey) ──
    let msg3 = "ratchet-step-2";
    match cmd_send(&http, &store_a, &bob_device.to_string(), msg3).await {
        Ok(()) => { pass("Alice sends normal message"); passed += 1; }
        Err(e) => { fail("Alice sends normal", &e.to_string()); failed += 1; }
    }

    {
        let state_b = store_b.load()?;
        let mut ed = [0u8; 32];
        ed.copy_from_slice(&state_b.identity_ed_private);
        let auth_http = HttpClient::with_auth(server, state_b.device_id, &ed);

        match cmd_recv(&auth_http, &store_b).await {
            Ok(()) => { pass("Bob receives normal message"); passed += 1; }
            Err(e) => { fail("Bob receives normal", &e.to_string()); failed += 1; }
        }
    }

    // ── Results ──
    println!();
    if failed == 0 {
        println!("\x1b[32m  {passed}/{passed} passed. E2E test PASSED.\x1b[0m");
    } else {
        println!("\x1b[31m  {passed}/{} passed, {failed} failed. E2E test FAILED.\x1b[0m", passed + failed);
    }
    println!();

    // Temp dirs auto-cleaned here
    Ok(())
}

async fn register_identity(
    http: &HttpClient,
    store: &IdentityStore,
    invite: &str,
) -> Result<(uuid::Uuid, Option<String>)> {
    let (account_id, auth_nonce) = http.redeem_invite(invite).await?;
    let keys = identity::KeyMaterial::generate();
    let (device_id, _cert, short_code, _screen_name) = http
        .upload_prekeys(account_id, &keys, Some(&auth_nonce))
        .await?;
    store.save(account_id, device_id, &keys)?;
    Ok((device_id, short_code))
}
