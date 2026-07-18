use std::collections::{HashSet, VecDeque};

use anyhow::Result;
use clap::{Parser, Subcommand};

use echo_client::http::HttpClient;
use echo_client::identity::{self, IdentityStore};
use echo_client::transparency;
use echo_client::wire::WireMessage;

#[cfg(feature = "e2e")]
mod e2e;

#[derive(Parser)]
#[command(name = "echo", about = "ECHO Messenger CLI — post-quantum secure messaging")]
struct Cli {
    /// Server URL (default: http://localhost:8080)
    #[arg(long, default_value = "http://localhost:8080")]
    server: String,

    /// Identity name (used to select key file, e.g. "alice" or "bob")
    #[arg(long, short)]
    identity: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Register a new account via invite code
    Register {
        /// Invite code
        #[arg(long)]
        invite: String,
    },

    /// Show this identity's device ID
    Whoami,

    /// Fetch another device's prekey bundle and establish a session
    Session {
        /// Recipient device UUID
        #[arg(long)]
        device: String,
    },

    /// Send an encrypted message via sealed sender
    Send {
        /// Recipient device UUID
        #[arg(long)]
        to: String,

        /// Message text
        #[arg(long, short)]
        msg: String,
    },

    /// Poll for and decrypt incoming messages
    Recv,

    /// Monitor own key transparency — verify server has correct keys
    Monitor,

    /// [TEST ONLY] Run full E2E test: 2 identities, short code lookup, bidirectional messaging
    #[cfg(feature = "e2e")]
    TestE2e {
        /// First invite code
        #[arg(long)]
        invite1: String,
        /// Second invite code
        #[arg(long)]
        invite2: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "echo=info".into()),
        )
        .init();

    let cli = Cli::parse();
    let http = HttpClient::new(&cli.server);
    let store = IdentityStore::new(&cli.identity)?;

    match cli.command {
        Commands::Register { invite } => cmd_register(&http, &store, &invite).await,
        Commands::Whoami => cmd_whoami(&store),
        Commands::Session { device } => {
            let state = store.load()?;
            let mut ed_bytes = [0u8; 32];
            ed_bytes.copy_from_slice(&state.identity_ed_private);
            let auth_http = HttpClient::with_auth(&cli.server, state.device_id, &ed_bytes, &state.identity_mldsa_private);
            cmd_session(&auth_http, &store, &device).await
        }
        Commands::Send { to, msg } => cmd_send(&http, &store, &to, &msg).await,
        Commands::Recv => {
            let state = store.load()?;
            let mut ed_bytes = [0u8; 32];
            ed_bytes.copy_from_slice(&state.identity_ed_private);
            let auth_http = HttpClient::with_auth(&cli.server, state.device_id, &ed_bytes, &state.identity_mldsa_private);
            cmd_recv(&auth_http, &store).await
        }
        Commands::Monitor => cmd_monitor(&http, &store).await,
        #[cfg(feature = "e2e")]
        Commands::TestE2e { invite1, invite2 } => {
            e2e::run_e2e(&cli.server, &invite1, &invite2).await
        }
    }
}

async fn cmd_register(http: &HttpClient, store: &IdentityStore, invite: &str) -> Result<()> {
    println!("Redeeming invite code...");
    let (account_id, auth_nonce) = http.redeem_invite(invite).await?;
    println!("Account: {}", account_id);

    println!("Generating identity keys...");
    let keys = identity::KeyMaterial::generate();

    println!("Uploading prekey bundle...");
    let (device_id, sender_cert, _short_code, _screen_name) = http.upload_prekeys(account_id, &keys, Some(&auth_nonce)).await?;
    println!("Device: {}", device_id);

    store.save(account_id, device_id, &keys)?;

    // Capture the real server-signed sender certificate (H1/C1): counter-sign it with our
    // Ed25519 identity key and store it, instead of relying on the legacy self-signed
    // placeholder cert (which carries a zeroed server signature and is rejected by the
    // now-mandatory server-signature check). Mirrors the GUI's auth.rs.
    if let Some(cert_bytes) = sender_cert {
        let state = store.load()?;
        if let Ok(mut cert) = bincode::deserialize::<echo_crypto::sealed_sender::SenderCertificate>(&cert_bytes) {
            let mut ed_priv = [0u8; 32];
            ed_priv.copy_from_slice(&state.identity_ed_private);
            echo_crypto::sealed_sender::countersign_sender_cert(&mut cert, &ed_priv, &state.identity_mldsa_private);
            store.save_sender_cert(&cert)?;
        }
    }
    println!("Identity saved to {}", store.path().display());
    println!("\nReady. Your device ID is: {}", device_id);

    Ok(())
}

fn cmd_whoami(store: &IdentityStore) -> Result<()> {
    let state = store.load()?;
    println!("Identity:  {}", store.name());
    println!("Account:   {}", state.account_id);
    println!("Device:    {}", state.device_id);
    println!("Ed25519:   {}", hex::encode(&state.identity_ed_public));
    println!("X25519:    {}", hex::encode(&state.identity_dh_public));
    Ok(())
}

pub(crate) async fn cmd_session(
    http: &HttpClient,
    store: &IdentityStore,
    device_str: &str,
) -> Result<()> {
    let state = store.load()?;
    let recipient_device: uuid::Uuid = device_str.parse()?;

    let last_sth = store.load_last_sth();
    let last_tree_size = last_sth.as_ref().map(|s| s.tree_size);

    println!("Fetching prekeys for {}...", recipient_device);
    let bundle = http.fetch_prekeys(state.device_id, recipient_device, last_tree_size).await?;

    // Verify key transparency
    if let Some(ref tp) = bundle.transparency {
        let ik_bytes = hex::decode(&bundle.identity_key)?;
        let idk_bytes = hex::decode(&bundle.identity_dh_key)?;

        let mut server_pubkey = store.load_server_transparency_key();
        if server_pubkey.is_none() {
            if let Ok(sth_resp) = http.fetch_sth().await {
                store.save_server_transparency_key(&sth_resp.server_public_key).ok();
                store.save_server_ml_dsa_key(&sth_resp.server_ml_dsa_public).ok();
                server_pubkey = Some(sth_resp.server_public_key);
            }
        }
        let server_ml_dsa = hex::decode(store.load_server_ml_dsa_key().unwrap_or_default()).unwrap_or_default();

        match transparency::verify_transparency(
            tp,
            &ik_bytes,
            &idk_bytes,
            last_sth.as_ref(),
            server_pubkey.as_deref(),
            &server_ml_dsa,
        ) {
            Ok(()) => {
                println!("Key transparency: VERIFIED");
                store.save_last_sth(&tp.sth)?;
            }
            Err(e) => {
                let err_str = e.to_string();
                // Consistency failure = tree grew (new devices). Clear cache, retry TOFU.
                if err_str.contains("consistency") && last_sth.is_some() {
                    eprintln!("Transparency cache stale, resetting to TOFU...");
                    store.clear_last_sth().ok();
                    match transparency::verify_transparency(
                        tp,
                        &ik_bytes,
                        &idk_bytes,
                        None,
                        server_pubkey.as_deref(),
                        &server_ml_dsa,
                    ) {
                        Ok(()) => {
                            println!("Key transparency: VERIFIED (TOFU reset)");
                            store.save_last_sth(&tp.sth)?;
                        }
                        Err(e2) => {
                            eprintln!("SECURITY: Key transparency verification FAILED: {}", e2);
                            return Err(e2);
                        }
                    }
                } else {
                    eprintln!("SECURITY: Key transparency verification FAILED: {}", e);
                    eprintln!("Session establishment BLOCKED — possible MITM attack.");
                    return Err(e);
                }
            }
        }
    } else {
        println!("Key transparency: server did not return proof (TOFU)");
    }

    println!("Running X4DH session establishment...");
    let keys = state.reconstruct_keys();

    let prekey_bundle = bundle.to_prekey_bundle()?;

    let init_result = echo_crypto::ratchet::x4dh::X4DH::initiate(
        &keys.identity_ed,
        &keys.identity_dh,
        &prekey_bundle,
    )?;

    let ratchet_state = identity::build_initiator_state(
        &keys,
        &prekey_bundle,
        &init_result,
    );

    store.save_session(
        recipient_device,
        &ratchet_state,
        &init_result,
        &prekey_bundle.identity_dh_key,
    )?;

    println!("Session established with {}", recipient_device);
    println!("  Ephemeral:  {}", hex::encode(&init_result.ephemeral_public.0));
    if init_result.used_one_time_prekey_id.is_some() {
        println!("  Used one-time prekey: yes");
    } else {
        println!("  Used one-time prekey: no (exhausted)");
    }

    Ok(())
}

pub(crate) async fn cmd_send(
    http: &HttpClient,
    store: &IdentityStore,
    to_str: &str,
    msg: &str,
) -> Result<()> {
    let state = store.load()?;
    let recipient_device: uuid::Uuid = to_str.parse()?;

    let (mut ratchet_state, mut session_meta) = store.load_session(recipient_device)?;

    let mut session = echo_crypto::ratchet::TripleRatchetSession::new(ratchet_state);
    let encrypted = session.encrypt(msg.as_bytes())?;

    let header_bytes = bincode::serialize(&encrypted.header)?;
    let wire_msg = if session_meta.needs_prekey_message {
        WireMessage::PreKey {
            sender_identity_key: state.identity_ed_public.clone(),
            sender_identity_dh_key: state.identity_dh_public.clone(),
            sender_identity_dh_signature: identity::sign_identity_dh_binding(&state),
            sender_ml_dsa_identity_key: state.identity_mldsa_public.clone(),
            sender_identity_dh_ml_dsa_signature: identity::sign_identity_dh_binding_ml_dsa(&state),
            ephemeral_public: session_meta.ephemeral_public.clone(),
            pq_ciphertext: session_meta.pq_ciphertext.clone(),
            used_one_time_prekey_id: session_meta.used_one_time_prekey_id,
            ratchet_header: header_bytes,
            encrypted_header: encrypted.encrypted_header,
            ciphertext: encrypted.ciphertext,
        }
    } else {
        WireMessage::Normal {
            ratchet_header: header_bytes,
            encrypted_header: encrypted.encrypted_header,
            ciphertext: encrypted.ciphertext,
        }
    };

    let wire_payload = bincode::serialize(&wire_msg)?;

    // Prefer the real server-signed + counter-signed cert saved at registration (H1/C1);
    // fall back to the legacy self-signed cert only for identities created before this fix.
    let cert = store.load_sender_cert()
        .unwrap_or_else(|| identity::build_sender_cert(&state));
    let envelope = echo_crypto::sealed_sender::seal_message(
        &session_meta.recipient_dh_key,
        &cert,
        &wire_payload,
    )?;

    let envelope_bytes = bincode::serialize(&envelope)?;

    http.send_message(recipient_device, &envelope_bytes).await?;

    let was_prekey = session_meta.needs_prekey_message;
    ratchet_state = session.export_state().clone();
    session_meta.needs_prekey_message = false;
    store.save_session_with_meta(recipient_device, &ratchet_state, &session_meta)?;

    let msg_type = if was_prekey { "prekey" } else { "normal" };
    println!("Sent {} bytes (sealed, {}) to {}", envelope_bytes.len(), msg_type, recipient_device);
    Ok(())
}

pub(crate) async fn cmd_recv(
    http: &HttpClient,
    store: &IdentityStore,
) -> Result<()> {
    let state = store.load()?;
    let keys = state.reconstruct_keys();

    println!("Polling messages for {}...", state.device_id);
    let messages = http.receive_messages(state.device_id).await?;

    if messages.is_empty() {
        println!("No new messages.");
        return Ok(());
    }

    println!("{} message(s) received:\n", messages.len());

    let mut ack_ids = Vec::new();

    for qm in &messages {
        let envelope_bytes = hex::decode(&qm.envelope)?;
        let envelope: echo_crypto::SealedEnvelope = match bincode::deserialize(&envelope_bytes) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("  [msg {}] failed to parse envelope: {}", qm.id, e);
                continue;
            }
        };

        // H1: Load server transparency key (required for cert verification)
        let server_pk: [u8; 32] = match store.load_server_transparency_key() {
            Some(hex_str) => {
                let bytes = hex::decode(&hex_str)?;
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                arr
            }
            None => {
                // Auto-fetch + cache the server transparency key if we've never
                // initiated a session (mirrors the GUI poller's Bug-2 fix). Without
                // this, a receiver that only registered + recv'd has no key and skips
                // every incoming message, so it can never establish a reply session.
                match http.fetch_sth().await {
                    Ok(sth_resp) => {
                        store.save_server_transparency_key(&sth_resp.server_public_key).ok();
                        store.save_server_ml_dsa_key(&sth_resp.server_ml_dsa_public).ok();
                        let bytes = hex::decode(&sth_resp.server_public_key)?;
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&bytes);
                        arr
                    }
                    Err(e) => {
                        eprintln!("  [msg {}] no server transparency key and fetch failed: {}", qm.id, e);
                        continue;
                    }
                }
            }
        };

        let server_ml_dsa_pk =
            hex::decode(store.load_server_ml_dsa_key().unwrap_or_default()).unwrap_or_default();
        let (sender_cert, inner) = match echo_crypto::sealed_sender::unseal_message(
            &keys.identity_dh,
            &envelope,
            &server_pk,
            &server_ml_dsa_pk,
        ) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("  [msg {}] failed to unseal: {}", qm.id, e);
                continue;
            }
        };

        let sender_id_hex = hex::encode(&sender_cert.sender_identity.0);
        let sender_device_id = sender_cert.sender_device_id;
        let sender_uuid = uuid::Uuid::from_bytes(sender_device_id.0);

        let wire_msg: WireMessage = match bincode::deserialize(&inner) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("  [msg {}] failed to parse wire message: {}", qm.id, e);
                continue;
            }
        };

        let (header_bytes, encrypted_header, ciphertext, prekey_data) = match wire_msg {
            WireMessage::PreKey {
                sender_identity_key,
                sender_identity_dh_key,
                sender_identity_dh_signature,
                sender_ml_dsa_identity_key,
                sender_identity_dh_ml_dsa_signature,
                ephemeral_public,
                pq_ciphertext,
                used_one_time_prekey_id,
                ratchet_header,
                encrypted_header,
                ciphertext,
            } => (
                ratchet_header,
                encrypted_header,
                ciphertext,
                Some((sender_identity_key, sender_identity_dh_key, sender_identity_dh_signature, sender_ml_dsa_identity_key, sender_identity_dh_ml_dsa_signature, ephemeral_public, pq_ciphertext, used_one_time_prekey_id)),
            ),
            WireMessage::Normal {
                ratchet_header,
                encrypted_header,
                ciphertext,
            } => (ratchet_header, encrypted_header, ciphertext, None),
        };

        let header: echo_crypto::MessageHeader = match bincode::deserialize(&header_bytes) {
            Ok(h) => h,
            Err(e) => {
                eprintln!("  [msg {}] failed to parse ratchet header: {}", qm.id, e);
                continue;
            }
        };

        let enc_msg = echo_crypto::ratchet::session::EncryptedMessage {
            header,
            encrypted_header,
            ciphertext,
        };

        let session_result = match store.load_session(sender_uuid) {
            Ok((ratchet_state, meta)) => Some((ratchet_state, meta)),
            Err(_) => None,
        };

        if let Some((ratchet_state, _meta)) = session_result {
            let mut session = echo_crypto::ratchet::TripleRatchetSession::new(ratchet_state);
            match session.decrypt(&enc_msg) {
                Ok(decrypted) => {
                    let text = String::from_utf8_lossy(&decrypted.plaintext);
                    println!("  From {}: {}", &sender_id_hex[..16], text);
                    store.update_session(sender_uuid, session.export_state())?;
                    ack_ids.push(qm.id);
                }
                Err(e) => {
                    eprintln!("  [msg {}] decrypt failed: {}", qm.id, e);
                }
            }
        } else if let Some((sender_ik, sender_dh_key, sender_dh_sig, sender_ml_dsa_ik, sender_dh_ml_dsa_sig, ephemeral_pub, pq_ct, _otpk_id)) = prekey_data {
            let mut eph = [0u8; 32];
            eph.copy_from_slice(&ephemeral_pub);
            let mut sdk = [0u8; 32];
            sdk.copy_from_slice(&sender_dh_key);

            // C4: Reconstruct sender Ed25519 identity for DH binding verification
            let sender_ed_key = if sender_ik.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&sender_ik);
                Some(echo_crypto::IdentityPublicKey(arr))
            } else {
                None
            };
            let sender_dh_sig_ref = if sender_dh_sig.is_empty() { None } else { Some(sender_dh_sig.as_slice()) };
            let sender_ml_dsa_ref = if sender_ml_dsa_ik.is_empty() { None } else { Some(sender_ml_dsa_ik.as_slice()) };
            let sender_dh_ml_dsa_sig_ref = if sender_dh_ml_dsa_sig.is_empty() { None } else { Some(sender_dh_ml_dsa_sig.as_slice()) };

            let otp_keypair = _otpk_id.and_then(|id| {
                keys.one_time_prekeys.iter().find(|(kid, _)| *kid == id).map(|(_, kp)| kp)
            });

            let x4dh_result = match echo_crypto::ratchet::x4dh::X4DH::respond(
                &keys.identity_ed,
                &keys.identity_dh,
                &keys.signed_prekey,
                otp_keypair,
                &keys.pq_sk,
                &echo_crypto::PublicKey(sdk),
                sender_ed_key.as_ref(),
                sender_dh_sig_ref,
                sender_ml_dsa_ref,
                sender_dh_ml_dsa_sig_ref,
                &echo_crypto::PublicKey(eph),
                &echo_crypto::PqCiphertext(pq_ct.clone()),
            ) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("  [msg {}] X4DH respond failed: {}", qm.id, e);
                    continue;
                }
            };

            let mut sik = [0u8; 32];
            sik.copy_from_slice(&sender_ik);

            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            let ratchet_state = echo_crypto::ratchet::state::RatchetState {
                local_identity: keys.identity_ed.public_key(),
                remote_identity: echo_crypto::IdentityPublicKey(sik),
                epoch_number: 0,
                my_epoch_pk: None,
                my_epoch_sk: None,
                peer_epoch_pk: None,
                epoch_message_count: 0,
                epoch_start_time: now,
                pending_epoch: None,
                dh_ratchet_number: 0,
                my_dh_public: keys.signed_prekey.public_key(),
                my_dh_private: Some(keys.signed_prekey.private_key_bytes()),
                peer_dh_public: Some(enc_msg.header.dh_public.clone()),
                root_key: x4dh_result.root_key.clone(),
                sending_chain_key: None,
                receiving_chain_key: Some(x4dh_result.chain_key),
                send_message_number: 0,
                recv_message_number: 0,
                prev_sending_chain_length: 0,
                // M11: Derive initial header keys (responder swaps send/recv direction)
                sending_header_key: Some(echo_crypto::crypto::kdf::derive_header_key(&x4dh_result.root_key, false)),
                receiving_header_key: Some(echo_crypto::crypto::kdf::derive_header_key(&x4dh_result.root_key, true)),
                next_sending_header_key: Some(echo_crypto::crypto::kdf::derive_header_key(&x4dh_result.root_key, false)),
                next_receiving_header_key: Some(echo_crypto::crypto::kdf::derive_header_key(&x4dh_result.root_key, true)),
                skipped_keys: std::collections::HashMap::new(),
                processed_ids: HashSet::new(),
                processed_order: VecDeque::new(),
            };

            let meta = identity::SessionMeta {
                recipient_device_id: sender_uuid,
                recipient_identity_key: sender_ik.clone(),
                recipient_dh_key: echo_crypto::PublicKey(sdk),
                ephemeral_public: ephemeral_pub,
                pq_ciphertext: pq_ct,
                used_one_time_prekey_id: None,
                needs_prekey_message: false, // Responder: session from recv, never send PreKey
            };

            let mut session = echo_crypto::ratchet::TripleRatchetSession::new(ratchet_state);
            match session.decrypt(&enc_msg) {
                Ok(decrypted) => {
                    let text = String::from_utf8_lossy(&decrypted.plaintext);
                    println!("  From {} (new session): {}", &sender_id_hex[..16], text);
                    store.save_session_with_meta(sender_uuid, session.export_state(), &meta)?;
                    ack_ids.push(qm.id);
                }
                Err(e) => {
                    eprintln!("  [msg {}] decrypt failed (new session): {}", qm.id, e);
                }
            }
        } else {
            eprintln!(
                "  [msg {}] no session for sender {} and not a prekey message",
                qm.id, &sender_id_hex[..16]
            );
        }
    }

    if !ack_ids.is_empty() {
        http.ack_messages(state.device_id, &ack_ids).await?;
        println!("\nAcked {} message(s)", ack_ids.len());
    }

    Ok(())
}

async fn cmd_monitor(
    http: &HttpClient,
    store: &IdentityStore,
) -> Result<()> {
    let state = store.load()?;
    let last_sth = store.load_last_sth();
    let last_tree_size = last_sth.as_ref().map(|s| s.tree_size);

    println!("Monitoring key transparency for device {}...", state.device_id);

    let proof = http
        .fetch_transparency_proof(state.device_id, last_tree_size)
        .await?;

    let mut server_pubkey = store.load_server_transparency_key();
    if server_pubkey.is_none() {
        if let Ok(sth_resp) = http.fetch_sth().await {
            store.save_server_transparency_key(&sth_resp.server_public_key).ok();
            store.save_server_ml_dsa_key(&sth_resp.server_ml_dsa_public).ok();
            server_pubkey = Some(sth_resp.server_public_key);
        }
    }

    if proof.leaf.identity_key != state.identity_ed_public {
        eprintln!("SECURITY ALERT: Server has DIFFERENT identity_key for your device!");
        eprintln!("  Local:  {}", hex::encode(&state.identity_ed_public));
        eprintln!("  Server: {}", hex::encode(&proof.leaf.identity_key));
        return Err(anyhow::anyhow!("Key mismatch detected — possible compromise"));
    }

    if proof.leaf.identity_dh_key != state.identity_dh_public {
        eprintln!("SECURITY ALERT: Server has DIFFERENT identity_dh_key for your device!");
        eprintln!("  Local:  {}", hex::encode(&state.identity_dh_public));
        eprintln!("  Server: {}", hex::encode(&proof.leaf.identity_dh_key));
        return Err(anyhow::anyhow!("Key mismatch detected — possible compromise"));
    }

    let server_ml_dsa = hex::decode(store.load_server_ml_dsa_key().unwrap_or_default()).unwrap_or_default();
    transparency::verify_transparency(
        &proof,
        &state.identity_ed_public,
        &state.identity_dh_public,
        last_sth.as_ref(),
        server_pubkey.as_deref(),
        &server_ml_dsa,
    )?;

    store.save_last_sth(&proof.sth)?;

    println!("Key transparency: VERIFIED");
    println!("  Tree size:     {}", proof.sth.tree_size);
    println!("  Root hash:     {}", hex::encode(&proof.sth.root_hash));
    println!("  Leaf index:    {}", proof.inclusion_proof.leaf_index);
    println!("  Identity key:  {} (matches local)", &hex::encode(&state.identity_ed_public)[..16]);
    if last_sth.is_some() {
        println!("  Consistency:   verified against cached STH");
    } else {
        println!("  Consistency:   first check (TOFU)");
    }

    Ok(())
}
