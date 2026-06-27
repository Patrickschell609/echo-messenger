# Echo Messenger — Opus 4.8 Session
## Date: June 27, 2026
## Scope: SSD/toolchain recovery, crypto hardening (Apr 21 audit H1/H2/M4), time-based send investigation

---

## TL;DR

- **Environment fix:** the SSK external SSD had dropped off the worn USB port and
  re-enumerated `sdb` → `sdc`, leaving a stale mount (`ls /mnt/xp-reborn` → I/O error)
  that broke rustup/cargo through the `~/.rustup` symlink. Fixed with `umount -l` +
  remount of `/dev/sdc2` (uid=1000,gid=1000). Toolchain healthy after.
- **B1 (chat.js UUID blocker)** — the long-standing "never works totally right" symptom.
  Was already fixed in the local working tree; committed + pushed as `35e78ff`. The
  higher-UUID side no longer hangs forever on "Connecting…".
- **Crypto hardening committed as `0d12f51`** — closes Apr 21 audit H1, H2, M4. Full
  suite green (45 unit + 15 integration + 10 transparency = 70 tests). 3 new regression
  tests lock the bypasses closed.

---

## Commits this session

| Commit | Status | Contents |
|--------|--------|----------|
| `35e78ff` | pushed to GitHub main | Local fixes: non-fatal screen-name claim (auth.rs), **B1 chat.js session race**, optional screen name (signon.js), session.rs M1 receive-side invariant |
| `0d12f51` | **local only — not pushed** | H1/H2/M4 crypto hardening + 3 regression tests |

> Note: GitHub `main` was at `8cdb45e` before this session; the local tree carried
> uncommitted fixes that were never pushed. `35e78ff` caught GitHub up; `0d12f51` is
> ahead of GitHub and awaiting a push decision.

---

## What `0d12f51` changes (Apr 21 audit closure)

**H2 — DH-binding signature now mandatory** (`shared/src/ratchet/x4dh.rs`)
- Initiator: reject prekey bundle with empty `identity_dh_key_signature` instead of
  silently skipping the C3 check. A compromised server could otherwise strip the sig
  and defeat identity binding (unknown-key-share).
- Responder: reject missing/empty DH-binding signature instead of skipping C4.

**H1 — no zero-fallback identity binding** (`x4dh.rs` responder)
- Reject prekey message missing the initiator's Ed25519 identity instead of binding the
  M8 session KDF to all-zeros (well-known constant).

**M4 — hard-fail send on missing server-signed sender cert**
(`echo-app/src-tauri/src/commands/messaging.rs` ×3 paths: send_message, send_file,
send_encrypted_payload; and `session.rs`)
- A self-built cert has `server_signature = [0u8;64]`, which the recipient's
  `unseal_message()` → `verify_sender_cert()` rejects. So shipping one silently dropped
  the message on the far end. Now returns an actionable error.
- Group send path (`groups.rs`) was already safe (Option + `if let Some`, never ships a
  self-built cert).

### ⚠️ Deployment caveat for `0d12f51`
Both boxes must run this build together. The initiator now rejects any prekey bundle
whose `identity_dh_key_sig` is empty (the server column is nullable). A device row
registered before DH-binding was signed will be rejected → that user must **re-register**.
Fresh registrations populate it, so reset boxes are fine.

---

## DIAGNOSED: time-based message send failure — THREE bugs, all detonate ~24h

**Symptom (Ghost, Jun 27):** two boxes exchange a few messages fine, but **after time
passes**, messages stop getting sent/delivered correctly.

Built an advanced "long-distance" test suite (`shared/tests/integration.rs`, Jun 27
section) that reproduces the failures: cert expiry, high-volume past the 100-msg epoch
boundary, out-of-order delivery, and a simulated 24h gap. It surfaced three distinct bugs.

### Bug #1 — sender certificate 24h expiry, never refreshed  ✅ reproduced (green test)
`server/src/api/keys.rs:283` signs the sender cert with `expiry = now + 86400` (24h). The
client saves it **only at registration** (`auth.rs:104-110`). The key-rotation path
(`poller.rs:980`) re-calls `upload_prekeys` — which returns a fresh cert — but **discards
the return value** (`if let Err(e)` only). No refresh path exists. After 24h the cached
cert is expired; the recipient's `verify_sender_cert` rejects it (`now > expiry`), the
poller ACKs+drops the message. Test: `test_expired_sender_cert_is_rejected_on_receive`.

### Bug #2 — responder's epoch PQ secret key is never initialized  ✅ confirmed in code
The initiator encapsulates its first PQ epoch ratchet to the responder's X4DH PQ prekey
(`peer_epoch_pk = bundle.pq_prekey`). But the responder builds its RatchetState with
`my_epoch_pk/sk = None` (`poller.rs:558-560`, `ffi_api.rs:474-476`). So when the epoch
ratchet fires (100 msgs / 24h), `epoch_ratchet_receive` errors with "no local PQ secret
key" → message dropped. **Fix:** responder must set `my_epoch_pk/sk` to its X4DH PQ
prekey pair (which it already holds as `keys.pq_pk`/`keys.pq_sk`).

### Bug #3 — epoch ratchet root desync after a turn-around  🔶 reproduced (ignored tests)
The deep one, and the best match for the symptom. After Bob replies once, the standard
double ratchet leaves Alice's `root_key` one KDF-step **ahead** of Bob's (her
`dh_ratchet_receive` pre-derives the next sending chain; Bob only catches up on his next
receive). `decrypt()` applies `epoch_ratchet_receive` (PQ mix into root, line 192)
**before** the DH step that resyncs the roots — so Alice mixes the PQ secret at root N+1
while Bob mixes at root N. Every subsequent chain key diverges → silent `DecryptionFailed`.
Only safe when no reply has happened yet (roots still equal), which is why short bursts
work and a day of back-and-forth breaks.
- `test_epoch_ratchet_first_message_minimal` — PASSES (roots synced, epoch works).
- `test_epoch_ratchet_after_24h_gap`, `test_long_distance_endurance_with_reordering` —
  `#[ignore]`d, reproduce the desync. Run `cargo test -- --ignored`.
**Likely fix:** reorder so the epoch PQ mix is applied to the root *after* the DH ratchet
resyncs both sides (mirror the same order on send). Needs careful protocol design — do
NOT ship blind.

### Status
- Diagnosis complete; tests committed as executable reproductions (suite green by
  default, reproducers under `--ignored`).
- **No product fix applied yet** — bugs #2 and #3 are crypto-core protocol changes
  awaiting Ghost's sign-off. Bug #1 needs a client-side cert-refresh path
  (re-fetch + save the cert the server already returns on key rotation).

---

## Remaining audit items (lower priority)
- **M1** — migrate `pqcrypto-kyber` → `ml-kem` (FIPS 203). Breaks existing sessions.
- **M2** — README Argon2 line says 256MB/4; code is 64MB/3/1. Fix README.
- **L1** — sweep server `.unwrap()`s (ws/mod.rs, api/keys.rs, api/screen_names.rs).
- **M3** — enforce MIME allowlist at receive time, not just preview.

---

*Compiled by Claude Opus 4.8 (1M context) on June 27, 2026*
