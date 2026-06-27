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
- **Bugs #1, #2, #3 ALL FIXED.** Full suite green: 45 unit + 22 integration + 10
  transparency = 77 tests; whole workspace compiles.

### Fix for #1 — sender cert refresh (poller.rs)
New `check_and_refresh_sender_cert()` runs every poll cycle (cheap expiry check; network
only when needed). If the cached cert is missing or within 6h of its 24h expiry, it
re-fetches from the server (idempotent re-upload of the CURRENT keys — Ed25519 sigs are
deterministic so they reproduce; no rotation, no OTP changes), counter-signs (C1), and
saves the fresh cert to the vault. Wired into both the WS and polling loop branches next to
`check_and_rotate_keys`. (Rotation runs every 7 days — far too slow for a 24h cert, which
is why a dedicated expiry-driven refresh was needed.) Not unit-tested (needs a live server,
like the rest of poller.rs); the crypto-level expiry rejection is covered by
`test_expired_sender_cert_is_rejected_on_receive`.

### Fix for #2 — responder epoch keypair (poller.rs)
`echo-app/src-tauri/src/poller.rs` responder RatchetState now sets
`my_epoch_pk = PqPublicKey(identity_state.pq_pk)`, `my_epoch_sk = keys.pq_sk` (its X4DH PQ
prekey pair) instead of `None`. The dormant Flutter FFI builder (`ffi_api.rs`) has a TODO
comment — fix it the same way if Flutter is revived (no active callers today).

### Fix for #3 — lazy DH ratchet + folded PQ (shared/src/ratchet/session.rs)
Converted the DH ratchet from **eager to lazy**: `dh_ratchet_receive` no longer pre-derives
the next sending chain (it clears it; the next send ratchets from a root the peer shares).
This removes the root asymmetry that desynced the epoch ratchet. The PQ epoch secret is now
**folded into the DH ratchet's root step** via the existing `kdf_root_combined` (one KDF on
both sides) instead of a separate `kdf_epoch` + extra DH step. `dh_ratchet_send` /
`dh_ratchet_receive` take an `Option<&[u8]>` PQ secret; `epoch_ratchet_send`/`_receive` were
replaced by `dh_ratchet_send_epoch` + inline receive handling in `decrypt`. The responder
also DEFERS an epoch ratchet until it holds the peer's epoch key (self-heals; no error).

**Known limitation:** the PQ KEM ciphertext rides on a single message, so messages within an
epoch transition must be delivered in order (intra-chain reordering elsewhere is fine via
skipped keys). Inherent to single-ciphertext PQ ratchets; transport delivers the queue in
order. Covered by `test_long_distance_endurance` (in-order, crosses epoch on both sides) +
`test_out_of_order_within_chain` (intra-chain reordering).

### ⚠️ Deployment note for #2/#3
This changes the wire/ratchet behavior of the epoch ratchet. Both boxes must run the new
build together; in-flight sessions established under the old (broken) epoch logic should be
re-established (they would never have survived an epoch ratchet anyway).

---

## Epoch ratchet robustness (commit `b41db4c`) — found while hardening the out-of-order edge

Looking hard at the epoch path (Ghost: "this is a touchy spot, heart of it") surfaced TWO
more flaws beyond #3, both reproduced by tests before fixing:

### A) Ordering — KEM ciphertext on a single message
The epoch KEM ciphertext rode on one message, so a post-epoch message arriving BEFORE the
epoch trigger couldn't derive the new chain (unlike the 32-byte DH key, which is stamped on
every message). **Fix (sticky advertisement):** the initiator re-stamps the epoch material
(`ct` + new epoch pk) on every message until the peer acks it — ack = an incoming
`epoch_number >= ours`, read off normal traffic (no dedicated handshake, never blocks on an
offline peer). New `RatchetState.pending_epoch` holds it. Any message of the new epoch can
now drive the peer's transition; the receiver is idempotent and recovers earlier messages
via skipped keys. Test: `test_epoch_transition_out_of_order`.

### B) Alternation — same side ratcheting twice in a row
The same side could epoch-ratchet consecutively (e.g. a one-directional 200-message burst),
re-encapsulating to a peer epoch key the peer had already rotated away → desync at the 2nd
boundary. The bidirectional endurance test hid it (epochs alternated naturally). **Fix
(alternation gate):** `peer_epoch_pk` is nulled once consumed by an outgoing epoch ratchet
and only refilled when the peer epoch-ratchets back — so a side may only initiate while
holding a fresh peer key, mirroring how the DH ratchet alternates. Test:
`test_one_directional_burst_crosses_epoch` (was failing at msg 200).

**Why no other messenger hits this:** classic Double Ratchet has no continuous PQ layer
(nothing to reorder); Signal's continuous PQ ratchet (SPQR) hits the same wall and chunks +
reliably reassembles the KEM ciphertext. Our ciphertext fits in one message, so the sticky
re-stamp is the lightweight equivalent. Known residual: messages within an epoch transition
must arrive in order relative to *each other* only up to the sticky window — covered.

CLI caveat: `cli/src/main.rs` responder still has `my_epoch=None` (POC test client, same gap
the old poller had; not the production path).

---

## Remaining audit items (lower priority)
- **M1** — migrate `pqcrypto-kyber` → `ml-kem` (FIPS 203). Breaks existing sessions.
- **M2** — README Argon2 line says 256MB/4; code is 64MB/3/1. Fix README.
- **L1** — sweep server `.unwrap()`s (ws/mod.rs, api/keys.rs, api/screen_names.rs).
- **M3** — enforce MIME allowlist at receive time, not just preview.

---

*Compiled by Claude Opus 4.8 (1M context) on June 27, 2026*
