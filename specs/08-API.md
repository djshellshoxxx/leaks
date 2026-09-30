# 08 — API Specification

Status: Draft v1.0 · Edition applicability: both (EE-only APIs marked **EE**) · Owner: Backend + Client teams

## 1. Purpose and scope

This document defines every network and IPC API exposed by Candor server components. Each API family is listed below with the section that specifies it.

| API family | Listener | Section |
|---|---|---|
| Source Web (HTML forms) | C-06, onion | §4 |
| Source App API | C-06, onion | §5 |
| Relay pull protocol | C-08 export endpoint | §6 |
| Key Directory / transparency API | C-14, via C-06 snapshot and Desk API | §7 |
| Desk API (recipient) | C-10 | §8 |
| Admin API | C-10 admin listener | §9 |
| Export Package API (connector side, **EE**) | C-10 | §10 |
| Health API | C-25 | §11 |
| Fleet Manager API (**EE**) | C-34 | §12 |
| SIEM export API (**EE**) | C-26 | §13 |

For every endpoint the tables give:
- METHOD and PATH;
- AUTHORIZATION;
- INPUT and OUTPUT;
- RATE LIMIT;
- ERROR BEHAVIOR;
- SENSITIVE DATA;
- LOGGING RULE;
- SECURITY REQUIREMENTS.

Common rules (§3) apply to every endpoint unless a row overrides them. Internal IPC (sealer and intake-store) is specified in 07-BACKEND.md §5.2–5.3.

## 2. Context and dependencies

| Document | Relationship |
|---|---|
| DECISIONS.md ADR-004/005/010/011/015/017/018/026/029 | Binding decisions |
| 06-SYSTEM-ARCHITECTURE.md | Listeners, trust boundaries, flows |
| 07-BACKEND.md | Implementation of routers, limits, error mapping, logging |
| 09-DATABASE.md | Persistence for each endpoint |
| 04-CRYPTOGRAPHY.md | Envelope, STREAM, signatures, key-wrap formats referenced as `EnvelopeHeaderCt`, `ManifestCt`, `WrapCt`, etc. |
| 14-CASE-MANAGEMENT.md; 15-AUTHENTICATION-AUTHORIZATION.md | Action names and policy semantics used in the AUTHORIZATION column |
| 20-LOGGING-AUDITING.md | Event names in the LOGGING column |
| 11-FRONTEND-SOURCE.md; 12-FRONTEND-RECIPIENT.md; 13-FRONTEND-ADMIN.md | Consumers |

## 3. Common conventions

### 3.1 Listeners, audiences and credentials

| Family | Listener | Audience (ADR-029) | Credential | Transport |
|---|---|---|---|---|
| Source Web | `/run/candor/web/http.sock` behind the source onion | `source-web` | `__Host-cs` session cookie (RAM session in C-06) | Tor onion, HTTP/1.1 |
| Source App | same socket, prefix `/app/v1/` | `source-app` | `Authorization: CandorSource <token>` (RAM session in C-06, distinct map and type from web sessions) | Tor onion (Arti), HTTP/1.1 |
| Relay | intake TCP 7443 | machine: `relay` (mTLS SAN) | pinned mTLS + `Candor-Relay-Sig` | TLS 1.3 |
| Key Directory | served through the Source App (`/app/v1/directory/*`), Source Web (`/keys`) and Desk API (`/desk/v1/kd/*`) | inherits host family | inherits | inherits |
| Desk API | desk.sock (RCP-ONION) or TCP 8443 (RCP-LAN) | `desk-api` | `Authorization: CandorDesk <access_token>` + `Candor-PoP` device signature + onion client-auth or mTLS client certificate | TLS 1.3 or onion |
| Admin API | admin.sock (separate onion) or TCP 9443 | `admin-api` | `Authorization: CandorAdmin <access_token>` + `Candor-PoP` + client certificate/onion auth | TLS 1.3 or onion |
| Export (connector) **EE** | TCP 8445, core internal network | machine: `connector` (mTLS SAN) | mTLS client certificate per connector instance | TLS 1.3 |
| Health collector | monitor TCP 8514 | machine: `agent` | mTLS per host | TLS 1.3 |
| SIEM gateway **EE** | C-26 TCP 8515 (in), customer SIEM (out) | machine: `audit-exporter`, `siem-client` | mTLS | TLS 1.3 / syslog-TLS |
| Fleet **EE** | vendor or customer C-34 TCP 443 | machine: `fleet-agent` | mTLS (instance certificate issued at enrollment) | TLS 1.3 |

**Token binding (ADR-029):**
- Every user token is a 256-bit random opaque value. It is stored server-side as `SHA-256(token)` with `{audience, tenant_id, principal_id, device_id, issued_at, expires_at, auth_strength}`.
- A token presented to a listener of another audience is rejected as if unknown (401, uniform).
- Web and app source sessions live in separate RAM maps with distinct Rust types. The cookie is never accepted on `/app/v1/*`, and the bearer token is never accepted on HTML routes (INC-105).
- Machine identities are mTLS SANs of the form `urn:candor:<role>:<tenant_id>:<instance_id>`. They are never accepted on user-audience listeners.

**Desk/Admin token lifetimes:**
- access token 15 min;
- refresh token 12 h, rotating and single-use, bound to `device_id`;
- step-up proof 5 min, single use per action.

**`Candor-PoP` header:**
- Value: `v1.<device_key_id>.<unix_s>.<nonce_b64u>.<sig_b64u>`, where `sig = Ed25519(device_key, "candor-pop-v1" ‖ method ‖ path_with_query ‖ sha256(body) ‖ unix_s ‖ nonce)`.
- The server requires `|now − unix_s| ≤ 60 s` and rejects a nonce seen within 120 s.
- The device key is the Desk device identity key (hardware-bound where possible; 15-AUTHENTICATION-AUTHORIZATION.md).

### 3.2 Identifiers

- All resource IDs are **random 128-bit** values from the OS CSPRNG, encoded as lowercase RFC 4648 base32 without padding (26 chars), with a 2-letter type prefix and underscore. Examples: `cs_…` case, `ev_…` evidence, `ch_…` channel, `rg_…` routing group, `us_…` user, `ex_…` export, `ie_…` import envelope, `jb_…` job, `bg_…` break-glass.
- There are no sequential, time-ordered (UUIDv1/v7, Snowflake) or content-derived public IDs.
- Human-facing case references (e.g., `K7Q-4MX2`) are random 40-bit display codes, unique per tenant. They are never accepted as API keys for lookup across tenants.
- Source-facing flows expose **no** resource IDs of cases, submissions or recipients.
- Cursors are opaque AEAD-encrypted tokens (server key, per audience) containing `{last_sort_key, filter_hash, principal_id, expiry}`. A cursor minted for another principal or filter is rejected as invalid.

### 3.3 Enumeration and IDOR resistance

- For any resource-bound route, "does not exist", "exists in another tenant" and "exists but caller not authorized" SHALL all produce the **same** response:
  - status **404**, body `{"error":"not_found"}` (Desk/Admin/Export/Relay), or the static 404 page (Source Web);
  - identical headers;
  - response time within the same timing class (DB lookup always performed; authorization decision computed after lookup; constant-work denial path).
- 403 is returned only when the caller is already authorized to *see* the resource but lacks the specific action (07-BACKEND.md §5.6).
- List endpoints filter silently. Counts reflect only visible items.
- Rows are always loaded by `(tenant_id, id)` under RLS. IDs from a path are never trusted to imply tenant.

### 3.4 Error model

| Audience | Format | Codes |
|---|---|---|
| Source Web | Static padded HTML page per class: `400`, `404`, `busy` (429/503), `500`. Error pages contain no echo of input. | Status code + page class |
| Source App | `{"error": "<code>"}` with codes `bad_request`, `unauthorized`, `not_found`, `too_large`, `busy`, `gone`, `conflict`, `internal`; padded to 1 KiB | as listed |
| Desk/Admin/Export | `{"error": "<code>", "retry": bool}` with codes `bad_request`, `unauthorized`, `step_up_required`, `forbidden`, `not_found`, `conflict`, `precondition_failed`, `too_large`, `rate_limited`, `unavailable`, `internal` | as listed |
| Relay/Health/Fleet/SIEM | Same as Desk | — |

No error message contains stack traces, SQL, file paths, IDs from the request, or any input value (07-BACKEND.md §8).

### 3.5 Versioning

- The path version (`/app/v1`, `/desk/v1`, `/admin/v1`, `/relay/v1`, `/kd/v1`, `/export/v1`) is the major version. Additive changes (new optional fields, new endpoints) do not change it. Unknown fields in **requests** are rejected (`deny_unknown_fields`). Clients ignore unknown fields in responses except where marked `critical`.
- Servers support major N and N−1 for ≥ 12 months after N ships.
- Desk and Source App send `Candor-Client: <product>/<semver>`. The server returns `426` with `{"error":"upgrade_required","min":"x.y.z"}` if below the minimum published in C-14 `CLIENT_RELEASE` entries.
- The Source Web has no version negotiation (server-rendered).

### 3.6 Content types and size

- JSON (`application/json`, UTF-8, RFC 8259, no duplicate keys — rejected) for Desk/Admin/Export/Health/Fleet/SIEM metadata. Deterministic CBOR (`application/cbor`) for Source App, Relay and Key Directory objects that are signed or hashed.
- Binary blobs use `application/octet-stream`. Blobs are always ciphertext.
- Body limits are in 07-BACKEND.md §11.

### 3.7 CSRF (Source Web only; other audiences use non-cookie credentials)

- Synchronizer token (256-bit) per session and per form in a hidden field `csrf`, compared in constant time.
- `SameSite=Strict` cookie.
- The `Origin` header must be absent, `null`, or equal to the serving onion origin. The `Referer` header is not used (`no-referrer`).
- State-changing routes are POST only. GET routes are side-effect-free (logout is POST).

### 3.8 Response padding (ADR-011)

| Family | Rule |
|---|---|
| Source Web | Every HTML response is padded to its route's class (16/32/64/128 KiB) with an HTML comment of random printable bytes (not compressible, since compression is off). Wrong-passphrase and inbox responses share class 64 KiB. |
| Source App | JSON/CBOR responses padded to the next multiple of 4 KiB (≥ 4 KiB), with a `pad` field of random bytes. Blob downloads are already bucketed. |
| Mailbox lists | Always return exactly `N_fixed = 32` entries; the real ones plus dummies indistinguishable at the ciphertext level (dummy reply ciphertexts under a random key) |
| Desk/Admin | Not padded (authenticated staff; 06 §13) |

### 3.9 Legend for tables

- **Sensitive:** SS = SOURCE-SENSITIVE, CT = content ciphertext, WF = workflow metadata, SEC = security data, SYS = system.
- **Log:** `none` = no event of any kind; `SEC:x` / `CASE:x` / `SYS:x` = typed event name (20-LOGGING-AUDITING.md); `CTR:x` = SOURCE-SENSITIVE daily counter only.
- **Rate:** per circuit token (source families), per user (Desk/Admin), per machine identity (machine families). "G:" = additional global bucket.
- **AuthZ** column uses action names from 15-AUTHENTICATION-AUTHORIZATION.md, e.g., `case.read`. "member(case)" = the caller has an active ACL entry on the case. "pub" = no authentication.

### 3.10 Security headers

**Source Web (all responses):**
```
Content-Security-Policy: default-src 'none'; style-src 'self'; img-src 'self'; font-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'; script-src 'none'; connect-src 'none'; object-src 'none'; manifest-src 'none'; worker-src 'none'; media-src 'none'
Referrer-Policy: no-referrer
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Embedder-Policy: require-corp
Cross-Origin-Resource-Policy: same-origin
Origin-Agent-Cluster: ?1
Permissions-Policy: accelerometer=(), ambient-light-sensor=(), autoplay=(), battery=(), camera=(), display-capture=(), document-domain=(), encrypted-media=(), fullscreen=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), midi=(), payment=(), picture-in-picture=(), publickey-credentials-get=(), screen-wake-lock=(), serial=(), usb=(), web-share=(), xr-spatial-tracking=(), clipboard-read=(), clipboard-write=(), interest-cohort=()
Cache-Control: no-store, max-age=0
Pragma: no-cache
X-Robots-Tag: noindex, nofollow, noarchive
Content-Type: text/html; charset=utf-8
```

Rules:
- No `Server`, `Date`, `ETag`, `Last-Modified`, `Set-Cookie` except the session cookie, or `Alt-Svc`.
- Omitting `Date` deviates from RFC 9110 §6.6.1 on purpose, to avoid exposing server clock skew. [Knowledge (unverified): clock-skew-based onion-service fingerprinting.]
- **WEBCAT-verified bundle (optional, `intake.tier_v.webcat_bundle.enabled`):** served only under `/v/` with `script-src 'self' 'wasm-unsafe-eval'; connect-src 'self'` and the enrollment manifest required by WEBCAT (B-CR-37, B-CR-40). The no-JS routes keep `script-src 'none'`.
- Logout additionally sends `Clear-Site-Data: "cache", "cookies", "storage"`.

**Desk/Admin/Export APIs:** `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, `Content-Type` exact. No CORS headers: requests with an `Origin` header are rejected, because the Desk uses a native HTTP client, not a browser origin.

## 4. Source Web (Tier W, HTML forms, audience `source-web`)

Family defaults:
- Rate: 60 req/min/circuit, burst 20, plus G: 600 req/s.
- Errors: static padded pages (§3.4).
- Sensitive: all request bodies are SS or content.
- Log: `none` unless stated.
- Security: headers §3.10, padding §3.8, no JS required, no external resources, no redirects to other origins, no URL changes that record state (no IDs in URLs).

| ID | Method Path | AuthZ | Input | Output | Rate | Errors | Sensitive | Log | Security |
|---|---|---|---|---|---|---|---|---|---|
| SW-01 | GET `/` | pub | — | Landing: mode statement (ANONYMOUS/CONFIDENTIAL/IDENTIFIED per channel), protection statement (06 ARCH-036), Tier W honesty statement, links to channels and `/verify` | default | 500 page | none | none | Pad 32 KiB; `lang` via `?l=xx` only from the allow-list |
| SW-02 | GET `/c/{channel_id}` | pub | `channel_id` | Channel description, routing (COI) options as checkboxes, "Start" form | default | 404 page (unknown or disabled channel) | none | none | Channel IDs are published values; disabled channels 404 |
| SW-03 | POST `/new` | pub + CSRF (pre-session token issued by SW-02 in a session-less signed hidden field, 10-min validity) | `csrf`, `channel_id`, `coi_flags[]` (≤ 16 u16) | Sets `__Host-cs`; page shows the 10-word passphrase once, with the confirmation form | 6/10 min/circuit; G: 600/h new accounts | busy page | SS (passphrase) | CTR:`accounts_started` | Passphrase never in URL or title; `autocomplete=off`; page pad 32 KiB |
| SW-04 | POST `/new/confirm` | session(PENDING_NEW) + CSRF | `csrf`, `w3`, `w7` (two words re-typed) | Redirect-free render of the submit form | default | same page with generic error | SS | none | Constant-time compare |
| SW-05 | POST `/submit/message` | session + CSRF | `csrf`, `text` ≤ 64 KiB UTF-8 | Draft page listing parts as "Message (n KB bucket)" | default | 413 page | content | none | Streamed to sealer (07 §5.2); no disk |
| SW-06 | POST `/submit/file` | session + CSRF | multipart: `csrf`, `file` (1 part) ≤ `intake.max_file_bytes` | Draft page | 30/h/circuit | 413 or 400 page; draft keeps prior parts | content; filename SS | none | Parser enforces the part allow-list before forwarding (INC-107); filename sealed in manifest |
| SW-07 | POST `/submit/remove` | session + CSRF | `csrf`, `part_index` (u8) | Draft page | default | 400 page | none | none | Part index local to session |
| SW-08 | POST `/submit/send` | session + CSRF | `csrf`, `identity_disclosure` (optional text ≤ 4 KiB for CONFIDENTIAL/IDENTIFIED; sealed to Identity Custodian keys, ADR-014) | Confirmation page (no IDs, no time) | 10/h/circuit | busy/500 page; draft retained ≤ 2 h | content; SS | CTR:`submissions_tier_w` | `NO_EPOCH_KEY` → busy page (no fallback) |
| SW-09 | GET `/login` | pub | — | Login form | default | — | none | none | Pad 16 KiB |
| SW-10 | POST `/login` | pub + CSRF | `csrf`, `passphrase` ≤ 256 B | Inbox (SW-11 render) or wrong-passphrase page, both in pad class 64 KiB | 5/10 min/circuit; G: Argon2id 4 concurrent | busy page | SS | CTR:`logins` | 2 s floor timing; uniform challenge (07 BE-010); new session ID issued (fixation-proof) |
| SW-11 | GET `/inbox` | session(AUTHENTICATED) | — | Replies decrypted in sealer and rendered as escaped text; day-granular dates; own messages as "sent on YYYY-MM-DD" | default | 404 page if not authenticated | content | none | No read receipts sent anywhere (ADR-010) |
| SW-12 | POST `/inbox/message` | session + CSRF | `csrf`, `text` ≤ 64 KiB | Inbox | 20/h/circuit | 413 page | content | CTR:`followups` | Follow-up envelope `kind=followup` with the same `thread_tag` |
| SW-13 | POST `/inbox/file` | session + CSRF | multipart `csrf`, `file` | Inbox with draft part | 30/h/circuit | 413 page | content | none | as SW-06 |
| SW-14 | POST `/inbox/reply-delete` | session + CSRF | `csrf`, `reply_index` (u8, index in the padded list) | Inbox | default | 400 page | none | none | Deletion local to intake; not reported to core |
| SW-15 | POST `/account/delete` | session + CSRF + re-entry of passphrase | `csrf`, `passphrase` | "Account deleted" page | 3/h/circuit | wrong-passphrase page | SS | CTR:`account_deletions` | Deletes the account record and mailbox in C-08. Already relayed submissions are unaffected (explained on the page). |
| SW-16 | POST `/logout` | session + CSRF | `csrf` | Landing | default | — | none | none | `Clear-Site-Data`; sealer `ZEROIZE` |
| SW-17 | GET `/keys` | pub | — | Human-readable channel key fingerprints, directory checkpoint, witness status, current client release hashes | default | — | none | none | Renders from the verified snapshot only |
| SW-18 | GET `/verify` | pub | — | Instructions for verifying the Source App and the onion address | default | — | none | none | Static |
| SW-19 | GET `/static/{sha256}.{css\|woff2\|svg}` | pub | hash | Asset | G only | 404 | none | none | Immutable; `Cache-Control: no-store` still sent (no disk cache on source device) |
| SW-20 | GET `/robots.txt` | pub | — | `Disallow: /` | G | — | none | none | — |

There are no other paths. Any unlisted path returns the SW 404 page (same bytes as SW-02 unknown).

## 5. Source App API (Tier V, audience `source-app`)

Family defaults:
- Rate: 120 req/min/circuit, burst 40; G: 1,000 req/s.
- Response padding to 4 KiB multiples.
- Errors per §3.4.
- Log: `none` unless stated.
- All objects are deterministic CBOR.
- The app uses a **fresh Tor circuit (new SOCKS isolation token) per logical operation group** (one for directory fetch, one per upload session, one for mailbox), so that operations are not trivially linkable at the circuit level (THR-047; 11-FRONTEND-SOURCE.md).

| ID | Method Path | AuthZ | Input | Output | Rate | Errors | Sensitive | Log | Security |
|---|---|---|---|---|---|---|---|---|---|
| SA-01 | GET `/app/v1/directory/checkpoint` | pub | — | Signed checkpoint + witness cosignatures + snapshot version | default | `busy` | none | none | Client verifies against pinned directory root and witnesses (§7) |
| SA-02 | GET `/app/v1/directory/channel/{channel_id}` | pub | `channel_id` | `{channel_identity entry, routing_map entry, epoch_keys per routing group (current + next), inclusion proofs, protection_statement}` | default | 404 uniform | none | none | Same response for unknown and disabled channels |
| SA-03 | GET `/app/v1/directory/consistency?from={size}` | pub | tree size | Consistency proof to the current checkpoint | default | 400 | none | none | Detects forks between app visits |
| SA-04 | GET `/app/v1/releases` | pub | — | Latest `CLIENT_RELEASE` entries with inclusion proofs | default | — | none | none | App refuses to run if its own hash is not logged or is below minimum |
| SA-05 | POST `/app/v1/auth/challenge` | pub | `{locator_hash: bytes32}` | `{challenge: bytes32, ch_id: bytes16}` (valid 60 s, single use) | 10/10 min/circuit | `busy` | SS | none | Uniform for unknown locators (07 BE-010) |
| SA-06 | POST `/app/v1/auth/session` | pub | `{ch_id, locator_hash, sig: bytes64}` | `{token: bytes32, expires_in: 1800}` | 5/10 min/circuit | `unauthorized` (uniform, 2 s floor) | SS | CTR:`logins` | Token audience `source-app`, RAM only, idle 20 min, absolute 2 h |
| SA-07 | POST `/app/v1/accounts` | pub + `pow` (optional app-level PoW when `intake.pow.app_level.enabled`: Equi-X solution over server-provided seed) | `{locator_hash, auth_pk: bytes32, xwing_pk: bytes1216, pow?}` | `201 {}` | 3/h/circuit; G: 600/h | `conflict` (locator exists; same body size as success, 409) | SS | CTR:`accounts_started` | Account is "pending" until the first envelope commit references it (SA-12). Pending accounts are purged after 1 epoch day. |
| SA-08 | POST `/app/v1/uploads` | pub (no session required; §5.1) | `{upload_id: bytes32 = SHA-256(U), chunk_count: u16 ≤ 1024, padded_size_bucket: u8}` | `201 {chunk_size: 4194304}` | 20/h/circuit; G: 2,000 pending | `busy`, `too_large` | none | none | No link to any account or session |
| SA-09 | PUT `/app/v1/uploads/{upload_id}/chunks/{n}` | capability: `Candor-Chunk-Mac: HMAC-SHA256(K_U, upload_id ‖ n ‖ sha256(body))` where `K_U = HKDF(U, "candor-upload-mac")`; `K_U` is registered by the first chunk request as `mac_key_commit = SHA-256(K_U)` in SA-08 | body = ciphertext chunk ≤ 4 MiB | `204` | 600/h/circuit | `not_found` (unknown upload), `conflict` (chunk already stored with a different digest), `too_large` | CT | none | Idempotent for identical chunk re-sends; MAC verified before storing |
| SA-10 | GET `/app/v1/uploads/{upload_id}` | capability MAC over `upload_id ‖ "status"` | — | `{received: bitmap}` | 60/h/circuit | `not_found` | none | none | Resumption from any circuit/session with no account linkage |
| SA-11 | DELETE `/app/v1/uploads/{upload_id}` | capability MAC | — | `204` | default | `not_found` | none | none | Abandon |
| SA-12 | POST `/app/v1/envelopes` | session token OR pub for one-shot mode (no reply capability) | `{kind, channel_id, routing_group_id, epoch_key_id, header_ct ≤ 8 KiB, manifest_ct ≤ 64 KiB, parts: [{upload_id, mac_proof}] ≤ 32, account_locator_hash?}` | `201 {}` (no ID, no time) | 10/h/circuit | `bad_request` (non-canonical), `gone` (epoch key too old), `not_found` (upload incomplete) | CT; SS (linkage) | CTR:`submissions_tier_v` | Canonical validation (07 BE-049); upload proofs verified; binds uploads to the envelope, and only now to the account |
| SA-13 | GET `/app/v1/mailbox` | session | — | `{items: [{slot: u8, ct_len_bucket}] × 32}` (fixed 32; dummies included) | 30/h/token | `unauthorized` | SS | none | Fixed-count list (§3.8) |
| SA-14 | GET `/app/v1/mailbox/{slot}` | session | slot 0–31 | `reply_ct` (bucketed; dummy slots return random ciphertext of a bucketed size) | 120/h/token | `not_found` for out-of-range only | CT | none | No fetch state recorded or propagated (ADR-010) |
| SA-15 | DELETE `/app/v1/mailbox/{slot}` | session | slot | `204` | default | as SA-14 | none | none | Dummy slots accept delete silently |
| SA-16 | POST `/app/v1/logout` | session | — | `204` | default | — | none | none | Token removed from the RAM map synchronously |
| SA-17 | DELETE `/app/v1/account` | session + fresh signature over `"delete" ‖ challenge` | `{ch_id, sig}` | `204` | 3/h/circuit | `unauthorized` | SS | CTR:`account_deletions` | As SW-15 |
| SA-18 | GET `/app/v1/pow/seed` | pub | — | `{seed: bytes32, effort: u32}` | default | — | none | none | Only when app-level PoW is enabled |

### 5.1 Resumable upload protocol and THR-047 analysis

**Design:**
1. The client generates a 256-bit secret `U` per upload and computes:
   - `upload_id = SHA-256("candor-upload-id" ‖ U)`;
   - `K_U = HKDF-SHA256(U, info="candor-upload-mac")`;
   - `mac_key_commit = SHA-256(K_U)`.
2. SA-08 registers `upload_id` and `mac_key_commit`.
3. Chunks carry an HMAC under `K_U`. The first chunk request also reveals `K_U` in header `Candor-Upload-Key`, and the server checks it against the commit and keeps `K_U` for verification. Only a holder of `U` can add chunks.
4. `U` and `upload_id` are **per upload**. They are never derived from the source passphrase, account keys or other uploads.
5. Uploads carry no session token. The server cannot link an upload to an account until SA-12 commits the envelope.
6. Chunk records store no time. Only `created_epoch_day` exists per upload, and uploads expire after 3 epoch days (07 §6.3).

| Linkage question | Answer | Residual |
|---|---|---|
| Can the server link two chunk requests to the same upload? | Yes, by `upload_id`. This is inherent to resumption. | The circuits used for one upload are linkable to each other. Mitigation: the app finishes uploads in as few sessions as possible. |
| Can it link two uploads to each other before commit? | No. They have independent `U` and no shared token. Circuit tokens are not persisted. | A network observer may correlate by timing (THR-003). |
| Can it link an upload to a source account? | Only at SA-12 commit, which is the same moment the envelope is linked to the account anyway. | none beyond the envelope↔account link that already exists (09 §9) |
| Can it link uploads across different envelopes? | No shared identifiers. `thread_tag` is inside the ciphertext. | Size buckets and the same day can correlate weakly |
| Does resumption state reveal time? | Only `created_epoch_day` | Day-level |
| Could a malicious server tag or track the client via upload responses? | Responses are fixed-shape. The app ignores unknown fields and never stores server-provided identifiers on disk (11-FRONTEND-SOURCE.md). | App-side storage of `U` for resumption is encrypted in the app's vault and deleted after commit |

## 6. Relay pull protocol (intake export endpoint, machine audience `relay`)

Family defaults:
- AuthZ: mTLS SAN = pinned relay identity for this intake instance, plus a valid `Candor-Relay-Sig` with strictly increasing `req_counter` (07 §5.4).
- Rate: 1 cycle in flight; 20 req/s.
- Errors: uniform JSON; 401 on signature failure (connection closed).
- Log: `SYS:relay_request{op, outcome}` (no IDs).
- Security: TLS 1.3 only, `TLS_CHACHA20_POLY1305_SHA256` or `TLS_AES_256_GCM_SHA384` (FIPS profile), no session resumption, no redirects.

| ID | Method Path | AuthZ | Input | Output | Rate | Errors | Sensitive | Log | Security |
|---|---|---|---|---|---|---|---|---|---|
| RL-01 | GET `/relay/v1/health` | relay | — | `{status: ok\|degraded, store_free_bucket, pending_bucket}` | default | — | SYS | SYS | — |
| RL-02 | POST `/relay/v1/batches/claim` | relay | `{max_objects ≤ 500, max_bytes ≤ 2 GiB}` | `{batch_no, objects: [{ref: bytes16, kind, channel_id, routing_group_id, epoch_key_id, received_epoch_day, header_len, manifest_len, parts: [{padded_size}], sha256}]}` | 1 in flight | `conflict` if a batch is unacked (returns the same batch) | CT; SS (day, routing group) | SYS | `ref` is intake-local, valid only for this batch |
| RL-03 | GET `/relay/v1/batches/{batch_no}/objects/{ref}/{part}` | relay | `part` = `header`, `manifest` or index | ciphertext stream | default | `not_found` | CT | none | Streaming; relay verifies digest |
| RL-04 | POST `/relay/v1/batches/{batch_no}/ack` | relay | `{committed: [sha256]}` | `{deleted: u32}` | default | `bad_request` if a digest is not in the batch | none | SYS | Intake deletes only matching digests (BE-014) |
| RL-05 | POST `/relay/v1/replies` | relay | `{replies: [{routing_ct ≤ 2 KiB, reply_ct ≤ 70,000 B}] ≤ 500}` | `{accepted: u32, rejected: [index]}` | default | `bad_request` | CT; routing SS-sealed | SYS | Intake decrypts `routing_ct` with the routing key; `available_epoch_day = today` |
| RL-06 | POST `/relay/v1/directory-snapshot` | relay | signed snapshot (CBOR) | `204` | default | `bad_request` (invalid signature or consistency) | none | SEC:`kd_snapshot_rejected` on failure | Intake verifies the signature chain and consistency from the previous snapshot |
| RL-07 | POST `/relay/v1/config` | relay | signed config bundle | `204` | default | `bad_request` | SEC | SEC:`config_applied`/`config_rejected` | Verification per 07 §7.1 at intake |
| RL-08 | POST `/relay/v1/deletions` | relay | `{reply_purge_before_day}` (retention) | `{purged: u32}` | daily | — | none | SYS | Only retention-driven; no targeted source deletion API exists from core |
| RL-09 | GET `/relay/v1/counters?day={d}` | relay | day | `{day, counters: {name: value_or_"<5"}}` | daily | `not_found` | SS aggregate | none | k-suppression at source (BE-030) |
| RL-10 | GET `/relay/v1/backup-snapshot` | relay | — | opaque ciphertext (encrypted to the Backup Key) + `{sha256, size}` | daily | `not_found` if not ready | CT | SYS | Core cannot read it |

There is intentionally **no** endpoint to query a source account, look up a mailbox, or list replies by account. Core never addresses sources directly (06 §14).

## 7. Key Directory / transparency API (C-14)

Served:
- to Desk as `/desk/v1/kd/*` (Desk auth);
- to Source App as `/app/v1/directory/*` (§5, from the intake snapshot);
- to witnesses and auditors (**optional**) via a read-only mirror published by an operator-chosen static host (no write path).

The formats below are shared.

| ID | Method Path | AuthZ | Input | Output | Rate | Errors | Sensitive | Log | Security |
|---|---|---|---|---|---|---|---|---|---|
| KD-01 | GET `/desk/v1/kd/checkpoint` | desk session | — | Signed note checkpoint `{origin, tree_size, root_hash}` + cosignatures | 60/min | — | none | none | Desk pins origin key and witness keys |
| KD-02 | GET `/desk/v1/kd/entries?start={i}&end={j}` | desk session | range ≤ 1,000 | Entries (CBOR) | 60/min | `bad_request` | none | none | Entries are public-key material and signed statements only |
| KD-03 | GET `/desk/v1/kd/proof/inclusion?leaf={hash}&size={n}` | desk session | leaf hash, tree size | Audit path | 600/min | `not_found` | none | none | — |
| KD-04 | GET `/desk/v1/kd/proof/consistency?old={m}&new={n}` | desk session | sizes | Proof | 600/min | `bad_request` | none | none | Desk stores the last verified checkpoint and requires consistency on every sync |
| KD-05 | GET `/desk/v1/kd/lookup/user/{user_id}` | desk session + `directory.read` | user_id | Current `USER_KEY` entries + inclusion proofs | 600/min | 404 uniform | none | none | Tenant-scoped; cross-tenant 404 |
| KD-06 | GET `/desk/v1/kd/lookup/channel/{channel_id}` | desk session | channel_id | Channel identity, routing map, epoch keys + proofs | 600/min | 404 uniform | none | none | — |
| KD-07 | POST (internal Unix only) `APPEND(entry, approvals)` | `candor-case` peer only | entry + approval records | `{leaf_index}` | n/a | codes | SEC | SEC:`kd_append` | Not network-exposed; approvals verified per entry type (07 §5.10) |
| KD-08 | Outbound: POST `{witness_url}/add-checkpoint` | directory key | checkpoint + consistency proof | cosignature | per checkpoint | retry | none | SYS | Witness protocol per 04-CRYPTOGRAPHY.md. [Knowledge (unverified): C2SP tlog-witness.] |

**Entry common fields:** `{type, tenant_id, subject_id, keys, valid_from_day, valid_until_day, prev_entry_hash (per subject), signer_key_id, sig}`. Entries never contain names or email addresses of users (display names are delivered separately via Desk API to authorized users). This keeps the log publishable without a staff directory.

## 8. Desk API (audience `desk-api`)

Family defaults:
- AuthZ: valid access token (`desk-api`, tenant) + `Candor-PoP` + transport credential.
- Rate: 600 req/min/user, burst 100; blob routes 120/min.
- Errors per §3.4 with uniform 404 (§3.3).
- Log: every content-bearing read emits `CASE:<object>_read`; every mutation emits the CASE/SECURITY event named.
- Security: `If-Match` on mutations of versioned resources; `Idempotency-Key` on POST.

### 8.1 Authentication and session (C-21)

| ID | Method Path | AuthZ | Input | Output | Rate | Errors | Sensitive | Log | Security |
|---|---|---|---|---|---|---|---|---|---|
| DA-01 | POST `/desk/v1/auth/webauthn/begin` | transport credential only | `{username}` | WebAuthn request options (challenge 32 B, allowCredentials for the user or a **deterministic fake list** for unknown users) | 10/min/device-cert; 20/h/username | `rate_limited` | SEC | none | User enumeration resistance |
| DA-02 | POST `/desk/v1/auth/webauthn/finish` | as DA-01 | assertion, `device_key_id`, device attestation | `{access_token, refresh_token, expires_in: 900}` | as DA-01 | `unauthorized` (uniform) | SEC | SEC:`login_ok` / `login_failed` | UV required; sign-count check; token bound to device key |
| DA-03 | POST `/desk/v1/auth/refresh` | refresh token + PoP | — | new pair (rotation) | 60/h | `unauthorized` → client re-auth | SEC | SEC:`token_refresh` (sampled 1/10) | Refresh reuse detection revokes the family |
| DA-04 | POST `/desk/v1/auth/logout` | access token | — | `204` | — | — | SEC | SEC:`logout` | Synchronous revocation of access and refresh tokens (INC-105) |
| DA-05 | POST `/desk/v1/auth/stepup/begin` | access token | `{action}` | WebAuthn options | 20/h | — | SEC | none | — |
| DA-06 | POST `/desk/v1/auth/stepup/finish` | access token | assertion | `{stepup_proof, expires_in: 300, action}` | 20/h | `unauthorized` | SEC | SEC:`stepup` | Single use, bound to action and resource |
| DA-07 | GET `/desk/v1/me` | access | — | profile, roles, routing groups, device list, notification settings | default | — | WF | none | — |
| DA-08 | PUT `/desk/v1/me/notification-settings` | access | `{mode: digest\|daily, contact_ref}` | `200` | 10/h | `bad_request` | SEC | SEC:`notif_settings_changed` | Contact addresses validated; changes notify the old contact (content-free) |

### 8.2 Sync, keys and devices

| ID | Method Path | AuthZ | Input | Output | Rate | Errors | Sensitive | Log | Security |
|---|---|---|---|---|---|---|---|---|---|
| DA-10 | GET `/desk/v1/sync?cursor={c}` | access | cursor | `{events: [{type, resource_id, version}], cursor}` for resources visible to the caller only | 120/min | `bad_request` (cursor) | WF | none | Events computed through C-22. Removal events are sent when access is lost, with no details. |
| DA-11 | POST `/desk/v1/devices/enroll` | enrollment token (one-time, 24 h, from admin invite) + transport | `{device_key_pk, identity_pk, xwing_pk, attestation?}` | `{device_id, status: pending_approval}` | 5/h | `unauthorized` | SEC | SEC:`device_enroll_requested` | Keys appear in C-14 only after admin approval (AP-06) |
| DA-12 | POST `/desk/v1/devices/{device_id}/revoke` | access + step-up (own device) | — | `204` | 5/h | 404 uniform | SEC | SEC:`device_revoked` | Appends `USER_KEY_REVOKE`; triggers the re-key reminder for the user's cases |
| DA-13 | GET `/desk/v1/channels/{channel_id}/epoch-keys/wrapped` | routing-group member | — | `[{epoch_key_id, wrap_ct}]` for caller's key | 60/h | 404 uniform | CT | CASE:`epoch_wrap_fetch` | Private epoch keys only as wraps to the caller |
| DA-14 | POST `/desk/v1/channels/{channel_id}/epoch-keys` | `channel.keygen` (routing-group member flagged key-steward) + step-up | `{routing_group_id, epochs: [{epoch_key_id, start_day, end_day, pk, sig_by_channel_identity, wraps: [{recipient_key_id, wrap_ct}]}] ≤ 8}` | `201` | 10/day | `conflict` (overlap), `bad_request` (wrap set ≠ group membership) | CT | SEC:`epoch_keys_published` | Server checks the wrap set equals current group members' keys (THR-046); appends KD entries |
| DA-15 | POST `/desk/v1/channels/{channel_id}/epoch-keys/{epoch_key_id}/destroy-ack` | group member | — | `204` | — | 404 | SEC | SEC:`epoch_destroy_ack` | Records that the client deleted its local copy |

### 8.3 Intake and triage

| ID | Method Path | AuthZ | Input | Output | Rate | Errors | Sensitive | Log | Security |
|---|---|---|---|---|---|---|---|---|---|
| DA-20 | GET `/desk/v1/intake/envelopes?routing_group={rg}&cursor={c}` | `intake.list` on routing group (membership) | filters | `[{import_envelope_id, channel_id, routing_group_id, epoch_key_id, received_epoch_day, parts: [{padded_size}], state}]` | 120/min | — | WF; SS (day) | CASE:`intake_list` | Only groups the caller belongs to; COI-excluded users never belong |
| DA-21 | GET `/desk/v1/intake/envelopes/{id}/header` | `intake.read` | — | `header_ct`, `manifest_ct` | 600/h | 404 uniform | CT | CASE:`intake_read` | — |
| DA-22 | GET `/desk/v1/intake/envelopes/{id}/parts/{n}` | `intake.read` | Range header allowed | ciphertext stream | 120/min | 404 uniform | CT | CASE:`intake_part_read` | Desk writes via `candor-safefs` only (ADR-027) |
| DA-23 | POST `/desk/v1/intake/envelopes/{id}/triage` | `intake.triage` | `{decision: import\|spam\|duplicate, target_case_id?}` + `If-Match` | `200 {state}` | 120/h | 404, 409 | WF | CASE:`intake_triaged` | Spam: blobs purged after 30 days unless reversed; `duplicate` links to a visible case only |
| DA-24 | POST `/desk/v1/cases/eligibility` | `case.create` in channel | `{channel_id, routing_group_id, department_id?}` | `{eligible: [{user_id, key_ids}], excluded_count_bucket}` | 60/h | 404 | WF | CASE:`eligibility_computed` | COI applied (ADR-015). Excluded identities are not returned. |

### 8.4 Cases

| ID | Method Path | AuthZ | Input | Output | Rate | Errors | Sensitive | Log | Security |
|---|---|---|---|---|---|---|---|---|---|
| DA-30 | POST `/desk/v1/cases` | `case.create` | `{channel_id, import_envelope_ids[] ≤ 32, workflow_def_id, record_ct ≤ 256 KiB, key_epoch: 1, wraps: [{recipient_key_id, wrap_ct}], dek_rewraps: [{import_envelope_id, part, rewrap_ct}], sealed_identity_ct?}` | `201 {case_id, display_ref, version}` | 60/h | `bad_request` (wrap set ≠ eligible set: BE-018), 404 (envelope not visible) | CT; WF | CASE:`case_created` | Server validates the eligible set at commit; envelopes → `imported` |
| DA-31 | GET `/desk/v1/cases?filter…&cursor` | `case.list` (ACL-filtered) | filters: state, channel, due_before_day, assigned_to_me | `[{case_id, display_ref, state, priority, channel_id, received_epoch_day, sla_due_day, version, record_ct}]` | 120/min | — | WF; CT | CASE:`case_list` (count bucket only) | No existence leak for non-member cases |
| DA-32 | GET `/desk/v1/cases/{case_id}` | member(case) + `case.read` | — | case row + my `wrap_ct` + members summary | 600/min | 404 uniform | CT; WF | CASE:`case_read` | — |
| DA-33 | PATCH `/desk/v1/cases/{case_id}` | member + `case.update` | allow-listed fields only: `{priority?, labels_ct?, record_ct?}` + `If-Match` | `200 {version}` | 120/h | 400 (unknown field), 409, 404 | CT; WF | CASE:`case_updated{fields}` | Per-role field allow-lists (INC-112) |
| DA-34 | POST `/desk/v1/cases/{case_id}/transitions` | member + transition-specific action | `{transition_id, reason_code?, If-Match}` | `200 {state, version}` | 60/h | 409 (invalid from state), 403, 404 | WF | CASE:`case_transition` | Workflow definition enforced server-side (14-CASE-MANAGEMENT.md) |
| DA-35 | GET `/desk/v1/cases/{case_id}/members` | member | — | `[{user_id, access_level, via, valid_until_day}]` | 120/min | 404 | WF | none | — |
| DA-36 | POST `/desk/v1/cases/{case_id}/members` | member(lead) + `case.share` + step-up | `{user_id, access_level, valid_until_day?, wrap: {recipient_key_id, wrap_ct}}` | `201` | 30/h | 403 (COI-excluded: returns **404** for the *user* to avoid revealing the COI list; see note), 409 | CT; WF | CASE:`member_added` | C-22 re-evaluates COI (ARCH-024); wrap key must be current |
| DA-37 | DELETE `/desk/v1/cases/{case_id}/members/{user_id}` | member(lead) + `case.share` | — | `204` + `rekey_recommended: true` | 30/h | 404 | WF | CASE:`member_removed` | Removal revokes server-side access immediately |
| DA-38 | POST `/desk/v1/cases/{case_id}/rekey` | member(lead) | `{key_epoch: n+1, wraps[], If-Match}` | `200` | 10/day | 400 (wrap set), 409 | CT | CASE:`case_rekeyed` | New content uses the new key; old wraps kept for old content unless crypto-erasure is requested |
| DA-39 | GET `/desk/v1/cases/{case_id}/records?cursor` | member + `case.read` | cursor | `[{record_id, kind, seq, created_day, author_user_id?, size_bucket, record_ct}]` | 600/min | 404 | CT | CASE:`records_read` | Exact staff times only inside `record_ct` (07 §12) |
| DA-40 | POST `/desk/v1/cases/{case_id}/records` | member + `case.note` | `{kind: note\|task\|decision, record_ct ≤ 256 KiB, key_epoch}` | `201 {record_id, seq}` | 300/h | 404, 400 | CT | CASE:`record_added{kind}` | — |
| DA-41 | POST `/desk/v1/cases/{case_id}/replies` | member + `case.reply` | `{reply_ct ≤ 70,000 B, routing_ct ≤ 2 KiB, record_ct (copy for case history)}` | `202` | 60/h | 404, 403 (channel has no reply capability), 400 | CT | CASE:`reply_queued` | Replies queued to `reply_outbox`; delivered on the next relay cycle; no delivery or read status is ever returned |
| DA-42 | POST `/desk/v1/cases/{case_id}/coi-declarations` | member (self) | `{declaration: conflict\|no_conflict}` | `204` | 10/h | 404 | WF | CASE:`coi_declared` | A self-declared conflict removes the declarant's access immediately and triggers a re-key recommendation |
| DA-43 | POST `/desk/v1/cases/{case_id}/legal-holds` | `legal_hold.place` + step-up | `{reason_ct}` | `201 {hold_id}` | 10/day | 404 | WF | CASE:`legal_hold_placed` | Blocks crypto-erasure |
| DA-44 | DELETE `/desk/v1/cases/{case_id}/legal-holds/{hold_id}` | `legal_hold.release` + second approver | `{approval_proof}` | `204` | 10/day | 404, 403 | WF | CASE:`legal_hold_released` | Dual control |
| DA-45 | POST `/desk/v1/cases/{case_id}/deletion-requests` | member(lead) + `case.delete` + step-up | `{reason_code}` | `202 {request_id}` | 10/day | 404, 409 (legal hold) | WF | CASE:`deletion_requested` | Second approver required (DA-46); then `crypto_erase_case` job |
| DA-46 | POST `/desk/v1/deletion-requests/{request_id}/approve` | `case.delete.approve`, distinct user + step-up | — | `202` | 10/day | 404, 403 | WF | CASE:`deletion_approved` | — |
| DA-47 | GET `/desk/v1/cases/{case_id}/audit?cursor` | `case.audit.read` (case lead, auditor role) | cursor | CASE events for the case (pseudonymous actors resolvable by the auditor role only) | 60/min | 404 | WF; SEC | CASE:`audit_viewed` | Viewing the audit is itself audited |
| DA-48 | GET `/desk/v1/sla/summary` | access | — | `[{case_id, timer_kind, due_day, state}]` for member cases | 60/min | — | WF | none | — |

Note on DA-36: when the target user is COI-excluded, the server returns `404 not_found` for the target (as if the user did not exist in the eligible universe). A generic "cannot add this member" banner is shown. The COI registry is not exposed to case members (14-CASE-MANAGEMENT.md).

### 8.5 Evidence

| ID | Method Path | AuthZ | Input | Output | Rate | Errors | Sensitive | Log | Security |
|---|---|---|---|---|---|---|---|---|---|
| DA-50 | GET `/desk/v1/cases/{case_id}/evidence?cursor` | member + `evidence.list` | — | `[{evidence_id, kind: original\|derivative, derived_from?, padded_size, meta_ct, version}]` | 600/min | 404 | CT | CASE:`evidence_list` | — |
| DA-51 | GET `/desk/v1/cases/{case_id}/evidence/{evidence_id}/blob` | member + `evidence.read` (originals may require `evidence.read_original`) | Range | ciphertext stream | 120/min | 404 uniform | CT | CASE:`evidence_read` | Desk writes via `candor-safefs`; opened only in C-17 |
| DA-52 | POST `/desk/v1/cases/{case_id}/evidence/uploads` | member + `evidence.add` | `{padded_size, chunk_count}` | `{upload_id, chunk_size: 8 MiB}` | 60/h | 404 | none | none | — |
| DA-53 | PUT `/desk/v1/evidence-uploads/{upload_id}/chunks/{n}` | uploader only | ciphertext chunk | `204` | 1,200/h | 404, 409 | CT | none | Upload is bound to user + case + upload_id |
| DA-54 | POST `/desk/v1/cases/{case_id}/evidence` | member + `evidence.add` | `{upload_id, kind: derivative, derived_from, transformation_record_ct, meta_ct, key_epoch}` | `201 {evidence_id}` | 120/h | 404, 400 | CT | CASE:`evidence_added{kind}` | Originals are immutable; derivatives must reference an existing object (ADR-012) |
| DA-55 | DELETE `/desk/v1/cases/{case_id}/evidence/{evidence_id}` | derivative: author + `evidence.remove`; original: **not permitted** (case-level deletion only) | — | `204` | 30/h | 404, 403 | WF | CASE:`evidence_removed` | — |

### 8.6 Sealed identity (ADR-014)

| ID | Method Path | AuthZ | Input | Output | Rate | Errors | Sensitive | Log | Security |
|---|---|---|---|---|---|---|---|---|---|
| DA-60 | POST `/desk/v1/cases/{case_id}/identity-unseal-requests` | member(lead) + `identity.request` + step-up | `{legal_basis_code, justification_ct}` | `201 {request_id}` | 5/day | 404 | SS; WF | CASE:`identity_unseal_requested` | — |
| DA-61 | POST `/desk/v1/identity-unseal-requests/{id}/approve` | `identity.approve` (Identity Custodian), distinct from requester + step-up | — | `200` | 20/day | 404, 403 | SEC | CASE:`identity_unseal_approved` | Second custodian approval if configured |
| DA-62 | GET `/desk/v1/cases/{case_id}/sealed-identity` | Identity Custodian after approval | — | `sealed_identity_ct` (wrapped to custodian keys) | 10/day | 404 | SS (ct) | CASE:`identity_unsealed` | Custodian decrypts and re-shares via a case record per policy; source-notice obligation tracked (14-CASE-MANAGEMENT.md) |

### 8.7 Break-glass

| ID | Method Path | AuthZ | Input | Output | Rate | Errors | Sensitive | Log | Security |
|---|---|---|---|---|---|---|---|---|---|
| DA-70 | POST `/desk/v1/breakglass/requests` | `breakglass.request` + step-up; not COI-excluded | `{case_id, reason_code, legal_basis_ct, duration_hours ≤ 72}` | `201 {request_id}` | 3/day | 404 (case unknown **or** excluded) | WF | SEC:`breakglass_requested` + CASE | Notifies all case members and approvers (content-free) |
| DA-71 | POST `/desk/v1/breakglass/requests/{id}/approve` | `breakglass.approve`, distinct user and role + step-up | — | `200 {state: approved_pending_wrap}` | 10/day | 404, 403 | WF | SEC:`breakglass_approved` | — |
| DA-72 | POST `/desk/v1/breakglass/requests/{id}/wrap` | existing member(case) | `{wrap: {recipient_key_id, wrap_ct}}` | `200 {state: active}` | 10/day | 404, 400 | CT | CASE:`breakglass_key_wrapped` | Grant marked `via=breakglass`, visible in all member views |
| DA-73 | GET `/desk/v1/breakglass/requests/{id}` | requester, approver, case members, reviewer | — | state machine view | 60/min | 404 | WF | none | — |
| DA-74 | POST `/desk/v1/breakglass/requests/{id}/review` | `breakglass.review` (independent reviewer role, not requester or approver) | `{outcome: justified\|unjustified, notes_ct}` | `200` | 20/day | 404, 403 | WF | SEC:`breakglass_reviewed` | Overdue > 7 days escalates |

### 8.8 Exports (Desk side)

| ID | Method Path | AuthZ | Input | Output | Rate | Errors | Sensitive | Log | Security |
|---|---|---|---|---|---|---|---|---|---|
| DA-80 | POST `/desk/v1/cases/{case_id}/exports` | member + `export.create` (`export.create_original` for originals) | `{kind: redacted\|original, destination: {type: media\|connector, connector_id?}, manifest_ct, package_digest, upload_id}` | `201 {export_id, state: pending_approval}` | 20/day | 404, 403 | CT | CASE:`export_created{kind,dest_type}` | Package is ciphertext to the destination key (connector key in C-14, or media passphrase-derived key) |
| DA-81 | GET `/desk/v1/exports/{export_id}` | creator, approvers, case lead | — | metadata, approvals, delivery status | 60/min | 404 | WF | none | — |
| DA-82 | POST `/desk/v1/exports/{export_id}/approvals` | `export.approve`, distinct from creator + step-up | `{decision: approve\|reject, digest_confirmed}` | `200 {state}` | 50/day | 404, 403, 409 (digest mismatch) | WF | CASE:`export_approval` | Originals need 2 approvals from distinct users (ADR-012, ADR-018) |
| DA-83 | GET `/desk/v1/exports/{export_id}/blob` | creator, only in state `approved`, destination=media | — | ciphertext | 5/day | 404 | CT | CASE:`export_downloaded` | Desk writes to LUKS media via `candor-safefs` |

## 9. Admin API (audience `admin-api`)

Family defaults:
- AuthZ: admin-api token + PoP + transport credential + an admin-family role.
- Rate: 120 req/min/user.
- Errors per §3.4.
- Log: every call emits a SECURITY event.
- Security: **no route returns case records, key wraps, evidence, envelope ciphertext or sealed identity** (ARCH-012). DANGEROUS items follow 07 §7.2.

| ID | Method Path | AuthZ | Input | Output | Rate | Errors | Sensitive | Log | Security |
|---|---|---|---|---|---|---|---|---|---|
| AP-01 | POST `/admin/v1/auth/webauthn/{begin,finish}`, `/refresh`, `/logout`, `/stepup/{begin,finish}` | as DA-01..06 with the admin audience | as DA | as DA | as DA | as DA | SEC | SEC:`admin_login_*` | Separate credential registrations from Desk use are allowed but tokens never cross audiences |
| AP-02 | GET `/admin/v1/users?cursor` | `user.list` | filters | `[{user_id, display_name, status, roles, devices}]` | default | — | SEC | SEC:`user_list` | — |
| AP-03 | POST `/admin/v1/users` | `user.invite` + step-up | `{display_name ≤ 128, username, contact_ref}` | `201 {user_id, enrollment_token (shown once)}` | 50/day | 409 (username) | SEC | SEC:`user_invited` | — |
| AP-04 | PATCH `/admin/v1/users/{user_id}` | `user.update` | allow-list `{display_name?, contact_ref?}` + `If-Match` | `200` | default | 400 (unknown field), 404 | SEC | SEC:`user_updated{fields}` | Cannot touch keys, roles or credentials here (INC-112) |
| AP-05 | POST `/admin/v1/users/{user_id}/disable` | `user.disable` + step-up | `{reason_code}` | `204` | default | 404 | SEC | SEC:`user_disabled` | Revokes sessions synchronously; recommends re-keys for the user's cases |
| AP-06 | POST `/admin/v1/devices/{device_id}/approve` | `device.approve` + step-up; a privileged-role user's device needs a second admin | `{fingerprint_confirmed}` | `200` | default | 404, 409 | SEC | SEC:`device_approved` | Appends `USER_KEY` to C-14 (THR-046); out-of-band fingerprint confirmation required |
| AP-07 | GET `/admin/v1/roles` | `role.list` | — | roles + permissions | default | — | SEC | none | Built-in roles immutable |
| AP-08 | POST `/admin/v1/role-assignments` | `role.assign` + step-up; privileged roles (breakglass.approve, identity custodian, auditor) need a second admin | `{user_id, role_id, scope_type, scope_id, valid_until_day?}` | `201 {assignment_id}` | default | 404, 409 (SoD conflict) | SEC | SEC:`role_assigned` | Separation-of-duties rules enforced (15-AUTHENTICATION-AUTHORIZATION.md); admins cannot grant themselves case access roles |
| AP-09 | DELETE `/admin/v1/role-assignments/{id}` | `role.assign` | — | `204` | default | 404 | SEC | SEC:`role_revoked` | — |
| AP-10 | GET/POST/PATCH `/admin/v1/channels[/{id}]` | `channel.manage`; mode change away from ANONYMOUS = DANGEROUS | `{public_label, description_i18n, mode, workflow_def_id, retention_policy_id, reply_enabled}` | channel | default | 400, 404, 409 | SEC | SEC:`channel_*` | Changes go into the signed config bundle + protection statement |
| AP-11 | GET/POST/PATCH `/admin/v1/channels/{id}/routing-groups[/{rg}]` | `routing.manage` + step-up | `{label, member_user_ids[]}` | group | default | 409 (member COI-excluded for the group's purpose) | SEC | SEC:`routing_group_*` | Membership change requires new epoch keys generated by a key steward (DA-14) |
| AP-12 | PUT `/admin/v1/channels/{id}/coi-map` | `coi.manage` + step-up + second admin | `{flags: [{flag_id, label_i18n, excluded_role_ids[], routing_group_id}]}` | `200 {kd_leaf}` | 10/day | 400 | SEC | SEC:`coi_map_changed` | Appended to C-14 as `ROUTING_MAP`; source-visible |
| AP-13 | POST/PUT `/admin/v1/workflows[/{id}]`, POST `/admin/v1/workflows/{id}/publish` | `workflow.manage` | definition (states, transitions, SLA rules) | `{def_id, version}` | 20/day | 400 (invalid graph) | WF | SEC:`workflow_published` | Versioned; running cases keep their version |
| AP-14 | GET/POST/PATCH `/admin/v1/retention-policies[/{id}]` | `retention.manage` (ADVANCED) | `{retain_days, action, legal_basis_code}` | policy | 20/day | 400 | WF | SEC:`retention_policy_*` | Shortening an in-use policy requires a second admin |
| AP-15 | GET `/admin/v1/config` | `config.read` | — | current bundle (items + classes) | default | — | SEC | none | — |
| AP-16 | POST `/admin/v1/config/changes` | `config.propose` + step-up | `{items: {key: value}}` | `201 {change_id, class, effective_after}` | 20/day | 400 (unknown key or range) | SEC | SEC:`config_proposed{class}` | Class computed server-side from the catalog, never from input |
| AP-17 | POST `/admin/v1/config/changes/{id}/approve` | `config.approve`, distinct admin + step-up | `{signature}` (admin signing key over the bundle) | `200 {state}` | 20/day | 404, 403 | SEC | SEC:`config_approved` | DANGEROUS: 2 signatures + 72 h |
| AP-18 | POST `/admin/v1/config/changes/{id}/cancel` | any admin or auditor | — | `200` | — | 404 | SEC | SEC:`config_cancelled` | — |
| AP-19 | GET `/admin/v1/audit/security?cursor` | `audit.security.read` | filters | SECURITY events | 60/min | — | SEC | SEC:`audit_viewed` | — |
| AP-20 | GET `/admin/v1/audit/checkpoints` | `audit.verify` | — | signed checkpoints | default | — | SEC | none | For external verification |
| AP-21 | GET `/admin/v1/health/summary` | `health.read` | — | per-host check status | default | — | SYS | none | — |
| AP-22 | GET `/admin/v1/reports/aggregates?from_day&to_day` | `reports.read` | range ≥ 7 days | counts by channel with k ≥ 5 suppression, day-bucketed ≥ week | 10/h | 400 (range < 7 d) | SS aggregate | SEC:`aggregate_viewed` | THR-039; no drill-down |
| AP-23 | POST `/admin/v1/recovery-quorum/enable` | DANGEROUS (2 admins) | `{quorum_pk, k, n, holder_role_labels[]}` | `202` | — | 400 | SEC | SEC:`recovery_quorum_change` | Published in C-14 (ADR-013) |
| AP-24 | POST `/admin/v1/intake/onion-rotation` | DANGEROUS | `{ceremony_id}` | `202` | — | — | SEC | SEC:`onion_rotation` | Coordinated with C-37 publication (16-TOR-I2P.md) |
| AP-25 | POST `/admin/v1/backups/run`; GET `/admin/v1/backups` | `backup.operate` | — | job / list with age and verify status | 5/day | — | SYS | SEC:`backup_run` | No restore via API; restore is `candorctl` dual-control offline (19-BACKUPS-DR.md) |
| AP-26 | GET `/admin/v1/updates`; POST `/admin/v1/updates/stage`; POST `/admin/v1/updates/apply` | `update.operate` (apply = ADVANCED + step-up) | `{target_version}` | status | 10/day | 409 (TUF verification failed) | SYS | SEC:`update_*` | Only TUF-verified, transparency-logged targets |
| AP-27 | POST `/admin/v1/support-bundles` | `support.bundle` + step-up | `{sections[] from an allow-list}` | bundle (SYSTEM data only, scrubbed; shown for local inspection before any sending) | 5/day | — | SYS | SEC:`support_bundle_created` | No DB dumps, no logs with IDs, no config secrets (INC-56) |
| AP-28 | POST `/admin/v1/tenants` (**EE**) | not exposed; `candorctl root-maint` only | — | — | — | 404 on the API | — | — | Cross-tenant operations never via API (INC-113) |

## 10. Export Package API — connector side (**EE**, machine audience `connector`)

| ID | Method Path | AuthZ | Input | Output | Rate | Errors | Sensitive | Log | Security |
|---|---|---|---|---|---|---|---|---|---|
| EX-01 | GET `/export/v1/packages?state=approved&cursor` | connector mTLS SAN; only packages whose `destination.connector_id` = caller | cursor | `[{export_id, package_digest, size, kind}]` | 60/min | — | WF | SYS | Connector sees only its own packages |
| EX-02 | GET `/export/v1/packages/{export_id}/blob` | as EX-01; state ∈ {approved} | — | ciphertext (encrypted to the connector key) | 60/h | 404 uniform | CT (plaintext after connector decrypts) | CASE:`export_fetched` | Connector key is registered in C-14 as a dedicated `CONNECTOR_KEY` entry (open issue O-2) |
| EX-03 | POST `/export/v1/packages/{export_id}/receipts` | as EX-01 | `{status: delivered\|failed, target_ref_hash}` | `204` | — | 404 | WF | CASE:`export_delivered` | Receipt recorded; blob deleted after `delivered` |

## 11. Health API

| ID | Method Path | AuthZ | Input | Output | Rate | Errors | Sensitive | Log | Security |
|---|---|---|---|---|---|---|---|---|---|
| HE-01 | Local Unix `/run/candor/health/agent.sock` `SELFTEST` | root or `candor-health` peer | — | check results | — | — | SYS | none | Local only |
| HE-02 | POST `https://monitor:8514/collector/v1/events` | agent mTLS SAN `urn:candor:agent:<tenant>:<host_role>:<host_id>` | `{events: [HealthEvent] ≤ 500}` (07 §5.11 schema) | `204` | 60/min/agent | `bad_request` (schema) → dropped + SYS | SYS | SYS (collector-local) | Schema-strict; host identity from the certificate, not the payload (INC-103) |
| HE-03 | GET `https://monitor/dashboard/v1/summary` | admin mTLS or local | — | aggregated status | — | — | SYS | none | Read-only; no write API on the monitor |

**Not provided:** any health endpoint on the source onion (information leakage; REQ-H-34).

## 12. Fleet Manager API (**EE**, C-34)

Direction: the instance's fleet agent (in Z-CORE) → C-34 outbound only. There is no inbound connection to customer instances (ARCH-032).

| ID | Method Path | AuthZ | Input | Output | Rate | Errors | Sensitive | Log | Security |
|---|---|---|---|---|---|---|---|---|---|
| FL-01 | POST `/fleet/v1/instances/{opaque_instance_id}/heartbeat` | instance mTLS (certificate issued at enrollment; SAN carries opaque ID) | `{versions: {component: semver}, profile, health: {check_id: status}, license_id}` | `{desired_version?, notices[]}` | 1/15 min | `unauthorized` | SYS | vendor SYS | **No** onion address, hostnames, IPs, tenant names, counts or users |
| FL-02 | GET `/fleet/v1/instances/{id}/desired-state` | as FL-01 | — | Signed (vendor fleet key) document `{target_version, safe_config_templates{}}` | 1/h | — | SYS | none | Instance applies only SAFE-class items automatically. Anything else becomes a proposal in AP-16 for local admins. Target versions must also verify via TUF (ADR-022). |
| FL-03 | POST `/fleet/v1/instances/{id}/support-bundles` | as FL-01 + local admin approval token | bundle from AP-27 | `201 {ticket_ref}` | 5/day | — | SYS | vendor SEC | Admin reviews bundle content before upload |
| FL-04 | Fleet console: GET `/fleet/v1/instances`, POST `/fleet/v1/rollouts` | customer or vendor fleet operators (OIDC + WebAuthn) | rollout plan (version, cohort %) | rollout | — | — | SYS | vendor SEC | Rollouts can only select among signed releases identical for all customers (ADR-022) |

## 13. SIEM export API (**EE**, C-26)

| ID | Method Path | AuthZ | Input | Output | Rate | Errors | Sensitive | Log | Security |
|---|---|---|---|---|---|---|---|---|---|
| SI-01 | POST `https://c26:8515/siem-gw/v1/events` | mTLS `audit-exporter` (C-24 host) | `{events: [ScrubbedEvent] ≤ 1,000}` | `204` | 10/s | schema reject | SEC; SYS | SYS | Allow-list: SECURITY and SYSTEM classes only; CASE events only as counts per day; pseudonymous IDs re-keyed with a SIEM-specific pseudonym key |
| SI-02 | Outbound syslog-TLS (RFC 5425) or HTTPS webhook to customer SIEM | C-26 client certificate | RFC 5424 structured data from `ScrubbedEvent` | — | configurable | retry/buffer 24 h | SEC; SYS | none | Destination allow-listed (ADVANCED) |
| SI-03 | GET `https://c26:8516/siem/v1/events?cursor` (pull mode) | customer SIEM mTLS | cursor | events | 60/min | — | SEC; SYS | SYS | Alternative to push |
| SI-04 | GET `/siem/v1/schema` | as SI-03 | — | JSON Schema of `ScrubbedEvent` | — | — | none | none | Versioned |

`ScrubbedEvent` never contains:
- case IDs;
- channel IDs of ANONYMOUS channels;
- routing groups;
- envelope or import IDs;
- day-level source counts per channel below k = 5;
- any SOURCE-SENSITIVE counter.

## 14. Requirements

| ID | Requirement | Evidence | Threats | Component | Verification |
|---|---|---|---|---|---|
| API-001 | Every route SHALL be declared in a deny-by-default registry with audience, authentication, authorization action and limits. CI SHALL fail on any undeclared or incompletely declared route. | ADR-029; INC-114; B-GL-37 | THR-021 | C-06; C-10 | TST: `route-registry-lint` |
| API-002 | Tokens and sessions SHALL be bound to exactly one audience and one tenant. A credential presented to another audience SHALL be rejected as unknown. | ADR-029; INC-105; B-SD-20 | THR-021; THR-022 | C-06; C-10; C-21 | TST: cross-context replay matrix (all audiences × all credential types, after logout, across workers) |
| API-003 | Logout and revocation SHALL synchronously invalidate access and refresh tokens (Desk/Admin) and RAM sessions (source). | INC-105 | THR-022; THR-034 | C-06; C-21 | TST: token use after logout returns 401 on all workers |
| API-004 | All public resource identifiers SHALL be random 128-bit values. No sequential, time-ordered or content-derived identifiers SHALL appear in any API. | B-GL-37; INC-112 | THR-021; THR-011 | C-06; C-10; C-12 | TST: ID generator tests; schema lint for serial/identity columns exposed in DTOs |
| API-005 | Resource-bound routes SHALL return an identical 404 (status, headers, body, timing class) for nonexistent, other-tenant and unauthorized resources. | INC-113; INC-114; REQ-H-09 | THR-021; THR-045 | C-10; C-06 | TST: enumeration test comparing responses and timing distributions (KS p > 0.01) |
| API-006 | Mutation endpoints SHALL accept only explicit per-role field allow-lists and SHALL reject unknown fields. No generic attribute-setting endpoint SHALL exist. | INC-112; B-GL-37 | THR-021; THR-034 | C-10 | TST: property-based mass-assignment fuzzing per endpoint per role |
| API-007 | Desk and Admin requests SHALL carry a valid `Candor-PoP` device signature with ±60 s freshness and nonce replay protection. | ADR-029; B-GL-04 | THR-022 | C-10; C-15; C-21 | TST: replayed, stale and wrong-device PoP rejected |
| API-008 | Source Web SHALL function fully without JavaScript. All no-JS routes SHALL send `script-src 'none'` and the §3.10 header set. | ADR-003; ADR-004; REQ-H-27 | THR-008; THR-006 | C-06 | TST: header golden test against the deployed onion (external probe); e2e in Tor Browser "Safest" |
| API-009 | Source Web SHALL NOT send `Server`, `Date`, `ETag` or `Last-Modified` headers, SHALL NOT use compression, and SHALL pad responses to route size classes. | ADR-011; INC-118 | THR-004; THR-011 | C-06 | TST: response size distribution test per route; header golden test |
| API-010 | Source Web state-changing requests SHALL be POST with a synchronizer CSRF token, a `SameSite=Strict` `__Host-` cookie and Origin validation. | INC-117; B-SD-13 | THR-021 | C-06 | TST: CSRF suite (missing, wrong or foreign token; foreign Origin) |
| API-011 | No source-facing API SHALL return a case ID, submission ID, recipient identity, exact timestamp or read/delivery status. | ADR-010; REQ-H-09 | THR-011; THR-019 | C-06 | TST: response schema inspection; INSP |
| API-012 | Login and challenge endpoints SHALL be indistinguishable for existing and nonexistent source accounts (response body class, status, timing floor). | INC-112 | THR-034 | C-06; C-08 | TST: timing and size indistinguishability test |
| API-013 | Tier V uploads SHALL use per-upload random capabilities (`U`), SHALL NOT require a session, and SHALL be linked to an account only at envelope commit. | THR-047 analysis §5.1 | THR-047 | C-03; C-06; C-08 | TST: DB inspection after an interrupted upload shows no account linkage; AUD: protocol review |
| API-014 | Mailbox listings SHALL always contain exactly 32 entries (dummies included), and fetch or delete of a reply SHALL NOT be propagated to Z-CORE. | ADR-010; ADR-011; B-SD-11 | THR-011; THR-015 | C-06; C-08 | TST: list-size invariance; relay protocol has no fetch-state field (schema test) |
| API-015 | The Source App SHALL verify directory checkpoints (signature, witness cosignatures when configured, consistency with the last seen checkpoint) and inclusion proofs before encrypting to any key. | ADR-004; INC-14; B-CR-37 | THR-046; THR-007 | C-03; C-14 | TST: malicious-server harness serving a forked tree, a stale checkpoint and a missing proof |
| API-016 | Relay endpoints SHALL require pinned mTLS plus signed, counter-protected requests, and SHALL offer no operation that queries source accounts or mailboxes. | ADR-009; INC-103 | THR-014; THR-015 | C-08; C-09 | TST: relay API inventory test; replay and unsigned-request tests |
| API-017 | The Admin API SHALL expose no endpoint returning case records, key wraps, evidence, envelope ciphertext or sealed identity data. | ADR-015; INC-114 | THR-018 | C-10 | TST: route inventory diff (ARCH-012) |
| API-018 | Configuration change requests SHALL have their class computed server-side from the catalog, and DANGEROUS changes SHALL require two distinct admin signatures and a 72-h cool-off. | ADR-013; INC-114 | THR-035 | C-10 | TST: e2e config workflow tests |
| API-019 | Case creation, member addition, epoch key publication and re-key SHALL be rejected if the submitted wrap set differs from the server-computed eligible set or uses non-current directory keys. | ADR-015; INC-14 | THR-046; THR-020 | C-10; C-22 | TST: wrap-set mismatch tests for DA-14, DA-30, DA-36, DA-38 |
| API-020 | Adding a COI-excluded user to a case SHALL fail with a uniform 404 for the target user, without revealing the COI registry to the caller. | ADR-015; INC-22 | THR-020 | C-10; C-22 | TST: COI add-member scenario |
| API-021 | Export of originals SHALL require approvals from two distinct users other than the creator, with step-up. Connectors SHALL fetch only approved packages addressed to them. | ADR-018; ADR-012 | THR-029; THR-041 | C-10; C-40 | TST: approval matrix tests; connector cross-fetch test |
| API-022 | Break-glass endpoints SHALL enforce distinct requester and approver users and roles, ≤ 72-h duration, member notification, and review by a third, independent user. | ADR-015 | THR-018; THR-019 | C-10; C-22 | TST: break-glass state-machine tests |
| API-023 | Every content-bearing Desk read SHALL emit a CASE audit event before the response body is sent. If audit append fails, the request SHALL fail. | ADR-016; INC-68 | THR-019; THR-037 | C-10; C-24 | TST: audit outage causes read failure; audit completeness test |
| API-024 | Error responses SHALL contain only closed error codes and SHALL never echo input values, IDs, SQL, paths or stack traces. | ADR-016; INC-120 | THR-016 | all API components | TST: `error-scrub` canary test across all endpoints |
| API-025 | Desk/Admin APIs SHALL reject requests bearing an `Origin` header and SHALL emit no CORS headers. | ADR-007; INC-117 | THR-022 | C-10 | TST: CORS negative tests |
| API-026 | Desk clients SHALL write all downloaded ciphertext through `candor-safefs` and SHALL treat every server-supplied field (names, sizes, counts, redirects) as hostile. | ADR-027; INC-101; INC-102; INC-104 | THR-023; THR-014 | C-15 | TST: malicious-server harness (path injection in every field, redirects 301–308, oversize counts) |
| API-027 | API clients (Desk, Source App, relay, fleet agent) SHALL disable HTTP redirects, cookies (except Source Web) and proxy-from-environment, and SHALL pin the endpoint at the connection layer. | INC-104; B-SD-36 | THR-014; THR-001 | C-03; C-09; C-15; C-34 | TST: redirect and Alt-Svc tests with packet capture |
| API-028 | The aggregate reporting API SHALL enforce k ≥ 5 suppression and a minimum 7-day range with week buckets. | ADR-016 | THR-039 | C-10 | TST: small-cell tests |
| API-029 | The SIEM export SHALL pass only allow-listed SECURITY/SYSTEM event schemas with SIEM-specific pseudonyms, and SHALL never pass case, envelope, routing-group or SOURCE-SENSITIVE data. | ADR-018; INC-56 | THR-016; THR-029 | C-24; C-26 | TST: exporter schema tests; canary fields dropped |
| API-030 | Fleet heartbeats SHALL contain only the FL-01 fields. Fleet desired-state SHALL auto-apply only SAFE items, and target versions SHALL independently pass TUF verification. | ADR-022; ADR-020 | THR-025; THR-027 | C-34 | TST: fleet payload schema test; malicious fleet server harness |
| API-031 | Health events SHALL be schema-strict. Host identity SHALL come from the agent certificate only. | INC-103 | THR-016; THR-035 | C-25 | TST: spoofed host-role payload test |
| API-032 | Unknown request fields SHALL be rejected. Duplicate JSON keys SHALL be rejected. Response parsers in clients SHALL ignore unknown non-critical fields. | B-SD-28; INC-112 | THR-021 | all | TST: parser conformance tests |
| API-033 | Servers SHALL support API major version N and N−1 for ≥ 12 months, and SHALL return 426 to clients below the minimum version published in the key directory. | Design | — | C-06; C-10 | TST: version negotiation tests |
| API-034 | Desk intake listing and fetch SHALL be restricted to members of the envelope's routing group. | ADR-015 | THR-020; THR-021 | C-10; C-22 | TST: non-member list and fetch return empty or 404 |
| API-035 | Cursors SHALL be AEAD-protected and bound to principal and filter. A foreign or modified cursor SHALL be rejected. | INC-113 | THR-021 | C-10 | TST: cursor tampering and cross-user tests |
| API-036 | Epoch key publication SHALL require the wrap set to equal current routing-group membership keys, and SHALL append directory entries signed by the channel identity key. | ADR-008; INC-14 | THR-046 | C-10; C-14; C-15 | TST: DA-14 negative tests |
| API-037 | Source App directory, release and mailbox responses SHALL be padded to 4-KiB multiples, and dummy mailbox ciphertexts SHALL be size-indistinguishable from real ones within buckets. | ADR-011 | THR-004; THR-011 | C-06 | TST: size distribution tests |
| API-038 | There SHALL be no health, status, debug or metrics endpoint on the source onion. | REQ-H-34; INC-34 | THR-001; THR-035 | C-06 | TST: path scan against the onion returns the uniform 404 for all non-listed paths |

## 15. Residual risks and limitations

- **Tier W sessions:** Tier W sessions rely on a cookie in Tor Browser. If the source does not close Tor Browser, the session persists until timeout (20 min idle). The UI instructs logout (11-FRONTEND-SOURCE.md).
- **Padding limits:** padding hides exact sizes within classes but not the class. Large file uploads reveal approximate size to a network observer on the source side (THR-002/003).
- **Resumable uploads:** requests of one upload are linkable to each other (§5.1).
- **Uniform 404 timing:** timing uniformity is statistical. A determined attacker with many samples might still distinguish classes. The rate limits bound samples.
- **Directory trust:** Desk/Admin API transport security relies on onion client-auth or mTLS PKI issued at enrollment. Enrollment-time key substitution is mitigated only by out-of-band fingerprint confirmation (AP-06).
- **Connector exposure:** connectors decrypt export packages in Z-CORE (EE). A compromised connector sees exported content. This is inherent in ADR-018 and is bounded by approvals.

## 16. Open issues

| # | Issue | Proposal |
|---|---|---|
| O-1 | ADR-029 enumerates four audiences. Machine audiences (`relay`, `connector`, `agent`, `audit-exporter`, `siem-client`, `fleet-agent`) are used here via mTLS SANs. | Amend ADR-029 (see 06 O-1). |
| O-2 | `CONNECTOR_KEY` directory entry type and the Intake Routing Key are not in ADR-008. | Add to 04-CRYPTOGRAPHY.md and ADR-008. |
| O-3 | Tor Browser handling of `__Host-`/`Secure` cookies on HTTP onion origins. [Knowledge (unverified): Tor Browser treats .onion as a secure context.] | Validate in 30-ANONYMITY-TESTING.md. Fallback: a cookie named `cs` with `HttpOnly; SameSite=Strict; Path=/`, no `Secure`. |
| O-4 | Omitting the `Date` header deviates from RFC 9110. | Validate that Tor Browser and the Source App HTTP stack tolerate it. |

### Open Issues for ADR revision
- **ADR-029:** machine audiences (O-1).
- **ADR-008:** connector and routing keys (O-2).
