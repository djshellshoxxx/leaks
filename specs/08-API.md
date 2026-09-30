# 08 — API Specification

Status: Draft v1.1 (revision round 2: ADR-034..046) · Edition applicability: both (EE-only APIs marked **EE**) · Owner: Backend + Client teams

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
| DECISIONS.md ADR-004/005/010/011/015/017/018/026/029, and ADR-034..046 (revision ADRs; supersede conflicting earlier text) | Binding decisions. This document is the **canonical owner of the upload protocol** (ADR-046(4)). |
| 11-FRONTEND-SOURCE.md §5.3–§5.6 | **Canonical** for the Source Web page contract: response headers and CSP, page size classes (P1/P2), cookie and session timers. §4 here specifies the API behaviour of those routes and does not restate the contract. |
| 24-LICENSING-BUSINESS-MODEL.md §TEL | Canonical metrics/k-anonymity regime used by AP-22, RL-09 and SI-* (ADR-046(5)) |
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
| Source Web | `/run/candor/web/http.sock` behind the source onion | `source-web` | `__Host-s` session cookie (11 §5.6; RAM session in C-06 and C-07) | Tor onion, HTTP/1.1 |
| Source App | same socket, prefix `/app/v1/` | `source-app` | none for reply retrieval and submission (ADR-039); per-upload capabilities for uploads (§5.1) | Tor onion (Arti), HTTP/1.1 |
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
- Web source sessions live in a RAM map. The Source App has no sessions (ADR-039). The cookie is never accepted on `/app/v1/*`, and no `/app/v1/*` credential is accepted on HTML routes (INC-105).
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

- All resource IDs are **random 128-bit** values from the OS CSPRNG, encoded as lowercase RFC 4648 base32 without padding (26 chars), with a 2-letter type prefix and underscore. Examples: `cs_…` case, `ev_…` evidence, `ch_…` channel, `us_…` user, `ex_…` export, `ie_…` import envelope, `jb_…` job, `bg_…` break-glass.
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
| Source Web | Size classes, padding bytes and budgets are defined **only** in 11 §5.4 (P1 = 65,536 bytes, P2 = 131,072 bytes; no other class). Wrong-passphrase and inbox responses are both P1 unless the inbox paginates to P2 (11 §5.4). Supersedes the earlier 16/32/64/128 KiB classes here (RVW-A-21). |
| Source App | JSON/CBOR responses padded to the next multiple of 4 KiB (≥ 4 KiB), with a `pad` field of random bytes. Blob downloads are already bucketed. |
| Tier W mailbox | The inbox always renders exactly `N_fixed = 32` entries; the real ones plus dummies indistinguishable at the ciphertext level (dummy reply ciphertexts under a random key) |
| Tier V reply pages (SA-20) | Every page holds exactly 64 entries, each a ciphertext padded to 70,000 bytes; the page count is padded to the next power of two (minimum 1) with dummy pages (ADR-039) |
| Desk/Admin | Not padded (authenticated staff; 06 §13) |

### 3.9 Legend for tables

- **Sensitive:** SS = SOURCE-SENSITIVE, CT = content ciphertext, WF = workflow metadata, SEC = security data, SYS = system.
- **Log:** `none` = no event of any kind; `SEC:x` / `CASE:x` / `SYS:x` = typed event name (20-LOGGING-AUDITING.md); `CTR:x` = SOURCE-SENSITIVE daily counter only.
- **Rate:** per circuit token (source families), per user (Desk/Admin), per machine identity (machine families). "G:" = additional global bucket.
- **AuthZ** column uses action names from 15-AUTHENTICATION-AUTHORIZATION.md, e.g., `case.read`. "member(case)" = the caller has an active ACL entry on the case. "pub" = no authentication.

### 3.10 Security headers

**Source Web (all responses):** the header set, including the single CSP string, is defined **only** in 11-FRONTEND-SOURCE.md §5.3 (inline CSS pinned by hash, `script-src` absent under `default-src 'none'`, `sandbox allow-forms allow-same-origin`, Trusted Types, no sub-resources). This document previously carried a second CSP with `style-src 'self'; font-src 'self'` and a static-asset route; both are withdrawn (RVW-A-21, API-048). API-level invariants that the route handlers enforce:
- No `Server`, `Date`, `ETag`, `Last-Modified`, `Content-Encoding`, `Alt-Svc`, or `Set-Cookie` other than the single session cookie `__Host-s`.
- Omitting `Date` deviates from RFC 9110 §6.6.1 on purpose, to avoid exposing server clock skew (16-TOR-I2P.md owns the decision).
- Exactly one HTTP request per page view; no sub-resources, no redirects (11 §5.4).
- **WEBCAT-verified bundle (optional, `intake.tier_v.webcat_bundle.enabled`):** served only under `/v/` with the CSP given in 11 §5.3 and the enrollment manifest required by WEBCAT (B-CR-37, B-CR-40). The no-JS routes never allow scripts.
- Logout (`/leave`) additionally sends `Clear-Site-Data: "cache", "cookies", "storage"`.

**Desk/Admin/Export APIs:** `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, `Content-Type` exact. No CORS headers: requests with an `Origin` header are rejected, because the Desk uses a native HTTP client, not a browser origin.

## 4. Source Web (Tier W, HTML forms, audience `source-web`)

Family defaults:
- Paths are relative to `/{lang}/` and follow the route list of 11 §5.5, which is canonical for route names and screens (S-numbers). This table specifies the API contract of each route. Rows keep their historical IDs; `SW-19` is withdrawn.
- Rate: 60 req/min/circuit, burst 20, plus G: 600 req/s.
- Errors: static padded pages (§3.4) in class P1.
- Sensitive: all request bodies are SS or content.
- Log: `none` unless stated.
- Security: headers per 11 §5.3, padding per 11 §5.4, no JS required, no external resources, no redirects, no IDs in URLs.
- Session: single cookie `__Host-s`; one timer set, idle 20 min and absolute 2 h (ADR-034); expiry zeroizes the RAM draft and deletes staged parts.
- **Draft state (ADR-034):** draft text and the identity block live only in C-07 mlocked RAM keyed by the session handle; attachment parts are encrypted under a per-session key held only in C-07 RAM and staged as ciphertext in tmpfs. Nothing is sealed to any recipient until the submission is finalized (SW-04). A sealer restart loses drafts, and the UI says so (11 S04/S06).
- **Tier W uploads (ADR-046(4)):** one file per request, no resume. A broken upload is re-sent from the start.

| ID | Method Path | AuthZ | Input | Output | Rate | Errors | Sensitive | Log | Security |
|---|---|---|---|---|---|---|---|---|---|
| SW-01 | GET `/` | pub | — | S01 Landing: mode statement per channel, protection statement (06 ARCH-036), Tier W honesty statement (ADR-035(5)), operator-statement status (banner if older than 30 days), links to channels | default | 500 page | none | none | `lang` only from the allow-list |
| SW-02 | GET `/new`, GET/POST `/concerns` | pub (GET); session + CSRF (POST) | `channel_id` (form body), `coi_label[]` (≤ 16 u16 role-label indices), `coi_category[]` (≤ 8 u16) | S04 channel description and protection statement; S04b **optional COI checklist** listing the channel's role labels (names only if `roster_names_visible`), rendered from the verified directory snapshot (ADR-030), default none selected, with the ADR-037(4) statement "Your answers are encrypted and seen only by the independent triage team…"; the page names the Triage Set role labels who read first | default | 404 page (unknown or disabled channel); busy page if no Triage Set member has a valid Member Epoch Key | SS (COI selection) | none | The selection is held only in C-07 RAM until finalization. If the ticks exclude every Triage Set member, the page names the channel's `alternative_channel_id` (ADR-037(1); RVW-C-18) and offers no other path |
| SW-03 | POST `/new` (start) | pub + CSRF (pre-session token issued by SW-02 in a session-less signed hidden field, 10-min validity) | `csrf`, `channel_id` | Sets `__Host-s`; renders S05. **No passphrase is generated here** (ADR-034). | 6/10 min/circuit; G: 600/h new sessions | busy page | none | none | Creates only a RAM session in C-06/C-07; nothing is written to C-08 |
| SW-04 | POST `/saved` | session(PENDING_CONFIRM) + CSRF | `csrf`, `w_a`, `w_b`, `w_c` (the 3 words at the positions the sealer chose at random in SW-08) | On a match: finalizes (SEAL_FINISH + COMMIT_ENVELOPE with `fsync`, 07 §5.2) and renders the "received" page (no ID, no time). On a mismatch: S10 again with the same passphrase and new positions (≤ 5 attempts, then the draft is discarded) | 10/h/circuit | busy/500 page | SS | CTR:`submissions` (monthly, 24 §TEL) | Constant-time compare. **This is the passphrase confirmation step** (ADR-034): the submission is not finalized before it, so a lost S10 response means nothing was submitted and the source restarts |
| SW-05 | POST `/q`, POST `/identity` | session + CSRF | `csrf`, questionnaire fields (total ≤ 96 KiB UTF-8, 11 §5.7); `identity_disclosure` (≤ 4 KiB, CONFIDENTIAL/IDENTIFIED only) | Next step page | default | 413 page | content; SS | none | Streamed to C-07 `DRAFT_SET` (RAM only, never disk, including on error paths); identity block zeroized if the source reverts to ANONYMOUS |
| SW-06 | POST `/files` | session + CSRF | multipart: `csrf`, `file` (1 part) ≤ `intake.max_file_bytes` | S06 draft page listing parts as "File (size bucket)" | 30/h/circuit; G: staging capacity | 413 or 400 page; busy page when the tmpfs staging area is full; draft keeps prior parts | content; filename SS | none | Parser enforces the part allow-list before forwarding (INC-107); ciphertext under the per-session key is staged in tmpfs (ADR-034); padded to the ADR-011 bucket before staging (ADR-038(5)); filename kept in C-07 RAM and sealed into the manifest at finalization |
| SW-07 | POST `/files` (action `remove`) | session + CSRF | `csrf`, `part_index` (u8) | S06 draft page | default | 400 page | none | none | Deletes the staged ciphertext immediately |
| SW-08 | POST `/submit` | session + CSRF | `csrf`, `delayed_delivery` (bool, optional, ADR-038(4)) | S10 Recovery Credential: the 10-word passphrase (generated now by C-07 `GEN_ACCOUNT`, held only in RAM) and a form asking for 3 randomly chosen words (SW-04) | 10/h/circuit | busy/500 page | SS (passphrase) | none | Passphrase never in URL or title; `autocomplete=off`. Follow-ups by a logged-in source skip S10 and finalize here directly |
| SW-09 | GET `/login` | pub | — | Login form | default | — | none | none | — |
| SW-10 | POST `/login` | pub + CSRF | `csrf`, `passphrase` ≤ 256 B | Inbox (SW-11 render) or wrong-passphrase page, same size class | 5/10 min/circuit; G: Argon2id 4 concurrent | busy page | SS | none | 2 s floor timing; uniform challenge (07 BE-010); new session ID issued (fixation-proof); on success the web passes `prefs_ct` to the sealer (`LOAD_PREFS`). Server-side mailbox lookup is inherent to Tier W (ADR-039 residual) |
| SW-11 | GET `/inbox` | session(AUTHENTICATED) | — | Replies decrypted in the sealer and rendered as escaped text with day-granular dates. **No own-message history** is shown or stored (ADR-039). | default | 404 page if not authenticated | content | none | No read receipts sent anywhere (ADR-010) |
| SW-12 | POST `/conversation` | session + CSRF | `csrf`, `text` ≤ 64 KiB, `delayed_delivery` (bool, optional) | S12 | 20/h/circuit | 413 page | content | CTR:`submissions` | Follow-up sealed only to members of the original eligible set who are still members (ADR-036(4)); no `kind` field is stored |
| SW-13 | POST `/conversation` (multipart) | session + CSRF | multipart `csrf`, `file` | S12 with a staged part | 30/h/circuit | 413 page | content | none | as SW-06 |
| SW-14 | POST `/conversation` (action `reply-delete`) | session + CSRF | `csrf`, `reply_index` (u8, index in the padded list) | S12 | default | 400 page | none | none | Deletion local to intake; not reported to core |
| SW-15 | POST `/end` (action `delete-account`) | session + CSRF + re-entry of passphrase | `csrf`, `passphrase` | "Account deleted" page | 3/h/circuit | wrong-passphrase page | SS | CTR:`account_deletions` | Deletes the account record and mailbox in C-08 and writes a `deletion_tombstone` (RVW-A-28). Already relayed submissions are unaffected (explained on the page). |
| SW-16 | POST `/leave` | session + CSRF | `csrf` | Leave page | default | — | none | none | `Clear-Site-Data`; sealer `ZEROIZE`; staged parts deleted |
| SW-17 | GET `/status` | pub | — | S03: channel role labels, protection statement, operator-statement status, and for Tier W the fixed sentence "Checking these values does not protect a report sent from this website; only the Candor app checks them before encrypting." Fingerprints, checkpoint and witness details are moved to the Tier V-oriented `/verify` content (RVW-A-17; ADR-036 Tier W limit) | default | — | none | none | Renders from the verified snapshot only |
| SW-18 | GET `/safety` | pub | — | S02 guidance, including how to obtain and verify the Source App from the project's onion service (ADR-041) | default | — | none | none | Static |
| SW-19 | WITHDRAWN (RVW-A-21; 11 §5.4 rule 4): GET `/static/{sha256}.{css\|woff2\|svg}`. No sub-resources exist; CSS is inline and hash-pinned. | — | — | — | — | — | — | — | — |
| SW-20 | GET `/robots.txt` | pub | — | `Disallow: /` | G | — | none | none | — |
| SW-21 | POST `/extend` | session + CSRF | `csrf` | Current page re-rendered | 12/h/circuit | — | none | none | Resets the idle timer only; the 2-h absolute limit is unchanged (ADR-034) |
| SW-22 | POST `/inbox` (action `rotate-passphrase`) | session(AUTHENTICATED) + CSRF + re-entry of the current passphrase | `csrf`, `passphrase` | S10-style page with the new passphrase and the 3-word confirmation (same flow as SW-04); after confirmation the old passphrase stops working | 3/day/circuit | wrong-passphrase page | SS | none | ADR-046(7): C-07 re-derives keys, re-encrypts pending replies to the new key in RAM, replaces the account's public record, and seals a key-update follow-up to the original eligible set so the case learns the new reply key |
| SW-23 | GET `/.well-known/candor/manifest` | pub | — | The signed **running manifest** (§7.1): byte-exact CBOR, identical for all requesters until the next release or platform update | G only | — | none | none | ADR-035(1), ADR-040. Exempt from P1/P2 padding (it is a static public document); no session, no cookie |

There are no other paths. Any unlisted path returns the SW 404 page (same bytes as SW-02 unknown). Routes SW-22 and SW-23 are requested for addition to 11 §5.5 (cross-document request).

## 5. Source App API (Tier V, audience `source-app`)

Family defaults:
- Rate: 120 req/min/circuit, burst 40; G: 1,000 req/s.
- Response padding to 4 KiB multiples.
- Errors per §3.4.
- Log: `none` unless stated.
- All objects are deterministic CBOR.
- The app uses a **fresh Tor circuit (new SOCKS isolation token) per logical operation group** (one for directory fetch, one per upload, one for reply retrieval), so that operations are not trivially linkable at the circuit level (THR-047; 11-FRONTEND-SOURCE.md).
- **No source sessions (ADR-039):** replies are retrieved by fetch-all (SA-19/SA-20); submissions and follow-ups are unauthenticated at the HTTP layer and authenticated inside the ciphertext by the source signing key (`sign_sk`, 04-CRYPTOGRAPHY.md). The intake therefore holds no Tier V account and cannot tell which source checked for replies or when.

| ID | Method Path | AuthZ | Input | Output | Rate | Errors | Sensitive | Log | Security |
|---|---|---|---|---|---|---|---|---|---|
| SA-01 | GET `/app/v1/directory/checkpoint` | pub | — | Signed checkpoint + witness cosignatures (≥ 2, ≥ 1 external in EE/GOV/MANAGED; ADR-036(5)) + snapshot version | default | `busy` | none | none | Client verifies against the pinned directory root, the witness key set embedded in the app, and the last pinned tree head (§7) |
| SA-02 | GET `/app/v1/directory/channel/{channel_id}` | pub | `channel_id` | `{channel_identity, channel_roster (role labels, member identity key IDs, `triage` flag, `member_since_day`, `effective_day`), role_label_certs (OVERSIGHT-signed, ADR-036(3)), coi_map (category → excluded labels), member_epoch_keys (Triage Set members only: current + next 4 epochs, each signed by the member identity key), alternative_channel_id, recipient_slots, inclusion proofs, protection_statement, operator_statement}` | default | 404 uniform | none | none | Same response for unknown and disabled channels. The app shows the COI checklist, applies the filter locally to the **Triage Set** (ADR-037(1)), warns when a member key is < 7 days old (ADR-036(3)), and directs the source to `alternative_channel_id` when no eligible triage member remains. Entries before their `effective_day` are not used for sealing. |
| SA-03 | GET `/app/v1/directory/consistency?from={size}` | pub | tree size | Consistency proof to the current checkpoint | default | 400 | none | none | Detects forks between app visits (persistent pin, ADR-036(5)) |
| SA-04 | GET `/app/v1/releases` | pub | — | Latest `CLIENT_RELEASE` entries with inclusion proofs | default | — | none | none | App refuses to run if its own hash is not logged or is below minimum |
| SA-05 | WITHDRAWN (ADR-039): POST `/app/v1/auth/challenge` | — | — | — | — | — | — | — | — |
| SA-06 | WITHDRAWN (ADR-039): POST `/app/v1/auth/session` | — | — | — | — | — | — | — | — |
| SA-07 | WITHDRAWN (ADR-039): POST `/app/v1/accounts`. The reply public key and `thread_tag` travel inside the envelope ciphertext; the intake stores no Tier V account. | — | — | — | — | — | — | — | — |
| SA-08 | POST `/app/v1/uploads` | pub (no session; §5.1) + optional app-level PoW (`intake.pow.app_level.enabled`) | `{upload_id: bytes32, k_u: bytes32, chunk_count: u16 ≤ 512 (≤ 2,048 in EE profiles), padded_size_bucket: u8, pow?}` | `201 {chunk_size: 8388608}` | 20/h/circuit; G: 2,000 pending | `busy`, `too_large` | none | none | No link to any account or session; upload expires 24 h after creation (§5.1) |
| SA-09 | PUT `/app/v1/uploads/{upload_id}/chunks/{n}` | capability: `Candor-Chunk-Mac: HMAC-SHA256(K_U, upload_id ‖ n ‖ sha256(body))` with `K_U` as registered in SA-08 | body = ciphertext chunk, exactly 8 MiB except the last (≤ 8 MiB) | `204` | 600/h/circuit | `not_found` (unknown or expired upload), `conflict` (chunk already stored with a different digest), `too_large` | CT | none | Idempotent for identical chunk re-sends; MAC verified before storing |
| SA-10 | GET `/app/v1/uploads/{upload_id}` | capability MAC over `upload_id ‖ "status"` | — | `{received: bitmap}` | 60/h/circuit | `not_found` | none | none | Resumption **within one app session only** (the app keeps `U` in RAM, never on disk) and ≤ 24 h after creation (ADR-046(4)) |
| SA-11 | DELETE `/app/v1/uploads/{upload_id}` | capability MAC | — | `204` | default | `not_found` | none | none | Abandon |
| SA-12 | POST `/app/v1/envelopes` | pub (+ optional app-level PoW) | `{channel_id, header_ct ≤ 8 KiB (16 fixed-size anonymous HPKE slots, random order, no key IDs), manifest_ct ≤ 64 KiB (contains the signed recipient list, `thread_tag`, reply public key; follow-ups also carry a signature by `sign_sk`), parts: [{upload_id, mac_proof}] ≤ 32, delayed_delivery: bool}` | `201 {}` (no ID, no time), returned only after the envelope and its blobs are `fsync`ed (ADR-046(1)) | 10/h/circuit | `bad_request` (non-canonical, slot count or size ≠ spec), `not_found` (upload incomplete) | CT | CTR:`submissions` (monthly) | Canonical validation (07 BE-049); upload proofs verified; no `kind`, tier or account field exists (ADR-039; RVW-B-11). The server cannot see recipients (ADR-033(1)). |
| SA-13 | WITHDRAWN (ADR-039): GET `/app/v1/mailbox`. Replaced by SA-19. | — | — | — | — | — | — | — | — |
| SA-14 | WITHDRAWN (ADR-039): GET `/app/v1/mailbox/{slot}`. Replaced by SA-20. | — | — | — | — | — | — | — | — |
| SA-15 | WITHDRAWN (ADR-039): DELETE `/app/v1/mailbox/{slot}`. Tier V replies leave the published set after ≤ 30 days. | — | — | — | — | — | — | — | — |
| SA-16 | WITHDRAWN (ADR-039): POST `/app/v1/logout` (no sessions). | — | — | — | — | — | — | — | — |
| SA-17 | WITHDRAWN (ADR-039): DELETE `/app/v1/account` (no Tier V account exists at the intake). | — | — | — | — | — | — | — | — |
| SA-18 | GET `/app/v1/pow/seed` | pub | — | `{seed: bytes32, effort: u32}` | default | — | none | none | Only when app-level PoW is enabled. `effort` is a fixed configured value, not load-dependent (ADR-038(5)) |
| SA-19 | GET `/app/v1/replies/index` | pub | — | `{set_version: u64, page_count: u16 (padded to a power of two), page_size: 64, window_days: 30}` | default | `busy` | none | none | Same response for every requester (ADR-039) |
| SA-20 | GET `/app/v1/replies/pages/{n}` | pub | page number | 64 reply ciphertexts, each padded to 70,000 bytes (dummies included), for all replies of the last 30 days across the tenant | 600/h/circuit | `not_found` for out-of-range only | CT | none | The client **must** fetch every page of the current `set_version` and trial-decrypt locally; fetching a subset is a client defect (API-040). No fetch state is recorded (ADR-010, ADR-039) |
| SA-21 | GET `/app/v1/manifest` | pub | — | Same signed running manifest as SW-23 | default | — | none | none | ADR-035(1), ADR-040 |

### 5.1 Resumable upload protocol and THR-047 analysis (canonical, ADR-046(4))

This section is the single normative definition of the upload protocol; 03, 07, 11 and 34 reference it.

**Parameters:**

| Parameter | Value |
|---|---|
| Chunk size | 8 MiB ciphertext (128 STREAM chunks of 64 KiB); last chunk ≤ 8 MiB |
| Chunk count | derived from the ADR-011 padded bucket; ≤ 512 (per-file cap 4 GiB) in standard profiles; ≤ 2,048 (16 GiB) only in EE profiles (EE-ONPREM, EE-HA, GOV-ONPREM, PRIVATE-CLOUD, MANAGED) where `intake.max_file_bytes` > 4 GiB is configured |
| Resume | Tier V only; within one app session (the app never persists `U`); ≤ 24 h after creation |
| Tier W | No resumable uploads; one file per request (SW-06); a failed upload is re-sent in full |
| Expiry | 24 h after creation (tracked in `candor-intake-store` RAM with a monotonic clock; no time stored), or intake-store restart; backstop `upload_gc` deletes uploads with `created_day` < today − 1 |

**Design:**
1. The client generates a 256-bit secret `U` per upload and computes:
   - `upload_id = SHA-256("candor-upload-id" ‖ U)`;
   - `K_U = HKDF-SHA256(U, info="candor-upload-mac")`.
2. SA-08 registers `upload_id` and `K_U`. The server keeps `K_U` only until the upload is committed or expires.
3. Every chunk, status or delete request carries an HMAC under `K_U`. A party that learns only `upload_id` (e.g., from a log or backup) cannot add, probe or delete chunks. `K_U` never leaves the intake store.
4. `U` and `upload_id` are **per upload** (per-upload tokens). They are never derived from the source passphrase, account keys or other uploads.
5. Uploads carry no session token. The server cannot link an upload to an envelope until SA-12 commits it, and never to an account (ADR-039).
6. Chunk records store no time. Only `created_day` exists per upload.
7. There is no cross-session resume: after the app exits, the upload is abandoned and restarted with a new `U`.

| Linkage question | Answer | Residual |
|---|---|---|
| Can the server link two chunk requests to the same upload? | Yes, by `upload_id`. This is inherent to resumption. | The circuits used for one upload are linkable to each other. Mitigation: resume only within one session, ≤ 24 h. |
| Can it link two uploads to each other before commit? | No. They have independent `U` and no shared token. Circuit tokens are not persisted. | A network observer may correlate by timing (THR-003). |
| Can it link an upload to a source account? | No. Tier V has no intake account (ADR-039). Uploads are linked to an envelope at SA-12 commit. | none beyond envelope ↔ parts |
| Can it link uploads across different envelopes? | No shared identifiers. `thread_tag` is inside the ciphertext. | Size buckets and the same day can correlate weakly |
| Does resumption state reveal time? | Only `created_day` | Day-level |
| Could a malicious server tag or track the client via upload responses? | Responses are fixed-shape. The app ignores unknown fields and never stores server-provided identifiers on disk (11-FRONTEND-SOURCE.md). | `U` is held only in app RAM and discarded after commit or exit |

## 6. Relay pull protocol (intake export endpoint, machine audience `relay`)

Family defaults:
- AuthZ: mTLS SAN = pinned relay identity for this intake instance, plus a valid `Candor-Relay-Sig` with strictly increasing `req_counter` (07 §5.4).
- Schedule: envelope import (RL-02..RL-04), reply push (RL-05) and counters/backup pulls run **only in fixed import slots** (default 4×/day at fixed tenant-configured times; HIGH/GOV 1×/day), never on arrival (ADR-038(1); 07 §5.4). Directory snapshots and config bundles (RL-06/RL-07) may additionally be pushed in the hourly fixed-minute **control cycle**, which performs no claims.
- Rate: 1 cycle in flight; 20 req/s.
- Errors: uniform JSON; 401 on signature failure (connection closed).
- Log: `SYS:relay_request{op, outcome}` (no IDs).
- Security: TLS 1.3 only, `TLS_CHACHA20_POLY1305_SHA256` or `TLS_AES_256_GCM_SHA384` (FIPS profile), no session resumption, no redirects.

| ID | Method Path | AuthZ | Input | Output | Rate | Errors | Sensitive | Log | Security |
|---|---|---|---|---|---|---|---|---|---|
| RL-01 | GET `/relay/v1/health` | relay | — | `{status: ok\|degraded, store_free_bucket, pending_bucket}` | default | — | SYS | SYS | — |
| RL-02 | POST `/relay/v1/batches/claim` | relay (import slot only) | `{max_objects ≤ 500, max_bytes ≤ 2 GiB}` | `{batch_no, objects: [{ref: bytes16, channel_id, epoch_index, header_len, manifest_len, parts: [{padded_size}], sha256}]}` | 1 in flight | `conflict` if a batch is unacked (returns the same batch) | CT; SS (epoch) | SYS | `ref` is intake-local, valid only for this batch. Only envelopes with `release_day` ≤ today are offered (delayed delivery, ADR-038(4)). No `kind` and no `received_date` cross to Z-CORE (ADR-038(3); RVW-B-11): the core records the slot date only. |
| RL-03 | GET `/relay/v1/batches/{batch_no}/objects/{ref}/{part}` | relay | `part` = `header`, `manifest` or index | ciphertext stream | default | `not_found` | CT | none | Streaming; relay verifies digest |
| RL-04 | POST `/relay/v1/batches/{batch_no}/ack` | relay | `{committed: [sha256]}` | `{deleted: u32}` | default | `bad_request` if a digest is not in the batch | none | SYS | Intake deletes only matching digests (BE-014) |
| RL-05 | POST `/relay/v1/replies` | relay (import slot only) | `{replies: [{routing_ct ≤ 2 KiB, reply_ct ≤ 70,000 B}] ≤ 500}` | `{accepted: u32, rejected: [index]}` (tombstoned mailboxes count as accepted and are dropped silently) | default | `bad_request` | CT; routing SS-sealed | SYS | Intake decrypts `routing_ct` with the routing key; files Tier W replies under the account and adds every reply to the published set (ADR-039); `available_day = today` |
| RL-06 | POST `/relay/v1/directory-snapshot` | relay (slot or control cycle) | signed snapshot (CBOR) | `204` | default | `bad_request` (invalid signature, consistency, witness quorum, or below the high-water mark) | none | SEC:`kd_snapshot_rejected` on failure | Intake verifies the signature chain, witness cosignatures (ADR-036(5)) and consistency from its **high-water mark** (09 `intake_meta.kd_tree_size_hwm`); older or smaller snapshots are rejected (ADR-036(6); RVW-A-04). The snapshot carries no time that the intake trusts; freshness is judged against the intake's independent clock (07 §12) |
| RL-07 | POST `/relay/v1/config` | relay | signed config bundle | `204` | default | `bad_request` | SEC | SEC:`config_applied`/`config_rejected` | Verification per 07 §7.1 at intake |
| RL-08 | POST `/relay/v1/deletions` | relay | `{reply_purge_before_day}` (retention, ≤ 30 days) | `{purged: u32}` | daily | — | none | SYS | Only retention-driven; no targeted source deletion API exists from core |
| RL-09 | GET `/relay/v1/counters?month={m}` | relay | a closed calendar month | `{month, counters: {name: value_or_suppressed}}` per 24 §TEL (k = 10; channels with < 3 cases/month folded into their channel group) | monthly | `not_found` (month not closed) | SS aggregate | none | ADR-046(5); replaces the daily export (RVW-B-07) |
| RL-10 | GET `/relay/v1/backup-snapshot` | relay | — | opaque ciphertext (encrypted to the Backup Key) + `{sha256, size}`: `source_account`, `deletion_tombstone`, `intake_meta` only (no envelopes, no replies) | daily | `not_found` if not ready | CT | SYS | Core cannot read it |

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
| KD-06 | GET `/desk/v1/kd/lookup/channel/{channel_id}` | desk session | channel_id | Channel identity, `CHANNEL_ROSTER`, `ROLE_LABEL_CERT`, `COI_MAP`, `MEMBER_EPOCH_KEY` entries + proofs | 600/min | 404 uniform | none | none | Desk verifies the **signed recipient list inside the decrypted payload** against these entries, including that the list was valid for the envelope's epoch and respects `effective_day` time locks (THR-046). Key IDs are never read from cleartext headers (ADR-046(10)) |
| KD-07 | POST (internal Unix only) `APPEND(entry, approvals)` | `candor-case` peer only | entry + approval records | `{leaf_index}` | n/a | codes | SEC | SEC:`kd_append` | Not network-exposed; approvals verified per entry type (07 §5.10) |
| KD-08 | Outbound: POST `{witness_url}/add-checkpoint` | directory key | checkpoint + consistency proof | cosignature | per checkpoint | retry | none | SYS | Witness protocol per 04-CRYPTOGRAPHY.md. [Knowledge (unverified): C2SP tlog-witness.] EE/GOV/MANAGED: ≥ 2 witnesses, ≥ 1 outside the operating organisation (ADR-036(5)) |
| KD-09 | GET `/desk/v1/kd/manifest` and SW-23/SA-21 | desk session / pub | — | Current signed running manifest (§7.1) + its transparency-log inclusion proof | 60/min | — | none | none | ADR-040 |

**Entry common fields:** `{type, tenant_id, subject_id, keys, valid_from_day, valid_until_day, effective_day, prev_entry_hash (per subject), signer_key_id, sig}`. `effective_day` is later than the append day for time-locked entries (roster additions, role-label changes, COI-policy loosening: + 3 days, GOV/HIGH + 7 days; ADR-036(2)); sealers and clients ignore such entries until then. Entries carry role labels (ADR-030). They carry staff names only when the channel sets `roster_names_visible` (ADVANCED), and never email addresses or usernames. Display names for staff views are delivered separately via the Desk API to authorized users.

**Entry types:** `USER_KEY`, `USER_KEY_REVOKE`, `CHANNEL_IDENTITY`, `CHANNEL_ROSTER` (includes the Triage Set flag per member), `ROLE_LABEL_CERT` (OVERSIGHT-signed, ADR-036(3)), `MEMBER_EPOCH_KEY`, `COI_MAP`, `ROUTING_KEY` (Intake Routing Key, ADR-046(12)), `CONNECTOR_KEY` (EE, ADR-046(12)), `RECOVERY_QUORUM_STATE`, `PROTECTION_STATEMENT`, `OPERATOR_STATEMENT` (quorum-signed, ≤ 30-day cadence, ADR-035(2)), `INCIDENT_NOTICE` (ADR-035(4)), `SERVER_RELEASE` (running-manifest digests of intake and core, ADR-040), `CLIENT_RELEASE`, `CONFIG_SIGNER` (07-BACKEND.md §5.10). Byte formats of new entry types are owned by 04-CRYPTOGRAPHY.md (cross-document request).

**Publication schedule (ADR-036(7); RVW-A-29):** `MEMBER_EPOCH_KEY` entries and time-locked roster/label/COI entries are appended only at the tenant's fixed **weekly publication slot**; checkpoints are signed daily at a fixed time and at the weekly slot. Removals, `USER_KEY_REVOKE` and `INCIDENT_NOTICE` are appended and checkpointed immediately because ADR-036(2) requires immediate effect; their timing is therefore visible (residual).

### 7.1 Running manifest (ADR-035(1), ADR-040)

The **running manifest** is a deterministic-CBOR document `{tenant_id, release_version, release_digest (TUF target hash of the installed Candor release), platform_manifest_digest (TUF-signed Platform Manifest, ADR-040), security_floor, static_asset_digests: {route → SHA-256 of the byte-exact static responses SW-18/SW-20 and of the template set}, csp_sha256, attestation: optional confidential-VM report (ADR-035(3)), issued_day}`, signed by the sealer signing key (K35, 04-CRYPTOGRAPHY.md). It is served byte-identically to every requester (SW-23, SA-21, KD-09) and its digest is appended to C-14 as `SERVER_RELEASE`. External Watchers fetch it over Tor and compare it, the served static assets and the CSP header, with the public transparency log (ADR-035(1)). Honest limit: a compelled operator can serve a correct manifest while running different code; the manifest detects accidental or careless divergence and forces deliberate lying to be signed. Dynamic pages (with CSRF tokens and padding) are not covered.

**Member Epoch Key ID:** `key_id = SHA-256("candor-mek-id" ‖ pk)[0..16]`. It is pseudonymous and new every epoch. It appears in `MEMBER_EPOCH_KEY` entries and inside the encrypted, signed recipient list of envelopes. It **never** appears in cleartext envelope headers (ADR-033 §1).

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
| DA-02 | POST `/desk/v1/auth/webauthn/finish` | as DA-01 | assertion, `device_key_id`, device attestation | `{access_token, refresh_token, expires_in: 900}` | as DA-01 | `unauthorized` (uniform) | SEC | SEC:`login_ok` / `login_failed` | UV required; sign-count check; token bound to device key. Channel-member activation requires ≥ 2 enrolled authenticators (ADR-044(2); 09 DB-054) |
| DA-03 | POST `/desk/v1/auth/refresh` | refresh token + PoP | — | new pair (rotation) | 60/h | `unauthorized` → client re-auth | SEC | SEC:`token_refresh` (sampled 1/10) | Refresh reuse detection revokes the family |
| DA-04 | POST `/desk/v1/auth/logout` | access token | — | `204` | — | — | SEC | SEC:`logout` | Synchronous revocation of access and refresh tokens (INC-105) |
| DA-05 | POST `/desk/v1/auth/stepup/begin` | access token | `{action}` | WebAuthn options | 20/h | — | SEC | none | — |
| DA-06 | POST `/desk/v1/auth/stepup/finish` | access token | assertion | `{stepup_proof, expires_in: 300, action}` | 20/h | `unauthorized` | SEC | SEC:`stepup` | Single use, bound to action and resource |
| DA-07 | GET `/desk/v1/me` | access | — | profile, roles, channel memberships (role labels, Triage Set flag), device list, epoch-key runway per channel, notification settings | default | — | WF | none | — |
| DA-08 | PUT `/desk/v1/me/notification-settings` | access | `{mode: daily_constant\|off, contact_ref}` | `200` | 10/h | `bad_request` | SEC | SEC:`notif_settings_changed` | ADR-038(2): `daily_constant` = one content-free digest at the tenant's fixed daily time every day, whether or not anything is pending; `off` = Desk badge only (HIGH default). No event-driven mode exists. Contact addresses validated; changes notify the old contact (content-free) |

### 8.2 Sync, keys and devices

| ID | Method Path | AuthZ | Input | Output | Rate | Errors | Sensitive | Log | Security |
|---|---|---|---|---|---|---|---|---|---|
| DA-10 | GET `/desk/v1/sync?cursor={c}` | access | cursor | `{events: [{type, resource_id, version}], cursor}` for resources visible to the caller only | 120/min | `bad_request` (cursor) | WF | none | Events computed through C-22. Removal events are sent when access is lost, with no details. |
| DA-11 | POST `/desk/v1/devices/enroll` | enrollment token (one-time, 24 h, from admin invite) + transport | `{device_key_pk, identity_pk, xwing_pk, attestation?}` | `{device_id, status: pending_approval}` | 5/h | `unauthorized` | SEC | SEC:`device_enroll_requested` | Keys appear in C-14 only after admin approval (AP-06) |
| DA-12 | POST `/desk/v1/devices/{device_id}/revoke` | access + step-up (own device) | — | `204` | 5/h | 404 uniform | SEC | SEC:`device_revoked` | Appends `USER_KEY_REVOKE`; triggers the re-key reminder for the user's cases |
| DA-13 | GET `/desk/v1/channels/{channel_id}/epoch-keys/mine` | channel member | — | `[{key_id, start_day, end_day, state: active\|decrypt_only\|destroy_due}]` for the caller's Member Epoch Keys | 60/h | 404 uniform | none | none | Private halves never leave the Desk; the server holds no private epoch keys (ADR-030) |
| DA-14 | POST `/desk/v1/channels/{channel_id}/epoch-keys` | Triage Set member of the channel (self only) + step-up on first publication per device | `{keys: [{key_id, start_day, end_day, pk, sig_by_member_identity_key}] ≤ 8}` | `202 {publication_day}` | 10/day | `conflict` (overlap), `bad_request` (signature or key not bound to a current `USER_KEY`) | none | SEC:`member_epoch_keys_published` | Desk pre-publishes ≥ 4 epochs ahead (ADR-030). Accepted keys are appended as `MEMBER_EPOCH_KEY` entries at the next fixed weekly publication slot, not at request time (ADR-036(7)) |
| DA-15 | POST `/desk/v1/channels/{channel_id}/epoch-keys/{key_id}/destroy-ack` | owner member | — | `204` | — | 404 | SEC | SEC:`epoch_destroy_ack` | Records that the Desk deleted the private key after its decrypt window |

### 8.3 Intake and triage

| ID | Method Path | AuthZ | Input | Output | Rate | Errors | Sensitive | Log | Security |
|---|---|---|---|---|---|---|---|---|---|
| DA-20 | GET `/desk/v1/intake/envelopes?channel={ch}&cursor={c}` | `intake.list` + active **Triage Set** member of the channel (ADR-037(2)) | filters | `[{import_envelope_id, channel_id, import_date, parts: [{padded_size}], state, escalated_date?, rejectable: bool}]` | 120/min | — (non-triage callers receive an empty list) | WF; SS (date) | CASE:`intake_list` | The Desk trial-decrypts the 16 anonymous slots and hides envelopes it cannot open. Excluded members hold no key for any slot (ADR-030, ADR-033). `import_date` is the fixed-slot date (ADR-038); `rejectable` is true after 14 days pending (ADR-038(6)). Non-triage roles see no intake counts anywhere. |
| DA-21 | GET `/desk/v1/intake/envelopes/{id}/header` | `intake.read` | — | `header_ct`, `manifest_ct` | 600/h | 404 uniform | CT | CASE:`intake_read` | — |
| DA-22 | GET `/desk/v1/intake/envelopes/{id}/parts/{n}` | `intake.read` | Range header allowed | ciphertext stream | 120/min | 404 uniform | CT | CASE:`intake_part_read` | Desk writes via `candor-safefs` only (ADR-027) |
| DA-23 | POST `/desk/v1/intake/envelopes/{id}/triage` | Triage Set member + `intake.triage` (import); `intake.reject` for reject | `{decision: import\|reject\|duplicate, reason_code?, target_case_id?}` + `If-Match` | `200 {state}` (`reject` → `pending_second_approval`) | 120/h | 404, 409 | WF | CASE:`intake_triaged` | Rejection requires a second distinct approver (DA-25), with no auto-expiry. Pending envelopes > 7 days escalate to the independent escalation role at most once per channel per 7 days (ADR-033(2), ADR-038(6)). `duplicate` links to a visible case only. |
| DA-24 | POST `/desk/v1/cases/eligibility` | Triage Set member + `case.create` in channel | `{channel_id, department_id?}` | `{candidates: [{user_id, key_ids, role_label}]}`: channel investigators and department members minus standing `coi_registry` exclusions | 60/h | 404 | WF | CASE:`eligibility_computed` (no counts, no user list in the event) | ADR-037(2): the server does **not** receive the source's COI ticks. The triage Desk removes flagged roles and manager-chain conflicts (using HR data held outside Candor or by the triage member) **locally**, then submits the final wrap set and blinded tags with DA-30. WITHDRAWN: inputs `import_envelope_ids`, `source_excluded_labels`; output `excluded_count_bucket` (RVW-B-01). |
| DA-25 | POST `/desk/v1/intake/envelopes/{id}/reject-approvals` | `intake.reject`, distinct from the first rejecter + step-up | `{approve: bool}` | `200 {state: rejected\|pending}` | 50/day | 404, 403 | WF | CASE:`intake_rejected` | A rejected envelope's row and blobs are deleted immediately so its epoch key can retire (ADR-033(2), ADR-038(6)) |

### 8.4 Cases

| ID | Method Path | AuthZ | Input | Output | Rate | Errors | Sensitive | Log | Security |
|---|---|---|---|---|---|---|---|---|---|
| DA-30 | POST `/desk/v1/cases` | Triage Set member + `case.create` | `{channel_id, import_envelope_ids[] ≤ 32, workflow_def_id, record_ct ≤ 256 KiB, key_epoch: 1, wraps: [{recipient_key_id, wrap_ct}], dek_rewraps: [{import_envelope_id, part, rewrap_ct}], coi_excl_tags: [bytes32] (multiple of 8, padded with random tags), sealed_identity_ct?}` | `201 {case_id, display_ref, version}` | 60/h | `bad_request` (wrap set ⊄ candidate set, fewer than `min_recipients` (default 2) distinct users, tag count not a multiple of 8, or a wrap for a user whose tag is present: BE-018), 404 (envelope not visible) | CT; WF | CASE:`case_created` | ADR-037(3), ADR-044(2). Server validates wraps against the DA-24 candidate set and the blinded tags at commit; envelopes → `imported` |
| DA-31 | GET `/desk/v1/cases?filter…&cursor` | `case.list` (ACL-filtered) | filters: state, channel, due_before_day, assigned_to_me | `[{case_id, display_ref, state, priority, channel_id, received_date, sla_due_day, version, record_ct}]` | 120/min | — | WF; CT | CASE:`case_list` (count bucket only) | No existence leak for non-member cases |
| DA-32 | GET `/desk/v1/cases/{case_id}` | member(case) + `case.read` | — | case row + my `wrap_ct` + members summary | 600/min | 404 uniform | CT; WF | CASE:`case_read` | — |
| DA-33 | PATCH `/desk/v1/cases/{case_id}` | member + `case.update` | allow-listed fields only: `{priority?, labels_ct?, record_ct?}` + `If-Match` | `200 {version}` | 120/h | 400 (unknown field), 409, 404 | CT; WF | CASE:`case_updated{fields}` | Per-role field allow-lists (INC-112) |
| DA-34 | POST `/desk/v1/cases/{case_id}/transitions` | member + transition-specific action | `{transition_id, reason_code?, If-Match}` | `200 {state, version}` | 60/h | 409 (invalid from state), 403, 404 | WF | CASE:`case_transition` | Workflow definition enforced server-side (14-CASE-MANAGEMENT.md) |
| DA-35 | GET `/desk/v1/cases/{case_id}/members` | member | — | `[{user_id, access_level, via, valid_until_day}]` | 120/min | 404 | WF | none | — |
| DA-36 | POST `/desk/v1/cases/{case_id}/members` | member(lead) + `case.share` + step-up; `records` access only by a Triage Set member | `{user_id, excl_tag: bytes32 (HMAC(K_case_excl, user_id) computed by the caller's Desk), access_level: read\|contribute\|lead\|records, valid_until_day? (mandatory ≤ 90 days for `records`), wrap: {recipient_key_id, wrap_ct}}` | `201` | 30/h | **404** for the target user when its tag is in `coi_excl_tag` or it is excluded by `coi_registry` (see note), 409 | CT; WF | CASE:`member_added` | C-22 checks the tag blindly (`candor.coi_tag_present`) and the standing registry; wrap key must be current. Other member Desks recompute the tag on sync and raise `coi_wrap_violation` on mismatch (ADR-037(3)). `records` grants implement ADR-044(5); there is no server-side cross-case search. |
| DA-37 | DELETE `/desk/v1/cases/{case_id}/members/{user_id}` | member(lead) + `case.share` | — | `202 {state: suspended, rekey_recommended: true}` | 30/h | 404 | WF | CASE:`member_removed` (generic `reason_code=REMOVED`) | ADR-044(1): server-side access is suspended immediately; the member's wrap is deleted only through DA-49. |
| DA-38 | POST `/desk/v1/cases/{case_id}/rekey` | member(lead) | `{key_epoch: n+1, wraps[], If-Match}` | `200` | 10/day | 400 (wrap set), 409 | CT | CASE:`case_rekeyed` | New content uses the new key; old wraps kept for old content unless crypto-erasure is requested |
| DA-39 | GET `/desk/v1/cases/{case_id}/records?cursor` | member + `case.read` | cursor | `[{record_id, kind, seq, created_day, author_user_id?, size_bucket, record_ct}]` | 600/min | 404 | CT | CASE:`records_read` | Exact staff times only inside `record_ct` (07 §12) |
| DA-40 | POST `/desk/v1/cases/{case_id}/records` | member + `case.note` | `{kind: note\|task\|decision, record_ct ≤ 256 KiB, key_epoch}` | `201 {record_id, seq}` | 300/h | 404, 400 | CT | CASE:`record_added{kind}` | — |
| DA-41 | POST `/desk/v1/cases/{case_id}/replies` | member + `case.reply` | `{reply_ct ≤ 70,000 B, routing_ct ≤ 2 KiB, record_ct (copy for case history)}` | `202` | 60/h | 404, 403 (channel has no reply capability), 400 | CT | CASE:`reply_queued` | Replies queued to `reply_outbox`; delivered on the next relay cycle; no delivery or read status is ever returned |
| DA-42 | POST `/desk/v1/cases/{case_id}/coi-declarations` | member (self) | `{declaration: conflict\|no_conflict, excl_tag?: bytes32 (own tag, when conflict), replaces_padding_tag?: bytes32}` | `204` | 10/h | 404 | WF | `conflict`: CASE:`member_removed` with generic `reason_code=REMOVED`; `no_conflict`: none | A self-declared conflict suspends the declarant's access immediately, replaces one padding tag with the declarant's blinded tag, and triggers a re-key recommendation. No event, table or export records that the removal was a COI declaration (ADR-037(3); RVW-B-01). WITHDRAWN: event `CASE:coi_declared`. |
| DA-43 | POST `/desk/v1/cases/{case_id}/legal-holds` | `legal_hold.place` + step-up | `{reason_ct}` | `201 {hold_id}` | 10/day | 404 | WF | CASE:`legal_hold_placed` | Blocks crypto-erasure |
| DA-44 | DELETE `/desk/v1/cases/{case_id}/legal-holds/{hold_id}` | `legal_hold.release` + second approver | `{approval_proof}` | `204` | 10/day | 404, 403 | WF | CASE:`legal_hold_released` | Dual control |
| DA-45 | POST `/desk/v1/cases/{case_id}/deletion-requests` | member(lead) + `case.delete` + step-up | `{reason_code}` | `202 {request_id}` | 10/day | 404, 409 (legal hold) | WF | CASE:`deletion_requested` | Second approver required (DA-46); then `crypto_erase_case` job |
| DA-46 | POST `/desk/v1/deletion-requests/{request_id}/approve` | `case.delete.approve`, distinct user + step-up | — | `202` | 10/day | 404, 403 | WF | CASE:`deletion_approved` | — |
| DA-47 | GET `/desk/v1/cases/{case_id}/audit?cursor` | `case.audit.read` (case lead, auditor role) | cursor | CASE events for the case (pseudonymous actors resolvable by the auditor role only) | 60/min | 404 | WF; SEC | CASE:`audit_viewed` | Viewing the audit is itself audited |
| DA-48 | GET `/desk/v1/sla/summary` | access | — | `[{case_id, timer_kind, due_day, state}]` for member cases | 60/min | — | WF | none | — |
| DA-49 | POST `/desk/v1/cases/{case_id}/wrap-deletions`; POST `/desk/v1/wrap-deletions/{request_id}/approve` | member(lead) to request; a distinct member(lead) or OVERSIGHT to approve, + step-up | `{target_user_id}` | `202 {request_id, not_before_day}` | 10/day | 404, 409 (`blocked_min_holders`) | WF; SEC | CASE:`wrap_deletion_requested` / `_approved` / `_executed` (generic, no reason) | ADR-044(1): dual control, 7-day cooling-off, content-free OVERSIGHT notice before execution; execution blocked while it would leave fewer than `min_recipients` holders. Not used for source-requested erasure or retention expiry (those use `crypto_erase_case`) |

Note on DA-36: when the target user is COI-excluded (blinded tag present or standing registry entry), the server returns `404 not_found` for the target (as if the user did not exist in the eligible universe). A generic "cannot add this member" banner is shown. Neither the tag set nor the COI registry is exposed to case members (14-CASE-MANAGEMENT.md).

### 8.5 Evidence

| ID | Method Path | AuthZ | Input | Output | Rate | Errors | Sensitive | Log | Security |
|---|---|---|---|---|---|---|---|---|---|
| DA-50 | GET `/desk/v1/cases/{case_id}/evidence?cursor` | member + `evidence.list` | — | `[{evidence_id, kind: original\|derivative, derived_from?, padded_size, meta_ct, version}]` | 600/min | 404 | CT | CASE:`evidence_list` | — |
| DA-51 | GET `/desk/v1/cases/{case_id}/evidence/{evidence_id}/blob` | member + `evidence.read` (originals may require `evidence.read_original`) | Range | ciphertext stream | 120/min | 404 uniform | CT | CASE:`evidence_read` | Desk writes ciphertext via `candor-safefs` and hands ciphertext plus a single-use per-job key to C-17. Plaintext exists only inside the viewer sandbox (ADR-033 §5). |
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
| DA-71 | POST `/desk/v1/breakglass/requests/{id}/approve` | `breakglass.approve`, distinct user and role + step-up; the approver SHALL hold an independent role outside the legal/management chain (ADR-045) | — | `200 {state: approved_pending_wrap}` | 10/day | 404, 403 | WF | SEC:`breakglass_approved` | — |
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

### 8.9 Desk update metadata (RVW-C-02, RVW-C-13)

| ID | Method Path | AuthZ | Input | Output | Rate | Errors | Sensitive | Log | Security |
|---|---|---|---|---|---|---|---|---|---|
| DA-90 | GET `/desk/v1/updates/{tuf_path}` | access (any Desk) | TUF metadata or target path | Cached TUF metadata/targets from the core update cache (fetched by core via its egress-restricted mirror, 06 §8.7) | 30/day/device | 404 | SYS | none | The Desk refreshes at a fixed daily time independent of Desk start and verifies TUF and transparency inclusion itself (ADR-022). Direct Desk access to the vendor clearnet mirror is ADVANCED |

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
| AP-05 | POST `/admin/v1/users/{user_id}/disable` (also the target of EE SCIM/HR/IdP deprovisioning) | `user.disable` + step-up | `{reason_code}` | `204` | default | 404 | SEC | SEC:`user_disabled` | Revokes sessions synchronously and **suspends** server-side authorization (`case_member.state = suspended`, `channel_member.state = suspended`). It never deletes key wraps (ADR-044(1); RVW-C-03); wrap deletion is DA-49 only |
| AP-06 | POST `/admin/v1/devices/{device_id}/approve` | `device.approve` + step-up; a privileged-role user's device needs a second admin | `{fingerprint_confirmed}` | `200` | default | 404, 409 | SEC | SEC:`device_approved` | Appends `USER_KEY` to C-14 (THR-046); out-of-band fingerprint confirmation required |
| AP-07 | GET `/admin/v1/roles` | `role.list` | — | roles + permissions | default | — | SEC | none | Built-in roles immutable |
| AP-08 | POST `/admin/v1/role-assignments` | `role.assign` + step-up; privileged roles (breakglass.approve, identity custodian, auditor) need a second admin | `{user_id, role_id, scope_type, scope_id, valid_until_day?}` | `201 {assignment_id}` | default | 404, 409 (SoD conflict) | SEC | SEC:`role_assigned` | Separation-of-duties rules enforced (15-AUTHENTICATION-AUTHORIZATION.md); admins cannot grant themselves case access roles |
| AP-09 | DELETE `/admin/v1/role-assignments/{id}` | `role.assign` | — | `204` | default | 404 | SEC | SEC:`role_revoked` | — |
| AP-10 | GET/POST/PATCH `/admin/v1/channels[/{id}]` | `channel.manage`; mode change away from ANONYMOUS = DANGEROUS; `min_recipients` = 1 is DANGEROUS | `{public_label, description_i18n, mode, channel_type: standard\|independent, workflow_def_id, retention_policy_id, reply_enabled, min_recipients (default 2), alternative_channel_id}` | channel | default | 400 (ANONYMOUS channel without `alternative_channel_id`; INDEPENDENT channel whose Triage Set lacks independent-custody devices, ADR-043), 404, 409 | SEC | SEC:`channel_*` | Changes go into the signed config bundle + protection statement |
| AP-11 | GET/POST/PATCH `/admin/v1/channels/{id}/roster[/{member_id}]` | `channel.roster.manage` + step-up. **Additions, role-label changes and Triage Set changes:** proposer + a distinct approver holding an independent role (ADR-036(2)), who confirms `person_ref` out of band. **Removals:** one admin, effective immediately | `{user_id, role_label_i18n, show_name: bool, triage: bool}` | `202 {change_id, effective_day}` (time-locked) or `200` (removal) | default | 409 (Triage Set would exceed `envelope.recipient_slots` or drop below 2; user excluded by the admin COI registry for this channel; fewer than 2 authenticators, ADR-044(2)) | SEC | SEC:`channel_roster_changed` | ADR-036(1)–(3): recorded in 09 `roster_change`; content-free notice to all current members and OVERSIGHT; the change enters C-14 at the weekly publication slot with `effective_day` = approval + 3 days (GOV/HIGH + 7); any member or OVERSIGHT may object during the lock. The `CHANNEL_ROSTER` entry is signed by the Channel Identity Key held only by Triage Set members and OVERSIGHT (never by other members). Role labels require an OVERSIGHT-signed `ROLE_LABEL_CERT`. New members publish Member Epoch Keys before they can receive reports. |
| AP-12 | PUT `/admin/v1/channels/{id}/coi-map` | `coi.manage` + step-up + second admin; loosening (removing any exclusion) additionally needs an independent-role approver | `{categories: [{category_id, label_i18n, excluded_role_labels[]}] ≤ 8}` | `200 {kd_leaf}` (tightening, immediate) or `202 {change_id, effective_day}` (loosening, time-locked as AP-11) | 10/day | 400 | SEC | SEC:`coi_map_changed` | ADR-036(2). Appended to C-14 as `COI_MAP`; source-visible in SW-02/SA-02 |
| AP-13 | POST/PUT `/admin/v1/workflows[/{id}]`, POST `/admin/v1/workflows/{id}/publish` | `workflow.manage` | definition (states, transitions, SLA rules) | `{def_id, version}` | 20/day | 400 (invalid graph) | WF | SEC:`workflow_published` | Versioned; running cases keep their version |
| AP-14 | GET/POST/PATCH `/admin/v1/retention-policies[/{id}]` | `retention.manage` (ADVANCED) | `{retain_days, action, legal_basis_code}` | policy | 20/day | 400 | WF | SEC:`retention_policy_*` | Shortening an in-use policy requires a second admin |
| AP-15 | GET `/admin/v1/config` | `config.read` | — | current bundle (items + classes) | default | — | SEC | none | — |
| AP-16 | POST `/admin/v1/config/changes` | `config.propose` + step-up | `{items: {key: value}}` | `201 {change_id, class, effective_after}` | 20/day | 400 (unknown key or range) | SEC | SEC:`config_proposed{class}` | Class computed server-side from the catalog, never from input |
| AP-17 | POST `/admin/v1/config/changes/{id}/approve` | `config.approve`, distinct admin + step-up | `{signature}` (admin signing key over the bundle) | `200 {state}` | 20/day | 404, 403 | SEC | SEC:`config_approved` | DANGEROUS: 2 signatures + 72 h |
| AP-18 | POST `/admin/v1/config/changes/{id}/cancel` | any admin or auditor | — | `200` | — | 404 | SEC | SEC:`config_cancelled` | — |
| AP-19 | GET `/admin/v1/audit/security?cursor` | `audit.security.read` | filters | SECURITY events | 60/min | — | SEC | SEC:`audit_viewed` | — |
| AP-20 | GET `/admin/v1/audit/checkpoints` | `audit.verify` | — | signed checkpoints | default | — | SEC | none | For external verification |
| AP-21 | GET `/admin/v1/health/summary` | `health.read` | — | per-host check status; source-influenced states (rate limits, Argon2id queue, new-account cap, staging use, relay backlog) only as a global **daily** health band (ADR-038(5), ADR-046(5); RVW-A-27) | default | — | SYS | none | — |
| AP-22 | GET `/admin/v1/reports/aggregates?month={m}` | `reports.read` | one or more closed calendar months | Report catalog from 24 §TEL: k = 10, complementary suppression, no medians/ratios/percentiles for cells < k, no per-channel cells for channels with < 3 cases/month | 10/h | 400 (open month) | SS aggregate | SEC:`aggregate_viewed` | ADR-046(5); THR-039; no drill-down. Supersedes the weekly k ≥ 5 buckets (RVW-B-07/-08) |
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

**Not provided:** any health endpoint on the source onion (information leakage; INC-34).

## 12. Fleet Manager API (**EE**, C-34)

Direction: the instance's fleet agent (in Z-CORE) → C-34 outbound only. There is no inbound connection to customer instances (ARCH-032).

| ID | Method Path | AuthZ | Input | Output | Rate | Errors | Sensitive | Log | Security |
|---|---|---|---|---|---|---|---|---|---|
| FL-01 | POST `/fleet/v1/instances/{opaque_instance_id}/heartbeat` | instance mTLS (certificate issued at enrollment; SAN carries opaque ID) | `{versions: {component: semver}, profile, health: {check_id: status}, license_id}` | `{desired_version?, notices[]}` | 1/15 min | `unauthorized` | SYS | vendor SYS | **No** onion address, hostnames, IPs, tenant names, counts or users |
| FL-02 | GET `/fleet/v1/instances/{id}/desired-state` | as FL-01 | — | Signed (vendor fleet key) document `{target_version, safe_config_templates{}}` | 1/h | — | SYS | none | Instance applies only SAFE-class items automatically. Anything else becomes a proposal in AP-16 for local admins. The instance ignores any item that would disable intake, lower the security floor, change routing (rosters, Triage Sets, COI maps, `min_recipients`), or hold a version below the signed security floor (ADR-040, ADR-045; RVW-C-13). Target versions must also verify via TUF (ADR-022). |
| FL-03 | POST `/fleet/v1/instances/{id}/support-bundles` | as FL-01 + local admin approval token | bundle from AP-27 | `201 {ticket_ref}` | 5/day | — | SYS | vendor SEC | Admin reviews bundle content before upload |
| FL-04 | Fleet console: GET `/fleet/v1/instances`, POST `/fleet/v1/rollouts` | customer or vendor fleet operators (OIDC + WebAuthn) | rollout plan (version, cohort %) | rollout | — | — | SYS | vendor SEC | Rollouts can only select among signed releases identical for all customers (ADR-022) |

## 13. SIEM export API (**EE**, C-26)

| ID | Method Path | AuthZ | Input | Output | Rate | Errors | Sensitive | Log | Security |
|---|---|---|---|---|---|---|---|---|---|
| SI-01 | POST `https://c26:8515/siem-gw/v1/events` | mTLS `audit-exporter` (C-24 host) | `{events: [ScrubbedEvent] ≤ 1,000}` | `204` | 10/s | schema reject | SEC; SYS | SYS | Allow-list: SECURITY and SYSTEM classes only; no CASE events and no source-influenced SYSTEM states finer than the global daily health band (ADR-038(5)); pseudonymous IDs re-keyed with a SIEM-specific pseudonym key. Timestamp precision per 20-LOGGING-AUDITING.md |
| SI-02 | Outbound syslog-TLS (RFC 5425) or HTTPS webhook to customer SIEM | C-26 client certificate | RFC 5424 structured data from `ScrubbedEvent` | — | configurable | retry/buffer 24 h | SEC; SYS | none | Destination allow-listed (ADVANCED) |
| SI-03 | GET `https://c26:8516/siem/v1/events?cursor` (pull mode) | customer SIEM mTLS | cursor | events | 60/min | — | SEC; SYS | SYS | Alternative to push |
| SI-04 | GET `/siem/v1/schema` | as SI-03 | — | JSON Schema of `ScrubbedEvent` | — | — | none | none | Versioned |

`ScrubbedEvent` never contains:
- case IDs;
- channel IDs of ANONYMOUS channels;
- recipient information of any kind;
- envelope or import IDs;
- any source count (per channel or global) at any granularity;
- any SOURCE-SENSITIVE counter;
- any COI-related reason code (ADR-037(3)).

## 14. Requirements

| ID | Requirement | Evidence | Threats | Component | Verification |
|---|---|---|---|---|---|
| API-001 | Every route SHALL be declared in a deny-by-default registry with audience, authentication, authorization action and limits. CI SHALL fail on any undeclared or incompletely declared route. | ADR-029; INC-114; B-GL-37 | THR-021 | C-06; C-10 | TST: `route-registry-lint` |
| API-002 | Tokens and sessions SHALL be bound to exactly one audience and one tenant. A credential presented to another audience SHALL be rejected as unknown. | ADR-029; INC-105; B-SD-20 | THR-021; THR-022 | C-06; C-10; C-21 | TST: cross-context replay matrix (all audiences × all credential types, after logout, across workers) |
| API-003 | Logout and revocation SHALL synchronously invalidate access and refresh tokens (Desk/Admin) and RAM sessions (source). | INC-105 | THR-022; THR-034 | C-06; C-21 | TST: token use after logout returns 401 on all workers |
| API-004 | All public resource identifiers SHALL be random 128-bit values. No sequential, time-ordered or content-derived identifiers SHALL appear in any API. | B-GL-37; INC-112 | THR-021; THR-011 | C-06; C-10; C-12 | TST: ID generator tests; schema lint for serial/identity columns exposed in DTOs |
| API-005 | Resource-bound routes SHALL return an identical 404 (status, headers, body, timing class) for nonexistent, other-tenant and unauthorized resources. | INC-113; INC-114; INC-11 | THR-021; THR-045 | C-10; C-06 | TST: enumeration test comparing responses and timing distributions (KS p > 0.01) |
| API-006 | Mutation endpoints SHALL accept only explicit per-role field allow-lists and SHALL reject unknown fields. No generic attribute-setting endpoint SHALL exist. | INC-112; B-GL-37 | THR-021; THR-034 | C-10 | TST: property-based mass-assignment fuzzing per endpoint per role |
| API-007 | Desk and Admin requests SHALL carry a valid `Candor-PoP` device signature with ±60 s freshness and nonce replay protection. | ADR-029; B-GL-04 | THR-022 | C-10; C-15; C-21 | TST: replayed, stale and wrong-device PoP rejected |
| API-008 | Source Web SHALL function fully without JavaScript. All no-JS routes SHALL send `script-src 'none'` and the §3.10 header set. | ADR-003; ADR-004; INC-27 | THR-008; THR-006 | C-06 | TST: header golden test against the deployed onion (external probe); e2e in Tor Browser "Safest" |
| API-009 | Source Web SHALL NOT send `Server`, `Date`, `ETag` or `Last-Modified` headers, SHALL NOT use compression, and SHALL pad responses to route size classes. | ADR-011; INC-118 | THR-004; THR-011 | C-06 | TST: response size distribution test per route; header golden test |
| API-010 | Source Web state-changing requests SHALL be POST with a synchronizer CSRF token, a `SameSite=Strict` `__Host-` cookie and Origin validation. | INC-117; B-SD-13 | THR-021 | C-06 | TST: CSRF suite (missing, wrong or foreign token; foreign Origin) |
| API-011 | No source-facing API SHALL return a case ID, submission ID, recipient identity, exact timestamp or read/delivery status. | ADR-010; INC-11 | THR-011; THR-019 | C-06 | TST: response schema inspection; INSP |
| API-012 | Login and challenge endpoints SHALL be indistinguishable for existing and nonexistent source accounts (response body class, status, timing floor). | INC-112 | THR-034 | C-06; C-08 | TST: timing and size indistinguishability test |
| API-013 | Tier V uploads SHALL use per-upload random capabilities (`U`), SHALL NOT require a session, and SHALL be linked to an account only at envelope commit. | ADR-026; B-SD-11 | THR-047 | C-03; C-06; C-08 | TST: DB inspection after an interrupted upload shows no account linkage; AUD: protocol review |
| API-014 | Mailbox listings SHALL always contain exactly 32 entries (dummies included), and fetch or delete of a reply SHALL NOT be propagated to Z-CORE. | ADR-010; ADR-011; B-SD-11 | THR-011; THR-015 | C-06; C-08 | TST: list-size invariance; relay protocol has no fetch-state field (schema test) |
| API-015 | The Source App SHALL verify directory checkpoints (signature, witness cosignatures when configured, consistency with the last seen checkpoint) and inclusion proofs before encrypting to any key. | ADR-004; INC-14; B-CR-37 | THR-046; THR-007 | C-03; C-14 | TST: malicious-server harness serving a forked tree, a stale checkpoint and a missing proof |
| API-016 | Relay endpoints SHALL require pinned mTLS plus signed, counter-protected requests, and SHALL offer no operation that queries source accounts or mailboxes. | ADR-009; INC-103 | THR-014; THR-015 | C-08; C-09 | TST: relay API inventory test; replay and unsigned-request tests |
| API-017 | The Admin API SHALL expose no endpoint returning case records, key wraps, evidence, envelope ciphertext or sealed identity data. | ADR-015; INC-114 | THR-018 | C-10 | TST: route inventory diff (ARCH-012) |
| API-018 | Configuration change requests SHALL have their class computed server-side from the catalog, and DANGEROUS changes SHALL require two distinct admin signatures and a 72-h cool-off. | ADR-013; INC-114 | THR-035 | C-10 | TST: e2e config workflow tests |
| API-019 | Case creation, member addition and re-key SHALL be rejected if the submitted wrap set differs from the server-computed eligible set or uses non-current directory keys. Member Epoch Key publication SHALL be rejected unless signed by the publishing member's current identity key. | ADR-015; ADR-030; INC-14 | THR-046; THR-020 | C-10; C-22 | TST: wrap-set mismatch tests for DA-30, DA-36, DA-38; forged-signature test for DA-14 |
| API-020 | Adding a COI-excluded user to a case SHALL fail with a uniform 404 for the target user, without revealing the COI registry to the caller. | ADR-015; INC-22 | THR-020 | C-10; C-22 | TST: COI add-member scenario |
| API-021 | Export of originals SHALL require approvals from two distinct users other than the creator, with step-up. Connectors SHALL fetch only approved packages addressed to them. | ADR-018; ADR-012 | THR-029; THR-041 | C-10; C-40 | TST: approval matrix tests; connector cross-fetch test |
| API-022 | Break-glass endpoints SHALL enforce distinct requester and approver users and roles, ≤ 72-h duration, member notification, and review by a third, independent user. | ADR-015 | THR-018; THR-019 | C-10; C-22 | TST: break-glass state-machine tests |
| API-023 | Every content-bearing Desk read SHALL emit a CASE audit event before the response body is sent. If audit append fails, the request SHALL fail. | ADR-016; INC-68 | THR-019; THR-037 | C-10; C-24 | TST: audit outage causes read failure; audit completeness test |
| API-024 | Error responses SHALL contain only closed error codes and SHALL never echo input values, IDs, SQL, paths or stack traces. | ADR-016; INC-120 | THR-016 | all API components | TST: `error-scrub` canary test across all endpoints |
| API-025 | Desk/Admin APIs SHALL reject requests bearing an `Origin` header and SHALL emit no CORS headers. | ADR-007; INC-117 | THR-022 | C-10 | TST: CORS negative tests |
| API-026 | Desk clients SHALL write all downloaded ciphertext through `candor-safefs` and SHALL treat every server-supplied field (names, sizes, counts, redirects) as hostile. | ADR-027; INC-101; INC-102; INC-104 | THR-023; THR-014 | C-15 | TST: malicious-server harness (path injection in every field, redirects 301–308, oversize counts) |
| API-027 | API clients (Desk, Source App, relay, fleet agent) SHALL disable HTTP redirects, cookies (except Source Web) and proxy-from-environment, and SHALL pin the endpoint at the connection layer. | INC-104; B-SD-36 | THR-014; THR-001 | C-03; C-09; C-15; C-34 | TST: redirect and Alt-Svc tests with packet capture |
| API-028 | The aggregate reporting API SHALL enforce k ≥ 5 suppression and a minimum 7-day range with week buckets. | ADR-016 | THR-039 | C-10 | TST: small-cell tests |
| API-029 | The SIEM export SHALL pass only allow-listed SECURITY/SYSTEM event schemas with SIEM-specific pseudonyms, and SHALL never pass case, envelope, recipient-slot or SOURCE-SENSITIVE data. | ADR-018; INC-56 | THR-016; THR-029 | C-24; C-26 | TST: exporter schema tests; canary fields dropped |
| API-030 | Fleet heartbeats SHALL contain only the FL-01 fields. Fleet desired-state SHALL auto-apply only SAFE items, and target versions SHALL independently pass TUF verification. | ADR-022; ADR-020 | THR-025; THR-027 | C-34 | TST: fleet payload schema test; malicious fleet server harness |
| API-031 | Health events SHALL be schema-strict. Host identity SHALL come from the agent certificate only. | INC-103 | THR-016; THR-035 | C-25 | TST: spoofed host-role payload test |
| API-032 | Unknown request fields SHALL be rejected. Duplicate JSON keys SHALL be rejected. Response parsers in clients SHALL ignore unknown non-critical fields. | B-SD-28; INC-112 | THR-021 | all | TST: parser conformance tests |
| API-033 | Servers SHALL support API major version N and N−1 for ≥ 12 months, and SHALL return 426 to clients below the minimum version published in the key directory. | Design | — | C-06; C-10 | TST: version negotiation tests |
| API-034 | Desk intake listing and fetch SHALL be restricted to active roster members of the envelope's channel. No API SHALL expose which members can open an envelope. | ADR-015; ADR-030; ADR-033 | THR-020; THR-021 | C-10; C-22 | TST: non-roster list and fetch return empty or 404; response schema has no recipient fields |
| API-035 | Cursors SHALL be AEAD-protected and bound to principal and filter. A foreign or modified cursor SHALL be rejected. | INC-113 | THR-021 | C-10 | TST: cursor tampering and cross-user tests |
| API-036 | Source Web (SW-02/SW-03) and Source App (SA-02) SHALL present the ADR-030 COI checklist from the verified directory (default none selected), and SHALL fail closed without submitting when fewer than `min_recipients` eligible members remain. | ADR-030; INC-22 | THR-020; THR-040 | C-03; C-06; C-07 | TST: e2e selections excluding all members yield the fail-closed page and no stored envelope; DEMO: usability test of the checklist |
| API-037 | Source App directory, release and mailbox responses SHALL be padded to 4-KiB multiples, and dummy mailbox ciphertexts SHALL be size-indistinguishable from real ones within buckets. | ADR-011 | THR-004; THR-011 | C-06 | TST: size distribution tests |
| API-038 | There SHALL be no health, status, debug or metrics endpoint on the source onion. | INC-34 | THR-001; THR-035 | C-06 | TST: path scan against the onion returns the uniform 404 for all non-listed paths |

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
