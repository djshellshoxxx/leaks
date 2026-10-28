# IMPL-RM8 — Tier V clients: Candor Source App (embedded Arti, encrypted vault) and WEBCAT-signed web bundle

Status: Draft v1.0 (2026-10-01) · Edition applicability: both (single generic build for all tenants) · Owner: T5 Source App; T1 (crypto/protocol client code); T2 (web bundle server side); T7 (distribution) · Roadmap milestone: RM-8

Global rules are in `IMPL-00-SECURE-IMPLEMENTATION-STANDARD.md` and are not repeated. Rule ID sources as in `IMPL-RM5-OPERATIONS.md`.

## 1. Purpose and scope

| Item | Content |
|---|---|
| Goal | A source can encrypt on their own device before upload, verify the organisation's recipient keys against the Key Directory, and leave a device that, without the passphrase, shows only that the app is installed |
| Components | C-03 (Source App: Linux AppImage incl. Tails, Windows, macOS, Android; iOS optional "higher trace"), C-11 (candor-core client use), C-14 (client verification VR-*), C-06 (serves the WEBCAT bundle and tenant JSON), C-32/C-33 (`source-app` and `web-bundle` TUF targets, project onion mirror), C-37 (never hosts the app) |
| Spec sections | ADR-004, ADR-039, ADR-041, ADR-047(1)(4)(6), ADR-050(3); 04 §11.8 (vault, K44), §12.2 (Tier V sealing), §14.5 (client verification VR-*), §24 (server-delivered code); 11 (Tier V flows); 16 §6.2, §9.1, §17 (client transport, Arti use); 33 §15.2, §15.3, §16 (Source App update, distribution, WEBCAT signing); 05 (device residue guidance); 29 ST-014, ST-090..ST-095, ST-171, ST-172; 30 AT-090; 37 A13 |

## 2. Preconditions

| # | Precondition |
|---|---|
| P1 | RM-7 GA: production TUF roles `source-app` and `web-bundle` exist; WEBCAT Sigsum signer keys generated (RM7-S1) |
| P2 | candor-core Tier V APIs (`seal_submission`, `open_reply`, directory verification) frozen and A4/A5/A6-reviewed |
| P3 | Malicious-server harness (ADR-027, ST-090..ST-097) available for client targets |
| P4 | Framework ADR recorded before S1 closes: desktop and Android shells, Rust core shared; constraints of §3 S1 binding |
| P5 | Project onion mirror and ≥ 2 independent byte-identical mirrors committed (SCM-069) |

## 3. Build sequence

### RM8-S1 App architecture, Rule-of-2 and shell hardening

| Aspect | Specification |
|---|---|
| Build | Rust core crate (`candor-source-client`) holding protocol, vault and transport; thin UI shell per platform; Rule-of-2 table entry (R8 §5.2) for C-03 |
| Rules | Untrusted input (server responses, replies) parsed only in Rust with bounded parsers (SI-A-02/03); if a WebView UI is used: bundled assets only, no remote capability, one capability file per window, Isolation pattern, strict CSP (SI-F-01); reply text rendered as text nodes only, no HTML/Markdown, links shown inert with a copy action (SL-R-002, SL-R-008); no `shell`/`opener` plugin, no custom URI scheme handler, no OS "open externally" for server-influenced strings (SL-R-008); no analytics, crash reporting, push or ads SDKs (ST-014, ADR-023); no OS keychain, recent-files, clipboard history, notification content or window titles containing tenant data; screenshots blocked on Android (`FLAG_SECURE`) |
| Pitfalls | INC-SL-09 (Signal Desktop HTML injection), INC-SL-11 (Tutanota XSS → RCE), INC-SL-12 (Element link → local execution), INC-117 (client-chosen security flag accepted by server) |
| Verify | Capability-manifest snapshot test; XSS/mXSS corpus through every reply/name render path (CSP violation count = 0); link-handling E2E (`file://`, `smb://`, `javascript:`, custom schemes → no navigation); ST-014 egress/SDK scan |

### RM8-S2 Embedded Arti transport (`ClientTransport`)

| Aspect | Specification |
|---|---|
| Build | `ClientTransport { bootstrap(bridges), connect(onion, isolation), shutdown }` (16 §6.2) over `arti-client` pinned exactly; features: onion-service client, vanguards (default), client `hs-pow`, bridges/pluggable transports (16 §12) |
| Rules | All app traffic through Arti; no socket APIs outside the transport crate (build-time check) and OS proxy/VPN settings ignored (16 §17); no DNS; fresh isolation token per app session plus a separate token for witness fetch; circuits torn down on exit; no background networking on mobile; fail closed with no clearnet fallback when bootstrap fails (ADR-002), offering bridges; Arti state directory outside the vault is documented device residue (THR-048) and is wiped by "Remove all Candor data"; Arti version tracked in the Platform/SBOM and advisories followed (TROVE) |
| Pitfalls | INC-36 (Tor Browser `file://` leak class: no local-URL handling), INC-35 (guard discovery via timing → vanguards on), INC-29 (traffic confirmation: residual) |
| Verify | Network namespace test: app traffic only to Tor entry; DNS capture empty; ST-014; bootstrap-failure UX shows no unsafe fallback (feeds AT-070 G1b/G1c) |

### RM8-S3 Fixed-size encrypted vault (ADR-047(1), 04 §11.8)

| Aspect | Specification |
|---|---|
| Build | Vault module: `VAULT_SIZE = 512 KiB`, created at first launch before any interaction; format `vault_salt ‖ nonce ‖ AEAD ciphertext ‖ tag`; K44 derivation (Argon2id m = 64 MiB, t = 3, p = 1 → HKDF label `candor/v1/source-app/vault`); full rewrite with fresh nonce, `fsync`, atomic rename on every change and at every exit; "Remove all Candor data" overwrites with a fresh random-key empty vault of the same size |
| Rules | Tenant onion address, ORG_ROOT fingerprint, Key Directory pin, witness endpoints, report index, drafts and passphrase-derived material exist only inside the vault or in RAM; first-session data in RAM only until passphrase confirmation; wrong passphrase and unused vault indistinguishable, no failure counter; unlock time independent of vault state (constant work: always run KDF and AEAD over full size); no compression inside the vault (SL-R-005); secret buffers pre-sized, zeroized, `mlock` where the OS allows (SI-A-05); key label registered and unique (SL-R-011); vault writes via validate-then-write into the app's private dir only (SL-R-001); updates preserve the vault byte-for-byte in size and location (33 §15.2) |
| Pitfalls | INC-63/INC-SL-05 (size side channel), INC-101 (write-before-validate), THR-048 seizure scenario |
| Verify | ST-171 (size/structure identical across never-used / one tenant / several tenants); AT-090 seized-device examination of three device states; dudect-style unlock-timing test (SI-A-06 method) used vs unused; filesystem diff after install, use and removal shows no tenant data outside vault |

### RM8-S4 Protocol client and key-directory verification

| Aspect | Specification |
|---|---|
| Build | Tier V sealing (04 §12.2) with COI filter applied locally (ADR-030); recipient-set verification by deterministic re-derivation of all 16 slots (ADR-050(3)); VR-* client verification (04 §14.5) incl. witness checkpoint fetch over a separate isolation token (ADR-036(5)); fetch-all reply retrieval in fixed order every inbox session (ADR-039); snapshot freshness ≤ 7 days by independent time (ADR-047(4)) |
| Rules | Trust decisions bind to full key bytes in `Verified<DirectoryEntry>` typestate; no re-resolution by ID (SL-R-003); refuse to seal to keys absent from the verified directory or with < required witness cosignatures (ST-093, ST-151); pin last seen tree head inside vault and reject rollback/inconsistency; warn on member keys < 7 days old (ADR-036(3)); server-supplied filenames never used for writes (SL-R-001); uniform `DecryptError` (R8 §2.2 pattern 7) |
| Pitfalls | INC-62/INC-SL-04 (Matrix key/ID confusion), INC-14 (Anom hidden recipient), INC-01 (Hushmail server-delivered code), INC-101/INC-102 (server-controlled paths) |
| Verify | ST-090..ST-095 malicious-server harness incl. key swap behind unchanged ID; ST-033; ST-172 freshness; property tests with N ≥ 2 heterogeneous recipients where only element k is invalid (SL-R-006); `cargo mutants` on verify fns |

### RM8-S5 Update path and distribution (ADR-041, 33 §15.2–§15.3)

| Aspect | Specification |
|---|---|
| Build | In-app TUF client (shared with RM-5 verifier code) fetching from the project onion mirror via Arti; embedded `root.json`, witness key set and witness onion endpoints; distribution pages on the project onion service and ≥ 2 independent mirrors; F-Droid reproducible build; optional generic store listings |
| Rules | Identical update requests for every user, never organisation-specific; refuse submit/login below the security floor; refuse submit when metadata unrefreshed > 30 days or expired; embedded end-of-life date; downloaded installers deleted after install and no persistent update logs; one generic build per platform for all tenants; per-locale wordlists ship inside the build as signed assets; C-37 never hosts or logs downloads; iOS and store installs labelled "higher trace" in UI and 05 guidance |
| Pitfalls | INC-52 (Linux Mint download replacement), INC-46 (third-party hosting takeover), INC-48 |
| Verify | ST-130 cases on the app updater; request-equality capture across two tenants; mirror byte-identity check (SCM-069); download page served without third-party resources |

### RM8-S6 Reproducible multi-platform builds

| Aspect | Specification |
|---|---|
| Build | Builders A and B reproduce AppImage, Windows, macOS and Android payloads; APK reproducible against the onion-served APK; platform signatures applied after hash agreement (33 §5.2) |
| Rules | Crypto KATs and Wycheproof run on every shipped arch incl. aarch64 Android/macOS and forced-portable backends (SL-R-004); `cargo auditable`; no build-time network |
| Verify | ST-131 per platform; diffoscope empty on unsigned payloads; multi-arch KAT matrix green |

### RM8-S7 WEBCAT-signed web bundle (ships disabled)

| Aspect | Specification |
|---|---|
| Build | Static HTML/CSS/JS/WASM bundle for Tier V-web (04 §24); WEBCAT manifest listing every path, hash and the CSP; Sigsum signatures 2-of-3; `web-bundle` TUF target; C-06 feature flag; tenant data served as JSON only; CLIENT_RELEASE directory entry on deployment (33 §16) |
| Rules | Feature flag OFF until Tor Browser enforces WEBCAT for onion origins (04 OI-10); when off, C-06 serves CSP `script-src 'none'`; when on, CSP `script-src 'self' 'wasm-unsafe-eval'` with hashes and no inline script (SI-C-03); bundle identical for all tenants, no tenant code; Tier W remains the default and fully functional without JS (ADR-004); server never trusts a client claim that content is already encrypted to skip server-side checks (INC-117); no third-party resources; CSP evaluated in CI with a bypass corpus (SL-R-007) |
| Pitfalls | INC-01 (Hushmail), INC-117, INC-46/INC-53 |
| Verify | `csp-evaluator` (or equivalent) 0 findings ≥ Medium; watcher compares served assets with logged manifest (ST-155); rollback of manifest version rejected; flag-off test shows no script served |

### RM8-S8 Verification UX, guidance and client audit

| Aspect | Specification |
|---|---|
| Build | Key-directory verification UX (pin fingerprint display, warnings for new member keys, mismatch stop screens); 05 guidance on acquisition and residue; short usability round (AT-070 subset, n ≥ 12) on verification UX; 37 A13 audit (38 calls it "A5 audit (client)") |
| Rules | Tier W UI SHALL NOT show verification affordances it cannot deliver (ADR-036); honest residual text: app presence visible, unlocked-device compromise not covered |
| Verify | Usability results per 30 §10.4; A13 report with 0 open Critical/High |

## 4. Auditor threat checklist (component-specific)

| # | Check | Threats |
|---|---|---|
| 1 | Is any tenant identifier, onion address, pin or passphrase-derived value written outside the vault (prefs, logs, caches, thumbnails, crash files, OS keychain, notification history)? | THR-048, THR-034 |
| 2 | Does vault size, structure, mtime pattern or unlock time differ between unused and used states? | THR-048 |
| 3 | Can any code path open a socket, resolve DNS or follow OS proxy settings outside Arti? | THR-001, THR-002 |
| 4 | Does the app fall back to any non-Tor path on bootstrap failure? | THR-001, THR-040 |
| 5 | Can a malicious server swap a key behind an unchanged ID, add a hidden recipient, roll back the directory or serve a stale snapshot? | THR-046, THR-007 |
| 6 | Are update requests identical across tenants and users, and is the floor enforced? | THR-025 |
| 7 | Can server-supplied text trigger HTML rendering, navigation, file writes by name or OS handoff? | THR-008, THR-023 |
| 8 | Is the web bundle actually inert (no scripts served) while WEBCAT is unavailable? | THR-007 |
| 9 | Are KATs run on every arch/backend shipped (incl. aarch64 fallbacks)? | THR-012 |
| 10 | Do distribution pages or mirrors log or fingerprint downloaders? | THR-002, THR-036 |

## 5. Test plan

| Test | Command / tool | Gate |
|---|---|---|
| Core tests | `cargo test -p candor-source-client --locked`; multi-arch matrix (x86_64, aarch64, forced portable) | PR; SL-R-004 |
| Fuzz | reply/directory/TUF parsers `cargo fuzz run <target> -- -max_total_time=3600` | SG-07 |
| Malicious server | ST-090..ST-095 | SG-09 |
| Vault | ST-171; AT-090; unlock-timing t-test | SG-29; SG-10 |
| Egress | run app in netns, `tcpdump` shows only Tor entry flows; ST-014 | PR (C-03) |
| Render safety | XSS/mXSS corpus, link-handoff E2E, capability snapshot | PR |
| CSP | csp-evaluator on bundle CSP; flag-off/flag-on header tests | SL-R-007 |
| Reproducibility | ST-131 per platform | SG-13 |
| Usability | AT-070 subset on verification UX | SG-24 |
| Audit | 37 A13 | RM-8 exit |

## 6. OPSEC checklist

| Exposure | Control |
|---|---|
| App presence on device | Disclosed in 05; Tails/AppImage path recommended; removal keeps vault-shaped file |
| App-store account records | Optional; labelled "higher trace"; never on employer-managed phones |
| Download source observed | Project onion primary; clearnet mirrors disclosed; C-37 never hosts |
| Arti guard/state files | Documented residue; wiped on removal |
| Update fetch fingerprinting | Identical requests via Arti to project onion mirror |
| Witness fetch links tenant | Separate isolation token; fixed request shape per witness |
| Reply retrieval reveals activity | Fetch-all fixed order every session (ADR-039) |
| WEBCAT enrollment publishes onion address | Address already public; disclosed in 33 §16 |

## 7. Exit criteria

| Type | Criterion |
|---|---|
| Roadmap (38 RM-8) | Source App reproducible across builders; client audit complete (37 A13); key-directory verification UX tested |
| Spec gates | SG-09, SG-10, SG-13, SG-29 (ST-171), AT-090 pass; web bundle disabled by default with CSP `script-src 'none'` until WEBCAT available |
| Audit gate | Each step RM8-S1..S8 audited independently (`process/audits/AUDIT-RM8-Sn.md`); 0 open Critical/High; Medium fixed or lead-accepted in writing |
| Milestone record | Signed RM-8 report logged (RM-005) |

## 8. Requirements

| ID | Requirement | Evidence | Threats | Component | Verification |
|---|---|---|---|---|---|
| IMP-RM8-001 | All Source App network traffic SHALL go through embedded Arti; the build SHALL fail if socket or DNS APIs are reachable outside the transport crate. | ADR-004; 16 §17 | THR-001, THR-002 | C-03 | ST-014; TST: netns egress capture |
| IMP-RM8-002 | On Arti bootstrap failure the app SHALL NOT use any non-Tor path and SHALL offer bridges. | ADR-002; INC-36 | THR-001, THR-040 | C-03 | TST: bootstrap-failure E2E; AT-070 (G1b/G1c) |
| IMP-RM8-003 | The app SHALL create one 512 KiB encrypted vault at first launch and SHALL store tenant identifiers, pins and passphrase-derived values only inside it or in RAM. | ADR-047(1); 04 §11.8 | THR-048, THR-034 | C-03 | ST-171; AT-090 |
| IMP-RM8-004 | Vault unlock time and file properties SHALL NOT depend on whether the vault holds data, and a wrong passphrase SHALL be indistinguishable from an unused vault. | ADR-047(1); INC-63 | THR-048 | C-03 | TST: unlock-timing t-test; ST-171 |
| IMP-RM8-005 | Updates SHALL preserve the vault byte-for-byte in size and location and SHALL NOT create per-tenant files. | 33 §15.2 | THR-048 | C-03 | TST: upgrade filesystem diff |
| IMP-RM8-006 | The client SHALL seal only to keys in a verified Key Directory snapshot ≤ 7 days old with required witness cosignatures, binding trust to full key bytes in a verified typestate. | ADR-047(4); ADR-036(5); INC-62 | THR-046, THR-007 | C-03 | ST-093; ST-151; ST-172; TST: `trybuild` compile-fail |
| IMP-RM8-007 | The client SHALL verify all 16 recipient slots by deterministic re-derivation and quarantine on any mismatch. | ADR-050(3); INC-14 | THR-046 | C-11 | ST-090..ST-095; TST: slot-swap vectors |
| IMP-RM8-008 | Server-supplied text SHALL render only as plain text; the app SHALL contain no URI handler, opener/shell capability or external-open path for server-influenced strings. | INC-SL-09; INC-SL-12; SL-R-008 | THR-008, THR-023 | C-03 | TST: XSS corpus; TST: capability snapshot; TST: link-handoff E2E |
| IMP-RM8-009 | Update checks SHALL be identical for all users and tenants, go to the project onion mirror via Arti, and block submission below the security floor or with metadata > 30 days old. | 33 §15.2; ADR-040 | THR-025 | C-03 | ST-130 (app); TST: request-equality capture |
| IMP-RM8-010 | One generic build per platform SHALL be distributed from the project onion service and ≥ 2 byte-identical independent mirrors; the organisation's clearnet site SHALL NOT host or log downloads. | ADR-041; INC-52 | THR-002, THR-025 | C-33 | INSP: SCM-069 mirror check; ST-131 |
| IMP-RM8-011 | Source App artifacts SHALL be reproduced bit-identically by Builders A and B for every platform, with KATs run on every shipped architecture. | SL-R-004; INC-SL-07 | THR-024, THR-012 | C-31 | ST-131; TST: multi-arch KAT matrix |
| IMP-RM8-012 | The WEBCAT bundle SHALL ship disabled until Tor Browser enforces WEBCAT for onion origins; while disabled C-06 SHALL send `script-src 'none'`. | ADR-004; 33 §16; INC-01 | THR-007 | C-06 | TST: CSP header test; ST-155 |
| IMP-RM8-013 | The web bundle SHALL be identical for all tenants, 2-of-3 Sigsum-signed, logged, and served under a CI-evaluated CSP with hashes and no inline script. | 33 §16; SL-R-007; INC-117 | THR-007, THR-024 | C-06 | TST: csp-evaluator; TST: manifest rollback rejection |
| IMP-RM8-014 | The app SHALL include no analytics, crash-reporting, push or advertising SDKs and SHALL keep no persistent logs. | ADR-023; INC-53 | THR-036, THR-048 | C-03 | ST-014; INSP: SBOM review |

## 9. Residual risks and open issues

| # | Item | Handling |
|---|---|---|
| R1 | App presence on a seized device is visible | Disclosed (05); Tails path recommended |
| R2 | Flash storage may retain old vault generations | Disclosed (04 §11.8 honest limits) |
| R3 | Compromised unlocked device defeats the app | Out of scope; disclosed |
| R4 | iOS App Store binaries cannot be user-verified | "Higher trace" labelling (33 §20) |
| R5 | Arti client vulnerabilities affect all app users | Exact pin, advisory tracking, floor raises |
| R6 | WEBCAT may never ship in Tor Browser | Tier W + Source App remain; bundle stays disabled (38 risk register) |
| OI-1 | UI framework per platform not yet fixed by ADR | P4 precondition |
| OI-2 | 38 "A5 audit (client)" corresponds to 37 A13 | Cross-document request (see IMPL-RM6 OI-2) |
