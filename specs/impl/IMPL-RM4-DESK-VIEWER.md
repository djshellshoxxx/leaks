# IMPL-RM4 — Candor Desk and Evidence Viewer

Status: Draft v1.0 · Edition applicability: both (Qubes/L2+ profiles optional in CE) · Owner: T4 Desk & Viewer (key storage and re-wrap with T1) · Standard: `IMPL-00-SECURE-IMPLEMENTATION-STANDARD.md`

## 1. Purpose and scope

| Item | Content |
|---|---|
| Milestone | RM-4 (`38` §4): Desk (Tauri), hardware-bound key storage (FIDO2 PRF / PIV / TPM), import and re-wrap, case UI, conversation, viewer microVM with pixels-to-PDF + mat2 + qpdf, Export Package with dual approval |
| Components | C-15 Candor Desk (Rust core + Tauri 2 webview) · C-17 Evidence Viewer / Containment (L1 microVM jobs; L2 Qubes DispVM optional) · C-19 Admin Console (admin mode of Desk, same binary) · C-18 air-gapped station (guidance and image only, optional) |
| Specs implemented | 12 (R01–R16, §4 shell, §6 containment indicators, §7 interlocks, §8 COI, §11–§12) · 10 (§3–§16: evidence model, pipeline, containment levels, platform tiers, sanitization, limits, redaction, export) · 13 (admin mode) · 15 §4.3 (login and key unlock) · 26 (WCAG 2.2 AA) · 04 §9 (key hierarchy on the Desk), §13.7–§13.8 · ADR-007, -012, -018, -027, -030, -037, -042, -043, -044, -047(7) |
| Not in scope | Source App (RM-8), Desk auto-update via TUF (RM-5; the Desk ships through signed packages until then), EE Qubes split-VM profile hardening (RM-9) |

## 2. Preconditions

| # | Precondition |
|---|---|
| P1 | RM-3 exit: desk-api, key directory, EKV, audit and authz in place. The malicious-server harness framework (ADR-027) exists in candor-lab |
| P2 | RM-1 `kd` verifier and `Verified<T>` API, `candor-safefs` Export/Store policies, `candor-core` stanza and record formats frozen |
| P3 | Feature threat models approved: `RM4-desk-ipc-capabilities`, `RM4-key-custody`, `RM4-viewer`, `RM4-export` (abuse cases: malicious server, malicious source file, malicious insider, managed endpoint) |
| P4 | Signed and reproducible viewer image pipeline (RM-0 builders) and a TUF target for the image |
| P5 | Accessibility test plan (26) and an assistive-technology reviewer available |

**Spec-over-research resolution:** R7 SI-G-01 proposes rootless Podman + gVisor as the CE default viewer. **10 §6 / ADR-042 rule that gVisor is not an L1 substrate.** L1 = Firecracker (Linux/KVM), Qubes DispVM, Hyper-V isolated VM or Virtualization.framework VM. A gVisor-only host is "Reduced tier" (text only). The Dangerzone two-phase design (pixels out, rebuild PDF on the host side in a second sandbox) and its flags (no network, cap-drop, `no-new-privileges`, logging off, signed image) apply **inside** L1, not instead of it.

## 3. Build sequence

### 4.1 Desk process architecture and Tauri hardening (C-15)
- **Build:** a Rust core holding all keys and crypto (via `candor-core` only). The webview is a pure view layer. `frontendDist` is bundled static assets only: no `devUrl` in release, no `remote` capability. One capability file per window listing only that window's commands. The case-view window gets read-only view-model commands only. The Isolation pattern is on, with a minimal validator. No `shell`, `opener`, `fs`, `http` or `dialog`-write plugin exposed to the webview. No custom URI scheme handler. `on_navigation` → deny except the app origin. New windows blocked. CSP per SI-F-01 (`default-src 'self'; script-src 'self'; connect-src ipc: http://ipc.localhost; img-src 'self' asset: blob:; object-src 'none'; frame-src 'none'; base-uri 'none'; form-action 'none'`), plus Trusted Types. TS `strict`. ESLint `no-unsanitized`, `react/no-danger`, no `innerHTML`/`eval`/`new Function` (27 §12.5 Desk UI). npm installs with `--ignore-scripts` from a SHA-512 lockfile (SCM-013/014). Every Tauri command validates its args (typed, `deny_unknown_fields`, bounded) and checks the caller window label.
- **Rules:** SI-F-01, SL-R-002, SL-R-007, SL-R-008. ADR-042. IMP-STD-022.
- **Pitfalls:** INC-SL-09 (Signal Desktop: HTML injection → RCE). INC-SL-11 (Tutanota: XSS → privileged API). INC-SL-12 (Element: link → local binary execution). INC-SL-13 (Wire: secondary renderers). RUSTSEC-2022-0088/0091 (Tauri FS-scope bypass). Merged capability boundaries when a window is listed in two capability files (B-SI-38).
- **Verify:** a capability-manifest snapshot test (any new permission fails CI without `security/desk-capability` approval). A CI assertion that there is no `remote` key, no `devUrl` in release, and the CSP is set. A red-team build hook injects JS into the case-view webview and asserts every IPC call except the allow-listed reads is denied. `csp-evaluator` 0 findings ≥ Medium. An IPC fuzz harness calls every command with fuzzed args from an untrusted window.

### 4.2 Hostile-string rendering (C-15)
- **Build:** one renderer for all untrusted text (messages, questionnaire answers, declared filenames, case fields from sources): `textContent` only, no Markdown, HTML, mentions, highlighting or link detection. Bidi and confusable controls made visible. Links shown as defanged text with a "copy" action only (no navigation, no OS handoff). Bounded length with an explicit truncation marker. No `blob:` URLs for attacker bytes. Attachments are never shown in the webview, only as Viewer-produced raw RGBA frames (10 §6).
- **Rules:** SL-R-002, SL-R-008. ADR-042. 12 §7.
- **Pitfalls:** INC-SL-10 (Proton: sanitized output processed again, mXSS). INC-36 (TorMoil: `file://` handoff). INC-SL-13 (renderer count > 1).
- **Verify:** ST-160 Desk plain-text rendering fuzz. ST-072 XSS polyglot and mXSS corpus through every render path (CSP violation counter = 0). E2E test: a submission with `file:///`, `smb://`, custom-scheme and `javascript:` links causes no navigation or handoff. An AST lint asserting the renderer count = 1. ST-090 hostile names to the Desk.

### 4.3 Hardware-bound key storage and unlock (C-15, T0)
- **Build:** the Desk keystore (04 §13.8 records) sealed by a hardware-bound key: FIDO2 `hmac-secret`/PRF (preferred), PIV + PIN, or TPM + PIN. The CE software fallback shows a persistent "Weaker protection" badge. Keys live only in the Rust core in `SecretBox` with `mlock` and the platform equivalent of no-dump (`PR_SET_DUMPABLE=0`, Windows `SetProcessMitigationPolicy`, WER `LocalDumps` off, WebView2 crash reporter off, macOS `ReportCrash` exclusion). Auto-lock after `DESK_IDLE_LOCK` (default 10 min), and on OS lock, sleep or token removal, clearing the webview DOM and plaintext caches. Posture checks at unlock (12 §4.1). Custody indicator (ADR-043). Case-key cache with the erasure-log-first rule (12 §4.3).
- **Rules:** SI-A-05, SI-A-06, SL-R-011. ADR-007, ADR-043, ADR-047(7). IMP-STD-006, IMP-STD-007.
- **Pitfalls:** INC-55 (vault theft) → local cache sealed to hardware. Plaintext persisting in webview caches or DOM after lock. OS crash dumps uploading memory. INC-72 (staff sharing media) → interlocks (§4.6).
- **Verify:** ST-027 zeroization (Desk core). ST-162 independent-custody enforcement. ST-163 key-access continuity. ST-175 re-wrap after vault loss. AT-028 (stolen device: a/b/c variants). AT-019 recipient-side sinks (DOM after lock, temp dirs, OS caches, swap, crash dumps).

### 4.4 Sync, import, trial-decrypt and re-wrap (C-15, T0)
- **Build:** a sync client over the desk-api using `candor-http` (redirects off, pinned origin, no proxy-from-env, no cookie store). Key-directory verification through the RM-1 `kd` verifier (split view → block). Erasure-log verification **before** any other sync operation. Triage Set trial-decrypt of import envelopes. Full 16-slot recipient-set verification (ADR-050(3)), quarantining on mismatch. Envelope-key validity ± 1 day flagged. Case creation and re-wrap only to `Verified` member keys, with wrap-set verification mirroring 07 §5.5 on the client. Blinded COI tag computation client-side (ADR-037(3)). Reply sealing to the source X-Wing key. Every server-supplied name and size goes through `candor-safefs` validate-then-write (SL-R-001).
- **Rules:** SL-R-001, SL-R-003. ADR-027, ADR-030, ADR-037, ADR-050. IMP-STD-010, IMP-STD-011.
- **Pitfalls:** INC-101 / INC-SL-01 (server-chosen filename written before the check). INC-62 / INC-SL-04 (key swapped behind an unchanged ID). INC-14 (hidden recipient). INC-104 (redirect origin bypass).
- **Verify:** malicious-server harness ST-090..ST-097 (hostile names, sizes, counts, nesting, ordering, redirects, key substitution, split view, rollback, hostile batch, transport identity). ST-093 hidden recipient. ST-165 undecryptable envelope. An inotify test: no inode outside the store on hostile `Content-Disposition`. `fuzz_desk_sync` registered as an ST-045/046 sub-target.

### 4.5 Evidence Viewer (C-17)
- **Build:** a per-platform L1 substrate (Firecracker + jailer on Linux/KVM; Qubes DispVM; Hyper-V; VZ) with no NIC, no shared FS, no device passthrough, no clipboard, no serial console in production, a read-only signed rootfs (TUF target hash verified before **each** launch) and tmpfs ≤ 8 GiB, a fixed UTC timezone and locale, vCPU 2 / RAM 4 GiB / 10 min wall-clock per object, and destruction after each job. I/O is a single virtio-vsock (or hvsocket) channel with a framed, length-prefixed protocol (max frame 64 MiB) carrying input bytes in and raw RGBA pages out. The host validates width, height, page count and total bytes before allocating. Phase 2 (in a second L1 VM): rebuild the PDF from pixels, OCR the text layer inside the sandbox (ADR-042 accessibility), `qpdf` normalize, `mat2` metadata strip. The containment probe runs at every unlock (no route, no key mount, fresh disk). Transformation records carry the converter release digest, platform tier and output hash. Labelled "rendering — not evidence". The Desk host never decodes PNG or PDF (10 §6). A Reduced-tier host gets text-only mode.
- **Rules:** SI-G-01 (flags inside L1), SI-G-02, SI-G-03. ADR-012, ADR-042. 10 §6, §10 (limits). Rule of 2 (R8 §5.2: untrusted input + unsafe parsers → privilege must be low). IMP-STD-024.
- **Pitfalls:** INC-27/INC-28 (NIT-class exploits; beacons calling home) → no NIC, and ST-084 network-attempt detection. THR-119 (decompression bombs). Polyglots (ST-087). INC-17/INC-18/INC-20 (metadata in documents) → sanitizer verification. Image signature not checked on update (Dangerzone independent updates, B-SI-43).
- **Verify:** ST-084 weaponized-document containment (CVE PoC corpus for LibreOffice, poppler and ImageMagick; zip and decompression bombs; host `tcpdump`/eBPF shows no network). Escape canaries (read a host canary file, open a socket → fail). ST-085 sanitizer and redaction verification (metadata fields absent after `mat2`/`qpdf`; text layer correct). ST-087 polyglots. ST-161 platform-tier enforcement. ST-049 `fuzz_archive` (bridge). A tampered-image launch is refused. Frame-bounds fuzzing of the host-side frame parser (`fuzz_viewer_frames`).

### 4.6 Case UI, conversation, interlocks and admin mode (C-15/C-19)
- **Build:** screens R02–R16 per 12. Safety interlocks (12 §7): no print, save or open-externally of originals; export only through the Export Package flow; screenshot protection requested on viewer windows. COI indicators (12 §8) with no exclusion identities shown. Notifications in-app only. Admin mode (13) shares the binary, uses the separate `admin-api` audience and a separate capability set, and has no content views (ADR-015). Step-up prompts for 15 §5.8 operations.
- **Rules:** ADR-015, ADR-029, ADR-037, ADR-045. SL-R-007.
- **Pitfalls:** INC-72 (staff exfiltrating media). INC-56 (support artefacts containing session data) → no HAR or log export with tokens. THR-041 (forwarding originals).
- **Verify:** ST-068 (admin mode cannot reach content), ST-070 break-glass flows, ST-164 org-as-adversary controls, AT-047 (no read receipts reach sources), AT-092 mode banners, WCAG 2.2 AA audit (26; axe-core + manual AT, AT-074).

### 4.7 Export Package with dual approval (C-15)
- **Build:** export only of sanitized derivatives by default, with originals requiring an elevated dual approval (10 §15). Redaction applied to pixels and the text layer (10 §14; no overlay redaction). A package format with a padded size class (no compression before encryption unless padded; SL-R-005), a signed manifest with chain of custody and transformation records, written through `candor-safefs` `RootPolicy::Export`. A second approver on a different device (`RequireSecondApprover`). Audit events at CASE class.
- **Rules:** ADR-018, SL-R-005. 10 §14–§15. 15 §5.8.
- **Pitfalls:** INC-19 (overlay redaction: Calipari, Manafort). INC-18 (Word revision history). INC-SL-05 (compression leaking size). THR-029 (integration exfiltration).
- **Verify:** ST-085 redaction verification (redacted text not recoverable from the PDF or text layer). ST-086 symlink containment on export trees. An export size-class test. ST-070 dual authorization. AT-019 recipient-side sinks after export.

### 4.8 Desk build, reproducibility and accessibility
- **Build:** Desk payloads built by builders A and B (SCM-032). Webview dependencies vendored (no runtime CDN; SCM-015). Static assets metadata-stripped. TUF metadata refreshed on a fixed daily schedule through the Z-CORE mirror (12 §4.1). Signed packages (TUF-wrapped updater in RM-5; SI-F-03).
- **Verify:** ST-131 on Desk artefacts. AT-052 (no external requests from the Desk; network capture). WCAG 2.2 AA audit report.

### 4.9 Malicious-server harness run and independent audit
- **Build:** run the full harness ST-090..097 against Desk builds on Linux, macOS and Windows and against the C-17 bridge (SG-09). Then the independent audit gate.
- **Verify:** 100 % harness pass. 0 open Critical/High.

## 4. Component-specific threat checklist (auditor)

| # | Check | Threat |
|---|---|---|
| A1 | No untrusted string reaches the DOM except through the single `textContent` renderer. No `innerHTML`, Markdown, link detection or `blob:` for attacker bytes | THR-023, THR-008 |
| A2 | Capabilities: one file per window, no remote, no shell/opener/fs/http plugin, no custom scheme, navigation denied. The case-view window has only read commands | THR-023 |
| A3 | Every Tauri command validates args and the caller window. No command returns key material to the webview | THR-013, THR-023 |
| A4 | Server-supplied names and sizes are never used for writes (validate-then-write via safefs). Redirects off. Origin pinned | THR-023, THR-007 |
| A5 | Trust decisions (recipients, re-wrap, directory) use `Verified<T>`. All 16 slots are re-derived. Split view blocks | THR-046 |
| A6 | Keys only in the Rust core, hardware-sealed at rest, zeroized on lock. DOM and caches cleared on lock. Crash reporting disabled. Not dumpable | THR-013, THR-031 |
| A7 | Viewer: no NIC or shared FS. Signed image verified per launch. Destroyed per job. Host-side frame parser bounded. The Desk never decodes PNG/PDF | THR-023, THR-107 |
| A8 | Phase 2 sanitization removes metadata. Redaction is real (pixels plus text layer). Output labelled as a rendering | THR-009, THR-037 |
| A9 | Export: dual approval, padded size, safefs export root, chain-of-custody manifest | THR-029, THR-041 |
| A10 | Admin mode cannot reach content APIs or views. Step-up enforced | THR-018 |
| A11 | No telemetry, crash upload or update check outside the fixed daily schedule. No clearnet URL opens | THR-036, THR-002 |
| A12 | COI: no exclusion identity shown or logged. Blinded tags computed client-side | THR-020 |
| A13 | Managed-endpoint and custody indicators are honest (non-authoritative wording per ADR-043) | THR-126 |

## 5. Test plan

| ID | Test | Command / tool |
|---|---|---|
| ST-090..097 | Malicious-server harness | `cargo test -p candor-lab --test malicious_server -- --desk <build>` on Linux/macOS/Windows |
| ST-072/160 | XSS, mXSS, plain-text rendering fuzz | `npx playwright test desk/tests/xss.spec.ts` (Tauri WebDriver); `cargo fuzz run fuzz_desk_text` |
| Capability snapshot | Tauri ACL | `cargo test -p candor-desk --test capabilities` (diff vs `security/desk-capabilities.snapshot`) |
| IPC deny | Injected-JS red team | `cargo test -p candor-desk --features redteam-hook --test ipc_deny` |
| CSP | Policy evaluation | `csp-evaluator` (vendored) on the built `tauri.conf.json` CSP |
| ST-084/087 | Hostile file corpus | `candor-lab viewer-corpus --level L1 --capture-net` |
| ST-085 | Sanitizer and redaction | `cargo test -p candor-viewer-host --test sanitize`; `pdftotext` recovery check |
| ST-161/162/163/175 | Platform tier, custody, continuity, re-wrap | candor-lab Desk suites |
| ST-027 | Zeroization | Desk core memscan test build |
| ST-131 | Desk reproducibility | `scripts/repro-check.sh desk` on builders A/B |
| AT-019/028 | Recipient sinks, stolen device | `candor-lab drill AT-028{a,b,c}`; sink sweep of the profile dir, temp, crash dirs, swap |
| AT-052 | No external requests | Network capture during the Desk E2E |
| A11Y | WCAG 2.2 AA | `axe-core` on all screens + manual screen-reader pass (AT-074) |
| ESLint | TS security rules | `npx eslint --max-warnings 0 desk/src` (`no-unsanitized`, `react/no-danger`) |
| npm | Install policy | `npm ci --ignore-scripts`; lockfile integrity check |

## 6. OPSEC checklist

| Metadata at risk | Prevention |
|---|---|
| Plaintext on the recipient disk (caches, temp files, swap, crash dumps, thumbnails, OS indexers) | No plaintext files. Keystore sealed. Webview cache disabled. DOM cleared on lock. Crash reporting off. Viewer output never written to the host except the sanitized export via safefs |
| Desk start and usage times visible to mirrors, proxies or the vendor | TUF refresh on a fixed daily schedule via the Z-CORE mirror. No telemetry. No update check at start |
| Evidence beacons (remote images, DNS, tracking pixels) | Viewer has no NIC. The webview never renders evidence. CSP `connect-src` IPC only |
| Source identity through document metadata in exports | Phase 2 `mat2` + `qpdf`, pixels-only rebuild, ST-085 |
| Recipient behaviour leaking to the source (read receipts, presence) | None exist (AT-047) |
| Clipboard and screenshots | No viewer clipboard channel. OS capture protection requested. Defanged "copy" for links only |
| COI exclusions visible on screen | Indicators without identities (12 §8) |
| Managed endpoint reading the screen or memory | Honest custody indicator and blocking for INDEPENDENT channels (ADR-043). Residual is documented |

## 7. Exit criteria (RM-4 definition of done)

- [ ] The malicious-server harness (ADR-027; ST-090..097) passes on all Desk builds and the C-17 bridge (38 RM-4 exit; SG-09).
- [ ] The hostile-file corpus (29) is contained at L1 (CL-1 in 38 wording): no network attempts, no escapes, bounded resources (ST-084, ST-087).
- [ ] WCAG 2.2 AA audit of the Desk passed (38 RM-4 exit).
- [ ] Desk reproducible build verified on builders A and B (38 RM-4 exit; ST-131).
- [ ] Capability snapshot, injected-JS IPC-deny test and XSS/mXSS corpus green. Renderer count = 1.
- [ ] ST-160..163, ST-175 pass. AT-019 and AT-028 drills ⊆ oracle.
- [ ] Export dual approval and redaction verification pass (ST-070, ST-085).
- [ ] SPEC-NOTES complete for `candor-desk`, `candor-viewer-host` and the viewer image. Independent audits closed (0 open Critical/High).

## 8. Requirements

| ID | Requirement | Evidence | Threats | Component | Verification |
|---|---|---|---|---|---|
| IMP-RM4-001 | The Desk webview SHALL load only bundled assets, with no remote capability, no `devUrl` in release, the Isolation pattern on and the SI-F-01 CSP. | B-SI-38; B-SI-39; B-SI-41 | THR-023; THR-008 | C-15 | TST: config assertion test; `csp-evaluator` |
| IMP-RM4-002 | Each window SHALL have exactly one capability file listing only its commands. Any added permission SHALL fail CI without security approval. | B-SL-35; INC-SL-11 | THR-023 | C-15 | TST: capability snapshot test |
| IMP-RM4-003 | The Desk SHALL expose no shell, opener, fs or http plugin, no custom URI scheme, and no OS handoff for any attacker-influenced string. | INC-SL-12; INC-36; B-SL-36 | THR-023 | C-15 | TST: AST lint; link-handoff E2E |
| IMP-RM4-004 | Untrusted text SHALL be rendered through a single `textContent` renderer with visible bidi/confusable controls and defanged links. | INC-SL-09; INC-SL-10; INC-SL-13; ADR-042 | THR-023; THR-008 | C-15 | TST: ST-160; ST-072; renderer-count lint |
| IMP-RM4-005 | Every Tauri command SHALL validate typed, bounded arguments and the caller window, and SHALL NOT return key material to the webview. | B-SI-38; B-SL-11 | THR-013; THR-023 | C-15 | TST: IPC fuzz; injected-JS deny test |
| IMP-RM4-006 | Private keys SHALL be sealed by a hardware-bound key (FIDO2 PRF, PIV or TPM), held only in the Rust core, zeroized on lock, and the process SHALL be non-dumpable with OS crash reporting disabled. | ADR-007; B-SI-04; INC-55 | THR-013; THR-031 | C-15 | TST: ST-027; AT-028 |
| IMP-RM4-007 | The Desk SHALL verify the erasure log before any other sync operation and purge listed cases' cached keys and local data. | ADR-047; ADR-025 | THR-017 | C-15 | TST: ST-163; ST-175 |
| IMP-RM4-008 | Server-supplied names and sizes SHALL never determine a write location. Content SHALL be validated before linking via safefs, and the HTTP client SHALL not follow redirects. | INC-101; INC-104; B-SL-26; ADR-027 | THR-023; THR-007 | C-15 | TST: ST-090; ST-092; inotify test |
| IMP-RM4-009 | Recipient and re-wrap decisions SHALL use `Verified<T>` directory entries, re-derive all 16 slots, and block on split view. | INC-62; INC-14; ADR-050 | THR-046 | C-15 | TST: ST-093; ST-094 |
| IMP-RM4-010 | Evidence SHALL be opened only in an L1-or-higher substrate with no NIC, shared FS or device passthrough, using a signed image verified before each launch and destroyed after each job. | ADR-042; B-SI-42; B-SI-43; B-SI-44; INC-27 | THR-023; THR-107 | C-17 | TST: ST-084; ST-161; tampered-image test |
| IMP-RM4-011 | The Desk host SHALL accept only bounded raw RGBA frames from the viewer and SHALL NOT decode PNG, PDF or other formats. | ADR-042; B-SL-45 | THR-023 | C-15; C-17 | TST: `fuzz_viewer_frames`; link-analysis check |
| IMP-RM4-012 | Sanitized derivatives SHALL be rebuilt from pixels with metadata stripped and an in-sandbox OCR text layer, and redaction SHALL remove underlying pixels and text. | INC-17; INC-18; INC-19; INC-20 | THR-009; THR-037 | C-17 | TST: ST-085 |
| IMP-RM4-013 | Export Packages SHALL require dual approval, SHALL be padded to a size class, and SHALL be written only through the safefs export root. | ADR-018; B-SL-30; INC-63 | THR-029; THR-041 | C-15 | TST: ST-070; ST-086; size-class test |
| IMP-RM4-014 | Admin mode SHALL use the `admin-api` audience and a separate capability set with no content views or commands. | ADR-015; ADR-029 | THR-018 | C-19; C-15 | TST: ST-068 |
| IMP-RM4-015 | The Desk SHALL make no network requests other than the desk-api and the fixed-schedule TUF refresh, and SHALL include no telemetry or crash upload. | ADR-023; INC-53 | THR-036; THR-002 | C-15 | TST: AT-052; ST-014 |
| IMP-RM4-016 | Desk UI dependencies SHALL be installed with scripts disabled from an integrity-pinned lockfile, and no asset SHALL load from third-party origins. | INC-42; INC-45; INC-46; INC-47 | THR-024; THR-036 | C-15 | TST: `npm ci --ignore-scripts`; SCM-015 check |
| IMP-RM4-017 | Desk artefacts SHALL be reproducible across builders A and B before release. | B-SL-03; ADR-022 | THR-024; THR-025 | C-15; C-31 | TST: ST-131 |
| IMP-RM4-018 | The Desk SHALL meet WCAG 2.2 AA, including accessible text renditions of sanitized evidence. | ADR-042 | THR-041 | C-15 | AUD: accessibility audit; TST: axe-core |
| IMP-RM4-019 | The Desk SHALL show the custody status honestly and block INDEPENDENT-channel intake on devices not attested as independent. | ADR-043 | THR-126; THR-019 | C-15 | TST: ST-162 |

## 9. Residual risks and open issues

- **WebView engines are memory-unsafe C++** (27 §9 inventory). Isolation, CSP and a single text renderer reduce but do not remove exposure to engine bugs.
- **A managed or compromised recipient endpoint can read decrypted content** (ADR-043 honest residual). Custody indicators are non-authoritative.
- L1 substrates depend on hypervisor isolation. A VM escape exposes the recipient host. Qubes and L3/L4 remain options for high-risk cases.
- Tier 2 (Windows Hyper-V, macOS VZ) substrates are harder to verify than Firecracker. The containment probe detects misconfiguration, not hypervisor bugs.
- OCR inside the sandbox can mis-recognise text. Sanitized renditions are labelled "rendering — not evidence".
- Open: Tauri updater single-key minisign must be wrapped in TUF (SI-F-03) at RM-5. Until then, only signed packages are distributed.
- Open: hardware PRF availability varies by platform (38 risk register). The software fallback is CE-only with a warning.
