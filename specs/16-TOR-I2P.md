# 16 — Anonymity Transport Specification (Tor, I2P, Transport Abstraction)
Status: Draft v1.1 (round-2 revision: ADR-034..046) · Edition applicability: both (identical anonymity transport in CE and EE) · Owner: Network Anonymity team

## 1. Purpose and scope

Specifies the anonymity transport for Candor's ANONYMOUS mode (ADR-001, ADR-002, ADR-003): the evidence-based choice between Tor and I2P, the Transport Adapter abstraction and its admission criteria, the exact tor configuration of the Intake Gateway (C-05), the Arti migration plan, onion-service key custody and compromise response (THR-044), onion address publication and verification, source guidance on bridges and pluggable transports, DoS defences (ADR-026), enforcement of "no clearnet fallback", reachability monitoring that does not observe source traffic, and an attack-class table.

Out of scope: application-level cryptography (04-CRYPTOGRAPHY.md), source operational security content (05-SOURCE-OPSEC.md), host hardening beyond network rules (17-INFRASTRUCTURE.md), anonymity test procedures (30-ANONYMITY-TESTING.md).

**What the transport protects (protection statement).** The onion-only transport is designed to prevent Candor components, the hosting provider and any party compelling them from learning a source's IP address (THR-001), and to hide the intake server's location from sources and network observers, under the assumptions that the source uses a current, unmodified Tor client, that the Tor network's relay population is not dominated by one adversary, and that no adversary observes both the source's and the service's network links (NA-1..NA-5 below). It does **not** hide that the source uses Tor from the source's local network (THR-002), does not defeat end-to-end timing correlation by an adversary watching both ends (THR-003), and only partly mitigates website fingerprinting (THR-004). Residual risks are in §20.

### 1.1 Network assumptions (to be registered as ASM-* in 40-SECURITY-ASSUMPTIONS.md)
| Label | Assumption |
|---|---|
| NA-1 | Tor v3 onion-service cryptography and path selection work as specified; tor/Arti are current (≤ 72 h behind a security release). |
| NA-2 | No single adversary controls a large fraction of guard and middle capacity for long periods (KAX17-class Sybils are eventually removed, B-AN-24). |
| NA-3 | No global passive adversary observes both the source's access link and the intake gateway's link (Tor explicitly excludes this adversary, R4 §2.1). |
| NA-4 | The source's device and Tor client are not compromised (THR-008 out of transport scope). |
| NA-5 | The Intake Gateway host has no network path that bypasses tor for source-facing traffic (enforced §14). |
| NA-6 | The signed Tor consensus (directory-authority majority) and at least one of ≥ 2 independently operated Roughtime servers give an honest time floor/cross-check that Z-CORE cannot influence (04 CA-10, ADR-036(6)). |

## 2. Context and dependencies

| Document | Relationship |
|---|---|
| DECISIONS.md | ADR-001 (Tor only + abstraction), ADR-002 (no fallback), ADR-003 (no Tor Browser fingerprinting), ADR-009 (intake/core separation), ADR-010 (timing), ADR-016 (logging), ADR-021 (per-customer onion), ADR-024 (profiles), ADR-026 (abuse), ADR-028 (secret placement), ADR-032 (onion key on ≤ 2 HA intake hosts). Round 2: ADR-035(1) (External Watchers fetch over Tor), ADR-036(5)/(6) (witness endpoints, independent time from the Tor consensus + Roughtime), ADR-038(5) (no queue/rate-limit oracle; daily health band), ADR-039 (fetch-all replies), ADR-040 (tor from pinned Platform Manifest), ADR-041 (client acquisition), ADR-046(3) (intake updates via the project onion mirror), ADR-046(8) (PQ transport residual), ADR-046(9) (vanguards fallback) |
| 02-THREAT-MODEL.md | THR-001..005, 008, 011, 016, 032, 035, 044, 047 |
| 03-PRIVACY-ANONYMITY.md | Timing/size minimization that complements transport |
| 04-CRYPTOGRAPHY.md | K16 onion key in key table; K01 signs onion address statements; onion TLS option (§5.1) |
| 05-SOURCE-OPSEC.md | Source-facing guidance text (bridges, networks, devices) |
| 06-SYSTEM-ARCHITECTURE.md | Transport Adapter placement |
| 11-FRONTEND-SOURCE.md | Page weight uniformity, no-JS, outage page |
| 17-INFRASTRUCTURE.md, 18-DEPLOYMENT.md | Host, firewall, hypervisor, profile-specific settings |
| 20-LOGGING-AUDITING.md | Log suppression for tor and web server |
| 30-ANONYMITY-TESTING.md | Verification of NET requirements |
| 31-INCIDENT-RESPONSE.md | Onion key compromise runbook |
| 33-RELEASE-UPDATE-SECURITY.md | tor/Arti version floors, updates to intake hosts |
| 37-SECURITY-AUDIT-PLAN.md | Transport audit scope |

## 3. Adversaries relevant to transport (from R4 §1)

| Adversary | Capability | Transport-level relevance |
|---|---|---|
| A. Employer / reported-on organisation | Corporate egress with TLS interception, EDR/MDM, document-access logs | Sees Tor use and timing from managed networks/devices; highest-likelihood adversary (INC-31 Eldo Kim) |
| B. National LE/intelligence | ISP compulsion, relay operation, long-term timing analysis | Guard discovery and timing (INC-35 BKA/Ricochet), NIT on seized servers (INC-27, INC-28) |
| C. Global/multi-AS passive | Large share of Internet paths | Out of scope for low-latency networks (NA-3) |
| D. Malicious relay operators | Sybil guards/middles | Guard discovery, tagging (INC-29 RELAY_EARLY, INC-30 KAX17) |
| E. DoS attacker / censor | Floods onion services; blocks Tor | Availability; pushes sources to riskier channels |

## 4. Evidence-based comparison: Tor vs I2P for Candor

| Criterion | Tor v3 onion services | I2P | Edge | Evidence |
|---|---|---|---|---|
| Maturity | Since 2004; v3 onion services since 2017; C-tor plus Rust Arti; funded team | Since 2003; small volunteer team; two implementations (Java I2P, i2pd) with different Sybil defences | Tor | B-AN-45, B-AN-48, B-AN-53 |
| Anonymity-set size | Millions of daily users (UNVERIFIED current Tor Metrics figure); ~7–8k relays (UNVERIFIED) | ~15–32k routers (2018–2026) | Tor (~100×) | B-AN-33, B-AN-54 |
| Architecture / tunnel design | Circuit-switched, bidirectional 3-hop circuits (6 hops client↔service via rendezvous); directory authorities publish a consensus (trust root that enables bad-relay removal) | Packet-switched garlic routing; unidirectional inbound/outbound tunnels (round trip crosses 4 tunnels); every node relays; DHT netDb held by floodfills that anyone meeting thresholds can become | Mixed in principle; in practice Tor | B-AN-33, B-AN-50 |
| Attack resistance (service location) | Vanguards-lite built in (0.4.7), full vanguards add-on / Arti full mode; PoW; active relay removal | netDb Sybil/eclipse (RAID 2013, ICISSP 2015); **all tested I2P hidden services' IPs deanonymized with 15 floodfills over 8 months (NDSS 2026)** | Tor | B-AN-11, B-AN-13, B-AN-55, B-AN-56, B-AN-57 |
| Attack resistance (clients) | Guard discovery and correlation are PRACTICAL for state adversaries on long-lived endpoints (INC-35); WF LAB→PRACTICAL for one monitored site | Same correlation class; small set magnifies intersection; one CNN study failed lab→live transfer (weak evidence) | Tor (set size) | B-AN-04, B-AN-05, B-AN-16, B-AN-58 |
| Availability under attack | 2022–23 DDoS mitigated by PoW (0.4.8) | Recurring February floodfill floods (2023, 2024); Feb 2026 ~700k hostile nodes (≈39:1) disrupted network | Tor | B-AN-26, B-AN-53, B-AN-54 |
| Client availability | Tor Browser (Win/macOS/Linux), Tor Browser for Android, Onion Browser (iOS, third-party, weaker), Tails/Whonix | Router install + separate browser config; Windows "Easy Install Bundle" beta; Android apps; no iOS (UNVERIFIED) | Tor (decisive) | B-AN-49, B-AN-59, B-AN-60 |
| Hardened uniform browser | Tor Browser (security levels, letterboxing) | None equivalent (user's own Firefox profile) | Tor | B-AN-59 |
| Source usability | One download, connects in about a minute, bridges built in | Tunnel warm-up of minutes, router must integrate, browser proxy config | Tor | R4 §5 |
| Enterprise/managed-network usability | Tor use detectable (public relay list, DPI); bridges hide it from simple blocking | Detectable (P2P patterns, reseed hosts); a relaying P2P router on a managed device is a louder signal | Neither — guidance: never use employer network/device | B-AN-33; INC-31 |
| Censorship resistance | Proven PT ecosystem (Russia 2021, Iran 2022) | Cheap to block by peer blacklisting (IMC 2018); no mature PT ecosystem (UNVERIFIED) | Tor | B-AN-30, B-AN-33 |
| Bridges | Unlisted bridges distributed via BridgeDB/Moat and built-in lists (Knowledge (unverified) distribution channels) | No equivalent (reseed servers only for bootstrap) | Tor | B-AN-31 |
| Pluggable transports | obfs4, Snowflake (WebRTC), WebTunnel (HTTPS-like, 2024), Conjure (alpha) | None mature (UNVERIFIED) | Tor | B-AN-30, B-AN-31, B-AN-32 |
| Hidden-service equivalent | .onion v3 (ed25519, blinded descriptors), restricted discovery (client auth), Onion-Location | Eepsites/destinations, b32 addresses, encrypted LeaseSets | Tor (ecosystem, tooling) | B-AN-44; R4 §3.1 |
| Discovery | Self-authenticating 56-char address; Onion-Location from clearnet; directory precedent (SecureDrop) | b32 addresses; addressbook/jump services (trust issues) | Tor | R4 §5 |
| Deployment complexity (server) | One tor daemon, torrc, optional vanguards add-on; well documented | Router must relay and needs uptime to integrate; tunnel tuning | Tor | R4 §5 |
| Protocol maintenance / roadmap | Arti (CGO stable 2.5.0, congestion control, restricted discovery), C-tor client deprecation roadmap | Active (SSU2, ECIES done) but small team | Tor | B-AN-45, B-AN-48, B-AN-51, B-AN-52 |
| Research depth | Hundreds of papers; attacks drive fixes | Few papers — fewer known attacks, less assurance | Tor | R4 §5 |
| Public audits | Multiple (UNVERIFIED list — e.g., Tor Browser, Arti) | None public located (UNVERIFIED negative) | Tor | R4 §4 |
| Mobile | Official Android; iOS via Onion Browser (weaker); Arti embeddable in apps | Android only | Tor | B-AN-49 |
| Platform support | Win/macOS/Linux/Android/iOS(3rd-party)/Tails/Whonix; Debian packages (deb.torproject.org) | Win/macOS/Linux/Android | Tor | R4 §3.3 |
| Admin burden | Low–moderate | Moderate–high | Tor | R4 §5 |
| Government/enterprise concerns | Tor often blocked/alerted in enterprises; seeing Tor from a managed device is itself a signal; running an onion service is lawful in target jurisdictions (Knowledge (unverified), legal review in 25) | Same, and relaying traffic from organisation infrastructure raises policy objections | Tor (less objectionable server footprint: no relaying) | R4 §5 |
| Precedent | SecureDrop, GlobaLeaks onion services | No major whistleblowing platform on I2P (UNVERIFIED) | Tor | B-SD-04; B-GL-04 |

## 5. Option analysis and decision (ADR-001)

| Option | Security | Privacy | Usability | Operations | Verdict |
|---|---|---|---|---|---|
| TOR ONLY | Largest set; vanguards; PoW; bad-relay removal; weak vs GPA | IP never reaches platform; Tor use visible locally | Tor Browser everywhere incl. Safest (no-JS) | Low–moderate; C-tor→Arti migration ahead | **Adopted** |
| I2P ONLY | Practical service IP deanonymization (NDSS 2026); recurring Sybil floods; no audits | Tiny anonymity set | No hardened browser; minutes of warm-up; no iOS | Relaying router; higher burden | Rejected |
| TOR + I2P | Doubles attack surface; I2P users get weaker anonymity under the same "ANONYMOUS" label (THR-040) | Splits the anonymity set | Confusing choice for sources | Two stacks to patch, monitor, audit | Rejected |
| TRANSPORT ABSTRACTION | Enables C-tor→Arti swap and future cover-traffic transports; risk: invites weak transports | Neutral with admission criteria | Neutral | Engineering cost | **Adopted as architecture** (§6) with strict admission criteria |

**Decision (conforms to ADR-001, ADR-046(9)):** ANONYMOUS mode is reachable only through a Tor v3 onion service on C-05, served by C-tor ≥ 0.4.8 with PoW and vanguards-lite (full vanguards add-on required in HIGH-risk profiles while it is maintained; documented fallback §7.2) until Arti onion services meet §9 criteria. The Transport Adapter interface (§6) is implemented; the only admitted anonymous transports in v1 are `tor-onion-v3-ctor` (service) and `tor-arti` (client, in C-03). I2P is not shipped.

## 6. Transport Adapter interface and admission criteria

### 6.1 Server-side interface (Rust, in C-06's process boundary; normative)
```rust
/// Opaque, per-circuit, random, in-memory only. Never persisted, logged, exported or derived from network identity.
#[derive(Copy, Clone, Eq, PartialEq, Hash)]
pub struct CircuitToken(u64);

pub enum AnonymityClass { Anonymous, Confidential }   // Confidential = C-38-style non-anonymous transports

pub struct AdmissionRecord {            // signed by K01 + 2 Key-Admins; logged in the key directory (04 §14) as policy
    pub transport_id: &'static str,     // e.g. "tor-onion-v3-ctor", "tor-onion-v3-arti"
    pub class: AnonymityClass,
    pub criteria_evidence: Vec<(CriterionId, EvidenceRef)>,
    pub approved_adr: &'static str,
}

#[async_trait::async_trait]
pub trait TransportAdapter: Send + Sync {
    fn id(&self) -> &'static str;
    fn admission(&self) -> &AdmissionRecord;
    async fn start(&self, cfg: &TransportConfig) -> Result<(), TransportError>;   // fails closed; no partial start
    async fn accept(&self) -> Result<InboundStream, TransportError>;
    async fn health(&self) -> TransportHealth;   // aggregate, bucketed, non-identifying (§15)
    async fn stop(&self) -> Result<(), TransportError>;
}

pub struct InboundStream {
    pub io: Box<dyn AsyncReadWrite + Send + Unpin>,   // byte stream only
    pub circuit: CircuitToken,                        // for in-memory rate limiting (ADR-026)
    pub class: AnonymityClass,
}
```
Rules: the adapter MUST NOT expose any peer address, port, relay fingerprint, timing metadata or transport-level identifier other than `CircuitToken`; C-06 MUST refuse to label a stream ANONYMOUS unless `class == Anonymous` and the adapter's AdmissionRecord verifies; streams of class Confidential are served only by C-38 with "NOT ANONYMOUS" branding (ADR-002). The `tor-onion-v3-ctor` adapter reads `CircuitToken` from the PROXY-protocol header produced by `HiddenServiceExportCircuitID haproxy` (§7.1) and replaces the tor circuit ID with a random token via an in-memory map that is cleared when the circuit closes.

### 6.2 Client-side interface (C-03 Candor Source App)
`ClientTransport` provides `bootstrap(bridges: Option<BridgeConfig>)`, `connect(onion: OnionAddress, isolation: IsolationToken)` and `shutdown()`. Each app session uses a fresh isolation token (new circuits); no persistent guard state beyond what Arti requires is kept outside the app's data directory, which is wiped on uninstall and documented as a device residue (THR-048).

### 6.3 Admission criteria for any transport labelled ANONYMOUS
| ID | Criterion (all MUST hold) | Measure |
|---|---|---|
| AC-1 | Peer-reviewed anonymity analysis and a literature review showing no unmitigated PRACTICAL deanonymization of clients or hidden services | Written review in 00-RESEARCH format, reviewed by an external expert |
| AC-2 | Anonymity set comparable to Tor's, or a cover-traffic design whose anonymity does not depend on the number of real senders | Metrics (users/day) or design proof (CoverDrop-style, B-GL-20) |
| AC-3 | Hardened client for Windows, macOS, Linux and Android usable without JavaScript, or embeddable in C-03 | Demonstration |
| AC-4 | Public independent security audit of the shipped implementation within the last 36 months | Audit report |
| AC-5 | Maintenance: security releases within 30 days of disclosure over the last 24 months; ≥ 3 active maintainers | Release history |
| AC-6 | Service-side DoS defence comparable to Tor PoW | Spec + test |
| AC-7 | Service-location protection comparable to vanguards against Sybil guard discovery | Spec + analysis |
| AC-8 | Censorship-circumvention path for sources | PT support |
| AC-9 | Fail-closed deployment with no clearnet leakage | 30-ANONYMITY-TESTING.md pass |
| AC-10 | Approved ADR amending ADR-001; UI and docs updated | DECISIONS.md |

A transport failing any criterion MAY only be admitted as `Confidential` (never labelled anonymous). Adding a transport never reduces requirements on existing ones.

## 7. Intake Gateway tor configuration (C-05)

### 7.1 torrc (C-tor ≥ 0.4.8; instance `candor-intake`)
File `/etc/tor/instances/candor-intake/torrc`, owned root:root 0644, generated by `candorctl` from a template in the signed release; any local modification makes the self-test fail (hash compared with release manifest).
```
## Candor Intake Gateway — managed file, do not edit (NET requirements, 16-TOR-I2P.md §7)
## Process / host
RunAsDaemon 0
DataDirectory /var/lib/tor-instances/candor-intake
Sandbox 1
DisableDebuggerAttachment 1
AvoidDiskWrites 1
HardwareAccel 1

## Not a client proxy, relay, bridge or exit
SocksPort 0
TransPort 0
DNSPort 0
ORPort 0
DirPort 0
ExitRelay 0
ExitPolicy reject *:*
BridgeRelay 0
PublishServerDescriptor 0

## Control interface: Unix socket only, cookie auth, group = _candor-torctl (vanguards / health exporter only)
ControlPort 0
ControlSocket /run/tor-instances/candor-intake/control.sock
ControlSocketsGroupWritable 1
CookieAuthentication 1
CookieAuthFile /run/tor-instances/candor-intake/control.authcookie
CookieAuthFileGroupReadable 1

## Logging: minimal, no client/circuit data
Log warn syslog
SafeLogging 1
LogMessageDomains 0

## Guard / padding defaults kept explicit
UseEntryGuards 1
VanguardsLiteEnabled 1
ConnectionPadding 1
ReducedConnectionPadding 0
CircuitPadding 1
ReducedCircuitPadding 0

## Onion service: source intake
HiddenServiceDir /var/lib/tor-instances/candor-intake/hs-source/
HiddenServiceVersion 3
HiddenServicePort 80 unix:/run/candor/source-web/http.sock
HiddenServiceAllowUnknownPorts 0
HiddenServiceDirGroupReadable 0
HiddenServiceNumIntroductionPoints 5
HiddenServiceMaxStreams 32
HiddenServiceMaxStreamsCloseCircuit 1
HiddenServiceExportCircuitID haproxy
HiddenServiceSingleHopMode 0
HiddenServiceNonAnonymousMode 0

## DoS defences (ADR-026)
HiddenServicePoWDefensesEnabled 1
HiddenServicePoWQueueRate 250
HiddenServicePoWQueueBurst 2500
HiddenServiceEnableIntroDoSDefense 1
HiddenServiceEnableIntroDoSRatePerSec 25
HiddenServiceEnableIntroDoSBurstPerSec 200
```
Notes and constraints:
- `HiddenServiceVersion 3` is explicit even though v2 is removed (R4 §3.1).
- **Single-hop / non-anonymous service modes are forbidden**: `HiddenServiceSingleHopMode 0` and `HiddenServiceNonAnonymousMode 0` are asserted by the config linter; the release build refuses any template containing `1` for either.
- Port 80 inside the onion is HTTP over the onion circuit; the optional onion TLS mode (04 §5.1) adds `HiddenServicePort 443 unix:/run/candor/source-web/https.sock` and removes port 80 (with an HTTP→HTTPS redirect handled only on the onion).
- `HiddenServiceExportCircuitID haproxy` provides the per-circuit identifier for in-memory rate limiting only (§13). Knowledge (unverified): support for PROXY headers on Unix-socket targets MUST be confirmed in integration test; if unsupported, the target becomes `127.0.0.1:8080` inside a network namespace that contains only loopback (§14.2).
- PoW/intro-DoS numeric values are C-tor defaults at the time of writing (Knowledge (unverified)); `candorctl` exposes them as tunables with bounds and the load-test profile in 34.
- `Sandbox 1` compatibility with the vanguards add-on's `SETCONF` calls MUST be confirmed in integration testing (Knowledge (unverified)); if incompatible in HIGH profile, `Sandbox 1` takes precedence and the incompatibility is recorded as an Open Issue.
- `VanguardsLiteEnabled` is on by default in tor ≥ 0.4.7 (B-AN-11); the explicit setting documents intent.
- IPv6: `ClientUseIPv6` follows the host's egress policy (17); no other client options are set.

### 7.2 Full vanguards (HIGH-risk profiles; ADR-001, ADR-046(9))
- `vanguards` add-on (pinned version from the Platform Manifest, hash-verified, run as user `_candor-vanguards` in group `_candor-torctl`, systemd sandboxed, no network except the control socket) with its default layer-2/layer-3 guard counts and lifetimes, `rendguard`, `bandguards` and `pathverify` enabled, `close_circuits = True`, logging to syslog at NOTICE with no circuit identifiers retained beyond the journal's volatile storage.
- **Maintenance gate and fallback (ADR-046(9)):** the add-on is used only while it is maintained (a release or maintainer-confirmed compatibility with the pinned tor version within the last 12 months, and no open security advisory; checked at each Platform Manifest release, 33 §4.1). If it fails this gate, HIGH profiles run C-tor's built-in **vanguards-lite** and the fallback is recorded in the Platform Manifest and shown in the admin console and the Operator Statement's configuration digest; once Arti onion services are admitted (§9), HIGH profiles use **Arti's full vanguards mode**. The fallback weakens guard-discovery resistance for long-lived services (B-AN-13); this is a documented residual (§19 #4).
- Profiles: CE-SINGLE, CE-HARDENED, EE-ONPREM: vanguards-lite (ADR-001 baseline) with full vanguards RECOMMENDED; GOV-ONPREM, MANAGED high-risk tenants and any tenant flagged HIGH: full vanguards REQUIRED (subject to the fallback above).

### 7.3 Host and service hardening for tor
- Separate system user per tor instance; `HiddenServiceDir` mode 0700, key files 0600; LUKS volume (04 §7).
- systemd: `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`, `NoNewPrivileges=yes`, `MemoryDenyWriteExecute=yes`, `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK`, `LimitCORE=0`.
- journald on intake hosts: `Storage=volatile`, `MaxRetentionSec=24h`; forwarding to C-25 only of allow-listed tor warnings (ADR-016).
- **tor packages (ADR-040; RVW-A-12):** tor (and the vanguards add-on) come from the Tor Project repository, pinned by signing key **and exact version**, ingested into Candor's snapshot-based mirror and listed with hashes in the TUF-signed **Platform Manifest** of each Candor release (33 §4.1, 28 §5.4). Intake hosts install them only from the local verified repository built from that manifest; no direct APT source (Tor Project or Debian) is configured on H-INTAKE. The self-test verifies installed tor binaries against the manifest; trust-path components refuse to start below the signed security floor (33 §4.1).
- Patch SLA: tor security releases are included in an emergency Platform Manifest update (≥ 2 h cooling, ≥ 2 signers from ≥ 2 organisations, 33 §10) and deployed ≤ 72 h after upstream publication (INC-29 lesson / REQ-H-29).

### 7.4 Configuration lint (CI and on-host self-test)
`candorctl net lint` fails if: any listening TCP socket on a non-loopback address other than the C-08 relay endpoint (§14.2 I1) and the optional sshd (I2); a SocksPort on the source onion instance; an onion service on the `candor-update` instance; SocksPort/TransPort/DNSPort non-zero on the intake instance; ControlPort TCP enabled; SingleHop/NonAnonymous mode = 1; `SafeLogging` ≠ 1; log level below `warn`; `HiddenServiceVersion` ≠ 3; PoW disabled; more than one `HiddenServicePort`; torrc hash ≠ release manifest.

## 8. Staff access onion (optional)

When staff reach Z-CORE over Tor (remote staff; AIRGAP-adjacent deployments), a separate tor instance runs on a **Z-CORE edge host** — never on the Intake Gateway (ADR-009) — with a separate onion using restricted discovery (client authorization):
```
HiddenServiceDir /var/lib/tor-instances/candor-staff/hs-staff/
HiddenServiceVersion 3
HiddenServicePort 443 unix:/run/candor/desk-api/https.sock
HiddenServiceSingleHopMode 0
HiddenServiceNonAnonymousMode 0
HiddenServicePoWDefensesEnabled 1
# authorized_clients/<device>.auth contains: descriptor:x25519:<base32 public key>
```
Each Desk device has its own x25519 client-auth key (K17, 04 §19); revocation = remove the `.auth` file and reload. Client-auth keys MUST NOT be copied to monitor or backup hosts (Secret Placement Manifest; SecureDrop GHSA-rqwh copied client-auth keys to the Monitor server, B-SD-22). Staff authentication and TLS pinning still apply (04 §5.2; 15).

## 9. Arti migration plan

### 9.1 Current use
- **Client side (C-03):** Arti embedded now (ADR-004), with vanguards-lite (B-AN-13), restricted discovery not needed, client PoW enabled via the `hs-pow` feature (B-AN-29), bridges/PT support (§12).
- **Service side (C-05):** C-tor until criteria below hold (Arti onion services not yet recommended for production, B-AN-47).

### 9.2 Migration criteria (all required)
| ID | Criterion |
|---|---|
| AM-1 | Arti release notes explicitly declare onion *services* production-ready (B-AN-47). |
| AM-2 | Service-side PoW (Equi-X, compatible with C-tor clients) enabled in the release build with tunables equivalent to §7.1. |
| AM-3 | Full vanguards mode for services (B-AN-13) and restricted discovery (B-AN-44) stable. |
| AM-4 | Key migration: the existing C-tor onion key imports into Arti preserving the address, with verified tooling (Knowledge (unverified) tool name). |
| AM-5 | Logging with no client-identifying data; equivalent of `SafeLogging`. |
| AM-6 | Per-circuit token for in-memory rate limiting available through the embedding API. |
| AM-7 | Published independent security audit covering Arti's onion-service code. |
| AM-8 | 90 days on staging plus a 30-day canary on ≥ 3 production deployments with 30-ANONYMITY-TESTING.md passing and reachability ≥ C-tor baseline. |

### 9.3 Phases
P0 (now): Arti client in C-03 only. P1: staging dual-run (Arti serves a separate test onion). P2: canary (AM-8). P3: default for new installs via Transport Adapter `tor-onion-v3-arti` (new AdmissionRecord). P4: migrate existing installs with key import; C-tor retained, disabled, as rollback for 6 months. Rollback criterion: any AT failure or unresolved security advisory.

### 9.4 Post-quantum transport tracking (ADR-046(8); RVW-A-11)
Tor circuit and onion-service handshakes are classical today (Knowledge (unverified) as of 2026-09), so recorded Tier W sessions — including passphrases at login — are exposed to harvest-now-decrypt-later (04 §5.1). Candor therefore: (1) enables onion TLS with the hybrid `X25519MLKEM768` group by default in HIGH/GOV profiles when a `.onion` certificate is obtainable (04 CRYPTO-029; §7.1 note); (2) recommends Tier V to HIGH-risk sources (05, 11); (3) tracks Tor's PQ circuit/onion handshake work at every Platform Manifest release and adopts it — in C-tor or Arti, client (C-03) and service (C-05) — in the first Candor minor release after it is available in a stable Tor release that meets §6.3, recorded in the Platform Manifest; (4) records the residual in §19.

## 10. Onion service key custody, rotation and compromise (THR-044)

| Aspect | Specification |
|---|---|
| Generation | By tor on C-05 at install (host RNG, 04 §23.4), or on the ceremony machine and transferred encrypted when the organisation requires offline generation |
| Storage | `hs_ed25519_secret_key` in `HiddenServiceDir` (0700/0600) on LUKS; present only on C-05 per Secret Placement Manifest (ADR-028). Single-host profiles: exactly one host copy + optional offline encrypted escrow. EE-HA/GOV-ONPREM: at most **2** intake gateway hosts, active/passive, both listed in the manifest and monitored identically (ADR-032); active/active OnionBalance-style publication is deferred |
| Offline identity key | Not supported for C-tor onion services (Knowledge (unverified)); track Arti (Open Issue OI-3) |
| Backup | Optional **Onion Key Escrow**: key file sealed (04 STREAM + HPKE) to the Backup Master public key (K25) and stored offline, separate from routine backups. HIGH profile MAY choose "no escrow" (rebuild = new address) |
| Standby address | A second onion key generated at install, sealed and stored offline (never on C-05); its address MAY be pre-published as "standby" in the signed address statement |
| Rotation | No scheduled rotation (address stability limits phishing); rotate only on compromise, host rebuild without escrow, or tenant request |
| Per tenant | One dedicated intake onion per tenant/customer (ADR-021); never shared across customers |

### 10.1 Compromise indicators
Intake host compromise (31); loss of escrow media; descriptor for our address observed with introduction points not published by our tor (C-25 compares the fetched descriptor's intro points and revision counter against the service's own published descriptor via the control socket); K25 compromise with escrow present.

### 10.2 Response (target: standby live ≤ 4 h after decision)
1. Stop the compromised tor instance; preserve evidence per 31.
2. Activate the standby key on a clean intake host (or generate a new key).
3. K01 signs a new ONION_ADDRESS statement: new active address; old address listed as **revoked** with day.
4. Publish on all channels (§11.2) and in the key directory; Source App refuses revoked addresses (fetches statement via the new address only after verifying K01).
5. Clearnet info site shows a prominent notice; Onion-Location updated.
6. The revoked address may continue to be operated by the attacker (an onion address cannot be revoked in the Tor network): sources using bookmarks are warned via every published channel; Tier V clients detect revocation; Tier W sources cannot be protected technically (residual).
7. Rotate any credential co-located on the host (04 §19: K31, K19 leaves, K28).

## 11. Onion address publication and verification

### 11.1 Signed onion address statement
JSON canonicalized with RFC 8785 JCS (Knowledge (unverified) RFC number), served at `https://<info-site>/.well-known/candor/onion-address.json` with detached `onion-address.json.sig` (Ed25519 + ML-DSA-65 signatures by K01, 04 §19), and also as the ONION_ADDRESS key-directory entry:
```json
{
  "format": "candor-onion-address/v1",
  "tenant_label": "Example Org Integrity Line",
  "org_root_fingerprint": "<base32 SHA-256 of K01 Ed25519 pk ‖ ML-DSA-65 pk>",
  "active": ["<56 chars>.onion"],
  "standby": ["<56 chars>.onion"],
  "revoked": [{"address": "<56 chars>.onion", "since_day": "2026-09-30"}],
  "valid_from_day": "2026-09-30",
  "expires_day": "2027-09-30",
  "verification_words": "<6 EFF words derived from SHA-256(active[0] ‖ org_root_fingerprint)>",
  "witness_cosignatures": [{"witness": "<name from ORG_ROOT>", "sig": "<base64 Ed25519 (K39) over the canonical statement>"}]
}
```
Verification words give humans a short check across channels. The statement expires after ≤ 12 months and is re-signed. **External witness cosignature (RVW-A-08; ADR-036(5)):** in EE, GOV and MANAGED the statement SHALL carry a cosignature by ≥ 1 witness outside the operating organisation (CE: SHOULD), so that substituting the statement on C-37 alone fails verification in the Source App (04 VR-1).

### 11.2 Publication channels (≥ 3 independent)
0. **Offline first (RVW-B-17):** organisations SHALL be advised (05, 13 onboarding) to publish the onion address and verification words primarily offline (posters, printed cards, QR codes, letters from the ombudsman) and, on intranets, only as **non-hyperlinked text** with the line "Don't open this at work. Copy it into Tor Browser at home." — because the employer's proxy and EDR log visits to a hyperlinked clearnet page before any guidance is read.
1. Clearnet Information Site (C-37): address, verification words, QR code, statement + signature, `Onion-Location` header on every page and `<meta http-equiv="onion-location">` (R4 §3.1; UNVERIFIED Tor Browser version detail).
2. Printed/offline materials (posters, employee handbook, letters from the ombudsman), with address and verification words.
3. A second, independently hosted domain or the organisation's annual report / regulator filing.
4. Optional: listing in a third-party directory (e.g., SecureDrop-style directories where appropriate), which the organisation does not control.
5. Candor Source App deep link `candor-source://v1/<onion>#<org_root_fingerprint>` (QR) — the app pins K01 from the fingerprint and fetches the statement over the onion.

### 11.3 Clearnet info site rules (C-37)
Static; no submission form for anonymous mode (ADR-002); no third-party resources or CDN terminating TLS (INC-46, INC-54); HSTS preload; Onion-Location on all pages; optional in-memory check of the client IP against the public Tor exit list refreshed hourly, used only to choose a banner ("You are not using Tor — …"), never logged or stored (ADR-003); no analytics; web server access logs disabled (ADR-016). Additionally (round 2):
- **First viewport warning (RVW-B-17):** the first screen of every page shows, above all other content, the 05 guidance "If you are on a work device or a work network, stop here" (text owned by 05).
- **No app hosting (ADR-041; RVW-A-14):** C-37 SHALL NOT host the Candor Source App or any installer and SHALL NOT log or count downloads; it links to the Candor project's distribution (project onion service and independent mirrors, 33 §15.3) and states that downloading over Tor is safest. Branding shown in the app comes from the signed address statement at run time, never from a per-tenant build.
- **Hosting independence (RVW-C-20):** for tenants of risk class D1/D2 (21 §6.3) and GOV-IG/IA, C-37 SHALL be hosted outside the organisation's own web stack (no corporate CMS, WAF, SSO cookies or intranet proxy in the path), as a static site with access logging disabled at the host, and the operator attests this in the quarterly C-37 review (32); for other tenants this is RECOMMENDED. A neutral multi-organisation directory run by the project MAY host C-37 pages to enlarge the anonymity set of visitors (RVW-B-17 option).

## 12. Bridges and pluggable transports — guidance for sources

| Situation | Guidance (text owned by 05) | Rationale |
|---|---|---|
| On an employer network or device | **Do not submit.** Use a personal device on a network not associated with you. Bridges do not make a monitored device safe. | INC-31; R4 §2.2 |
| Home/public network, Tor not blocked | Tor Browser, security level Safest, no bridge needed | R4 §3.3 |
| Network where Tor use is conspicuous or blocked (ISP, country) | Tor Browser built-in bridges: **WebTunnel** (HTTPS-like) or **obfs4**; **Snowflake** where obfs4/WebTunnel are blocked; request unlisted bridges via Tor Browser's built-in request (Knowledge (unverified) "Moat") | B-AN-30, B-AN-31 |
| iOS only | Onion Browser is weaker (WebKit, fingerprinting); prefer another device | R4 §3.3 |
| High risk | Tails (amnesic) with bridges as needed | B-SD-04 |

Candor Source App: supports configuring obfs4, Snowflake and WebTunnel through Arti's PT integration (external PT binaries bundled and hash-pinned; Knowledge (unverified) Arti PT mechanism); default "automatic" tries direct then offers bridges; never auto-falls back to non-Tor connectivity.

## 13. DoS defences (ADR-026)

| Layer | Mechanism | Parameters | Privacy constraint |
|---|---|---|---|
| L1 tor | Onion PoW (Equi-X), dormant until overload | §7.1 tunables | None stored |
| L2 tor | Intro-point DoS defence | 25/s rate, 200 burst per intro point | — |
| L3 tor | `HiddenServiceMaxStreams 32` + close circuit | — | — |
| L4 app | Per-CircuitToken token bucket in C-06 (e.g., 20 requests/min, burst 40; uploads 2 concurrent) | In-memory map, entries evicted on circuit close or 10 min idle | Tokens never persisted/logged (ADR-026) |
| L5 app | Global concurrency limits: C-07 Argon2id semaphore of 4 (04 CRYPTO-044, ADR-046(7)), upload bandwidth cap, FIFO queue; the busy/wait page only on queue overflow sized ≥ 10× design peak | 34 | Queue length, position and saturation are not exposed in any response or dashboard beyond a coarse daily health band (ADR-038(5); RVW-A-27) |
| L6 app | Optional app-level Equi-X PoW for Tier V clients to enter the priority tier when queue > threshold | Difficulty adaptive | — |
| L7 abuse | Upload quotas per source account (Tier W session / authenticated Tier V operations) and per CircuitToken for unauthenticated Tier V envelope uploads (04 CRYPTO-065); submission size caps; spam triage queue | 10, 14 | Quota counters keyed by `lookup_tag` hold the current UTC day only and are reset daily; no quota history is retained (ADR-038(3); RVW-A-26, RVW-B-11) |
| L8 availability | Standby onion (§10); in EE-HA/GOV-ONPREM a second intake host holding the same onion key, **passive** (tor instance stopped) until failover, so only one host publishes descriptors at a time (ADR-032) | 21 | — |

No third-party CAPTCHA or CDN (ADR-026; INC-54).

## 14. No-clearnet-fallback enforcement

### 14.1 Principles
- The source web service exists only behind tor; there is no clearnet listener, reverse proxy, CDN or alternative anonymous path (ADR-002; INC-33, INC-34).
- If tor or the onion service is down, sources cannot reach Candor anonymously; the Clearnet Information Site shows an outage notice and never offers a clearnet "anonymous" form.

### 14.2 Host enforcement (Intake Gateway)
- C-06 and C-07 run with `PrivateNetwork=yes` (only loopback in their namespace) and communicate via Unix sockets; they have no route to any network.
- **H-INTAKE flow matrix (RVW-A-23; final round: aligned with `17-INFRASTRUCTURE.md` §4.3.1, which is normative for initiated flows E1–E5; `06-SYSTEM-ARCHITECTURE.md` §8.5 references the same table).** Interface names (`ext0`, `relay0`, `mgmt0`) and ports are those of 06 and 17.

| # | Direction | Process / UID | Interface | Peer | Port | Purpose |
|---|---|---|---|---|---|---|
| E1 | out | `_tor-candor-intake` (source onion instance `candor-intake`, §7.1) | ext0 | Tor relays | any TCP | onion service circuits |
| E2 | out | `_tor-candor-update` (client-only instance `candor-update`, §14.3) | ext0 | Tor relays | any TCP | TUF updates from the project onion mirror (ADR-046(3)); Roughtime over Tor; nothing else |
| E3 | out | `candor-health` (C-25 agent) | mgmt0 | H-MON collector only | 8514 (mTLS) | self-test and daily health-band **push** (ARCH-014 push-only; the monitor never connects to the intake) |
| E4 | out | `_chrony` | mgmt0 | H-MON internal NTS source only | UDP 123, TCP 4460 | time discipline from the internal source (17 INFRA-007); never Z-CORE |
| E5 | out (initramfs only) | root (clevis) | mgmt0 | H-MON / off-site Tang | 7500 | boot-time Tang unlock; rule absent after switch-root |
| I1 | in | C-08 relay endpoint `candor-istore` | relay0 | C-09 relay host only | 7443 (mTLS) | core-initiated pull and reply push (ADR-009); the intake never initiates this flow |
| I2 | in (optional) | sshd | mgmt0 | admin jump host | 22 | administration (or admin over the staff onion, §8) |
| — | any other | — | — | — | — | dropped and counted |

H-MON (E3–E5 destination) SHALL satisfy 17 §4.3.2: no IP forwarding, no default route, no mail daemon, no clearnet egress except via its own tor client (RVW-A-23). No clearnet DNS or NTP flow exists; E4 reaches only the internal H-MON source. The v1.0 rows "F3 8443/int0" and "F4 exporter pull on 9443" are withdrawn (final round, DISP-G6 item 1).
- nftables (normative ruleset; interface names per 06/17; 17 §4.3 holds the full host ruleset including initramfs rules):
```
table inet candor_intake {
  chain input {
    type filter hook input priority 0; policy drop;
    iif "lo" accept
    ct state established,related accept
    iifname "relay0" ip saddr @core_relay tcp dport 7443 ct state new accept   # I1: C-09 core-initiated pull/push (ADR-009)
    iifname "mgmt0"  ip saddr @admin_jump tcp dport 22   ct state new accept   # I2: optional; or admin over staff onion
  }
  chain output {
    type filter hook output priority 0; policy drop;
    oif "lo" accept
    ct state established,related accept                                         # replies to I1/I2
    oifname "ext0"  meta skuid "_tor-candor-intake" meta l4proto tcp ct state new accept   # E1
    oifname "ext0"  meta skuid "_tor-candor-update" meta l4proto tcp ct state new accept   # E2
    oifname "mgmt0" meta skuid "candor-health" ip daddr @mon_hosts tcp dport 8514 accept   # E3 agent push
    oifname "mgmt0" meta skuid "_chrony" ip daddr @mon_hosts udp dport 123 accept          # E4 NTP (internal)
    oifname "mgmt0" meta skuid "_chrony" ip daddr @mon_hosts tcp dport 4460 accept         # E4 NTS-KE
    meta skuid { "_tor-candor-intake", "_tor-candor-update" } udp dport 53 drop            # tor needs no DNS here
    log prefix "candor-egress-deny " level warn limit rate 1/minute drop        # counters only; no payload
  }
  chain forward { type filter hook forward priority 0; policy drop; }
}
```
- No DNS resolver configured for application users; no clearnet NTP; host time per §14.3. The v1.0 chrony SOCK refclock fed by C-09 timestamps is **withdrawn** (ADR-036(6)); no Z-CORE-supplied timestamp sets or validates the intake clock.
- Cloud metadata endpoints (169.254.169.254, fd00:ec2::254) and IPv6 router advertisements blocked/disabled (PRIVATE-CLOUD profile; THR-030).
- **Updates (ADR-046(3); RVW-C-08):** intake hosts fetch TUF metadata and artifacts only through the `candor-update` instance (UID `_tor-candor-update`, E2) from the Candor project's onion mirror, verifying TUF and log proofs themselves (33 §14); the v1.0 option of bundles pushed by C-09 is **withdrawn** (ADR-046(3)), so Z-INTAKE has exactly one update path; never via direct clearnet, never relay-pushed.
- Fail-closed checks: `candorctl net selftest` asserts no non-loopback TCP listeners except the relay endpoint (I1, 7443 on relay0) and the optional sshd (I2), that an Internet egress attempt by any UID other than the two tor UIDs fails, that only `candor-health`/`_chrony` reach H-MON on the E3/E4 ports, that no packet from H-INTAKE can reach a host with a default route to the Internet except via tor (probe to a canary host behind relay0/mgmt0), and that the onion is the only path to C-06; runs at boot and every 15 min; failure stops C-06.

### 14.3 Independent time source (ADR-036(6); RVW-A-04; values aligned with 17 §4.5)
- **Client instance.** A second tor instance `candor-update` (user `_tor-candor-update`; `SocksPort unix:/run/tor-instances/candor-update/socks.sock`, group `_candor-net`; no onion services; `ControlSocket` readable only by `_candor-time`; `SafeLogging 1`; started by `candor-update.timer` and `candor-roughtime.timer`, never sharing a data directory with `candor-intake`) serves the updater and the time checker. It holds no onion service key.
- **Clock discipline.** chrony disciplines the clock only from the internal H-MON NTS source (E4; 17 INFRA-007). There is no SOCK refclock and no Z-CORE time input. The checks below do not steer the clock; they decide whether C-07 may seal.
- **Floor from the Tor consensus.** `_candor-time` reads the `valid-after` of the latest consensus verified by tor (directory-authority signatures checked by tor; Knowledge (unverified): `GETINFO consensus/valid-after`, else the cached consensus file). Rule: `valid_after − 5 min ≤ now ≤ valid_after + 27 h` (3 h validity + 24 h "reasonably live" tolerance; Knowledge (unverified) exact tor tolerance).
- **Roughtime over Tor.** Every 6 h ± 30 min the time checker queries ≥ 2 Roughtime servers from ≥ 2 independent operators through the `candor-update` SOCKS socket (Roughtime over TCP; Knowledge (unverified) server support, 04 OI-16), verifies signatures against pinned server keys shipped in the Platform Manifest (updated through TUF), and requires two agreeing responses.
- **Fail closed.** If the consensus rule fails, the host clock is > 30 min from the agreeing Roughtime responses, or the persisted monotonic high-water mark of accepted time steps backwards by > 5 min, the time checker signals C-07, which fails closed for sealing (04 §12.1 step 3, §12.6) until resolved; the C-25 agent pushes an alert (E3). Z-CORE-supplied timestamps (C-09 pulls, checkpoint `issued`) are never used to set or validate the clock.
- **Feasibility.** If no TCP-capable Roughtime server is reachable over Tor, the intake operates on the consensus floor plus H-MON NTS and reports "Roughtime unavailable" in the daily health band (OI-7).
- **Residual:** the consensus floor bounds rollback of time to ≈ 1 day; an adversary controlling a directory-authority majority, or all configured Roughtime operators and H-MON, can skew time within those bounds (04 CA-10).

## 15. Monitoring onion reachability without observing source traffic

- **Active probing from C-25 (Z-SOC host), not from the intake host:** a separate tor client on the monitor host fetches `/.well-known/candor/health` (fixed-size static response served by C-06 without touching C-07/C-08) at exponentially distributed intervals (mean 10 min); records success/failure, descriptor fetch time and total latency; retains results ≤ 30 days.
- **Descriptor integrity check:** C-25 fetches the service descriptor via its own tor client and compares intro points / revision counter with values exported by the intake's health exporter (§10.1).
- **Intake health exporter** (runs as `_candor-torctl`, reads the control socket and hands the values to the local C-25 agent `candor-health`, which **pushes** them to the collector over mTLS on flow E3; ARCH-014 push-only, the collector never connects to the intake): tor bootstrap state, whether the current descriptor was published (yes/no), intro-point count, PoW active flag (public in the descriptor anyway). Load-related values (descriptor uploads, rendezvous circuits, suggested PoW effort, Argon2 queue) are exported only as a **coarse daily health band** (normal / elevated / overloaded, computed over the UTC day and emitted after the day ends; ADR-038(5), ADR-046(5); RVW-A-27). No per-circuit data, no event timestamps finer than 1 day for load values, no stream counts per circuit.
- **Never:** packet capture, NetFlow/sFlow, eBPF per-connection tracing, or tor `Log info/debug` on intake hosts in production; debugging requires a documented change with dual approval and a volatile, time-boxed (≤ 1 h) window, with sources warned via the info site only if the intake stays open (20, 32).
- Alerts are content-free (ADR-017).

### 15.1 External Watchers (ADR-035(1); RVW-A-01, RVW-A-13)
- **Who:** ≥ 2 independent watcher organisations per tenant (EE/GOV/MANAGED: ≥ 1 outside the operator's jurisdiction; selection per 36), listed with their K39 keys in ORG_ROOT (04 §14.2). Watchers are never operated by the tenant's operator or its hosting provider.
- **What they fetch, over Tor:** the landing page and all static source-UI routes, response headers (CSP, cookies, cache headers), `/.well-known/candor/manifest` (04 §9.14), the key-directory snapshot and checkpoint, and — for HIGH/GOV Confidential-VM profiles — the latest SEALER_ATTESTATION.
- **How, to resist selective serving:** each fetch uses a fresh Tor Browser (Safest) profile or an HTTP client that reproduces Tor Browser's request headers and ordering exactly (C-06 cannot distinguish watchers from sources by request shape), a new circuit (new isolation token) per fetch, at exponentially distributed intervals with mean 6 h, from ≥ 2 vantage points per watcher.
- **Comparison:** static assets and CSP strings are compared byte-for-byte with the release digests in the transparency log (33 §7); the running manifest's release and Platform Manifest hashes must be current, and the manifest must be ≤ 48 h old; directory checkpoints must be consistent with those the watcher saw before and with witnesses. Mismatches and staleness are published by the watcher (signed with K39) and sent to the tenant's OVERSIGHT; C-06 does not learn which fetches were watchers.
- **Honest limit:** watchers see only what an anonymous first-time visitor sees. A modification that activates only for a specific logged-in session, a specific form answer or after a delay is not observable by watchers (RVW-A-01); Tier V remains the only content-protecting path.

## 16. Attack classes, status and Candor mitigations

| Attack class | Status | Candor mitigation | Residual |
|---|---|---|---|
| End-to-end timing correlation (B-AN-01..05) | PRACTICAL for adversaries seeing both ends | Onion-only (no exit); full/lite vanguards; ADR-010 day-granularity timestamps; fixed import schedule and constant-schedule staff digests (ADR-038(1)/(2)); optional delayed delivery (ADR-038(4)); guidance against employer networks | Not defeated (NA-3) |
| State timing analysis of long-lived endpoints (INC-35) | PRACTICAL (in the wild) | Sources need no persistent client or onion service; current Tor Browser; service runs current tor + vanguards | Long-running service remains a guard-discovery target |
| Guard discovery against the service (B-AN-09..13) | PRACTICAL | Vanguards (lite/full), patch SLA, dedicated host, no co-hosting | Seizure after location found |
| Website fingerprinting of the portal (B-AN-14..19) | LAB → PRACTICAL for one monitored site | Minimal uniform pages, fixed response size classes (11), no third-party resources, bundled assets | Employer may get a lead, not proof |
| Onion circuit fingerprinting (B-AN-20) | LAB → PRACTICAL for malicious guard | Tor circuit padding (defaults on); bridges advice | Reveals "visits an onion" |
| Predecessor / intersection over repeat visits (B-AN-21, B-AN-22) | PRACTICAL over time | Tier V: fetch-all reply retrieval and unauthenticated follow-ups, so the server cannot tell which mailbox is active (ADR-039); Tier W: server-side lookup reveals account activity to a compromised intake (residual); follow-up days stored only at slot granularity (ADR-038(3)); guidance to vary networks and batch visits (05) | Accumulates with each visit at the network edge |
| Global passive adversary | THEORETICAL for most / PRACTICAL for Five-Eyes class | Out of scope; future cover-traffic transport via §6 | Not addressed |
| Upload volume/time at the service uplink (RVW-A-22) | PRACTICAL for a compelled hosting provider plus a source-side observer | Tier V pads before upload (ADR-011); Tier W parts padded before staging (ADR-038(5)) protect storage only; honesty text and guidance (05) that large website uploads are recognisable by size; optional HIGH-profile decoy uploads from an independent network (evaluation, OI-5) | Tier W upload spikes remain a correlation feature |
| Harvest-now-decrypt-later of recorded circuits (RVW-A-11) | THEORETICAL today; recording is PRACTICAL | Onion TLS with hybrid PQ group default in HIGH/GOV (04 CRYPTO-029); Tier V recommended for HIGH risk; passphrase rotation (04 §11.7); adoption of PQ onion handshakes (§9.4) | Tier W sessions recorded before PQ transport exists (ADR-046(8)) |
| Clock/directory freeze via the intake's time source (RVW-A-04) | PRACTICAL for a compromised Z-CORE under the v1.0 design | Independent time (§14.3), directory high-water mark (04 §12.1) | Bounded to ≈ 1 day by the consensus floor |
| Active tagging (RELAY_EARLY, INC-29) | PRACTICAL (observed) | Current tor; patch SLA 72 h | New variants |
| Sybil relays (INC-30) | PRACTICAL (observed) | Onion-only (exit Sybils irrelevant), vanguards | Network-level, outside our control |
| Congestion/bandwidth attacks | LAB (deanon) / PRACTICAL (DoS) | Congestion control (tor), PoW, vanguards bandguards (HIGH) | — |
| Onion DoS | PRACTICAL | §13 | Degraded availability under large attacks |
| Censorship / Tor blocking | PRACTICAL | Bridges/PT guidance (§12), Source App PT support | Sophisticated censors |
| Server misconfiguration leaks (INC-33, INC-34) | PRACTICAL | §14 enforcement, lint, no status pages, no co-hosting, OnionScan-class tests (30) | Human error on custom deployments |
| Seized server + NIT (INC-27, INC-28) | PRACTICAL (in the wild) | No-JS source UI; Tier V code integrity (04 §24); CLIENT_RELEASE monitoring | Tier W sources after seizure |
| Tor Browser/OS leaks (INC-36) | PRACTICAL (historic) | No external links, schemes, file previews in source UI | Browser bugs |
| Onion key theft / impersonation (THR-044) | PRACTICAL after host compromise | §10 custody and response; signed address statements; Source App pinning | Tier W sources on revoked address |
| I2P-specific netDb attacks | N/A (not shipped) | — | — |

## 17. Source App transport rules (C-03)
- All network traffic of C-03 goes through embedded Arti; the app has no code path for direct connections (build-time check: no socket APIs outside the Arti crate; runtime: OS-level VPN/proxy settings ignored).
- Update checks (33) also go over Arti to the Candor project's onion mirror, identical requests for every user; no organisation-specific endpoint is contacted for updates.
- **Acquisition (ADR-041; RVW-A-14):** the primary download is the project's onion service and independent onion/clearnet mirrors (reproducible, signed, identical for all tenants, 33 §15.3); guidance (05) recommends downloading over Tor Browser. App-store installs are optional and disclosed as leaving account-linked records.
- **Witness checkpoint fetch (ADR-036(5); 04 VR-3):** once per session the app fetches the tenant's latest cosigned checkpoint from ≥ 1 external witness onion endpoint (from ORG_ROOT and the witness key set embedded in the release), on a separate isolation token from the tenant connection, in a fixed request shape identical for all tenants of that witness.
- **Replies (ADR-039):** reply retrieval downloads all dead-drop pages in a fixed order in every session that opens the inbox, regardless of whether the source expects replies, so traffic volume depends on the tenant's reply volume, not on the source.
- Session isolation: one isolation token per app session (plus the witness token); circuits torn down on exit; no background networking when the app is not in the foreground (mobile).

## 18. Requirements

| ID | Requirement | Evidence | Threats | Component | Verification |
|---|---|---|---|---|---|
| NET-001 | ANONYMOUS mode SHALL be reachable only through a Tor v3 onion service on the Intake Gateway; no other transport SHALL be labelled anonymous in v1. | ADR-001; B-AN-57; B-AN-54 | THR-001; THR-040 | C-05, C-06 | INSP: route/transport registry; TST: C-06 rejects non-Anonymous streams for anonymous routes |
| NET-002 | The source web service SHALL have no clearnet listener, reverse proxy or CDN; it SHALL listen only on Unix sockets (or loopback in an isolated namespace) reachable from tor. | ADR-002; INC-33; INC-34 | THR-001; THR-035 | C-06, C-05 | TST: external port scan of all host IPs; `ss -ltnp` check in `net selftest` |
| NET-003 | The Intake Gateway SHALL run C-tor ≥ 0.4.8 (or an admitted Arti per §9) installed only from the release's TUF-signed Platform Manifest (Tor Project repository pinned by key and exact version), at or above the signed security floor, and tor security releases SHALL be deployed within 72 hours via the emergency release path. | INC-29; INC-35; B-AN-26; ADR-040; RVW-A-12 | THR-005; THR-003; THR-024 | C-05, C-25 | TST: C-25 version-floor and manifest-hash check; no APT source on H-INTAKE; DEMO: advisory drill |
| NET-004 | The intake torrc SHALL be exactly the release template of §7.1 (hash-verified) with only documented tunables changed within bounds. | INC-34 | THR-035 | C-05 | TST: `candorctl net lint`; INSP |
| NET-005 | `HiddenServiceSingleHopMode` and `HiddenServiceNonAnonymousMode` SHALL be 0 on every onion service and the build SHALL refuse templates setting either to 1. | B-AN-12 | THR-001; THR-005 | C-05, C-31 | TST: config lint in CI and on host |
| NET-006 | Onion PoW defence (`HiddenServicePoWDefensesEnabled 1`) and intro-point DoS defence SHALL be enabled on every onion service. | ADR-026; B-AN-26; B-AN-27; B-AN-28 | THR-032 | C-05 | TST: lint; load test (34) shows PoW activation |
| NET-007 | Vanguards-lite SHALL be enabled on all profiles; full vanguards (add-on while it passes the §7.2 maintenance gate, or Arti full mode once admitted) SHALL be enabled for GOV-ONPREM, MANAGED high-risk and HIGH-flagged tenants; when the gate fails, the vanguards-lite fallback SHALL be recorded in the Platform Manifest and shown to admins and in the Operator Statement's configuration digest. | ADR-001; ADR-046(9); B-AN-11; B-AN-12; B-AN-13 | THR-005 | C-05 | TST: control-socket query in self-test; INSP: profile config and manifest flag |
| NET-008 | tor on intake hosts SHALL log at level `warn` or higher with `SafeLogging 1` to volatile journald storage retained ≤ 24 h; web server access logs SHALL be disabled. | ADR-016; B-SD-21; INC-60 | THR-016; THR-011 | C-05, C-06 | TST: log canary test; INSP: journald config |
| NET-009 | The tor ControlPort SHALL be disabled; control access SHALL be via a Unix socket with cookie authentication readable only by the vanguards and health-exporter users. | INC-34 | THR-035; THR-014 | C-05 | TST: lint; permission check |
| NET-010 | tor SHALL run with `Sandbox 1`, `DisableDebuggerAttachment 1`, no core dumps and the systemd hardening of §7.3. | INC-58 | THR-014 | C-05 | TST: `systemd-analyze security` threshold; lint |
| NET-011 | The intake tor instance SHALL NOT act as a client proxy, relay, bridge or exit (`SocksPort 0`, `ORPort 0`, `ExitRelay 0`, `BridgeRelay 0`, `PublishServerDescriptor 0`). | B-AN-11; B-AN-12 | THR-005; THR-035 | C-05 | TST: lint |
| NET-012 | The Transport Adapter SHALL expose to applications only a byte stream, an in-memory random CircuitToken and an AnonymityClass, never addresses, relay identities or timing metadata. | ADR-001; ADR-026 | THR-001; THR-016 | C-06 | TST: API test; INSP: code review |
| NET-013 | CircuitTokens and rate-limit state SHALL exist only in memory and SHALL be evicted on circuit close or after 10 minutes idle. | ADR-026 | THR-001; THR-047 | C-06 | TST: memory inspection; persistence scan |
| NET-014 | A transport SHALL be labelled ANONYMOUS only if its signed AdmissionRecord shows all criteria AC-1..AC-10 met and an ADR amending ADR-001 exists. | ADR-001; B-AN-57 | THR-040 | C-06, C-14 | INSP: ADR + record review |
| NET-015 | Staff onion services, if used, SHALL run on a Z-CORE edge host, use restricted discovery with per-device client-auth keys, and SHALL NOT run on the Intake Gateway. | ADR-009; B-AN-44; B-SD-22 | THR-022; THR-014 | C-10, C-15 | TST: placement self-test; lint |
| NET-016 | Client-auth keys and onion keys SHALL be present only on hosts listed in the Secret Placement Manifest; deployment SHALL fail otherwise. | ADR-028; B-SD-22 | THR-044 | C-05, C-25 | TST: planted-key self-test |
| NET-017 | The Candor Source App SHALL route all traffic through embedded Arti with client PoW enabled and SHALL contain no direct-connection code path. | ADR-004; B-AN-29 | THR-001; THR-002 | C-03 | TST: build-time socket API ban; network capture shows only Tor traffic |
| NET-018 | Service-side migration to Arti SHALL occur only when criteria AM-1..AM-8 are met, via a new AdmissionRecord, with C-tor rollback retained for 6 months. | B-AN-47; B-AN-13; B-AN-44 | THR-005; THR-032 | C-05 | INSP: migration checklist; TST: AT suite (30) on canary |
| NET-019 | Onion service keys SHALL be generated per tenant on the intake host or ceremony machine, stored only in the 0700 `HiddenServiceDir` on an encrypted volume, and optionally escrowed offline sealed to K25. | ADR-021; ADR-028; B-GL-11 | THR-044; THR-031 | C-05, C-27 | INSP; TST: permission and placement checks |
| NET-020 | A standby onion key SHALL be generated at install and stored offline, not on C-05. | B-AN-26 | THR-044; THR-032 | C-05, C-28 | INSP: standby inventory |
| NET-021 | On onion key compromise, the standby address SHALL be activated and a K01-signed statement revoking the old address published on all channels within 4 hours of the decision. | B-AN-26; INC-28 | THR-044 | C-05, C-37, C-14 | DEMO: annual drill (31) |
| NET-022 | C-25 SHALL compare fetched onion descriptors with the service's own published descriptor and alert on unexpected introduction points or revision counters. | ADR-028; Knowledge (unverified) | THR-044 | C-25 | TST: simulated duplicate-descriptor test |
| NET-023 | The organisation's onion address SHALL be published as a K01-signed statement (§11.1) on the info site, in the key directory and on ≥ 2 further independent channels, with verification words. | INC-52 | THR-044; THR-007 | C-37, C-14 | INSP; TST: signature verification of published statement |
| NET-024 | The Source App SHALL accept an organisation only via an onion address plus K01 fingerprint (deep link/QR or manual entry) and SHALL refuse revoked or unsigned addresses. | INC-52; INC-28 | THR-044 | C-03 | TST: revoked/unsigned address rejected |
| NET-025 | The Clearnet Information Site SHALL send `Onion-Location` on every page, be static with no submission form for anonymous mode, load no third-party resources, and not be fronted by a TLS-terminating third party. | ADR-002; ADR-003; INC-46; INC-54 | THR-036; THR-040 | C-37 | TST: header and CSP scanner; INSP: hosting config |
| NET-026 | Any Tor exit-list check on C-37 SHALL be performed in memory for banner selection only and SHALL NOT be logged or stored. | ADR-003 | THR-001; THR-016 | C-37 | TST: log canary; INSP |
| NET-027 | Source guidance SHALL advise against employer networks/devices and describe WebTunnel, obfs4 and Snowflake bridges per §12. | INC-31; B-AN-30; B-AN-31 | THR-002 | C-06, C-37 | INSP: content review (05) |
| NET-028 | The Source App SHALL support obfs4, Snowflake and WebTunnel bridges with hash-pinned PT binaries and SHALL never fall back to non-Tor connectivity. | B-AN-30; B-AN-31 | THR-002 | C-03 | TST: bridge connectivity tests; network capture |
| NET-029 | C-06 SHALL enforce per-CircuitToken rate limits and global concurrency limits (§13), queue waiting requests without revealing queue state, and serve a no-JS busy page only on queue overflow. | ADR-026; ADR-038(5); RVW-A-27 | THR-032; THR-033; THR-011 | C-06, C-07 | TST: load test (34); responses below overflow indistinguishable in size class and latency floor |
| NET-030 | No third-party CAPTCHA, CDN or WAF SHALL be placed in the source path. | ADR-026; INC-54 | THR-036; THR-001 | C-05, C-06 | INSP; TST: resource origin scan |
| NET-031 | Intake-host network flows SHALL be exactly the matrix of §14.2 (= 17 §4.3.1 E1–E5 plus inbound I1 relay TCP 7443 on `relay0` and optional I2 sshd): default-deny; only the two tor UIDs reach ext0; only the C-25 agent push (E3) and chrony (E4) reach H-MON; no inbound monitoring pull; no clearnet DNS/NTP. | ADR-009; INC-33; RVW-A-23 | THR-001; THR-035; THR-104 | C-05, C-39 | TST: egress test as every other UID fails; ruleset diff against template; canary-host reachability probe |
| NET-032 | C-06 and C-07 SHALL run in a network namespace with only loopback and communicate through Unix sockets. | INC-33 | THR-014; THR-001 | C-06, C-07 | TST: namespace inspection in self-test |
| NET-033 | Intake hosts SHALL use no clearnet DNS or NTP; host time SHALL satisfy the Tor-consensus floor rule and the Roughtime cross-check of §14.3, SHALL NOT be set or validated from Z-CORE-supplied timestamps, and violations SHALL make C-07 fail closed. | ADR-036(6); INC-33; RVW-A-04 | THR-043; THR-035 | C-05, C-07 | TST: no resolver; clock-skew injection; Z-CORE-supplied wrong time ignored |
| NET-034 | `candorctl net selftest` SHALL run at boot and every 15 minutes and stop C-06 on any failure of §14.2 checks. | ADR-002 | THR-035 | C-05, C-06, C-25 | TST: fault injection |
| NET-035 | If the onion service is unavailable, no alternative anonymous path SHALL be offered; the info site SHALL display an outage notice. | ADR-002; INC-03 | THR-040 | C-37, C-06 | DEMO; TST |
| NET-036 | Reachability monitoring SHALL be performed from C-25 using its own tor client against a static health endpoint; intake hosts SHALL export only the liveness fields and daily load bands of §15, pushed by the local C-25 agent (E3); the collector SHALL NOT initiate connections to the intake (ARCH-014). | ADR-016; ADR-038(5); ADR-046(5); INC-60 | THR-016; THR-011 | C-25, C-05 | INSP: exporter schema; TST: exporter output contains only allowed fields and no sub-day load values |
| NET-037 | Packet capture, flow export, per-connection tracing and tor info/debug logging SHALL be disabled on intake hosts in production, except in a dual-approved, time-boxed (≤ 1 h), volatile debugging window. | ADR-016; INC-60 | THR-016 | C-05, C-39 | INSP: config; TST: flow-export absent |
| NET-038 | Source-facing pages SHALL be minimal and uniform in size class to reduce website fingerprinting (targets in 11). | B-AN-16; B-AN-19 | THR-004 | C-06 | TST: size-class test (30) |
| NET-039 | Each tenant/customer SHALL have a dedicated onion service and intake gateway; onion services SHALL NOT be shared across customers. | ADR-021 | THR-045 | C-05 | INSP: deployment inventory |
| NET-040 | The Source App's update checks, witness-checkpoint fetches, reply retrieval and all other network requests SHALL use Arti, with identical request shapes for all users; updates SHALL come from the project onion mirror and SHALL NOT contact organisation-specific endpoints. | ADR-022; ADR-036(5); ADR-039; ADR-041 | THR-002; THR-025 | C-03, C-33 | TST: traffic capture |
| NET-041 | Intake hosts SHALL block cloud metadata endpoints and IPv6 router advertisements. | INC-59 | THR-030 | C-39 | TST: probe from host |
| NET-042 | The optional onion TLS mode SHALL replace (not add to) the HTTP onion port and SHALL NOT permit downgrade to HTTP. | B-CR-08 | THR-003 | C-05, C-06 | TST: port scan over Tor |
| NET-043 | An onion service private key SHALL be present on exactly one intake host in single-host profiles and on at most two intake hosts (active/passive, only one tor instance publishing at a time) in EE-HA/GOV-ONPREM, both listed in the Secret Placement Manifest and monitored identically. | ADR-032; ADR-028 | THR-044 | C-05, C-25 | TST: placement self-test counts key copies; failover test shows single publisher |
| NET-044 | Intake hosts SHALL fetch updates only through the `candor-update` tor instance from the Candor project's onion mirror and SHALL verify TUF and log proofs themselves; no other update path SHALL exist for Z-INTAKE. | ADR-046(3); ADR-009; RVW-C-08 | THR-001; THR-025 | C-05, C-10 | TST: egress capture during update; bundle push from C-09 refused |
| NET-045 | A separate `candor-update` tor instance (UID `_tor-candor-update`) without onion keys SHALL serve updates and time checks; the source onion instance SHALL have no SocksPort and its control socket SHALL NOT be readable by the updater or time checker. | ADR-028; RVW-A-23 | THR-044; THR-035 | C-05 | TST: lint; permission check |
| NET-046 | External Watchers (≥ 2 organisations, ≥ 1 outside the operator's jurisdiction for EE/GOV/MANAGED) SHALL fetch the source UI, headers, running manifest and directory over Tor per §15.1 with Tor Browser-identical request shapes and fresh circuits at random intervals, compare them with the transparency log and publish mismatches. | ADR-035(1); RVW-A-01; RVW-A-13 | THR-007; THR-026; THR-025 | C-06, C-25 (external) | DEMO: watcher report per release; TST: injected asset change detected within 24 h in staging |
| NET-047 | The signed onion address statement SHALL carry a cosignature by ≥ 1 external witness in EE, GOV and MANAGED (CE: SHOULD). | ADR-036(5); RVW-A-08 | THR-044; THR-046 | C-37, C-14 | TST: Source App rejects statement without required cosignature |
| NET-048 | C-37 SHALL NOT host or log downloads of the Source App and SHALL link to the project distribution; its first viewport SHALL show the "work device or work network: stop here" warning; for D1/D2 and GOV-IG/IA tenants it SHALL be hosted outside the organisation's web stack with host access logging disabled. | ADR-041; RVW-A-14; RVW-B-17; RVW-C-20 | THR-002; THR-036 | C-37 | INSP: hosting attestation (quarterly C-37 review); TST: page scan; no installer served |
| NET-049 | Onboarding and source guidance SHALL advise offline publication of the onion address and non-hyperlinked intranet text (§11.2 item 0). | RVW-B-17; INC-31 | THR-002 | C-37, C-19 | INSP: content review (05, 13) |
| NET-050 | Candor SHALL adopt PQ onion/circuit handshakes in client and service in the first minor release after they are available in a stable Tor release meeting §6.3, and SHALL enable onion TLS with the hybrid PQ group by default in HIGH/GOV where a `.onion` certificate is obtainable. | ADR-046(8); RVW-A-11 | THR-003; THR-012 | C-05, C-03, C-06 | INSP: Platform Manifest release checklist; TST: TLS scan (04 CRYPTO-029) |

## 19. Residual risks and limitations (honest)
1. **Tor use is visible** to the source's local network, employer and ISP (THR-002). Bridges reduce, but do not eliminate, this signal; on managed devices nothing at the transport layer helps. Visits to a hyperlinked C-37 from work are logged before any guidance is read; offline publication (§11.2) is advice organisations may ignore.
2. **End-to-end correlation** by adversaries who see both the source's link and the service's link is not prevented (THR-003); timing minimization reduces application-level correlation only. Unpadded Tier W upload volume at the service uplink remains a correlation feature (RVW-A-22).
3. **Website fingerprinting** of a single monitored portal can give an employer a lead (THR-004).
4. **Guard discovery** against a long-lived service remains a state-level threat; vanguards raise cost, not impossibility. If the full vanguards add-on fails its maintenance gate, HIGH profiles fall back to vanguards-lite until Arti services are admitted (ADR-046(9)).
5. **Onion address impersonation** after key theft cannot be revoked inside Tor; Tier W sources on bookmarks may be phished.
6. **No offline onion identity keys** with C-tor: the key is on an Internet-connected host — on two hosts in HA profiles (ADR-032), doubling THR-044 exposure.
7. **Anonymity set within an organisation** may be very small (the employees who use Tor) regardless of Tor's global size.
8. **Onion Browser (iOS)** offers weaker protections; iOS-only sources are at higher risk.
9. **Availability**: large DoS can still degrade intake, and sources may turn to unsafe channels.
10. **Harvest-now-decrypt-later:** Tier W sessions recorded before PQ onion handshakes exist can be decrypted by a future quantum adversary, including passphrases (ADR-046(8)).
11. **Independent time** depends on Tor directory authorities and Roughtime operators; freeze is bounded to ≈ 1 day, not eliminated; Roughtime over Tor depends on TCP-capable servers (Knowledge (unverified)).
12. **External Watchers** only see what an anonymous first-time visitor sees; selective modification after login or for specific answers is invisible to them; watcher diversity depends on external organisations' participation.

## 20. Open issues
| # | Issue | Proposed resolution |
|---|---|---|
| OI-1 | Verify `HiddenServiceExportCircuitID` with Unix-socket targets, and `Sandbox 1` with vanguards `SETCONF` (Knowledge (unverified)). | Integration tests in 29/30; fall back to loopback TCP in isolated namespace. |
| OI-2 | ADR-001 vanguards baseline and add-on maintenance status. | **Resolved by ADR-046(9):** full vanguards for HIGH with a maintenance gate and documented fallback to vanguards-lite / Arti full mode (§7.2). Extending full vanguards to all profiles remains a proposal for when Arti services are admitted. |
| OI-3 | C-tor has no offline onion identity key support (Knowledge (unverified)). | Track Arti; revisit K16 custody. |
| OI-4 | Current Tor Metrics figures, Onion Browser status and Arti service-side PoW status require re-verification (R4 §8). | Research follow-up before 1.0. |
| OI-5 | Cover-traffic transport (CoverDrop/Nym-style) evaluation for "using the channel is not a signal"; decoy uploads for HIGH (RVW-A-22). | Separate research track; admission per §6.3. |
| OI-6 | Active/active HA with one onion address (OnionBalance-style) is deferred by ADR-032; the passive host doubles THR-044 exposure. | Security review before any active/active design (21). |
| OI-7 | Roughtime-over-TCP server availability and the exact tor control query for consensus `valid-after` (Knowledge (unverified)). | Integration test; if no TCP Roughtime server is reachable, operate on the consensus floor alone and record it in the health band. |
| OI-8 | **Resolved (final consistency pass):** 17 and 18 now use `_tor-candor-intake`. Final round: 17 §4.3.1 row E1 names the source onion UID `debian-tor`; this document and the §7.1 per-instance layout use `_tor-candor-intake` (Debian `tor-instance-create` convention). Ports, interfaces and flows are otherwise identical. | 17 to rename E1 and its ruleset UID to `_tor-candor-intake` (logged in `process/DISP-FINAL-F2.md`). |
