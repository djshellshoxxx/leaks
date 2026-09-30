# 18 — Deployment Profiles, Packaging, Installation, Upgrade and Recovery

Status: Draft v1.2 (final consistency pass: ADR-047, cross-document requests) · previously v1.1 (revision round 2: ADR-034..046) · Edition applicability: both (CE profiles CE-SINGLE, CE-HARDENED; EE/GOV profiles marked) · Owner: Platform Engineering / Release Engineering

## 1. Purpose and scope

This document specifies:
- the eight deployment profiles of ADR-024, each with threat model, advantages, disadvantages, minimum hardware, network design, failover, backups, key management and operational complexity;
- the packaging assessment: Debian packages, OCI, Kubernetes, VMs, physical appliances;
- installation: automated, hardened, IaC, offline, and a simple small-business installer with secure defaults;
- upgrade, rollback, backup and recovery procedures, with operator command sequences;
- the configuration checker;
- the Secret Placement Manifest (ADR-028).

Infrastructure baselines that the installer applies are in `17-INFRASTRUCTURE.md`. Backup cryptography and DR policy are in `19-BACKUPS-DR.md`. Update signing and TUF roles are in `33-RELEASE-UPDATE-SECURITY.md`. Configuration classification is in `32-OPERATIONS.md` §7.

## 2. Context and dependencies

| Source | Use |
|---|---|
| ADR-009, 019, 021, 022, 024, 028 | Binding: intake/core separation; Debian 13 + signed .deb primary; multi-tenancy limits; TUF updates; profiles; secret manifest |
| ADR-035, 038, 040, 043, 044, 045, 046 (revision round 2) | External Watchers and Operator Statement; fixed import slots and constant-schedule notifications; Platform Manifest and security floors; independent-custody devices; vault DR and backup exclusion, `min_recipients` 2, GOV Recovery Quorum default; small-organisation mode and Fleet limits; no intake replication, no HSM fallback, per-zone update paths, config labels, CE-SINGLE VM default |
| ADR-047 (final round) | Chaff envelopes (intake spool sizing), Key Directory/attestation freshness, intake deletion list applied on restore (§13), Desk re-wrap after vault loss (§13), MANAGED customer-held audit key and verifier (§4.8, §8.1) |
| `17-INFRASTRUCTURE.md` | Host roles (H-*, including H-ALERT `alert-relay`, r3), segments (N-*), flows (F1–F16, F5b, F10a), FDE unlock modes (U1–U7), hosting-provider analysis, C-37 hosting (§4.11) |
| `19-BACKUPS-DR.md` | Backup sets (BS-*), RPO/RTO |
| `21-ENTERPRISE.md` | HA orchestration module (EE, ADR-020) |
| `22-GOVERNMENT.md` | GOV-ONPREM specifics |
| `23-COMMUNITY-EDITION.md` | SMB positioning |
| `33-RELEASE-UPDATE-SECURITY.md` | Release signing, TUF roles, transparency |
| `34-PERFORMANCE-SCALABILITY.md` | Sizing and upload limits |

Research lessons applied:

| Lesson | Evidence | Applied in |
|---|---|---|
| SecureDrop's two-server + firewall + Tails model is a heavy operational burden ($2.2–2.4k in hardware plus a Linux sysadmin); its Ansible deployment leaked secrets to the Monitor server | B-SD-08, B-SD-22 | Simple installer (§8); no directory copies and a verified manifest (§15) |
| SecureDrop's server FDE is missing because of unattended boot | B-SD-13 | FDE modes (`17-INFRASTRUCTURE.md` §6.3) |
| SecureDrop's Focal→Noble migration was phased, then automated migration was disabled | B-SD-02, B-SD-03 | OS major upgrades by rebuild-and-restore (§11.4) |
| GlobaLeaks `install.sh` uses a placeholder checksum, TOFU key fetch into `trusted.gpg.d`, and `:latest` images | B-GL-05, B-GL-41 | Pinned fingerprints, `Signed-By`, digests (§7.3) |
| CoverDrop: k3s on-premises, GitOps with manual PR approval, sealed secrets | B-GL-30 | EE-HA GitOps (§9.3) |
| xz, SolarWinds, 3CX | INC-37, INC-38, INC-41 | Offline bundles and TUF verification (§10, §11) |

## 3. Profile overview

| Profile | Edition | Hosts (minimum) | Z-INTAKE isolation | Z-CORE platform | K8s allowed | HSM | Default FDE unlock (`17-INFRASTRUCTURE.md` §6.3) | Staff path |
|---|---|---|---|---|---|---|---|---|
| CE-SINGLE | CE | 1 physical (3 VMs; + optional `alert-relay` VM when alerts are enabled) | Separate VM (container split = ADVANCED) | VM | No | No (TPM2) | U3 (or U2 ADVANCED) | RCP-ONION |
| CE-HARDENED | CE | 3 physical + off-site Tang | Dedicated host | Dedicated host | No | Optional | U4 | RCP-ONION |
| EE-ONPREM | EE | 4 hosts/VM hosts (intake physical) | Dedicated host | VMs on dedicated virtualization | No | Optional (recommended) | U4 | RCP-LAN (RCP-ONION allowed) |
| EE-HA | EE | ≥ 9 | 2 dedicated intake hosts, active/passive, shared-nothing (no DB replication, ADR-046(1)), same onion key (ADR-032) | Dedicated K8s cluster or VM cluster | Z-CORE only | Yes (pair; no fallback keys, ADR-046(2)) | U4 (Tang ×2 sites) | RCP-LAN (RCP-ONION allowed) |
| GOV-ONPREM | EE | as EE-ONPREM or EE-HA | Dedicated host in accredited facility | VMs (K8s only if accredited) | Z-CORE only | Mandatory (FIPS 140-3 L3) | U7 or U3 | RCP-LAN (accredited) or RCP-ONION |
| AIRGAP-RCP | CE/EE add-on | +1 sync WS + ≥1 air-gapped WS per recipient team | (inherits server profile) | (inherits) | — | Hardware tokens | U3 on workstations | From WS-SYNC only (RCP-ONION or RCP-LAN) |
| PRIVATE-CLOUD | EE (CE possible) | ≥ 3 VMs in customer cloud account + on-prem Tang | Sole-tenant / confidential VM | VMs, or K8s (ADVANCED) | Z-CORE only | Customer on-prem HSM or none; **no provider KMS** | U4 (Tang on-prem) or U6 | RCP-LAN (RCP-ONION recommended where staff IPs should stay hidden from the provider) |
| MANAGED | EE | Vendor-operated, dedicated per customer | Dedicated intake VM or host + onion key per customer | Dedicated per customer | Z-CORE only | Vendor HSM partition per customer (integrity keys only) | U4 (Tang at a second vendor site) | RCP-ONION |

In every profile, devices of INDEPENDENT-channel members (ADR-043) use RCP-ONION or the padded WireGuard variant (`17-INFRASTRUCTURE.md` §4.6), whatever the profile's default staff path.

## 4. Deployment profiles (detail)

### 4.1 CE-SINGLE

| Attribute | Specification |
|---|---|
| THREAT MODEL | **Designed against:** remote attackers (web exploitation of C-06); database/disk theft of a powered-off host; curious non-technical insiders without admin credentials; legal compulsion of the operator for stored data (yields ciphertext and metadata only; `17-INFRASTRUCTURE.md` §8). **Not designed against:** a hypervisor/host-kernel compromise, which reaches both zones; a live-seized host (Tier W in-flight plaintext); an adversary controlling the site network (THR-002/003); a determined physical attacker with repeated access. **A malicious SYS_ADMIN is not detectable** in this profile: H-MON runs on the same hypervisor the admin controls, so attestation and the self-test give no independent evidence (RVW-C-09). High-risk channels on CE-SINGLE SHOULD be Tier V only. Suitable for low/moderate-risk organizations (ADR-021 classification); organisations with fewer than 4 distinct enrolled persons run in small-organisation mode (§8.1, ADR-045) |
| ADVANTAGES | One machine; about 1 hour to install with `candor-setup`; low cost; all CE cryptographic protections identical to other profiles (ADR-020); VM separation (the CE-SINGLE default, ADR-046(6); container-only separation is ADVANCED) keeps the ADR-009 pull model |
| DISADVANTAGES | Single point of failure (no failover); the hypervisor is shared trust; H-MON on the same host cannot independently detect host compromise; a Tang server on the same host is meaningless (hence U3) |
| MINIMUM HARDWARE | 1 × x86-64 server or workstation-class machine: 8 cores with VT-x/AMD-V + IOMMU, 32 GiB ECC RAM (non-ECC allowed with warning), 2 × 1 TB NVMe (RAID1 under LUKS), TPM 2.0, UEFI Secure Boot, 1–2 NICs, UPS. VMs: `intake` 2 vCPU/10 GiB (includes the 4 GiB Tier W staging tmpfs, ADR-034; `34-PERFORMANCE-SCALABILITY.md` §8.2)/64 GiB + spool per 34; `core` 4 vCPU/12 GiB/500 GiB, with the Erasure Key Vault on a **separate virtual disk** (`/var/lib/candor/ekv`, excluded from any hypervisor snapshot; `17-INFRASTRUCTURE.md` §5.7); `mon` 1 vCPU/2 GiB/20 GiB (no uplink); optional `alert-relay` 1 vCPU/1 GiB/8 GiB (own uplink, no `br-mgmt` port; `17-INFRASTRUCTURE.md` §3). The intake spool includes chaff envelopes (ADR-047(3); `34-PERFORMANCE-SCALABILITY.md`); the Tier W staging tmpfs is mounted at `/run/candor/staging`. Backup: 2 × 2 TB external SSDs (rotating, one off-site). Staff: ≥ 2 recipient workstations (`min_recipients` 2, ADR-044(2)), 1 admin workstation (MAY be a separate OS account on a recipient workstation with a separate hardware key: CFG ADVANCED), 2 hardware authenticators per person (primary + stored backup, ADR-044(2)) |
| NETWORK DESIGN | Host NIC → site router/firewall. `br-ext` carries the intake and core VM uplinks (egress tor only, `17-INFRASTRUCTURE.md` §4.3–4.4). `br-relay` is an L2-only link between core and intake; the host has no IP. `br-mgmt` carries mon ↔ intake/core. No inbound port forwarding is required (onion services only). Uplink independence per `17-INFRASTRUCTURE.md` §4.10 |
| FAILOVER | None. Documented RTO via restore to replacement hardware (`19-BACKUPS-DR.md` RPO/RTO table). An outage shows sources the onion unreachable (fail closed; no clearnet fallback, ADR-002) |
| BACKUPS | Nightly BS-CORE and BS-INTAKE to a rotating encrypted external disk (H-BAK role played by the disk). BS-SECRETS written once at install and after each key rotation to 2 offline media (`19-BACKUPS-DR.md`) |
| KEY MANAGEMENT | Recipient keys on staff hardware (ADR-007). Onion key on the intake VM plus BS-SECRETS. Audit and key-directory log signing keys in a TPM2-resident key of the host (vTPM per VM via swtpm, sealed by host TPM). The backup KEK is held offline as a Shamir 2-of-3 Infrastructure Recovery Key (IRK) on hardware tokens/paper (`19-BACKUPS-DR.md`). Recovery Quorum off (ADR-013) |
| OPERATIONAL COMPLEXITY | Low-medium (2/5). Budget per §4.9: about 3 h/week averaged over a year for one named operator (weekly backup rotation, update review, self-test review) plus one yearly ceremony day and quarterly restore/seal tasks. v1.0 claimed "2 h/week, no Linux expertise"; that was not consistent with the controls (RVW-C-17). Organisations without a named competent operator SHOULD use MANAGED by an independent operator |

### 4.2 CE-HARDENED

| Attribute | Specification |
|---|---|
| THREAT MODEL | Everything in CE-SINGLE, plus: kernel/hypervisor escape from intake to core (separate hardware); seizure of the server room without the Tang site (U4); independent monitoring by H-MON (attestation, `17-INFRASTRUCTURE.md` §5.6); higher-risk organizations (newsrooms, NGOs) similar to SecureDrop's app/monitor split [B-SD-04]. **Not designed against:** live seizure of H-INTAKE; provider-level network observation of the uplink; coerced admin with FIDO2 |
| ADVANTAGES | Physical zone separation (ADR-009); unattended reboot with FDE (U4), which closes the gap left open in SecureDrop [B-SD-13]; independent monitor; optional air-gapped viewing (AIRGAP-RCP) |
| DISADVANTAGES | 3 hosts + off-site Tang to maintain; more hardware cost; still no automatic failover |
| MINIMUM HARDWARE | H-INTAKE: 4 cores, 16 GiB ECC (includes the 8 GiB Tier W staging tmpfs), 2 × 512 GB NVMe RAID1, TPM2, 2 NICs (ext0, relay0) + mgmt0. H-CORE: 8 cores, 32 GiB ECC, 2 × 2 TB NVMe RAID1, TPM2, NICs relay0, mgmt0, bak0, egress0. H-MON: 2 cores, 4 GiB, 128 GB SSD, TPM2 (a mini-PC is acceptable), **no Internet uplink**. H-ALERT (`alert-relay`, r3): a separate small device or VM with its own uplink and a direct link to H-MON (N-ALERT) only; required if alerts or the external onion probe are used. H-CORE: the Erasure Key Vault on a dedicated LUKS volume on the host's physical TPM. Off-site Tang: a small fanless device in a different building. H-BAK: 4 TB NAS/server running an S3-compatible store with Object Lock (compliance mode), plus 2 offline rotation disks. Optional managed switch with VLANs, or direct cables for relay0/bak0. Optional C-18 air-gapped station |
| NETWORK DESIGN | Per `17-INFRASTRUCTURE.md` §4.1: separate physical links for N-RELAY and N-BAK (direct cables recommended), N-MGMT via a small unmanaged switch, N-OOB disconnected. H-INTAKE on an independent uplink line where possible |
| FAILOVER | Cold spare: one pre-installed H-INTAKE spare with no secrets, stored sealed. Promotion restores BS-SECRETS (onion key) + BS-INTAKE and applies the merged deletion list (`19-BACKUPS-DR.md` DR-P1), keeping the same onion address. H-CORE: restore to spare hardware |
| BACKUPS | BS-CORE nightly (full) + WAL archive every 15 min (fixed-size segments, 19 §5.3) to H-BAK (WORM). Weekly copy to offline disk, rotated off-site. BS-INTAKE nightly. BS-SECRETS on change |
| KEY MANAGEMENT | As CE-SINGLE, but signing keys in each host's TPM2. Optional USB HSM for the audit and directory keys. IRK 2-of-3 (default) or 3-of-5. Tang keys on H-MON + off-site device, rotated yearly |
| OPERATIONAL COMPLEXITY | Medium (3/5). About 4 h/week; Linux-competent admin; quarterly seal inspection and restore test |

### 4.3 EE-ONPREM

| Attribute | Specification |
|---|---|
| THREAT MODEL | As CE-HARDENED, plus enterprise insiders: corporate IT/SOC staff, DBAs, virtualization admins and executives (THR-018, THR-020); integration exfiltration (THR-029); SSO compromise (THR-022). Z-CORE runs on customer virtualization, so **the virtualization admin team is an observer of Z-CORE** (no content, but metadata; 17 §7 rows apply to internal virtualization). **Not designed against:** a customer that controls every layer and colludes (a compelled operator can still observe Tier W live) |
| ADVANTAGES | Uses existing enterprise virtualization for Z-CORE; SSO/SCIM (EE); SIEM export (C-26); HSM integration; enterprise backup targets |
| DISADVANTAGES | Enterprise infrastructure teams become observers; change-management friction; temptation to integrate with general logging, backup or EDR tooling, which the config checker flags |
| MINIMUM HARDWARE | H-INTAKE: dedicated physical host as in CE-HARDENED but with 32 GiB RAM (16 GiB Tier W staging, `34-PERFORMANCE-SCALABILITY.md` §8.2) (NOT on the shared virtualization cluster). Z-CORE: dedicated VMs on hosts **not shared with general IT workloads**: `core-app` 8 vCPU/16 GiB; `core-db` 8 vCPU/32 GiB/1 TB+ (per 34); `core-blob` 4 vCPU/8 GiB/size per 34. H-MON VM (separate host from core). H-BAK: enterprise WORM target (S3 Object Lock / immutable NAS snapshots) in a separate security domain. Optional network HSM pair (FIPS 140-3 L3). Off-site Tang |
| NETWORK DESIGN | H-INTAKE on an independent uplink (`17-INFRASTRUCTURE.md` §4.10). N-RELAY: dedicated VLAN with firewall rule core→intake:7443 only. Z-CORE VLAN(s) with no route to user networks except the recipient VLAN for RCP-LAN (Desk API TCP 8443 mTLS, default per `06-SYSTEM-ARCHITECTURE.md` §8.3) or RCP-ONION. The recipient VLAN is excluded from per-flow logging by general network monitoring (INFRA-009). SIEM export from C-26 only |
| FAILOVER | H-INTAKE cold spare (as CE-HARDENED). Z-CORE: virtualization HA restart (VM-level). DB with a streaming replica VM on a different host (RPO ≈ 0 within a site) |
| BACKUPS | As CE-HARDENED, plus a second WORM copy at a secondary site. Enterprise backup tools SHALL NOT image Z-INTAKE/Z-CORE VMs, and in particular SHALL NOT copy the Erasure Key Vault volume or vTPM state (hypervisor-level copies bypass BS-* encryption and retention and defeat the 14-day deletion bound, RVW-C-06). Because this is invisible to the guest, go-live requires the signed exclusion attestation of `17-INFRASTRUCTURE.md` INFRA-037 by the virtualization and backup owners. Z-CORE on virtualization **shared with general IT workloads** is ADVANCED and requires the same attestation |
| KEY MANAGEMENT | HSM: audit checkpoint, key-directory log, DB TDE (optional), SSH CA with two-person issuance for H-INTAKE, Erasure Key Vault volume key (or physical TPM of a dedicated core host; never a vTPM for HIGH, ADR-044(4)). IRK for the backup KEK held by 3 of 5 custodians (security officer, DPO, ombudsman, …), at least one from an independent role. Recovery Quorum optional (ADR-013, DANGEROUS config) |
| OPERATIONAL COMPLEXITY | Medium-high (3.5/5). Security team + infra team; 0.25 FTE admin; change calendar per `32-OPERATIONS.md` |

### 4.4 EE-HA

| Attribute | Specification |
|---|---|
| THREAT MODEL | As EE-ONPREM, with availability objectives (THR-032, THR-042). Explicitly accounts for the **extra observers introduced by HA** (listed in `34-PERFORMANCE-SCALABILITY.md` §7): core replication links, extra copies of the onion keys, K8s control plane, mesh sidecars. The intake has **no** replication link (ADR-046(1)) |
| ADVANTAGES | Intake service survives a single-host failure (new submissions continue on the passive host; see FAILOVER for what is not carried over); core survives node/zone failure; rolling upgrades with a short source-visible switchover |
| DISADVANTAGES | More hosts means more seizure targets and more observers; the onion key exists on 2 hosts (ADR-032 doubles THR-044 exposure); K8s adds cluster-admin as a super-role; highest complexity |
| MINIMUM HARDWARE | Z-INTAKE: H-INTAKE (active) + H-INTAKE-B (passive), each as CE-HARDENED H-INTAKE, in separate racks with separate power; **shared-nothing** (each host its own intake store; no PostgreSQL replication, ADR-046(1)); a direct-cable heartbeat link N-INTAKE-HB; a fencing device (switched PDU or BMC on N-OOB) for STONITH. DR site: an intake VM **without** onion key until DR is declared. Z-CORE: dedicated K8s (3 control-plane + 3 workers, 8 vCPU/32 GiB each) **or** VM cluster; PostgreSQL 3-node (Patroni-class) on dedicated VMs outside K8s (recommended) or as a StatefulSet; blob store 4-node erasure-coded S3-compatible on-prem. H-MON × 2 (no uplink) + H-ALERT × 2. HSM pair. H-BAK at 2 sites. Tang × 2 sites |
| NETWORK DESIGN | Only the active intake's tor instance publishes descriptors. The passive host's tor is stopped (same onion key, ADR-032; active/active descriptor aggregation is deferred per `21-ENTERPRISE.md` §5.2 and `16-TOR-I2P.md`). Both intake hosts sit on the same site with independent uplinks from the same independent provider (a second site adds a second uplink observer; ADVANCED). N-INTAKE-HB carries only the fixed-size heartbeat (observer analysis in `34-PERFORMANCE-SCALABILITY.md` §7). C-09 pulls from the active intake, and after a failover also from the recovered former active until its queue is empty. K8s: dedicated cluster, NetworkPolicies default-deny, no service-mesh access logs, staff Desk API behind an L4 passthrough LB with logging off (`21-ENTERPRISE.md` HA-004) |
| FAILOVER | **Unplanned intake failover:** health probe every 10 s; 3 consecutive failures → fence (STONITH) the active → start the passive (tor start, descriptor publish) on its own store. Target intake RTO ≤ 10 min (single value across 18, 19 and 21; RVW-C-19); sources with a cached old descriptor may fail until they refetch. A source sees "received" only after local fsync on the host that accepted it (ADR-046(1)); envelopes and account records on the failed host are **not lost but unavailable** until its disk is recovered, after which C-09 pulls them. Source accounts created on the failed host since the passive's last seeding cannot log in on the passive until then (the source UI states "your mailbox is temporarily unavailable; do not create a new one unless advised"). **Planned switchover** (upgrades, maintenance): stop-transfer-start at the start of an import slot: the active stops accepting, C-09 pulls all pending envelopes, then pulls an encrypted store export (BS-INTAKE format) and restores it to the passive over the relay (core-initiated, never intake-to-intake), then the passive publishes (source-visible unavailability ≤ 10 min). Core: Patroni failover ≤ 30 s; K8s rescheduling. Site DR: onion key restored from BS-SECRETS under IRK quorum; the Erasure Key Vault is replicated to the DR core within the core RPO (ADR-044(4), `19-BACKUPS-DR.md` §6.1) |
| BACKUPS | WAL archiving every 15 min with fixed-size segments; nightly base backup; WORM at 2 sites; offline monthly copy |
| KEY MANAGEMENT | Source onion key on H-INTAKE and H-INTAKE-B only (TPM-sealed on each), plus BS-SECRETS offline. Both hosts are in the Secret Placement Manifest and monitored equally (ADR-032). Standby onion key offline only (`16-TOR-I2P.md` NET-020). HSM pair for signing keys; if both HSMs are unavailable, signing pauses (no TPM or software fallback, ADR-046(2); `21-ENTERPRISE.md` HA-013 superseded). The K8s Secrets encryption provider SHALL use the customer HSM (KMS v2 plugin), never provider KMS. Key custodians of IRK/IRK-S and every case's key holders are geographically split per `19-BACKUPS-DR.md` §11.1 so that a site loss does not remove all of them |
| OPERATIONAL COMPLEXITY | High (4.5/5). Dedicated platform team (≥ 1 FTE), on-call, runbooks, twice-yearly failover drills |

### 4.5 GOV-ONPREM

| Attribute | Specification |
|---|---|
| THREAT MODEL | As EE-ONPREM/EE-HA, plus nation-state adversaries, insider threat programs, legal compulsion via internal channels, and accreditation requirements (FIPS 140-3 crypto; SP 800-53 controls, see `22-GOVERNMENT.md`, `25-COMPLIANCE.md` [B-CO-40]). Adversaries may include the agency's own leadership (IG context, 5 USC 407 [B-CO-13]) |
| ADVANTAGES | FIPS profile CANDOR-FIPS-1 (ADR-006); HSM-backed integrity keys; no vendor access; air-gapped update path; accredited facility physical controls |
| DISADVANTAGES | Slow update cadence (offline bundles); FIPS profile constraints; heavy accreditation documentation; PQ limited to FIPS-approved ML-KEM hybrid |
| MINIMUM HARDWARE | As EE-ONPREM or EE-HA. Plus: FIPS 140-3 L3 HSM (network or PCIe) pair; hardware with removable-radio-free chassis for C-18; U7 smartcard readers; GPS/PTP time source for H-MON |
| NETWORK DESIGN | As EE-ONPREM. H-INTAKE uplink on an independent circuit (not the agency enterprise network), with the relay VLAN crossing a guard/firewall with a documented rule set. No vendor connectivity. Updates via cross-domain transfer of offline bundles (§10) |
| FAILOVER | Per chosen base (EE-ONPREM or EE-HA). Spare hardware stored in the facility |
| BACKUPS | WORM on-prem + offline media in a separate accredited facility; courier under two-person rule |
| KEY MANAGEMENT | HSM mandatory for audit, key-directory, SSH CA, internal CA, backup KEK (offline HSM). FDE: U7 (smartcard + PIN) or U3. Staff keys on PIV/CAC-class cards (ADR-007 PIV option). **Organization Recovery Quorum enabled by default** (ADR-044(3)) with custodians from independent roles and disclosed to sources on the landing page, because records law may prohibit unrecoverable loss; disabling it requires a written determination by the agency records officer recorded in the deployment record. Erasure Key Vault volume key on the physical TPM or HSM, never a vTPM (ADR-044(4)) |
| OPERATIONAL COMPLEXITY | Very high (5/5). Accredited admin staff; ISSO; formal change control |

### 4.6 AIRGAP-RCP (air-gapped recipient environment; add-on to any server profile)

| Attribute | Specification |
|---|---|
| THREAT MODEL | Recipient-side malware and exfiltration (THR-023, THR-041), remote compromise of networked recipient workstations (THR-022), and network-borne exfiltration of decrypted content. **Not designed against:** malicious media transfer (USB is bidirectional; the SVS lesson, [B-SD-04]); a malicious insider at the station; a document exploit that persists on the station (mitigated by C-17 disposables on the station) |
| ADVANTAGES | Private keys and plaintext never exist on a networked machine; strongest option for high-risk investigations |
| DISADVANTAGES | Latency (manual transfers); human error at the transfer step; the **epoch window constraint**: envelopes MUST be imported within the 14-day decrypt window of the member epoch keys (ADR-008, ADR-030), and each member's WS-VIEW must publish new member epoch keys (pre-published 4 epochs ahead, ADR-030) via WS-SYNC. Epoch keys are retired only after import (ADR-033(2)), so a late sync delays access rather than losing data, but envelopes un-imported for more than 7 days escalate to the independent channel. A sync at least every 7 days is therefore REQUIRED; the self-test warns at 5 days |
| MINIMUM HARDWARE | WS-SYNC: a networked workstation running Candor Desk in **sync-only mode** (holds the RCP-ONION client credential or RCP-LAN certificate and a sync-role token; no decryption keys). WS-VIEW: an air-gapped laptop per team (TPM2, 16 GiB+, radios removed) running Candor Desk full mode + C-17 disposable viewer. Transfer media: dedicated, labelled IN/OUT USB drives (`17-INFRASTRUCTURE.md` §6.6). Hardware keys per recipient |
| NETWORK DESIGN | WS-SYNC → Desk API only (RCP-ONION or RCP-LAN). WS-VIEW: no network interfaces enabled. Transfer bundles: signed by the originating device's staff key, content-addressed names (ADR-027) |
| FAILOVER | A spare WS-VIEW enrolled with the same staff keys requires key re-provisioning per `04-CRYPTOGRAPHY.md`. Otherwise staff keys are wrapped per device |
| BACKUPS | Server-side backups unchanged. WS-VIEW holds no unique data except drafts; drafts SHALL be synced back as sealed objects or discarded |
| KEY MANAGEMENT | Staff private keys generated on WS-VIEW and wrapped by hardware key. Member epoch private keys generated and held only on WS-VIEW (public halves carried OUT for publication). Replies sealed on WS-VIEW and carried OUT to WS-SYNC |
| OPERATIONAL COMPLEXITY | High for recipients (3.5/5): documented transfer ritual; weekly minimum sync |

### 4.7 PRIVATE-CLOUD

| Attribute | Specification |
|---|---|
| THREAT MODEL | As EE-ONPREM, plus the **cloud provider as observer and compellable party** (`17-INFRASTRUCTURE.md` §7, THR-030, THR-026). Designed against: disk/snapshot theft at the provider (in-guest FDE with keys outside the provider), IMDS/SSRF credential theft, public-bucket leaks (INC-59). **Not designed against:** covert compelled hypervisor access (Tier W plaintext in RAM), provider netflow correlation. Not recommended for high-risk tenants (ADR-021) unless Tier V only (CFG: `intake.tier_w.enabled=false`, ADVANCED) |
| ADVANTAGES | No hardware; elastic capacity; provider availability zones |
| DISADVANTAGES | Additional observer that cannot be removed; jurisdiction exposure; complex IAM; provider log sprawl |
| MINIMUM HARDWARE | Intake: 1 sole-tenant or confidential VM (4 vCPU/8 GiB; SEV-SNP/TDX where available). Core: 2–3 VMs (as EE-ONPREM) or dedicated K8s (ADVANCED). Monitor VM in a separate account/project. Backups: object storage with Object Lock (compliance mode) in a **separate account** with a write-only role. Tang: **on-premises** device reachable via a site-to-site tunnel (or U6) |
| NETWORK DESIGN | A dedicated cloud account/project for Candor. VPC with subnets per zone; security groups mirror flows F1–F15; no public IPs except NAT egress for tor; no LB on the source path (REQ-H-54); flow logs disabled for the intake subnet (CFG default for this profile); IMDSv2 hop-limit 1; no IAM role on intake VMs; organization SCP denying snapshot creation on intake volumes **and on the core Erasure Key Vault volume** (ADR-044(4)) |
| FAILOVER | Intake: warm standby VM in another zone without secrets; promotion restores BS-SECRETS. Core: managed-instance restart; DB replica in a second zone |
| BACKUPS | WAL archiving (15-min fixed segments) + nightly base backup to the Object Lock bucket (separate account); monthly export to offline on-prem media |
| KEY MANAGEMENT | Provider KMS **not** used for source-relevant keys (INFRA-022). Signing keys: vTPM (provider-accessible, so integrity only) or an on-prem HSM via tunnel. Backup KEK offline (IRK) |
| OPERATIONAL COMPLEXITY | Medium-high (3.5/5). Cloud IAM expertise required; IaC mandatory (§9.2) |

### 4.8 MANAGED (vendor-operated)

| Attribute | Specification |
|---|---|
| THREAT MODEL | Customer organization's insiders (the vendor is independent of the customer, REQ-H-22); remote attackers. **Vendor-specific threats:** vendor personnel (THR-027), compulsion of the vendor (THR-026), cross-customer leakage (THR-045). Vendor cannot decrypt content: recipient keys stay on customer Desks (ADR-007). Vendor **can** observe intake metadata (timing/volume, as provider) and **can** read Tier W plaintext live if it compromises its own intake host; this is disclosed to customers and sources (ADR-004 honesty text names the operator). **What the vendor can see or be compelled to hand over, for every customer it hosts** (RVW-B-19): all server-visible metadata of Z-INTAKE and Z-CORE (`17-INFRASTRUCTURE.md` §8.5–8.6: account counts, received days and import-slot dates, padded sizes, workflow state, staff directory and notification addressees, SECURITY and CASE audit including exact staff-action timestamps); backup sets if it also holds k IRK shares; live Tier W plaintext, passphrases and return-visit times through its own hypervisor or a modified intake. COI exclusion identities are blinded (ADR-037(3)). One legal order to the vendor reaches many customers at once. The customer-visible inventory in `21-ENTERPRISE.md` SHALL list these, including live capabilities |
| ADVANTAGES | No customer infrastructure skills required; vendor handles patching within SLAs; independence from customer IT (a benefit when the adversary is the customer's own leadership) |
| DISADVANTAGES | Trust in vendor operations; vendor is a legal target; vendor sees metadata across customers (aggregated risk); onion key custody by vendor |
| MINIMUM HARDWARE | Per customer: dedicated H-INTAKE (VM on vendor dedicated hosts, or physical for high-risk customers) with its own onion key (ADR-021); dedicated Z-CORE VMs and dedicated PostgreSQL instance; per-customer backup bucket and per-customer backup KEK. Shared: Fleet Manager C-34 (opaque instance IDs, ADR-022), monitoring backplane receiving only allow-listed self-test results |
| NETWORK DESIGN | Per customer: separate VLAN/VPC, separate tor instances, separate relay links; no cross-customer routes. Vendor ops access via two-person SSH certificates with a **customer-visible access log** (EE feature, `21-ENTERPRISE.md`), whose hash chain is anchored to a **customer-controlled witness** within 15 min so that the vendor cannot rewrite it (RVW-C-21) |
| INDEPENDENT VERIFICATION (RVW-C-21, ADR-035) | (1) ≥ 2 External Watchers, at least one outside the vendor's jurisdiction, compare served static assets and the Sealer's running manifest with the transparency log (ADR-035(1)). (2) The confidential-VM Sealer profile (`17-INFRASTRUCTURE.md` §5.9) is RECOMMENDED for high-risk tenants; its attestation report is verified by the **customer's own** Desks at import, not by vendor-run H-MON. (3) The quorum-signed Operator Statement (ADR-035(2)) includes ≥ 1 customer-side independent signer. (4) For tenants classified high-risk (`21-ENTERPRISE.md` §6.3), `intake.tier_w.enabled` defaults to **off** (Tier V only) unless the customer's OVERSIGHT records an acceptance of the Tier W residual. (5) A **customer-held attestation verifier** (`17-INFRASTRUCTURE.md` §5.6, INFRA-046) receives the intake's PCR quotes and CVM evidence (≤ 24 h old, ADR-047(4)) and alerts the customer's OVERSIGHT; vendor-run H-MON is not the only verifier |
| FAILOVER | As EE-HA or EE-ONPREM per contract tier |
| BACKUPS | Per-customer encrypted sets; the backup KEK is IRK-split with at least one custodian at the customer (so the vendor alone cannot decrypt backups; configurable), WORM at 2 vendor sites. Audit exports are encrypted to a **customer-held audit export key** (ADR-047(10)); the vendor stores but cannot read them |
| KEY MANAGEMENT | Customer holds recipient keys and the optional Recovery Quorum. Vendor holds onion keys (per customer), integrity keys in per-customer HSM partitions. The customer can **export** its instance (BS-SECRETS + data) to self-host (portability; no lock-in of onion address) |
| OPERATIONAL COMPLEXITY | Low for the customer (1.5/5); high for the vendor. The customer still performs recipient-side duties (Desk weekly, custody of its IRK share, Operator Statement co-signature, OVERSIGHT tasks) |

### 4.9 Operational Load Budget (normative; RVW-C-17)

The v1.0 profile texts understated the recurring work. The table sums, per profile, the recurring duties defined in 17, 19, 31 and 32. Figures are planning estimates to be validated in the operational pilot of DEP-037; a deployment that cannot staff its row SHALL choose a lighter profile or MANAGED by an independent operator (ADR-045 small-organisation mode applies below 4 distinct persons).

| Profile | Distinct natural persons (minimum) | Recurring operator hours / month (averaged) | Hardware tokens in circulation | Scheduled ceremonies / year | Drills / year |
|---|---|---|---|---|---|
| CE-SINGLE (small-organisation mode) | 3: operator (SYS_ADMIN+USER_ADMIN acknowledged), 2 recipients; + 1 external party as OVERSIGHT (ADR-045) | ~12 (weekly backup rotation 1 h, updates/self-test review 1 h/week, quarterly RT-1 3 h, quarterly seal/access review 2 h) | 2 per person (primary + backup authenticator) + 3 custodian packs (IRK 2-of-3) | 1 combined ceremony day (key epochs, IRK attestation) | 1 tabletop + 1 restore drill |
| CE-HARDENED | 5: SYS_ADMIN, SECURITY_OFFICER (also H-MON admin), ≥ 2 recipients, 1 OVERSIGHT | ~24 | as above + Tang rotation | 1 combined + event-driven | 4 tabletops, RT-1 ×4, RT-3/RT-4 ×1 |
| EE-ONPREM | ≥ 8 (full SoD of `32-OPERATIONS.md` §4.2) | ~40 (0.25 FTE) | + HSM SO/user cards | 1–2 | as CE-HARDENED + failover of core |
| EE-HA / GOV-ONPREM | ≥ 12 incl. on-call rota | ≥ 160 (≥ 1 FTE platform team) | + HSM pair cards, DR-site custodians | 2 | monthly RT-1, twice-yearly RT-4 and failover drills |
| MANAGED (customer side) | ≥ 3 recipients/OVERSIGHT + 1 IRK custodian | ~4 | 2 per person + 1 custodian pack | Operator Statement co-signature monthly | 1 tabletop |

Custodian packs (`17-INFRASTRUCTURE.md` §6.6) keep each person to one custody token regardless of the number of k-of-n schemes they participate in. Kernel updates require no ceremony (ADR-040).

## 5. Packaging assessment

| Packaging | Where allowed | Threat implications | Decision |
|---|---|---|---|
| **Signed Debian packages (.deb)** | All hosts, all profiles | + Debian security updates and a native AppArmor/systemd integration. + Reproducible (build twice + diffoscope [B-SD-26]). + Simple audit. − APT trust must be scoped (`Signed-By`, not `trusted.gpg.d` [B-GL-41]). − maintainer scripts run as root, so they are reviewed and minimal | **Primary** (ADR-019). Maintainer scripts SHALL NOT fetch from the network and SHALL NOT copy directories of secrets |
| **OCI images** | Z-CORE in EE-HA, PRIVATE-CLOUD, MANAGED; never Z-INTAKE | + Immutable artifacts pinned by digest. − Container runtime logs (stdout capture) can collect sensitive output; registry pulls reveal deployment activity to the registry; shared kernel; base image supply chain. Images are built reproducibly from the same sources as the debs, signed, and logged (ADR-022) | Allowed for Z-CORE. Referenced by `@sha256:` digest only; `:latest` forbidden [B-GL-41]; distroless or Debian-slim bases; runtime log driver `none` or local-with-retention for trust-path containers |
| **Kubernetes** | Z-CORE only, in EE-HA/PRIVATE-CLOUD/MANAGED (ADR-024) | − cluster-admin = root on all workloads; etcd stores Secrets (must be encrypted with a customer HSM KMS plugin); kubelet/containerd/audit logs; service-mesh sidecars often log requests by default; CNI flow logs; multi-tenant clusters enable co-residency (THR-045); admission and operators run privileged. + Scheduling/HA | **Not assumed.** Allowed only as a dedicated cluster (no other workloads), with NetworkPolicy default-deny, Pod Security `restricted`, no mesh access logging, API audit policy excluding request bodies, and etcd encryption via the customer HSM. Z-INTAKE on K8s is forbidden |
| **VM appliance image** | CE-SINGLE (optional), MANAGED | + Fast install. − The image bakes in host keys and machine IDs unless regenerated; hypervisor trust | Allowed. First boot SHALL regenerate machine-id, SSH host keys, LUKS keys (re-encrypt), onion keys and TLS keys; the image contains **no** secrets (manifest-verified) |
| **Physical appliance** (vendor-supplied hardware) | EE/GOV option | + Known hardware, Secure Boot keys pre-provisioned. − Supply-chain interdiction risk; vendor-held firmware keys | Allowed with tamper-evident shipping, serial verification, and first-boot attestation against published golden PCRs |

## 6. Installer architecture

| Tool | Package | Role |
|---|---|---|
| `candor-bootstrap` | `candor-bootstrap_<ver>_all.deb` | Contains the TUF trusted root (`root.json`, threshold keys per ADR-022) and `candor-update` |
| `candor-update` | in bootstrap | TUF client. Z-INTAKE: fetches over the client-only update tor instance from the project onion mirror (C-33); Z-CORE: from the egress-restricted HTTPS mirror; any host: from an offline bundle (ADR-046(3)). Verifies threshold signatures + transparency inclusion proof, fetches the release's **Platform Manifest** packages (OS, tor, PostgreSQL) from the pinned snapshot mirror and checks each hash (ADR-040), and writes verified .debs into a local APT repository `/var/lib/candor/repo` signed by a host-local repo key generated at init |
| `candor-setup` | `candor-installer` | Interactive TUI for CE-SINGLE and CE-HARDENED (§8) |
| `candorctl` | `candor-admin-tools` (C-19 CLI) | Declarative plan/apply for all profiles; check; backup; restore; upgrade; rollback; selftest; secrets verify; support bundle |
| `candor-site.toml` | operator-authored | Declarative site description (§9.1) |

Design rules:
- Secrets are **generated on the host that owns them** and never transit the admin workstation, except BS-SECRETS exports, which are encrypted to the IRK (`19-BACKUPS-DR.md`). This is the class fix for B-SD-22.
- Every file copy in installer logic names explicit files. Copying a directory into a secret-bearing path is a lint error in CI (`installer-no-dir-copy`).

## 7. Hardened installation procedure (reference: CE-HARDENED)

### 7.1 Pre-install checklist (recorded by `candorctl site record-checklist`)

1. Hardware matches §4.2. TPM2 is present and cleared. Secure Boot is in setup mode or has the Debian keys. The firmware password is set. BMC is disabled or on N-OOB.
2. Uplink decision for H-INTAKE is recorded (`17-INFRASTRUCTURE.md` §4.10).
3. Tamper seals applied and photographed (`17-INFRASTRUCTURE.md` §6.4).
4. Two admins present; FIDO2 keys (2 per admin) available.
5. Offline media for BS-SECRETS (2×) and IRK tokens/paper (n shares) prepared.

### 7.2 Verify the Debian installation medium (on the admin workstation)

```bash
# Run on WS-ADM. Obtain the Debian ISO, SHA512SUMS and SHA512SUMS.sign from cdimage.debian.org (via Tor Browser or torsocks).
set -euo pipefail
cd ~/candor-install
sq cert import debian-cd-signing-key.asc            # key from debian.org, fingerprint cross-checked on 2 channels
sq verify --signer-file debian-cd-signing-key.asc --signature-file SHA512SUMS.sign SHA512SUMS
sha512sum --ignore-missing -c SHA512SUMS             # must print: debian-13.*-amd64-netinst.iso: OK
```

### 7.3 Base OS install and Candor bootstrap (on each host)

Install Debian 13 with the Candor preseed. It enforces a minimal install, LUKS2 on all volumes except the ESP, no swap, UEFI, `/var/lib/candor` as a separate LV, and only `standard` tasks deselected. Then, on the host console:

```bash
# Run as root on the fresh host. Values in <> are published in the Candor release notes
# AND in the transparency log AND on the project's onion site; compare all three before continuing.
set -euo pipefail
export CANDOR_VERSION="<VERSION>"
export CANDOR_BOOTSTRAP_SHA256="<SHA256 of candor-bootstrap_${CANDOR_VERSION}_all.deb>"
export CANDOR_RELEASE_FPR="<RELEASE KEY FINGERPRINT>"

apt-get update
apt-get install --no-install-recommends -y tor apt-transport-tor sq torsocks

# Bootstrap package obtained over tor (or copied from verified offline media, see §10)
torsocks curl --fail --proto '=http' -o /root/candor-bootstrap.deb \
  "http://<CANDOR_ONION_MIRROR>.onion/bootstrap/candor-bootstrap_${CANDOR_VERSION}_all.deb"
torsocks curl --fail --proto '=http' -o /root/candor-bootstrap.deb.sig \
  "http://<CANDOR_ONION_MIRROR>.onion/bootstrap/candor-bootstrap_${CANDOR_VERSION}_all.deb.sig"

echo "${CANDOR_BOOTSTRAP_SHA256}  /root/candor-bootstrap.deb" | sha256sum -c -
sq verify --signer-cert "${CANDOR_RELEASE_FPR}" --keyring /root/candor-release-keys.pgp \
  --signature-file /root/candor-bootstrap.deb.sig /root/candor-bootstrap.deb

apt-get install -y /root/candor-bootstrap.deb     # installs candor-update + TUF root.json

candor-update init --mirror "tor+http://<CANDOR_ONION_MIRROR>.onion/tuf" --channel stable
candor-update fetch                                 # verifies TUF threshold signatures + transparency proofs
# candor-update writes /etc/apt/sources.list.d/candor-local.sources with
#   URIs: file:/var/lib/candor/repo  Signed-By: /var/lib/candor-update/local-repo.pgp
apt-get update
candorctl platform converge --disable-upstream-sources   # ADR-040: replaces bootstrap-time packages (incl. tor)
                                                          # with the Platform Manifest set; removes Debian/Tor apt sources
candorctl platform verify                                 # installed set == Platform Manifest; security floor satisfied
```

On Z-CORE hosts, `candor-update init` takes `--mirror "https://<MIRROR_HOST>/tuf" --pin-cert <SHA256>` instead of the onion mirror (ADR-046(3)). The `apt-get install tor` in the bootstrap block uses the Debian installation medium only to reach the onion mirror once; the package is replaced by the pinned Tor Project build at `platform converge`.

### 7.4 Role installation

On H-MON first, then H-CORE, then H-INTAKE, as root:

```bash
set -euo pipefail
# H-MON
apt-get install -y candor-role-monitor
candorctl host init --role monitor --site /root/candor-site.toml
candorctl fde bind --mode tpm2+pin            # H-MON itself: U3
candorctl tang init                            # Tang server for U4 of the other hosts
```

```bash
set -euo pipefail
# H-CORE
apt-get install -y candor-role-core
candorctl host init --role core --site /root/candor-site.toml
candorctl fde bind --mode tpm2+tang --tang http://10.30.0.5:7500 --tang http://<OFFSITE_TANG>:7500 --sss-threshold 2
candorctl ssh enroll-admin --fido2            # touch + PIN; repeat for each admin key
candorctl onion init --kind rcp               # RCP-ONION profiles: restricted-discovery Desk/Admin onions, keys generated here
# RCP-LAN profiles instead: candorctl rcp-lan init --vlan <RCP_VLAN> (server cert on H-CORE; device certs at enrollment)
```

```bash
set -euo pipefail
# H-INTAKE
apt-get install -y candor-role-intake
candorctl host init --role intake --site /root/candor-site.toml
candorctl fde bind --mode tpm2+tang --tang http://10.30.0.5:7500 --tang http://<OFFSITE_TANG>:7500 --sss-threshold 2
candorctl onion init --kind source             # source onion key generated on this host only
candorctl relay pair --print-fingerprint       # compare fingerprint shown on H-CORE `candorctl relay pair --expect <fp>`
```

### 7.5 Post-install verification and secrets escrow

On WS-ADM, over the admin onions:

```bash
set -euo pipefail
candorctl check --all-hosts --fail-on advanced-unacknowledged    # configuration checker, §14
candorctl secrets verify --all-hosts                              # manifest equality, §15
candorctl selftest run --all --wait
candorctl platform verify --all-hosts                            # ADR-040 Platform Manifest + security floor
candorctl backup secrets-export --irk-shares 3 --irk-threshold 2 --out /media/candor-offline-A
candorctl backup secrets-export --irk-shares 3 --irk-threshold 2 --out /media/candor-offline-B --reuse-irk
candorctl site record-install --sign             # signed install record (versions, PCR golden values, manifest hashes)
```

The installation is complete only when all five report `OK` and the go-live gates of §8.1 are met. Any `FAIL` blocks the intake (fail closed, `34-PERFORMANCE-SCALABILITY.md` FAIL table).

## 8. Small-business simple installer (`candor-setup`, CE-SINGLE)

Goal: a non-specialist completes a secure installation in about 60 minutes with ≤ 10 questions. Secure defaults are pre-selected; nothing DANGEROUS is reachable from the wizard.

| Step | Question / action | Default | Refusal conditions |
|---|---|---|---|
| 1 | Hardware check (automatic) | — | Refuses: no UEFI; no VT-x/IOMMU; disks non-empty; cloud IMDS detected (suggests PRIVATE-CLOUD); other listening services. Warns: no TPM2 (falls back to U1 passphrase), non-ECC RAM |
| 2 | "Organization display name" (shown to sources) | — | — |
| 3 | "Can someone type a PIN on this machine after every power cut or reboot?" | Yes → U3 | No → U2 (TPM-only) with an explicit warning screen that must be typed-confirmed (ADVANCED) |
| 4 | "Plug in the 2 backup disks" → formats and encrypts (LUKS2) | nightly 02:15 local ± 30 min jitter | Refuses a single backup disk (one must be off-site) |
| 5 | Admin enrollment: 2 FIDO2 keys for the first admin; **a second, distinct admin or an external co-signer** (external counsel, board member, ombuds service) enrolled before go-live (§8.1) | — | Refuses without 2 keys; go-live blocked without the second person (RVW-C-09) |
| 6 | IRK shares: print 3 paper shares (2-of-3) or write 3 tokens | Paper QR + words | Requires re-entry of one share to prove legibility |
| 7 | First intake channel name | "General" | — |
| 8 | Invite ≥ 2 recipients (enrollment codes shown once, for Candor Desk); each enrols 2 hardware authenticators (primary + stored backup) | 2 | Refuses fewer than 2 (`min_recipients` 2, ADR-044(2)) |
| 9 | Notification relay (optional SMTP) | none (Desk shows a badge); if configured: constant-schedule daily digest at a fixed time, sent every day (ADR-038(2)) | Refuses: plaintext SMTP; relays without certificate pinning; event-driven notifications are not offered |
| 10 | Jurisdiction content pack (SLA calendars, rights notices; `25-COMPLIANCE.md`) | EU | — |
| 11 | Oversight and small-organisation check: "Who outside management can act as OVERSIGHT?" | — | If fewer than 4 distinct persons are enrolled, small-organisation mode is set (ADR-045): at least one **external** party SHALL hold OVERSIGHT; refuses to finish otherwise |

Output:
- the onion address;
- a printable "publish this" sheet for the Clearnet Information Site (C-37) with Onion-Location and guidance text, and the **first-contact publication checklist** (§8.2);
- the self-test result;
- the next steps.

Secure defaults applied without questions: VM separation (ADR-046(6)); Tier W + Tier V enabled; PoW on; vanguards per `16-TOR-I2P.md`; no clearnet intake (C-38 off); Recovery Quorum off (CE; GOV defaults differ, ADR-044(3)); telemetry off (ADR-023); notifications off or constant-schedule daily digest (ADR-038(2)); relay imports at fixed slots (4×/day default, ADR-038(1)); `min_recipients` 2; no access logs; attachment limits per `34-PERFORMANCE-SCALABILITY.md`; automatic security updates on with a staged Candor upgrade window (Sun 03:00 ± 60 min) and the security floor enforced (ADR-040).

### 8.1 Go-live gates (all installers and `candorctl site go-live`)

Intake stays closed (`candorctl site go-live` refuses) until:
1. `candorctl check`, `secrets verify`, `selftest` and `platform verify` report OK (§7.5).
2. At least two distinct natural persons hold admin/co-approver roles, or one admin plus an enrolled external co-signer (RVW-C-09). Distinctness is checked against the authenticator attestation (AAGUID and, where exposed, serial) as specified in `15-AUTHENTICATION-AUTHORIZATION.md`.
3. Small-organisation mode (ADR-045), set automatically when fewer than 4 distinct persons are enrolled: an external OVERSIGHT holder is enrolled; the Admin UI and the published Operator Statement display "Reduced separation of duties"; the dual controls that degrade to single control with notice are listed in `32-OPERATIONS.md` §4.5.
4. The non-identification policy is confirmed (HUM-009).
5. The first Operator Statement (ADR-035(2)) is signed and published; for EE/GOV/MANAGED, ≥ 2 External Watchers (≥ 1 outside the operator's jurisdiction) are registered (ADR-035(1)).
6. Where Z-CORE runs on virtualization or storage Candor cannot inspect, the Erasure Key Vault exclusion attestation is recorded (`17-INFRASTRUCTURE.md` INFRA-037).
7. INDEPENDENT channels: Triage Set members' devices have recorded independent-custody status (ADR-043); otherwise the channel cannot be enabled without a DANGEROUS approval (dual approval incl. OVERSIGHT, disclosed in the configuration digest).
8. ANONYMOUS channels publish role labels only; publishing a member's personal name in a channel descriptor is DANGEROUS (`14-CASE-MANAGEMENT.md` ROUTE-002; `32-OPERATIONS.md` §7).
9. The first-contact publication checklist (§8.2) is recorded, including the C-37 hosting record.
10. MANAGED: the customer-held attestation verifier is registered and has verified at least one quote, and the customer-held audit export key is enrolled (ADR-047(10); `17-INFRASTRUCTURE.md` INFRA-046).
11. The intake has received a Key Directory snapshot no older than 7 days by its independent time floor (ADR-047(4)); otherwise sealing is refused anyway.

### 8.2 First-contact publication checklist (`05-SOURCE-OPSEC.md` §8.14, SOPS-055; RVW-B-17)

Printed by every installer and recorded (tick list, signed by the channel owner) by `candorctl site record-publication`:

| # | Item |
|---|---|
| 1 | Publish the onion address **offline** first: posters, printed cards, payslip inserts, QR codes on printed material |
| 2 | On intranets, publish it only as **non-hyperlinked** text with "Don't open this at work. Copy it into Tor Browser at home." Never as a clickable link, never in e-mail signatures or tracked newsletters |
| 3 | C-37 shows GC-43 and the GC-04/GC-05 stop line in its first viewport (`05-SOURCE-OPSEC.md`); verified by the `c37-check` snapshot (`17-INFRASTRUCTURE.md` INFRA-042) |
| 4 | C-37 hosting per `17-INFRASTRUCTURE.md` §4.11: no third-party CDN, proxy, analytics or embedded resources; logs off or ≤ 24 h aggregate; outside the organisation's web stack for D1/D2 tenants and INDEPENDENT channels. The project's neutral multi-organisation directory domain is an option |
| 5 | C-37 does not host the Source App; it links to the project distribution over Tor (ADR-041) |
| 6 | Channel descriptors of ANONYMOUS channels show role labels only; personal names are DANGEROUS (§8.1 gate 8) |

The C-37 hosting record (item 4) is re-attested in the quarterly review (`32-OPERATIONS.md`).

## 9. Infrastructure as Code

### 9.1 Declarative site file (`candor-site.toml`, excerpt)

```toml
[site]
profile = "CE-HARDENED"
name = "example-ngo"
jurisdiction_pack = "EU"

[hosts.intake]
role = "intake"
nic.ext = "ext0"; nic.relay = "relay0"; nic.mgmt = "mgmt0"
relay_addr = "10.20.0.2/29"; mgmt_addr = "10.30.0.2/28"
fde = "tpm2+tang"
uplink_independent = true           # 17 §4.10; false requires acknowledgement id

[hosts.core]
role = "core"
relay_addr = "10.20.0.3/29"; mgmt_addr = "10.30.0.3/28"; bak_addr = "10.50.0.2/29"
fde = "tpm2+tang"

[hosts.monitor]
role = "monitor"
mgmt_addr = "10.30.0.5/28"
tang = true

[backup]
target = "s3+objectlock://10.50.0.3:443/candor"   # write-only credentials generated on H-BAK
ekv_exclusion_attestation = "attest-2026-10-01.sig"   # INFRA-037; required when core runs on uninspectable virtualization
schedule = "02:15"; jitter_minutes = 30
wal_archive_timeout_s = 900

[acknowledgements]                   # ADVANCED settings require an entry here (config checker)
# "fde.u2.tpm_only" = { by = ["admin-a"], reason = "...", date = "2026-10-01" }
```

Rules: the site file SHALL contain no secrets; `candorctl plan` refuses to run if secret-like strings are detected (entropy + pattern scan).

### 9.2 PRIVATE-CLOUD modules (OpenTofu/Terraform)

- Candor ships signed modules that create the VPC, subnets, security groups mirroring F1–F15, sole-tenant/confidential instances, the Object Lock bucket in a separate account, and SCPs (deny snapshot on intake volumes, deny public ACLs, deny IMDSv1).
- Terraform state SHALL NOT contain Candor secrets. The modules create no keys; hosts generate keys at first boot.
- The state backend is encrypted and access-restricted, and MAY use provider KMS (non-sensitive).
- `candorctl cloud audit` runs Prowler/ScoutSuite-class checks (INC-59) after `apply`.

### 9.3 GitOps (EE-HA / MANAGED Z-CORE on K8s)

- Manifests are rendered by `candorctl render k8s` with images pinned by digest.
- Changes are applied through a GitOps controller that requires a manual approval per change: a PR reviewed by a second person (CoverDrop practice [B-GL-30]).
- Secrets are never in Git. They are created in-cluster by the Candor operator from HSM-backed material.
- Admission policy rejects unsigned images or images not in the transparency log (ADR-022).

## 10. Offline installation (GOV, air-gapped sites, AIRGAP-RCP stations)

```bash
# On a connected build/transfer workstation (not a Candor host)
set -euo pipefail
candor-update bundle create --channel stable --version "<VERSION>" \
  --include-debian-deps trixie --out /media/transfer/candor-bundle-<VERSION>.tar
# Output includes: TUF metadata snapshot, targets, transparency inclusion proofs, Debian packages + signed Release files
sha256sum /media/transfer/candor-bundle-<VERSION>.tar > /media/transfer/candor-bundle-<VERSION>.tar.sha256
```

```bash
# On the offline host (after cross-domain transfer procedure)
set -euo pipefail
apt-get install -y /media/transfer/candor-bootstrap_<VERSION>_all.deb   # bootstrap verified per §7.3 (sig + hash)
candor-update bundle verify /media/transfer/candor-bundle-<VERSION>.tar   # TUF threshold + inclusion proofs + freshness policy
candor-update bundle import /media/transfer/candor-bundle-<VERSION>.tar
apt-get update && apt-get install -y candor-role-<role>
```

Freshness: TUF timestamp expiry is normally short. In offline mode `candor-update` accepts expired timestamp metadata only if:
- the bundle's snapshot is ≤ 30 days old, as configurable by GOV policy (`update.offline.max_age_days`, ADVANCED above 30);
- the root/targets signatures are valid;
- the inclusion proofs verify against a signed log checkpoint included in the bundle.

## 11. Upgrade procedure

### 11.1 Policy

- Trust-path artifacts are identical for all customers (ADR-022).
- Rollout is staged in time, never selected per customer. A release is offered to all instances at once. Operators choose their window. `candor-update` applies a random delay of 0–72 h for automatic mode, so that update-fetch timing does not become a fleet-wide fingerprint.
- Security releases MAY set `urgent=true` → window 0–6 h, counted from the end of the release's signing cooling period (≥ 2 h with ≥ 2 signers from ≥ 2 organisations for emergency releases, ADR-040; `33-RELEASE-UPDATE-SECURITY.md`).
- **Security floor** (ADR-040): when a release raises `min_secure_version`, trust-path units below the floor refuse to start (`17-INFRASTRUCTURE.md` INFRA-036). Neither local policy nor the EE Fleet Manager can defer an instance below the floor (ADR-045); the operator's only choice is when, within the window, to install.
- Pre-upgrade backup is mandatory.

### 11.2 Operator commands (all profiles except EE-HA rolling)

```bash
set -euo pipefail
candorctl upgrade plan                         # shows target version, TUF-verified targets, transparency proofs,
                                               # schema migrations (expand/contract), rollback eligibility, restarts
candorctl check --all-hosts                    # must be OK before upgrading
candorctl backup create --set core,intake --label "pre-upgrade-<VERSION>" --wait
candorctl backup verify --label "pre-upgrade-<VERSION>"
candorctl upgrade apply --version "<VERSION>" --hosts monitor,core,intake
candorctl selftest run --all --wait            # must be OK within 15 min, else automatic rollback (§12)
candorctl platform verify --all-hosts                  # ADR-040: installed set == Platform Manifest, >= security floor
candorctl attest update-golden --verified-update "<VERSION>"  # re-records PCR 4/9 golden values only after a manifest-verified update
```

### 11.3 EE-HA rolling upgrade

```bash
set -euo pipefail
candorctl upgrade plan --rolling
candorctl backup create --set core,intake --label "pre-upgrade-<VERSION>" --wait
candorctl upgrade apply --rolling --intake-switchover at-next-import-slot --version "<VERSION>"
# Sequence: core services (expand migration) -> passive intake upgraded (not serving)
# -> planned switchover at the start of an import slot (stop-transfer-start, §4.4 FAILOVER; no DB replication, ADR-046(1)):
#    active stops accepting; C-09 pulls pending envelopes; C-09 pulls the encrypted store export and restores it on the passive;
#    old active fenced; passive publishes descriptors (intake unavailability <= 10 min)
# -> upgrade old active (now passive) -> contract migration after all nodes report the new version.
candorctl selftest run --all --wait
```

### 11.4 Debian major-version upgrades (e.g., 13 → 14)

In-place `dist-upgrade` of Candor hosts is **not supported**. Lesson: SecureDrop's automated Focal→Noble migration needed a phased rollout and was later disabled [B-SD-02, B-SD-03]. The procedure is **rebuild and restore**:
1. Build a new host with the new Debian.
2. Restore the role from BS-* sets (§13).
3. Verify.
4. Switch the relay pairing.
5. Crypto-erase the old host (`17-INFRASTRUCTURE.md` §6.7).

For H-INTAKE this keeps the onion address, because the key is restored from BS-SECRETS.

## 12. Rollback

- Automatic: if the post-upgrade self-test is not `OK` within 15 min, `candorctl` reinstalls the previous version from the local repo cache (the last 2 versions are retained) and restores the pre-upgrade DB snapshot **only if** the schema migration was not expand-compatible. Otherwise it only downgrades binaries.
- Manual:

```bash
set -euo pipefail
candorctl rollback plan                          # shows eligible version (N-1 only) and data impact
candorctl rollback apply --to previous --confirm "<VERSION-1>"
candorctl selftest run --all --wait
```

- Rollback is refused when the target version is marked `revoked` in TUF targets metadata (a security release revokes vulnerable predecessors). The operator then rolls forward.
- In EE and GOV, rollback requires a second admin's FIDO2 approval (`--co-sign`).
- DB migrations SHALL follow expand/contract so that N-1 binaries run against the N schema until contract.

## 13. Backup and recovery procedures (operator commands)

Policy, formats and DR playbooks are in `19-BACKUPS-DR.md`. Command reference:

```bash
set -euo pipefail
candorctl backup status                          # last success per set, age, WORM retention, next run (no sizes finer than buckets)
candorctl backup create --set core --wait        # ad hoc
candorctl backup verify --latest --deep          # hash chain + manifest signature + WORM lock present; no decryption
candorctl backup offline-rotate --out /media/candor-offline-B   # weekly offline copy
```

Restore a lost H-INTAKE onto replacement hardware (keeps the onion address):

```bash
set -euo pipefail
# New host prepared per §7.3; role package installed; NOT yet initialised with new keys
candorctl host init --role intake --site /root/candor-site.toml --restore
candorctl restore secrets --set BS-SECRETS --from /media/candor-offline-A --irk-quorum   # prompts for 2 of 3 IRK shares
candorctl restore data --set BS-INTAKE --latest --apply-deletion-list   # BS-INTAKE = source_account, deletion_tombstone, intake_meta only (19 §3)
candorctl fde bind --mode tpm2+tang --tang http://10.30.0.5:7500 --tang http://<OFFSITE_TANG>:7500 --sss-threshold 2
candorctl relay pair --print-fingerprint
candorctl relay push-deletion-list --wait        # C-09 pushes the newest Z-CORE replica (ADR-047(9)); intake merges and applies it; intake stays closed until verified
candorctl secrets verify --host intake
candorctl selftest run --host intake --wait
```

Restore H-CORE including the Erasure Key Vault (the erasure log is applied before any service starts, ADR-044(4)):

```bash
set -euo pipefail
candorctl host init --role core --site /root/candor-site.toml --restore
candorctl restore secrets --set BS-SECRETS --from /media/candor-offline-A --irk-quorum --items ekv-vmk,rcp-onion
candorctl restore data --set BS-CORE --latest --wal-until "<T0 or latest>"
candorctl restore data --set BS-ERASURE --paired-with BS-CORE --apply-erasure-log   # destroys vault keys of every case in the signed erasure log
candorctl ekv verify --report-missing                                             # lists cases needing Desk re-wrap (19 §11.2)
candorctl ekv rewrap open --cases @missing --window 7d                            # dual approval; holders' Desks re-create wraps and K_meta fields (ADR-047(7))
candorctl selftest run --host core --wait
```

## 14. Configuration checker (`candorctl check`)

| Aspect | Specification |
|---|---|
| When | Pre-install (hardware), post-install, pre-upgrade, daily via C-25, and on every configuration change (as a dry run before apply) |
| Inputs | Effective config of every host (Candor config, torrc, nftables, sysctl, systemd units, AppArmor status, FDE bindings, package list, K8s manifests if any), `candor-site.toml`, acknowledgements |
| Rules | Every control in the CFG table (`32-OPERATIONS.md` §7) plus the `17-INFRASTRUCTURE.md` baselines. Each rule has: `id`, CFG class (SAFE / ADVANCED / DANGEROUS / FIXED only; the former label "WEAKENING" maps to DANGEROUS, ADR-046(6)), expected value, check command, remediation text. **Attested rules** (`32-OPERATIONS.md` CFG-008) cover knobs the guest cannot observe (hypervisor/SAN snapshots, image-level backups of Z-CORE, intake port mirroring, BMC console logging): the rule checks that a current signed attestation exists and reports its absence as DANGEROUS |
| Output | Human table + JSON (`--json`), without secrets or source-related data. Exit codes: 0 all SAFE DEFAULT or acknowledged ADVANCED; 10 ADVANCED unacknowledged; 20 DANGEROUS without a valid dual-approval record; 30 baseline failure (e.g., egress open, swap on, secret misplaced) |
| Enforcement | Exit ≥ 20 blocks upgrades, and blocks intake start at boot (fail closed) except for the documented DANGEROUS settings whose dual approval is recorded and source-disclosed |
| Tamper-resistance | The rule set ships in the signed package. Local rule overrides are impossible, only acknowledgements, which are signed with an admin FIDO2 key and logged as SECURITY audit events |

Example:

```bash
candorctl check --all-hosts
# HOST    RULE                          CLASS     STATUS  DETAIL
# intake  egress.default_deny           baseline  OK
# intake  fde.unlock_mode               ADVANCED  ACK     U2 tpm2-only acknowledged by admin-a,admin-b 2026-10-01
# core    notify.content_free           SAFE      OK
# core    backup.worm_retention_days    SAFE      OK      35
# exit=0
```

## 15. Secret Placement Manifest (ADR-028)

### 15.1 Format

The manifest ships in the role package at `/usr/share/candor/manifests/<role>.yaml` and is signed as part of the package. Feature flags select entries.

```yaml
manifest_version: 1
role: intake
secrets:
  - id: onion.source.hs_ed25519_secret_key
    path: /var/lib/tor/candor-source/hs_ed25519_secret_key
    owner: _tor-candor-intake
    mode: "0600"
    provenance: generated_on_host   # or: restored_from_BS-SECRETS
    backup_set: BS-SECRETS
    flags: [always]
  - id: onion.ssh.hs_ed25519_secret_key
    path: /var/lib/tor/candor-ssh/hs_ed25519_secret_key
    owner: debian-tor
    mode: "0600"
    provenance: generated_on_host
    backup_set: BS-SECRETS
    flags: [always]
  - id: relay.server_tls_key
    path: /var/lib/candor/relay/tls.key
    owner: candor-relay
    mode: "0600"
    provenance: generated_on_host
    backup_set: none                # re-paired on restore
    flags: [always]
  - id: intake.routing_key
    path: /var/lib/candor/intake/routing_key.sealed   # X-Wing private key, TPM-sealed where available
    owner: candor-istore
    mode: "0400"
    provenance: generated_on_host
    backup_set: BS-SECRETS
    flags: [always]
  - id: intake.argon2_deployment_salt
    path: /var/lib/candor/intake/salt.bin
    owner: candor-sealer
    mode: "0400"
    provenance: generated_on_host
    backup_set: BS-SECRETS
    flags: [always]
  # The client-only update/time tor instance (_tor-candor-update) holds no onion keys; its
  # DataDirectory contains only consensus/guard state and is listed as non-secret state.
scan:
  roots: [/, ]
  exclude: [/proc, /sys, /dev, /run/user]
  patterns:                         # any match not listed above = violation
    - pem_private_key
    - openssh_private_key
    - tor_hs_secret_key             # "== ed25519v1-secret: type0 =="
    - tor_client_auth_private       # "*.auth_private" content "descriptor:x25519:"
    - age_or_hpke_identity
    - openpgp_secret_packet
    - jwk_private
    - pkcs12
forbidden_everywhere:
  - staff.private_key               # ADR-007: never on servers
  - case_key_plaintext
  - epoch_private_key_plaintext
  - irk_share                       # never on any online host
```

### 15.2 Per-role summary (normative; complements `17-INFRASTRUCTURE.md` §3)

| Secret | H-INTAKE (+ H-INTAKE-B in EE-HA/GOV) | H-CORE | H-MON | H-BAK | WS-ADM | WS-RCP | Offline |
|---|---|---|---|---|---|---|---|
| Source onion key | ✔ (both intake hosts in EE-HA/GOV, ADR-032) | — | — | — | — | — | BS-SECRETS |
| Standby onion key (`16-TOR-I2P.md` NET-020) | — | — | — | — | — | — | ✔ only (BS-SECRETS) |
| Intake Routing Key (private) | ✔ (TPM-sealed where available) | — | — | — | — | — | BS-SECRETS |
| SSH-onion keys (remote sites only) | own host | own | own | own | — | — | BS-SECRETS |
| Admin-onion / RCP-ONION client-auth private keys | — | — | — | — | ✔ admin (hardware-sealed) | ✔ Desk (hardware-wrapped) | — |
| RCP-ONION onion keys (Desk API, Admin API) | — | ✔ (or Z-CORE edge host) | — | — | — | — | BS-SECRETS |
| RCP-LAN server key / device client certificates | — | server | — | — | admin cert | device cert | re-issue |
| Relay mTLS server / client key | server | client | — | — | — | — | re-pair |
| C-25 agent mTLS client keys / collector server key | agent | agent | collector | agent | — | — | re-pair |
| Intake heartbeat/fencing credential (EE-HA/GOV; replaces the v1.0 intake-replication TLS key, ADR-046(1)) | ✔ | — | — | — | — | — | re-pair |
| Erasure Key Vault (ADR-033(3)) | — | ✔ (host-local file on a dedicated volume, never a DB schema; EE-HA: also the standby/DR core, ADR-044(4)) | — | — | — | — | BS-ERASURE only (≤ 14 days) |
| Erasure Key Vault volume key (VMK) | — | ✔ (physical TPM or HSM; CE-SINGLE vTPM) | — | — | — | — | escrow copy in BS-SECRETS (`19-BACKUPS-DR.md` §3) |
| Audit / key-directory signing key | — | ✔ (TPM/HSM) | — | — | — | — | HSM backup / BS-SECRETS |
| Backup-agent signing key | intake set signer | ✔ | — | — | — | — | re-generate |
| Backup KEK public keys (BK-DATA, BK-SECRETS) | public | public | — | — | — | — | — |
| Backup KEK private / IRK shares | — | — | — | — | — | — | ✔ only |
| WORM store root credentials | — | — | — | ✔ | — | — | sealed envelope |
| Tang keys | — | — | ✔ | — | — | — | off-site Tang |
| Staff private keys, member epoch private keys, case keys | — | — | — | — | — | ✔ (case keys also in the hardware-sealed Desk cache, ADR-047(7)) | (Quorum if enabled) |

H-ALERT (`alert-relay`, r3) holds only its alert-pull mTLS client key and alert transport credentials (manifest role `alert-relay`); it holds no onion key, no collector key and nothing listed for H-MON. H-MON holds no alert transport credentials any more.

## 16. Requirements

| ID | Requirement | Evidence | Threats | Component | Verification |
|---|---|---|---|---|---|
| DEP-001 | Candor SHALL support exactly the eight deployment profiles of ADR-024, each documented with the nine attributes of §4. | ADR-024 | THR-035 | C-19 | INSP: docs completeness check in CI (`profile-doc-lint`) |
| DEP-002 | Z-INTAKE SHALL run on dedicated hosts or dedicated VMs in every profile, and SHALL NOT run on Kubernetes or on hosts shared with non-Candor workloads. | ADR-024; REQ-H-34 | THR-045, THR-014 | C-05..C-08 | TST: `candorctl check` rule `intake.dedicated`; INSP: IaC plan |
| DEP-003 | Kubernetes SHALL be permitted only for Z-CORE in EE-HA, PRIVATE-CLOUD and MANAGED, as a dedicated cluster with NetworkPolicy default-deny, Pod Security `restricted`, no mesh access logs, API audit without request bodies, and etcd encryption via a customer-controlled KMS/HSM. | ADR-024; INC-60 | THR-016, THR-045, THR-030 | C-10, C-12, C-39 | TST: rendered-manifest policy tests (conftest); INSP: cluster audit |
| DEP-004 | OCI images SHALL be referenced only by digest, built reproducibly from the same sources as the .debs, signed and transparency-logged. `:latest` tags SHALL be rejected. | B-GL-41; ADR-022 | THR-024, THR-025 | C-31, C-33 | TST: admission-policy test rejects tag-only and unsigned images |
| DEP-005 | Debian maintainer scripts in Candor packages SHALL NOT perform network access or copy directories into secret-bearing paths. | B-SD-22 | THR-013, THR-024 | C-33 | TST: CI lint `installer-no-dir-copy`; piuparts run in netns without network |
| DEP-006 | The installer SHALL generate each secret on the host that owns it. Secrets SHALL NOT transit the admin workstation except as IRK-encrypted BS-SECRETS exports. | B-SD-22; ADR-028 | THR-013, THR-044 | C-19 | TST: install trace shows no secret material in WS-ADM filesystem snapshots (canary scan) |
| DEP-007 | Bootstrap SHALL verify the bootstrap package by pinned release-key signature and by hash compared across ≥ 2 independent publication channels. APT keys SHALL be scoped with `Signed-By` and never placed in `trusted.gpg.d`. | B-GL-05; B-GL-41; REQ-H-15 | THR-024, THR-025 | C-33, C-32 | TST: tampered bootstrap is rejected; INSP: no files in `/etc/apt/trusted.gpg.d/` from Candor |
| DEP-008 | Candor packages SHALL be installed only from a local repository populated by `candor-update` after TUF threshold and transparency-inclusion verification. | ADR-022; B-CR-45 | THR-025 | C-33 | TST: TUF test vectors (rollback, freeze, mix-and-match, threshold); inclusion-proof failure blocks import |
| DEP-009 | Automatic update fetches SHALL use a uniformly random delay of 0–72 h (0–6 h for urgent) and SHALL NOT send instance identifiers or onion addresses. | ADR-022; ADR-023 | THR-025, THR-036 | C-33 | TST: request capture shows no instance-identifying fields; delay-distribution test |
| DEP-010 | The simple installer (`candor-setup`) SHALL apply the secure defaults of §8 and SHALL NOT offer any DANGEROUS setting. | R1 do-not-copy #4; B-SD-08 | THR-035 | C-19 | DEMO: usability test with non-specialist admins (completion ≤ 90 min, 0 unsafe configs); TST: wizard option inventory vs CFG table |
| DEP-011 | The simple installer SHALL refuse to proceed with fewer than two admin FIDO2 keys, fewer than two backup media, or fewer than two recipients (each with two hardware authenticators), and SHALL block go-live until a second distinct admin or an external co-signer is enrolled. | ADR-013; ADR-044(2); ADR-045; B-SD-08; RVW-C-09 | THR-042, THR-022, THR-139 | C-19 | TST: wizard negative tests; go-live refused with a single enrolled person |
| DEP-012 | The installer SHALL refuse installation when a cloud metadata service is detected under a non-cloud profile, or when unrelated listening services exist on the target. | INC-59; REQ-H-34 | THR-030, THR-035 | C-19 | TST: installer in a cloud VM without PRIVATE-CLOUD profile → refusal |
| DEP-013 | Every profile SHALL enforce FDE with the default unlock mode of §3. Selecting another mode SHALL require the CFG class acknowledgement defined in `32-OPERATIONS.md`. | B-SD-13; ADR-024 | THR-031 | C-39 | TST: `candorctl check` rule `fde.unlock_mode` |
| DEP-014 | The site file and IaC state SHALL contain no secrets. `candorctl plan` SHALL refuse input with secret-like content. | INC-59; B-SD-22 | THR-013 | C-19 | TST: planted high-entropy key in the site file → refusal |
| DEP-015 | PRIVATE-CLOUD IaC SHALL create: a dedicated account/project, SCPs denying snapshots of intake volumes, public ACLs and IMDSv1; an Object Lock bucket in a separate account; and no IAM role on intake VMs. | INC-59; ADR-024 | THR-030, THR-017 | C-39, C-27 | TST: IaC unit tests (plan JSON assertions); `candorctl cloud audit` |
| DEP-016 | GitOps changes to Z-CORE on K8s SHALL require approval by a second person, and secrets SHALL NOT be stored in Git. | B-GL-30 | THR-018, THR-024 | C-10 | INSP: repository protection rules; TST: secret scanner on the GitOps repo |
| DEP-017 | Offline bundles SHALL carry TUF metadata, targets, inclusion proofs and a signed log checkpoint, and SHALL be accepted only within `update.offline.max_age_days` (default 30). | ADR-022; INC-52 | THR-025 | C-33 | TST: bundle aged 31 days rejected; tampered target rejected |
| DEP-018 | Upgrades SHALL require a successful pre-upgrade backup and configuration check, and SHALL roll back automatically if the post-upgrade self-test fails within 15 min. | B-SD-02 (phased upgrade lesson) | THR-042, THR-025 | C-19, C-25 | TST: induced self-test failure → automatic rollback in the upgrade test suite |
| DEP-019 | Schema migrations SHALL follow expand/contract so that version N-1 runs against the N schema until contract. | Design | — | C-12 | TST: CI runs the N-1 binary test suite against the N schema |
| DEP-020 | Rollback SHALL be limited to N-1, SHALL be refused for TUF-revoked versions, and SHALL require a second admin's approval in EE and GOV. | ADR-022 | THR-025, THR-018 | C-19, C-33 | TST: rollback to a revoked version refused; co-sign required in EE mode |
| DEP-021 | Debian major-version transitions SHALL use rebuild-and-restore. In-place dist-upgrade of Candor hosts SHALL be blocked by the config checker. | B-SD-02; B-SD-03 | THR-042 | C-19 | TST: dist-upgrade detection rule; DEMO: 13→14 rehearsal |
| DEP-022 | VM appliance images SHALL contain no secrets and SHALL regenerate machine-id, host keys, LUKS keys, onion keys and TLS keys at first boot. | B-SD-22; ADR-028 | THR-044, THR-013 | C-39 | TST: two instances from the same image have disjoint key fingerprints; manifest scan of the image |
| DEP-023 | Each host role SHALL ship a signed Secret Placement Manifest (§15). Post-deploy verification SHALL fail the deploy on any unexpected or missing secret for any feature-flag combination. | ADR-028; B-SD-22 | THR-013, THR-044 | C-25, C-19 | TST: CI matrix over all flag combinations; planted-key tests |
| DEP-024 | Items marked `forbidden_everywhere` (staff private keys, plaintext case keys and member epoch keys, IRK shares) SHALL cause a critical alert and intake shutdown if found on any online host. | ADR-007; ADR-013 | THR-013, THR-018 | C-25 | TST: planted forbidden item → alert + intake closed |
| DEP-025 | The configuration checker SHALL evaluate every CFG-classified control and the `17-INFRASTRUCTURE.md` baselines, with exit codes per §14, and SHALL block intake start on exit ≥ 20 unless a valid dual-approval record exists. | THR-035; B-GL-04 | THR-035 | C-19, C-25 | TST: rule-coverage test (every CFG row has a checker rule); exit-code tests |
| DEP-026 | Configuration-checker output SHALL contain no secrets, onion addresses of source channels, or source-related data. | ADR-016; INC-56 | THR-016 | C-19 | TST: canary scan of `--json` output |
| DEP-027 | MANAGED SHALL provide per-customer dedicated intake host/VM, onion key, Z-CORE, database, backup set and backup KEK, with no cross-customer network routes. | ADR-021; B-GL-37 (CVE-2026-46648 cross-tenant) | THR-045, THR-027 | C-05, C-12, C-27 | TST: cross-customer reachability tests; INSP: vendor architecture audit (AUD) |
| DEP-028 | MANAGED vendor administrative access SHALL use two-person SSH certificate issuance and SHALL be recorded in a customer-visible access log. | INC-56; INC-69 | THR-027, THR-018 | C-34, C-36 | TST: single-person issuance refused; DEMO: customer views log |
| DEP-029 | MANAGED customers SHALL be able to export BS-SECRETS and data to self-host with the same onion address. | Design; THR-026 | THR-026 | C-19 | DEMO: export/import exercise |
| DEP-030 | AIRGAP-RCP SHALL enforce that WS-SYNC holds no decryption keys, and the self-test SHALL warn when no import has occurred for 5 days and alert at 7 days (epoch window and member epoch key pre-publication, ADR-030). | ADR-008; ADR-030; B-SD-04 | THR-013, THR-023 | C-15, C-18, C-25 | TST: manifest check on WS-SYNC; timer test |
| DEP-031 | Enterprise hypervisor-level or agent-based backup tools SHALL NOT image Z-INTAKE or Z-CORE volumes, and in particular not the Erasure Key Vault volume or vTPM state. The config checker SHALL detect in-guest backup agents and SHALL require the signed exclusion attestation of `17-INFRASTRUCTURE.md` INFRA-037 for guest-invisible mechanisms (reported as DANGEROUS when absent). | INC-55; ADR-044(4); RVW-C-06 | THR-017, THR-015, THR-130 | C-27 | TST: agent-detection rule; checker rule `ekv.backup_exclusion_attested`; INSP: customer attestation |
| DEP-032 | The staff access path SHALL default to RCP-ONION in CE-SINGLE, CE-HARDENED and MANAGED, and to RCP-LAN in EE-ONPREM, EE-HA, GOV-ONPREM and PRIVATE-CLOUD (`06-SYSTEM-ARCHITECTURE.md` §8.3), except that devices of INDEPENDENT-channel members SHALL default to RCP-ONION (or the padded WireGuard variant) in every profile. RCP-LAN deployments SHALL isolate the recipient VLAN from per-flow logging by general network monitoring. | ADR-007; ADR-024; ADR-043; RVW-C-20 | THR-018, THR-022, THR-020, THR-129 | C-10, C-15 | TST: config checker rule `rcp.path`; INSP: network monitoring configuration |
| DEP-033 | In EE-HA and GOV-ONPREM, the source onion key SHALL exist on at most the two intake hosts of the active/passive pair (plus BS-SECRETS offline). Only the active host's tor SHALL publish descriptors, and promotion SHALL require successful fencing of the old active. The two hosts SHALL be shared-nothing (ADR-046(1)). | ADR-032 | THR-044, THR-032 | C-05, C-25 | TST: manifest verification per role; failover test asserts that the old active is fenced before the passive publishes |
| DEP-034 | Physical appliances SHALL ship with tamper-evident packaging and serial records, and SHALL attest first boot against published golden PCR values. | INC-50; Knowledge (unverified) | THR-024, THR-031 | C-39 | DEMO: first-boot attestation; INSP: shipping record |
| DEP-035 | The install record (versions, golden PCRs, manifest hashes, checklist) SHALL be signed by two admins and stored in Z-ADM. | B-SD-04 | THR-018, THR-035 | C-19 | INSP: record present and verifiable (`candorctl site verify-record`) |
| DEP-036 | Operational documentation SHALL provide copy-pasteable, `set -euo pipefail` command blocks for install, upgrade, rollback, backup and restore, tested in CI against a reference lab. | B-SD-08 (burden lesson) | THR-035 | C-19 | TST: docs-as-tests job executes every command block in the lab |
| DEP-037 | The Operational Load Budget of §4.9 SHALL be maintained per profile and validated in a 6-month operational pilot with at least one small organisation before 1.0; profile texts SHALL NOT claim lower effort than the budget. | RVW-C-17; B-SD-08 | THR-035, THR-042 | C-19 | DEMO: pilot report with measured hours per duty; INSP: profile texts vs budget |
| DEP-038 | `candorctl site go-live` SHALL keep intake closed until every gate of §8.1 is satisfied. | RVW-C-09; ADR-035; ADR-043; ADR-044(4); ADR-045 | THR-139, THR-135, THR-126, THR-130 | C-19, C-25 | TST: each gate removed in turn → go-live refused with the named gate |
| DEP-039 | When fewer than 4 distinct natural persons are enrolled, the installer and Admin API SHALL set small-organisation mode, require an external OVERSIGHT holder, and display "Reduced separation of duties" to admins and in the published Operator Statement. | ADR-045; RVW-C-09 | THR-139, THR-018 | C-19, C-22, C-14 | TST: enrolment of 3 persons → mode set, banner present, statement text present; removing the external OVERSIGHT holder closes intake |
| DEP-040 | Install, restore and upgrade procedures SHALL end with `candorctl platform verify` (installed packages = Platform Manifest; version ≥ security floor) on every host, and SHALL disable upstream apt sources. | ADR-040; RVW-A-12 | THR-024, THR-025, THR-137 | C-19, C-33 | TST: install lab asserts no upstream apt sources remain and platform verify passes; an off-manifest package blocks go-live |
| DEP-041 | EE-HA intake failover SHALL be active/passive shared-nothing: unplanned failover starts the passive on its own store after fencing; planned switchover SHALL use stop-transfer-start through the core-initiated relay; the source SHALL see "received" only after local fsync; the documented intake RTO SHALL be ≤ 10 min in 18, 19 and 21. | ADR-046(1); RVW-C-08; RVW-C-19 | THR-032, THR-011 | C-05, C-08, C-09 | TST: LT-6 (`34-PERFORMANCE-SCALABILITY.md`) plus a planned-switchover test showing no envelope loss and no intake-to-intake connection |
| DEP-042 | MANAGED SHALL anchor the customer-visible access log to a customer-controlled witness within 15 min, SHALL support customer-side verification of the confidential-VM Sealer attestation and running manifest, SHALL register ≥ 2 External Watchers (≥ 1 outside the vendor's jurisdiction), and SHALL default `intake.tier_w.enabled` to off for high-risk tenants. | ADR-035; RVW-C-21; RVW-B-19 | THR-027, THR-026, THR-135 | C-34, C-36, C-06, C-07 | TST: log rewrite detected by the customer witness; DEMO: customer Desk rejects a mismatching attestation; INSP: tenant defaults |
| DEP-043 | GOV-ONPREM SHALL enable the Organization Recovery Quorum by default with custodians from independent roles, disclosed on the landing page; disabling it SHALL require a recorded determination by the agency records officer. | ADR-044(3); RVW-C-14 | THR-117, THR-128 | C-28, C-19 | TST: GOV profile default; INSP: determination record when disabled |
| DEP-044 | Installers SHALL print, and go-live SHALL require the recorded completion of, the first-contact publication checklist of §8.2 (offline publication, non-hyperlinked intranet text, C-37 first viewport and hosting), with the C-37 hosting record re-attested quarterly. | RVW-B-17; RVW-A-23; ADR-041 | THR-002, THR-036 | C-19, C-37 | INSP: checklist record; TST: go-live refuses without it |
| DEP-045 | Publishing personal names of members for ANONYMOUS channels, and enabling an INDEPENDENT channel whose Triage Set lacks recorded independent custody, SHALL each be DANGEROUS (dual approval with OVERSIGHT, disclosed in the configuration digest). | ADR-043; RVW-B-32; ADR-046(6) | THR-020, THR-019 | C-19, C-14 | TST: config checker classes; go-live gate test |
| DEP-046 | Every profile that enables alerts SHALL deploy H-ALERT separately from H-MON; H-MON SHALL have no uplink. | RVW-A-23; `17-INFRASTRUCTURE.md` INFRA-032, INFRA-043 | THR-104, THR-016 | C-25 | TST: `candorctl check` rule `mon.no_uplink`; INSP: site file |
| DEP-047 | Intake restore SHALL apply BS-INTAKE's deletion list and the pushed Z-CORE replica before opening; core restore SHALL use the dual-approved Desk re-wrap for missing Erasure Keys (`19-BACKUPS-DR.md` §11, §11.2). | ADR-047(7); ADR-047(9) | THR-017, THR-042 | C-08, C-09, C-10 | TST: DEP-036 runbook lab executes both paths |

## 17. Residual risks and limitations

1. CE-SINGLE shares a hypervisor between zones; a host compromise defeats ADR-009 separation, and a malicious SYS_ADMIN is not detectable because H-MON shares the hypervisor. It is documented as reduced isolation.
2. PRIVATE-CLOUD and MANAGED add a provider or vendor observer who can see intake timing and volume and, if compelled or malicious, live Tier W plaintext (`17-INFRASTRUCTURE.md` §7). Disclosure reduces deception but not exposure.
3. EE-HA adds seizure targets and observers (a second onion-key host, core replicas, the K8s control plane). Availability is traded against metadata exposure (`34-PERFORMANCE-SCALABILITY.md` §7). Because intake hosts are shared-nothing (ADR-046(1)), an unplanned failover leaves envelopes and source accounts on the failed host unavailable until its disk is recovered; a destroyed host loses them (bounded by the last BS-INTAKE and the import-slot interval).
4. Offline installs accept metadata up to 30 days old. A key compromise inside that window may not be revoked on offline sites in time.
5. The simple installer's U2 option (TPM-only) weakens seizure resistance for organizations without on-site staff.
6. AIRGAP-RCP relies on human transfer discipline. A missed weekly sync delays handling and triggers the ADR-033(2) escalation. It does not lose data, because epoch keys are retired only after import.
7. Active/passive failover leaves sources with cached descriptors failing for several minutes after promotion (`21-ENTERPRISE.md` §5.2).
8. Signed attestations (Erasure Key Vault backup exclusion, uplink independence, guest-invisible knobs) are only as honest as the teams that sign them, which may report to the accused.
9. Small-organisation mode discloses reduced separation of duties but does not create independence; an external OVERSIGHT holder can be captured or inattentive.
10. The Operational Load Budget is an estimate until the DEP-037 pilot; under-staffed operators may still skip drills, which the maintenance calendar surfaces only as overdue warnings.
11. MANAGED: a compelled vendor retains live Tier W capture capability and sees server-visible metadata of all customers; the controls of §4.8 make untargeted changes detectable and push high-risk tenants to Tier V, but do not remove the vendor as a single compellable party.

## 18. Open issues

1. Active/active intake (descriptor aggregation) is deferred (ADR-032). If it is adopted later, re-run the observer analysis of `34-PERFORMANCE-SCALABILITY.md` §7 and the manifest design.
2. Define the Candor Desk sync-only mode API scope for AIRGAP-RCP (`12-FRONTEND-RECIPIENT.md`, `15-AUTHENTICATION-AUTHORIZATION.md`).
3. The local-repo signing approach (`candor-update` host-local key) needs review by `33-RELEASE-UPDATE-SECURITY.md`. An alternative is an APT method plugin that verifies TUF directly.
4. The MANAGED customer-held IRK share model needs to be reconciled with vendor-side DR SLAs (`21-ENTERPRISE.md`).

5. **Shared-nothing EE-HA and source accounts.** ADR-046(1) forbids intake replication. Source accounts created on the active host are unavailable on the passive after an unplanned failover until the failed disk is recovered. A core-mediated re-provisioning of account records (RVW-B-22 proposal) would remove this gap; it needs an ADR and changes to `08-API.md`/`09-DATABASE.md` (cross-document request).

### Open Issues for ADR revision

- ADR-024 described CE-SINGLE as "VMs/containers". Resolved by ADR-046(6): VMs are the default, container-only separation is ADVANCED.
