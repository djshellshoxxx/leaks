# R4 — Anonymity Networks for a Whistleblowing Platform: Attack Literature, Tor vs I2P, Recommendation

*Research date: 2026-09-30. Scope: transport-layer anonymity for sources submitting to our platform, plus the non-network deanonymization channels (stylometry, documents, media, printers) that routinely defeat network anonymity in practice.*

## 0. Method and verification caveats

- Sources were gathered with web search on 2026-09-30. **Direct page fetches were blocked by the research environment's egress proxy** for blog.torproject.org, forum.torproject.org, gitlab.torproject.org, i2p.net, arxiv.org, usenix.org, petsymposium.org, docs.securedrop.org and krebsonsecurity.com. Facts below come from search-engine extracts of those primary pages, which are reliable for titles, authors, venues and dates but may be less reliable for fine detail.
- Items marked **UNVERIFIED** come from the author's prior knowledge and could not be confirmed in this session (no URL fetched or found). No URL is invented. Where a URL is given for an UNVERIFIED item, it follows a known, stable pattern and should be checked before anyone cites it.
- The search budget ran out before searches on SecureDrop/GlobaLeaks docs, CoverDrop, Loopix/Nym, Tor Metrics numbers, Onion Browser, Conflux and Onion-Location. Those sections are marked UNVERIFIED and need a follow-up pass (see §8).

**Bottom line up front:** use **Tor onion services (v3) as the only anonymous-mode transport**, run on **C-tor 0.4.8+/0.4.9 with PoW enabled and the full Vanguards add-on** for the service side (move to Arti once Arti's onion-*service* side is declared production-ready). Keep an **internal transport abstraction** so that a mixnet or cover-traffic transport (CoverDrop-style, Nym/Loopix) can be added later. **Do not ship I2P** as a submission transport. **Require Tor for anonymous mode** (onion-only submission endpoint) and allow **no clearnet fallback** for anonymous submissions. The largest residual risks are not in the network layer. They are **what the source does** (managed device or network, timing, repeat visits) and **what the content reveals** (stylometry, document canaries and watermarks, metadata, printer MICs). The platform must address these too.

---

## 1. Threat model summary (for this application)

| Adversary | Typical capabilities | Relevance |
|---|---|---|
| A. Employer (the organization being reported on) | Sees corporate network egress (often with TLS interception), logs on managed endpoints (EDR, MDM, proxy logs), document-access and print logs, and the leaked document itself (with canaries and watermarks) | **Highest-likelihood adversary.** Deanonymizes through *who had access* plus *who used Tor, and when*. No network-layer attack is needed. |
| B. National LE/intel (single jurisdiction) | ISP-level observation within the country, legal compulsion of ISPs, may run relays, can run long-term timing analysis (BKA 2019–2021) | Realistic for national-security and corruption leaks. |
| C. Global / multi-AS passive adversary (Five Eyes-class) | Sees a large share of Internet paths, BGP-level manipulation | Low-latency networks (Tor and I2P alike) are **not designed** to resist it. |
| D. Malicious relay operators (Sybil) | Run many relays, as KAX17 did with 900+ | Increases the chance of guard or middle compromise, and enables guard discovery and predecessor attacks. |
| E. DoS attacker / censor | Floods onion services, blocks Tor | Availability, and pushes sources toward riskier fallbacks. |

---

## 2. Attack taxonomy (Topic A)

Category key: **PRACTICAL** = observed in the wild, or feasible today for realistic adversaries. **LAB** = demonstrated experimentally under assumptions that often don't hold in deployment. **THEORETICAL** = analytic or simulation only, or needs capabilities few adversaries have.

### 2.1 Network-layer attacks on Tor

| Attack | Key papers / incidents | Category | Realistic threat to a whistleblower submitting to our onion service | Mitigation available to us |
|---|---|---|---|---|
| **End-to-end traffic/timing correlation** | Murdoch & Danezis, *Low-Cost Traffic Analysis of Tor*, IEEE S&P 2005 [B-AN-01]; Johnson et al., *Users Get Routed*, CCS 2013 [B-AN-02]; Sun et al., *RAPTOR*, USENIX Sec 2015 [B-AN-03]; Nasr et al., *DeepCorr*, CCS 2018 (96% vs 4% for prior art with about 900 packets) [B-AN-04]; Oh et al., *DeepCoFFEA*, IEEE S&P 2022 (93% TPR at high precision, two orders of magnitude faster) [B-AN-05] | **PRACTICAL** for adversaries that see both ends: ISP, national LE, or an AS/IXP on both paths. | For onion services there is no exit. The adversary must see **the source's link to its guard** and **our service's link to its guard**, or control or identify those guards. An employer watching the corporate uplink sees Tor use (the timing "when") but not the destination. If it also knows *when* a submission arrived (for example, the journalist publishes or queries the company), crude timing intersection is enough. That is the realistic threat. | Tell sources not to use employer networks or devices. Decouple submission time from any observable event: queue submissions server-side and never expose arrival timestamps to journalists at fine granularity. Pad and batch our responses. Full vanguards on the service. Future: cover traffic (§6). |
| **Operational timing analysis by LE (real case)** | 2024 Panorama/STRG_F reports: German BKA deanonymized a Ricochet user (Boystown admin) through repeated timing analysis over 2019–2021, exploiting an **old Ricochet build without vanguards-lite** [B-AN-06, B-AN-07]; Tor Project response "Tor is still safe", 2024-09-18 [B-AN-08] | **PRACTICAL (in the wild)** | Shows that a state with ISP-level compulsion and relay monitoring can find a long-lived, **always-online** Tor endpoint's guard, then use ISP data to identify it. A source who keeps a Tor client online for long periods, or uses outdated software, is exposed. | Sources use current Tor Browser, which has vanguards-lite since 0.4.7. Sessions are short-lived: no persistent source client and no always-on messenger-style presence. Our service runs current tor with full vanguards (§3.4). |
| **Guard discovery** (find the guard of a service or client, then compel or observe it) | Øverlier & Syverson, *Locating Hidden Servers*, IEEE S&P 2006 [B-AN-09, UNVERIFIED URL]; Biryukov et al., *Trawling for Tor Hidden Services*, IEEE S&P 2013 [B-AN-10, UNVERIFIED URL]; Vanguards-lite, Prop. 333 in tor 0.4.7 [B-AN-11]; Vanguards spec [B-AN-12]; Arti vanguards lite and full, Arti 1.2.2 (2024) [B-AN-13] | **PRACTICAL** (the BKA case is an instance) | Chiefly a threat to **our service's location** (seizure, or compelled logging at the hosting provider) and to long-lived client identities. With vanguards-lite, clients keep 4 long-lived layer-2 guards (1–12 days, mean about a week) [B-AN-11]. | Service side: **full Vanguards** (C-tor plus the `vanguards` add-on, or Arti full-vanguards mode, which is meant for services with uptime over a month [B-AN-13]). Source side: current Tor Browser. |
| **Website fingerprinting (WF)** by a local passive observer (ISP, employer, Wi-Fi) | Panchenko et al., WPES 2011 and NDSS 2016 "Website Fingerprinting at Internet Scale" [B-AN-14, UNVERIFIED URL]; Sirinam et al., *Deep Fingerprinting*, CCS 2018 (>98% closed world; 0.99 precision / 0.94 recall open world, undefended) [B-AN-15]; Rahman et al., *Tik-Tok*, PETS 2020 (98.4% undefended; **64.7% against onion sites**) [B-AN-16] | **LAB** in general; becomes **PRACTICAL for a small monitored set** | An employer or ISP could train a classifier on **our** onion service's load pattern and flag "this Tor user just loaded the leak portal". The target set is one site, which is WF's easiest case. | Keep the landing and submission pages **minimal and uniform in size**: few resources, no third-party content, fixed-size padding of responses, and the same page weight for every step. Consider serving the source UI as a single constant-size bundle. Ask sources to also browse other sites in the same session (a weak defense). Tor's circuit padding framework exists; WF-specific padding in production remains limited (UNVERIFIED status in 2026). |
| **Realism critiques of WF** | Juarez et al., *A Critical Evaluation of WF Attacks*, CCS 2014 [B-AN-17]; Cherubin, Jansen & Troncoso, *Online Website Fingerprinting*, USENIX Sec 2022 [B-AN-18]; Jansen, Wails & Johnson, genuine Tor traces (GTT23), arXiv 2404.07892, 2024 [B-AN-19] | (Evidence modifier) | Accuracy drops sharply with realistic browsing, base rates, TB versions and real exit traces. **However**, all critiques concern the *many-sites* problem. A **single high-value target site** with a low base rate still gives useful *leads* for investigation, and employer investigations only need leads. | As above. Treat WF as "adversary gets a lead, not proof", and aim for leads that are **not unique to our portal**. |
| **Onion-service / circuit fingerprinting** | Kwon et al., *Circuit Fingerprinting Attacks*, USENIX Sec 2015 (>98% TPR identifying HS circuits; 88% TPR for 50 monitored services) [B-AN-20]; Overdorf et al., *How Unique is Your .onion?*, CCS 2017 [UNVERIFIED]; Jansen et al., *Inside Job*, NDSS 2018 [UNVERIFIED] | **LAB → PRACTICAL** for a malicious guard or middle relay | A malicious guard can tell that a client is using an onion service (rendezvous-circuit shape), which shows that "this user visits some onion". Tor added circuit-setup padding for onion circuits in 0.4.1 (UNVERIFIED version). | Same page-uniformity measures. Recommend that sources use **bridges** (obfs4, WebTunnel, Snowflake) when the local network is hostile: this hides Tor use from the employer but not from a malicious bridge. |
| **Predecessor & intersection attacks** | Wright et al., predecessor attack, TISSEC 2004 / 2008 [B-AN-21]; Kesdogan et al. disclosure attack (2002); Danezis, *Statistical Disclosure Attacks*, 2003 [B-AN-22] | **PRACTICAL over long periods** | **The main multi-visit risk.** Each time a source returns (for example to check replies), the adversary intersects "who was online on Tor at time T" across visits. Employers can intersect "employees who accessed document X" with "employees seen using Tor". | Minimize the number of return visits. Tell sources not to check back from the same network. Randomize and delay when replies become visible. Avoid "reply within minutes" UX, and use a long-lived codename or passphrase so each visit need not be anchored to a device. Long-term: cover traffic (§6). |
| **Long-term observation / statistical disclosure** | Danezis 2003 [B-AN-22]; Johnson et al. 2013 (compromise probability grows with time, since guards rotate) [B-AN-02] | **PRACTICAL** (state) / THEORETICAL (small adversary) | Same as above. Low-latency networks give no protection over months. | UX that discourages long-lived engagement from one location. Journalist-side operational security. |
| **Global passive adversary (GPA)** | Tor design explicitly excludes GPA (Tor design paper, 2004; UNVERIFIED URL); Murdoch-Danezis intro [B-AN-01] | **THEORETICAL for most, PRACTICAL for Five Eyes-class** | Neither Tor nor I2P defends against it. | Only high-latency or cover-traffic systems help (Loopix, Nym, CoverDrop, §6). Document this residual risk to sources. |
| **Active traffic manipulation / watermarking** | Houmansadr et al., RAINBOW, NDSS 2009 [UNVERIFIED]; **RELAY_EARLY attack, 2014**: relays active from 2014-01-30 to 2014-07-04 encoded HS names into relay/relay-early cell patterns to tag HS-directory lookups [B-AN-23] | **PRACTICAL (observed in the wild)** | Shows that malicious relays *will* try active tagging of onion-service users. The specific bug is fixed (clients drop inbound RELAY_EARLY). | Keep tor current. Rely on Tor's bad-relay detection. |
| **Sybil & malicious relays** | KAX17: 900+ relays at peak, about 16% chance of being used as guard and 35% as middle; removed Oct–Nov 2021 [B-AN-24]. BTCMITM20: about 23% of exit capacity in May 2020, SSL stripping [B-AN-25] | **PRACTICAL (observed in the wild)** | KAX17-type entry/middle Sybils are exactly the setup needed for guard discovery and predecessor attacks against onion users. (BTCMITM20 targeted exits, which is irrelevant to onion-only use; this is a point in favor of **onion-only**.) | Onion-only (no exits). Vanguards. Current Tor. We cannot control the network's relay population. |
| **Congestion / bandwidth attacks** | Murdoch-Danezis 2005 [B-AN-01]; Evans, Dingledine & Grothoff, *A Practical Congestion Attack on Tor Using Long Paths*, USENIX Sec 2009 [UNVERIFIED]; Jansen et al., *Sniper Attack*, NDSS 2014 [UNVERIFIED]; Jansen et al., *Point Break*, USENIX Sec 2019 [UNVERIFIED] | **LAB** (deanonymization); **PRACTICAL** (DoS) | Used to locate relays on a circuit or to force circuit rebuilds, which also raises guard-discovery exposure. | Vanguards. Tor congestion control (0.4.7). PoW (below). |
| **DoS against onion services** | 2022–2023 sustained DDoS on onion services and the network; Tor 0.4.8 **PoW defense** (Equi-X / HashX, Prop. 327), blog 2023-08-23 [B-AN-26, B-AN-27, B-AN-28] | **PRACTICAL (in the wild)** | Takes the portal offline at critical moments and pushes sources toward insecure fallbacks. PoW stays dormant until the service is under stress, then prioritizes intro requests that carry more work. | Enable **HiddenServicePoWDefensesEnabled** (C-tor ≥0.4.8). Use intro-point rate limits. Keep a **second onion address** (separately keyed) in reserve. Arti: client PoW exists behind the non-default `hs-pow` feature [B-AN-29]; service-side PoW parity is UNVERIFIED as of 2026-09. |
| **Censorship / Tor blocking** | Snowflake, USENIX Sec 2024 [B-AN-30]; WebTunnel, 2024-03-12 [B-AN-31]; Conjure in Tor Browser alpha [B-AN-32]; obfs4 [UNVERIFIED URL] | **PRACTICAL** (Russia 2021, Iran 2022 per [B-AN-30]) | Relevant to sources in censored states **and** on corporate networks that block Tor. | Source guide on bridges: WebTunnel (looks like HTTPS), Snowflake (WebRTC), obfs4. Guidance to leave the managed network rather than bridge through it. |
| **Anonymity-set degradation** | Johnson 2013 [B-AN-02]; Hoang 2018 for I2P [B-AN-33] | **PRACTICAL** | Tor's set is millions of daily users (UNVERIFIED: Tor Metrics has shown roughly 2 million or more directly connecting daily users for years; recheck). I2P's is tens of thousands at most (§4). Within an *employer*, the relevant set is "employees who use Tor", which may be **one person**. | Tell sources that on corporate networks the anonymity set is the employee population, not the Tor network. |

### 2.2 Application- and user-layer attacks

| Attack | Key papers / incidents | Category | Threat to whistleblower | Mitigation available to us |
|---|---|---|---|---|
| **User behavior correlation** | BKA/Ricochet (long-lived presence) [B-AN-06]; predecessor/intersection [B-AN-21, B-AN-22]; widely documented OPSEC failures of leakers (UNVERIFIED as a class citation) | **PRACTICAL** (dominant real-world vector) | Submitting from work, soon after accessing documents, during working hours, or in response to a news story. | Onboarding copy along the lines of SecureDrop's source guidance (use a personal device on a public or home network, not work; UNVERIFIED because the docs could not be fetched) and a pre-submit OPSEC checklist. |
| **Browser fingerprinting** | Tor Browser uniformity design, letterboxing from TB 9.0 (2019), security levels Standard/Safer/Safest (UNVERIFIED specifics) | **PRACTICAL** against non-Tor browsers; **mitigated** in Tor Browser | If a source uses a non-TB browser over Tor (for example Brave's Tor window or a system proxy), the page can fingerprint them, and the employer can later match that fingerprint. | **Our service must never run fingerprinting JS.** The source UI must work with **JavaScript disabled** (TB "Safest"). No third-party resources. Recommend Tor Browser at the Safest level. |
| **Stylometry** | Narayanan et al., *On the Feasibility of Internet-Scale Author Identification*, IEEE S&P 2012: >20% top-1 among 100,000 authors, >80% precision with abstention [B-AN-34]; Brennan, Afroz & Greenstadt, *Adversarial Stylometry*, ACM TISSEC 2012 [B-AN-35]; Huang, Chen & Shu, *Can LLMs Identify Authorship?*, EMNLP Findings 2024 [B-AN-36]; LLM deanonymization at scale, arXiv 2601.12407 (2026) [B-AN-37]; SALA stylometry-assisted LLM agent, arXiv 2602.23079 (2026) [B-AN-38] | **PRACTICAL** for employers, who hold a corpus of every employee's email and chat | An employer with the full internal email archive is the **ideal** stylometry adversary: a closed candidate set of employees, plenty of training text, and cheap LLM analysis. | Advise sources to keep cover notes minimal and factual. Offer **optional, local, client-side** rewriting guidance. Evidence on LLM paraphrasing as a defense: effective on average but **bimodal**, failing for some authors [B-AN-39]; ALISON [B-AN-40]; Brennan found manual obfuscation effective and machine translation ineffective [B-AN-35]. **Never** send source text to a third-party LLM API. |
| **Document fingerprinting / canary traps** | Well-known practice. Individualized copies (wording variants, spacing, invisible characters, per-recipient PDF watermarks) are standard in DLP products (UNVERIFIED as citation) | **PRACTICAL** | The leaked file itself identifies the recipient copy. **The network layer cannot help.** | Server-side **metadata stripping** (as SecureDrop and GlobaLeaks do; UNVERIFIED) is necessary but **not sufficient** against content watermarks. Journalist workflow: publish excerpts or retyped text, compare multiple copies, and never publish originals. Warn sources. |
| **Media metadata** | EXIF GPS, camera serials, Office/PDF author fields (common knowledge; UNVERIFIED citation) | **PRACTICAL** | Photos of screens or documents leak location, device and time. | Automatic metadata removal on ingest (mat2-style; UNVERIFIED tool status) plus a source warning. Sensor-noise (PRNU) camera identification is **not** removable by metadata stripping (UNVERIFIED citation). |
| **Printer Machine Identification Codes** | EFF MIC project and printer list (no longer updated; EFF says "it appears likely that all recent commercial color laser printers print some kind of forensic tracking codes") [B-AN-41]; Richter, Escher, Schönfeld & Strufe, **DEDA**, TU Dresden, ACM IH&MMSec 2018: 1,286 prints, 141 printers, 18 manufacturers, 4 pattern formats [B-AN-42]; Reality Winner 2017 (dots visible on the published scan; the FBI affidavit relied chiefly on print-audit logs showing 6 people had printed it; UNVERIFIED characterization) [B-AN-43] | **PRACTICAL (in the wild)** | Scans or photos of printed documents carry the printer serial and print time. | Tell sources **not to print**. The journalist workflow must never publish original scans. Optional DEDA-style anonymization for scans received. |

---

## 3. Tor onion services: state of the art (2026-09)

### 3.1 Core features
- **v3 onion services**: ed25519 identity keys, 56-character addresses, blinded keys per time period so HSDirs cannot enumerate services (rend-spec-v3; UNVERIFIED URL). v2 was removed from the network in 2021 (UNVERIFIED date).
- **Client authorization, renamed "restricted discovery" in Arti**: descriptors are encrypted to authorized x25519 client keys. Arti stabilized restricted discovery in **Arti 1.7.0 (2025-11-03)** [B-AN-44]. For *our* public source portal this is not usable, since sources are unknown. It **is** useful for a **separate journalist/admin onion** (as in SecureDrop's authenticated Journalist Interface; UNVERIFIED).
- **Onion-Location**: an HTTP header or meta tag that makes Tor Browser offer the .onion when a user visits the clearnet site (TB 9.5, 2020; UNVERIFIED).
- **PoW DoS defense**: tor 0.4.8, Equi-X (Equihash<60,3> over HashX), dormant until the service is under stress [B-AN-26, B-AN-27, B-AN-28].
- **Vanguards**: vanguards-lite is built into C-tor since 0.4.7 (Prop. 333) [B-AN-11]. Full vanguards come via the Python `vanguards` add-on for C-tor (UNVERIFIED maintenance status 2026), or natively in Arti ("full" mode for services with uptime over a month) [B-AN-13].
- **Conflux** (traffic splitting, Prop. 329) arrived in tor 0.4.8 for exit circuits. It is **not** applicable to onion services as of the last known status (UNVERIFIED).
- **Counter Galois Onion (CGO)** relay encryption became stable in Arti 2.5.0 (2026-06-30) [B-AN-45]. This hardens against tagging attacks at the relay-crypto layer (UNVERIFIED characterization; network-wide deployment depends on relay support).

### 3.2 Arti (Rust) status and C-tor deprecation
- Arti releases: 1.2.2 (2024, vanguards) [B-AN-13]; 1.7.0 (2025-11-03, restricted discovery stable) [B-AN-44]; 1.9.0 (2026-01-13); 2.0.0 (semver bump; APIs marked experimental; relay/dirauth work) [B-AN-46, date UNVERIFIED, early 2026]; 2.4.0 (2026-06-01, flow-control/cc stable); **2.5.0 (2026-06-30, CGO stable, congestion control on by default, fixes TROVE-2026-024 and -027)** [B-AN-45]; 2.5.1 exists [B-AN-45].
- **Onion services in Arti**: repeated Arti release notes said Arti onion *services* were **not yet recommended for production** because of missing security features [B-AN-47]. I could not verify whether 2.x lifted this. **Treat Arti onion *hosting* as not yet production-grade until an Arti release note explicitly says otherwise.** Client-side PoW is behind the non-default `hs-pow` feature [B-AN-29].
- **C-tor deprecation**: the Network Team's (DRAFT) phases say C-tor becomes deprecated *for client use* once Arti is a secure, feature-complete client, while relay use continues. C-tor gets serious-bug fixes only, and new client features land in Rust [B-AN-48]. The long-term plan is full replacement. **Implication:** build the platform to run the service under **C-tor now** with a tested **Arti migration path** (both speak the same onion protocol, and keys can be converted; UNVERIFIED tooling).

### 3.3 Clients available to sources
| Platform | Client | Notes |
|---|---|---|
| Windows / macOS / Linux | **Tor Browser** (official) | Security levels Standard, Safer, Safest. Letterboxing. Uniform fingerprint. Bundled bridges: obfs4, Snowflake, WebTunnel, Conjure in alpha [B-AN-30, B-AN-31, B-AN-32]. |
| Android | **Tor Browser for Android** (official) | TB 13.5 (2024) improved the connection UX [B-AN-49]. |
| iOS | **Onion Browser** (third party, recommended by the Tor Project; UNVERIFIED current status) | WebKit-based, so it **cannot** match Tor Browser's fingerprint uniformity or JS-disable guarantees (UNVERIFIED specifics). Treat as a weaker option. |
| Tails / Whonix | Tor Browser inside an amnesic or isolated OS | Best choice for high-risk sources (UNVERIFIED current versions). |

### 3.4 Recommended service configuration (for R-spec authors)
Onion-only listener. HiddenServiceVersion 3. PoW enabled. Full vanguards. No clearnet origin reachable from the onion host. Separate onion (restricted discovery) for journalists and admins. Single-hop or non-anonymous modes forbidden. Keep an offline backup of the onion keys so the address survives a rebuild. Keep a pre-generated standby address for DoS or seizure events. Enable **no** logging of circuit or connection metadata.

---

## 4. I2P: state of the art (2026-09)

- **Architecture**: garlic routing (bundled messages). **Unidirectional** inbound and outbound tunnels (so a round trip crosses 4 tunnels). Packet-switched. Every participant is by default a router that also relays. Distributed **netDb (Kademlia-style) held by "floodfill" routers**, which anyone meeting the thresholds can become. No central directory authorities [B-AN-33, B-AN-50].
- **Crypto and transports**: NTCP2 (0.9.36, 2018), ECIES-X25519-Ratchet end-to-end (0.9.46, 2020), ECIES tunnel build (1.5.0, 2021), **SSU2 (2.0.0, 2022)**, which removed the last ElGamal use. NTCP1 was removed in 0.9.50 (2021) and **SSU1 in 2.4.0 (Dec 2023)**. The current release line is 2.10.0 (Oct 2025) [B-AN-51, B-AN-52].
- **Implementations**: Java I2P (reference) and **i2pd** (C++). They differ in Sybil defenses: in the Feb 2023 floodfill attack, i2pd-based Bitcoin nodes failed while Java I2P was "seemingly unaffected due to its Sybil analysis and block list function" [B-AN-53].
- **Network size**: about 32K daily active peers (14K behind NAT/firewall) in 2018 [B-AN-33]. Reporting on the 2026 attack described the normal network as **15,000–20,000 active devices** [B-AN-54]. An I2P comparison page is quoted in search extracts as "about 55,000 routers" (UNVERIFIED, since the page could not be fetched). **Consensus: 10⁴ scale, about 100× smaller than Tor's user base.**
- **Attacks on I2P**:
  - Egger, Schlumberger, Kruegel & Vigna, *Practical Attacks Against the I2P Network*, RAID 2013: a limited-resource attacker can deanonymize a user accessing a resource of interest with high probability, via floodfill/netDb Sybil plus timing [B-AN-55].
  - Timpanaro et al., ICISSP 2015: netDb design especially vulnerable to eclipse attacks [B-AN-56].
  - Hoang et al., IMC 2018: measurement and **censorship**. Blocking I2P by blacklisting peers is cheap: a censor running a few routers could block most of the network (UNVERIFIED exact figure; the paper's headline is the ease of address-based blocking) [B-AN-33].
  - **Wang, Ling, … Fu, *Time will Tell* (I2PERCEPTION), NDSS 2026**: **15 floodfill routers over 8 months** passively collected RouterInfos and, correlated with actively probed on/off patterns, **deanonymized all tested (controlled) I2P hidden services' IPs** [B-AN-57]. **This is directly relevant to *hosting* a service on I2P.**
  - Rohrer et al. (2026), CNN traffic deanonymization of I2P: lab models failed to transfer to the live network [B-AN-58]. This is weak evidence *for* I2P against passive ML classifiers, but it is a single preprint.
  - **Availability**: annual February floodfill/Sybil floods (2023, 2024) [B-AN-53, B-AN-54]; **Feb 2026: about 700,000 hostile nodes (Kimwolf IoT botnet), roughly 39:1 over honest nodes, disrupted the network** [B-AN-54].
- **Audits**: **no public, comprehensive third-party security audit of Java I2P or i2pd could be located** (UNVERIFIED negative; I2P publishes a papers list, not audit reports). Contrast: Tor components have had multiple public audits (UNVERIFIED list; e.g., Tor Browser and Arti audits by Cure53/Radically Open Security, needs follow-up).
- **Browser**: there is **no Tor-Browser-equivalent hardened, uniform browser**. I2P offers the **"Easy Install Bundle" (Beta, Windows)** with a hardened Firefox profile (NoScript strict by default, resistFingerprinting, WebRTC proxy obedience) [B-AN-59, B-AN-60]. This still runs on the user's own Firefox or Chromium, so the anonymity set is tiny and fingerprints are heterogeneous.
- **Mobile**: Java I2P and i2pd Android apps exist (UNVERIFIED current status). No iOS support (UNVERIFIED).

---

## 5. Tor vs I2P comparison for THIS application

| Dimension | Tor onion services (v3) | I2P | Edge |
|---|---|---|---|
| Maturity | Since 2004; v3 HS since 2017; C-tor plus Arti; large paid team | Since 2003; small volunteer team; two implementations | Tor |
| Anonymity-set size | Millions of daily users (UNVERIFIED current figure); about 7–8k relays (UNVERIFIED) | About 15–32K routers (2018–2026 figures) [B-AN-33, B-AN-54] | **Tor (by about 100×)** |
| Architecture | Circuit-switched, bidirectional 3-hop (6 hops to an HS). Directory authorities, so there is a trust root but Sybil control (bad-relay removal) | Packet-switched garlic routing, unidirectional tunnels, DHT netDb, every node a router | Mixed. I2P's design limits some correlation *in principle* but opens netDb Sybil/eclipse attacks |
| Resistance to §2 attacks | Vanguards, PoW, active bad-relay removal (KAX17), congestion control; weak vs GPA | Documented netDb Sybil/eclipse and **practical HS IP deanonymization (NDSS 2026)**; weak vs GPA; small set | **Tor** |
| Hidden-service equivalent | .onion v3; restricted discovery; Onion-Location | "Eepsites" / destinations, b32 addresses, encrypted LeaseSets | Tor (ecosystem, tooling) |
| Service discovery | Self-authenticating address; Onion-Location from clearnet; SecureDrop directory model | b32 addresses; addressbook/jump services (trust issues) | Tor |
| Client availability & source usability | One download (Tor Browser); works in minutes; Android; iOS via Onion Browser | Router install, tunnel warm-up (minutes), separate browser configuration; Windows beta bundle | **Tor (decisively)** |
| Hardened browser | **Tor Browser** (uniform, security levels) | None equivalent [B-AN-59] | **Tor** |
| Censorship resistance / PTs | obfs4, Snowflake, WebTunnel, Conjure; proven in Russia and Iran [B-AN-30–32] | No mature PT ecosystem (UNVERIFIED); cheap to block per Hoang 2018 [B-AN-33] | **Tor** |
| Enterprise/managed-network visibility | Tor use is detectable (public relay list, DPI); bridges help | Also detectable (UDP/TCP P2P patterns, reseed hosts); **a P2P router on a corporate device is a louder signal** | Neither is safe. Both argue for "don't use the employer's network or device" |
| Mobile | Official Android; iOS via Onion Browser | Android only | Tor |
| Deployment complexity (server) | Well-understood: one tor daemon, torrc, vanguards | Router must also relay and needs uptime to integrate; tunnel tuning | Tor |
| Protocol maintenance & roadmap | Active: Arti, CGO, PoW, congestion control; C-tor client deprecation roadmap [B-AN-45, B-AN-48] | Active (SSU2 and ECIES done) but small team [B-AN-51] | Tor |
| Security-research depth | Very deep (hundreds of papers; attacks drive fixes) | Shallow. Few papers, so fewer *known* attacks but also less assurance | Tor |
| Audit history | Multiple public audits (UNVERIFIED list) | None public found (UNVERIFIED) | Tor |
| Availability under attack | 2022–23 DDoS mitigated by PoW | Recurring Sybil floods; Feb 2026 700k-node event [B-AN-54] | Tor |
| Admin burden | Low–moderate | Moderate–high | Tor |
| Government/enterprise concerns | Tor is commonly blocked or alerted on in enterprises; seeing Tor from a managed device is itself a signal | Same, and P2P relaying from managed devices is worse | Neither. Mitigate by guidance |
| Precedent | SecureDrop and GlobaLeaks are Tor-onion-based (UNVERIFIED: docs not fetched, well established) | No major whistleblowing platform uses I2P (UNVERIFIED) | Tor |

---

## 6. Future transports: cover traffic and mixnets

- **Loopix** (Piotrowska et al., USENIX Sec 2017; URL https://www.usenix.org/conference/usenixsecurity17/technical-sessions/presentation/piotrowska, **UNVERIFIED**, fetch blocked): Poisson mixing plus loop and drop cover traffic. Resists a GPA at the cost of latency. **Nym** is the production descendant (mixnet, NymVPN "anonymous mode"; UNVERIFIED 2025–26 status). Suitable for asynchronous message submission, which is our use case since latency is acceptable.
- **CoverDrop** (Ahmed-Rengers, Vasile, Hugenroth, Beresford, Anderson, *CoverDrop: Blowing the Whistle Through A News App*, PoPETs 2025; **UNVERIFIED** venue and issue): every user of a news app sends constant cover messages, so real whistleblower messages are indistinguishable and **installing or using the app is not itself a signal**. Deployed as the Guardian's "Secure Messaging" in its apps (UNVERIFIED date, reported as 2024). **This is the only design that addresses the "Tor use is itself a signal" problem**, but it needs a large carrier app with a big user base.
- **Implication:** keep an internal **transport abstraction** (submission API independent of transport; store-and-forward; fixed-size message framing) so a CoverDrop-style or mixnet channel can be added later without redesign.

---

## 7. Option analysis and recommendation

| Option | Pros | Cons | Verdict |
|---|---|---|---|
| **TOR ONLY** | Largest anonymity set; Tor Browser; mature PoW/vanguards; industry precedent; best censorship tooling; lowest admin burden | Weak vs GPA; Tor use is visible on hostile networks; C-tor→Arti migration ahead | **Recommended (primary)** |
| **I2P ONLY** | No central directory; unidirectional tunnels | Tiny set; no hardened browser; practical HS deanonymization (NDSS 2026); recurring Sybil floods; no audits found; poor source usability; no iOS | **Reject** |
| **TOR + I2P** | Diversity; one more path when Tor is blocked | Doubles attack surface and admin burden. I2P users get **worse** anonymity while believing they are equally safe, and that anonymity-set split harms them. I2P is *also* blockable (Hoang 2018). Censorship is better solved with Tor PTs | **Reject** |
| **TRANSPORT ABSTRACTION** (Tor now; pluggable later) | Future-proof for mixnets and CoverDrop; lets us swap C-tor for Arti | Engineering cost; risk of inviting weak transports | **Recommended as architecture** (with admission criteria: a transport must match or beat Tor on anonymity set, audit status and client hardening before it is enabled for anonymous mode) |

### 7.1 Recommendation
1. **Anonymous mode = Tor v3 onion service only.** Serve it with C-tor ≥0.4.8 (PoW on, full vanguards). Track Arti and migrate the service once Arti declares onion services production-ready *with* PoW and full vanguards.
2. **Require Tor for anonymous submissions.** The anonymous submission endpoint exists **only** as an onion service. That enforces Tor use without any fingerprinting: any request reaching the onion listener came over Tor. We **cannot** (and should not try to) prove it is *Tor Browser* rather than another Tor client without fingerprinting. Instead, (a) make the source UI work with JavaScript off, (b) show static guidance recommending Tor Browser at Safest, and (c) never use UA sniffing or JS probes.
3. **Clearnet site = information only.** It carries the onion address (and ideally a signed copy of it), the Onion-Location header, and a guide. The clearnet landing page may compare the requesting IP against the **public Tor exit list** and, if the visitor is *not* on Tor, show a strong warning. This is IP-based and non-fingerprinting. It must be a **stateless** check and never logged.
4. **No clearnet fallback for anonymous mode.** Risks of fallback: the source IP is exposed to our hosting provider, CDN and any legal process; employer TLS interception reveals the destination; browsers leak via fingerprinting; and sources falsely believe they are anonymous. A clearnet channel may exist only as an explicitly **"confidential, not anonymous"** mode with separate branding and informed consent.
5. **Journalist/admin side:** a separate onion with restricted discovery (client auth).
6. **Non-network defenses are mandatory**: metadata stripping, a no-print warning, stylometry advice (optional *local* paraphrase guidance, no third-party LLM), a canary-trap warning and journalist workflow, and timing decoupling (batching, delayed visibility, no fine-grained arrival timestamps).
7. **Transport abstraction** in the core, with explicit admission criteria. Watch CoverDrop and Nym as the path to "using the channel is not a signal".

---

## 8. Open items (needs follow-up with unrestricted fetch)
- Confirm the current Arti onion-*service* production status and service-side PoW (Arti 2.5.x release notes, doc/OnionService.md).
- Current Tor Metrics figures: users, relays, bridges, onion services.
- SecureDrop and GlobaLeaks current docs on Tor-only access, Tor2web removal, and metadata cleaning.
- CoverDrop paper citation (PoPETs 2025 issue and URL) and Guardian deployment date. Nym mixnet status.
- The I2P site's "about 55K" claim, and any I2P or i2pd third-party audit.
- Onion Browser (iOS) maintenance status in 2026. Status of the `vanguards` add-on for C-tor.

---

## 9. Bibliography

| ID | Title | URL | Date | Relevance |
|---|---|---|---|---|
| B-AN-01 | Murdoch & Danezis, *Low-Cost Traffic Analysis of Tor*, IEEE S&P | https://www.cl.cam.ac.uk/~sjm217/papers/oakland05torta.pdf | 2005 | Foundational timing/congestion attack |
| B-AN-02 | Johnson, Wacek, Jansen, Sherr, Syverson, *Users Get Routed: Traffic Correlation on Tor by Realistic Adversaries*, CCS | https://seclab.cs.georgetown.edu/bibliography/DBLP_conf/ccs/JohnsonWJSS13.html | 2013 | Realistic AS/IXP/relay correlation over time |
| B-AN-03 | Sun et al., *RAPTOR: Routing Attacks on Privacy in Tor*, USENIX Sec | https://www.cs.princeton.edu/~jrex/papers/usenixsec15.pdf | 2015 | BGP-level correlation |
| B-AN-04 | Nasr, Bahramali, Houmansadr, *DeepCorr*, CCS | https://arxiv.org/pdf/1808.07285 | 2018 | DL flow correlation, 96% |
| B-AN-05 | Oh et al., *DeepCoFFEA*, IEEE S&P | https://par.nsf.gov/biblio/10348312 | 2022 | Scalable DL correlation, 93% TPR |
| B-AN-06 | CyberInsider, *Tor Project reassures users amid claims of de-anonymization attack* | https://cyberinsider.com/tor-project-reassures-users-amid-claims-of-de-anonymization-attack/ | 2024-09 | BKA/Ricochet timing-analysis case |
| B-AN-07 | Gigazine, *'Tor is still safe,' claims the Tor Project* | https://gigazine.net/gsc_news/en/20240924-tor-is-still-safe | 2024-09-24 | Same case; old Ricochet without guard-discovery protection |
| B-AN-08 | Tor Project blog, *Tor is still safe* | https://blog.torproject.org/tor-is-still-safe/ (URL UNVERIFIED, fetch blocked) | 2024-09-18 | Official response |
| B-AN-09 | Øverlier & Syverson, *Locating Hidden Servers*, IEEE S&P | UNVERIFIED (no URL confirmed) | 2006 | Guard discovery origin |
| B-AN-10 | Biryukov, Pustogarov, Weinmann, *Trawling for Tor Hidden Services*, IEEE S&P | UNVERIFIED (no URL confirmed) | 2013 | HSDir/guard attacks |
| B-AN-11 | Tor Proposal 333, *Vanguards lite* | https://spec.torproject.org/proposals/333-vanguards-lite.html | 2021 (tor 0.4.7) | Guard-discovery mitigation |
| B-AN-12 | Tor Vanguards Specification | https://spec.torproject.org/vanguards-spec/ | current | Full/lite vanguards |
| B-AN-13 | Tor blog, *Announcing Vanguards Support in Arti* | https://blog.torproject.org/announcing-vanguards-for-arti/ | 2024 (Arti 1.2.2) | Arti lite/full modes |
| B-AN-14 | Panchenko et al., *Website Fingerprinting at Internet Scale*, NDSS | UNVERIFIED | 2016 | WF (CUMUL) |
| B-AN-15 | Sirinam et al., *Deep Fingerprinting*, CCS | https://arxiv.org/pdf/1801.02265 | 2018 | DL WF, >98% |
| B-AN-16 | Rahman et al., *Tik-Tok*, PoPETs 2020(3) | https://www.petsymposium.org/popets/2020/popets-2020-0043.php | 2020 | Timing WF; 64.7% on onion sites |
| B-AN-17 | Juarez et al., *A Critical Evaluation of Website Fingerprinting Attacks*, CCS | https://nymity.ch/tor-dns/pdf/Juarez2014a.pdf | 2014 | WF realism critique |
| B-AN-18 | Cherubin, Jansen, Troncoso, *Online Website Fingerprinting*, USENIX Sec (pp. 753–770) | UNVERIFIED URL (listed in DBLP https://dblp.uni-trier.de/pid/14/7561.html) | 2022 | Real-world WF evaluation |
| B-AN-19 | Jansen, Wails, Johnson, *A Measurement of Genuine Tor Traces for Realistic Website Fingerprinting* | https://arxiv.org/pdf/2404.07892 | 2024 | Realistic WF dataset |
| B-AN-20 | Kwon et al., *Circuit Fingerprinting Attacks*, USENIX Sec | https://usenix.org/node/190967 | 2015 | Onion-service circuit fingerprinting |
| B-AN-21 | Wright, Adler, Levine, Shields, *Passive-Logging Attacks Against Anonymous Communications Systems*, ACM TISSEC 11(2) | https://ftp.math.utah.edu/pub/tex/bib/idx/tissec/11/2/3-3.html | 2008 (2004 predecessor paper) | Predecessor attack |
| B-AN-22 | Danezis, *Statistical Disclosure Attacks* | https://www.freehaven.net/anonbib/cache/statistical-disclosure.pdf | 2003 | Long-term intersection |
| B-AN-23 | Tor blog, *Tor security advisory: "relay early" traffic confirmation attack* | https://blog.torproject.org/node/893 | 2014-07-30 (UNVERIFIED day; attack 2014-01-30 → 07-04) | Active tagging in the wild |
| B-AN-24 | The Record, *A mysterious threat actor is running hundreds of malicious Tor relays* (KAX17) | https://therecord.media/a-mysterious-threat-actor-is-running-hundreds-of-malicious-tor-relays/ | 2021-12 | Sybil in the wild |
| B-AN-25 | SecurityWeek, *Malicious actor controlled 23% of Tor exit nodes* (BTCMITM20) | https://www.securityweek.com/malicious-actor-controlled-23-tor-exit-nodes/ | 2020-08 | Malicious exits |
| B-AN-26 | Tor blog, *Introducing Proof-of-Work Defense for Onion Services* | https://blog.torproject.org/introducing-proof-of-work-defense-for-onion-services | 2023-08-23 | PoW in 0.4.8 |
| B-AN-27 | Onion service PoW spec: Scheme v1, Equi-X and Blake2b | https://spec.torproject.org/hspow-spec/v1-equix.html | current | Equi-X |
| B-AN-28 | Tor Proposal 327, PoW over intro | https://spec.torproject.org/proposals/327-pow-over-intro.html | 2020–2023 | PoW design |
| B-AN-29 | Arti MR "First pass at proof of work client"; issue "Onion Service PoW stabilization" | https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/2026 ; https://gitlab.torproject.org/tpo/core/arti/-/issues/1751 | 2024–25 (UNVERIFIED) | Arti PoW status (non-default `hs-pow`) |
| B-AN-30 | Bocovich et al., *Snowflake*, USENIX Sec | https://www.usenix.org/conference/usenixsecurity24/presentation/bocovich | 2024 | PT; Russia 2021, Iran 2022 |
| B-AN-31 | Tor-relays list, *(Announcement) WebTunnel … now available for deployment*; coverage | https://lists.torproject.org/mailman3/hyperkitty/list/tor-relays@lists.torproject.org/thread/FB77HO2ZFFLJJLLDIPOD4VBJKWZYMTR2/ | 2024-03-12 | HTTPS-mimicking PT |
| B-AN-32 | Tor forum, *Call for testers: Conjure on Tor Browser alpha* | https://forum.torproject.org/t/call-for-testers-help-the-tor-project-to-test-conjure-on-tor-browser-alpha/7815 | 2023 (UNVERIFIED) | Refraction PT |
| B-AN-33 | Hoang et al., *An Empirical Study of the I2P Anonymity Network and its Censorship Resistance*, IMC | https://www.freehaven.net/anonbib/cache/i2p-imc18.pdf (arXiv 1809.09086) | 2018 | I2P size (about 32K/day) and blocking |
| B-AN-34 | Narayanan et al., *On the Feasibility of Internet-Scale Author Identification*, IEEE S&P | https://www.cs.princeton.edu/~arvindn/publications/author-identification-draft.pdf | 2012 | Stylometry at 100k scale |
| B-AN-35 | Brennan, Afroz, Greenstadt, *Adversarial Stylometry*, ACM TISSEC 15(3) | https://ftp.math.utah.edu/pub/tex/bib/idx/tissec/15/3/12-12.html | 2012 | Obfuscation defenses |
| B-AN-36 | Huang, Chen, Shu, *Can Large Language Models Identify Authorship?*, Findings of EMNLP | https://arxiv.org/abs/2403.08213v2 | 2024 | LLM authorship attribution |
| B-AN-37 | *De-Anonymization at Scale via Tournament-Style Attribution* | https://arxiv.org/html/2601.12407v1 | 2026-01 | LLM deanonymization, whistleblower forums named |
| B-AN-38 | *Assessing Deanonymization Risks with Stylometry-Assisted LLM Agent* (SALA) | https://arxiv.org/abs/2602.23079 | 2026-02 | LLM attribution plus a rewriting defense |
| B-AN-39 | *Personalized Author Obfuscation with Large Language Models* | https://arxiv.org/abs/2505.12090v1 | 2025-05 | LLM paraphrase defense; bimodal efficacy |
| B-AN-40 | *ALISON: Fast and Effective Stylometric Authorship Obfuscation* | https://ar5iv.labs.arxiv.org/html/2402.00835 | 2024 | Obfuscation tool |
| B-AN-41 | EFF, *List of Printers Which Do or Do Not Display Tracking Dots* | https://www.eff.org/pages/list-printers-which-do-or-do-not-display-tracking-dots | undated (no longer updated) | Printer MICs |
| B-AN-42 | The Register, *German researchers defeat printers' doc-tracking dots* (DEDA, TU Dresden, IH&MMSec 2018) | https://www.theregister.com/2018/06/27/german_researchers_defeat_printer_tracking_dots/ | 2018-06-27 | DEDA tool |
| B-AN-43 | iTWire, *NSA document leaker identified by printer dot pattern* (Reality Winner) | https://itwire.com/security/nsa-document-leaker-identified-by-printer-dot-pattern.html | 2017-06 | MIC case (role of dots vs logs: UNVERIFIED) |
| B-AN-44 | Tor blog, *Arti 1.7.0 released: onion service restricted discovery …* | https://blog.torproject.org/arti_1_7_0_released/ | 2025-11-03 | Client auth / restricted discovery in Arti |
| B-AN-45 | Tor blog, *Arti 2.5.0 released: Stable Counter Galois Onion*; *Arti 2.5.1 released* | https://blog.torproject.org/arti_2_5_0_released/ ; https://blog.torproject.org/arti_2_5_1_released/ | 2026-06-30; 2.5.1 date UNVERIFIED | Current Arti status |
| B-AN-46 | Tor blog, *Arti 2.0.0 released* | https://blog.torproject.org/arti_2_0_0_released/ | UNVERIFIED (early 2026) | Semver/relay work |
| B-AN-47 | Tor blog, *Arti 1.2.0 is released: onion services development* (and later notes: services not yet production-recommended) | https://blog.torproject.org/arti_1_2_0_released/ | 2024 | Arti onion-service caveat |
| B-AN-48 | Tor Network Team wiki (DRAFT), *Deprecation Tor Phases* | https://gitlab.torproject.org/tpo/core/team/-/wikis/NetworkTeam/DeprecationTorPhases | UNVERIFIED | C-tor client deprecation roadmap |
| B-AN-49 | BleepingComputer, *Tor Browser 13.5 brings Android enhancements, better bridge management* | https://www.bleepingcomputer.com/news/security/tor-browser-135-brings-android-enhancements-better-bridge-management/ | 2024-06 (UNVERIFIED month) | Android client |
| B-AN-50 | I2P threat model | https://beta.i2p.net/en/docs/overview/threat-model | current | I2P design and threats |
| B-AN-51 | I2P blog, *SSU2 Transport* | https://i2p.net/en/blog/2022/10/11/ssu2-transport/ | 2022-10-11 | Crypto migration timeline |
| B-AN-52 | I2P Low-level Cryptography Specification | https://geti2p.net/spec/cryptography | current | ECIES/X25519 |
| B-AN-53 | No Bullshit Bitcoin, *Ongoing Attack On I2P Network: Bitcoin Nodes Using i2pd Affected* | https://nobsbitcoin.com/ongoing-attack-on-the-i2p-network | 2023-02 | Floodfill Sybil; i2pd vs Java |
| B-AN-54 | Krebs on Security, *Kimwolf Botnet Swamps Anonymity Network I2P* | https://krebsonsecurity.com/2026/02/kimwolf-botnet-swamps-anonymity-network-i2p/ | 2026-02-11 | 700k-node Sybil; normal size 15–20k |
| B-AN-55 | Egger, Schlumberger, Kruegel, Vigna, *Practical Attacks Against the I2P Network*, RAID | https://sites.cs.ucsb.edu/~chris/research/doc/raid13_i2p.pdf | 2013 | I2P deanonymization |
| B-AN-56 | Timpanaro et al., *Evaluation of the Anonymous I2P Network's Design Choices Against Performance and Security*, ICISSP | https://www.scitepress.org/papers/2015/52266/52266.pdf | 2015 | netDb eclipse |
| B-AN-57 | Wang, Ling, Xu, Pan, Liu, Luo, Fu, *Time will Tell: Large-scale De-anonymization of Hidden I2P Services via Live Behavior Alignment*, NDSS | https://www.ndss-symposium.org/ndss-paper/time-will-tell-large-scale-de-anonymization-of-hidden-i2p-services-via-live-behavior-alignment (arXiv 2512.15510) | 2026 | Practical I2P HS IP deanonymization |
| B-AN-58 | Rohrer et al., *Convolutional-Neural-Networks for Deanonymisation of I2P Traffic* | https://arxiv.org/pdf/2605.11606 | 2026-05 | Lab-to-live transfer failure |
| B-AN-59 | I2P, *I2P Easy Install Bundle (Beta) for Windows* | https://geti2p.net/firefox | current | No TB-equivalent browser |
| B-AN-60 | I2P blog, *Easy Install Bundle 2.0.0* | https://geti2p.net/ko/blog/post/2022/11/23/easy_install_bundle_2.0.0 | 2022-11-23 | Browser profile status |
