// SPDX-License-Identifier: AGPL-3.0-or-later
//! Source flows end to end over the Unix socket against a scripted sealer
//! speaking the real IPC protocol (IMPL-RM2 §2.8; 11 §6; 08 SW-01..SW-30).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod support;

use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use candor_sealer::proto::Op;
use support::*;

const SEP: &str = "----geckoformboundary9f1c";

fn multipart(csrf: &str, filename: &str, data: &[u8], action: &str) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(
        format!("--{SEP}\r\nContent-Disposition: form-data; name=\"csrf\"\r\n\r\n{csrf}\r\n")
            .as_bytes(),
    );
    b.extend_from_slice(format!("--{SEP}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\nContent-Type: application/pdf\r\n\r\n").as_bytes());
    b.extend_from_slice(data);
    b.extend_from_slice(format!("\r\n--{SEP}\r\nContent-Disposition: form-data; name=\"action\"\r\n\r\n{action}\r\n--{SEP}--\r\n").as_bytes());
    b
}

fn multipart_req(path: &str, cookie: &str, body: &[u8]) -> Vec<u8> {
    let mut r = format!(
        "POST {path} HTTP/1.1\r\nHost: {HOST}\r\nContent-Type: multipart/form-data; boundary={SEP}\r\nContent-Length: {}\r\nOrigin: null\r\nSec-Fetch-Site: same-origin\r\nCookie: {cookie}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    r.extend_from_slice(body);
    r
}

/// ST-003-like: S01 → S04 → S04b → S05 (3..6) → S06 (upload) → S07 → S08 →
/// S10 → S10c → S10s; the draft lives only in the sealer; the passphrase is
/// shown once; nothing is sealed before the 3-word confirmation (ADR-034).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn full_report_flow() {
    let h = harness().await;
    let (cs, tok) = h.start("anonymous").await;
    let c = [cs.as_str()];
    // S04b: tick role index 1 (role-label id 2).
    let r = h
        .post("/en/concerns", &c, &format!("csrf={tok}&coi_label=1"))
        .await;
    assert_eq!(r.status, 200);
    assert!(
        r.text().contains("name=\"step\""),
        "S05 follows S04b for ANONYMOUS"
    );
    // S05 step 3: required category missing → field error, nothing advanced.
    let r = h
        .post(
            "/en/q",
            &c,
            &format!("csrf={tok}&step=3&nav=next&category="),
        )
        .await;
    assert!(r.text().contains("aria-invalid=\"true\""));
    let r = h
        .post(
            "/en/q",
            &c,
            &format!("csrf={tok}&step=3&nav=next&category=fraud"),
        )
        .await;
    assert!(r.text().contains("value=\"4\""), "step 4 shown");
    let what = "Payments were moved off the books \u{2014} canary-what-7781.";
    let body = format!(
        "csrf={tok}&step=4&nav=next&what={}&when_month=3&when_year=2025&where={}",
        enc(what),
        enc("Head office")
    );
    let r = h.post("/en/q", &c, &body).await;
    assert_eq!(r.status, 200);
    for step in [5, 6] {
        let r = h
            .post("/en/q", &c, &format!("csrf={tok}&step={step}&nav=next"))
            .await;
        assert_eq!(r.status, 200);
    }
    // The sealer holds the draft (fields sorted, COI ticks with the role id
    // and the category id).
    {
        let m = h.sealer.sessions.lock().unwrap();
        let s = m.values().next().unwrap();
        assert!(
            s.fields
                .iter()
                .any(|(k, v)| *k == 2 && v.contains("canary-what-7781"))
        );
        assert!(s.fields.windows(2).all(|w| w[0].0 < w[1].0));
        assert_eq!(s.coi.as_ref().unwrap(), &(vec![2], vec![10]));
    }
    // S06: upload a 200 KiB file, streamed in ≤ 64 KiB chunks.
    let data: Vec<u8> = (0..200 * 1024).map(|i| (i % 251) as u8).collect();
    let body = multipart(&tok, "r\u{e9}port canary-name.pdf", &data, "upload");
    let r = parse(&raw(&h.web_sock, 1, &multipart_req("/en/files", &cs, &body)).await);
    assert_eq!(r.status, 200, "{}", r.text());
    assert!(
        !r.text().contains("canary-name"),
        "file names never reach the web pages"
    );
    assert!(*h.sealer.max_chunk.lock().unwrap() <= 65_536);
    {
        let m = h.sealer.sessions.lock().unwrap();
        let s = m.values().next().unwrap();
        assert_eq!(s.parts.len(), 1);
        assert_eq!(
            s.parts[0].2,
            data.len() as u64,
            "every byte reached the sealer"
        );
    }
    // S06 continue → S07 → S08.
    let r = h
        .post(
            "/en/files",
            &c,
            &format!("csrf={tok}&nav=continue&desc_0={}", enc("ledger")),
        )
        .await;
    assert_eq!(r.status, 200);
    let r = h
        .post(
            "/en/files/check",
            &c,
            &format!("csrf={tok}&action=continue"),
        )
        .await;
    assert!(
        r.text().contains("canary-what-7781"),
        "S08 shows the answers"
    );
    assert_eq!(
        h.sealer.sealed.load(Ordering::SeqCst),
        0,
        "nothing sealed yet"
    );
    // S08 → S10: passphrase shown once.
    let r = h
        .post(
            "/en/review",
            &c,
            &format!("csrf={tok}&delayed_delivery=true&action=send"),
        )
        .await;
    let words = passphrase_words();
    let page = r.text();
    assert!(words.iter().all(|w| page.contains(w.as_str())));
    // S10 → S10c, wrong words first.
    let r = h.post("/en/check", &c, &format!("csrf={tok}")).await;
    assert!(
        !words.iter().all(|w| r.text().contains(w.as_str())),
        "never shown again"
    );
    let r = h
        .post(
            "/en/submit",
            &c,
            &format!("csrf={tok}&w_a=zoom&w_b=zoom&w_c=zoom"),
        )
        .await;
    assert_eq!(r.status, 200);
    assert_eq!(h.sealer.sealed.load(Ordering::SeqCst), 0);
    // Right words → sealed, S10s with the day only.
    let pick = |p: u8| enc(&words[usize::from(p)]);
    let body = format!(
        "csrf={tok}&w_a={}&w_b={}&w_c={}",
        pick(POSITIONS[0]),
        pick(POSITIONS[1]),
        pick(POSITIONS[2]).to_uppercase()
    );
    let r = h.post("/en/submit", &c, &body).await;
    assert_eq!(r.status, 200, "{}", r.text());
    assert!(r.text().contains("2026-10-01"));
    assert_eq!(
        r.header("Clear-Site-Data"),
        Some("\"cache\", \"cookies\", \"storage\"")
    );
    assert_eq!(h.sealer.sealed.load(Ordering::SeqCst), 1);
    // A repeated /submit (lost response) re-renders S10s, no second send.
    let r = h.post("/en/submit", &c, &body).await;
    assert!(r.text().contains("2026-10-01"));
    assert_eq!(h.sealer.sealed.load(Ordering::SeqCst), 1);
    // The sealer session was zeroized after the send.
    assert!(h.sealer.sessions.lock().unwrap().is_empty());
}

/// IMPL-RM2-011 / AT-042 (lab bound): every login outcome is released no
/// earlier than the 3 s floor, with the same status and size, whether the
/// account exists, the words are wrong, malformed or the sealer is busy.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn login_uniform_status_size_and_floor() {
    let h = harness().await;
    let words = passphrase_words().join(" ");
    h.store.add_account(&words);
    h.store
        .replies
        .lock()
        .unwrap()
        .push(b"REPLY:We received your report.".to_vec());
    let mut wrong: Vec<String> = passphrase_words();
    wrong[0] = "zoom".into();
    let cases: Vec<(String, bool)> = vec![
        (words.clone(), true),
        (wrong.join(" "), false),
        ("abacus abacus".into(), false),
        ("not words at all".into(), false),
    ];
    let mut sizes = Vec::new();
    for (pw, ok) in &cases {
        let (pre, tok) = h.pre().await;
        let start = Instant::now();
        let r = h
            .post(
                "/en/login",
                &[&pre],
                &format!("csrf={tok}&action=login&passphrase={}", enc(pw)),
            )
            .await;
        let el = start.elapsed();
        assert!(
            el >= Duration::from_secs(3),
            "floor on every outcome ({el:?})"
        );
        assert!(
            el < Duration::from_secs(4),
            "floor + ≤ 250 ms jitter ({el:?})"
        );
        assert_eq!(r.status, 200);
        sizes.push(r.head.len() + r.body.len());
        assert_eq!(r.text().contains("We received your report."), *ok);
        assert!(
            !r.text().contains(pw.as_str()) || pw.len() < 8,
            "never echoes the passphrase"
        );
    }
    assert!(
        sizes.windows(2).all(|w| w[0] == w[1]),
        "same size class: {sizes:?}"
    );
    // Busy (sealer queue full): the busy page, after the same floor.
    h.sealer.busy.store(true, Ordering::SeqCst);
    let (pre, tok) = h.pre().await;
    let start = Instant::now();
    let r = h
        .post(
            "/en/login",
            &[&pre],
            &format!("csrf={tok}&action=login&passphrase={}", enc(&words)),
        )
        .await;
    assert!(start.elapsed() >= Duration::from_secs(3));
    assert_eq!(r.status, 429);
    assert_eq!(r.head.len() + r.body.len(), sizes[0]);
}

/// SW-10/SW-11: a successful login sets a new session cookie, renders the
/// inbox with the verified reply; the inbox is reachable by GET with the
/// cookie, the session ends at Leave.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn login_inbox_and_leave() {
    let h = harness().await;
    let words = passphrase_words().join(" ");
    h.store.add_account(&words);
    h.store
        .replies
        .lock()
        .unwrap()
        .push(b"REPLY:Thank you, canary-reply.".to_vec());
    let (pre, tok) = h.pre().await;
    let r = h
        .post(
            "/en/login",
            &[&pre],
            &format!("csrf={tok}&action=login&passphrase={}", enc(&words)),
        )
        .await;
    let cs = r.cookie().unwrap();
    assert!(cs.starts_with("__Host-cs="));
    let tok = r.csrf();
    // 32 openings per inbox render (08 §3.8 N_fixed), real and dummy.
    assert_eq!(h.sealer.count(Op::OpenReply), 32);
    let r = h.get("/en/inbox", &[&cs]).await;
    assert!(r.text().contains("canary-reply"));
    assert_eq!(r.body.len(), 131_072);
    // Follow-up message (SW-12): sealed for the case.
    let r = h
        .post(
            "/en/conversation",
            &[&cs],
            &format!("csrf={tok}&action=send&text={}", enc("More detail")),
        )
        .await;
    assert_eq!(r.status, 200);
    assert_eq!(h.sealer.sealed.load(Ordering::SeqCst), 1);
    // Leave: session gone, sealer zeroized.
    let r = h.post("/en/leave", &[&cs], &format!("csrf={tok}")).await;
    assert!(r.header("Clear-Site-Data").is_some());
    let r = h.get("/en/inbox", &[&cs]).await;
    assert!(!r.text().contains("canary-reply"), "signed out");
}

/// S11r: re-entry of the current passphrase, new passphrase, 3-word
/// confirmation, then ROTATE_FINISH; the floor applies.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn passphrase_rotation() {
    let h = harness().await;
    let words = passphrase_words().join(" ");
    h.store.add_account(&words);
    let (pre, tok) = h.pre().await;
    let r = h
        .post(
            "/en/login",
            &[&pre],
            &format!("csrf={tok}&action=login&passphrase={}", enc(&words)),
        )
        .await;
    let cs = r.cookie().unwrap();
    let tok = r.csrf();
    let c = [cs.as_str()];
    // Wrong current passphrase: refused, after the floor.
    let start = Instant::now();
    let r = h
        .post(
            "/en/inbox",
            &c,
            &format!("csrf={tok}&action=rotate-passphrase&passphrase=zoom"),
        )
        .await;
    assert!(start.elapsed() >= Duration::from_secs(3));
    assert_eq!(h.sealer.count(Op::RotatePassphrase), 0);
    assert_eq!(r.status, 200);
    let r = h
        .post(
            "/en/inbox",
            &c,
            &format!(
                "csrf={tok}&action=rotate-passphrase&passphrase={}",
                enc(&words)
            ),
        )
        .await;
    assert_eq!(h.sealer.count(Op::RotatePassphrase), 1);
    assert!(
        passphrase_words()
            .iter()
            .all(|w| r.text().contains(w.as_str()))
    );
    let r = h.post("/en/check", &c, &format!("csrf={tok}")).await;
    assert_eq!(r.status, 200);
    let w = passphrase_words();
    let body = format!(
        "csrf={tok}&w_a={}&w_b={}&w_c={}",
        w[usize::from(POSITIONS[0])],
        w[usize::from(POSITIONS[1])],
        w[usize::from(POSITIONS[2])]
    );
    let r = h.post("/en/rotate/confirm", &c, &body).await;
    assert_eq!(r.status, 200, "{}", r.text());
    assert_eq!(h.sealer.count(Op::RotateFinish), 1);
}

/// 07 §13 fail closed: sealer down → the busy page (never a degraded path);
/// store restore-pending or down → busy for login and new reports; an
/// insane clock refuses the final send.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fail_closed_dependencies() {
    let h = harness().await;
    // Store restore pending.
    h.store.restore_pending.store(true, Ordering::SeqCst);
    let (pre, tok) = h.pre().await;
    let body = format!("csrf={tok}&channel_id={}&mode=anonymous", "c1".repeat(16));
    let r = h.post("/en/new", &[&pre], &body).await;
    assert_eq!(r.status, 429);
    assert!(
        r.cookie().unwrap().starts_with("__Host-cpre="),
        "no session created"
    );
    h.store.restore_pending.store(false, Ordering::SeqCst);
    // Clock insane at the final send.
    let (cs, tok) = h.start("anonymous").await;
    let c = [cs.as_str()];
    h.post(
        "/en/q",
        &c,
        &format!("csrf={tok}&step=3&nav=next&category=fraud"),
    )
    .await;
    h.post("/en/q", &c, &format!("csrf={tok}&step=4&nav=next&what=x"))
        .await;
    h.post("/en/review", &c, &format!("csrf={tok}&action=send"))
        .await;
    h.post("/en/check", &c, &format!("csrf={tok}")).await;
    h.clock.0.store(false, Ordering::SeqCst);
    let w = passphrase_words();
    let body = format!("csrf={tok}&w_a={}&w_b={}&w_c={}", w[0], w[4], w[9]);
    let r = h.post("/en/submit", &c, &body).await;
    assert_eq!(r.status, 429);
    assert_eq!(h.sealer.sealed.load(Ordering::SeqCst), 0);
    // No eligible first reader: fail-closed page, nothing sealed elsewhere.
    h.clock.0.store(true, Ordering::SeqCst);
    h.sealer.no_reader.store(true, Ordering::SeqCst);
    let r = h.post("/en/submit", &c, &body).await;
    assert_eq!(r.status, 200);
    assert_eq!(h.sealer.sealed.load(Ordering::SeqCst), 0);
    h.sealer.no_reader.store(false, Ordering::SeqCst);
    // Sealer gone entirely: the busy page.
    let h2 = harness_without_sealer().await;
    let (pre, tok) = h2.pre().await;
    let body = format!("csrf={tok}&channel_id={}&mode=anonymous", "c1".repeat(16));
    let r = h2.post("/en/new", &[&pre], &body).await;
    assert_eq!(r.status, 429);
    assert!(!h2.web.health().sealer_up);
}

/// SW-30 / 11a: `/en/safety/tips` is a stateless P1 page; S02, S03 too.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn safety_tips_and_static_pages() {
    let h = harness().await;
    for p in [
        "/en/safety/tips",
        "/en/safety",
        "/en/status",
        "/en/",
        "/",
        "/en/new",
        "/en/login",
    ] {
        let r = h.get(p, &[]).await;
        assert_eq!(r.status, 200, "{p}");
        assert_eq!(r.body.len(), 65_536, "{p} is P1");
    }
    assert!(
        h.sealer.ops().is_empty(),
        "public GETs never touch the sealer"
    );
}

/// SW-21 extend, S13 discard, CONFIDENTIAL identity (S05b) and its removal.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn extend_identity_and_discard() {
    let h = harness().await;
    let (cs, tok) = h.start("confidential").await;
    let c = [cs.as_str()];
    let r = h.post("/en/concerns", &c, &format!("csrf={tok}")).await;
    assert!(
        r.text().contains("name=\"full_name\""),
        "S05b follows for CONFIDENTIAL"
    );
    let r = h
        .post(
            "/en/identity",
            &c,
            &format!("csrf={tok}&nav=next&full_name=&role_dept=x&contact=mailbox"),
        )
        .await;
    assert!(r.text().contains("aria-invalid=\"true\""), "name required");
    let r = h
        .post(
            "/en/identity",
            &c,
            &format!(
                "csrf={tok}&nav=next&full_name={}&role_dept=Clerk&contact=mailbox",
                enc("A Person")
            ),
        )
        .await;
    assert_eq!(r.status, 200);
    assert!(
        h.sealer
            .sessions
            .lock()
            .unwrap()
            .values()
            .next()
            .unwrap()
            .identity
            .is_some()
    );
    // Decline: back to ANONYMOUS, the identity block is gone.
    h.post("/en/identity", &c, &format!("csrf={tok}&nav=decline"))
        .await;
    assert!(
        h.sealer
            .sessions
            .lock()
            .unwrap()
            .values()
            .next()
            .unwrap()
            .identity
            .is_none()
    );
    // Extend.
    let r = h.post("/en/extend", &c, &format!("csrf={tok}")).await;
    assert_eq!(r.status, 200);
    assert_eq!(h.sealer.count(Op::Touch), 1);
    // Discard.
    let r = h
        .post("/en/end", &c, &format!("csrf={tok}&action=discard"))
        .await;
    assert!(r.header("Clear-Site-Data").is_some());
    assert!(h.sealer.sessions.lock().unwrap().is_empty());
    let r = h.get("/en/q", &c).await;
    assert!(
        r.header("Clear-Site-Data").is_some(),
        "signed-out page (S94)"
    );
}

/// ST-082: uploads over the size limit, a missing CSRF part and an empty
/// file never reach PART_BEGIN; a broken upload is dropped in the sealer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn upload_attacks() {
    let h = harness().await;
    let (cs, tok) = h.start("anonymous").await;
    // CSRF not first: refused before any sealer op.
    let mut bad = format!(
        "--{SEP}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a\"\r\n\r\nxx\r\n"
    )
    .into_bytes();
    bad.extend_from_slice(&multipart(&tok, "b", b"yy", "upload")[..]);
    let r = parse(&raw(&h.web_sock, 1, &multipart_req("/en/files", &cs, &bad)).await);
    assert_eq!(r.status, 500);
    // Wrong CSRF token.
    let r = parse(
        &raw(
            &h.web_sock,
            1,
            &multipart_req(
                "/en/files",
                &cs,
                &multipart(&"0".repeat(64), "a", b"x", "upload"),
            ),
        )
        .await,
    );
    assert_eq!(r.status, 500);
    // Empty file.
    let r = parse(
        &raw(
            &h.web_sock,
            1,
            &multipart_req("/en/files", &cs, &multipart(&tok, "", b"", "upload")),
        )
        .await,
    );
    assert_eq!(r.status, 200);
    assert!(r.text().contains("aria-invalid"));
    assert_eq!(h.sealer.count(Op::PartBegin), 0);
    // Too large by Content-Length (4 MiB limit in the harness).
    let big = vec![0u8; (4 << 20) + 70_000];
    let r = parse(
        &raw(
            &h.web_sock,
            1,
            &multipart_req("/en/files", &cs, &multipart(&tok, "a", &big, "upload")),
        )
        .await,
    );
    assert_eq!(r.status, 200);
    assert_eq!(h.sealer.count(Op::PartBegin), 0);
    // Truncated body: the part is dropped, nothing kept.
    let body = multipart(&tok, "a", &vec![7u8; 100_000], "upload");
    let mut req = multipart_req("/en/files", &cs, &body);
    req.truncate(req.len() - 200);
    let r = parse(&raw(&h.web_sock, 1, &req).await);
    assert_eq!(r.status, 200);
    let m = h.sealer.sessions.lock().unwrap();
    assert!(
        m.values().next().unwrap().parts.is_empty(),
        "half a file is never kept"
    );
}

/// 11 S10c: after 3 mismatches only "Get a new passphrase" and "Discard"
/// remain (the right words are no longer accepted for this passphrase); a
/// new passphrase resets the attempts. Nothing is sealed before a match.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn confirmation_attempt_limit() {
    let h = harness().await;
    let (cs, tok) = h.start("anonymous").await;
    let c = [cs.as_str()];
    h.post(
        "/en/q",
        &c,
        &format!("csrf={tok}&step=3&nav=next&category=fraud"),
    )
    .await;
    h.post("/en/q", &c, &format!("csrf={tok}&step=4&nav=next&what=x"))
        .await;
    h.post("/en/review", &c, &format!("csrf={tok}&action=send"))
        .await;
    h.post("/en/check", &c, &format!("csrf={tok}")).await;
    for _ in 0..3 {
        h.post(
            "/en/submit",
            &c,
            &format!("csrf={tok}&w_a=zoom&w_b=zoom&w_c=zoom"),
        )
        .await;
    }
    let w = passphrase_words();
    let right = format!("csrf={tok}&w_a={}&w_b={}&w_c={}", w[0], w[4], w[9]);
    let before = h.sealer.count(Op::ConfirmPassphrase);
    let r = h.post("/en/submit", &c, &right).await;
    assert_eq!(r.status, 200);
    assert_eq!(
        h.sealer.count(Op::ConfirmPassphrase),
        before,
        "not even sent to the sealer"
    );
    assert_eq!(h.sealer.sealed.load(Ordering::SeqCst), 0);
    // New passphrase → new attempts.
    h.post("/en/newphrase", &c, &format!("csrf={tok}")).await;
    h.post("/en/check", &c, &format!("csrf={tok}")).await;
    let r = h.post("/en/submit", &c, &right).await;
    assert!(r.text().contains("2026-10-01"));
    assert_eq!(h.sealer.sealed.load(Ordering::SeqCst), 1);
}
