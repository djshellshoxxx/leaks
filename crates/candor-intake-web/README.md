<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# candor-intake-web

The Candor **Source Web Service** (component C-06; `candor-web` in 07 §4.1). Licence: AGPL-3.0-or-later.

It serves the server-rendered, JavaScript-free Tier W source interface (11 §5–§7, 08 §4) behind the Tor v3 onion service. tor connects to a Unix stream socket and writes its PROXY line first; the service never opens a TCP socket. Drafts, passphrases and keys live only in the Intake Sealer (C-07). The web holds a RAM session table and nothing else.

Read `SPEC-NOTES.md` first. It covers the design, the implementation decisions (some need the lead), the dependency justifications, the test map, the required privileges and the security self-review.

## Guarantees

- **No TCP.** The only listener type in the API is `tokio::net::UnixListener` (NET-002). Every stream must start with tor's `HiddenServiceExportCircuitID haproxy` line. A stream without it is closed with no response.
- **A strict HTTP/1.1 subset.** There is one request per connection, so there is no pipelining and no smuggling between requests.
  - Framing is `Content-Length` only. `Transfer-Encoding`, `Content-Encoding`, `Expect`, `Upgrade` and `TE` are refused, as are obsolete folding, bare CR/LF, duplicate framing headers and a foreign `Host`.
  - Limits: the head is at most 16 KiB with at most 50 fields, the request line at most 4 KiB, and a form body at most 112 KiB.
  - Timeouts: 10 s to read the head, 60 s body idle, 4 h total for an upload.
- **Exact responses.** `candor-source-ui` renders every byte. The head is always exactly 2,048 bytes and carries the 11 §5.3 header set, at most one `Set-Cookie` and the `X-Pad` header. There is no `Date`, `Server`, `Connection` or `ETag`. The body is padded to P1 (65,536 B) or P2 (131,072 B), chosen only by the method and the presence of a session cookie. A test checks the bytes on the wire (AUD-RM1-SUI-14).
- **Cookies.** There is at most one per response:
  - `__Host-cs` is the session cookie, session-only. The server keeps only `SHA-256(HKDF(cs))`, never `cs`.
  - `__Host-cpre` is the pre-session cookie, valid for 15 min, and binds the pre-session CSRF token.
- **CSRF.** Every POST is checked, in this order, before any state changes:
  1. `Origin` is absent, `null` or the exact onion origin.
  2. `Sec-Fetch-Site` is absent or `same-origin`.
  3. The `csrf` token is the session token, or a pre-session token bound to `__Host-cpre`. The comparison is constant-time.

  In a multipart upload the token must be the first part, so no file byte is forwarded before it has been checked.
- **Uniform responses.** Every outcome of POST `/login`, `/inbox` and `/rotate/confirm` is released at `max(elapsed, T_LOGIN_FLOOR) + U(0, 250 ms)`, whether the attempt succeeds, uses a wrong or unknown passphrase, is malformed, fails CSRF, is rate-limited or hits BUSY.
  - The login path does the same work against a dummy key when the locator is unknown.
  - Every busy cause returns the same page.
  - Every inbox render opens exactly 32 entries.
- **Fail closed.** If the sealer is down or busy, or the store is down or in restore-pending, or the clock is insane, the service returns the busy page. If no eligible first reader exists, it returns the S04b-X page. Nothing is ever degraded.
- **No metadata.** No access log and no per-request event. The client address, User-Agent, time, filename, size, passphrase, body and circuit id are never recorded. The circuit id becomes a keyed token at once and lives in RAM for at most 10 min idle.
  - Panics: release builds abort. In unwinding builds a panic becomes the fixed 500 page. The panic hook writes a static diagnostic only.
- **Process hardening.** `hardening::harden_process` disables core dumps, applies `mlockall` and sets up Landlock. Landlock allows no filesystem access and no TCP, and at ABI 6 it scopes abstract sockets and signals.

## API

```rust
use candor_intake_web::{install_panic_hook, serve, SealerClient, Web, WebConfig, DayClock};
use candor_intake_web::hardening::{harden_process, LandlockLevel};

install_panic_hook();
// main thread, before any runtime; listener inherited from systemd (fd "http"):
let report = harden_process(LandlockLevel::Required)?;
let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
rt.block_on(async {
    let web = Web::new(cfg /* WebConfig */, SealerClient::new("/run/candor/sealer/seal.sock".into()),
                       store /* impl StoreReads, e.g. any IntakeStore */, clock /* Arc<dyn DayClock> */)?;
    tokio::spawn({ let w = web.clone(); async move { loop { tokio::time::sleep(REAP).await; w.reap(); } } });
    serve(web, listener).await;   // never returns
});
```

- `WebConfig` contains the onion host (the only accepted `Host`), the tenant id, the login floor (2–6 s), the file limits, the global limits, the page content (`SiteContent`, including `ChannelConfig`s), and the optional signed running manifest. `Web::new` validates all of it and renders the fixed pages once. Start is refused on any error.
- `StoreReads` is implemented for every `candor_intake_store::IntakeStore`. It exposes only `serving_allowed`, `account(lookup_tag)` and `mailbox(account)`.
- `DayClock::today()` is the independent day clock (16 §14.3). `None` means the clock is insane.
- `Web::health()` reports whether the sealer and the store were reachable last time. It carries no counts.
- Public parser modules: `http`, `form`, `multipart` and `proxy`. They are pure functions over bytes and are fuzzed.

## Layout

| Module | Content |
|---|---|
| `server` | Accept loop, connection caps, deadlines, body reader, lingering close, handler task isolation |
| `http` | Request-head parser, response-head serializer |
| `proxy` | tor PROXY line |
| `form`, `multipart` | Strict URL-encoded and streaming multipart parsers, text validation (NFC, controls, limits) |
| `token`, `session`, `ratelimit` | Cookies, handle derivation, CSRF, the RAM session table with 20 min / 2 h timers, per-circuit and global buckets |
| `routes` | Deny-by-default route registry (audience `source-web`), field allow-lists |
| `app`, `flows` | Dispatch, uniform pages, the S01–S13 flows over the sealer IPC |
| `sealer` | One-request-per-connection client of `candor_sealer::proto` |
| `config`, `limits`, `hardening` | Configuration and seams, named limits, process hardening |

## Tests

```
cargo test -p candor-intake-web          # unit + proptest + Unix-socket integration (≈40 s)
cd crates/candor-intake-web && cargo +nightly-2026-09-28 fuzz run fuzz_http_request <corpus> fuzz/seeds/fuzz_http_request -- -max_total_time=60
```

The integration tests run the real server on a Unix socket. The other end is a scripted sealer that speaks the real IPC protocol over its own Unix socket. The tests use no network. `tests/sto29_handover.rs` runs the sealer's `StoreConnection::hand_over` against the store's `StagedReceiver` and `MemoryStore` (C-5 / AUD-RM2-STO-29). `tests/hardening.rs` (`harness = false`) hardens the test process and then serves a request.
