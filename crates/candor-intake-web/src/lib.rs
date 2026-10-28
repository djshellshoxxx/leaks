// SPDX-License-Identifier: AGPL-3.0-or-later
//! Candor Source Web Service (component C-06; 07 §5.1, 08 §4, 11 §5–§7;
//! IMPL-RM2 §2.6): the server-rendered, JavaScript-free Tier W intake, reached
//! only through the Tor v3 onion service. tor connects to a Unix stream socket
//! (PROXY line first); the service never opens a TCP socket.
//!
//! * HTTP: a strict HTTP/1.1 subset, one request per connection
//!   ([`http`], [`server`]); bounded heads, bodies, fields and parts.
//! * Pages: [`candor_source_ui`] renders every byte; the response head is the
//!   fixed 2,048-byte head with at most one cookie (`__Host-cs`, or the
//!   pre-session `__Host-cpre`) and the body is padded to P1/P2.
//! * State: drafts, passphrases and keys live only in the Intake Sealer
//!   (`candor_sealer::proto` over its Unix socket); the web keeps a RAM
//!   session table (20 min idle / 2 h absolute) and holds no keys.
//! * Store: read-only account and mailbox lookups through [`StoreReads`]
//!   (implemented for every `candor_intake_store::IntakeStore`).
//! * Nothing is logged per request; no client address, User-Agent, time,
//!   filename, size, passphrase or body is ever recorded.
//!
//! Integration: build a [`WebConfig`], a [`SealerClient`], a store and a
//! [`DayClock`], then `serve(Web::new(..)?, listener).await` on the
//! socket-activated listener, with [`install_panic_hook`] called first.

mod app;
pub mod config;
mod flows;
pub mod form;
pub mod hardening;
pub mod http;
pub mod limits;
pub mod multipart;
pub mod proxy;
pub mod ratelimit;
pub mod routes;
pub mod sealer;
pub mod server;
pub mod session;
pub mod token;

pub use app::{Health, Reply, ReplyBody, Web, route_of};
pub use config::{
    AccountView, ChannelConfig, ConfigError, DayClock, SiteContent, StoreReads, StoreUnavailable,
    WebConfig,
};
pub use sealer::{SealerClient, SealerError};
pub use server::serve;

/// Replace the default panic hook (which prints the payload and location to
/// stderr) with one that records only a static diagnostic through
/// candor-log (IMPL-00 §4.4; 07 §8). No payload, location, backtrace or input
/// is ever written. Call once at process start, before serving.
pub fn install_panic_hook() {
    std::panic::set_hook(Box::new(|_info| {
        candor_log::diag!(Error, "candor-web: handler panic (payload discarded)");
    }));
}
