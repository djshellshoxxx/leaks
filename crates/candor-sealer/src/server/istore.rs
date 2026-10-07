// SPDX-License-Identifier: AGPL-3.0-or-later
//! The production [`EnvelopeSink`]: `istore.sock` (07 §5.3) through the
//! store crate's client (`candor_intake_store::client::Conn`, protocol
//! `candor_intake_store::proto`) plus the staged hand-over of
//! [`super::handover`] on the same connection (O-2 of the web SPEC-NOTES).
//!
//! * `COMMIT_GROUP` carries the inline objects (main, IDENTITY), the slot
//!   blocks and the disposition marker; its `Ok` is followed by the
//!   ATTACHMENT_BUNDLE hand-over (sealed memfd, `0x02 ‖ h` copied, `0x01 ‖ h`
//!   committed). **AUD-RM2-SEA-01 / WEB-13:** any transport failure or
//!   timeout closes the socket and the whole exchange is repeated once on a
//!   fresh connection with the **same** sealed group; a group the store had
//!   already committed is acknowledged as a success and never committed
//!   twice (`candor_intake_store::staged`). A refusal by the store (an error
//!   code) is final and not retried.
//! * `ACCOUNT_UPSERT` and `DELETE` are idempotent in the store, so they are
//!   retried once the same way.
//! * [`EnvelopeSink::is_available`] opens the connection if it is closed, so
//!   a seal is refused up front while the store is unreachable.
//!
//! The sink holds one connection under a mutex: commits are serialised, as
//! the sealer's blocking sink calls are. Nothing is logged; errors are the
//! uniform [`SinkError`].

use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use candor_intake_store::client::{ClientError, Conn, Connector};
use candor_intake_store::proto as ip;

use super::handover::{
    ACK_COMMITTED, ACK_COPIED, ACK_TIMEOUT, COPY_DEADLINE_BASE, MAX_BUNDLE_LEN, await_ack_within,
    copy_deadline_with, send,
};
use super::sink::{
    AccountUpsert, Blob, DeleteOutcome, EnvelopeGroup, EnvelopeSink, SinkError, UpsertError,
};

/// Default per-call deadline of the request/response exchanges.
pub const DEFAULT_CALL_TIMEOUT: Duration = Duration::from_secs(30);

/// `istore.sock` sink.
pub struct IstoreSink {
    conn: Mutex<Conn>,
    copy_base: Duration,
    ack_timeout: Duration,
}

impl core::fmt::Debug for IstoreSink {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("IstoreSink")
    }
}

/// Why an attempt failed: a store refusal is final, a transport failure is
/// retried once on a fresh connection.
enum Attempt {
    Refused,
    Transport,
}

impl From<ClientError> for Attempt {
    fn from(e: ClientError) -> Self {
        match e {
            ClientError::Transport => Self::Transport,
            ClientError::Store(_) => Self::Refused,
        }
    }
}

impl IstoreSink {
    /// A sink over `connector` (the integrator opens `istore.sock`), with the
    /// production deadlines ([`COPY_DEADLINE_BASE`], [`ACK_TIMEOUT`]).
    #[must_use]
    pub fn new(connector: Connector, call_timeout: Duration) -> Self {
        Self {
            conn: Mutex::new(Conn::new(connector, call_timeout)),
            copy_base: COPY_DEADLINE_BASE,
            ack_timeout: ACK_TIMEOUT,
        }
    }

    /// Shorter hand-over deadlines (tests and integration tuning).
    #[must_use]
    pub fn with_handover_deadlines(mut self, copy_base: Duration, ack_timeout: Duration) -> Self {
        self.copy_base = copy_base;
        self.ack_timeout = ack_timeout;
        self
    }

    fn lock(&self) -> MutexGuard<'_, Conn> {
        self.conn.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Run `f` once; on a transport failure close and run it once more on a
    /// fresh connection (every operation is idempotent in the store).
    fn retrying<T>(
        &self,
        mut f: impl FnMut(&mut Conn) -> Result<T, Attempt>,
    ) -> Result<T, SinkError> {
        let mut conn = self.lock();
        match f(&mut conn) {
            Ok(t) => Ok(t),
            Err(Attempt::Refused) => Err(SinkError),
            Err(Attempt::Transport) => {
                conn.close();
                f(&mut conn).map_err(|_| SinkError)
            }
        }
    }

    fn commit_once(
        conn: &mut Conn,
        req: &ip::Request,
        bundle: &super::handover::StagedBundle,
        copy_base: Duration,
        ack_timeout: Duration,
    ) -> Result<(), Attempt> {
        match conn.call(req)? {
            ip::Response::Empty => {}
            _ => {
                conn.close();
                return Err(Attempt::Transport);
            }
        }
        let r = (|| {
            let sock = conn.socket().ok_or(SinkError)?;
            let hash = bundle.sha256();
            send(sock, bundle)?;
            await_ack_within(
                sock,
                copy_deadline_with(copy_base, bundle.len()),
                ACK_COPIED,
                &hash,
            )?;
            await_ack_within(sock, ack_timeout, ACK_COMMITTED, &hash)
        })();
        if r.is_err() {
            conn.close();
            return Err(Attempt::Transport);
        }
        Ok(())
    }
}

/// Classify the store's answer to `ACCOUNT_UPSERT` (AUD-RM2-IPC-10): transient
/// conditions with nothing applied (`UNAVAILABLE`: restore-pending, backend,
/// deadline; `BUSY`; `INTERNAL`; transport failure; an undecodable reply) are
/// `Unavailable` and stay queued; a definitive refusal (`INVALID`,
/// `FORBIDDEN`, `BAD_FRAME`) is `Refused`; `NOT_FOUND` for a replacement is
/// `Stale` (the old account is gone), for a create it cannot occur and is
/// treated as a refusal.
pub fn classify_upsert(
    r: Result<ip::Response, ClientError>,
    replacement: bool,
) -> Result<(), UpsertError> {
    use ip::ErrorCode as C;
    match r {
        Ok(ip::Response::Empty) => Ok(()),
        Ok(_) | Err(ClientError::Transport) => Err(UpsertError::Unavailable),
        Err(ClientError::Store(C::Unavailable | C::Busy | C::Internal)) => {
            Err(UpsertError::Unavailable)
        }
        Err(ClientError::Store(C::NotFound)) if replacement => Err(UpsertError::Stale),
        Err(ClientError::Store(C::NotFound | C::Invalid | C::Forbidden | C::BadFrame)) => {
            Err(UpsertError::Refused)
        }
    }
}

fn inline(o: &super::sink::EnvelopeObject) -> Result<ip::InlineObject, SinkError> {
    match &o.blob {
        Blob::Inline(b) => Ok(ip::InlineObject {
            object_hash: o.object_hash,
            slot_block: o.slot_block.clone(),
            bytes: b.clone(),
        }),
        Blob::Staged(_) => Err(SinkError),
    }
}

/// The wire form of a group; the bundle must be staged and within the cap.
fn commit_request(
    group: &EnvelopeGroup,
    epoch_id: u32,
    received_day: u32,
    release_offset_days: u8,
) -> Result<(ip::Request, super::handover::StagedBundle), SinkError> {
    let Blob::Staged(b) = &group.bundle.blob else {
        return Err(SinkError);
    };
    if b.is_empty() || b.len() > MAX_BUNDLE_LEN {
        return Err(SinkError);
    }
    let req = ip::Request::CommitGroup(Box::new(ip::CommitGroup {
        channel_id: group.channel_id,
        epoch_index: epoch_id,
        received_day,
        release_offset_days,
        disposition_ct: group.disposition_ct.clone(),
        main: inline(&group.main)?,
        bundle: ip::BundleObject {
            object_hash: group.bundle.object_hash,
            slot_block: group.bundle.slot_block.clone(),
            padded_size: b.len(),
        },
        identity: inline(&group.identity)?,
    }));
    // Refused by the encoder before anything is sent if a field is out of
    // range (the store would refuse it too).
    ip::encode_request(0, &req).map_err(|_| SinkError)?;
    Ok((req, b.clone()))
}

impl EnvelopeSink for IstoreSink {
    fn commit_envelope_group(
        &self,
        group: EnvelopeGroup,
        epoch_id: u32,
        received_day: u32,
        release_offset_days: u8,
    ) -> Result<(), SinkError> {
        let (req, bundle) = commit_request(&group, epoch_id, received_day, release_offset_days)?;
        let (copy_base, ack_timeout) = (self.copy_base, self.ack_timeout);
        self.retrying(|conn| Self::commit_once(conn, &req, &bundle, copy_base, ack_timeout))
    }

    fn upsert_account(&self, op: AccountUpsert) -> Result<(), UpsertError> {
        let req = ip::Request::AccountUpsert(Box::new(ip::AccountUpsert {
            replaces: op.replaces,
            lookup_tag: op.account.lookup_tag,
            auth_pk: op.account.auth_pk,
            xwing_pk: op.account.xwing_pk.clone(),
            prefs_ct: op.account.prefs_ct.clone(),
            mailbox_ids: op.account.mailbox_ids.clone(),
            rewrapped: op.rewrapped_replies.clone(),
        }));
        ip::encode_request(0, &req).map_err(|_| UpsertError::Refused)?;
        // Transient answers are retried once here and again at the next
        // flush (`Unavailable`); only a definitive refusal is final.
        let mut conn = self.lock();
        let replacement = op.replaces.is_some();
        let attempt = |conn: &mut Conn| classify_upsert(conn.call(&req), replacement);
        match attempt(&mut conn) {
            Err(UpsertError::Unavailable) => {
                conn.close();
                attempt(&mut conn)
            }
            r => r,
        }
    }

    fn is_available(&self) -> bool {
        self.lock().ensure().is_ok()
    }

    fn delete_replies(&self, lookup_tag: [u8; 32], replies: &[[u8; 16]]) -> Result<u32, SinkError> {
        let req = ip::Request::Delete(ip::Delete::Replies {
            lookup_tag,
            replies: replies.to_vec(),
        });
        ip::encode_request(0, &req).map_err(|_| SinkError)?;
        self.retrying(|conn| match conn.call(&req)? {
            ip::Response::Deleted(n) => Ok(n),
            _ => Err(Attempt::Transport),
        })
    }

    fn delete_account(&self, lookup_tags: &[[u8; 32]]) -> Result<DeleteOutcome, SinkError> {
        let req = ip::Request::Delete(ip::Delete::Account {
            lookup_tags: lookup_tags.to_vec(),
        });
        ip::encode_request(0, &req).map_err(|_| SinkError)?;
        self.retrying(|conn| match conn.call(&req) {
            Ok(ip::Response::Deleted(entries)) => Ok(DeleteOutcome::Deleted { entries }),
            Err(ClientError::Store(ip::ErrorCode::NotFound)) => Ok(DeleteOutcome::NotFound),
            Err(e) => Err(Attempt::from(e)),
            Ok(_) => Err(Attempt::Transport),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// AUD-RM2-IPC-10: every store code is pinned to its class.
    #[test]
    fn upsert_classification_table() {
        use ip::ErrorCode as C;
        let cases: Vec<(Result<ip::Response, ClientError>, bool, Result<(), UpsertError>)> = vec![
            (Ok(ip::Response::Empty), false, Ok(())),
            (Ok(ip::Response::Deleted(1)), false, Err(UpsertError::Unavailable)),
            (Err(ClientError::Transport), false, Err(UpsertError::Unavailable)),
            (Err(ClientError::Store(C::Unavailable)), false, Err(UpsertError::Unavailable)),
            (Err(ClientError::Store(C::Busy)), true, Err(UpsertError::Unavailable)),
            (Err(ClientError::Store(C::Internal)), true, Err(UpsertError::Unavailable)),
            (Err(ClientError::Store(C::NotFound)), true, Err(UpsertError::Stale)),
            (Err(ClientError::Store(C::NotFound)), false, Err(UpsertError::Refused)),
            (Err(ClientError::Store(C::Invalid)), false, Err(UpsertError::Refused)),
            (Err(ClientError::Store(C::Forbidden)), true, Err(UpsertError::Refused)),
            (Err(ClientError::Store(C::BadFrame)), false, Err(UpsertError::Refused)),
        ];
        for (r, replacement, want) in cases {
            assert_eq!(classify_upsert(r, replacement), want);
        }
        // Exhaustive over the code enum: every code is one of the two classes.
        for c in [
            C::BadFrame,
            C::Forbidden,
            C::NotFound,
            C::Invalid,
            C::Unavailable,
            C::Busy,
            C::Internal,
        ] {
            let got = classify_upsert(Err(ClientError::Store(c)), true);
            let transient = matches!(c, C::Unavailable | C::Busy | C::Internal);
            assert_eq!(got == Err(UpsertError::Unavailable), transient, "{c:?}");
        }
    }
}
