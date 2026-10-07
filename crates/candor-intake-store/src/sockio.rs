// SPDX-License-Identifier: AGPL-3.0-or-later
//! Datagram I/O shared by the `istore` server and client: one `SEQPACKET`
//! message per call, truncation and stray descriptors refused.

use std::io::IoSliceMut;
use std::mem::MaybeUninit;
use std::os::fd::BorrowedFd;

use rustix::net::{
    RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags, SendAncillaryBuffer,
    SendFlags,
};

use crate::proto::MAX_FRAME_LEN;

/// One datagram. `Ok(None)` on EOF or timeout; `Err` on a truncated message
/// or one carrying descriptors (closed) or credentials.
pub(crate) fn recv_datagram(sock: BorrowedFd<'_>, buf: &mut [u8]) -> Result<Option<usize>, ()> {
    let mut space = [MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmRights(4))];
    let mut control = RecvAncillaryBuffer::new(&mut space);
    let msg = match rustix::net::recvmsg(
        sock,
        &mut [IoSliceMut::new(buf)],
        &mut control,
        RecvFlags::CMSG_CLOEXEC,
    ) {
        Ok(m) => m,
        Err(_) => return Ok(None),
    };
    let mut unexpected = false;
    for m in control.drain() {
        unexpected = true;
        if let RecvAncillaryMessage::ScmRights(fds) = m {
            fds.for_each(drop);
        }
    }
    if unexpected
        || msg
            .flags
            .intersects(ReturnFlags::TRUNC | ReturnFlags::CTRUNC)
        || msg.bytes > MAX_FRAME_LEN
    {
        return Err(());
    }
    if msg.bytes == 0 {
        return Ok(None);
    }
    Ok(Some(msg.bytes))
}

/// Send one datagram (also used by the client).
pub(crate) fn send_bytes(sock: BorrowedFd<'_>, bytes: &[u8]) -> Result<(), ()> {
    let mut control = SendAncillaryBuffer::default();
    let n = rustix::net::sendmsg(
        sock,
        &[std::io::IoSlice::new(bytes)],
        &mut control,
        SendFlags::NOSIGNAL,
    )
    .map_err(|_| ())?;
    if n == bytes.len() { Ok(()) } else { Err(()) }
}
