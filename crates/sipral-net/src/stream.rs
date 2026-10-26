// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! One SIP connection: plain TCP, or TCP under a rustls client.
//!
//! A connection is made on a thread of its own (connecting and the handshake block), then read by
//! another and written by whoever sends. The TLS state is shared between the two behind a lock
//! held only while records are turned into bytes or back, never while the socket blocks on a
//! read.

use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use rustls::pki_types::ServerName;
use rustls::{ClientConnection, ProtocolVersion};
use sipral_core::endpoint::TransportErrorKind;

use crate::failure::{Failure, TlsFailure};
use crate::trust::{ClientCertificate, PlatformRoots, Prepared, Trust, prepare};

/// How much one read takes off the socket. Messages are framed further down, on
/// `Content-Length` (RFC 3261 §18.3).
pub(crate) const CHUNK: usize = 16_384;

/// Bounds on how long a TLS 1.3 connection waits, after its handshake, for the server's first
/// records: its session tickets, or its verdict on this end's certificate. Between them, twice
/// what connecting took — the bindings' `settle_seconds`.
const SETTLE_LEAST: Duration = Duration::from_millis(250);
const SETTLE_MOST: Duration = Duration::from_secs(3);

/// What a connection is made with.
pub(crate) struct Dial<'a> {
    pub(crate) remote: SocketAddr,
    /// `None` for plain TCP; for TLS, what to check the server against.
    pub(crate) tls: Option<TlsDial<'a>>,
    pub(crate) patience: Duration,
}

/// The TLS half of a [`Dial`].
pub(crate) struct TlsDial<'a> {
    pub(crate) name: ServerName<'static>,
    pub(crate) trust: &'a Trust,
    pub(crate) pin: Option<&'a sipral_core::pin::CertificatePin>,
    pub(crate) client: Option<&'a ClientCertificate>,
    pub(crate) platform: &'a PlatformRoots,
}

/// What the TLS handshake learnt that the first reads still need.
#[derive(Clone, Copy, Debug)]
struct Learnt {
    presented: bool,
    asked: bool,
}

/// The writing half of a connection, and what its reader needs.
pub(crate) struct Connection {
    writer: TcpStream,
    tls: Option<Arc<Mutex<ClientConnection>>>,
    learnt: Learnt,
    /// Plaintext the server sent while the connection settled.
    pub(crate) early: Vec<u8>,
    pub(crate) local: SocketAddr,
    reader: TcpStream,
}

/// What a reader saw end its connection.
pub(crate) enum Ended {
    /// The far end closed, or the connection was closed here.
    Closed,
    /// It broke, for this reason.
    Failed(Failure),
}

/// How a TLS label reads in a sentence.
fn said(remote: SocketAddr, tls: bool) -> String {
    format!("{} to {remote}", if tls { "TLS" } else { "TCP" })
}

/// Make the connection: TCP, and the handshake over it for TLS.
pub(crate) fn connect(dial: &Dial<'_>) -> Result<Connection, Failure> {
    let what = said(dial.remote, dial.tls.is_some());
    // checked before anything is sent: a client certificate that cannot be presented never
    // reaches the server
    let prepared = match dial.tls {
        Some(ref tls) => Some((
            prepare(tls.trust, tls.pin, tls.client, tls.platform)?,
            tls.name.clone(),
        )),
        None => None,
    };
    let started = Instant::now();
    let mut tcp = TcpStream::connect_timeout(&dial.remote, dial.patience)
        .map_err(|error| Failure::of_io(&what, &error))?;
    let local = tcp
        .local_addr()
        .map_err(|error| Failure::of_io(&what, &error))?;
    tcp.set_nodelay(true)
        .map_err(|error| Failure::of_io(&what, &error))?;
    let reader = tcp
        .try_clone()
        .map_err(|error| Failure::of_io(&what, &error))?;
    let Some((prepared, name)) = prepared else {
        return Ok(Connection {
            writer: tcp,
            tls: None,
            learnt: Learnt {
                presented: false,
                asked: false,
            },
            early: Vec::new(),
            local,
            reader,
        });
    };
    let Prepared {
        config,
        asked,
        presented,
    } = prepared;
    let mut session = ClientConnection::new(config, name).map_err(|error| {
        Failure::new(
            TransportErrorKind::Other,
            TlsFailure::HandshakeRefused,
            &format!("{what} could not start: {error}"),
        )
    })?;
    tcp.set_read_timeout(Some(dial.patience))
        .and_then(|()| tcp.set_write_timeout(Some(dial.patience)))
        .map_err(|error| Failure::of_io(&what, &error))?;
    while session.is_handshaking() {
        if let Err(error) = session.complete_io(&mut tcp) {
            let learnt = Learnt {
                presented,
                asked: asked.load(Ordering::Acquire),
            };
            return Err(handshake_failure(&what, &error, learnt));
        }
    }
    let learnt = Learnt {
        presented,
        asked: asked.load(Ordering::Acquire),
    };
    let early = if session.protocol_version() == Some(ProtocolVersion::TLSv1_3) {
        let waited = started.elapsed().saturating_mul(2);
        settle(
            &mut tcp,
            &mut session,
            waited.clamp(SETTLE_LEAST, SETTLE_MOST),
            &what,
            learnt,
        )?
    } else {
        Vec::new()
    };
    tcp.set_read_timeout(None)
        .map_err(|error| Failure::of_io(&what, &error))?;
    Ok(Connection {
        writer: tcp,
        tls: Some(Arc::new(Mutex::new(session))),
        learnt,
        early,
        local,
        reader,
    })
}

/// A handshake that `complete_io` gave up on: the TLS error rustls kept, or the socket's.
fn handshake_failure(what: &str, error: &io::Error, learnt: Learnt) -> Failure {
    match error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<rustls::Error>())
    {
        Some(tls) => Failure::of_tls(what, tls, learnt.presented, learnt.asked),
        None if error.kind() == io::ErrorKind::UnexpectedEof => {
            // closed in the middle of the handshake without a word: what Asterisk does at TLS 1.2
            // to a client that has no certificate for it
            let tls = if learnt.asked {
                if learnt.presented {
                    TlsFailure::ClientCertificateRefused
                } else {
                    TlsFailure::ClientCertificateRequired
                }
            } else {
                TlsFailure::HandshakeRefused
            };
            Failure::new(
                TransportErrorKind::ConnectionReset,
                tls,
                &format!("{what} refused: the server closed the connection during the handshake"),
            )
        }
        None => Failure::of_io(what, error),
    }
}

/// Wait for a TLS 1.3 server to say whether it took this end's certificate (RFC 8446 §4.4.2: the
/// client's handshake is over before the server has read it), and keep what it sent meanwhile.
///
/// A server that takes the certificate sends its session tickets (§4.6.1), which end the wait. A
/// refusal is an alert, read here rather than lost to a reset on the first write. A server that
/// closes cleanly with nothing said refused too: Asterisk's way with a certificate its authority
/// did not sign.
fn settle(
    tcp: &mut TcpStream,
    session: &mut ClientConnection,
    wait: Duration,
    what: &str,
    learnt: Learnt,
) -> Result<Vec<u8>, Failure> {
    tcp.set_read_timeout(Some(wait))
        .map_err(|error| Failure::of_io(what, &error))?;
    let read = session.read_tls(tcp);
    match read {
        Ok(0) => {
            let tls = if learnt.presented {
                TlsFailure::ClientCertificateRefused
            } else {
                TlsFailure::None
            };
            return Err(Failure::new(
                TransportErrorKind::ConnectionReset,
                tls,
                &format!(
                    "{what} refused: the server closed the connection after the handshake, no \
                     alert reaching this end"
                ),
            ));
        }
        Ok(_) => {}
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ) =>
        {
            return Ok(Vec::new());
        }
        Err(error) => return Err(Failure::of_io(what, &error)),
    }
    session
        .process_new_packets()
        .map_err(|error| Failure::of_tls(what, &error, learnt.presented, learnt.asked))?;
    let mut early = Vec::new();
    // a close_notify here is read again, and reported, by the connection's first read
    plaintext(session, &mut early).map_err(|error| Failure::of_io(what, &error))?;
    // whatever the session owes the server after reading, an alert or a key update
    flush_records(session, tcp).map_err(|error| Failure::of_io(what, &error))?;
    Ok(early)
}

/// Move every decrypted byte the session holds into `into`; `true` once the server has said
/// `close_notify`.
fn plaintext(session: &mut ClientConnection, into: &mut Vec<u8>) -> io::Result<bool> {
    let mut buffer = [0_u8; CHUNK];
    loop {
        match session.reader().read(&mut buffer) {
            Ok(0) => return Ok(true),
            Ok(read) => into.extend_from_slice(buffer.get(..read).unwrap_or_default()),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(false),
            Err(error) => return Err(error),
        }
    }
}

/// Write every record the session has queued.
fn flush_records(session: &mut ClientConnection, tcp: &mut TcpStream) -> io::Result<()> {
    while session.wants_write() {
        session.write_tls(tcp)?;
    }
    Ok(())
}

impl Connection {
    /// The half that reads, for the reader's thread; this one keeps writing.
    pub(crate) fn split(self) -> (Writer, Reader) {
        (
            Writer {
                tcp: self.writer,
                tls: self.tls.clone(),
            },
            Reader {
                tcp: self.reader,
                tls: self.tls,
                learnt: self.learnt,
                heard: !self.early.is_empty(),
            },
        )
    }
}

/// What sends on a connection.
pub(crate) struct Writer {
    tcp: TcpStream,
    tls: Option<Arc<Mutex<ClientConnection>>>,
}

impl Writer {
    /// Write one message whole.
    pub(crate) fn send(&mut self, payload: &[u8]) -> io::Result<()> {
        match self.tls {
            None => self.tcp.write_all(payload),
            Some(ref tls) => {
                let mut session = tls.lock().unwrap_or_else(PoisonError::into_inner);
                session.writer().write_all(payload)?;
                flush_records(&mut session, &mut self.tcp)
            }
        }
    }

    /// Close the connection, which also ends its reader.
    pub(crate) fn close(&mut self) {
        if let Some(ref tls) = self.tls {
            let mut session = tls.lock().unwrap_or_else(PoisonError::into_inner);
            session.send_close_notify();
            let _ = flush_records(&mut session, &mut self.tcp);
        }
        let _ = self.tcp.shutdown(Shutdown::Both);
    }
}

/// What reads a connection, on a thread of its own.
pub(crate) struct Reader {
    tcp: TcpStream,
    tls: Option<Arc<Mutex<ClientConnection>>>,
    learnt: Learnt,
    /// Whether the server has said anything yet.
    heard: bool,
}

impl Reader {
    /// Block for the next bytes: `Ok` with what was read, or how the connection ended.
    pub(crate) fn next(&mut self, what: &str) -> Result<Vec<u8>, Ended> {
        let mut buffer = [0_u8; CHUNK];
        loop {
            let read = match self.tcp.read(&mut buffer) {
                Ok(0) => return Err(self.ended_quietly(what)),
                Ok(read) => read,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(self.broke(what, &error)),
            };
            let got = buffer.get(..read).unwrap_or_default();
            let Some(ref tls) = self.tls else {
                self.heard = true;
                return Ok(got.to_vec());
            };
            let mut session = tls.lock().unwrap_or_else(PoisonError::into_inner);
            let mut records = got;
            while !records.is_empty() {
                if let Err(error) = session.read_tls(&mut records) {
                    return Err(Ended::Failed(Failure::of_io(what, &error)));
                }
                if let Err(error) = session.process_new_packets() {
                    let mut writer = &self.tcp;
                    while session.wants_write() {
                        if session.write_tls(&mut writer).is_err() {
                            break;
                        }
                    }
                    return Err(Ended::Failed(Failure::of_tls(
                        what,
                        &error,
                        self.learnt.presented,
                        self.learnt.asked,
                    )));
                }
            }
            let mut out = Vec::new();
            let closed = match plaintext(&mut session, &mut out) {
                Ok(closed) => closed,
                Err(error) => return Err(Ended::Failed(Failure::of_io(what, &error))),
            };
            {
                let mut writer = &self.tcp;
                while session.wants_write() {
                    if session.write_tls(&mut writer).is_err() {
                        break;
                    }
                }
            }
            drop(session);
            if !out.is_empty() {
                self.heard = true;
                return Ok(out);
            }
            if closed {
                return Err(Ended::Closed);
            }
        }
    }

    /// The connection closed without an error. A server that asked for a certificate and closed
    /// before saying anything at all refused it, or the lack of one: Asterisk at TLS 1.2 does this
    /// for a certificate its authority did not sign.
    fn ended_quietly(&self, what: &str) -> Ended {
        if self.tls.is_some() && self.learnt.asked && !self.heard {
            let tls = if self.learnt.presented {
                TlsFailure::ClientCertificateRefused
            } else {
                TlsFailure::ClientCertificateRequired
            };
            return Ended::Failed(Failure::new(
                TransportErrorKind::ConnectionReset,
                tls,
                &format!(
                    "{what} closed by the server before it answered anything, and no alert came"
                ),
            ));
        }
        Ended::Closed
    }

    /// The socket's read failed.
    fn broke(&self, what: &str, error: &io::Error) -> Ended {
        match self.ended_quietly(what) {
            Ended::Failed(failure) => Ended::Failed(failure),
            Ended::Closed => Ended::Failed(Failure::of_io(what, error)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Dial, connect};
    use crate::TlsFailure;
    use sipral_core::endpoint::TransportErrorKind;
    use std::net::TcpListener;
    use std::time::Duration;

    #[test]
    fn nothing_listening_is_a_refused_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let remote = listener.local_addr().unwrap();
        drop(listener);
        let refused = connect(&Dial {
            remote,
            tls: None,
            patience: Duration::from_secs(2),
        })
        .err()
        .expect("nothing listens there");
        assert_eq!(refused.error, TransportErrorKind::ConnectionRefused);
        assert_eq!(refused.tls, TlsFailure::None);
        assert!(
            refused.detail.starts_with("TCP to 127.0.0.1:"),
            "{}",
            refused.detail
        );
    }
}
