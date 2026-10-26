// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The sockets under one stack, and the one place everything that arrives on them is waited for.
//!
//! Every socket is read on a thread of its own, every connection is made on one, and every lookup
//! is answered on the resolver's; all of them post to one channel, which [`Network::wait`] drains.
//! The loop that owns the user agent stays single-threaded: it writes, waits, and feeds what it
//! was handed, in that order, as `docs/08-ffi.md` has a loop do.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::thread;
use std::time::Duration;

use rustls::pki_types::ServerName;
use sipral_core::endpoint::{Answer, Query, TransportErrorKind, TransportId, TransportProtocol};
use sipral_core::pin::CertificatePin;

use crate::failure::{Failure, TlsFailure};
use crate::resolver::Resolver;
use crate::stream::{Dial, Ended, Reader, TlsDial, Writer, connect};
use crate::trust::{ClientCertificate, PlatformRoots, Trust};

/// The largest datagram read.
const DATAGRAM: usize = 65_535;

/// How often a datagram socket's reader looks up from its socket, so a closed one ends.
const DATAGRAM_PATIENCE: Duration = Duration::from_millis(250);

/// How a [`Network`] connects and resolves.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct NetworkConfig {
    /// Which TLS servers are trusted. A connection's own pin wins over it.
    pub trust: Trust,
    /// Presented when a TLS server asks for a client certificate.
    pub client_certificate: Option<ClientCertificate>,
    /// The name servers to ask; empty for the system's configuration.
    pub name_servers: Vec<SocketAddr>,
    /// How long connecting, and then the TLS handshake, may each take.
    pub connect_timeout: Duration,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            trust: Trust::Platform,
            client_certificate: None,
            name_servers: Vec::new(),
            connect_timeout: Duration::from_secs(8),
        }
    }
}

/// What a TLS connection is checked against.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct StreamTarget {
    /// The name the server's certificate must carry (RFC 5922 §7.3 has it the domain of the SIP
    /// URI the user configured, not the host SRV turned it into); `None` checks the address.
    pub server_name: Option<String>,
    /// The one certificate trusted for this connection, in place of the [`Trust`].
    pub pin: Option<CertificatePin>,
}

impl StreamTarget {
    /// Checked against `server_name`, pinned to `pin` when there is one.
    #[must_use]
    pub const fn new(server_name: Option<String>, pin: Option<CertificatePin>) -> Self {
        Self { server_name, pin }
    }
}

/// Something that arrived, for the loop to hand to the user agent.
#[derive(Debug)]
#[non_exhaustive]
pub enum Happening {
    /// A datagram on a signalling socket: `Input::Datagram`.
    Datagram {
        /// The socket's transport.
        transport: TransportId,
        /// Where it came from.
        remote: SocketAddr,
        /// The socket's own address.
        local: SocketAddr,
        /// The packet.
        data: Vec<u8>,
    },
    /// Bytes off a connection: `Input::StreamData`.
    StreamData {
        /// The connection's transport.
        transport: TransportId,
        /// The bytes, in any chunking.
        data: Vec<u8>,
    },
    /// A connection asked for with [`Network::connect`] is up: `Input::TransportBound`, then
    /// `early` as `Input::StreamData` when it is not empty.
    Connected {
        /// The number it was asked for under.
        transport: TransportId,
        /// What it speaks, as it was asked for.
        protocol: TransportProtocol,
        /// This end of it.
        local: SocketAddr,
        /// The far end.
        remote: SocketAddr,
        /// What the server sent while a TLS 1.3 connection settled.
        early: Vec<u8>,
    },
    /// A connection could not be made: `Input::TransportFailed`, and the reason for the log, or
    /// for the C ABI's `sipral_transport_failure_t`.
    ConnectFailed {
        /// The number it was asked for under.
        transport: TransportId,
        /// What it would have spoken.
        protocol: TransportProtocol,
        /// Where it was to go.
        remote: SocketAddr,
        /// Why not.
        failure: Failure,
    },
    /// The far end closed a connection: `Input::StreamClosed`.
    StreamClosed {
        /// Which.
        transport: TransportId,
    },
    /// A connection broke: `Input::TransportFailed`.
    StreamFailed {
        /// Which.
        transport: TransportId,
        /// Why.
        failure: Failure,
    },
    /// A lookup asked for with [`Network::look_up`] was answered: `UserAgent::looked_up`.
    LookedUp {
        /// What the caller tagged it with: the account that asked.
        tag: u64,
        /// What was asked.
        query: Query,
        /// What the name servers said.
        answer: Answer,
    },
    /// A packet on a media socket opened with [`Network::open_media`].
    Media {
        /// The socket's address.
        local: SocketAddr,
        /// Where it came from.
        remote: SocketAddr,
        /// The packet.
        data: Vec<u8>,
    },
}

/// What the threads post: a happening, or a connection's writer on its way to the loop. Each
/// connection carries the serial it was started under, so news from one closed meanwhile is
/// dropped rather than mistaken for its successor's.
enum Arrival {
    Plain(Happening),
    Connected {
        serial: u64,
        writer: Writer,
        happening: Happening,
    },
    Stream {
        serial: u64,
        happening: Happening,
    },
}

/// Sends from one media socket, from any thread ([`Network::media_sender`]).
#[derive(Clone, Debug)]
pub struct MediaSender(Arc<UdpSocket>);

impl MediaSender {
    /// Send one packet to `to`.
    ///
    /// # Errors
    /// The send's own error; a refused datagram is one destination's, not the socket's.
    pub fn send(&self, to: SocketAddr, data: &[u8]) -> io::Result<()> {
        self.0.send_to(data, to).map(|_| ())
    }
}

/// One socket the network reads, and how to stop its reader.
struct Datagram {
    socket: Arc<UdpSocket>,
    open: Arc<AtomicBool>,
}

impl Drop for Datagram {
    fn drop(&mut self) {
        self.open.store(false, Ordering::Release);
    }
}

/// The sockets and connections under one stack.
pub struct Network {
    config: NetworkConfig,
    resolver: Resolver,
    inbox: Receiver<Arrival>,
    postbox: Sender<Arrival>,
    datagrams: HashMap<TransportId, Datagram>,
    streams: HashMap<TransportId, (u64, Writer)>,
    /// Connections being made, by serial.
    connecting: HashMap<TransportId, u64>,
    /// Serials closed while their connection was being made.
    abandoned: HashSet<u64>,
    serial: u64,
    media: HashMap<SocketAddr, Datagram>,
    platform: Arc<PlatformRoots>,
}

impl fmt::Debug for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Network")
            .field("datagrams", &self.datagrams.len())
            .field("streams", &self.streams.len())
            .field("connecting", &self.connecting.len())
            .field("media", &self.media.len())
            .finish_non_exhaustive()
    }
}

impl Drop for Network {
    fn drop(&mut self) {
        for (_, (_, mut writer)) in self.streams.drain() {
            writer.close();
        }
    }
}

impl Network {
    /// A network with nothing open yet, and its resolver started.
    ///
    /// # Errors
    /// The resolver could not be started: the system's configuration is unreadable, or no thread.
    pub fn new(config: NetworkConfig) -> io::Result<Self> {
        let resolver = if config.name_servers.is_empty() {
            Resolver::system()?
        } else {
            Resolver::with_servers(&config.name_servers)?
        };
        let (postbox, inbox) = channel();
        Ok(Self {
            config,
            resolver,
            inbox,
            postbox,
            datagrams: HashMap::new(),
            streams: HashMap::new(),
            connecting: HashMap::new(),
            abandoned: HashSet::new(),
            serial: 0,
            media: HashMap::new(),
            platform: Arc::default(),
        })
    }

    /// The resolver this network answers lookups with.
    #[must_use]
    pub const fn resolver(&self) -> &Resolver {
        &self.resolver
    }

    /// Bind a UDP socket at `local` as `transport`, and start reading it. Returns the address it
    /// was bound to, with the port the system chose when `local` named none.
    ///
    /// Tell the user agent `Input::TransportBound` with that address. A wildcard address cannot
    /// say where a datagram arrived (RFC 3581 §4), so name the interface.
    ///
    /// # Errors
    /// The bind's own error, or [`io::ErrorKind::InvalidInput`] for a wildcard address.
    pub fn bind_datagram(
        &mut self,
        transport: TransportId,
        local: SocketAddr,
    ) -> io::Result<SocketAddr> {
        let (datagram, bound) =
            self.read_datagrams(local, move |remote, local, data| Happening::Datagram {
                transport,
                remote,
                local,
                data,
            })?;
        self.datagrams.insert(transport, datagram);
        Ok(bound)
    }

    /// Open a UDP socket at `local` for one call's media, and start reading it. Returns the
    /// address it was bound to; packets arrive as [`Happening::Media`].
    ///
    /// # Errors
    /// The bind's own error, or [`io::ErrorKind::InvalidInput`] for a wildcard address.
    pub fn open_media(&mut self, local: SocketAddr) -> io::Result<SocketAddr> {
        let (datagram, bound) =
            self.read_datagrams(local, |remote, local, data| Happening::Media {
                local,
                remote,
                data,
            })?;
        self.media.insert(bound, datagram);
        Ok(bound)
    }

    /// Close a media socket; `false` when none is open there.
    pub fn close_media(&mut self, local: SocketAddr) -> bool {
        self.media.remove(&local).is_some()
    }

    /// Send one packet from the media socket at `local`.
    ///
    /// # Errors
    /// [`io::ErrorKind::NotFound`] when no media socket is open there, or the send's own error.
    pub fn send_media(&self, local: SocketAddr, to: SocketAddr, data: &[u8]) -> io::Result<()> {
        let Some(datagram) = self.media.get(&local) else {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("no media socket is open at {local}"),
            ));
        };
        datagram.socket.send_to(data, to).map(|_| ())
    }

    /// What sends from the media socket at `local` without the network: for an audio thread,
    /// which must not wait while the loop's thread sits in [`Network::wait`]. `None` when no
    /// media socket is open there. The socket closes once [`Network::close_media`] has run and
    /// the last sender is dropped.
    #[must_use]
    pub fn media_sender(&self, local: SocketAddr) -> Option<MediaSender> {
        self.media
            .get(&local)
            .map(|datagram| MediaSender(Arc::clone(&datagram.socket)))
    }

    /// Bind a socket and start a reader that posts what `made` makes of every packet.
    fn read_datagrams(
        &self,
        local: SocketAddr,
        made: impl Fn(SocketAddr, SocketAddr, Vec<u8>) -> Happening + Send + 'static,
    ) -> io::Result<(Datagram, SocketAddr)> {
        if local.ip().is_unspecified() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "{local} is a wildcard address, and what is sent from it has to say where it \
                     can be answered (RFC 3581 section 4, RFC 4566 c=): name the interface"
                ),
            ));
        }
        let socket = Arc::new(UdpSocket::bind(local)?);
        let bound = socket.local_addr()?;
        socket.set_read_timeout(Some(DATAGRAM_PATIENCE))?;
        let open = Arc::new(AtomicBool::new(true));
        let reading = Arc::clone(&socket);
        let still = Arc::clone(&open);
        let postbox = self.postbox.clone();
        thread::Builder::new()
            .name("sipral-net-udp".to_owned())
            .spawn(move || {
                let mut buffer = vec![0_u8; DATAGRAM];
                while still.load(Ordering::Acquire) {
                    // an error is the timeout, so a closed socket's reader notices, or an ICMP
                    // unreachable a previous send left, which is one destination's and not the
                    // socket's
                    if let Ok((read, remote)) = reading.recv_from(&mut buffer) {
                        let data = buffer.get(..read).unwrap_or_default().to_vec();
                        if postbox
                            .send(Arrival::Plain(made(remote, bound, data)))
                            .is_err()
                        {
                            break;
                        }
                    }
                }
            })?;
        Ok((Datagram { socket, open }, bound))
    }

    /// Start a connection to `remote` as `transport`: TCP for [`TransportProtocol::Tcp`] and
    /// [`TransportProtocol::Ws`], TLS checked against `target` for [`TransportProtocol::Tls`] and
    /// [`TransportProtocol::Wss`]. A WebSocket's handshake and frames are the user agent's.
    ///
    /// Returns at once; [`Happening::Connected`] or [`Happening::ConnectFailed`] follows. A
    /// transport already open or connecting under that number is closed first.
    pub fn connect(
        &mut self,
        transport: TransportId,
        protocol: TransportProtocol,
        remote: SocketAddr,
        target: StreamTarget,
    ) {
        self.close(transport);
        self.serial = self.serial.wrapping_add(1);
        let serial = self.serial;
        self.connecting.insert(transport, serial);
        let tls = matches!(protocol, TransportProtocol::Tls | TransportProtocol::Wss);
        let trust = self.config.trust.clone();
        let client = self.config.client_certificate.clone();
        let patience = self.config.connect_timeout;
        let platform = Arc::clone(&self.platform);
        let postbox = self.postbox.clone();
        let spawned = thread::Builder::new()
            .name("sipral-net-stream".to_owned())
            .spawn(move || {
                let what = format!("{} to {remote}", if tls { "TLS" } else { "TCP" });
                let made = match target.server_name {
                    Some(ref name) if tls => ServerName::try_from(name.clone()).map_err(|error| {
                        Failure::new(
                            TransportErrorKind::Other,
                            TlsFailure::HandshakeRefused,
                            &format!("{what} not tried: {name:?} is not a server name: {error}"),
                        )
                    }),
                    _ => Ok(ServerName::IpAddress(remote.ip().into())),
                }
                .and_then(|name| {
                    connect(&Dial {
                        remote,
                        tls: tls.then_some(TlsDial {
                            name,
                            trust: &trust,
                            pin: target.pin.as_ref(),
                            client: client.as_ref(),
                            platform: &platform,
                        }),
                        patience,
                    })
                });
                let mut connection = match made {
                    Ok(connection) => connection,
                    Err(failure) => {
                        let _ = postbox.send(Arrival::Stream {
                            serial,
                            happening: Happening::ConnectFailed {
                                transport,
                                protocol,
                                remote,
                                failure,
                            },
                        });
                        return;
                    }
                };
                let local = connection.local;
                let early = std::mem::take(&mut connection.early);
                let (writer, reader) = connection.split();
                let up = Arrival::Connected {
                    serial,
                    writer,
                    happening: Happening::Connected {
                        transport,
                        protocol,
                        local,
                        remote,
                        early,
                    },
                };
                if postbox.send(up).is_ok() {
                    read_stream(reader, &what, transport, serial, &postbox);
                }
            });
        if let Err(error) = spawned {
            self.connecting.remove(&transport);
            let _ = self.postbox.send(Arrival::Plain(Happening::ConnectFailed {
                transport,
                protocol,
                remote,
                failure: Failure::of_io("no thread to connect on:", &error),
            }));
        }
    }

    /// Close whatever is open or being opened as `transport`; `false` when nothing was. Nothing
    /// more is heard from it, not even its closing.
    pub fn close(&mut self, transport: TransportId) -> bool {
        if let Some(serial) = self.connecting.remove(&transport) {
            self.abandoned.insert(serial);
            return true;
        }
        if let Some((_, mut writer)) = self.streams.remove(&transport) {
            writer.close();
            return true;
        }
        self.datagrams.remove(&transport).is_some()
    }

    /// Write one message on `transport`: to `destination` on a datagram socket, on the connection
    /// otherwise.
    ///
    /// # Errors
    /// [`TransportErrorKind::Closed`] when nothing is open under that number. A connection whose
    /// write fails is closed here, and the failure is the one to tell the user agent. A refused
    /// datagram is one destination's, not the socket's: the transaction's own timer notices it
    /// (RFC 3261 §17), so it is not an error here.
    pub fn send(
        &mut self,
        transport: TransportId,
        destination: SocketAddr,
        payload: &[u8],
    ) -> Result<(), Failure> {
        if let Some(datagram) = self.datagrams.get(&transport) {
            let _ = datagram.socket.send_to(payload, destination);
            return Ok(());
        }
        let Some(&mut (_, ref mut writer)) = self.streams.get_mut(&transport) else {
            return Err(Failure::new(
                TransportErrorKind::Closed,
                TlsFailure::None,
                &format!("nothing is open as transport {}", transport.0),
            ));
        };
        match writer.send(payload) {
            Ok(()) => Ok(()),
            Err(error) => {
                if let Some((_, mut writer)) = self.streams.remove(&transport) {
                    writer.close();
                }
                Err(Failure::of_io(
                    &format!("the connection to {destination}"),
                    &error,
                ))
            }
        }
    }

    /// Ask `query` for the caller, tagged `tag`; [`Happening::LookedUp`] follows.
    pub fn look_up(&self, tag: u64, query: Query) {
        let postbox = self.postbox.clone();
        let asked = query.clone();
        self.resolver.look_up_then(query, move |answer| {
            let _ = postbox.send(Arrival::Plain(Happening::LookedUp {
                tag,
                query: asked,
                answer,
            }));
        });
    }

    /// Everything that has arrived, waiting up to `timeout` for the first of it (`None`: until
    /// something arrives). Empty when the time ran out.
    pub fn wait(&mut self, timeout: Option<Duration>) -> Vec<Happening> {
        let first = match timeout {
            Some(timeout) => self.inbox.recv_timeout(timeout).ok(),
            None => self.inbox.recv().ok(),
        };
        let mut out = Vec::new();
        let Some(first) = first else {
            return out;
        };
        let mut next = Some(first);
        while let Some(arrival) = next {
            if let Some(happening) = self.arrived(arrival) {
                out.push(happening);
            }
            next = self.inbox.try_recv().ok();
        }
        out
    }

    /// One arrival as the caller hears it, or nothing for news of a closed connection.
    fn arrived(&mut self, arrival: Arrival) -> Option<Happening> {
        match arrival {
            Arrival::Plain(happening) => Some(happening),
            Arrival::Connected {
                serial,
                mut writer,
                happening,
            } => {
                let transport = transport_of(&happening)?;
                if self.abandoned.remove(&serial)
                    || self.connecting.get(&transport) != Some(&serial)
                {
                    writer.close();
                    return None;
                }
                self.connecting.remove(&transport);
                self.streams.insert(transport, (serial, writer));
                Some(happening)
            }
            Arrival::Stream { serial, happening } => {
                let transport = transport_of(&happening)?;
                if let Happening::ConnectFailed { .. } = happening {
                    if self.abandoned.remove(&serial)
                        || self.connecting.get(&transport) != Some(&serial)
                    {
                        return None;
                    }
                    self.connecting.remove(&transport);
                    return Some(happening);
                }
                let current = self
                    .streams
                    .get(&transport)
                    .is_some_and(|&(open, _)| open == serial);
                if !current {
                    return None;
                }
                if matches!(
                    happening,
                    Happening::StreamClosed { .. } | Happening::StreamFailed { .. }
                ) {
                    self.streams.remove(&transport);
                }
                Some(happening)
            }
        }
    }
}

/// The transport a connection's happening is about.
const fn transport_of(happening: &Happening) -> Option<TransportId> {
    match *happening {
        Happening::Connected { transport, .. }
        | Happening::ConnectFailed { transport, .. }
        | Happening::StreamData { transport, .. }
        | Happening::StreamClosed { transport }
        | Happening::StreamFailed { transport, .. }
        | Happening::Datagram { transport, .. } => Some(transport),
        Happening::LookedUp { .. } | Happening::Media { .. } => None,
    }
}

/// Read a connection until it ends, posting what it says and how it ended.
fn read_stream(
    mut reader: Reader,
    what: &str,
    transport: TransportId,
    serial: u64,
    postbox: &Sender<Arrival>,
) {
    loop {
        let happening = match reader.next(what) {
            Ok(data) => Happening::StreamData { transport, data },
            Err(Ended::Closed) => Happening::StreamClosed { transport },
            Err(Ended::Failed(failure)) => Happening::StreamFailed { transport, failure },
        };
        let last = !matches!(happening, Happening::StreamData { .. });
        if postbox.send(Arrival::Stream { serial, happening }).is_err() || last {
            return;
        }
    }
}
