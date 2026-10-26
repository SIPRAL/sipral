// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! RFC 3263's lookups: NAPTR, SRV, A and AAAA, answered for the core's `Locator`.
//!
//! The procedure — what to ask, in which order, how to rank the answers — is the core's
//! (`sipral_core::endpoint::Locator`); this module only asks. Lookups run on one thread of their
//! own, a current-thread runtime under the resolver, so a slow name server never holds the loop
//! that waits for its answer, and several lookups are in flight at once.

use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hickory_resolver::TokioResolver;
use hickory_resolver::config::{ConnectionConfig, NameServerConfig, ResolverConfig};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::{RData, RecordType as DnsType};
use sipral_core::endpoint::{
    AddressFamily, Answer, LocateError, Located, Locator, Naptr, Query, Record, RecordType, Srv,
    TransportProtocol,
};
use sipral_core::msg::Uri;
use tokio::sync::mpsc::{UnboundedSender, unbounded_channel};

/// How long [`Resolver::look_up`] waits for one answer before calling it failed.
const PATIENCE: Duration = Duration::from_secs(10);

/// One lookup, and where its answer goes.
struct Job {
    query: Query,
    reply: Box<dyn FnOnce(Answer) + Send>,
}

/// NAPTR, SRV, A and AAAA lookups for the core, against the system's resolver configuration or the
/// name servers the application names.
///
/// Cheap to clone: every clone hands its lookups to the same thread, which ends when the last
/// clone is dropped.
#[derive(Clone)]
pub struct Resolver {
    jobs: UnboundedSender<Job>,
}

impl fmt::Debug for Resolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Resolver").finish_non_exhaustive()
    }
}

impl Resolver {
    /// A resolver configured as the system is: `/etc/resolv.conf` on Unix, the System
    /// Configuration framework on Apple platforms, the adapters on Windows.
    ///
    /// # Errors
    /// The system configuration could not be read, or the resolver's thread could not start;
    /// on Android, always [`io::ErrorKind::Unsupported`]: name the servers with
    /// [`Resolver::with_servers`].
    #[cfg(not(target_os = "android"))]
    pub fn system() -> io::Result<Self> {
        let builder = TokioResolver::builder_tokio().map_err(io::Error::other)?;
        Self::start(move || builder.build().map_err(io::Error::other))
    }

    /// See the other targets' `system`: Android's configuration is not read yet.
    ///
    /// # Errors
    /// Always [`io::ErrorKind::Unsupported`].
    #[cfg(target_os = "android")]
    pub fn system() -> io::Result<Self> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "the system's resolver configuration is not read on Android yet: name the servers",
        ))
    }

    /// A resolver that asks these name servers, over UDP and then TCP, and nothing else.
    ///
    /// # Errors
    /// No server was named, or the resolver's thread could not start.
    pub fn with_servers(servers: &[SocketAddr]) -> io::Result<Self> {
        if servers.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a resolver of its own needs at least one name server",
            ));
        }
        let name_servers = servers
            .iter()
            .map(|server| {
                let mut udp = ConnectionConfig::udp();
                udp.port = server.port();
                let mut tcp = ConnectionConfig::tcp();
                tcp.port = server.port();
                NameServerConfig::new(server.ip(), true, vec![udp, tcp])
            })
            .collect();
        let config = ResolverConfig::from_name_servers(name_servers);
        Self::start(move || {
            TokioResolver::builder_with_config(config, TokioRuntimeProvider::default())
                .build()
                .map_err(io::Error::other)
        })
    }

    /// Start the thread the lookups run on, with the resolver `build` makes there.
    fn start(
        build: impl FnOnce() -> io::Result<TokioResolver> + Send + 'static,
    ) -> io::Result<Self> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let (jobs, mut inbox) = unbounded_channel::<Job>();
        let (ready, started) = mpsc::channel::<io::Result<()>>();
        thread::Builder::new()
            .name("sipral-net-dns".to_owned())
            .spawn(move || {
                runtime.block_on(async move {
                    let resolver = match build() {
                        Ok(resolver) => {
                            let _ = ready.send(Ok(()));
                            resolver
                        }
                        Err(error) => {
                            let _ = ready.send(Err(error));
                            return;
                        }
                    };
                    while let Some(job) = inbox.recv().await {
                        let resolver = resolver.clone();
                        tokio::spawn(async move {
                            let answer = answer(&resolver, &job.query).await;
                            (job.reply)(answer);
                        });
                    }
                });
            })?;
        started
            .recv()
            .map_err(|_| io::Error::other("the resolver's thread ended before it started"))??;
        Ok(Self { jobs })
    }

    /// Ask `query`, and hand the answer to `reply` on the resolver's thread when it comes.
    ///
    /// A resolver that has stopped answers [`Answer::Failed`] at once, on this thread.
    pub fn look_up_then(&self, query: Query, reply: impl FnOnce(Answer) + Send + 'static) {
        if let Err(refused) = self.jobs.send(Job {
            query,
            reply: Box::new(reply),
        }) {
            (refused.0.reply)(Answer::Failed);
        }
    }

    /// Ask `query` and wait for the answer, ten seconds at most.
    #[must_use]
    pub fn look_up(&self, query: &Query) -> Answer {
        let (answered, answer) = mpsc::channel();
        self.look_up_then(query.clone(), move |found| {
            let _ = answered.send(found);
        });
        answer.recv_timeout(PATIENCE).unwrap_or(Answer::Failed)
    }

    /// RFC 3263 §4 to the end for `target` over `protocol`: every lookup the core's `Locator` asks
    /// for, made in turn, and the addresses it ranked.
    ///
    /// For a caller that needs an address before a stack exists; a stack's own accounts ask
    /// through their lookups instead.
    ///
    /// # Errors
    /// The [`LocateError`] the procedure ended with.
    pub fn locate(
        &self,
        target: &Uri,
        protocol: TransportProtocol,
        family: AddressFamily,
        naptr: bool,
    ) -> Result<Located, LocateError> {
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(1, |since| u64::from(since.subsec_nanos()) | 1);
        let mut locator = Locator::new(target, protocol, family, naptr, seed);
        while let Some(query) = locator.poll_query() {
            let answer = self.look_up(&query);
            locator.answer(&query, answer);
        }
        locator
            .take_outcome()
            .unwrap_or(Err(LocateError::Unanswered))
    }
}

/// A DNS name as the core writes one: no trailing dot.
fn plain(name: &str) -> Box<str> {
    name.strip_suffix('.').unwrap_or(name).into()
}

/// What the name servers say to `query`, as the core reads it.
async fn answer(resolver: &TokioResolver, query: &Query) -> Answer {
    let asked = match query.record {
        RecordType::Naptr => DnsType::NAPTR,
        RecordType::Srv => DnsType::SRV,
        RecordType::A => DnsType::A,
        RecordType::Aaaa => DnsType::AAAA,
    };
    let lookup = match resolver.lookup(&*query.name, asked).await {
        Ok(lookup) => lookup,
        Err(error) if error.is_no_records_found() => return Answer::Nothing,
        Err(_) => return Answer::Failed,
    };
    let records: Vec<Record> = lookup
        .answers()
        .iter()
        .filter_map(|record| {
            let ttl = Duration::from_secs(u64::from(record.ttl));
            match record.data {
                RData::NAPTR(ref naptr) if query.record == RecordType::Naptr => {
                    Some(Record::Naptr(Naptr::new(
                        naptr.order,
                        naptr.preference,
                        String::from_utf8_lossy(&naptr.flags).into_owned(),
                        String::from_utf8_lossy(&naptr.services).into_owned(),
                        plain(&naptr.replacement.to_utf8()),
                        ttl,
                    )))
                }
                RData::SRV(ref srv) if query.record == RecordType::Srv => {
                    Some(Record::Srv(Srv::new(
                        srv.priority,
                        srv.weight,
                        srv.port,
                        plain(&srv.target.to_utf8()),
                        ttl,
                    )))
                }
                RData::A(address) if query.record == RecordType::A => Some(Record::Address {
                    address: address.0.into(),
                    ttl,
                }),
                RData::AAAA(address) if query.record == RecordType::Aaaa => Some(Record::Address {
                    address: address.0.into(),
                    ttl,
                }),
                _ => None,
            }
        })
        .collect();
    if records.is_empty() {
        Answer::Nothing
    } else {
        Answer::Records(records)
    }
}
