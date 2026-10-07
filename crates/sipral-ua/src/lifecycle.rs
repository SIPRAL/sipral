// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! What happens to a stack whose machine goes to sleep, or moves.
//!
//! **The clock cannot tell.** A monotonic clock stops while the machine is
//! suspended, so after eight hours asleep every deadline still looks future.
//! Only the operating system knows, so the application calls these entry
//! points.
//!
//! **A registration that reads valid is not evidence.**
//! [`RegistrationState::Unverified`] is a binding a registrar granted over a
//! transport since suspended or lost: not `Registered` (unproven), not
//! `Failed` (nothing refused it), not `Idle` (a REGISTER did go out). Every
//! entry point here starts by producing it.
//!
//! **No interface and no resolver need opposite treatment.** With no
//! interface nothing can leave, so nothing is tried. With no resolver packets
//! flow and everything looks healthy, while every address learned from a name
//! may be wrong. Accounts whose registrar is a literal address are left
//! running.
//!
//! **Suspending sends nothing, on purpose.** A REGISTER with `Expires: 0` may
//! never leave a socket about to stop, and if it does, a de-registered device
//! cannot be woken by push. The window is spent on bounded, synchronous
//! bookkeeping instead.
//!
//! **The ladder does not double.** Each rung waits a random draw in
//! [32·T1, 64·T1]: §17.1.2.2's non-INVITE timeout, so a rung never overlaps
//! the previous one's request. Doubling already happens below, on the RFC 5626
//! §4.5 schedule; the random draw keeps a fleet that wakes together apart.

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use sipral_core::endpoint::TransportId;
use sipral_core::msg::{HostRef, Uri};

use crate::account::AccountId;
use crate::agent::UserAgent;
use crate::call::{CallHandle, CallState};
use crate::contact::{contact_at, contact_names};
use crate::error::UaError;
use crate::event::{RegistrationState, UaEvent};
use crate::registration::spread;
use crate::subscription::SubscriptionState;

/// What kind of link the application is on.
///
/// Coarse on purpose: only [`Link::Down`] changes what is done. The others
/// make a change of kind under the same address (Wi-Fi to cellular, a tunnel
/// coming up) visible as a change.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Link {
    /// There is no usable interface.
    #[default]
    Down,
    /// Cable.
    Wired,
    /// Wireless local network.
    Wifi,
    /// A mobile network.
    Cellular,
    /// A tunnel over one of the others.
    Tunnel,
}

impl core::fmt::Display for Link {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match *self {
            Self::Down => "down",
            Self::Wired => "wired",
            Self::Wifi => "wifi",
            Self::Cellular => "cellular",
            Self::Tunnel => "tunnel",
        })
    }
}

/// A network, in enough detail to decide what a change to another one needs.
///
/// The **address** is in every `Via` and `Contact`, so changing it
/// invalidates every transport and binding. The **interface** matters because
/// two networks can hand out the same address. **Whether names resolve** is
/// the one failure that leaves everything else looking healthy.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Network {
    link: Link,
    address: Option<IpAddr>,
    interface: Option<Box<str>>,
    resolves: bool,
}

impl Network {
    /// A network of this kind, with a resolver and nothing else said about it.
    #[must_use]
    pub const fn new(link: Link) -> Self {
        Self {
            link,
            address: None,
            interface: None,
            resolves: true,
        }
    }

    /// No usable interface.
    #[must_use]
    pub const fn down() -> Self {
        Self {
            link: Link::Down,
            address: None,
            interface: None,
            resolves: false,
        }
    }

    /// The local address this stack's transports are bound to.
    #[must_use]
    pub const fn address(mut self, address: IpAddr) -> Self {
        self.address = Some(address);
        self
    }

    /// The platform's identity for the interface, whatever shape it takes.
    ///
    /// Never parsed, only compared for equality: a name, an index or a UUID
    /// all work, as long as it is stable per interface.
    #[must_use]
    pub fn interface(mut self, name: &str) -> Self {
        self.interface = Some(Box::from(name));
        self
    }

    /// Whether a name can become an address on this network.
    #[must_use]
    pub const fn resolves(mut self, yes: bool) -> Self {
        self.resolves = yes;
        self
    }

    /// What kind of link it is.
    #[must_use]
    pub const fn link(&self) -> Link {
        self.link
    }

    /// The local address, when the application said one.
    #[must_use]
    pub const fn local(&self) -> Option<IpAddr> {
        self.address
    }

    /// The interface identity, when the application said one.
    #[must_use]
    pub fn interface_name(&self) -> Option<&str> {
        self.interface.as_deref()
    }

    /// Whether names resolve here.
    #[must_use]
    pub const fn has_resolver(&self) -> bool {
        self.resolves
    }
}

/// What a change of network is worth doing about.
///
/// [`UserAgent::network_changed`] takes both networks so that not every
/// change rebuilds everything; a laptop flipping between access points would
/// otherwise cause a re-registration storm.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Recovery {
    /// Nothing this stack uses changed. Nothing is sent.
    #[default]
    Nothing,
    /// The address stands, so the transports do, but a NAT upstream may have
    /// a new binding the registrar does not know.
    Reregister,
    /// A wake. The transport is tried first; a new one is asked for only if
    /// it turns out dead.
    Reprove,
    /// The address is gone. The application must open a transport again
    /// before anything can be sent.
    Rebuild,
    /// Packets leave but names do not resolve. Nothing is sent: every held
    /// address may now be wrong.
    Resolve,
    /// There is no interface. Nothing is tried until there is one.
    Detach,
}

impl Recovery {
    /// What is tried, in order, from the moment this is chosen.
    ///
    /// Every ladder starts with [`Rung::Distrust`] and all but
    /// [`Recovery::Detach`]'s end with [`Rung::GiveUp`]. `Detach` rests at no
    /// cost until the application reports a network.
    #[must_use]
    pub const fn ladder(self) -> &'static [Rung] {
        match self {
            Self::Nothing => &[],
            Self::Reregister => &[
                Rung::Distrust,
                Rung::Reregister,
                Rung::Reregister,
                Rung::GiveUp,
            ],
            Self::Reprove => &[
                Rung::Distrust,
                Rung::Reregister,
                Rung::WantTransport,
                Rung::Reregister,
                Rung::GiveUp,
            ],
            Self::Rebuild => &[
                Rung::Distrust,
                Rung::WantTransport,
                Rung::Reregister,
                Rung::WantAddress,
                Rung::Reregister,
                Rung::GiveUp,
            ],
            // ask for a new address first; the registrar usually has not
            // moved, so the cached one is tried if the application gives none
            Self::Resolve => &[
                Rung::Distrust,
                Rung::WantAddress,
                Rung::Reregister,
                Rung::WantAddress,
                Rung::Reregister,
                Rung::GiveUp,
            ],
            Self::Detach => &[Rung::Distrust],
        }
    }

    /// Where the machine sits while this ladder is being climbed.
    const fn state(self) -> LifecycleState {
        match self {
            Self::Nothing => LifecycleState::Running,
            Self::Reregister | Self::Reprove | Self::Rebuild => LifecycleState::Recovering,
            Self::Resolve => LifecycleState::ResolutionLost,
            Self::Detach => LifecycleState::InterfaceLost,
        }
    }

    /// What a change from one network to another is worth doing about.
    ///
    /// In order: no interface, then a changed address or interface (a dead
    /// transport carries nothing either way; a lost resolver can still be
    /// reported with [`UserAgent::name_resolution_lost`]), then no resolver,
    /// then a changed link kind or a resolver back, which both mean
    /// re-register.
    #[must_use]
    pub fn choose(from: &Network, to: &Network) -> Self {
        if to.link == Link::Down {
            return Self::Detach;
        }
        if from.address != to.address || from.interface != to.interface {
            return Self::Rebuild;
        }
        if !to.resolves {
            return Self::Resolve;
        }
        if from.link != to.link || !from.resolves {
            return Self::Reregister;
        }
        Self::Nothing
    }
}

impl core::fmt::Display for Recovery {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match *self {
            Self::Nothing => "nothing to do",
            Self::Reregister => "register again",
            Self::Reprove => "prove it again",
            Self::Rebuild => "rebuild the transports",
            Self::Resolve => "resolve again",
            Self::Detach => "no network",
        })
    }
}

/// One step of a recovery ladder.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Rung {
    /// Live bindings become [`RegistrationState::Unverified`], live
    /// subscriptions stop counting and schedules are cleared. Sends nothing,
    /// cannot fail.
    Distrust,
    /// A REGISTER for every distrusted binding. Bindings never started, given
    /// up or refused for good are left alone.
    Reregister,
    /// Ask the application for a transport, supplied with
    /// [`UserAgent::receive`] and then [`UserAgent::rebind`].
    WantTransport,
    /// Ask the application for an address: the name may resolve elsewhere
    /// on this network.
    WantAddress,
    /// Stop, and say so as [`UaEvent::RecoveryGaveUp`].
    GiveUp,
}

impl core::fmt::Display for Rung {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match *self {
            Self::Distrust => "distrust",
            Self::Reregister => "register again",
            Self::WantTransport => "a transport is wanted",
            Self::WantAddress => "an address is wanted",
            Self::GiveUp => "give up",
        })
    }
}

/// Where the lifecycle machine is.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum LifecycleState {
    /// Nothing is wrong.
    #[default]
    Running,
    /// The process stops shortly. Nothing is scheduled or sent.
    Suspending,
    /// Awake or moved, proving bindings again.
    Recovering,
    /// No interface. Nothing is tried until the network is reported back.
    InterfaceLost,
    /// Packets leave and names do not resolve.
    ResolutionLost,
    /// Every rung failed. Nothing happens until the application reports a
    /// change.
    GaveUp,
}

impl core::fmt::Display for LifecycleState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match *self {
            Self::Running => "running",
            Self::Suspending => "suspending",
            Self::Recovering => "recovering",
            Self::InterfaceLost => "no interface",
            Self::ResolutionLost => "no name resolution",
            Self::GaveUp => "gave up",
        })
    }
}

/// Why a recovery ladder ran out.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RecoveryFailure {
    /// No REGISTER was answered.
    Unreachable,
    /// A transport was asked for and the application did not bind one.
    NoTransport,
    /// An address was asked for and the application did not supply one.
    Unresolved,
}

impl core::fmt::Display for RecoveryFailure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match *self {
            Self::Unreachable => "nothing answered",
            Self::NoTransport => "no transport was bound",
            Self::Unresolved => "no address was supplied",
        })
    }
}

/// What was standing when the process was told it is about to stop.
///
/// Counts only, so nothing allocates in the suspend window. Nothing was sent.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Suspending {
    /// Bindings that were live and are now unverified.
    pub unverified: usize,
    /// Subscriptions that stopped being live.
    pub subscriptions: usize,
    /// Calls that were up, left untouched (see `docs/16-lifecycle.md`).
    pub calls: usize,
}

/// What the stack has to do, and when.
///
/// Answers "may the application stop polling?". `next` of `None` means no
/// deadline anywhere: a loop may block until a packet arrives.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Idle {
    /// The next deadline in the stack, as [`UserAgent::poll_timeout`].
    pub next: Option<Instant>,
    /// Bindings with something scheduled: a refresh, or a retry.
    pub registrations: usize,
    /// Subscriptions this layer is keeping alive.
    pub subscriptions: usize,
    /// Calls that exist, in any state.
    pub calls: usize,
    /// Transactions the endpoint is still running.
    pub transactions: usize,
    /// Dialogs the endpoint is keeping.
    pub dialogs: usize,
}

impl Idle {
    /// No deadline, no call, no transaction: only a packet or the
    /// application can start work again.
    #[must_use]
    pub const fn is_quiet(&self) -> bool {
        self.next.is_none() && self.calls == 0 && self.transactions == 0
    }
}

/// Where the machine is and how far up the ladder.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Machine {
    state: LifecycleState,
    ladder: &'static [Rung],
    /// The next rung to climb. One past the end means the ladder is finished.
    step: usize,
    due: Option<Instant>,
    /// Whether the application answered a want-rung, which decides the
    /// give-up reason.
    told: bool,
}

impl Machine {
    /// The rung that was climbed last, when one was.
    fn last(&self) -> Option<Rung> {
        self.ladder.get(self.step.checked_sub(1)?).copied()
    }
}

// -- what the application says -----------------------------------------------

impl UserAgent {
    /// Where the lifecycle machine is.
    #[must_use]
    pub const fn lifecycle(&self) -> LifecycleState {
        self.life.state
    }

    /// The operating system says this process stops shortly.
    ///
    /// Synchronous, bounded and infallible. Nothing is sent (see the module
    /// doc) and nothing stays scheduled.
    ///
    /// Live calls are left as they are: a lid closing for seconds should not
    /// hang them up.
    pub fn suspending(&mut self, now: Instant) -> Suspending {
        self.life = Machine {
            state: LifecycleState::Suspending,
            ..Machine::default()
        };
        let report = self.distrust();
        self.events.push_back(UaEvent::Lifecycle {
            state: LifecycleState::Suspending,
            rung: Some(Rung::Distrust),
            next_in: None,
        });
        // nothing is scheduled, keep-alives included: a suspended phone
        // relies on push (RFC 8599)
        self.settle_keepalives(now);
        report
    }

    /// The process is awake again.
    ///
    /// An unknown time has passed and any transport may be dead. Bindings are
    /// proved again on [`Recovery::Reprove`]'s ladder, current transport
    /// first.
    ///
    /// Safe to call without a matching [`UserAgent::suspending`]. Some
    /// platforms only notify on the way back.
    pub fn resumed(&mut self, now: Instant) {
        self.recover(Recovery::Reprove, now);
    }

    /// The network is a different one.
    ///
    /// Returns the decision ([`Recovery::choose`]); [`Recovery::ladder`] says
    /// what it sets off.
    pub fn network_changed(&mut self, from: &Network, to: &Network, now: Instant) -> Recovery {
        let recovery = Recovery::choose(from, to);
        self.recover(recovery, now);
        if recovery == Recovery::Rebuild {
            self.want_call_addresses();
        }
        recovery
    }

    /// A [`UaEvent::CallAddressWanted`] for every call that can be offered a
    /// new description, in handle order.
    ///
    /// Only on a change of address or interface: otherwise the media sockets
    /// still work.
    fn want_call_addresses(&mut self) {
        let mut moving: Vec<CallHandle> = self
            .calls
            .iter()
            .filter(|(_, held)| {
                held.dialog.is_some()
                    && match held.state {
                        CallState::Confirmed | CallState::Consulting => true,
                        early => early.is_early() && held.update_allowed,
                    }
            })
            .map(|(call, _)| *call)
            .collect();
        moving.sort_unstable();
        for call in moving {
            self.events.push_back(UaEvent::CallAddressWanted { call });
        }
    }

    /// There is no usable interface.
    ///
    /// Nothing is tried or scheduled until [`UserAgent::network_changed`];
    /// [`UserAgent::poll_timeout`] offers no deadlines from this layer.
    pub fn interface_lost(&mut self, now: Instant) {
        self.recover(Recovery::Detach, now);
    }

    /// Names no longer become addresses.
    ///
    /// Bindings whose registrar is a name stop counting as live; those at a
    /// literal address are left running.
    pub fn name_resolution_lost(&mut self, now: Instant) {
        self.recover(Recovery::Resolve, now);
    }

    /// Point an account at a transport and an address again.
    ///
    /// The answer to [`Rung::WantTransport`] and [`Rung::WantAddress`]. The
    /// contact is required: the old one may be unreachable after a move.
    ///
    /// An account on its own connection ([`crate::Account::on_stream`])
    /// ignores a `transport` of another protocol and keeps (or waits for) a
    /// connection of its own protocol, so nothing meant for TLS goes in clear.
    ///
    /// If a want-rung is waiting, the next rung is climbed at once.
    ///
    /// # Errors
    /// [`UaError::NoSuchAccount`].
    pub fn rebind(
        &mut self,
        account: AccountId,
        transport: TransportId,
        remote: SocketAddr,
        contact: &Uri,
        now: Instant,
    ) -> Result<(), UaError> {
        let config = self
            .accounts
            .get_mut(&account)
            .ok_or(UaError::NoSuchAccount)?;
        config.transport = transport;
        config.remote = remote;
        config.contact = contact.clone();
        self.keep_own_flow(account, transport);
        if matches!(
            self.life.last(),
            Some(Rung::WantTransport | Rung::WantAddress)
        ) {
            self.life.told = true;
            self.life.due = None;
            self.climb(now);
        }
        Ok(())
    }

    /// A named server was located again while [`Rung::WantAddress`] waited:
    /// climb at once, as [`UserAgent::rebind`] does.
    pub(crate) fn address_found(&mut self, now: Instant) {
        if matches!(self.life.last(), Some(Rung::WantAddress)) && self.life.due.is_some() {
            self.life.told = true;
            self.life.due = None;
            self.climb(now);
        }
    }

    /// This end is now reached at `to` instead of `from`: every account on
    /// `transport` whose `Contact` names `from` is rewritten and re-registered.
    ///
    /// Fed by a STUN answer about the signalling socket
    /// (`docs/06-nat.md`): `from` is the bound address or an earlier public
    /// one, `to` the new one. Only host and port change; a `Contact` with a
    /// name or another address is left alone.
    ///
    /// An account holding or seeking a binding sends a REGISTER at once,
    /// superseding anything in flight as [`UserAgent::retarget`] does. Until a
    /// 2xx, every REGISTER also carries the old `Contact` with `expires=0`
    /// (RFC 3261 §10.2.2), including a private address registered before the
    /// first STUN answer. The old `Contact` goes without `+sip.instance`:
    /// a registrar that matches removals by instance (Kamailio does) would
    /// otherwise remove the new binding too. Accounts not registering are
    /// only rewritten.
    ///
    /// A REGISTER that cannot leave gives
    /// [`UaEvent::RegistrationFailed`](crate::UaEvent::RegistrationFailed)
    /// with [`RegistrationFailure::Unreachable`](crate::RegistrationFailure::Unreachable)
    /// and a retry on the back-off.
    ///
    /// Calls already up switch `Contact` at their next target refresh
    /// (RFC 3261 §12.2); none is sent just for this.
    ///
    /// Returns how many accounts were rewritten.
    pub fn readdress(
        &mut self,
        transport: TransportId,
        from: SocketAddr,
        to: SocketAddr,
        now: Instant,
    ) -> usize {
        let mut moved = Vec::new();
        for (id, config) in &mut self.accounts {
            if config.transport != transport || !contact_names(&config.contact, from) {
                continue;
            }
            let Some(contact) = contact_at(&config.contact, to) else {
                continue;
            };
            let old = config.removal_contact_value();
            config.contact = contact;
            moved.push((*id, old, config.removal_contact_value()));
        }
        moved.sort_unstable_by_key(|(id, ..)| *id);
        let count = moved.len();
        // seen at an address other than the bound one: behind a NAT, so the
        // flow needs keep-alives (`crate::keepalive`)
        let behind = self
            .endpoint
            .bound_transport(transport)
            .is_some_and(|(_, local)| local != to);
        for (id, ..) in &moved {
            self.note_nat(*id, behind);
        }
        for (id, old, new) in moved {
            let Some(reg) = self.registrations.get_mut(&id) else {
                continue;
            };
            if reg.unregistering || (reg.transaction.is_none() && reg.due.is_none()) {
                continue;
            }
            reg.retire(old, &new);
            if self.send_register(id, false, now).is_err() {
                self.retry_later(id, None, None, None, now);
            }
        }
        self.drain(now);
        count
    }

    /// What is scheduled, and whether there is anything at all to do.
    #[must_use]
    pub fn idle(&self) -> Idle {
        let (transactions, dialogs) = self.endpoint.in_flight();
        Idle {
            next: self.poll_timeout(),
            registrations: self
                .registrations
                .values()
                .filter(|reg| reg.due.is_some())
                .count(),
            subscriptions: self.subscriptions.len(),
            calls: self.calls.len(),
            transactions,
            dialogs,
        }
    }
}

// -- the ladder --------------------------------------------------------------

impl UserAgent {
    /// When this layer next climbs a rung.
    pub(crate) const fn lifecycle_deadline(&self) -> Option<Instant> {
        self.life.due
    }

    /// The wait after a rung is over.
    pub(crate) fn fire_lifecycle_timers(&mut self, now: Instant) {
        if self.life.due.is_some_and(|at| at <= now) {
            self.life.due = None;
            self.climb(now);
        }
    }

    /// A registrar answered, so the path works.
    ///
    /// One account is enough: an account still failing on a working path is
    /// a registrar problem, handled by its own RFC 5626 §4.5 schedule.
    pub(crate) fn registration_proved(&mut self) {
        if self.life.state == LifecycleState::Running {
            return;
        }
        self.life = Machine::default();
        self.events.push_back(UaEvent::Lifecycle {
            state: LifecycleState::Running,
            rung: None,
            next_in: None,
        });
    }

    /// Start a ladder.
    fn recover(&mut self, recovery: Recovery, now: Instant) {
        let before = self.life.state;
        let state = recovery.state();
        self.life = Machine {
            state,
            ladder: recovery.ladder(),
            step: 0,
            due: None,
            told: false,
        };
        // keep-alives follow the state
        self.settle_keepalives(now);
        if self.life.ladder.is_empty() {
            // an event only if the state moved: a repeated one reads like a
            // recovery that just settled
            if state != before {
                self.events.push_back(UaEvent::Lifecycle {
                    state,
                    rung: None,
                    next_in: None,
                });
            }
            return;
        }
        self.climb(now);
    }

    /// Do the next rung, and say when the one after it happens.
    fn climb(&mut self, now: Instant) {
        let Some(rung) = self.life.ladder.get(self.life.step).copied() else {
            // only Detach's ladder ends here, and rests
            self.life.due = None;
            return;
        };
        self.life.step = self.life.step.saturating_add(1);
        let state = self.life.state;

        let after = self.perform(rung, now);
        // a rung may already have ended the ladder, e.g. a REGISTER answered
        // from a queued response
        if after == After::Stop || self.life.state != state {
            return;
        }
        let wait = if after == After::Wait {
            let entropy = self.endpoint.token();
            rung_wait(self.timer_n, &entropy)
        } else {
            Duration::ZERO
        };
        self.events.push_back(UaEvent::Lifecycle {
            state,
            rung: Some(rung),
            next_in: Some(wait),
        });
        if wait.is_zero() {
            self.climb(now);
        } else {
            self.life.due = Some(now + wait);
        }
    }

    /// One rung, and whether there is anything to wait for afterwards.
    fn perform(&mut self, rung: Rung, now: Instant) -> After {
        match rung {
            Rung::Distrust => {
                self.distrust();
                After::Now
            }
            // wait only if something went out; demoted subscriptions ride
            // the same rung
            Rung::Reregister => {
                let reached = self.reregister(now) | self.resubscribe(now);
                if reached { After::Wait } else { After::Now }
            }
            // only an event: the application owns sockets
            Rung::WantTransport => After::Wait,
            // accounts with a named server are also re-located here
            // (`crate::locate`)
            Rung::WantAddress => {
                self.relocate(now);
                After::Wait
            }
            Rung::GiveUp => {
                self.give_up_recovering();
                After::Stop
            }
        }
    }

    /// Stop believing anything that came off a network.
    ///
    /// Sends nothing and cannot fail: the first rung of every ladder and all
    /// [`UserAgent::suspending`] does.
    ///
    /// Bindings never started, given up or refused for good claimed nothing
    /// and are left alone; an account with no registrar stays
    /// `NotRegistering`, but its subscriptions are demoted. What is demoted
    /// is exactly what the next rung re-registers.
    fn distrust(&mut self) -> Suspending {
        // only a lost resolver affects some accounts and not others
        let only_named = self.life.state == LifecycleState::ResolutionLost;
        let named = if only_named {
            self.named_registrars()
        } else {
            Vec::new()
        };
        let mut unverified = 0_usize;
        let mut doubted = Vec::new();
        for (id, reg) in &mut self.registrations {
            if only_named && !named.contains(id) {
                continue;
            }
            reg.due = None;
            reg.transaction = None;
            // service route and GRUUs need a fresh 2xx (RFC 5627 §4.4)
            reg.learned = None;
            if matches!(
                reg.state,
                RegistrationState::Registering
                    | RegistrationState::Registered
                    | RegistrationState::Refreshing
                    | RegistrationState::Retrying
                    | RegistrationState::Restored
            ) {
                reg.state = RegistrationState::Unverified;
                unverified = unverified.saturating_add(1);
                doubted.push(*id);
            }
        }
        // reported at once, so no line keeps showing as ready
        doubted.sort_unstable();
        for account in doubted {
            self.events.push_back(UaEvent::Unverified { account });
        }

        // a busy lamp must not show pre-sleep state, and deadlines measured
        // across a suspend are stale; `Rung::Reregister` re-proves them
        let mut subscriptions = 0_usize;
        for held in self.subscriptions.values_mut() {
            if only_named && !named.contains(&held.account) {
                continue;
            }
            // all of them, not only live ones: Timer N and retry deadlines
            // are stale too
            held.state = SubscriptionState::Retrying;
            held.stop_timers();
            subscriptions = subscriptions.saturating_add(1);
        }

        Suspending {
            unverified,
            subscriptions,
            calls: self.calls.len(),
        }
    }

    /// A REGISTER for every unverified binding; `true` when one reached a
    /// transport.
    fn reregister(&mut self, now: Instant) -> bool {
        let waiting: Vec<AccountId> = self
            .registrations
            .iter()
            .filter(|(_, reg)| reg.state == RegistrationState::Unverified)
            .map(|(id, _)| *id)
            .collect();
        let mut sent = false;
        for account in waiting {
            // a failed send stays unverified for the next rung
            sent |= self.register(account, now).is_ok();
        }
        sent
    }

    /// The ladder is finished and nothing worked.
    ///
    /// An unanswered want-rung wins as the reason: "no transport was bound"
    /// tells the application where to look.
    fn give_up_recovering(&mut self) {
        let rung = self
            .life
            .ladder
            .get(self.life.step.saturating_sub(2))
            .copied()
            .unwrap_or(Rung::Distrust);
        let asked = self
            .life
            .ladder
            .iter()
            .find(|step| matches!(**step, Rung::WantTransport | Rung::WantAddress));
        let reason = match asked.filter(|_| !self.life.told) {
            Some(&Rung::WantTransport) => RecoveryFailure::NoTransport,
            Some(&Rung::WantAddress) => RecoveryFailure::Unresolved,
            _ => RecoveryFailure::Unreachable,
        };
        let unverified = self
            .registrations
            .values()
            .filter(|reg| reg.state == RegistrationState::Unverified)
            .count();
        self.life = Machine {
            state: LifecycleState::GaveUp,
            ..Machine::default()
        };
        self.events.push_back(UaEvent::RecoveryGaveUp {
            rung,
            reason,
            unverified,
        });
    }

    /// Accounts whose registrar is a name. One without a registrar uses an
    /// outbound proxy address and is never among them.
    fn named_registrars(&self) -> Vec<AccountId> {
        self.accounts
            .iter()
            .filter(|(_, config)| {
                config
                    .registrar()
                    .and_then(Uri::sip)
                    .is_some_and(|uri| matches!(uri.host, HostRef::Name(_)))
            })
            .map(|(id, _)| *id)
            .collect()
    }
}

/// Whether a rung left anything to wait for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum After {
    /// Nothing is in flight, so the next rung happens now.
    Now,
    /// Something went out, or somebody was asked for something.
    Wait,
    /// The ladder ended.
    Stop,
}

/// How long a rung waits before the next one is climbed.
/// A random draw in [32·T1, 64·T1] (see the module doc).
fn rung_wait(timer_n: Duration, entropy: &[u8]) -> Duration {
    let whole = u64::try_from(timer_n.as_millis()).unwrap_or(u64::MAX);
    let half = whole / 2;
    let span = whole - half;
    if span == 0 {
        return Duration::from_millis(whole);
    }
    Duration::from_millis(half + u64::from(spread(entropy)) % (span + 1))
}

#[cfg(test)]
mod tests {
    use super::{Idle, Link, Network, Recovery, RecoveryFailure, Rung, rung_wait};
    use crate::account::{Account, AccountId};
    use crate::agent::UserAgent;
    use crate::event::{RegistrationFailure, RegistrationState, UaEvent};
    use crate::lifecycle::LifecycleState;
    use crate::subscription::{Subscribe, SubscriptionEnd, SubscriptionState};
    use crate::{EndpointConfig, Input, TransportId, TransportProtocol, UaError, Uri};
    use sipral_core::msg::{Contacts, HeaderName, ParseMode, ParseScratch, RawMessage, parse};
    use std::net::{IpAddr, SocketAddr};
    use std::time::{Duration, Instant};

    const UDP: TransportId = TransportId(1);
    /// One this agent was never told about, so nothing can be written to it.
    const GONE: TransportId = TransportId(77);
    const HOUR: Duration = Duration::from_hours(1);
    /// 64·T1 with the default timings, which is every wait this ladder has.
    const RUNG: Duration = Duration::from_secs(32);

    fn local() -> SocketAddr {
        "192.0.2.1:5060".parse().expect("a local address")
    }

    fn registrar() -> SocketAddr {
        "192.0.2.9:5060".parse().expect("the registrar's address")
    }

    fn uri(text: &str) -> Uri {
        Uri::parse_str(text).expect("a URI")
    }

    fn agent(now: Instant) -> UserAgent {
        let mut agent = UserAgent::new(EndpointConfig::default(), [11; 32]).unwrap();
        agent
            .receive(
                Input::TransportBound {
                    transport: UDP,
                    protocol: TransportProtocol::Udp,
                    local: local(),
                    remote: None,
                },
                now,
            )
            .expect("binding a transport");
        agent
    }

    /// An account whose registrar is a name, so it needs a resolver.
    fn account() -> Account {
        Account::new(
            uri("sip:alice@example.com"),
            uri("sip:example.com"),
            uri("sip:alice@192.0.2.1"),
            UDP,
            registrar(),
        )
    }

    /// One pointed at a literal address, which never needed a resolver.
    fn literal_account() -> Account {
        Account::new(
            uri("sip:bob@192.0.2.9"),
            uri("sip:192.0.2.9"),
            uri("sip:bob@192.0.2.1"),
            UDP,
            registrar(),
        )
    }

    /// One with no registrar at all, whose requests go to a proxy that is not
    /// the registrar's address.
    fn trunk() -> Account {
        Account::unregistered(
            uri("sip:pbx@example.com"),
            uri("sip:pbx@192.0.2.1"),
            UDP,
            "198.51.100.20:5060".parse().expect("the proxy's address"),
        )
    }

    fn transmits(agent: &mut UserAgent) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        while let Some(transmit) = agent.poll_transmit() {
            out.push(transmit.payload.to_vec());
        }
        out
    }

    /// The `To` of every REGISTER in `out`, which says whose binding it is.
    fn registering(out: &[Vec<u8>]) -> Vec<String> {
        out.iter()
            .filter(|bytes| bytes.starts_with(b"REGISTER "))
            .map(|bytes| String::from_utf8_lossy(&header(bytes, HeaderName::To)).into_owned())
            .collect()
    }

    fn events(agent: &mut UserAgent) -> Vec<UaEvent> {
        let mut out = Vec::new();
        while let Some(event) = agent.poll_event() {
            out.push(event);
        }
        out
    }

    fn with<T>(bytes: &[u8], f: impl FnOnce(&RawMessage<'_>) -> T) -> T {
        let mut scratch = ParseScratch::new();
        f(&parse(bytes, &mut scratch, ParseMode::Lenient).expect("a message"))
    }

    fn header(bytes: &[u8], name: HeaderName<'_>) -> Vec<u8> {
        with(bytes, |message| {
            message.header(name).unwrap_or_default().to_vec()
        })
    }

    /// The 200 a registrar sends for a binding it kept.
    fn granted(request: &[u8], seconds: u32) -> Vec<u8> {
        let mut out = b"SIP/2.0 200 OK\r\n".to_vec();
        for (name, value) in [
            ("Via", header(request, HeaderName::Via)),
            ("From", header(request, HeaderName::From)),
            ("To", header(request, HeaderName::To)),
            ("Call-ID", header(request, HeaderName::CallId)),
            ("CSeq", header(request, HeaderName::CSeq)),
            ("Contact", header(request, HeaderName::Contact)),
        ] {
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(&value);
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(format!("Expires: {seconds}\r\n").as_bytes());
        out.extend_from_slice(b"Content-Length: 0\r\n\r\n");
        out
    }

    fn deliver(agent: &mut UserAgent, bytes: &[u8], now: Instant) {
        agent
            .receive(
                Input::Datagram {
                    transport: UDP,
                    remote: registrar(),
                    local: local(),
                    data: bytes,
                },
                now,
            )
            .expect("a response the agent can read");
    }

    /// One account, registered for an hour, everything drained.
    fn registered(now: Instant) -> (UserAgent, AccountId) {
        let mut agent = agent(now);
        let id = agent.add_account(account());
        agent.register(id, now).expect("a REGISTER");
        let mut out = transmits(&mut agent);
        let request = out.pop().expect("the REGISTER");
        deliver(&mut agent, &granted(&request, 3_600), now);
        let _ = events(&mut agent);
        (agent, id)
    }

    fn address(text: &str) -> IpAddr {
        text.parse().expect("an address")
    }

    fn wifi() -> Network {
        Network::new(Link::Wifi)
            .address(address("192.0.2.1"))
            .interface("en0")
    }

    // -- what suspending is allowed to do ------------------------------------

    #[test]
    fn suspending_writes_nothing_at_all() {
        // no de-registration in the suspend window
        let t0 = Instant::now();
        let (mut agent, _) = registered(t0);
        let report = agent.suspending(t0);
        assert_eq!(report.unverified, 1);
        assert!(
            transmits(&mut agent).is_empty(),
            "suspending put something on the wire"
        );
    }

    #[test]
    fn a_binding_stops_being_evidence_the_moment_the_machine_is_told_it_sleeps() {
        let t0 = Instant::now();
        let (mut agent, id) = registered(t0);
        assert_eq!(
            agent.registration_state(id),
            Some(RegistrationState::Registered)
        );
        agent.suspending(t0);
        assert_eq!(
            agent.registration_state(id),
            Some(RegistrationState::Unverified),
            "a cached registration still reading as valid is the failure"
        );
        assert_eq!(agent.lifecycle(), LifecycleState::Suspending);
    }

    #[test]
    fn a_suspended_stack_has_no_deadline_left_to_fire() {
        // C5: backgrounded with no call, the loop may block until a packet
        // arrives. Timer K has to run out first -- the transaction that
        // carried the REGISTER is the endpoint's, not this layer's
        let t0 = Instant::now();
        let (mut agent, _) = registered(t0);
        let settled = t0 + Duration::from_secs(6);
        agent.handle_timeout(settled);
        let _ = events(&mut agent);
        assert!(agent.poll_timeout().is_some(), "the refresh is scheduled");

        agent.suspending(settled);
        assert_eq!(agent.poll_timeout(), None);
        let idle = agent.idle();
        assert!(idle.is_quiet(), "{idle:?}");
        assert_eq!(idle.registrations, 0);
    }

    #[test]
    fn a_timer_that_fires_after_a_suspend_that_never_resumed_does_nothing() {
        // the shape of the crash: a background timer on a suspended stack
        let t0 = Instant::now();
        let (mut agent, id) = registered(t0);
        agent.suspending(t0);
        let _ = events(&mut agent);
        for hours in 1..=8 {
            agent.handle_timeout(t0 + HOUR * hours);
        }
        assert!(transmits(&mut agent).is_empty());
        assert!(events(&mut agent).is_empty());
        assert_eq!(
            agent.registration_state(id),
            Some(RegistrationState::Unverified)
        );
    }

    // -- resume ---------------------------------------------------------------

    #[test]
    fn a_resume_registers_again_before_anything_else_is_asked_for() {
        let t0 = Instant::now();
        let (mut agent, id) = registered(t0);
        agent.suspending(t0);
        let _ = transmits(&mut agent);
        let _ = events(&mut agent);

        let woke = t0 + Duration::from_millis(4);
        agent.resumed(woke);
        assert_eq!(agent.lifecycle(), LifecycleState::Recovering);
        let out = transmits(&mut agent);
        assert_eq!(
            out.len(),
            1,
            "one REGISTER, on the transport we already had"
        );
        assert!(
            out.first()
                .is_some_and(|bytes| bytes.starts_with(b"REGISTER"))
        );

        // and the 200 is what ends the ladder
        let request = out.first().cloned().unwrap_or_default();
        deliver(&mut agent, &granted(&request, 3_600), woke);
        assert_eq!(agent.lifecycle(), LifecycleState::Running);
        assert_eq!(
            agent.registration_state(id),
            Some(RegistrationState::Registered)
        );
    }

    #[test]
    fn a_resume_over_a_dead_transport_asks_for_one_instead_of_waiting() {
        // an unknown transport: a socket that did not survive the sleep
        let t0 = Instant::now();
        let (mut agent, id) = registered(t0);
        if let Some(config) = agent.accounts.get_mut(&id) {
            config.transport = GONE;
        }
        let _ = events(&mut agent);

        agent.resumed(t0);
        assert!(
            transmits(&mut agent).is_empty(),
            "nothing can be written to a transport that is not there"
        );
        let seen = events(&mut agent);
        assert!(
            seen.iter().any(|event| matches!(
                *event,
                UaEvent::Lifecycle {
                    rung: Some(Rung::WantTransport),
                    ..
                }
            )),
            "{seen:?}"
        );
        assert_eq!(agent.lifecycle(), LifecycleState::Recovering);
    }

    #[test]
    fn a_transport_bound_after_the_ask_is_used_at_once() {
        let t0 = Instant::now();
        let (mut agent, id) = registered(t0);
        if let Some(config) = agent.accounts.get_mut(&id) {
            config.transport = GONE;
        }
        agent.resumed(t0);
        let _ = events(&mut agent);

        agent
            .rebind(id, UDP, registrar(), &uri("sip:alice@192.0.2.7"), t0)
            .expect("an account that exists");
        let out = transmits(&mut agent);
        assert_eq!(out.len(), 1, "the REGISTER goes without waiting out a rung");
        let contact = header(
            out.first().map_or(&[][..], Vec::as_slice),
            HeaderName::Contact,
        );
        assert!(
            contact.windows(9).any(|w| w == b"192.0.2.7"),
            "the new contact has to be the one registered"
        );
    }

    #[test]
    fn a_wake_that_nothing_answers_gives_up_and_says_which_rung_it_was_on() {
        let t0 = Instant::now();
        let (mut agent, id) = registered(t0);
        if let Some(config) = agent.accounts.get_mut(&id) {
            config.transport = GONE;
        }
        agent.resumed(t0);
        let _ = events(&mut agent);

        // nothing is bound, so the ask times out and the last REGISTER cannot
        // be sent either
        let mut at = t0;
        for _ in 0..4 {
            at += RUNG;
            agent.handle_timeout(at);
        }
        let seen = events(&mut agent);
        let gave_up = seen.iter().find_map(|event| match *event {
            UaEvent::RecoveryGaveUp {
                rung,
                reason,
                unverified,
            } => Some((rung, reason, unverified)),
            _ => None,
        });
        assert_eq!(
            gave_up,
            Some((Rung::Reregister, RecoveryFailure::NoTransport, 1)),
            "{seen:?}"
        );
        assert_eq!(agent.lifecycle(), LifecycleState::GaveUp);
        assert_eq!(
            agent.poll_timeout(),
            None,
            "a stack that gave up costs nothing"
        );
    }

    #[test]
    fn several_accounts_are_proved_by_whichever_one_works() {
        // one healthy account proves the path; the other stays on its back-off
        let t0 = Instant::now();
        let (mut agent, healthy) = registered(t0);
        let broken = agent.add_account(literal_account());
        agent.register(broken, t0).expect("a REGISTER");
        let mut out = transmits(&mut agent);
        let second = out.pop().expect("the second REGISTER");
        deliver(&mut agent, &granted(&second, 3_600), t0);
        if let Some(config) = agent.accounts.get_mut(&broken) {
            config.transport = GONE;
        }
        let _ = events(&mut agent);

        agent.resumed(t0);
        let out = transmits(&mut agent);
        assert_eq!(out.len(), 1, "only the account that can be written to");
        let request = out.first().cloned().unwrap_or_default();
        deliver(&mut agent, &granted(&request, 3_600), t0);

        assert_eq!(agent.lifecycle(), LifecycleState::Running);
        assert_eq!(
            agent.registration_state(healthy),
            Some(RegistrationState::Registered)
        );
        assert_eq!(
            agent.registration_state(broken),
            Some(RegistrationState::Unverified),
            "nothing proved this one and nothing pretends otherwise"
        );
    }

    // -- a network that changed ----------------------------------------------

    #[test]
    fn a_notification_that_changed_nothing_this_stack_uses_does_nothing() {
        let t0 = Instant::now();
        let (mut agent, id) = registered(t0);
        let _ = events(&mut agent);
        assert_eq!(
            agent.network_changed(&wifi(), &wifi(), t0),
            Recovery::Nothing
        );
        assert!(transmits(&mut agent).is_empty());
        assert_eq!(
            agent.registration_state(id),
            Some(RegistrationState::Registered),
            "a binding nothing happened to is still a binding"
        );
    }

    #[test]
    fn a_roam_that_kept_the_address_registers_again_without_rebuilding() {
        let t0 = Instant::now();
        let (mut agent, _) = registered(t0);
        let _ = events(&mut agent);
        let tunnel = Network::new(Link::Tunnel)
            .address(address("192.0.2.1"))
            .interface("en0");
        assert_eq!(
            agent.network_changed(&wifi(), &tunnel, t0),
            Recovery::Reregister
        );
        assert_eq!(transmits(&mut agent).len(), 1, "the transport is kept");
    }

    #[test]
    fn an_address_that_changed_asks_for_a_transport_before_it_sends_anything() {
        let t0 = Instant::now();
        let (mut agent, _) = registered(t0);
        let _ = events(&mut agent);
        let moved = Network::new(Link::Wired)
            .address(address("198.51.100.4"))
            .interface("en5");
        assert_eq!(
            agent.network_changed(&wifi(), &moved, t0),
            Recovery::Rebuild
        );
        assert!(
            transmits(&mut agent).is_empty(),
            "the transport is bound to an address that is gone"
        );
        let seen = events(&mut agent);
        assert!(
            seen.iter().any(|event| matches!(
                *event,
                UaEvent::Lifecycle {
                    rung: Some(Rung::WantTransport),
                    ..
                }
            )),
            "{seen:?}"
        );
    }

    #[test]
    fn the_same_address_on_a_different_interface_is_still_a_rebuild() {
        // two offices handing out the same private address
        let elsewhere = Network::new(Link::Wifi)
            .address(address("192.0.2.1"))
            .interface("en1");
        assert_eq!(Recovery::choose(&wifi(), &elsewhere), Recovery::Rebuild);
    }

    #[test]
    fn an_interface_that_went_away_is_not_a_rebuild_but_a_detach() {
        assert_eq!(
            Recovery::choose(&wifi(), &Network::down()),
            Recovery::Detach
        );
    }

    // -- no interface --------------------------------------------------------

    #[test]
    fn losing_the_interface_stops_everything_and_tries_nothing() {
        let t0 = Instant::now();
        let (mut agent, id) = registered(t0);
        let settled = t0 + Duration::from_secs(6);
        agent.handle_timeout(settled);
        let _ = events(&mut agent);

        agent.interface_lost(settled);
        assert_eq!(agent.lifecycle(), LifecycleState::InterfaceLost);
        assert!(
            transmits(&mut agent).is_empty(),
            "there is nowhere for it to go"
        );
        assert_eq!(
            agent.registration_state(id),
            Some(RegistrationState::Unverified)
        );
        assert_eq!(
            agent.poll_timeout(),
            None,
            "a retry is not a smaller version of working"
        );

        // and it stays that way however long the application waits
        agent.handle_timeout(settled + HOUR);
        assert!(transmits(&mut agent).is_empty());
        assert_eq!(agent.lifecycle(), LifecycleState::InterfaceLost);
    }

    #[test]
    fn the_interface_coming_back_is_what_starts_anything_again() {
        let t0 = Instant::now();
        let (mut agent, _) = registered(t0);
        agent.interface_lost(t0);
        let _ = transmits(&mut agent);
        let _ = events(&mut agent);

        let back = Network::new(Link::Wifi)
            .address(address("192.0.2.1"))
            .interface("en0");
        assert_eq!(
            agent.network_changed(&Network::down(), &back, t0),
            Recovery::Rebuild
        );
        assert_eq!(agent.lifecycle(), LifecycleState::Recovering);
    }

    // -- no name resolution --------------------------------------------------

    #[test]
    fn losing_the_resolver_untrusts_the_bindings_that_needed_one_and_no_others() {
        // a named registrar is distrusted; a literal one keeps running
        let t0 = Instant::now();
        let (mut agent, named) = registered(t0);
        let literal = agent.add_account(literal_account());
        agent.register(literal, t0).expect("a REGISTER");
        let mut out = transmits(&mut agent);
        let request = out.pop().expect("the REGISTER");
        deliver(&mut agent, &granted(&request, 3_600), t0);
        let _ = events(&mut agent);

        agent.name_resolution_lost(t0);
        assert_eq!(agent.lifecycle(), LifecycleState::ResolutionLost);
        assert_eq!(
            agent.registration_state(named),
            Some(RegistrationState::Unverified)
        );
        let doubted: Vec<_> = events(&mut agent)
            .into_iter()
            .filter_map(|event| match event {
                UaEvent::Unverified { account } => Some(account),
                _ => None,
            })
            .collect();
        assert_eq!(
            doubted,
            vec![named],
            "the binding that needed a resolver is said to be unproved, and only it"
        );
        assert_eq!(
            agent.registration_state(literal),
            Some(RegistrationState::Registered),
            "a literal address does not stop being one when a resolver dies"
        );
        assert!(
            transmits(&mut agent).is_empty(),
            "an address learned from a name is not a thing to send to now"
        );
    }

    #[test]
    fn a_resolver_that_never_comes_back_gives_up_saying_an_address_was_wanted() {
        let t0 = Instant::now();
        let (mut agent, _) = registered(t0);
        agent.name_resolution_lost(t0);
        let _ = events(&mut agent);
        let mut at = t0;
        for _ in 0..4 {
            at += RUNG;
            agent.handle_timeout(at);
        }
        let seen = events(&mut agent);
        assert!(
            seen.iter().any(|event| matches!(
                *event,
                UaEvent::RecoveryGaveUp {
                    reason: RecoveryFailure::Unresolved,
                    ..
                }
            )),
            "{seen:?}"
        );
    }

    #[test]
    fn an_address_supplied_while_the_resolver_was_gone_is_used_at_once() {
        let t0 = Instant::now();
        let (mut agent, id) = registered(t0);
        agent.name_resolution_lost(t0);
        let _ = events(&mut agent);
        agent
            .rebind(
                id,
                UDP,
                "198.51.100.9:5060".parse().expect("an address"),
                &uri("sip:alice@192.0.2.1"),
                t0,
            )
            .expect("an account that exists");
        assert_eq!(transmits(&mut agent).len(), 1);
    }

    // -- an account with no registrar ----------------------------------------

    #[test]
    fn a_wake_a_move_and_a_lost_resolver_never_register_an_account_without_a_registrar() {
        let t0 = Instant::now();
        let (mut agent, _) = registered(t0);
        let pbx = agent.add_account(trunk());
        let _ = events(&mut agent);

        let report = agent.suspending(t0);
        agent.resumed(t0);
        let out = transmits(&mut agent);
        let to = registering(&out);
        assert!(
            to.len() == 1 && to.iter().all(|to| to.contains("alice")),
            "a wake re-proves the binding that exists and nothing else: {to:?}"
        );
        assert_eq!(
            report.unverified, 1,
            "only a binding that exists is doubted"
        );
        let request = out.first().cloned().unwrap_or_default();
        deliver(&mut agent, &granted(&request, 3_600), t0);
        assert_eq!(agent.lifecycle(), LifecycleState::Running);

        let tunnel = Network::new(Link::Tunnel)
            .address(address("192.0.2.1"))
            .interface("en0");
        assert_eq!(
            agent.network_changed(&wifi(), &tunnel, t0),
            Recovery::Reregister
        );
        let out = transmits(&mut agent);
        let to = registering(&out);
        assert!(
            to.len() == 1 && to.iter().all(|to| to.contains("alice")),
            "a roam re-registers the binding that exists and nothing else: {to:?}"
        );
        let request = out.first().cloned().unwrap_or_default();
        deliver(&mut agent, &granted(&request, 3_600), t0);

        // and a resolver that goes and never comes back, to the end of its
        // ladder
        agent.name_resolution_lost(t0);
        let mut out = transmits(&mut agent);
        let mut at = t0;
        for _ in 0..5 {
            at += RUNG;
            agent.handle_timeout(at);
            out.extend(transmits(&mut agent));
        }
        let to = registering(&out);
        assert!(
            !to.is_empty() && to.iter().all(|to| to.contains("alice")),
            "only the account whose registrar is a name is tried again: {to:?}"
        );
        assert_eq!(
            agent.registration_state(pbx),
            Some(RegistrationState::NotRegistering),
            "nothing that happened to the network is news about an account with no binding"
        );
    }

    #[test]
    fn a_stack_whose_only_account_never_registers_sends_nothing_on_a_wake() {
        let t0 = Instant::now();
        let mut agent = agent(t0);
        let pbx = agent.add_account(trunk());
        let report = agent.suspending(t0);
        agent.resumed(t0);
        let mut at = t0;
        for _ in 0..4 {
            at += RUNG;
            agent.handle_timeout(at);
        }
        assert!(
            transmits(&mut agent).is_empty(),
            "a wake put something on the wire for an account with no registrar"
        );
        assert_eq!(report.unverified, 0, "there was no binding to doubt");
        let seen = events(&mut agent);
        assert!(
            !seen.iter().any(|event| matches!(
                *event,
                UaEvent::Registering { .. } | UaEvent::RegistrationFailed { .. }
            )),
            "{seen:?}"
        );
        // no registrar to answer: the ladder runs out with nothing unverified
        assert!(
            seen.iter()
                .any(|event| matches!(*event, UaEvent::RecoveryGaveUp { unverified: 0, .. })),
            "{seen:?}"
        );
        assert_eq!(
            agent.registration_state(pbx),
            Some(RegistrationState::NotRegistering)
        );
    }

    // -- what a refresh over a dead transport does ---------------------------

    #[test]
    fn a_subscription_worked_on_by_a_timer_over_a_dead_transport_ends_as_an_event() {
        // B3, in the shape it actually happens: a background timer, a
        // subscription, a transport that is not there any more
        let t0 = Instant::now();
        let (mut agent, id) = registered(t0);
        let watched = agent
            .subscribe(
                id,
                &Subscribe::new(uri("sip:bob@example.com"), "dialog"),
                t0,
            )
            .expect("a subscription");
        let _ = transmits(&mut agent);
        let _ = events(&mut agent);
        if let Some(config) = agent.accounts.get_mut(&id) {
            config.transport = GONE;
        }

        // ten minutes on a dead transport: Timer N, the transaction giving
        // up, and re-subscriptions that cannot leave
        for tick in 1..=20 {
            agent.handle_timeout(t0 + Duration::from_secs(30 * tick));
            while let Some(transmit) = agent.poll_transmit() {
                // the retransmissions of the SUBSCRIBE that was already in
                // flight are the endpoint's and go where it sent the first
                assert_eq!(
                    transmit.transport, UDP,
                    "a transport that is gone was written to"
                );
            }
        }

        let told: Vec<(SubscriptionEnd, Option<Duration>)> = events(&mut agent)
            .into_iter()
            .filter_map(|event| match event {
                UaEvent::SubscriptionEnded {
                    subscription,
                    reason,
                    retry_in,
                    ..
                } if subscription == watched => Some((reason, retry_in)),
                _ => None,
            })
            .collect();
        assert_eq!(
            told.first().map(|(reason, _)| *reason),
            Some(SubscriptionEnd::NoNotify),
            "{told:?}"
        );
        assert_eq!(
            told.last(),
            Some(&(SubscriptionEnd::Unreachable, None)),
            "the last word is a reason code and no promise of another attempt"
        );
        assert_eq!(agent.subscription_state(watched), None);
    }

    #[test]
    fn a_registration_refreshed_over_a_dead_transport_is_an_event_and_not_an_abort() {
        // scheduled while the transport was alive
        let t0 = Instant::now();
        let (mut agent, id) = registered(t0);
        let _ = events(&mut agent);
        if let Some(config) = agent.accounts.get_mut(&id) {
            config.transport = GONE;
        }
        agent.handle_timeout(t0 + Duration::from_secs(3_060));
        let seen = events(&mut agent);
        // and another attempt follows: an unsendable refresh is not a refusal
        assert!(
            seen.iter().any(|event| matches!(
                *event,
                UaEvent::RegistrationFailed {
                    reason: RegistrationFailure::Unreachable,
                    retry_in: Some(_),
                    ..
                }
            )),
            "{seen:?}"
        );
        assert!(transmits(&mut agent).is_empty());
        assert_eq!(
            agent.registration_state(id),
            Some(RegistrationState::Retrying)
        );
    }

    #[test]
    fn what_a_notifier_said_before_the_sleep_stops_being_evidence() {
        // no pre-suspend lamp state may survive
        let t0 = Instant::now();
        let (mut agent, id) = registered(t0);
        let watched = agent
            .subscribe(
                id,
                &Subscribe::new(uri("sip:bob@example.com"), "dialog"),
                t0,
            )
            .expect("a subscription");
        // fake an active state, which is what dialog_info gates on
        if let Some(held) = agent.subscriptions.get_mut(&watched) {
            held.state = SubscriptionState::Active;
        }
        assert!(agent.dialog_info(watched).is_some());

        let report = agent.suspending(t0);
        assert_eq!(report.subscriptions, 1);
        assert!(
            agent.dialog_info(watched).is_none(),
            "the table stopped being evidence when the machine did"
        );
    }

    // -- the ladders themselves ----------------------------------------------

    #[test]
    fn every_ladder_starts_by_believing_nothing() {
        for recovery in [
            Recovery::Reregister,
            Recovery::Reprove,
            Recovery::Rebuild,
            Recovery::Resolve,
            Recovery::Detach,
        ] {
            assert_eq!(
                recovery.ladder().first(),
                Some(&Rung::Distrust),
                "{recovery} starts somewhere else"
            );
        }
        assert!(Recovery::Nothing.ladder().is_empty());
    }

    #[test]
    fn every_ladder_but_the_one_with_nowhere_to_go_ends_by_saying_so() {
        for recovery in [
            Recovery::Reregister,
            Recovery::Reprove,
            Recovery::Rebuild,
            Recovery::Resolve,
        ] {
            assert_eq!(
                recovery.ladder().last(),
                Some(&Rung::GiveUp),
                "{recovery} ends without saying so"
            );
        }
        // with no interface there is nothing to give up on, so it rests
        assert_eq!(Recovery::Detach.ladder(), &[Rung::Distrust]);
    }

    #[test]
    fn a_rung_never_fires_while_the_request_before_it_is_still_trying() {
        // 17.1.2.2 gives a non-INVITE transaction 64*T1 to conclude
        let timer_n = Duration::from_secs(32);
        for nonce in 0_u32..300 {
            let token = format!("{nonce:08x}{nonce:08x}").into_bytes();
            let wait = rung_wait(timer_n, &token);
            assert!(wait >= timer_n / 2, "{wait:?}");
            assert!(wait <= timer_n, "{wait:?}");
        }
    }

    #[test]
    fn the_wait_is_drawn_rather_than_fixed_so_a_fleet_does_not_converge() {
        let timer_n = Duration::from_secs(32);
        let mut seen = std::collections::HashSet::new();
        for nonce in 0_u32..500 {
            let token = format!("{nonce:08x}{nonce:08x}").into_bytes();
            seen.insert(rung_wait(timer_n, &token));
        }
        assert!(seen.len() > 100, "the draw is barely moving");
    }

    #[test]
    fn a_configuration_with_no_room_to_draw_in_still_waits() {
        assert_eq!(
            rung_wait(Duration::from_millis(1), b"ffffffff"),
            Duration::from_millis(1)
        );
        assert_eq!(rung_wait(Duration::ZERO, b"ffffffff"), Duration::ZERO);
    }

    // -- cheap when idle ------------------------------------------------------

    #[test]
    fn an_idle_stack_wakes_once_an_hour_per_account_and_for_nothing_else() {
        // C5, measured: one binding granted an hour, refreshed at 0.85 of it
        let t0 = Instant::now();
        let (mut agent, _) = registered(t0);
        let settled = t0 + Duration::from_secs(6);
        agent.handle_timeout(settled);
        let _ = events(&mut agent);

        let idle = agent.idle();
        assert_eq!(idle.next, Some(t0 + Duration::from_secs(3_060)));
        assert_eq!(idle.registrations, 1);
        assert_eq!(idle.calls, 0);
        assert_eq!(idle.transactions, 0, "Timer K has run out");
        assert!(!idle.is_quiet(), "there is still a refresh to do");
    }

    #[test]
    fn nothing_registered_and_nothing_dialled_is_nothing_to_do() {
        let t0 = Instant::now();
        let mut agent = agent(t0);
        let id = agent.add_account(account());
        assert_eq!(agent.registration_state(id), Some(RegistrationState::Idle));
        let idle = agent.idle();
        assert!(idle.is_quiet(), "{idle:?}");
        assert_eq!(idle.next, None);
    }

    #[test]
    fn what_is_scheduled_is_answerable_without_reading_an_event() {
        let t0 = Instant::now();
        let (mut agent, id) = registered(t0);
        agent
            .subscribe(
                id,
                &Subscribe::new(uri("sip:bob@example.com"), "dialog"),
                t0,
            )
            .expect("a subscription");
        let idle = agent.idle();
        assert_eq!(idle.subscriptions, 1);
        assert_eq!(idle.registrations, 1);
        assert_eq!(idle.calls, 0);
        assert!(idle.next.is_some());
    }

    #[test]
    fn an_idle_report_is_quiet_only_when_every_part_of_it_is() {
        let t0 = Instant::now();
        let busy = Idle {
            next: None,
            registrations: 0,
            subscriptions: 0,
            calls: 1,
            transactions: 0,
            dialogs: 1,
        };
        assert!(!busy.is_quiet());
        assert!(
            !Idle {
                next: Some(t0),
                calls: 0,
                ..busy
            }
            .is_quiet(),
            "a deadline is work even with nothing else standing"
        );
        assert!(
            Idle {
                next: None,
                calls: 0,
                ..busy
            }
            .is_quiet()
        );
    }

    // -- the guarantee --------------------------------------------------------

    #[test]
    fn nothing_the_lifecycle_is_told_can_fail_the_call_that_told_it() {
        // OS notification entry points never refuse or fault
        let t0 = Instant::now();
        let mut agent = agent(t0);
        agent.suspending(t0);
        agent.resumed(t0);
        agent.interface_lost(t0);
        agent.name_resolution_lost(t0);
        agent.network_changed(&Network::down(), &wifi(), t0);
        agent.handle_timeout(t0 + RUNG);
        // with no accounts the machine still ends in a defined state
        assert!(matches!(
            agent.lifecycle(),
            LifecycleState::Recovering | LifecycleState::GaveUp
        ));
    }

    #[test]
    fn rebinding_an_account_that_is_gone_is_an_error_and_not_a_fault() {
        let t0 = Instant::now();
        let (mut agent, id) = registered(t0);
        agent.remove_account(id);
        assert_eq!(
            agent.rebind(id, UDP, registrar(), &uri("sip:alice@192.0.2.1"), t0),
            Err(UaError::NoSuchAccount)
        );
    }

    // -- a NAT's public address ----------------------------------------------

    fn contact_of(agent: &UserAgent, id: AccountId) -> String {
        agent
            .account(id)
            .expect("the account")
            .contact()
            .as_str()
            .to_owned()
    }

    #[test]
    fn a_registered_account_moves_to_the_public_address_and_registers_it() {
        let t0 = Instant::now();
        let (mut agent, id) = registered(t0);
        let public: SocketAddr = "203.0.113.7:41000".parse().expect("an address");
        assert_eq!(agent.readdress(UDP, local(), public, t0), 1);
        assert_eq!(contact_of(&agent, id), "sip:alice@203.0.113.7:41000");
        let out = transmits(&mut agent);
        assert_eq!(registering(&out).len(), 1, "one REGISTER, at once");
        let contact = header(out.last().expect("the REGISTER"), HeaderName::Contact);
        assert_eq!(
            String::from_utf8_lossy(&contact),
            "<sip:alice@203.0.113.7:41000>, <sip:alice@192.0.2.1>;expires=0"
        );

        // and a later move starts from where the last one left it, asking
        // for both addresses it left to be dropped while neither REGISTER
        // has been answered
        let again: SocketAddr = "203.0.113.7:52000".parse().expect("an address");
        assert_eq!(agent.readdress(UDP, local(), again, t0), 0);
        assert_eq!(agent.readdress(UDP, public, again, t0), 1);
        assert_eq!(contact_of(&agent, id), "sip:alice@203.0.113.7:52000");
        let out = transmits(&mut agent);
        let contact = header(out.last().expect("the REGISTER"), HeaderName::Contact);
        assert_eq!(
            String::from_utf8_lossy(&contact),
            "<sip:alice@203.0.113.7:52000>, <sip:alice@192.0.2.1>;expires=0, \
             <sip:alice@203.0.113.7:41000>;expires=0"
        );

        // a mapping that moves back never asks for the address it is on to go
        assert_eq!(agent.readdress(UDP, again, public, t0), 1);
        let out = transmits(&mut agent);
        let contact = header(out.last().expect("the REGISTER"), HeaderName::Contact);
        assert_eq!(
            String::from_utf8_lossy(&contact),
            "<sip:alice@203.0.113.7:41000>, <sip:alice@192.0.2.1>;expires=0, \
             <sip:alice@203.0.113.7:52000>;expires=0"
        );
    }

    // -- keeping the registrar's flow open behind a NAT -----------------------

    /// What the registrar was sent that is a keep-alive: a double CRLF alone
    /// in a datagram, to its own address over the account's transport.
    fn pings(agent: &mut UserAgent) -> usize {
        let mut count = 0;
        while let Some(transmit) = agent.poll_transmit() {
            if &*transmit.payload == b"\r\n\r\n" {
                assert_eq!(transmit.destination, registrar());
                assert_eq!(transmit.transport, UDP);
                assert_eq!(transmit.protocol, TransportProtocol::Udp);
                count += 1;
            }
        }
        count
    }

    /// One account registered, then moved by a STUN answer onto `public`
    /// and registered again there, everything drained.
    fn readdressed_to(public: SocketAddr, now: Instant) -> (UserAgent, AccountId) {
        let (mut agent, id) = registered(now);
        agent.readdress(UDP, local(), public, now);
        let mut out = transmits(&mut agent);
        if let Some(request) = out.pop().filter(|bytes| bytes.starts_with(b"REGISTER ")) {
            deliver(&mut agent, &granted(&request, 3_600), now);
        }
        let _ = events(&mut agent);
        (agent, id)
    }

    /// Run every deadline up to `until`, and count the pings on the way.
    fn run_until(agent: &mut UserAgent, from: Instant, until: Instant) -> usize {
        let mut count = pings(agent);
        let mut now = from;
        while let Some(due) = agent.poll_timeout() {
            if due > until {
                break;
            }
            now = due.max(now);
            agent.handle_timeout(now);
            count += pings(agent);
            let _ = events(agent);
        }
        count
    }

    #[test]
    fn an_account_stun_showed_behind_a_nat_keeps_its_registrars_flow_open() {
        // lab failure: a call 330 s after the REGISTER was dropped by an
        // address-and-port-dependent filter (RFC 4787 §5); keep-alives must
        // go to the registrar itself, by default every 20 to 25 s
        let t0 = Instant::now();
        let public: SocketAddr = "203.0.113.7:41000".parse().expect("an address");
        let (mut agent, id) = readdressed_to(public, t0);
        assert!(agent.keeping_registrar_flow_alive(id));
        let first = agent
            .keepalive_deadline()
            .expect("a keep-alive is scheduled");
        assert!(
            first >= t0 + Duration::from_secs(20) && first <= t0 + Duration::from_secs(25),
            "{:?}",
            first - t0
        );
        // 330 s: at least thirteen of them, none further apart than 25 s
        let sent = run_until(&mut agent, t0, t0 + Duration::from_secs(330));
        assert!((13..=17).contains(&sent), "{sent} keep-alives in 330 s");
    }

    #[test]
    fn an_account_stun_found_on_its_own_address_sends_no_keep_alive() {
        // no NAT between the socket and the world: nothing to keep open
        let t0 = Instant::now();
        let (mut agent, id) = readdressed_to(local(), t0);
        assert!(!agent.keeping_registrar_flow_alive(id));
        assert_eq!(run_until(&mut agent, t0, t0 + Duration::from_secs(300)), 0);
    }

    #[test]
    fn the_keep_alive_interval_is_the_applications_and_can_be_turned_off() {
        let t0 = Instant::now();
        let public: SocketAddr = "203.0.113.7:41000".parse().expect("an address");
        let (mut agent, id) = readdressed_to(public, t0);
        assert_eq!(agent.registrar_keepalive(), Some(Duration::from_secs(25)));

        agent
            .keep_registrar_flows_alive(Some(Duration::from_secs(10)), t0)
            .expect("ten seconds");
        let first = agent
            .keepalive_deadline()
            .expect("drawn again from the new one");
        assert!(first <= t0 + Duration::from_secs(10), "{:?}", first - t0);
        // every 8 to 10 s
        let sent = run_until(&mut agent, t0, t0 + Duration::from_secs(100));
        assert!((10..=12).contains(&sent), "{sent} keep-alives in 100 s");

        for refused in [
            Duration::ZERO,
            Duration::from_millis(999),
            Duration::from_secs(121),
        ] {
            assert_eq!(
                agent.keep_registrar_flows_alive(Some(refused), t0),
                Err(UaError::InvalidKeepalive(refused))
            );
        }
        assert_eq!(agent.registrar_keepalive(), Some(Duration::from_secs(10)));

        agent
            .keep_registrar_flows_alive(None, t0)
            .expect("off is always taken");
        assert!(!agent.keeping_registrar_flow_alive(id));
        let later = t0 + Duration::from_secs(100);
        assert_eq!(
            run_until(&mut agent, later, later + Duration::from_secs(300)),
            0
        );
    }

    #[test]
    fn a_suspended_stack_keeps_nothing_open_and_a_proved_binding_starts_it_again() {
        // a phone asleep is woken by a push (RFC 8599), not by a process
        // that is not running; once the wake registers again, the flow is
        // kept open again
        let t0 = Instant::now();
        let public: SocketAddr = "203.0.113.7:41000".parse().expect("an address");
        let (mut agent, id) = readdressed_to(public, t0);
        agent.suspending(t0);
        assert!(!agent.keeping_registrar_flow_alive(id));
        assert_eq!(
            agent.keepalive_deadline(),
            None,
            "nothing scheduled while suspended"
        );
        assert_eq!(run_until(&mut agent, t0, t0 + Duration::from_secs(300)), 0);

        let woke = t0 + HOUR;
        agent.resumed(woke);
        let out = transmits(&mut agent);
        let request = out
            .into_iter()
            .rev()
            .find(|bytes| bytes.starts_with(b"REGISTER "))
            .expect("the wake registers again");
        assert!(
            agent.keeping_registrar_flow_alive(id),
            "the flow the binding is being proved on is kept open again"
        );
        deliver(&mut agent, &granted(&request, 3_600), woke);
        let _ = events(&mut agent);
        assert!(agent.keeping_registrar_flow_alive(id));
        assert!(run_until(&mut agent, woke, woke + Duration::from_secs(60)) >= 2);
    }

    #[test]
    fn a_binding_given_up_or_an_account_removed_is_no_longer_kept_open() {
        let t0 = Instant::now();
        let public: SocketAddr = "203.0.113.7:41000".parse().expect("an address");
        let (mut agent, id) = readdressed_to(public, t0);
        agent.unregister(id, t0).expect("the de-registration goes");
        let _ = transmits(&mut agent);
        assert!(!agent.keeping_registrar_flow_alive(id));

        let (mut agent, id) = readdressed_to(public, t0);
        agent.remove_account(id);
        assert!(!agent.keeping_registrar_flow_alive(id));
        assert_eq!(run_until(&mut agent, t0, t0 + Duration::from_secs(120)), 0);
    }

    /// Every keep-alive that left, on any transport, as (transport,
    /// destination, protocol), from `from` up to `until`.
    fn every_ping_until(
        agent: &mut UserAgent,
        from: Instant,
        until: Instant,
    ) -> Vec<(TransportId, SocketAddr, TransportProtocol, Instant)> {
        let mut seen = Vec::new();
        let mut now = from;
        loop {
            while let Some(transmit) = agent.poll_transmit() {
                if &*transmit.payload == b"\r\n\r\n" {
                    seen.push((
                        transmit.transport,
                        transmit.destination,
                        transmit.protocol,
                        now,
                    ));
                }
            }
            let _ = events(agent);
            match agent.poll_timeout() {
                Some(due) if due <= until => {
                    now = due.max(now);
                    agent.handle_timeout(now);
                }
                _ => return seen,
            }
        }
    }

    #[test]
    fn with_no_stun_and_no_interval_of_its_own_an_account_sends_no_keep_alive() {
        // the default is what it was: nothing leaves for a registrar unless
        // STUN showed the account behind a NAT
        let t0 = Instant::now();
        let (mut agent, id) = registered(t0);
        assert!(!agent.keeping_registrar_flow_alive(id));
        let seen = every_ping_until(&mut agent, t0, t0 + Duration::from_secs(300));
        assert!(seen.is_empty(), "{seen:?}");
    }

    #[test]
    fn an_account_with_an_interval_of_its_own_keeps_its_registrars_flow_open_without_stun() {
        // the trial's failure: STUN off, a NAT that forgets a UDP flow in
        // 30 s, and every call between two REGISTERs lost at it
        let t0 = Instant::now();
        let mut agent = agent(t0);
        let id = agent.add_account(
            account()
                .keepalive(Duration::from_secs(15))
                .expect("fifteen seconds"),
        );
        assert!(
            !agent.keeping_registrar_flow_alive(id),
            "nothing before the account registers"
        );
        agent.register(id, t0).expect("a REGISTER");
        let request = transmits(&mut agent).pop().expect("the REGISTER");
        deliver(&mut agent, &granted(&request, 3_600), t0);
        let _ = events(&mut agent);
        assert!(agent.keeping_registrar_flow_alive(id));

        let seen = every_ping_until(&mut agent, t0, t0 + Duration::from_secs(150));
        assert!((10..=13).contains(&seen.len()), "{} pings", seen.len());
        let mut last = t0;
        for (transport, destination, protocol, at) in seen {
            assert_eq!(
                (transport, destination, protocol),
                (UDP, registrar(), TransportProtocol::Udp)
            );
            let gap = at - last;
            assert!(
                gap >= Duration::from_secs(12) && gap <= Duration::from_secs(15),
                "{gap:?}"
            );
            last = at;
        }
    }

    #[test]
    fn an_accounts_own_interval_holds_with_the_agents_nat_keep_alive_off() {
        let t0 = Instant::now();
        let mut agent = agent(t0);
        agent
            .keep_registrar_flows_alive(None, t0)
            .expect("off is always taken");
        let id = agent.add_account(
            account()
                .keepalive(Duration::from_secs(20))
                .expect("twenty seconds"),
        );
        agent.register(id, t0).expect("a REGISTER");
        let request = transmits(&mut agent).pop().expect("the REGISTER");
        deliver(&mut agent, &granted(&request, 3_600), t0);
        let seen = every_ping_until(&mut agent, t0, t0 + Duration::from_secs(100));
        assert!((5..=6).contains(&seen.len()), "{} pings", seen.len());

        // and it stops with the binding
        let later = t0 + Duration::from_secs(100);
        agent
            .unregister(id, later)
            .expect("the de-registration goes");
        let _ = transmits(&mut agent);
        assert!(!agent.keeping_registrar_flow_alive(id));
    }

    #[test]
    fn an_interval_outside_one_second_to_two_minutes_is_refused_on_the_account() {
        for refused in [
            Duration::ZERO,
            Duration::from_millis(999),
            Duration::from_secs(121),
        ] {
            assert_eq!(
                account().keepalive(refused).map(|_| ()),
                Err(UaError::InvalidKeepalive(refused))
            );
        }
        let taken = account()
            .keepalive(Duration::from_secs(1))
            .expect("one second");
        assert_eq!(taken.keepalive_interval(), Some(Duration::from_secs(1)));
        assert_eq!(account().keepalive_interval(), None);
    }

    #[test]
    fn a_trunk_with_an_interval_of_its_own_keeps_its_proxys_flow_open() {
        // no binding to hold, but the calls the proxy sends in cross the
        // same NAT
        let t0 = Instant::now();
        let mut agent = agent(t0);
        let proxy: SocketAddr = "198.51.100.20:5060".parse().expect("the proxy");
        let id = agent.add_account(
            trunk()
                .keepalive(Duration::from_secs(10))
                .expect("ten seconds"),
        );
        // taken up by the next round of work, whatever it is
        agent.handle_timeout(t0);
        let seen = every_ping_until(&mut agent, t0, t0 + Duration::from_secs(60));
        assert!(agent.keeping_registrar_flow_alive(id));
        assert!((6..=7).contains(&seen.len()), "{} pings", seen.len());
        assert!(seen.iter().all(|(_, to, _, _)| *to == proxy));

        agent.suspending(t0 + Duration::from_secs(60));
        assert!(!agent.keeping_registrar_flow_alive(id));
    }

    #[test]
    fn an_account_on_a_stream_has_its_connection_pinged_at_its_own_interval() {
        // RFC 5626 §4.4.1 on the connection: the endpoint pings it at the
        // account's interval rather than at its own 25 s
        const TCP: TransportId = TransportId(2);
        let t0 = Instant::now();
        let mut agent = agent(t0);
        agent
            .receive(
                Input::TransportBound {
                    transport: TCP,
                    protocol: TransportProtocol::Tcp,
                    local: local(),
                    remote: Some(registrar()),
                },
                t0,
            )
            .expect("binding TCP");
        let streamed = Account::new(
            uri("sip:alice@example.com"),
            uri("sip:example.com;transport=tcp"),
            uri("sip:alice@192.0.2.1;transport=tcp"),
            TCP,
            registrar(),
        )
        .keepalive(Duration::from_secs(10))
        .expect("ten seconds");
        let id = agent.add_account(streamed);
        agent.register(id, t0).expect("a REGISTER");
        let request = transmits(&mut agent).pop().expect("the REGISTER");
        deliver(&mut agent, &granted(&request, 3_600), t0);
        let _ = events(&mut agent);
        assert!(agent.keeping_registrar_flow_alive(id));
        assert_eq!(
            agent.endpoint_ref().stream_keepalive(TCP),
            Some(Duration::from_secs(10))
        );
        let seen = every_ping_until(&mut agent, t0, t0 + Duration::from_secs(100));
        assert!((10..=12).contains(&seen.len()), "{} pings", seen.len());
        assert!(
            seen.iter()
                .all(|(transport, _, protocol, _)| *transport == TCP
                    && *protocol == TransportProtocol::Tcp)
        );

        // an account removed hands the connection back to the endpoint
        agent.remove_account(id);
        agent.handle_timeout(t0 + Duration::from_secs(100));
        assert_eq!(
            agent.endpoint_ref().stream_keepalive(TCP),
            Some(Duration::from_secs(25))
        );
    }

    #[test]
    fn a_register_sent_before_the_nat_answer_is_taken_back_by_the_one_after() {
        // the private address registered before STUN answered must be
        // removed with expires=0 (RFC 3261 §10.2.2), or calls fork to it
        let t0 = Instant::now();
        let mut agent = agent(t0);
        let id = agent.add_account(account());
        agent.register(id, t0).expect("a REGISTER");
        let first = transmits(&mut agent);
        let first_contact = header(first.last().expect("the REGISTER"), HeaderName::Contact);
        assert_eq!(
            String::from_utf8_lossy(&first_contact),
            "<sip:alice@192.0.2.1>"
        );

        let public: SocketAddr = "203.0.113.7:41000".parse().expect("an address");
        assert_eq!(agent.readdress(UDP, local(), public, t0), 1);
        let out = transmits(&mut agent);
        let request = out.last().expect("the REGISTER that moves it");
        let contacts = with(request, |message| match message.contact() {
            Ok(Contacts::Addrs(addrs)) => addrs
                .map(|addr| {
                    let addr = addr.expect("a contact");
                    (
                        String::from_utf8_lossy(addr.uri_bytes()).into_owned(),
                        addr.expires()
                            .ok()
                            .flatten()
                            .and_then(|value| value.require().ok()),
                    )
                })
                .collect::<Vec<_>>(),
            other => panic!("no contact list: {other:?}"),
        });
        assert_eq!(
            contacts,
            vec![
                ("sip:alice@203.0.113.7:41000".to_owned(), None),
                ("sip:alice@192.0.2.1".to_owned(), Some(0)),
            ]
        );

        // once the registrar has said yes, the private binding is gone and
        // the next refresh has nothing left to take back
        deliver(&mut agent, &granted(request, 3_600), t0);
        let _ = events(&mut agent);
        let later = t0 + Duration::from_secs(3_600);
        agent.handle_timeout(later);
        let refresh = transmits(&mut agent);
        let refresh = refresh
            .iter()
            .rev()
            .find(|bytes| bytes.starts_with(b"REGISTER "))
            .expect("a refresh");
        assert_eq!(
            String::from_utf8_lossy(&header(refresh, HeaderName::Contact)),
            "<sip:alice@203.0.113.7:41000>"
        );
    }

    #[test]
    fn the_contact_taken_back_names_its_address_and_not_the_instance() {
        // the lab's Kamailio keys by `+sip.instance`: a tagged removal took
        // the new binding too. The bare URI removes only the old one (RFC
        // 3261 §10.2.2); the new Contact keeps its tag
        let t0 = Instant::now();
        let mut agent = agent(t0);
        let id = agent
            .add_account(account().instance_id("urn:uuid:0c4a8f5e-2b1d-4e6a-9f00-5d3e2a1b7c90"));
        agent.register(id, t0).expect("a REGISTER");
        let _first = transmits(&mut agent);

        let public: SocketAddr = "203.0.113.7:41000".parse().expect("an address");
        assert_eq!(agent.readdress(UDP, local(), public, t0), 1);
        let out = transmits(&mut agent);
        let contact = header(out.last().expect("the REGISTER"), HeaderName::Contact);
        assert_eq!(
            String::from_utf8_lossy(&contact),
            "<sip:alice@203.0.113.7:41000>;\
             +sip.instance=\"<urn:uuid:0c4a8f5e-2b1d-4e6a-9f00-5d3e2a1b7c90>\", \
             <sip:alice@192.0.2.1>;expires=0"
        );
    }

    #[test]
    fn an_account_moved_whose_register_cannot_leave_is_still_counted_and_retried() {
        // the Contact moves even if the REGISTER cannot leave; that one is
        // retried on the back-off
        let t0 = Instant::now();
        let (mut agent, id) = registered(t0);
        let _ = events(&mut agent);
        if let Some(config) = agent.accounts.get_mut(&id) {
            config.transport = GONE;
        }
        let public: SocketAddr = "203.0.113.7:41000".parse().expect("an address");
        assert_eq!(agent.readdress(GONE, local(), public, t0), 1);
        assert_eq!(contact_of(&agent, id), "sip:alice@203.0.113.7:41000");
        assert!(events(&mut agent).iter().any(|event| matches!(
            *event,
            UaEvent::RegistrationFailed {
                reason: RegistrationFailure::Unreachable,
                retry_in: Some(_),
                ..
            }
        )));
    }

    #[test]
    fn an_account_never_registered_is_rewritten_and_sends_nothing() {
        let t0 = Instant::now();
        let mut agent = agent(t0);
        let id = agent.add_account(account());
        let trunk = agent.add_account(trunk());
        let public: SocketAddr = "203.0.113.7:5060".parse().expect("an address");
        assert_eq!(agent.readdress(UDP, local(), public, t0), 2);
        // the port is written out even where it is the default: the address
        // is the NAT's, and what the NAT said is a port as well as a host
        assert_eq!(contact_of(&agent, id), "sip:alice@203.0.113.7:5060");
        assert_eq!(contact_of(&agent, trunk), "sip:pbx@203.0.113.7:5060");
        assert!(transmits(&mut agent).is_empty());
    }

    #[test]
    fn a_contact_the_application_chose_is_left_alone() {
        let t0 = Instant::now();
        let mut agent = agent(t0);
        let named = agent.add_account(Account::new(
            uri("sip:carol@example.com"),
            uri("sip:example.com"),
            uri("sip:carol@phone.example.com"),
            UDP,
            registrar(),
        ));
        let elsewhere = agent.add_account(Account::new(
            uri("sip:dave@example.com"),
            uri("sip:example.com"),
            uri("sip:dave@192.0.2.1:5070"),
            UDP,
            registrar(),
        ));
        let other_transport = agent.add_account(Account::new(
            uri("sip:erin@example.com"),
            uri("sip:example.com"),
            uri("sip:erin@192.0.2.1"),
            GONE,
            registrar(),
        ));
        let public: SocketAddr = "203.0.113.7:5060".parse().expect("an address");
        assert_eq!(agent.readdress(UDP, local(), public, t0), 0);
        assert_eq!(contact_of(&agent, named), "sip:carol@phone.example.com");
        assert_eq!(contact_of(&agent, elsewhere), "sip:dave@192.0.2.1:5070");
        assert_eq!(contact_of(&agent, other_transport), "sip:erin@192.0.2.1");
    }

    #[test]
    fn a_registrar_that_refuses_for_good_is_not_woken_up_again_by_a_resume() {
        // a refused password is not re-sent on wake: it would lock the account
        let t0 = Instant::now();
        let mut agent = agent(t0);
        let id = agent.add_account(account());
        agent.register(id, t0).expect("a REGISTER");
        let mut out = transmits(&mut agent);
        let request = out.pop().expect("the REGISTER");
        let mut refusal = b"SIP/2.0 403 Forbidden\r\n".to_vec();
        for (name, value) in [
            ("Via", header(&request, HeaderName::Via)),
            ("From", header(&request, HeaderName::From)),
            ("To", header(&request, HeaderName::To)),
            ("Call-ID", header(&request, HeaderName::CallId)),
            ("CSeq", header(&request, HeaderName::CSeq)),
        ] {
            refusal.extend_from_slice(name.as_bytes());
            refusal.extend_from_slice(b": ");
            refusal.extend_from_slice(&value);
            refusal.extend_from_slice(b"\r\n");
        }
        refusal.extend_from_slice(b"Content-Length: 0\r\n\r\n");
        deliver(&mut agent, &refusal, t0);
        assert_eq!(
            agent.registration_state(id),
            Some(RegistrationState::Failed)
        );
        let _ = events(&mut agent);

        agent.resumed(t0);
        assert!(transmits(&mut agent).is_empty());
        assert_eq!(
            agent.registration_state(id),
            Some(RegistrationState::Failed)
        );
    }

    #[test]
    fn every_state_and_every_rung_reads_as_a_sentence() {
        let t0 = Instant::now();
        let (agent, _) = registered(t0);
        assert_eq!(agent.lifecycle(), LifecycleState::Running);
        assert_eq!(agent.lifecycle().to_string(), "running");
        assert_eq!(Rung::WantAddress.to_string(), "an address is wanted");
        assert_eq!(Recovery::Rebuild.to_string(), "rebuild the transports");
        assert_eq!(Link::Cellular.to_string(), "cellular");
        assert_eq!(
            RecoveryFailure::NoTransport.to_string(),
            "no transport was bound"
        );
        assert_eq!(
            RegistrationState::Unverified.to_string(),
            "unverified",
            "the state a wake produces has to read as a sentence too"
        );
    }

    #[test]
    fn a_network_says_back_what_it_was_told() {
        let net = wifi().resolves(false);
        assert_eq!(net.link(), Link::Wifi);
        assert_eq!(net.local(), Some(address("192.0.2.1")));
        assert_eq!(net.interface_name(), Some("en0"));
        assert!(!net.has_resolver());
        assert_eq!(Network::down().link(), Link::Down);
    }
}
