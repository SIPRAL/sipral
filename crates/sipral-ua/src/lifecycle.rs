// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! What happens to a stack whose machine goes to sleep, or moves.
//!
//! Everything else in this crate assumes a network that is there. This module
//! is about the ways it stops being there, and it exists because that is where
//! the worst failures of a softphone live: not in a parser and not in a state
//! machine, but on a background timer that fires after a wake, over a transport
//! that died while nobody was watching, while thirty subscriptions are being
//! refreshed at once.
//!
//! **The clock is no help at all.** A monotonic clock does not advance while
//! the machine is suspended — that is what monotonic means on every platform
//! this runs on — so a stack that slept for eight hours comes back believing
//! that eight milliseconds passed. Every deadline it holds is still in the
//! future, the binding it was granted an hour ago still has fifty minutes to
//! run, and nothing it can measure contradicts any of that. It cannot find out
//! by looking. The operating system is the only thing that knows, which is why
//! these entry points exist and why they are the application's to call.
//!
//! **A registration that reads valid is not evidence.** The failure this is
//! designed against is a refresh going out over a dead transport on a timer,
//! and the reason no amount of "are we registered?" checking prevents it is
//! that the answer is yes and the answer is worthless. So there is a state for
//! that: [`RegistrationState::Unverified`] is a binding a registrar really did
//! grant, over a transport this process has since suspended or lost, which
//! nothing has proved since. It is not `Registered`, because it is not
//! evidence; it is not `Failed`, because nothing refused it; and it is not
//! `Idle`, because a REGISTER really did go out. Every entry point here begins
//! by producing it.
//!
//! **Losing an interface and losing a resolver are not the same failure.**
//! With no interface nothing can leave at all, so nothing is tried: a retry is
//! not a smaller version of working, and a stack that keeps trying on a dead
//! interface is a stack that keeps a phone warm in a pocket for nothing. With
//! a resolver gone the interface is fine and packets flow — which is exactly
//! what makes it dangerous, because everything looks healthy while every name
//! this stack holds an address for may now stand for somewhere else. The two
//! need opposite treatment, so they are different states with different
//! ladders, and the resolver one distinguishes accounts by whether their
//! registrar was written as a name at all: an account pointed at a literal
//! address never needed a resolver and is left running.
//!
//! **Suspending sends nothing, and that is a decision rather than an
//! omission.** The obvious thing to do in the window before the process stops
//! is a REGISTER with `Expires: 0`, so that the registrar stops offering calls
//! to a phone that cannot answer. It is wrong twice over. Nothing waits for
//! us — the datagram is handed to a socket the operating system is about to
//! stop servicing, and whether it left is not knowable from here — and if it
//! does leave, the damage is worse than the failure it was meant to avoid: a
//! de-registered device cannot be woken by a push notification at all, so the
//! polite thing to do on the way out is the thing that makes the phone
//! unreachable until somebody unlocks it. The window is spent on bookkeeping
//! instead, which is bounded by the number of accounts, synchronous, and
//! cannot fail.
//!
//! **The ladder does not double, and the layer below it does.** Every rung
//! waits 64·T1, drawn between half of it and all of it. That is not a number
//! chosen here: §17.1.2.2 gives a non-INVITE transaction exactly that long to
//! conclude, so a rung never fires while the request the previous rung sent is
//! still trying, and the ladder cannot outrun itself. Doubling on top of it
//! would only add dead time to a wake, where somebody is waiting — and the
//! doubling that a registrar needs protecting by is already there, one layer
//! down, on the RFC 5626 §4.5 schedule that every registration failure goes
//! on. The draw is that schedule's idea and is here for its reason: a fleet
//! that wakes together must not come back in the same millisecond.

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use sipral_core::endpoint::TransportId;
use sipral_core::msg::{HostRef, Uri};

use crate::account::AccountId;
use crate::agent::UserAgent;
use crate::contact::{contact_at, contact_names};
use crate::error::UaError;
use crate::event::{RegistrationState, UaEvent};
use crate::registration::spread;
use crate::subscription::SubscriptionState;

/// What kind of link the application is on.
///
/// Coarse on purpose: nothing here changes what is sent, and the one value
/// that changes what is *done* is [`Link::Down`]. The rest is carried so that
/// a change of kind over an unchanged address — a tunnel coming up, a phone
/// moving from Wi-Fi to a mobile network that kept the address — is visible as
/// a change at all, and so that an event says which way the phone went.
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

/// A network, described in as much detail as it takes to decide what to do
/// when it becomes a different one.
///
/// Three facts and no more, because three is what the decision needs. The
/// **address** is the one every `Via` and every `Contact` this stack writes
/// carries, so a change of it invalidates every transport and every binding at
/// once. The **interface** is the platform's own identity for the thing the
/// address is on, because two networks can hand out the same address and a
/// phone that walks from one office to the other gets away with it until a
/// call comes in. And **whether names resolve**, because that is the one
/// failure that leaves everything else looking healthy.
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
    /// Never parsed and never compared to anything but another one of itself,
    /// so a name, an index written out, or a universally unique identifier all
    /// work. What matters is that the same interface produces the same string
    /// twice and a different one does not.
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
/// The whole point of [`UserAgent::network_changed`] taking two of them is that
/// this choice can be made at all. A stack told only "something changed" has to
/// assume the worst and rebuild everything, which on a laptop that flips
/// between two access points all day is a re-registration storm the registrar
/// sees and the user does not.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Recovery {
    /// Nothing this stack uses is different. Nothing is done and nothing is
    /// sent.
    #[default]
    Nothing,
    /// The address still stands, so the transports do. What is upstream of it
    /// may not: a roam between access points on one subnet keeps the address
    /// and gets a new binding in whatever translates it, and the registrar is
    /// still holding the old one.
    Reregister,
    /// A wake. The transport probably survived and may not have, and there is
    /// no way to tell from here but to use it — so it is used first, and only
    /// a new one is asked for when it turns out to be dead.
    Reprove,
    /// The address is gone. Everything bound to it is unusable and the
    /// application has to open a transport again before anything can be sent.
    Rebuild,
    /// Packets can leave and names cannot be turned into addresses. Nothing is
    /// sent, because every address this stack holds may now stand for
    /// somewhere else.
    Resolve,
    /// There is no interface. Nothing is tried until there is one.
    Detach,
}

impl Recovery {
    /// What is tried, in order, from the moment this is chosen.
    ///
    /// Every ladder starts with [`Rung::Distrust`], which sends nothing and
    /// cannot fail, and every ladder but [`Recovery::Detach`]'s ends with
    /// [`Rung::GiveUp`]. That `Detach` has no `GiveUp` is the design and not an
    /// oversight: with no interface there is nothing to give up on, so the
    /// machine rests instead, costs nothing while it does, and waits to be
    /// told.
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
            // the cached address is asked about first and tried second. A
            // resolver usually dies while the registrar stays where it was, so
            // one datagram to the address already held is the cheapest thing
            // that can end this, and it only goes out once the application has
            // been asked for a better one and has not given one
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
    /// Ordered, and the order is the argument. No interface beats everything.
    /// A changed address beats a missing resolver, because a transport bound to
    /// an address that no longer exists carries nothing whether or not names
    /// resolve — and an application that finds it cannot resolve either says so
    /// with [`UserAgent::name_resolution_lost`], which moves the machine to the
    /// cheaper ladder. Below those, a kind of link that changed under an
    /// unchanged address is the roam case, and a resolver that came back is the
    /// same shape: the path works and the far end's idea of where we are does
    /// not.
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
    /// Stop believing. Every binding that read as live becomes
    /// [`RegistrationState::Unverified`], every live subscription stops being
    /// evidence about anything, and nothing this layer had scheduled stays
    /// scheduled. Sends nothing, touches no transport, and cannot fail.
    Distrust,
    /// Send a REGISTER for every binding that stopped being evidence. A
    /// binding the application never asked for is not started here, and one
    /// that was given up on purpose or refused for good is left alone.
    Reregister,
    /// Ask the application for a transport. Nothing here opens a socket, so a
    /// transport that cannot be written to is a thing only the application can
    /// replace — with [`UserAgent::receive`] and then [`UserAgent::rebind`].
    WantTransport,
    /// Ask the application for an address. The one this stack holds was
    /// learned from a name, and on this network the name may stand for
    /// somewhere else.
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
    /// Nothing is wrong. Bindings refresh themselves, subscriptions refresh
    /// themselves, and what this layer believes is what it last proved.
    #[default]
    Running,
    /// The operating system says the process stops shortly. Nothing is
    /// scheduled and nothing is sent.
    Suspending,
    /// Awake, or moved, and proving again what it used to believe.
    Recovering,
    /// There is no interface. Nothing is scheduled and nothing is tried, and
    /// it stays that way until the application says the network is back.
    InterfaceLost,
    /// Packets leave and names do not resolve.
    ResolutionLost,
    /// Every rung was climbed and none of them worked. Nothing more happens
    /// until the application says something changed.
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
    /// Every REGISTER that could be sent was sent and none of them was
    /// answered.
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
/// Counts and nothing else, because the window this is produced in is one
/// where an allocation that grows with the number of accounts is a cost with
/// no upper bound worth paying. Everything in it is already past tense by the
/// time it is read: the bindings have stopped being evidence, the
/// subscriptions have stopped being evidence, and nothing was sent about
/// either.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Suspending {
    /// Bindings that read as live and do not any more.
    pub unverified: usize,
    /// Subscriptions whose last notification stopped being evidence.
    pub subscriptions: usize,
    /// Calls that were up. Nothing was sent about them and nothing was
    /// changed: see `docs/16-lifecycle.md` for why a lid closing does not hang
    /// up a call.
    pub calls: usize,
}

/// What the stack has to do, and when.
///
/// The answer to "may this application stop polling?", which on a phone that
/// is backgrounded with no call is the difference between a battery that lasts
/// a day and one that does not. `next` is the whole answer: `None` means there
/// is no deadline anywhere in the stack, so a loop may block until a packet
/// arrives, or stop reading altogether if the platform is about to suspend it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Idle {
    /// The next deadline anywhere in the stack, including the endpoint's own.
    /// The same instant [`UserAgent::poll_timeout`] answers with.
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
    /// Whether there is nothing at all to do.
    ///
    /// No deadline, no call, no transaction — so no timer has to be run, and
    /// the only thing that can start work again is a packet or the
    /// application.
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
    /// Whether the application answered a [`Rung::WantTransport`] or a
    /// [`Rung::WantAddress`] on this ladder, which is what tells a give-up
    /// whether it is reporting an unreachable registrar or an application that
    /// never supplied what was asked for.
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
    /// Everything reached from here is synchronous, bounded by the number of
    /// accounts and subscriptions, and cannot fail. Nothing is sent — see the
    /// module note for why a graceful de-registration is the wrong thing to
    /// attempt in this window rather than the obvious one — and nothing stays
    /// scheduled, so a stack that is suspended and never resumed has no
    /// deadline to fire and no work to leave behind.
    ///
    /// Calls that are up are left exactly as they are. A lid closing and
    /// opening again is seconds, and hanging up a live call because the
    /// machine blinked is worse than finding out a few seconds later that it
    /// is gone.
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
        // the clock is taken and not read, and that is the whole shape of this
        // call: nothing here is scheduled against a time, because nothing will
        // be running to reach it
        let _ = now;
        report
    }

    /// The process is awake again.
    ///
    /// Arbitrary time has passed — arbitrary, not measurable, because the
    /// clock this stack is driven by did not run while the machine was
    /// suspended — and every transport may be dead. What was believed is
    /// dropped and proved again on [`Recovery::Reprove`]'s ladder: the
    /// transport that is already there is used first, because most wakes are
    /// short and it still works, and a new one is asked for only when it turns
    /// out not to.
    ///
    /// Safe to call without a matching [`UserAgent::suspending`]. Some
    /// platforms only notify on the way back.
    pub fn resumed(&mut self, now: Instant) {
        self.recover(Recovery::Reprove, now);
    }

    /// The network is a different one.
    ///
    /// Answers with what it decided, so that an application does not have to
    /// read an event to find out whether anything happened. See
    /// [`Recovery::choose`] for the decision and [`Recovery::ladder`] for what
    /// each answer sets off.
    pub fn network_changed(&mut self, from: &Network, to: &Network, now: Instant) -> Recovery {
        let recovery = Recovery::choose(from, to);
        self.recover(recovery, now);
        recovery
    }

    /// There is no usable interface.
    ///
    /// Distinct from [`UserAgent::name_resolution_lost`] because the recovery
    /// is the opposite one. Nothing can leave, so nothing is tried and nothing
    /// is scheduled: [`UserAgent::poll_timeout`] stops offering deadlines of
    /// this layer's, and the stack costs nothing until the application says
    /// the network is back with [`UserAgent::network_changed`].
    pub fn interface_lost(&mut self, now: Instant) {
        self.recover(Recovery::Detach, now);
    }

    /// Names no longer become addresses.
    ///
    /// The dangerous one, and the reason it is its own entry point: the
    /// interface is up and packets leave, so everything reads healthy, while
    /// every address this stack learned from a name may now stand for
    /// somewhere else. Bindings whose registrar was written as a name stop
    /// being evidence; bindings pointed at a literal address never needed a
    /// resolver and are left running.
    pub fn name_resolution_lost(&mut self, now: Instant) {
        self.recover(Recovery::Resolve, now);
    }

    /// Point an account at a transport and an address again.
    ///
    /// What [`Rung::WantTransport`] and [`Rung::WantAddress`] ask for. The
    /// contact is not optional: after a change of address the old one names
    /// somewhere the far end cannot reach, and a stack that let it stand would
    /// register a binding that silently receives nothing.
    ///
    /// When the machine is waiting to be told this, being told it climbs the
    /// next rung at once rather than at the end of the wait — the application
    /// answering in milliseconds is the normal case and there is nothing to be
    /// gained by making a wake take a further half minute.
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

    /// This end is reached at `to` now, where it was reached at `from`: every
    /// account on `transport` whose `Contact` names `from` is rewritten to
    /// name `to`, and says so to its registrar.
    ///
    /// What a STUN server's answer about the signalling socket turns into
    /// (`docs/06-nat.md`): `from` is the address the socket is bound to, or
    /// the public address an earlier answer gave, and `to` is the one this
    /// answer gives. Only the host and the port move. The user part, the
    /// parameters and the headers the application wrote stay as written, and
    /// a `Contact` written with a name or with some other address is one the
    /// application chose on purpose and is left alone.
    ///
    /// An account that holds a binding, or is on its way to one, sends a
    /// REGISTER at once with the new `Contact`, superseding anything in
    /// flight the way [`UserAgent::retarget`] does: a registrar holding the
    /// old one is routing this end's calls to an address that reaches
    /// nothing. The same REGISTER carries the old `Contact` with
    /// `expires=0`, and every one after it does until the registrar has
    /// answered one with a 2xx, so the old binding is removed rather than
    /// left to expire (RFC 3261 §10.2.2) — including the private address a
    /// REGISTER sent before the first STUN answer arrived. No `reg-id` is
    /// sent, so the registrar keys each binding by its URI (RFC 5626 §6) and
    /// removing the old one cannot touch the new. An account that was never
    /// asked to register, or is giving its binding up, is only rewritten.
    ///
    /// A REGISTER that cannot leave is what a refresh that cannot leave is:
    /// [`UaEvent::RegistrationFailed`](crate::UaEvent::RegistrationFailed)
    /// with [`RegistrationFailure::Unreachable`](crate::RegistrationFailure::Unreachable),
    /// and another attempt on the back-off.
    ///
    /// Calls already up keep the `Contact` their dialog was given until their
    /// next target refresh: every re-INVITE and UPDATE this stack sends — a
    /// hold, a resume, a session timer's refresh — carries the account's
    /// `Contact` as it is then (RFC 3261 §12.2), and none is sent just for
    /// this.
    ///
    /// Answers how many accounts were rewritten, whether or not their
    /// REGISTERs could leave.
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
            let old = config.register_contact_value(true);
            config.contact = contact;
            moved.push((*id, old, config.register_contact_value(true)));
        }
        moved.sort_unstable_by_key(|(id, ..)| *id);
        let count = moved.len();
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
    /// One account is enough. The ladder is about whether anything can leave
    /// this machine and come back, not about whether every account is happy —
    /// an account that still fails against a working path is a registrar
    /// problem, and it has its own RFC 5626 §4.5 schedule for that.
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
        if self.life.ladder.is_empty() {
            // A ladder with no rungs is the decision that nothing needs doing.
            // Saying so is worth an event only when the state moved: an event
            // that repeats the state the stack is already in reads, from a C
            // application, exactly like a recovery that has just settled, and
            // a network change that changed nothing would announce one every
            // time it was reported.
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
            // only Detach's ladder ends without a GiveUp rung, and resting is
            // what it is for
            self.life.due = None;
            return;
        };
        self.life.step = self.life.step.saturating_add(1);
        let state = self.life.state;

        let after = self.perform(rung, now);
        // the last rung has already moved the machine somewhere else, and a
        // rung can prove the path on its way past -- a REGISTER answered out
        // of a queue that was already full -- in which case the ladder it was
        // on is gone by now
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
            // a REGISTER that never reached a transport leaves nothing in
            // flight, and waiting out a transaction that does not exist is
            // half a minute of a wake spent on nothing. A demoted
            // subscription rides the same rung, for the same reason it was
            // demoted alongside the registrations in the first place
            Rung::Reregister => {
                let reached = self.reregister(now) | self.resubscribe(now);
                if reached { After::Wait } else { After::Now }
            }
            // an event and nothing else. Whoever owns the socket and whoever
            // owns the resolver is the application, and this is the only way
            // to reach either of them
            Rung::WantTransport | Rung::WantAddress => After::Wait,
            Rung::GiveUp => {
                self.give_up_recovering();
                After::Stop
            }
        }
    }

    /// Stop believing anything that came off a network.
    ///
    /// Sends nothing and cannot fail, which is what makes it the first rung of
    /// every ladder and the only thing [`UserAgent::suspending`] does.
    ///
    /// A binding that was never asked for is not started, one that was given
    /// up on purpose stays given up, and one that was refused for good is left
    /// refused — none of those claimed anything, so there is nothing to stop
    /// believing. An account with no registrar never had a binding to claim
    /// and stays `NotRegistering`; its subscriptions are not a binding and are
    /// demoted like anybody's. What is left is exactly the set the next rung
    /// re-registers.
    fn distrust(&mut self) -> Suspending {
        // only a lost resolver divides the accounts. Every other way of losing
        // a network loses it for all of them at once
        let only_named = self.life.state == LifecycleState::ResolutionLost;
        let named = if only_named {
            self.named_registrars()
        } else {
            Vec::new()
        };
        let mut unverified = 0_usize;
        for (id, reg) in &mut self.registrations {
            if only_named && !named.contains(id) {
                continue;
            }
            reg.due = None;
            reg.transaction = None;
            // the service route and the GRUUs came off the same network, and
            // the lapse that would stop them being used is measured on the
            // clock that stopped. RFC 5627 §4.4 wants an active registration
            // before a GRUU is used, and nothing here is one until a 2xx says
            // it all again
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
            }
        }

        // a lamp showing what a notifier said before the machine slept is the
        // one wrong answer a busy lamp field must never give, so the table
        // stops answering the moment there is any doubt. Its own deadlines go
        // with it -- an `Instant` frozen across the suspend would otherwise
        // read a stale refresh or a stale lapse as still ahead, which is not
        // evidence of anything either. `Rung::Reregister` is what re-proves it
        let mut subscriptions = 0_usize;
        for held in self.subscriptions.values_mut() {
            if only_named && !named.contains(&held.account) {
                continue;
            }
            // every one of them, not only the live ones. A subscription
            // waiting on its first NOTIFY has a Timer N scheduled and is not
            // live; one already retrying has a retry scheduled and is not
            // live either. Both of those deadlines were measured against a
            // clock that has since stopped, which is what this rung exists to
            // disbelieve — and a subscription that has ended for good has no
            // record here at all, so there is nothing in this table that
            // should keep what it had scheduled
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

    /// A REGISTER for everything that stopped being evidence.
    ///
    /// `true` when at least one of them reached a transport, which is what
    /// decides whether there is anything to wait for.
    fn reregister(&mut self, now: Instant) -> bool {
        let waiting: Vec<AccountId> = self
            .registrations
            .iter()
            .filter(|(_, reg)| reg.state == RegistrationState::Unverified)
            .map(|(id, _)| *id)
            .collect();
        let mut sent = false;
        for account in waiting {
            // a send that fails is not an error of this ladder: it is what the
            // next rung is for, and the account stays unverified until
            // something proves otherwise
            sent |= self.register(account, now).is_ok();
        }
        sent
    }

    /// The ladder is finished and nothing worked.
    ///
    /// The reason is about the ladder rather than about its last rung: one
    /// that asked for something and was never answered says so, whatever it
    /// happened to try afterwards, because "no transport was bound" tells an
    /// application where to look and "nothing answered" does not.
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

    /// The accounts whose registrar was written as a name, and so needed a
    /// resolver to become an address at all.
    ///
    /// An account with no registrar is not among them. What it has is an
    /// outbound proxy, which is an address and never a name, so a resolver
    /// going away changes nothing about where its requests go.
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
    /// There is no next rung: the ladder ended and the machine has already
    /// moved.
    Stop,
}

/// How long a rung waits before the next one is climbed.
///
/// 64·T1, drawn between half of it and all of it. §17.1.2.2 gives a non-INVITE
/// transaction exactly that long to conclude, so a rung never fires while the
/// request the rung before it sent is still trying; the draw is RFC 5626
/// §4.5's, for its reason, so that a fleet of phones waking from the same
/// outage does not come back in the same millisecond.
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
        // the window is one where nothing waits for us, so everything in it is
        // bookkeeping: a de-registration that may or may not leave is not a
        // thing to attempt with a hard deadline overhead
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
        // the account names a transport this agent was never told about, which
        // is what a socket that did not survive the sleep looks like from here
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
        // one healthy and one whose transport is gone: the path is proved, and
        // the account that still fails is the registrar's problem, on its own
        // back-off
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
        // two offices that hand out the same private address is a real
        // configuration, and it is the one a phone gets away with until a call
        // comes in
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
        // the crash: a cached registration reading as valid over a name that
        // no longer resolves. A binding pointed at a literal address never
        // needed the resolver and is left running
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
        // nothing it holds can be answered by a registrar, so the ladder runs
        // out the way it does for a stack with no accounts at all, and says
        // that nothing was left unproved
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

        // ten minutes of a background timer on a dead transport: 4.1.2.4's
        // Timer N, the transaction giving up, and every re-subscription that
        // cannot reach a transport at all
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
        // the refresh was scheduled while the transport was alive, which is
        // the only way this ever happens
        let t0 = Instant::now();
        let (mut agent, id) = registered(t0);
        let _ = events(&mut agent);
        if let Some(config) = agent.accounts.get_mut(&id) {
            config.transport = GONE;
        }
        agent.handle_timeout(t0 + Duration::from_secs(3_060));
        let seen = events(&mut agent);
        // and it promises another attempt: a refresh that could not leave is
        // not a registrar that refused, and the transport being gone at the
        // moment a deadline fell due is the normal case on a machine that
        // slept rather than a reason to give the account up for the life of
        // the process
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
        // a lamp showing a colleague as free because a NOTIFY said so an hour
        // and one suspend ago is the one wrong answer this must never give
        let t0 = Instant::now();
        let (mut agent, id) = registered(t0);
        let watched = agent
            .subscribe(
                id,
                &Subscribe::new(uri("sip:bob@example.com"), "dialog"),
                t0,
            )
            .expect("a subscription");
        // pretend the notifier answered: only the state is needed here, and it
        // is what dialog_info gates on
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
        // B4 and B3 together: these are the entry points an operating system
        // notification lands on, and none of them can refuse or fault
        let t0 = Instant::now();
        let mut agent = agent(t0);
        agent.suspending(t0);
        agent.resumed(t0);
        agent.interface_lost(t0);
        agent.name_resolution_lost(t0);
        agent.network_changed(&Network::down(), &wifi(), t0);
        agent.handle_timeout(t0 + RUNG);
        // with no accounts at all there is nothing to prove and nothing to
        // send, and the machine still ends somewhere it can be asked about
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

    #[test]
    fn a_register_sent_before_the_nat_answer_is_taken_back_by_the_one_after() {
        // the account registered its private address, because the STUN
        // answer had not arrived yet; the REGISTER that moves it must also
        // remove that binding, or the registrar forks every call to an
        // address that reaches nothing until the binding expires an hour
        // later (RFC 3261 §10.2.2: a Contact with expires=0 removes it)
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
    fn an_account_moved_whose_register_cannot_leave_is_still_counted_and_retried() {
        // the Contact moves whatever happens to the REGISTER that says so;
        // an answer of "none moved" would have the application believe its
        // accounts still name the private address, and the REGISTER that
        // could not leave is a refresh that could not leave, owed again on
        // the back-off rather than dropped
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
        // a password that was refused stays refused; re-sending it is how an
        // account gets locked out, and a wake is not new information about it
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
