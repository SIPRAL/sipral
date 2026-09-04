// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! The names the caller holds things by.
//!
//! RFC 3261 §17 has four transaction machines, and they are not
//! interchangeable: a PRACK is answered on an INVITE server transaction, a
//! CANCEL forms a non-INVITE client transaction of its own, and mixing them up
//! is the kind of mistake that shows up as a call that never connects.
//!
//! So the handle is typed by machine. `respond(prack_transaction, ...)` where
//! an INVITE server transaction was meant does not compile, and the guarantee
//! survives into C — one struct per kind — and from there into Swift, .NET and
//! Kotlin.
//!
//! The other half is generational identity. A transaction dies on a timer and
//! its slot is reused; a handle issued before that never answers to the new
//! occupant. See [`super::slab`].

use core::fmt;
use core::marker::PhantomData;

/// Slot plus generation. A handle into a slot that has since been reused never
/// compares equal to the new occupant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct Raw {
    pub(crate) slot: u32,
    pub(crate) generation: u32,
}

/// Which end of the exchange a machine sits on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Role {
    /// Sends the request and reads the responses (RFC 3261 §17.1).
    Client,
    /// Reads the request and sends the responses (§17.2).
    Server,
}

mod sealed {
    pub trait Sealed {}
}

/// One of the four transaction machines in RFC 3261 §17.
///
/// Sealed: the set is closed by the RFC, and an extension method still uses
/// one of these four.
pub trait TransactionKind: sealed::Sealed + 'static {
    /// Which end this machine sits on.
    const ROLE: Role;
    /// The states this machine can be in.
    type State: Copy + Eq + fmt::Debug;
    /// For error messages and for the C projection.
    const NAME: &'static str;
}

/// RFC 3261 §17.1.1, with RFC 6026's `Accepted`: timers A, B, D and M.
#[derive(Debug)]
pub enum InviteClient {}

/// RFC 3261 §17.1.2: timers E, F and K.
#[derive(Debug)]
pub enum NonInviteClient {}

/// RFC 3261 §17.2.1, with RFC 6026's `Accepted`: timers G, H, I and L.
#[derive(Debug)]
pub enum InviteServer {}

/// RFC 3261 §17.2.2: timer J.
#[derive(Debug)]
pub enum NonInviteServer {}

/// RFC 3261 §17.1.1.2, as corrected by RFC 6026 §7.1.
///
/// `Accepted` is the correction: a 2xx does not end the transaction outright.
/// It sits here for timer M and passes every further 2xx up, including ones
/// from other forks, instead of treating them as strays — which is what
/// produces "the call connected but the app thinks it failed".
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum InviteClientState {
    /// The INVITE has gone out and nothing has come back.
    Calling,
    /// A provisional response arrived.
    Proceeding,
    /// A 2xx arrived and more may follow.
    Accepted,
    /// A final response other than 2xx arrived; the ACK is being retransmitted
    /// for as long as the response is.
    Completed,
    /// Done.
    Terminated,
}

/// RFC 3261 §17.1.2.2.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum NonInviteClientState {
    /// The request has gone out and nothing has come back.
    Trying,
    /// A provisional response arrived.
    Proceeding,
    /// A final response arrived; timer K absorbs its retransmissions.
    Completed,
    /// Done.
    Terminated,
}

/// RFC 3261 §17.2.1, as corrected by RFC 6026 §8.1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum InviteServerState {
    /// The INVITE arrived; provisional responses may go out.
    Proceeding,
    /// A 2xx went out. Timer L, and retransmissions of the INVITE are absorbed
    /// here rather than answered again.
    Accepted,
    /// A final response other than 2xx went out and is being retransmitted
    /// until the ACK arrives.
    Completed,
    /// The ACK arrived; timer I absorbs its retransmissions.
    Confirmed,
    /// Done.
    Terminated,
}

/// RFC 3261 §17.2.2.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum NonInviteServerState {
    /// The request arrived and nothing has gone out.
    Trying,
    /// A provisional response went out.
    Proceeding,
    /// A final response went out; timer J absorbs retransmissions of the
    /// request.
    Completed,
    /// Done.
    Terminated,
}

macro_rules! kinds {
    ($($kind:ident => $state:ident, $role:ident, $name:literal;)*) => {
        $(
            impl sealed::Sealed for $kind {}
            impl TransactionKind for $kind {
                const ROLE: Role = Role::$role;
                type State = $state;
                const NAME: &'static str = $name;
            }
        )*
    };
}

kinds! {
    InviteClient    => InviteClientState,    Client, "INVITE client";
    NonInviteClient => NonInviteClientState, Client, "non-INVITE client";
    InviteServer    => InviteServerState,    Server, "INVITE server";
    NonInviteServer => NonInviteServerState, Server, "non-INVITE server";
}

/// A transaction, named by the machine it runs.
///
/// The kind is a phantom, so this is four bytes of slot and four of
/// generation whichever machine it names.
pub struct TransactionId<K: TransactionKind> {
    pub(crate) raw: Raw,
    // fn() -> K rather than K: this is Send and Sync whatever K is, and K is
    // never constructed
    kind: PhantomData<fn() -> K>,
}

impl<K: TransactionKind> TransactionId<K> {
    pub(crate) const fn new(raw: Raw) -> Self {
        Self {
            raw,
            kind: PhantomData,
        }
    }

    /// Which end of the exchange this transaction sits on.
    #[must_use]
    pub const fn role(&self) -> Role {
        K::ROLE
    }
}

// derive would demand K: Clone and friends, which an uninhabited kind cannot
// offer and does not need
impl<K: TransactionKind> Clone for TransactionId<K> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<K: TransactionKind> Copy for TransactionId<K> {}

impl<K: TransactionKind> PartialEq for TransactionId<K> {
    fn eq(&self, other: &Self) -> bool {
        self.raw == other.raw
    }
}

impl<K: TransactionKind> Eq for TransactionId<K> {}

impl<K: TransactionKind> core::hash::Hash for TransactionId<K> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.raw.hash(state);
    }
}

impl<K: TransactionKind> fmt::Debug for TransactionId<K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}#{}.{}", K::NAME, self.raw.slot, self.raw.generation)
    }
}

/// A transaction of any kind, for the places that hold all four.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AnyTransactionId {
    /// An INVITE client transaction.
    InviteClient(TransactionId<InviteClient>),
    /// A non-INVITE client transaction.
    NonInviteClient(TransactionId<NonInviteClient>),
    /// An INVITE server transaction.
    InviteServer(TransactionId<InviteServer>),
    /// A non-INVITE server transaction.
    NonInviteServer(TransactionId<NonInviteServer>),
}

impl AnyTransactionId {
    /// Which end of the exchange this transaction sits on.
    #[must_use]
    pub const fn role(&self) -> Role {
        match *self {
            Self::InviteClient(_) | Self::NonInviteClient(_) => Role::Client,
            Self::InviteServer(_) | Self::NonInviteServer(_) => Role::Server,
        }
    }

    /// The machine's name, for a message a person will read.
    #[must_use]
    pub const fn kind_name(&self) -> &'static str {
        match *self {
            Self::InviteClient(_) => InviteClient::NAME,
            Self::NonInviteClient(_) => NonInviteClient::NAME,
            Self::InviteServer(_) => InviteServer::NAME,
            Self::NonInviteServer(_) => NonInviteServer::NAME,
        }
    }
}

macro_rules! any_from {
    ($($kind:ident => $variant:ident;)*) => {
        $(
            impl From<TransactionId<$kind>> for AnyTransactionId {
                fn from(id: TransactionId<$kind>) -> Self {
                    Self::$variant(id)
                }
            }
        )*
    };
}

any_from! {
    InviteClient => InviteClient;
    NonInviteClient => NonInviteClient;
    InviteServer => InviteServer;
    NonInviteServer => NonInviteServer;
}

/// A dialog: `Call-ID` and both tags (RFC 3261 §12).
///
/// Not parameterised by anything. Which transaction created a dialog is not
/// part of the dialog's identity, and a dialog outlives the transaction that
/// made it by however long the call lasts.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct DialogId {
    pub(crate) raw: Raw,
}

impl DialogId {
    pub(crate) const fn new(raw: Raw) -> Self {
        Self { raw }
    }
}

impl fmt::Debug for DialogId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "dialog#{}.{}", self.raw.slot, self.raw.generation)
    }
}

/// One reliable provisional response awaiting its PRACK (RFC 3262).
///
/// It carries the dialog, so a PRACK cannot be aimed at the wrong one: a fork
/// produces several early dialogs on the same INVITE, each with its own RSeq
/// sequence, and the numbers alone do not say which is which.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProvisionalResponseId {
    dialog: DialogId,
    rseq: u32,
    pub(crate) raw: Raw,
}

impl ProvisionalResponseId {
    pub(crate) const fn new(dialog: DialogId, rseq: u32, raw: Raw) -> Self {
        Self { dialog, rseq, raw }
    }

    /// The dialog this response belongs to.
    #[must_use]
    pub const fn dialog(&self) -> DialogId {
        self.dialog
    }

    /// The `RSeq` it carried (RFC 3262 §7.1).
    #[must_use]
    pub const fn rseq(&self) -> u32 {
        self.rseq
    }
}

impl fmt::Debug for ProvisionalResponseId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?} rseq {}", self.dialog, self.rseq)
    }
}

/// A transport the caller opened, named by the caller.
///
/// The endpoint never opens a socket and never owns one; it is told which
/// transports exist and asked to write bytes to them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TransportId(pub u32);

impl fmt::Display for TransportId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "transport {}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AnyTransactionId, DialogId, InviteClient, InviteServer, NonInviteClient,
        ProvisionalResponseId, Raw, Role, TransactionId, TransactionKind, TransportId,
    };
    use std::collections::HashSet;

    const fn raw(slot: u32, generation: u32) -> Raw {
        Raw { slot, generation }
    }

    #[test]
    fn a_handle_carries_the_role_of_its_machine() {
        let client: TransactionId<InviteClient> = TransactionId::new(raw(0, 0));
        let server: TransactionId<InviteServer> = TransactionId::new(raw(0, 0));
        assert_eq!(client.role(), Role::Client);
        assert_eq!(server.role(), Role::Server);
        assert_eq!(InviteClient::NAME, "INVITE client");
        assert_eq!(NonInviteClient::ROLE, Role::Client);
    }

    #[test]
    fn two_handles_to_the_same_slot_in_different_generations_differ() {
        let first: TransactionId<InviteClient> = TransactionId::new(raw(3, 0));
        let second: TransactionId<InviteClient> = TransactionId::new(raw(3, 1));
        assert_ne!(first, second);
        assert_eq!(first, TransactionId::new(raw(3, 0)));

        let mut set = HashSet::new();
        set.insert(first);
        assert!(!set.contains(&second));
        assert!(set.contains(&first));
    }

    #[test]
    fn the_kind_is_free_at_runtime() {
        assert_eq!(
            size_of::<TransactionId<InviteClient>>(),
            size_of::<Raw>(),
            "the phantom cost something"
        );
        assert_eq!(size_of::<Raw>(), 8);
    }

    #[test]
    fn a_typed_handle_widens_into_the_any_form_and_keeps_its_name() {
        let id: TransactionId<InviteServer> = TransactionId::new(raw(1, 2));
        let any: AnyTransactionId = id.into();
        assert_eq!(any, AnyTransactionId::InviteServer(id));
        assert_eq!(any.role(), Role::Server);
        assert_eq!(any.kind_name(), "INVITE server");
    }

    #[test]
    fn the_debug_form_says_which_machine_and_which_generation() {
        let id: TransactionId<InviteClient> = TransactionId::new(raw(7, 3));
        assert_eq!(format!("{id:?}"), "INVITE client#7.3");
        assert_eq!(format!("{:?}", DialogId::new(raw(1, 0))), "dialog#1.0");
    }

    #[test]
    fn a_provisional_response_remembers_which_dialog_it_belongs_to() {
        // a fork gives several early dialogs on one INVITE, each numbering its
        // own provisionals, so the RSeq alone does not identify one
        let left = DialogId::new(raw(0, 0));
        let right = DialogId::new(raw(1, 0));
        let from_left = ProvisionalResponseId::new(left, 1, raw(0, 0));
        let from_right = ProvisionalResponseId::new(right, 1, raw(1, 0));
        assert_eq!(from_left.rseq(), from_right.rseq());
        assert_ne!(from_left.dialog(), from_right.dialog());
        assert_ne!(from_left, from_right);
    }

    #[test]
    fn a_transport_is_named_by_whoever_opened_it() {
        assert_eq!(TransportId(4).to_string(), "transport 4");
        assert!(TransportId(1) < TransportId(2));
    }
}
