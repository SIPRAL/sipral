// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Which end of a DTLS-SRTP call sends the ClientHello: `a=setup`.
//!
//! RFC 4145 §4 defines the attribute for TCP — which end opens the
//! connection — and RFC 5763 §5 borrows it for DTLS: "Whichever party is
//! active MUST initiate a DTLS handshake by sending a ClientHello". So the
//! active end is the DTLS client and the passive end the server, and an
//! `actpass` offer leaves the choice to the answer.
//!
//! The mapping is kept apart from everything that reads SDP, as a pure
//! function, because getting it wrong is silent: two ends that both believe
//! they are the server wait for each other until the handshake times out, and
//! two clients each answer the other's ClientHello with nothing.

use crate::{Error, Role};

/// An `a=setup` value (RFC 4145 §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Setup {
    /// `active`: this end initiates.
    Active,
    /// `passive`: this end accepts.
    Passive,
    /// `actpass`: either; the answer decides.
    ActPass,
    /// `holdconn`: no connection for the time being.
    HoldConn,
}

impl Setup {
    /// The value an `a=setup` line carries. ABNF quoted strings are
    /// case-insensitive (RFC 5234 §2.3), so `ACTPASS` is read too.
    ///
    /// # Errors
    ///
    /// [`Error::IllegalValue`] for anything but the four roles.
    pub fn parse(value: &str) -> Result<Self, Error> {
        [Self::Active, Self::Passive, Self::ActPass, Self::HoldConn]
            .into_iter()
            .find(|setup| setup.name().eq_ignore_ascii_case(value))
            .ok_or(Error::IllegalValue)
    }

    /// The value as it is written.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Passive => "passive",
            Self::ActPass => "actpass",
            Self::HoldConn => "holdconn",
        }
    }

    /// What an answerer writes for `offer`.
    ///
    /// The one choice is `actpass`, where RFC 5763 §5 makes `active`
    /// RECOMMENDED: the answerer's ClientHello can then leave with the answer
    /// instead of waiting for the offerer to receive it. Every other offer
    /// leaves one value that is not `holdconn`, and that is the one written.
    #[must_use]
    pub const fn answer_to(offer: Self) -> Self {
        match offer {
            Self::Active => Self::Passive,
            Self::Passive | Self::ActPass => Self::Active,
            Self::HoldConn => Self::HoldConn,
        }
    }
}

/// Which side of the offer/answer exchange an end is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Party {
    /// The end that wrote the offer.
    Offerer,
    /// The end that wrote the answer.
    Answerer,
}

/// The DTLS role `party` plays, given the `a=setup` of the offer and of the
/// answer — `None` for an attribute that is absent.
///
/// An absent attribute takes RFC 4145 §4.1's default: "'active' in the offer
/// and 'passive' in the answer". RFC 5763 §5 requires the attribute and
/// requires an offer to say `actpass`; a peer that did not is still mapped by
/// the table RFC 4145 gives, since that table is what the value means.
///
/// `Ok(None)` when the answer is `holdconn`: no handshake for now.
///
/// # Errors
///
/// [`Error::IllegalValue`] for an answer RFC 4145 §4.1 does not allow for
/// the offer: `actpass` in any answer, an answer that repeats an `active` or
/// `passive` offer, and anything but `holdconn` in answer to `holdconn`.
pub fn dtls_role(
    party: Party,
    offer: Option<Setup>,
    answer: Option<Setup>,
) -> Result<Option<Role>, Error> {
    let offer = offer.unwrap_or(Setup::Active);
    let answer = answer.unwrap_or(Setup::Passive);
    let active = match (offer, answer) {
        (_, Setup::HoldConn) => return Ok(None),
        (Setup::Active | Setup::ActPass, Setup::Passive) => Party::Offerer,
        (Setup::Passive | Setup::ActPass, Setup::Active) => Party::Answerer,
        _ => return Err(Error::IllegalValue),
    };
    Ok(Some(if party == active {
        Role::Client
    } else {
        Role::Server
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [Setup; 4] = [
        Setup::Active,
        Setup::Passive,
        Setup::ActPass,
        Setup::HoldConn,
    ];

    #[test]
    fn values_are_read_and_written_as_rfc_4145_spells_them() {
        for (setup, name) in ALL
            .into_iter()
            .zip(["active", "passive", "actpass", "holdconn"])
        {
            assert_eq!(setup.name(), name);
            assert_eq!(Setup::parse(name), Ok(setup));
            assert_eq!(Setup::parse(&name.to_uppercase()), Ok(setup));
        }
        for wrong in ["", "act pass", "actpas", "active ", "connection"] {
            assert_eq!(Setup::parse(wrong), Err(Error::IllegalValue), "{wrong:?}");
        }
    }

    /// RFC 4145 §4.1's table, row by row, with the role each party takes.
    #[test]
    fn every_pair_of_offer_and_answer_maps_as_the_table_says() {
        use Setup::{ActPass, Active, HoldConn, Passive};
        // (offer, answer, the offerer's role) for every pair the table allows
        let allowed = [
            (Active, Passive, Some(Role::Client)),
            (Active, HoldConn, None),
            (Passive, Active, Some(Role::Server)),
            (Passive, HoldConn, None),
            (ActPass, Active, Some(Role::Server)),
            (ActPass, Passive, Some(Role::Client)),
            (ActPass, HoldConn, None),
            (HoldConn, HoldConn, None),
        ];
        for offer in ALL {
            for answer in ALL {
                let expected = allowed
                    .iter()
                    .find(|(o, a, _)| *o == offer && *a == answer)
                    .map(|(_, _, role)| *role);
                let offerer = dtls_role(Party::Offerer, Some(offer), Some(answer));
                let answerer = dtls_role(Party::Answerer, Some(offer), Some(answer));
                if let Some(role) = expected {
                    assert_eq!(offerer, Ok(role), "{offer:?} / {answer:?}");
                    // the two ends never take the same role
                    assert_eq!(answerer, Ok(role.map(Role::peer)), "{offer:?} / {answer:?}");
                } else {
                    assert_eq!(offerer, Err(Error::IllegalValue), "{offer:?} / {answer:?}");
                    assert_eq!(answerer, Err(Error::IllegalValue), "{offer:?} / {answer:?}");
                }
            }
        }
    }

    #[test]
    fn an_absent_attribute_is_active_in_the_offer_and_passive_in_the_answer() {
        assert_eq!(
            dtls_role(Party::Offerer, None, None),
            Ok(Some(Role::Client))
        );
        assert_eq!(
            dtls_role(Party::Answerer, None, None),
            Ok(Some(Role::Server))
        );
        assert_eq!(
            dtls_role(Party::Offerer, Some(Setup::ActPass), None),
            Ok(Some(Role::Client))
        );
        assert_eq!(
            dtls_role(Party::Answerer, None, Some(Setup::Active)),
            Err(Error::IllegalValue)
        );
    }

    #[test]
    fn the_answer_this_end_writes_is_allowed_and_makes_it_the_client_where_it_can_choose() {
        for offer in ALL {
            let answer = Setup::answer_to(offer);
            assert!(
                dtls_role(Party::Answerer, Some(offer), Some(answer)).is_ok(),
                "{offer:?} answered {answer:?}"
            );
        }
        assert_eq!(
            dtls_role(
                Party::Answerer,
                Some(Setup::ActPass),
                Some(Setup::answer_to(Setup::ActPass))
            ),
            Ok(Some(Role::Client))
        );
    }
}
