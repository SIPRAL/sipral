// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Presence across the boundary: this account's own, published (RFC 3903),
//! and other people's, watched (RFC 3856).
//!
//! **Publishing is one call per change.** [`sipral_account_publish_presence`]
//! writes the PIDF document (RFC 3863) with the RPID activity phones show
//! (RFC 4480) and publishes it for the account's address of record; a second
//! call modifies the same publication. The stack refreshes it, answers the
//! compositor's challenges with the account's credentials, publishes afresh
//! when the compositor forgot it (412) and asks for a longer lifetime when
//! it wants one (423). [`sipral_account_unpublish_presence`] takes it away.
//! What becomes of it is `SIPRAL_EVENT_KIND_PRESENCE_CHANGED` with
//! `SIPRAL_PRESENCE_KIND_PUBLICATION`.
//!
//! **Watching is a subscription.** One made with `sipral_account_subscribe`
//! naming the `presence` package reads every `application/pidf+xml`
//! notification, and says what it read as
//! `SIPRAL_EVENT_KIND_PRESENCE_CHANGED` with `SIPRAL_PRESENCE_KIND_WATCHED`:
//! open or closed, the first activity, the first note.

use std::ffi::c_char;

use sipral_ua::presence::{Activity, Basic, Note, Person, Presence, Tuple};
use sipral_ua::{PublishEvent, PublishFailure};

use crate::abi::{codes, record};
use crate::call::ua_failed;
use crate::error::{Fail, entry, fail};
use crate::handle::{SIPRAL_HANDLE_NONE, SipralHandle};
use crate::stack::{handle_failed, with_stack_at};
use crate::status::SipralStatus;
use crate::text::text;
use crate::versioned::{Versioned, read_versioned};

codes! {
    /// What a [`crate::event::SipralEventKind::PresenceChanged`] is about.
    /// Names for `sipral_presence_event_t::kind`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralPresenceKind: u32 {
        /// Never written by this build.
        Unknown = 0,
        /// A `presence` subscription was told about the presentity.
        Watched = 1,
        /// This account's own published presence moved.
        Publication = 2,
    }
}

codes! {
    /// Whether a presentity can be reached: PIDF's `basic` (RFC 3863
    /// §4.1.4). Names for `sipral_presence_t::basic` and
    /// `sipral_presence_event_t::basic`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralBasic: u32 {
        /// Not said. A document published with this is refused, since
        /// §4.1.3 wants one.
        Unknown = 0,
        /// Reachable.
        Open = 1,
        /// Not reachable.
        Closed = 2,
    }
}

codes! {
    /// What the person behind a presentity is doing: the RPID activities
    /// (RFC 4480 §3.2) phones show. Names for `sipral_presence_t::activity`
    /// and `sipral_presence_event_t::activity`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralActivity: u32 {
        /// None said. Published, the document carries no person at all.
        None = 0,
        /// `away`.
        Away = 1,
        /// `busy`.
        Busy = 2,
        /// `on-the-phone`.
        OnThePhone = 3,
        /// `meeting`.
        Meeting = 4,
        /// `vacation`.
        Vacation = 5,
        /// Another activity, which this ABI has no number for.
        Other = 6,
    }
}

codes! {
    /// What became of this account's published presence. Names for
    /// `sipral_presence_event_t::publication_state`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralPublicationState: u32 {
        /// Not a publication event.
        Unknown = 0,
        /// The compositor holds it: published, modified or refreshed.
        Published = 1,
        /// It was taken away (`sipral_account_unpublish_presence`).
        Removed = 2,
        /// Its lifetime ran out with no refresh; the next publish starts it
        /// afresh.
        Expired = 3,
        /// The compositor refused, or never answered.
        Failed = 4,
    }
}

codes! {
    /// Why a publication failed. Names for `sipral_presence_event_t::failure`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralPublishFailure: u32 {
        /// Nothing failed.
        None = 0,
        /// 489: the compositor does not know the `presence` package. Nothing
        /// more is sent.
        BadEvent = 1,
        /// 423 with no `Min-Expires` this stack could meet.
        IntervalTooBrief = 2,
        /// A 2xx without the `SIP-ETag` every one must carry.
        NoEntityTag = 3,
        /// Any other refusal, a challenge nothing could answer among them;
        /// `status_code` says which.
        Refused = 4,
        /// No answer at all.
        Unreachable = 5,
    }
}

record! {
    /// This account's presence, as [`sipral_account_publish_presence`] takes
    /// it.
    ///
    /// Set `size` to `sizeof(sipral_presence_t)` and zero the rest before
    /// filling anything in.
    #[derive(Clone, Copy)]
    pub struct SipralPresence {
        /// `sizeof` this struct, as the caller's header declares it.
        pub size: usize,
        /// A [`SipralBasic`], open or closed. Required.
        pub basic: u32,
        /// A [`SipralActivity`]; [`SipralActivity::None`] publishes no
        /// person at all. [`SipralActivity::Other`] is refused: there is no
        /// name to publish it under.
        pub activity: u32,
        /// A note a buddy list shows beside the name, UTF-8 and not
        /// NUL-terminated, or null for none.
        pub note: *const c_char,
        /// How many bytes of it.
        pub note_len: usize,
    }
}

// Safety: the trait's contract. Plain data with no invariant between the
// members, and all-zero is valid: the pointer is null beside a length of
// zero, and a zero `basic` is refused by name.
unsafe impl Versioned for SipralPresence {
    const NAME: &'static str = "sipral_presence";
    const MIN_SIZE: usize = crate::versioned::min_size::PRESENCE;

    fn set_declared_size(&mut self, bytes: usize) {
        self.size = bytes;
    }
}

record! {
    /// What a [`crate::event::SipralEventKind::PresenceChanged`] carries.
    ///
    /// The text points into the event and is valid for as long as the
    /// callback is.
    #[derive(Clone, Copy)]
    pub struct SipralPresenceEvent {
        /// A [`SipralPresenceKind`].
        pub kind: u32,
        /// [`SipralPresenceKind::Watched`]: which subscription.
        /// `SIPRAL_HANDLE_NONE` for a publication, whose account is the
        /// event's `account`.
        pub subscription: SipralHandle,
        /// [`SipralPresenceKind::Watched`]: a [`SipralBasic`], open when any
        /// of the presentity's tuples is open.
        pub basic: u32,
        /// [`SipralPresenceKind::Watched`]: a [`SipralActivity`], the first
        /// the person listed.
        pub activity: u32,
        /// [`SipralPresenceKind::Watched`]: the presentity, as the document
        /// named it. Not NUL-terminated.
        pub entity: *const c_char,
        /// How many bytes of it.
        pub entity_len: usize,
        /// [`SipralPresenceKind::Watched`]: the first note, the document's
        /// own or else a tuple's. Null when there is none.
        pub note: *const c_char,
        /// How many bytes of it.
        pub note_len: usize,
        /// [`SipralPresenceKind::Publication`]: a [`SipralPublicationState`].
        pub publication_state: u32,
        /// [`SipralPresenceKind::Publication`]: a [`SipralPublishFailure`]
        /// when the state is [`SipralPublicationState::Failed`].
        pub failure: u32,
        /// [`SipralPresenceKind::Publication`]: the status the compositor
        /// answered with, when one did.
        pub status_code: u32,
        /// [`SipralPresenceKind::Publication`]: the lifetime granted, in
        /// milliseconds, when it was published.
        pub expires_ms: u64,
        /// [`SipralPresenceKind::Publication`]: how long until the stack
        /// refreshes it, in milliseconds.
        pub refresh_in_ms: u64,
    }
}

impl SipralPresenceEvent {
    const fn empty(kind: SipralPresenceKind) -> Self {
        Self {
            kind: kind as u32,
            subscription: SIPRAL_HANDLE_NONE,
            basic: SipralBasic::Unknown as u32,
            activity: SipralActivity::None as u32,
            entity: std::ptr::null(),
            entity_len: 0,
            note: std::ptr::null(),
            note_len: 0,
            publication_state: SipralPublicationState::Unknown as u32,
            failure: SipralPublishFailure::None as u32,
            status_code: 0,
            expires_ms: 0,
            refresh_in_ms: 0,
        }
    }
}

const fn activity_of(activity: Option<&Activity>) -> SipralActivity {
    match activity {
        None => SipralActivity::None,
        Some(Activity::Away) => SipralActivity::Away,
        Some(Activity::Busy) => SipralActivity::Busy,
        Some(Activity::OnThePhone) => SipralActivity::OnThePhone,
        Some(Activity::Meeting) => SipralActivity::Meeting,
        Some(Activity::Vacation) => SipralActivity::Vacation,
        Some(_) => SipralActivity::Other,
    }
}

fn millis(duration: std::time::Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

/// What a watched presentity's document said, as C reads it. The pointers
/// point into `presence`, which the delivery keeps alive.
pub(crate) fn watched(subscription: SipralHandle, presence: &Presence) -> SipralPresenceEvent {
    let mut payload = SipralPresenceEvent::empty(SipralPresenceKind::Watched);
    payload.subscription = subscription;
    let any_basic = presence.tuples.iter().any(|tuple| tuple.basic.is_some());
    payload.basic = if presence.is_open() {
        SipralBasic::Open
    } else if any_basic {
        SipralBasic::Closed
    } else {
        SipralBasic::Unknown
    } as u32;
    payload.activity = activity_of(presence.activities().first()) as u32;
    payload.entity = presence.entity.as_ptr().cast::<c_char>();
    payload.entity_len = presence.entity.len();
    let note = presence
        .notes
        .first()
        .or_else(|| presence.tuples.iter().find_map(|tuple| tuple.notes.first()));
    if let Some(note) = note {
        payload.note = note.text.as_ptr().cast::<c_char>();
        payload.note_len = note.text.len();
    }
    payload
}

/// What became of this account's publication, as C reads it.
pub(crate) fn published(event: &PublishEvent) -> SipralPresenceEvent {
    let mut payload = SipralPresenceEvent::empty(SipralPresenceKind::Publication);
    let state = match *event {
        PublishEvent::Published {
            expires,
            refresh_in,
            ..
        } => {
            payload.expires_ms = millis(expires);
            payload.refresh_in_ms = millis(refresh_in);
            SipralPublicationState::Published
        }
        PublishEvent::Removed => SipralPublicationState::Removed,
        PublishEvent::Expired => SipralPublicationState::Expired,
        PublishEvent::Failed { reason, status } => {
            payload.failure = match reason {
                PublishFailure::BadEvent => SipralPublishFailure::BadEvent,
                PublishFailure::IntervalTooBrief => SipralPublishFailure::IntervalTooBrief,
                PublishFailure::NoEntityTag => SipralPublishFailure::NoEntityTag,
                PublishFailure::Unreachable => SipralPublishFailure::Unreachable,
                _ => SipralPublishFailure::Refused,
            } as u32;
            payload.status_code = status.map_or(0, |status| u32::from(status.get()));
            SipralPublicationState::Failed
        }
        _ => SipralPublicationState::Unknown,
    };
    payload.publication_state = state as u32;
    payload
}

/// The document `presence` describes, for the account at `entity`.
///
/// # Safety
///
/// `presence.note` must be readable for `presence.note_len` bytes.
unsafe fn document(entity: &str, presence: &SipralPresence) -> Result<Presence, Fail> {
    let basic = match presence.basic {
        1 => Basic::Open,
        2 => Basic::Closed,
        other => {
            return Err(fail(
                SipralStatus::InvalidArgument,
                format!("basic is {other}, and a published presence is open (1) or closed (2)"),
            ));
        }
    };
    let activity = match presence.activity {
        0 => None,
        1 => Some(Activity::Away),
        2 => Some(Activity::Busy),
        3 => Some(Activity::OnThePhone),
        4 => Some(Activity::Meeting),
        5 => Some(Activity::Vacation),
        other => {
            return Err(fail(
                SipralStatus::InvalidArgument,
                format!("activity is {other}, which is not one this ABI can publish"),
            ));
        }
    };
    let mut document = Presence::new(entity);
    let mut tuple = Tuple::new("t1", basic);
    if let Some(note) = unsafe { text(presence.note, presence.note_len, "note") }? {
        tuple.notes.push(Note::new(note));
    }
    document.tuples.push(tuple);
    if let Some(activity) = activity {
        document.person = Some(Person {
            id: Box::from("p1"),
            activities: vec![activity],
        });
    }
    Ok(document)
}

entry! {
    /// Publish this account's presence (RFC 3903, RFC 3856 §6.2): a PIDF
    /// document for its address of record, open or closed, with the activity
    /// and the note `presence` gives. The first call publishes it and every
    /// later one modifies the same publication; the stack keeps it refreshed
    /// until [`sipral_account_unpublish_presence`].
    ///
    /// Nothing has happened when this returns: the PUBLISH is in the
    /// transmit queue, and `SIPRAL_EVENT_KIND_PRESENCE_CHANGED` with
    /// `SIPRAL_PRESENCE_KIND_PUBLICATION` says what the compositor did with
    /// it.
    ///
    /// # Safety
    ///
    /// `presence` must point at a `sipral_presence_t` whose `size` member
    /// says how long it is, with its pointer readable for the length beside
    /// it.
    fn sipral_account_publish_presence(
        stack: SipralHandle,
        account: SipralHandle,
        presence: *const SipralPresence,
        now_ms: u64,
    ) {
        let presence = unsafe { read_versioned(presence) }?;
        with_stack_at(stack, now_ms, |state, now| {
            let id = state.accounts.get(account).map_err(handle_failed)?;
            let entity = state
                .agent
                .account(id)
                .map(|config| config.aor().to_string())
                .unwrap_or_default();
            let document = unsafe { document(&entity, &presence) }?;
            state
                .agent
                .publish_presence(id, &document, now)
                .map(|_| ())
                .map_err(|error| ua_failed(&error))
        })
    }
}

entry! {
    /// Take this account's published presence away (RFC 3903 §4.5):
    /// `SIPRAL_PUBLICATION_STATE_REMOVED` says when it is gone.
    ///
    /// `SIPRAL_STATUS_WRONG_STATE` for an account that has published none.
    ///
    /// # Safety
    ///
    /// Safe to call with any handle value.
    fn sipral_account_unpublish_presence(stack: SipralHandle, account: SipralHandle, now_ms: u64) {
        with_stack_at(stack, now_ms, |state, now| {
            let id = state.accounts.get(account).map_err(handle_failed)?;
            let Some(publication) = state.agent.presence_publication(id) else {
                return Err(fail(
                    SipralStatus::WrongState,
                    "this account has published no presence",
                ));
            };
            state
                .agent
                .unpublish(publication, now)
                .map_err(|error| ua_failed(&error))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{
        SipralActivity, SipralBasic, SipralPresence, SipralPresenceKind, SipralPublicationState,
        SipralPublishFailure, sipral_account_publish_presence, sipral_account_unpublish_presence,
    };
    use crate::call::tests::{account_on, body, deliver, field, one, sent, start_line};
    use crate::conference::tests::{notified, subscribed};
    use crate::error::last_error_text;
    use crate::event::SipralEventKind;
    use crate::handle::{SIPRAL_HANDLE_NONE, SipralHandle};
    use crate::stack::sipral_stack_destroy;
    use crate::stack::tests::{Observed, Told, poll, stack};
    use crate::status::SipralStatus;
    use sipral_core::msg::HeaderName;
    use std::ffi::c_char;
    use std::ptr;

    fn presence(basic: SipralBasic, activity: u32, note: &str) -> SipralPresence {
        SipralPresence {
            size: size_of::<SipralPresence>(),
            basic: basic as u32,
            activity,
            note: if note.is_empty() {
                ptr::null()
            } else {
                note.as_ptr().cast::<c_char>()
            },
            note_len: note.len(),
        }
    }

    fn publish(
        handle: SipralHandle,
        account: SipralHandle,
        presence: &SipralPresence,
        now_ms: u64,
    ) -> SipralStatus {
        unsafe { sipral_account_publish_presence(handle, account, ptr::from_ref(presence), now_ms) }
    }

    /// The compositor's answer to a PUBLISH, with the fields `more` adds.
    fn answered(publish: &[u8], status: &str, more: &str) -> Vec<u8> {
        let mut out = format!("SIP/2.0 {status}\r\n").into_bytes();
        for (name, value) in [
            ("Via", field(publish, HeaderName::Via)),
            ("From", field(publish, HeaderName::From)),
            ("To", {
                let mut to = field(publish, HeaderName::To);
                to.extend_from_slice(b";tag=compositor");
                to
            }),
            ("Call-ID", field(publish, HeaderName::CallId)),
            ("CSeq", field(publish, HeaderName::CSeq)),
        ] {
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(&value);
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(more.as_bytes());
        out.extend_from_slice(b"Content-Length: 0\r\n\r\n");
        out
    }

    fn presence_events(observed: &Observed) -> Vec<Told> {
        observed
            .protocols
            .iter()
            .filter(|told| told.kind == Some(SipralEventKind::PresenceChanged))
            .cloned()
            .collect()
    }

    fn line(observed: &mut Observed) -> (SipralHandle, SipralHandle) {
        let handle = stack(observed);
        (handle, account_on(handle))
    }

    #[test]
    fn presence_is_published_as_pidf_and_what_the_compositor_granted_is_told() {
        let mut observed = Observed::default();
        let (handle, account) = line(&mut observed);
        let busy = presence(
            SipralBasic::Open,
            SipralActivity::OnThePhone as u32,
            "In a call",
        );
        assert_eq!(
            publish(handle, account, &busy, 1_000),
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        let request = one(handle);
        assert!(start_line(&request).starts_with("PUBLISH sip:alice@example.com"));
        assert_eq!(field(&request, HeaderName::Event), b"presence");
        assert_eq!(
            field(&request, HeaderName::ContentType),
            b"application/pidf+xml"
        );
        let document = String::from_utf8(body(&request)).expect("UTF-8");
        assert!(
            document.contains("entity=\"sip:alice@example.com\""),
            "{document}"
        );
        assert!(document.contains("<basic>open</basic>"), "{document}");
        assert!(document.contains("on-the-phone"), "{document}");
        assert!(document.contains("In a call"), "{document}");

        deliver(
            handle,
            &answered(&request, "200 OK", "SIP-ETag: tag-one\r\nExpires: 1800\r\n"),
            1_100,
        );
        poll(handle, 1_100);
        let told = presence_events(&observed);
        assert_eq!(told.len(), 1, "{:?}", observed.kinds());
        assert_eq!(
            told[0].presence_kind,
            SipralPresenceKind::Publication as u32
        );
        assert_eq!(told[0].account, account);
        assert_eq!(told[0].subscription, SIPRAL_HANDLE_NONE);
        assert_eq!(
            told[0].publication_state,
            SipralPublicationState::Published as u32
        );
        assert_eq!(told[0].expires_ms, 1_800_000);
        assert!(
            told[0].refresh_in_ms > 0 && told[0].refresh_in_ms < 1_800_000,
            "{}",
            told[0].refresh_in_ms
        );

        // a second call modifies the same publication
        let away = presence(SipralBasic::Closed, SipralActivity::Away as u32, "");
        assert_eq!(publish(handle, account, &away, 1_200), SipralStatus::Ok);
        let modified = one(handle);
        assert_eq!(
            field(&modified, HeaderName::Extension("SIP-If-Match")),
            b"tag-one"
        );
        let document = String::from_utf8(body(&modified)).expect("UTF-8");
        assert!(document.contains("<basic>closed</basic>"), "{document}");
        assert!(document.contains("away"), "{document}");
        assert!(!document.contains("note"), "{document}");
        deliver(
            handle,
            &answered(
                &modified,
                "200 OK",
                "SIP-ETag: tag-two\r\nExpires: 1800\r\n",
            ),
            1_300,
        );
        poll(handle, 1_300);

        // and taking it away is a PUBLISH with no body and Expires: 0
        let status = unsafe { sipral_account_unpublish_presence(handle, account, 1_400) };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let removal = one(handle);
        assert_eq!(field(&removal, HeaderName::Expires), b"0");
        assert_eq!(
            field(&removal, HeaderName::Extension("SIP-If-Match")),
            b"tag-two"
        );
        deliver(
            handle,
            &answered(&removal, "200 OK", "SIP-ETag: tag-two\r\nExpires: 0\r\n"),
            1_500,
        );
        poll(handle, 1_500);
        let told = presence_events(&observed);
        assert_eq!(
            told.last().map(|last| last.publication_state),
            Some(SipralPublicationState::Removed as u32)
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn a_compositor_that_does_not_know_presence_is_a_failure_with_its_reason() {
        let mut observed = Observed::default();
        let (handle, account) = line(&mut observed);
        let open = presence(SipralBasic::Open, SipralActivity::None as u32, "");
        assert_eq!(publish(handle, account, &open, 1_000), SipralStatus::Ok);
        let request = one(handle);
        let document = String::from_utf8(body(&request)).expect("UTF-8");
        assert!(
            !document.contains("person"),
            "no activity, no person: {document}"
        );
        deliver(handle, &answered(&request, "489 Bad Event", ""), 1_100);
        poll(handle, 1_100);
        let told = presence_events(&observed);
        assert_eq!(told.len(), 1, "{:?}", observed.kinds());
        assert_eq!(
            told[0].publication_state,
            SipralPublicationState::Failed as u32
        );
        assert_eq!(told[0].failure, SipralPublishFailure::BadEvent as u32);
        assert_eq!(told[0].status_code, 489);
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn what_cannot_be_published_is_refused_with_nothing_sent() {
        let mut observed = Observed::default();
        let (handle, account) = line(&mut observed);
        for refused in [
            presence(SipralBasic::Unknown, 0, ""),
            presence(SipralBasic::Open, SipralActivity::Other as u32, ""),
            presence(SipralBasic::Open, 99, ""),
            presence(SipralBasic::Open, 0, "two\r\nlines"),
        ] {
            assert_eq!(
                publish(handle, account, &refused, 1_000),
                SipralStatus::InvalidArgument
            );
        }
        let short = SipralPresence {
            size: 8,
            ..presence(SipralBasic::Open, 0, "")
        };
        assert_eq!(
            publish(handle, account, &short, 1_000),
            SipralStatus::UnsupportedVersion
        );
        assert_eq!(
            unsafe { sipral_account_unpublish_presence(handle, account, 1_000) },
            SipralStatus::WrongState,
            "nothing is published"
        );
        assert!(sent(handle).is_empty(), "nothing went out");
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    const PIDF: &str = "application/pidf+xml";

    const BUDDY: &[u8] = br#"<?xml version="1.0" encoding="UTF-8"?>
<presence xmlns="urn:ietf:params:xml:ns:pidf" xmlns:dm="urn:ietf:params:xml:ns:pidf:data-model" xmlns:rpid="urn:ietf:params:xml:ns:pidf:rpid" entity="sip:bob@example.com">
  <tuple id="t1"><status><basic>open</basic></status><note>Back at four</note></tuple>
  <dm:person id="p1"><rpid:activities><rpid:meeting/></rpid:activities></dm:person>
</presence>"#;

    #[test]
    fn a_watched_presentity_is_told_as_open_with_its_activity_and_note() {
        let mut observed = Observed::default();
        let (handle, subscription, subscribe) =
            subscribed(&mut observed, "presence", "sip:bob@example.com");
        deliver(
            handle,
            &notified(&subscribe, "presence", PIDF, BUDDY, 1),
            1_200,
        );
        poll(handle, 1_200);
        let told = presence_events(&observed);
        assert_eq!(told.len(), 1, "{:?}", observed.kinds());
        assert_eq!(told[0].presence_kind, SipralPresenceKind::Watched as u32);
        assert_eq!(told[0].subscription, subscription);
        assert_eq!(told[0].basic, SipralBasic::Open as u32);
        assert_eq!(told[0].activity, SipralActivity::Meeting as u32);
        assert_eq!(told[0].entity, "sip:bob@example.com");
        assert_eq!(told[0].note.as_deref(), Some("Back at four"));
        assert_eq!(
            told[0].publication_state,
            SipralPublicationState::Unknown as u32
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }
}
