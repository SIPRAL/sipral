// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Conferences across the boundary: the picture a `conference` subscription
//! keeps (RFC 4575), and the conference focus of RFC 4579.
//!
//! The stack merges every `conference` notification by RFC 4575 §4.6: a gap
//! asks for full state, a deleted conference ends the subscription. Read it
//! with [`sipral_subscription_conference`],
//! [`sipral_subscription_conference_user_at`] and
//! [`sipral_subscription_conference_text`].
//!
//! A focus marks its `Contact` with `isfocus` (RFC 4579 §4.2):
//! [`sipral_call_conference_uri`] reads it, [`sipral_call_subscribe_conference`]
//! watches it outside the dialog (§3.4), [`sipral_call_set_focus`] marks ours.

use std::ffi::c_char;

use sipral_ua::conference::{Conference, EndpointStatus, User};
use sipral_ua::{ConferenceUpdate, SubscriptionHandle, UaError, UserAgent};

use crate::abi::{Number, codes, record};
use crate::call::ua_failed;
use crate::diagnostics::copy_out;
use crate::error::{Fail, entry, fail};
use crate::handle::SipralHandle;
use crate::stack::{StackState, handle_failed, with_stack, with_stack_at};
use crate::status::SipralStatus;
use crate::subscription::subscription_of;
use crate::versioned::{Versioned, declared_size, write_versioned};

codes! {
    /// What one conference document did. Names for
    /// `sipral_conference_event_t::update`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralConferenceUpdate: u32 {
        /// Never written by this build.
        Unknown = 0,
        /// It was merged into the picture.
        Applied = 1,
        /// Deleted by the focus; the subscription ends (RFC 4575 §4.6).
        Ended = 2,
    }
}

codes! {
    /// Where one endpoint of a conference is (RFC 4575 §5.7.2). Names for
    /// `sipral_conference_user_t::status`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralEndpointStatus: u32 {
        /// Absent or not in the schema.
        Unknown = 0,
        /// `pending`: waiting for policy or for the focus.
        Pending = 1,
        /// `dialing-out`: the focus is calling it.
        DialingOut = 2,
        /// `dialing-in`: it is calling the focus.
        DialingIn = 3,
        /// `alerting`: it is ringing.
        Alerting = 4,
        /// `on-hold`.
        OnHold = 5,
        /// `connected`: it is in the conference.
        Connected = 6,
        /// `muted-via-focus`: in, and muted by the focus.
        MutedViaFocus = 7,
        /// `disconnecting`.
        Disconnecting = 8,
        /// `disconnected`: it has left.
        Disconnected = 9,
    }
}

codes! {
    /// Which text [`sipral_subscription_conference_text`] reads, as the focus
    /// wrote it. The first three ignore `index`; the rest are about that user.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralConferenceText: u32 {
        /// Never asked for.
        Unknown = 0,
        /// The conference's URI, the `entity` of `conference-info`.
        Entity = 1,
        /// Its `subject`.
        Subject = 2,
        /// Its `display-text`.
        DisplayText = 3,
        /// A user's `entity`: the address of record it takes part as.
        UserEntity = 4,
        /// A user's `display-text`.
        UserDisplayText = 5,
        /// The `entity` of a user's first endpoint: the device it is on.
        UserEndpoint = 6,
    }
}

record! {
    /// What a [`crate::event::SipralEventKind::ConferenceChanged`] carries.
    #[derive(Clone, Copy)]
    pub struct SipralConferenceEvent {
        /// Which subscription.
        pub subscription: SipralHandle,
        /// A [`SipralConferenceUpdate`].
        pub update: Number<SipralConferenceUpdate>,
        /// The current document version; zero once ended.
        pub version: u32,
        /// How many users the picture holds.
        pub users: u32,
    }
}

record! {
    /// A conference as a `conference` subscription holds it, read with
    /// [`sipral_subscription_conference`].
    #[derive(Clone, Copy)]
    pub struct SipralConference {
        /// How many bytes of this struct the library filled in.
        pub size: usize,
        /// The version of the last document merged.
        pub version: u32,
        /// Users held, indexed by [`sipral_subscription_conference_user_at`].
        pub users: u32,
        /// Whether `user-count` was sent; it may differ from `users`.
        pub has_user_count: u32,
        /// That count, when it said.
        pub user_count: u32,
        /// `active`: 1 true, 2 false, 0 not said.
        pub active: u32,
        /// Its `locked`, the same way.
        pub locked: u32,
    }
}

// Safety: plain data, filled only by the library.
unsafe impl Versioned for SipralConference {
    const NAME: &'static str = "sipral_conference";
    const PIN: crate::versioned::Pin = crate::versioned::pin!(SipralConference, locked);

    fn set_declared_size(&mut self, bytes: usize) {
        self.size = bytes;
    }
}

record! {
    /// One user of a conference, read with
    /// [`sipral_subscription_conference_user_at`]; its text is read with
    /// [`sipral_subscription_conference_text`].
    #[derive(Clone, Copy)]
    pub struct SipralConferenceUser {
        /// How many bytes of this struct the library filled in.
        pub size: usize,
        /// How many endpoints (devices) the user joined from.
        pub endpoints: u32,
        /// A [`SipralEndpointStatus`] of the first endpoint.
        pub status: Number<SipralEndpointStatus>,
        /// Media streams of the first endpoint.
        pub media: u32,
        /// Zero. Pads to alignment so later members never land in padding.
        pub reserved: u32,
    }
}

// Safety: as for `SipralConference`.
unsafe impl Versioned for SipralConferenceUser {
    const NAME: &'static str = "sipral_conference_user";
    const PIN: crate::versioned::Pin = crate::versioned::pin!(SipralConferenceUser, reserved);

    fn set_declared_size(&mut self, bytes: usize) {
        self.size = bytes;
    }
}

pub(crate) fn changed(
    agent: &UserAgent,
    named: SipralHandle,
    subscription: SubscriptionHandle,
    update: ConferenceUpdate,
) -> SipralConferenceEvent {
    let held = agent.conference(subscription);
    SipralConferenceEvent {
        subscription: named,
        update: match update {
            ConferenceUpdate::Applied => SipralConferenceUpdate::Applied,
            ConferenceUpdate::Ended => SipralConferenceUpdate::Ended,
            _ => SipralConferenceUpdate::Unknown,
        } as u32,
        version: held.and_then(Conference::version).unwrap_or(0),
        users: held.map_or(0, |conference| count(conference.users().len())),
    }
}

fn count(len: usize) -> u32 {
    u32::try_from(len).unwrap_or(u32::MAX)
}

fn picture_of(state: &StackState, subscription: SipralHandle) -> Result<&Conference, Fail> {
    let named = subscription_of(state, subscription)?;
    state.agent.conference(named).ok_or_else(|| {
        fail(
            SipralStatus::NotSupported,
            "this subscription holds no conference: either it is not to the `conference` \
             package, no document has named the conference yet, or it is not live and what it \
             had been told is no longer evidence about anything",
        )
    })
}

fn user_of(conference: &Conference, index: usize) -> Result<&User, Fail> {
    conference.users().get(index).ok_or_else(|| {
        fail(
            SipralStatus::InvalidArgument,
            format!(
                "there is no user {index}; the conference holds {}",
                conference.users().len()
            ),
        )
    })
}

const fn status_of(status: Option<&EndpointStatus>) -> SipralEndpointStatus {
    match status {
        Some(EndpointStatus::Pending) => SipralEndpointStatus::Pending,
        Some(EndpointStatus::DialingOut) => SipralEndpointStatus::DialingOut,
        Some(EndpointStatus::DialingIn) => SipralEndpointStatus::DialingIn,
        Some(EndpointStatus::Alerting) => SipralEndpointStatus::Alerting,
        Some(EndpointStatus::OnHold) => SipralEndpointStatus::OnHold,
        Some(EndpointStatus::Connected) => SipralEndpointStatus::Connected,
        Some(EndpointStatus::MutedViaFocus) => SipralEndpointStatus::MutedViaFocus,
        Some(EndpointStatus::Disconnecting) => SipralEndpointStatus::Disconnecting,
        Some(EndpointStatus::Disconnected) => SipralEndpointStatus::Disconnected,
        _ => SipralEndpointStatus::Unknown,
    }
}

/// A flag the focus may leave out, as one, two or zero.
const fn tristate(flag: Option<bool>) -> u32 {
    match flag {
        Some(true) => 1,
        Some(false) => 2,
        None => 0,
    }
}

entry! {
    /// What a `conference` subscription holds about the conference as a
    /// whole (RFC 4575 §5.5). `SIPRAL_STATUS_NOT_SUPPORTED` when it holds
    /// none: another package, no document yet, or not live.
    ///
    /// # Safety
    ///
    /// `out_conference` must point at a `sipral_conference_t` whose `size`
    /// member says how long it is.
    fn sipral_subscription_conference(
        stack: SipralHandle,
        subscription: SipralHandle,
        out_conference: *mut SipralConference,
    ) {
        unsafe { declared_size(out_conference.cast_const()) }?;
        with_stack(stack, |state| {
            let conference = picture_of(state, subscription)?;
            let status = conference.status();
            let out = SipralConference {
                size: size_of::<SipralConference>(),
                version: conference.version().unwrap_or(0),
                users: count(conference.users().len()),
                has_user_count: u32::from(status.and_then(|held| held.user_count).is_some()),
                user_count: status.and_then(|held| held.user_count).unwrap_or(0),
                active: tristate(status.and_then(|held| held.active)),
                locked: tristate(status.and_then(|held| held.locked)),
            };
            unsafe { write_versioned(out_conference, out) }
        })
    }
}

entry! {
    /// One user of the conference, by index, in the order the focus first
    /// named them. The index is stable only until the next
    /// `SIPRAL_EVENT_KIND_CONFERENCE_CHANGED`.
    ///
    /// # Safety
    ///
    /// `out_user` must point at a `sipral_conference_user_t` whose `size`
    /// member says how long it is.
    fn sipral_subscription_conference_user_at(
        stack: SipralHandle,
        subscription: SipralHandle,
        index: usize,
        out_user: *mut SipralConferenceUser,
    ) {
        unsafe { declared_size(out_user.cast_const()) }?;
        with_stack(stack, |state| {
            let user = user_of(picture_of(state, subscription)?, index)?;
            let first = user.endpoints.first();
            let out = SipralConferenceUser {
                reserved: 0,
                size: size_of::<SipralConferenceUser>(),
                endpoints: count(user.endpoints.len()),
                status: status_of(first.and_then(|endpoint| endpoint.status.as_ref())) as u32,
                media: first.map_or(0, |endpoint| count(endpoint.media.len())),
            };
            unsafe { write_versioned(out_user, out) }
        })
    }
}

entry! {
    /// Text about the conference or a user, as `which` (a
    /// [`SipralConferenceText`]) and `index` say. `out_needed` gets the bytes
    /// needed including the NUL; a small buffer is
    /// `SIPRAL_STATUS_BUFFER_TOO_SMALL` with nothing written; absent text is
    /// just the NUL.
    ///
    /// # Safety
    ///
    /// `buffer` must be writable for `capacity` bytes or be null with a
    /// capacity of zero, and `out_needed` must point at one `size_t` or be
    /// null.
    fn sipral_subscription_conference_text(
        stack: SipralHandle,
        subscription: SipralHandle,
        index: usize,
        which: Number<SipralConferenceText>,
        buffer: *mut c_char,
        capacity: usize,
        out_needed: *mut usize,
    ) {
        let wanted = match which {
            1 => SipralConferenceText::Entity,
            2 => SipralConferenceText::Subject,
            3 => SipralConferenceText::DisplayText,
            4 => SipralConferenceText::UserEntity,
            5 => SipralConferenceText::UserDisplayText,
            6 => SipralConferenceText::UserEndpoint,
            other => {
                return Err(fail(
                    SipralStatus::InvalidArgument,
                    format!("{other} is not a piece of text a conference has"),
                ));
            }
        };
        with_stack(stack, |state| {
            let conference = picture_of(state, subscription)?;
            let description = conference.description();
            let text = match wanted {
                SipralConferenceText::Entity => conference.entity(),
                SipralConferenceText::Subject => {
                    description.and_then(|held| held.subject.as_deref())
                }
                SipralConferenceText::DisplayText => {
                    description.and_then(|held| held.display_text.as_deref())
                }
                SipralConferenceText::UserEntity => Some(&*user_of(conference, index)?.entity),
                SipralConferenceText::UserDisplayText => {
                    user_of(conference, index)?.display_text.as_deref()
                }
                SipralConferenceText::UserEndpoint => user_of(conference, index)?
                    .endpoints
                    .first()
                    .map(|endpoint| &*endpoint.entity),
                SipralConferenceText::Unknown => None,
            }
            .unwrap_or("");
            unsafe { copy_out(text, buffer, capacity, out_needed) }
        })
    }
}

entry! {
    /// Put (`focus` 1) or remove (0) `isfocus` on this call's `Contact` from
    /// the next message on (RFC 4579 §4.2): the answer, or the next re-INVITE
    /// or UPDATE on an established call.
    ///
    /// # Safety
    ///
    /// Safe to call with any handle value.
    fn sipral_call_set_focus(stack: SipralHandle, call: SipralHandle, focus: u32) {
        if focus > 1 {
            return Err(fail(
                SipralStatus::InvalidArgument,
                format!("focus is {focus}, and it is one or zero"),
            ));
        }
        with_stack(stack, |state| {
            let id = state.calls.get(call).map_err(handle_failed)?;
            state
                .agent
                .set_focus(id, focus == 1)
                .map_err(|error| ua_failed(&error))
        })
    }
}

entry! {
    /// The conference URI when the far end's `Contact` has `isfocus` (RFC 4579
    /// §4.2), copied as `sipral_subscription_conference_text` copies.
    /// `SIPRAL_STATUS_NOT_A_FOCUS` otherwise.
    ///
    /// # Safety
    ///
    /// `buffer` must be writable for `capacity` bytes or be null with a
    /// capacity of zero, and `out_needed` must point at one `size_t` or be
    /// null.
    fn sipral_call_conference_uri(
        stack: SipralHandle,
        call: SipralHandle,
        buffer: *mut c_char,
        capacity: usize,
        out_needed: *mut usize,
    ) {
        with_stack(stack, |state| {
            let id = state.calls.get(call).map_err(handle_failed)?;
            let conference = state
                .agent
                .call_conference(id)
                .ok_or_else(|| ua_failed(&UaError::NotAFocus))?;
            unsafe { copy_out(&conference.to_string(), buffer, capacity, out_needed) }
        })
    }
}

entry! {
    /// Subscribe to the conference package of the call's focus (RFC 4579
    /// §3.4), outside the call's dialog, from the call's account. The
    /// subscription outlives the call. `SIPRAL_STATUS_NOT_A_FOCUS` when the
    /// far end is not a focus.
    ///
    /// # Safety
    ///
    /// `out_subscription` must point at one `sipral_handle_t`.
    fn sipral_call_subscribe_conference(
        stack: SipralHandle,
        call: SipralHandle,
        out_subscription: *mut SipralHandle,
        now_ms: u64,
    ) {
        if out_subscription.is_null() {
            return Err(fail(
                SipralStatus::InvalidArgument,
                "out_subscription is null",
            ));
        }
        with_stack_at(stack, now_ms, |state, now| {
            let id = state.calls.get(call).map_err(handle_failed)?;
            let made = state
                .agent
                .subscribe_call_conference(id, now)
                .map_err(|error| ua_failed(&error))?;
            let handle = state.subscriptions.insert(made).map_err(|status| {
                fail(
                    status,
                    "this stack has handed out every subscription handle it has room for",
                )
            })?;
            unsafe { out_subscription.write(handle) };
            Ok(())
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::{
        SipralConference, SipralConferenceText, SipralConferenceUpdate, SipralConferenceUser,
        SipralEndpointStatus, sipral_call_conference_uri, sipral_call_set_focus,
        sipral_call_subscribe_conference, sipral_subscription_conference,
        sipral_subscription_conference_text, sipral_subscription_conference_user_at,
    };
    use crate::call::sipral_call_answer;
    use crate::call::tests::{
        ANSWER, account_on, call_config, called, deliver, field, invitation, one, place, sent,
        start_line,
    };
    use crate::error::last_error_text;
    use crate::event::SipralEventKind;
    use crate::handle::{SIPRAL_HANDLE_NONE, SipralHandle};
    use crate::stack::sipral_stack_destroy;
    use crate::stack::tests::{Observed, Told, poll, stack};
    use crate::status::SipralStatus;
    use crate::subscription::sipral_account_subscribe;
    use crate::subscription::tests::{as_text, granted, watch};
    use sipral_core::msg::HeaderName;
    use std::ffi::c_char;
    use std::ptr;

    /// A NOTIFY in the dialog `subscribe` opened; `cseq` keeps each distinct.
    pub(crate) fn notified(
        subscribe: &[u8],
        package: &str,
        content_type: &str,
        body: &[u8],
        cseq: u32,
    ) -> Vec<u8> {
        let mut out = b"NOTIFY sip:alice@192.0.2.10:5060 SIP/2.0\r\n".to_vec();
        out.extend_from_slice(
            format!("Via: SIP/2.0/UDP 203.0.113.9:5060;branch=z9hG4bK-notified-{cseq}\r\n")
                .as_bytes(),
        );
        out.extend_from_slice(b"Max-Forwards: 70\r\n");
        for (name, value) in [
            ("From", {
                let mut to = field(subscribe, HeaderName::To);
                to.extend_from_slice(b";tag=notifier");
                to
            }),
            ("To", field(subscribe, HeaderName::From)),
            ("Call-ID", field(subscribe, HeaderName::CallId)),
        ] {
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(&value);
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(
            format!(
                "CSeq: {cseq} NOTIFY\r\n\
Contact: <sip:pbx@203.0.113.9:5060>\r\n\
Event: {package}\r\n\
Subscription-State: active;expires=3600\r\n\
Content-Type: {content_type}\r\n\
Content-Length: {}\r\n\r\n",
                body.len()
            )
            .as_bytes(),
        );
        out.extend_from_slice(body);
        out
    }

    /// A granted subscription: the stack, the subscription and the SUBSCRIBE.
    pub(crate) fn subscribed(
        observed: &mut Observed,
        package: &str,
        target: &str,
    ) -> (SipralHandle, SipralHandle, Vec<u8>) {
        let handle = stack(observed);
        let account = account_on(handle);
        let mut config = watch(target);
        (config.package, config.package_len) = as_text(package);
        let mut subscription = SIPRAL_HANDLE_NONE;
        let status = unsafe {
            sipral_account_subscribe(
                handle,
                account,
                ptr::from_ref(&config),
                &raw mut subscription,
                1_000,
            )
        };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let subscribe = one(handle);
        deliver(handle, &granted(&subscribe, 3600), 1_100);
        poll(handle, 1_100);
        (handle, subscription, subscribe)
    }

    const CONFERENCE_INFO: &str = "application/conference-info+xml";

    const ROOM: &[u8] = br#"<?xml version="1.0"?>
<conference-info xmlns="urn:ietf:params:xml:ns:conference-info" entity="sip:room@example.com" state="full" version="1">
  <conference-description><subject>Weekly</subject><display-text>Team room</display-text></conference-description>
  <conference-state><user-count>3</user-count><active>true</active><locked>false</locked></conference-state>
  <users>
    <user entity="sip:bob@example.com" state="full"><display-text>Bob</display-text>
      <endpoint entity="sip:bob@203.0.113.5"><status>connected</status><media id="1"><type>audio</type></media></endpoint>
    </user>
    <user entity="sip:carol@example.com" state="full">
      <endpoint entity="sip:carol@203.0.113.6"><status>alerting</status></endpoint>
    </user>
  </users>
</conference-info>"#;

    const DELETED: &[u8] = br#"<conference-info xmlns="urn:ietf:params:xml:ns:conference-info" entity="sip:room@example.com" state="deleted" version="2"/>"#;

    fn conference_events(observed: &Observed) -> Vec<Told> {
        observed
            .protocols
            .iter()
            .filter(|told| told.kind == Some(SipralEventKind::ConferenceChanged))
            .cloned()
            .collect()
    }

    fn picture(
        handle: SipralHandle,
        subscription: SipralHandle,
    ) -> (SipralStatus, SipralConference) {
        let mut out = SipralConference {
            size: size_of::<SipralConference>(),
            version: u32::MAX,
            users: u32::MAX,
            has_user_count: u32::MAX,
            user_count: u32::MAX,
            active: u32::MAX,
            locked: u32::MAX,
        };
        let status = unsafe { sipral_subscription_conference(handle, subscription, &raw mut out) };
        (status, out)
    }

    fn user(
        handle: SipralHandle,
        subscription: SipralHandle,
        index: usize,
    ) -> (SipralStatus, SipralConferenceUser) {
        let mut out = SipralConferenceUser {
            reserved: 0,
            size: size_of::<SipralConferenceUser>(),
            endpoints: u32::MAX,
            status: u32::MAX,
            media: u32::MAX,
        };
        let status = unsafe {
            sipral_subscription_conference_user_at(handle, subscription, index, &raw mut out)
        };
        (status, out)
    }

    fn text_of(
        handle: SipralHandle,
        subscription: SipralHandle,
        index: usize,
        which: SipralConferenceText,
    ) -> String {
        let mut buffer = [0 as c_char; 128];
        let mut needed = 0_usize;
        let status = unsafe {
            sipral_subscription_conference_text(
                handle,
                subscription,
                index,
                which as u32,
                buffer.as_mut_ptr(),
                buffer.len(),
                &raw mut needed,
            )
        };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let bytes: Vec<u8> = buffer[..needed - 1]
            .iter()
            .map(|byte| byte.to_ne_bytes()[0])
            .collect();
        String::from_utf8(bytes).expect("UTF-8")
    }

    #[test]
    fn a_conference_notification_is_merged_and_read_back_whole() {
        let mut observed = Observed::default();
        let (handle, subscription, subscribe) =
            subscribed(&mut observed, "conference", "sip:room@example.com");
        deliver(
            handle,
            &notified(&subscribe, "conference", CONFERENCE_INFO, ROOM, 1),
            1_200,
        );
        poll(handle, 1_200);
        let told = conference_events(&observed);
        assert_eq!(told.len(), 1, "{:?}", observed.kinds());
        assert_eq!(told[0].subscription, subscription);
        assert_eq!(told[0].update, SipralConferenceUpdate::Applied as u32);
        assert_eq!(told[0].version, 1);
        assert_eq!(told[0].users, 2);
        assert_eq!(told[0].account, SIPRAL_HANDLE_NONE);

        let (status, whole) = picture(handle, subscription);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        assert_eq!(whole.version, 1);
        assert_eq!(whole.users, 2);
        assert_eq!((whole.has_user_count, whole.user_count), (1, 3));
        assert_eq!((whole.active, whole.locked), (1, 2));

        let (status, bob) = user(handle, subscription, 0);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        assert_eq!(bob.endpoints, 1);
        assert_eq!(bob.status, SipralEndpointStatus::Connected as u32);
        assert_eq!(bob.media, 1);
        let (_, carol) = user(handle, subscription, 1);
        assert_eq!(carol.status, SipralEndpointStatus::Alerting as u32);
        assert_eq!(
            user(handle, subscription, 2).0,
            SipralStatus::InvalidArgument
        );

        for (index, which, expected) in [
            (0, SipralConferenceText::Entity, "sip:room@example.com"),
            (0, SipralConferenceText::Subject, "Weekly"),
            (0, SipralConferenceText::DisplayText, "Team room"),
            (1, SipralConferenceText::UserEntity, "sip:carol@example.com"),
            (0, SipralConferenceText::UserDisplayText, "Bob"),
            // a piece the focus did not send is empty
            (1, SipralConferenceText::UserDisplayText, ""),
            (0, SipralConferenceText::UserEndpoint, "sip:bob@203.0.113.5"),
        ] {
            assert_eq!(
                text_of(handle, subscription, index, which),
                expected,
                "{which:?}"
            );
        }
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn a_deleted_conference_ends_the_picture_and_the_subscription() {
        let mut observed = Observed::default();
        let (handle, _, subscribe) =
            subscribed(&mut observed, "conference", "sip:room@example.com");
        deliver(
            handle,
            &notified(&subscribe, "conference", CONFERENCE_INFO, ROOM, 1),
            1_200,
        );
        poll(handle, 1_200);
        let _ = sent(handle);
        deliver(
            handle,
            &notified(&subscribe, "conference", CONFERENCE_INFO, DELETED, 2),
            1_300,
        );
        poll(handle, 1_300);
        let told = conference_events(&observed);
        assert_eq!(told.len(), 2);
        assert_eq!(told[1].update, SipralConferenceUpdate::Ended as u32);
        assert_eq!(told[1].users, 0);
        // RFC 4575 §4.6: the subscriber gives it up
        let out = sent(handle);
        assert!(
            out.iter()
                .any(|message| start_line(message).starts_with("SUBSCRIBE")
                    && field(message, HeaderName::Expires) == b"0"),
            "no unsubscribe went out"
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn a_subscription_to_another_package_holds_no_conference() {
        let mut observed = Observed::default();
        let (handle, subscription, _) = subscribed(&mut observed, "dialog", "sip:2001@example.com");
        assert_eq!(picture(handle, subscription).0, SipralStatus::NotSupported);
        assert_eq!(user(handle, subscription, 0).0, SipralStatus::NotSupported);
        let mut needed = 0_usize;
        let status = unsafe {
            sipral_subscription_conference_text(
                handle,
                subscription,
                0,
                0,
                ptr::null_mut(),
                0,
                &raw mut needed,
            )
        };
        assert_eq!(status, SipralStatus::InvalidArgument, "zero names no text");
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// An INVITE from a focus: its Contact carries `isfocus` (RFC 4579 §4.2).
    fn invitation_from_a_focus() -> Vec<u8> {
        String::from_utf8(invitation())
            .expect("text")
            .replace(
                "Contact: <sip:bob@203.0.113.5:5060>",
                "Contact: <sip:room@203.0.113.5:5060>;isfocus",
            )
            .into_bytes()
    }

    fn conference_uri(handle: SipralHandle, call: SipralHandle) -> (SipralStatus, String) {
        let mut buffer = [0 as c_char; 64];
        let mut needed = 0_usize;
        let status = unsafe {
            sipral_call_conference_uri(
                handle,
                call,
                buffer.as_mut_ptr(),
                buffer.len(),
                &raw mut needed,
            )
        };
        let text = if status == SipralStatus::Ok {
            buffer[..needed - 1]
                .iter()
                .map(|byte| char::from(byte.to_ne_bytes()[0]))
                .collect()
        } else {
            String::new()
        };
        (status, text)
    }

    fn incoming(observed: &mut Observed, invite: &[u8]) -> (SipralHandle, SipralHandle) {
        let handle = stack(observed);
        let _ = account_on(handle);
        deliver(handle, invite, 1_000);
        poll(handle, 1_000);
        let call = called(observed);
        let _ = sent(handle);
        (handle, call)
    }

    #[test]
    fn a_call_from_a_focus_names_its_conference_and_can_watch_it() {
        let mut observed = Observed::default();
        let (handle, call) = incoming(&mut observed, &invitation_from_a_focus());
        assert_eq!(
            conference_uri(handle, call),
            (SipralStatus::Ok, "sip:room@203.0.113.5:5060".to_owned())
        );
        let mut subscription = SIPRAL_HANDLE_NONE;
        let status =
            unsafe { sipral_call_subscribe_conference(handle, call, &raw mut subscription, 1_100) };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        assert_ne!(subscription, SIPRAL_HANDLE_NONE);
        let subscribe = one(handle);
        assert!(
            start_line(&subscribe).starts_with("SUBSCRIBE sip:room@203.0.113.5:5060"),
            "{}",
            start_line(&subscribe)
        );
        assert_eq!(field(&subscribe, HeaderName::Event), b"conference");
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn a_call_from_anyone_else_is_not_a_focus() {
        let mut observed = Observed::default();
        let (handle, call) = incoming(&mut observed, &invitation());
        assert_eq!(conference_uri(handle, call).0, SipralStatus::NotAFocus);
        let mut subscription = SIPRAL_HANDLE_NONE;
        let status =
            unsafe { sipral_call_subscribe_conference(handle, call, &raw mut subscription, 1_100) };
        assert_eq!(status, SipralStatus::NotAFocus);
        assert_eq!(subscription, SIPRAL_HANDLE_NONE);
        assert!(sent(handle).is_empty(), "nothing went out");
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn this_end_says_it_is_the_focus_on_its_answer() {
        let mut observed = Observed::default();
        let (handle, call) = incoming(&mut observed, &invitation());
        assert_eq!(
            unsafe { sipral_call_set_focus(handle, call, 2) },
            SipralStatus::InvalidArgument
        );
        assert_eq!(
            unsafe { sipral_call_set_focus(handle, call, 1) },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        let status =
            unsafe { sipral_call_answer(handle, call, ANSWER.as_ptr(), ANSWER.len(), 1_100) };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let answer = one(handle);
        let contact = String::from_utf8(field(&answer, HeaderName::Contact)).expect("text");
        assert!(contact.contains(";isfocus"), "{contact}");
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn a_call_placed_as_the_focus_says_so_and_one_placed_otherwise_does_not() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let account = account_on(handle);
        let mut config = call_config();
        let (status, _) = place(handle, account, &config, 1_000);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let contact = String::from_utf8(field(&one(handle), HeaderName::Contact)).expect("text");
        assert!(!contact.contains("isfocus"), "{contact}");

        config.focus = 1;
        let (status, _) = place(handle, account, &config, 1_100);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let contact = String::from_utf8(field(&one(handle), HeaderName::Contact)).expect("text");
        assert!(contact.contains(";isfocus"), "{contact}");

        config.focus = 2;
        assert_eq!(
            place(handle, account, &config, 1_200).0,
            SipralStatus::InvalidArgument
        );
        assert!(sent(handle).is_empty(), "nothing went out");
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }
}
