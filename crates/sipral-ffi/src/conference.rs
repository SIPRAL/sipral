// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Conferences across the boundary: the picture a `conference` subscription
//! keeps (RFC 4575), and the conference focus of RFC 4579.
//!
//! **A `conference` subscription is kept by the stack.** One made with
//! `sipral_account_subscribe` naming the `conference` package, or with
//! [`sipral_call_subscribe_conference`], merges every notification into a
//! picture of its own by RFC 4575 §4.6: a merged document is
//! `SIPRAL_EVENT_KIND_CONFERENCE_CHANGED`, a gap asks for full state by
//! itself, and a deleted conference ends the subscription.
//! [`sipral_subscription_conference`] reads the conference as a whole,
//! [`sipral_subscription_conference_user_at`] one user, and
//! [`sipral_subscription_conference_text`] the text the focus wrote about
//! either, copied into the caller's buffer.
//!
//! **A focus says so in its `Contact`.** A call whose far end is a focus
//! belongs to a conference whose URI is that `Contact`
//! ([`sipral_call_conference_uri`], RFC 4579 §4.2), and
//! [`sipral_call_subscribe_conference`] watches it outside the call's
//! dialog, as §3.4 asks. The other way round, [`sipral_call_set_focus`] puts
//! `isfocus` on this end's `Contact` for a call it hosts a conference on, and
//! `sipral_call_config_t::focus` places one that way.

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
        /// The focus deleted the conference: the picture is empty, and the
        /// subscription is being given up (RFC 4575 §4.6).
        Ended = 2,
    }
}

codes! {
    /// Where one endpoint of a conference is (RFC 4575 §5.7.2). Names for
    /// `sipral_conference_user_t::status`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralEndpointStatus: u32 {
        /// The focus did not say, or said something the schema does not
        /// list.
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
    /// Which piece of text [`sipral_subscription_conference_text`] is being
    /// asked for. The first three are about the conference and ignore
    /// `index`; the rest are about the user at `index`.
    ///
    /// Every one of them is what the focus wrote.
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
        /// The version of the document the picture is at now; zero once the
        /// conference ended.
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
        /// How many users the picture holds, which is what
        /// [`sipral_subscription_conference_user_at`] reads by index.
        pub users: u32,
        /// Whether the focus said how many users it counts
        /// (`conference-state`'s `user-count`), which may differ from
        /// `users`: a focus need not list every one.
        pub has_user_count: u32,
        /// That count, when it said.
        pub user_count: u32,
        /// `conference-state`'s `active`: one when the focus said it is, two
        /// when it said it is not, zero when it said nothing.
        pub active: u32,
        /// Its `locked`, the same way.
        pub locked: u32,
    }
}

// Safety: the trait's contract. Plain data with no invariant between the
// members, and the library is the only one that fills it in.
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
        /// How many endpoints — devices — the user is in the conference
        /// from.
        pub endpoints: u32,
        /// A [`SipralEndpointStatus`]: where the first of them is.
        pub status: Number<SipralEndpointStatus>,
        /// How many media streams the first of them has.
        pub media: u32,
        /// Zero. Rounds the struct up to a whole multiple of its alignment on
        /// every target, so that a member a later version appends starts at or
        /// past the length a caller built against this header declares, never
        /// in padding inside it. The library writes zero here and reads nothing
        /// from it.
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

/// The payload of a conference event, as C reads it.
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

/// The picture one subscription holds, or why there is none.
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
    /// whole (RFC 4575 §5.5).
    ///
    /// `SIPRAL_STATUS_NOT_SUPPORTED` for a subscription that holds no
    /// conference: one to another package, one no document has reached yet,
    /// or one that is not live.
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
    /// A piece of text about the conference or one of its users, copied into
    /// the caller's buffer the way `sipral_subscription_dialog_text` copies
    /// one: `out_needed` receives the bytes it needs including the NUL, a
    /// buffer too small is `SIPRAL_STATUS_BUFFER_TOO_SMALL` with nothing
    /// written, and a piece the focus did not send is one byte, the NUL.
    ///
    /// `which` is a [`SipralConferenceText`]; `index` names the user for the
    /// pieces about one, and is ignored for the others.
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
    /// Say, or stop saying, that this end is the focus of a conference the
    /// call belongs to (RFC 4579 §4.2): `isfocus` on the `Contact` of every
    /// request and response the call sends from here on — the answer, for a
    /// call not answered yet, and the next re-INVITE or UPDATE for one that
    /// is up, which is how the far end learns it.
    ///
    /// `focus` is one to say it and zero to stop.
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
    /// The URI of the conference a call belongs to, when its far end said it
    /// is a focus (`isfocus` in its `Contact`, RFC 4579 §4.2), copied into
    /// the caller's buffer as `sipral_subscription_conference_text` copies.
    ///
    /// `SIPRAL_STATUS_NOT_A_FOCUS` for a call whose far end said nothing of
    /// the kind.
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
    /// §3.4), outside the call's dialog, from the call's own account, and
    /// write the subscription's handle. It is kept like any subscription and
    /// outlives the call; `SIPRAL_EVENT_KIND_CONFERENCE_CHANGED` says what it
    /// learns.
    ///
    /// `SIPRAL_STATUS_NOT_A_FOCUS` for a call whose far end did not say it is
    /// a focus.
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

    /// A notification in the dialog `subscribe` opened, for `package`,
    /// carrying `body` as `content_type`; `cseq` keeps each one a
    /// transaction of its own.
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

    /// Subscribe to `package` at `target`, and have the notifier grant it.
    /// Hands back the stack, the subscription and the SUBSCRIBE.
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

    /// An incoming call from `invite`, rung and waiting.
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
