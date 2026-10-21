// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! What the proxy asks a notification service for, and what it hears back.
//!
//! RFC 8599 leaves the push request itself to each service (§5.1), and asks
//! for no payload (§13). The device's side of this repository does want two
//! things in it, both read off the request held in the bucket: who is
//! calling, which `PushKitBridge` reads as `caller` and
//! `sipral_account_announce` matches the INVITE by, and the INVITE's
//! `Call-ID`, which `sipral_account_announce_call` matches it by first
//! (docs/15-mobile.md, "The matching rule"). So a push carries `kind`, then
//! `caller`, `name` when the caller gave one, and `call-id`, for whatever is
//! held; a refresh, with nothing held, carries `kind` alone.

use crate::json;

/// Why the device is being woken.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PushKind {
    /// An INVITE is held for it (§5.6.2).
    Call,
    /// A MESSAGE is held for it (§5.6.2).
    Message,
    /// A request inside a dialog is held for it (§6.2.3).
    Dialog,
    /// Its binding is about to lapse and nothing is held (§5.5).
    Refresh,
}

impl PushKind {
    /// The word the payload says it with.
    pub(crate) const fn word(self) -> &'static str {
        match self {
            Self::Call => "call",
            Self::Message => "message",
            Self::Dialog => "dialog",
            Self::Refresh => "refresh",
        }
    }

    /// Whether `provider` may be asked for a push of this kind.
    ///
    /// On APNs the only push that reaches a VoIP application is a VoIP push,
    /// and since iOS 13 an application that receives one and reports no call
    /// to CallKit is terminated and, after a few times, stops receiving them
    /// (PushKit's documentation, `pushRegistry(_:didReceiveIncomingPushWith:
    /// for:completion:)`). A MESSAGE, a re-INVITE or a refresh is not a call
    /// the user should be shown, so on APNs only an INVITE is pushed. FCM's
    /// high-priority data message carries no such rule.
    pub(crate) fn allowed_on(self, provider: &str) -> bool {
        match provider {
            "apns" => self == Self::Call,
            _ => true,
        }
    }
}

/// One push the proxy wants sent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PushRequest {
    /// The proxy's own number for it, which the outcome comes back with.
    pub(crate) id: u64,
    /// `pn-provider`, lower case.
    pub(crate) provider: String,
    /// `pn-prid`, unescaped.
    pub(crate) prid: String,
    /// `pn-param`, unescaped, when there was one.
    pub(crate) param: Option<String>,
    /// Why.
    pub(crate) kind: PushKind,
    /// The `From` URI of the request that is held, when one is.
    pub(crate) caller: Option<String>,
    /// The display name on that `From`, when it has one.
    pub(crate) name: Option<String>,
    /// The `Call-ID` of the request that is held, when one is.
    pub(crate) call_id: Option<String>,
}

impl PushRequest {
    /// The payload as a JSON object: `kind`, then `caller`, `name` and
    /// `call-id` when there are any. Every value a string, which FCM's `data`
    /// requires and APNs does not mind.
    pub(crate) fn payload(&self) -> String {
        let mut fields = vec![("kind", self.kind.word().to_owned())];
        if let Some(caller) = &self.caller {
            fields.push(("caller", caller.clone()));
        }
        if let Some(name) = &self.name {
            fields.push(("name", name.clone()));
        }
        if let Some(call_id) = &self.call_id {
            fields.push(("call-id", call_id.clone()));
        }
        json::object(&fields)
    }
}

/// What the service said.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum PushOutcome {
    /// Accepted for delivery, with whatever the service called it.
    Accepted(String),
    /// Refused, or never reached: why, in the service's own words.
    Failed(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_call_is_pushed_on_apns() {
        assert!(PushKind::Call.allowed_on("apns"));
        assert!(!PushKind::Message.allowed_on("apns"));
        assert!(!PushKind::Refresh.allowed_on("apns"));
        assert!(!PushKind::Dialog.allowed_on("apns"));
        assert!(PushKind::Message.allowed_on("fcm"));
        assert!(PushKind::Refresh.allowed_on("fcm"));
    }

    #[test]
    fn the_payload_names_the_caller_and_the_call() {
        let request = PushRequest {
            id: 1,
            provider: "apns".into(),
            prid: "00ff".into(),
            param: Some("ABCDE12345.org.example.voip".into()),
            kind: PushKind::Call,
            caller: Some("sip:alice@example.com".into()),
            name: Some("Alice \"A\"".into()),
            call_id: Some("a84b4c76e66710@pc33.example.com".into()),
        };
        assert_eq!(
            request.payload(),
            r#"{"kind":"call","caller":"sip:alice@example.com","name":"Alice \"A\"","call-id":"a84b4c76e66710@pc33.example.com"}"#
        );
        let refresh = PushRequest {
            kind: PushKind::Refresh,
            caller: None,
            name: None,
            call_id: None,
            ..request
        };
        assert_eq!(refresh.payload(), r#"{"kind":"refresh"}"#);
    }
}
