// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! What the client remembers about who challenged it (RFC 3261 §22.1).
//!
//! A challenge is worth keeping. Without it every request costs two round
//! trips — one to be refused, one to be believed — and a registrar that
//! refreshes every few minutes pays that forever. So a challenge is kept per
//! protection domain, and the next request carries credentials before anyone
//! asks.
//!
//! Three things this refuses to do. It never uses one realm's challenge to
//! answer another, because "each such protection domain has its own set of
//! usernames and passwords". It never answers the same nonce twice after a
//! refusal: §22.1 says "A UAC MUST NOT re-attempt requests with the
//! credentials that have just been rejected (though the request may be retried
//! if the nonce was stale)", so a second challenge with the same nonce and no
//! `stale` means the password is wrong, and trying again would only lock the
//! account. And it never offers a proxy's credentials to a request that is not
//! the conversation they were earned in: §22.3 makes the `Call-ID` the limit —
//! "it should incorporate credentials for that realm in all subsequent
//! requests that contain the same Call-ID. These credentials MUST NOT be
//! cached across dialogs" — while §22.2 puts no such limit on a registrar's or
//! a callee's own challenge, which belongs to the destination rather than to
//! one conversation with it.

use std::sync::Arc;

use super::digest::Challenge;
use super::secret::Credentials;
use crate::msg::{ChallengeRef, HeaderError, HeaderName, Method, RawMessage};

/// What a challenge response was worth.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Learned {
    /// Something new to answer: the request is worth sending again.
    Retry,
    /// The same nonce came back without `stale`, so the credentials were
    /// refused rather than missing. §22.1 says not to try them again.
    Refused,
    /// Nothing here can be answered: no Digest challenge with an algorithm
    /// this stack has. "The client MUST ignore any challenge it does not
    /// understand" (RFC 8760 §2.4).
    Unusable,
}

/// The challenges a client is currently able to answer.
#[derive(Debug, Default)]
pub struct AuthCache {
    entries: Vec<Entry>,
}

#[derive(Debug)]
struct Entry {
    challenge: Challenge,
    cnonce: Arc<str>,
    /// How many times this client nonce has been used with this challenge.
    count: u32,
    refused: bool,
    /// The `Call-ID` of the request this was learned from, which is how far a
    /// proxy's challenge may travel (§22.3).
    call_id: Arc<[u8]>,
}

impl AuthCache {
    /// An empty cache.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Take in a 401 or a 407.
    ///
    /// `cnonce` is the client nonce to use for whatever is learned here; the
    /// core draws no random numbers, so it arrives from the caller. `call_id`
    /// is the one the refused request carried, which is how far a proxy's
    /// challenge may be re-used (§22.3). Per realm, the topmost challenge that
    /// can be answered wins — RFC 8760 §2.3 has the server list them "in the
    /// order in which it would prefer to see them used", and §2.4 has the
    /// client "use the topmost header field that it supports".
    pub fn learn(&mut self, response: &RawMessage<'_>, cnonce: &str, call_id: &[u8]) -> Learned {
        let www = response.www_authenticate().map(|c| (c, false));
        let proxy = response.proxy_authenticate().map(|c| (c, true));

        let mut outcome = Learned::Unusable;
        let mut seen: Vec<(bool, Arc<str>)> = Vec::new();
        let call_id: Arc<[u8]> = Arc::from(call_id);
        for (challenge, is_proxy) in www.chain(proxy) {
            let Some(challenge) = readable(challenge, is_proxy) else {
                continue;
            };
            let realm = (is_proxy, Arc::clone(&challenge.realm));
            if seen.contains(&realm) {
                // a lower one for a realm already answered: the server's
                // preference is the order it wrote them in
                continue;
            }
            seen.push(realm);
            outcome = worst(outcome, self.take(challenge, cnonce, &call_id));
        }
        outcome
    }

    /// The header fields to put on the request going out, one per challenge
    /// still worth answering.
    ///
    /// Each one spends a step of the counter, so a value taken here is a value
    /// that has to go on the wire: `nc` "MUST" be different for every request
    /// sent with the same nonce, and a skipped number looks to the server like
    /// a replay it should not accept.
    ///
    /// `call_id` is the one the request going out carries. A proxy's challenge
    /// is answered only inside the conversation it was made in (§22.3); a
    /// registrar's or a callee's own goes on any request to that destination,
    /// which is what §22.2 asks for and what spares a refresh its refusal.
    pub fn authorize(
        &mut self,
        credentials: &Credentials,
        method: Method<'_>,
        uri: &[u8],
        call_id: &[u8],
    ) -> Vec<(HeaderName<'static>, String)> {
        let mut out = Vec::new();
        for entry in &mut self.entries {
            if entry.refused || (entry.challenge.proxy && *entry.call_id != *call_id) {
                continue;
            }
            entry.count = entry.count.saturating_add(1);
            out.push((
                entry.challenge.header(),
                entry
                    .challenge
                    .respond(credentials, method, uri, entry.count, &entry.cnonce),
            ));
        }
        out
    }

    /// The challenges being answered, in the order they were learned.
    pub fn challenges(&self) -> impl Iterator<Item = &Challenge> {
        self.entries
            .iter()
            .filter(|entry| !entry.refused)
            .map(|entry| &entry.challenge)
    }

    /// Whether there is anything to send.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.challenges().next().is_none()
    }

    /// Forget everything, for a change of account.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    fn take(&mut self, challenge: Challenge, cnonce: &str, call_id: &Arc<[u8]>) -> Learned {
        let existing = self.entries.iter_mut().find(|entry| {
            entry.challenge.proxy == challenge.proxy && entry.challenge.realm == challenge.realm
        });
        let Some(entry) = existing else {
            self.entries.push(Entry {
                challenge,
                cnonce: Arc::from(cnonce),
                count: 0,
                refused: false,
                call_id: Arc::clone(call_id),
            });
            return Learned::Retry;
        };

        // "though the request may be retried if the nonce was stale". A nonce
        // the server has expired comes back with `stale`, and answering the
        // new one is what it is asking for; the same nonce without it means
        // the password was wrong, whether it went out after a refusal or
        // ahead of one.
        if entry.challenge.nonce == challenge.nonce && !challenge.stale {
            entry.refused = true;
            return Learned::Refused;
        }
        entry.challenge = challenge;
        entry.cnonce = Arc::from(cnonce);
        entry.count = 0;
        entry.refused = false;
        entry.call_id = Arc::clone(call_id);
        Learned::Retry
    }
}

fn readable(challenge: Result<ChallengeRef<'_>, HeaderError>, proxy: bool) -> Option<Challenge> {
    Challenge::read(&challenge.ok()?, proxy)
}

/// One answerable challenge makes the whole response answerable; a refusal
/// only stands if nothing else could be answered.
const fn worst(current: Learned, next: Learned) -> Learned {
    match (current, next) {
        (Learned::Retry, _) | (_, Learned::Retry) => Learned::Retry,
        (Learned::Refused, _) | (_, Learned::Refused) => Learned::Refused,
        _ => Learned::Unusable,
    }
}

#[cfg(test)]
mod tests {
    use super::{AuthCache, Learned};
    use crate::auth::{Credentials, DigestAlgorithm};
    use crate::msg::{HeaderName, Method, ParseMode, ParseScratch, parse};

    /// A 401 or 407 carrying the given challenge lines.
    fn refusal(status: u16, challenges: &[(&str, &str)]) -> Vec<u8> {
        let mut out = format!(
            "SIP/2.0 {status} Unauthorized\r\n\
Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK1\r\n\
From: <sip:alice@example.com>;tag=alice1\r\n\
To: <sip:alice@example.com>;tag=server1\r\n\
Call-ID: a84b4c76e66710\r\n\
CSeq: 1 REGISTER\r\n"
        );
        for (field, value) in challenges {
            out.push_str(field);
            out.push_str(": ");
            out.push_str(value);
            out.push_str("\r\n");
        }
        out.push_str("Content-Length: 0\r\n\r\n");
        out.into_bytes()
    }

    /// The `Call-ID` of the request every test here is answering for.
    const CALL: &[u8] = b"a84b4c76e66710";

    fn learn(cache: &mut AuthCache, bytes: &[u8]) -> Learned {
        let mut scratch = ParseScratch::new();
        let response = parse(bytes, &mut scratch, ParseMode::Strict).expect("a response");
        cache.learn(&response, "0a4f113b", CALL)
    }

    fn authorize(cache: &mut AuthCache) -> Vec<(HeaderName<'static>, String)> {
        authorize_for(cache, CALL)
    }

    fn authorize_for(cache: &mut AuthCache, call_id: &[u8]) -> Vec<(HeaderName<'static>, String)> {
        cache.authorize(
            &Credentials::new("alice", "secret"),
            Method::Register,
            b"sip:example.com",
            call_id,
        )
    }

    fn challenge(realm: &str, nonce: &str, extra: &str) -> String {
        format!("Digest realm=\"{realm}\", nonce=\"{nonce}\", qop=\"auth\"{extra}")
    }

    #[test]
    fn a_challenge_is_kept_so_the_next_request_can_carry_it() {
        let mut cache = AuthCache::new();
        assert!(cache.is_empty());
        assert_eq!(
            learn(
                &mut cache,
                &refusal(
                    401,
                    &[("WWW-Authenticate", &challenge("example.com", "n1", ""))]
                )
            ),
            Learned::Retry
        );
        assert!(!cache.is_empty());

        let first = authorize(&mut cache);
        assert_eq!(first.len(), 1);
        assert_eq!(first.first().expect("one").0, HeaderName::Authorization);
        assert!(first.first().expect("one").1.contains("nc=00000001"));

        // the counter is what makes a captured response useless a second time
        let second = authorize(&mut cache);
        assert!(second.first().expect("one").1.contains("nc=00000002"));
        assert_ne!(
            first.first().expect("one").1,
            second.first().expect("one").1,
            "the same request twice is two different responses"
        );
    }

    #[test]
    fn the_two_spaces_are_answered_in_their_own_fields() {
        let mut cache = AuthCache::new();
        learn(
            &mut cache,
            &refusal(
                401,
                &[
                    ("WWW-Authenticate", &challenge("example.com", "n1", "")),
                    (
                        "Proxy-Authenticate",
                        &challenge("proxy.example.net", "n2", ""),
                    ),
                ],
            ),
        );
        let values = authorize(&mut cache);
        assert_eq!(values.len(), 2);
        assert_eq!(values.first().expect("first").0, HeaderName::Authorization);
        assert_eq!(
            values.get(1).expect("second").0,
            HeaderName::ProxyAuthorization
        );
        assert!(
            values
                .first()
                .expect("first")
                .1
                .contains("realm=\"example.com\"")
        );
        assert!(
            values
                .get(1)
                .expect("second")
                .1
                .contains("realm=\"proxy.example.net\"")
        );
    }

    #[test]
    fn the_topmost_challenge_we_understand_is_the_one_answered() {
        // "The UAS MUST add these header fields to the response in the order
        // in which it would prefer to see them used"
        let mut cache = AuthCache::new();
        learn(
            &mut cache,
            &refusal(
                401,
                &[
                    (
                        "WWW-Authenticate",
                        &challenge("example.com", "n1", ", algorithm=SHA-512-256"),
                    ),
                    (
                        "WWW-Authenticate",
                        &challenge("example.com", "n1", ", algorithm=MD5"),
                    ),
                ],
            ),
        );
        let kept: Vec<DigestAlgorithm> = cache.challenges().map(|c| c.algorithm).collect();
        assert_eq!(kept, [DigestAlgorithm::Sha512_256]);
    }

    #[test]
    fn a_challenge_we_cannot_read_is_skipped_and_the_next_one_taken() {
        let mut cache = AuthCache::new();
        assert_eq!(
            learn(
                &mut cache,
                &refusal(
                    401,
                    &[
                        (
                            "WWW-Authenticate",
                            &challenge("example.com", "n1", ", algorithm=SHA3-512"),
                        ),
                        (
                            "WWW-Authenticate",
                            &challenge("example.com", "n1", ", algorithm=SHA-256"),
                        ),
                    ],
                ),
            ),
            Learned::Retry
        );
        let kept: Vec<DigestAlgorithm> = cache.challenges().map(|c| c.algorithm).collect();
        assert_eq!(kept, [DigestAlgorithm::Sha256]);
    }

    #[test]
    fn the_same_nonce_coming_back_means_the_password_was_wrong() {
        let mut cache = AuthCache::new();
        let refused = refusal(
            401,
            &[("WWW-Authenticate", &challenge("example.com", "n1", ""))],
        );
        assert_eq!(learn(&mut cache, &refused), Learned::Retry);
        authorize(&mut cache);

        assert_eq!(learn(&mut cache, &refused), Learned::Refused);
        assert!(
            authorize(&mut cache).is_empty(),
            "a UAC MUST NOT re-attempt with credentials that have just been rejected"
        );
        assert!(cache.is_empty());
    }

    #[test]
    fn a_stale_nonce_is_worth_another_try_with_the_same_password() {
        let mut cache = AuthCache::new();
        learn(
            &mut cache,
            &refusal(
                401,
                &[("WWW-Authenticate", &challenge("example.com", "n1", ""))],
            ),
        );
        authorize(&mut cache);
        authorize(&mut cache);

        let stale = refusal(
            401,
            &[(
                "WWW-Authenticate",
                &challenge("example.com", "n1", ", stale=true"),
            )],
        );
        assert_eq!(learn(&mut cache, &stale), Learned::Retry);
        let value = authorize(&mut cache);
        assert!(
            value.first().expect("one").1.contains("nc=00000001"),
            "a new nonce starts its own count"
        );
    }

    #[test]
    fn a_new_nonce_for_a_realm_replaces_the_old_one() {
        let mut cache = AuthCache::new();
        learn(
            &mut cache,
            &refusal(
                401,
                &[("WWW-Authenticate", &challenge("example.com", "n1", ""))],
            ),
        );
        assert_eq!(
            learn(
                &mut cache,
                &refusal(
                    401,
                    &[("WWW-Authenticate", &challenge("example.com", "n2", ""))]
                )
            ),
            Learned::Retry
        );
        assert_eq!(cache.challenges().count(), 1, "one realm, one challenge");
        let value = authorize(&mut cache);
        assert!(value.first().expect("one").1.contains("nonce=\"n2\""));
    }

    #[test]
    fn a_second_realm_is_a_second_entry() {
        let mut cache = AuthCache::new();
        learn(
            &mut cache,
            &refusal(
                401,
                &[("WWW-Authenticate", &challenge("example.com", "n1", ""))],
            ),
        );
        learn(
            &mut cache,
            &refusal(
                401,
                &[("WWW-Authenticate", &challenge("example.net", "n2", ""))],
            ),
        );
        assert_eq!(cache.challenges().count(), 2);
        assert_eq!(authorize(&mut cache).len(), 2);
    }

    #[test]
    fn a_response_with_nothing_we_understand_is_unusable() {
        let mut cache = AuthCache::new();
        assert_eq!(
            learn(
                &mut cache,
                &refusal(401, &[("WWW-Authenticate", "Basic realm=\"example.com\"")])
            ),
            Learned::Unusable
        );
        assert!(cache.is_empty());
        assert!(authorize(&mut cache).is_empty());
    }

    #[test]
    fn clearing_it_forgets_everything() {
        let mut cache = AuthCache::new();
        learn(
            &mut cache,
            &refusal(
                401,
                &[("WWW-Authenticate", &challenge("example.com", "n1", ""))],
            ),
        );
        cache.clear();
        assert!(cache.is_empty());
    }
}
