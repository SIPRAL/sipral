// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

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

/// An answer to the challenges a destination has made, and which of them it
/// covers.
///
/// Two halves because the nonce count may not move until the bytes do. The
/// fields go on the request; the rest is what [`AuthCache::spend`] needs to
/// move the counter on afterwards, and names the nonce each answer was made
/// to so that a challenge relearned in between is left alone.
#[derive(Debug, Default)]
#[must_use = "the fields have to go on a request, and the count spent once they have"]
pub struct Answered {
    fields: Vec<(HeaderName<'static>, String)>,
    answered: Vec<(bool, Arc<str>, Arc<str>)>,
}

impl Answered {
    /// The header fields, to put on the request.
    #[must_use]
    pub fn fields(&self) -> &[(HeaderName<'static>, String)] {
        &self.fields
    }

    /// Whether there is anything to send.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }
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

    /// Take in a 401 or a 407, answering `request`.
    ///
    /// `request` is the one that was refused, as it went out: its `Call-ID`
    /// is how far a proxy's challenge may be re-used (§22.3), and the
    /// credentials it carried say whether a nonce coming back was a verdict
    /// on them. `cnonce` is the client nonce to use for whatever is learned
    /// here; the core draws no random numbers, so it arrives from the caller.
    /// Per realm, the topmost challenge that can be answered wins — RFC 8760
    /// §2.3 has the server list them "in the order in which it would prefer
    /// to see them used", and §2.4 has the client "use the topmost header
    /// field that it supports".
    pub fn learn(
        &mut self,
        response: &RawMessage<'_>,
        request: &RawMessage<'_>,
        cnonce: &str,
    ) -> Learned {
        let www = response.www_authenticate().map(|c| (c, false));
        let proxy = response.proxy_authenticate().map(|c| (c, true));
        let carried = carried(request);

        let mut outcome = Learned::Unusable;
        let mut seen: Vec<(bool, Arc<str>)> = Vec::new();
        let call_id: Arc<[u8]> = Arc::from(request.call_id().unwrap_or_default());
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
            let answered = carried.iter().any(|(proxy, realm, nonce)| {
                *proxy == challenge.proxy
                    && **realm == *challenge.realm.as_bytes()
                    && **nonce == *challenge.nonce.as_bytes()
            });
            outcome = worst(outcome, self.take(challenge, cnonce, &call_id, answered));
        }
        outcome
    }

    /// The header fields to put on the request going out, one per challenge
    /// still worth answering.
    ///
    /// Working out the answer does not move the counter. `nc` "MUST" be
    /// different for every request sent with the same nonce, so the number
    /// belongs to the request that actually leaves: a request that is built
    /// and then refused — §18.1.1 asking for a stream is the one that
    /// happens — would otherwise take a number with it into the bin, and
    /// whoever is asked next either repeats it, which the server reads as a
    /// replay, or steps over it. [`Self::spend`] is what moves the counter,
    /// and belongs immediately after the bytes are committed to a
    /// transaction.
    ///
    /// `call_id` is the one the request going out carries. A proxy's challenge
    /// is answered only inside the conversation it was made in (§22.3); a
    /// registrar's or a callee's own goes on any request to that destination,
    /// which is what §22.2 asks for and what spares a refresh its refusal.
    pub fn authorize(
        &self,
        credentials: &Credentials,
        method: Method<'_>,
        uri: &[u8],
        call_id: &[u8],
    ) -> Answered {
        let mut answered = Answered::default();
        for entry in &self.entries {
            if entry.refused || (entry.challenge.proxy && *entry.call_id != *call_id) {
                continue;
            }
            let count = entry.count.saturating_add(1);
            answered.fields.push((
                entry.challenge.header(),
                entry
                    .challenge
                    .respond(credentials, method, uri, count, &entry.cnonce),
            ));
            answered.answered.push((
                entry.challenge.proxy,
                Arc::clone(&entry.challenge.realm),
                entry.challenge.nonce.clone(),
            ));
        }
        answered
    }

    /// Move the counter on for every challenge the answer covered, now that
    /// the request carrying it is on its way.
    ///
    /// An entry that has changed since the answer was drawn — a new challenge
    /// learned in between, which resets the count — is left alone: the answer
    /// was to a nonce this cache no longer holds, and moving a count that
    /// belongs to a different nonce is worse than leaving it where it is.
    pub fn spend(&mut self, answered: &Answered) {
        for (proxy, realm, nonce) in &answered.answered {
            let Some(entry) = self.entries.iter_mut().find(|entry| {
                entry.challenge.proxy == *proxy
                    && entry.challenge.realm == *realm
                    && entry.challenge.nonce == *nonce
            }) else {
                continue;
            };
            entry.count = entry.count.saturating_add(1);
        }
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

    /// Stop answering these challenges, and stop offering the credentials
    /// ahead of one.
    ///
    /// For when an answer has been given as many times as it is going to be.
    /// §22.1's guard — the same nonce back without `stale` means the password
    /// was wrong — turns on the nonce being the same, and a server that draws
    /// a fresh one for every refusal walks straight past it. Stopping the
    /// retries alone would not be enough: [`Self::authorize`] would go on
    /// putting the same wrong password on every later request to this
    /// destination, which is the same lock-out at a slower rate.
    ///
    /// It is not permanent. A later challenge carrying a nonce this cache has
    /// not answered starts the entry again, which is what lets a password
    /// corrected while the process runs take effect.
    ///
    /// Only the protection domains `response` is challenging are closed. One
    /// destination can hold a registrar's realm and a proxy's at once, with
    /// different passwords and only one of them wrong; refusing the lot
    /// because one ran out of answers would stop sending credentials that
    /// were working and had never been refused by anybody.
    pub fn refuse(&mut self, response: &RawMessage<'_>) {
        let www = response.www_authenticate().map(|c| (c, false));
        let proxy = response.proxy_authenticate().map(|c| (c, true));
        for (challenge, is_proxy) in www.chain(proxy) {
            let Some(challenge) = readable(challenge, is_proxy) else {
                continue;
            };
            for entry in &mut self.entries {
                if entry.challenge.proxy == challenge.proxy
                    && entry.challenge.realm == challenge.realm
                {
                    entry.refused = true;
                }
            }
        }
    }

    /// The same for one protection domain named outright: stop answering it,
    /// and stop offering the credentials ahead of it.
    ///
    /// For a challenge the caller decided not to answer at all — one from
    /// somebody the password is not for. Learning it already put it here,
    /// and left there [`Self::authorize`] would hand that party an answer
    /// on the next request to the same destination without being asked. A
    /// later challenge with a nonce not answered opens the entry again, and
    /// the caller decides about that one too.
    pub fn refuse_realm(&mut self, proxy: bool, realm: &str) {
        for entry in &mut self.entries {
            if entry.challenge.proxy == proxy && *entry.challenge.realm == *realm {
                entry.refused = true;
            }
        }
    }

    /// `answered` is whether the refused request carried an answer to this
    /// very challenge — its realm and its nonce.
    fn take(
        &mut self,
        challenge: Challenge,
        cnonce: &str,
        call_id: &Arc<[u8]>,
        answered: bool,
    ) -> Learned {
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
        // new one is what it is asking for; the same nonce without it, on a
        // request that answered it, means the password was wrong, whether it
        // went out after a refusal or ahead of one.
        if entry.challenge.nonce == challenge.nonce && !challenge.stale {
            if answered || entry.refused {
                entry.refused = true;
                return Learned::Refused;
            }
            // §22.1 forbids re-sending "the credentials that have just been
            // rejected", and a request that carried none had nothing
            // rejected: a server that draws its nonce from the clock hands
            // the same one to every request in the same second, so the
            // SUBSCRIBE that follows a REGISTER is challenged with the nonce
            // the REGISTER already answered. It is still good, so it is
            // answered again — and the count is left where it is, since `nc`
            // numbers every request sent with one nonce (RFC 7616 §3.4).
            // The request's own allowance still caps how often.
            entry.call_id = Arc::clone(call_id);
            return Learned::Retry;
        }
        // a new nonce starts its own count; the same one marked stale does
        // not, for the reason the branch above keeps it: `nc` counts the
        // requests sent "with the nonce value", and starting it again would
        // send 00000001 under the same nonce and cnonce a second time — to
        // the server, the first request replayed
        if entry.challenge.nonce != challenge.nonce {
            entry.cnonce = Arc::from(cnonce);
            entry.count = 0;
        }
        entry.challenge = challenge;
        entry.refused = false;
        entry.call_id = Arc::clone(call_id);
        Learned::Retry
    }
}

/// The realm and nonce of every set of credentials `request` carried, with
/// which of the two spaces each answered. Values that do not parse carried
/// nothing anyone could have refused.
fn carried(request: &RawMessage<'_>) -> Vec<(bool, Vec<u8>, Vec<u8>)> {
    let www = request.authorization().map(|c| (c, false));
    let proxy = request.proxy_authorization().map(|c| (c, true));
    www.chain(proxy)
        .filter_map(|(credentials, is_proxy)| {
            let credentials = credentials.ok()?;
            Some((
                is_proxy,
                credentials.realm()?.into_owned(),
                credentials.nonce()?.into_owned(),
            ))
        })
        .collect()
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

    /// Take in a refusal of a request that carried no credentials.
    fn learn(cache: &mut AuthCache, bytes: &[u8]) -> Learned {
        learn_after(cache, bytes, &[])
    }

    /// Take in a refusal of a request that carried `fields`.
    fn learn_after(
        cache: &mut AuthCache,
        bytes: &[u8],
        fields: &[(HeaderName<'static>, String)],
    ) -> Learned {
        let mut sent = format!(
            "REGISTER sip:example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK1\r\n\
From: <sip:alice@example.com>;tag=alice1\r\n\
To: <sip:alice@example.com>\r\n\
Call-ID: {}\r\n\
CSeq: 1 REGISTER\r\n",
            String::from_utf8_lossy(CALL)
        );
        for (name, value) in fields {
            sent.push_str(&name.to_string());
            sent.push_str(": ");
            sent.push_str(value);
            sent.push_str("\r\n");
        }
        sent.push_str("Content-Length: 0\r\n\r\n");
        let (mut scratch, mut sent_scratch) = (ParseScratch::new(), ParseScratch::new());
        let response = parse(bytes, &mut scratch, ParseMode::Strict).expect("a response");
        let request =
            parse(sent.as_bytes(), &mut sent_scratch, ParseMode::Strict).expect("a request");
        cache.learn(&response, &request, "0a4f113b")
    }

    fn authorize(cache: &mut AuthCache) -> Vec<(HeaderName<'static>, String)> {
        authorize_for(cache, CALL)
    }

    /// Draw and spend in one go, which is what a caller that sends does.
    fn authorize_for(cache: &mut AuthCache, call_id: &[u8]) -> Vec<(HeaderName<'static>, String)> {
        let answered = cache.authorize(
            &Credentials::new("alice", "secret"),
            Method::Register,
            b"sip:example.com",
            call_id,
        );
        cache.spend(&answered);
        answered.fields().to_vec()
    }

    fn challenge(realm: &str, nonce: &str, extra: &str) -> String {
        format!("Digest realm=\"{realm}\", nonce=\"{nonce}\", qop=\"auth\"{extra}")
    }

    #[test]
    fn running_out_of_answers_in_one_realm_leaves_the_other_alone() {
        // A destination can hold a registrar's realm and a proxy's at once,
        // with different passwords and only one of them wrong. Closing the
        // lot because one ran out of answers would stop sending credentials
        // that were working and that nobody had refused.
        let mut cache = AuthCache::new();
        assert_eq!(
            learn(
                &mut cache,
                &refusal(
                    401,
                    &[
                        ("WWW-Authenticate", &challenge("example.com", "n1", "")),
                        (
                            "Proxy-Authenticate",
                            &challenge("proxy.example.net", "p1", "")
                        ),
                    ]
                )
            ),
            Learned::Retry
        );
        assert_eq!(cache.challenges().count(), 2, "both realms are live");

        // the registrar's allowance runs out, so its realm is closed
        let spent = refusal(
            401,
            &[("WWW-Authenticate", &challenge("example.com", "n2", ""))],
        );
        let mut scratch = ParseScratch::new();
        let spent = parse(&spent, &mut scratch, ParseMode::Strict).expect("a response");
        cache.refuse(&spent);

        let left: Vec<_> = cache
            .challenges()
            .map(|challenge| (challenge.proxy, challenge.realm.to_string()))
            .collect();
        assert_eq!(
            left,
            vec![(true, "proxy.example.net".to_owned())],
            "the proxy's credentials were never refused by anybody"
        );
        let still_offered = authorize(&mut cache);
        assert_eq!(still_offered.len(), 1);
        assert_eq!(
            still_offered.first().expect("one").0,
            HeaderName::ProxyAuthorization
        );
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
        let sent = authorize(&mut cache);

        assert_eq!(learn_after(&mut cache, &refused, &sent), Learned::Refused);
        assert!(
            authorize(&mut cache).is_empty(),
            "a UAC MUST NOT re-attempt with credentials that have just been rejected"
        );
        assert!(cache.is_empty());
    }

    #[test]
    fn the_same_nonce_on_a_request_that_did_not_answer_it_is_answered() {
        // A server that draws its nonce from the clock challenges every
        // request in one second with the same one: the SUBSCRIBE that follows
        // a REGISTER is refused with the nonce the REGISTER already answered.
        // Nothing was rejected — the SUBSCRIBE carried no credentials — so the
        // nonce is answered again, counting on from where it was.
        let mut cache = AuthCache::new();
        let refused = refusal(
            401,
            &[("WWW-Authenticate", &challenge("example.com", "n1", ""))],
        );
        assert_eq!(learn(&mut cache, &refused), Learned::Retry);
        let first = authorize(&mut cache);
        assert!(first.first().expect("one").1.contains("nc=00000001"));

        assert_eq!(learn(&mut cache, &refused), Learned::Retry);
        let again = authorize(&mut cache);
        assert!(
            again.first().expect("one").1.contains("nc=00000002"),
            "nc numbers every request sent with the nonce: {again:?}"
        );

        // and once that answer is refused in its turn, the password is wrong
        assert_eq!(learn_after(&mut cache, &refused, &again), Learned::Refused);
        // after which not even an unanswered request gets it again
        assert_eq!(learn(&mut cache, &refused), Learned::Refused);
    }

    #[test]
    fn an_answer_to_another_realm_or_nonce_is_not_this_one() {
        let mut cache = AuthCache::new();
        let refused = refusal(
            401,
            &[("WWW-Authenticate", &challenge("example.com", "n1", ""))],
        );
        assert_eq!(learn(&mut cache, &refused), Learned::Retry);
        authorize(&mut cache);
        let elsewhere = [(
            HeaderName::Authorization,
            "Digest username=\"alice\", realm=\"other.example\", nonce=\"n1\", \
uri=\"sip:example.com\", response=\"00\""
                .to_owned(),
        )];
        assert_eq!(
            learn_after(&mut cache, &refused, &elsewhere),
            Learned::Retry
        );
        let older = [(
            HeaderName::Authorization,
            "Digest username=\"alice\", realm=\"example.com\", nonce=\"n0\", \
uri=\"sip:example.com\", response=\"00\""
                .to_owned(),
        )];
        assert_eq!(learn_after(&mut cache, &refused, &older), Learned::Retry);
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
        // RFC 7616 §3.4: nc is the "count of the number of requests
        // (including the current request) that the client has sent with the
        // nonce value in this request". Two went with n1 already, so this is
        // the third, stale or not; a second nc=00000001 with n1 is the same
        // nc value "seen twice", which the server reads as a replay
        assert!(
            value.first().expect("one").1.contains("nc=00000003"),
            "the same nonce carries on its own count: {value:?}"
        );

        // while a stale challenge with a nonce of its own starts one
        let fresh = refusal(
            401,
            &[(
                "WWW-Authenticate",
                &challenge("example.com", "n2", ", stale=true"),
            )],
        );
        assert_eq!(learn(&mut cache, &fresh), Learned::Retry);
        let value = authorize(&mut cache);
        assert!(
            value.first().expect("one").1.contains("nc=00000001"),
            "a new nonce starts its own count: {value:?}"
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
