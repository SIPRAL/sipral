// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! What the client remembers about who challenged it (RFC 3261 §22.1).
//!
//! A challenge is kept per protection domain so the next request carries
//! credentials up front, instead of paying two round trips on every refresh.
//!
//! Three rules:
//! - One realm's challenge never answers another: "each such protection
//!   domain has its own set of usernames and passwords".
//! - A nonce is not answered again after a refusal. §22.1: "A UAC MUST NOT
//!   re-attempt requests with the credentials that have just been rejected
//!   (though the request may be retried if the nonce was stale)". The same
//!   nonce back without `stale` means a wrong password; retrying would only
//!   lock the account.
//! - A proxy's credentials stay within their `Call-ID` (§22.3: "These
//!   credentials MUST NOT be cached across dialogs"). A registrar's or
//!   callee's challenge (§22.2) belongs to the destination and has no such
//!   limit.

use std::sync::Arc;

use super::bearer::{self, BearerChallenge};
use super::digest::Challenge;
use super::secret::Credentials;
use crate::msg::{HeaderName, Method, RawMessage};

/// What a challenge response was worth.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Learned {
    /// Something new to answer: the request is worth sending again.
    Retry,
    /// The same nonce came back without `stale`, so the credentials were
    /// refused rather than missing. §22.1 says not to try them again.
    Refused,
    /// Nothing here can be answered: no Digest challenge with a supported
    /// algorithm and no `Bearer` one. "The client MUST ignore any challenge
    /// it does not understand" (RFC 8760 §2.4).
    Unusable,
}

/// The challenges a client is currently able to answer.
#[derive(Debug, Default)]
pub struct AuthCache {
    entries: Vec<Entry>,
    bearer: Vec<BearerEntry>,
}

/// An answer to a destination's challenges, and which of them it covers.
///
/// The nonce count may not move until the bytes are sent. The fields go on
/// the request; the rest lets [`AuthCache::spend`] move the counter later,
/// and names each nonce so a challenge relearned in between is left alone.
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

/// A `Bearer` challenge (RFC 8898), and the token it last refused.
#[derive(Debug)]
struct BearerEntry {
    challenge: BearerChallenge,
    /// SHA-256 of the last token this domain refused. A request that carried
    /// it and was challenged again means the token was turned down, whatever
    /// `error` says, so it is not offered here again. The value is never kept.
    rejected: Option<[u8; 32]>,
    refused: bool,
    /// As [`Entry::call_id`]: how far a proxy's challenge may travel.
    call_id: Arc<[u8]>,
}

#[derive(Debug)]
struct Entry {
    challenge: Challenge,
    cnonce: Arc<str>,
    /// How many times this client nonce has been used with this challenge.
    count: u32,
    refused: bool,
    /// The `Call-ID` this was learned from: how far a proxy's challenge may
    /// travel (§22.3).
    call_id: Arc<[u8]>,
}

impl AuthCache {
    /// An empty cache.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
            bearer: Vec::new(),
        }
    }

    /// Take in a 401 or a 407 answering `request`.
    ///
    /// `request` is the refused request as sent: its `Call-ID` bounds a
    /// proxy's challenge (§22.3), and its credentials say whether a repeated
    /// nonce is a verdict on them. `cnonce` comes from the caller because the
    /// core draws no random numbers. Per realm the topmost answerable
    /// challenge wins: servers list them "in the order in which it would
    /// prefer to see them used" (RFC 8760 §2.3), and the client uses "the
    /// topmost header field that it supports" (§2.4).
    ///
    /// A `Bearer` challenge (RFC 8898) is kept beside the Digest ones, one
    /// per protection domain. A token that was refused is not offered to
    /// that domain again; only a different token answers it.
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
            let Ok(challenge) = challenge else {
                continue;
            };
            if let Some(challenge) = BearerChallenge::read(&challenge, is_proxy) {
                let carried = carried_token(request, is_proxy);
                outcome = worst(outcome, self.take_bearer(challenge, &call_id, carried));
                continue;
            }
            let Some(challenge) = Challenge::read(&challenge, is_proxy) else {
                continue;
            };
            let realm = (is_proxy, Arc::clone(&challenge.realm));
            if seen.contains(&realm) {
                // the server's preference is the order it wrote them in
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

    /// The header fields for the outgoing request, one per challenge still
    /// worth answering.
    ///
    /// This does not move the counter. `nc` must differ for every request
    /// sent with a nonce, so it belongs to the request that actually leaves.
    /// A request built and then dropped (§18.1.1 asking for a stream) would
    /// otherwise burn a number, and the next request would repeat it (seen
    /// as a replay) or skip it. Call [`Self::spend`] right after the bytes
    /// are committed to a transaction.
    ///
    /// `call_id` is the outgoing request's. A proxy's challenge is answered
    /// only within its conversation (§22.3); a registrar's or callee's goes
    /// on any request to that destination (§22.2).
    pub fn authorize(
        &self,
        credentials: &Credentials,
        method: Method<'_>,
        uri: &[u8],
        call_id: &[u8],
    ) -> Answered {
        let mut answered = Answered::default();
        // RFC 8898 §2.1.1: offered both schemes for one realm, the client
        // picks "based on local policy". Ours: an application that supplied
        // a token did so for this server.
        let mut by_token: Vec<(bool, &str)> = Vec::new();
        let token = bearer::fingerprint_of(credentials);
        for entry in &self.bearer {
            if entry.refused
                || (entry.challenge.proxy && *entry.call_id != *call_id)
                || token.is_none()
                || token == entry.rejected
            {
                continue;
            }
            let Some(value) = BearerChallenge::respond(credentials) else {
                continue;
            };
            answered.fields.push((entry.challenge.header(), value));
            by_token.push((entry.challenge.proxy, &entry.challenge.realm));
        }
        for entry in &self.entries {
            if entry.refused
                || (entry.challenge.proxy && *entry.call_id != *call_id)
                || by_token.contains(&(entry.challenge.proxy, &*entry.challenge.realm))
            {
                continue;
            }
            let count = entry.count.saturating_add(1);
            let Some(value) =
                entry
                    .challenge
                    .respond(credentials, method, uri, count, &entry.cnonce)
            else {
                continue;
            };
            answered.fields.push((entry.challenge.header(), value));
            answered.answered.push((
                entry.challenge.proxy,
                Arc::clone(&entry.challenge.realm),
                entry.challenge.nonce.clone(),
            ));
        }
        answered
    }

    /// Move the counter on for every challenge the answer covered, now that
    /// the request is on its way.
    ///
    /// An entry relearned since the answer was drawn (which resets its count)
    /// is left alone: the count now belongs to a different nonce.
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

    /// The `Bearer` challenges being answered, in the order they were learned.
    pub fn bearer_challenges(&self) -> impl Iterator<Item = &BearerChallenge> {
        self.bearer
            .iter()
            .filter(|entry| !entry.refused)
            .map(|entry| &entry.challenge)
    }

    /// The first open `Bearer` challenge `credentials` cannot answer: no
    /// token, or only the one that domain refused. The application needs a
    /// new token for it.
    #[must_use]
    pub fn token_wanted(&self, credentials: Option<&Credentials>) -> Option<&BearerChallenge> {
        let token = credentials.and_then(bearer::fingerprint_of);
        self.bearer
            .iter()
            .find(|entry| !entry.refused && (token.is_none() || token == entry.rejected))
            .map(|entry| &entry.challenge)
    }

    /// Whether there is anything to send.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.challenges().next().is_none() && self.bearer_challenges().next().is_none()
    }

    /// Forget everything, for a change of account.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.bearer.clear();
    }

    /// Stop answering the challenges in `response`, and stop sending the
    /// credentials up front for them.
    ///
    /// For when the retry allowance is spent. §22.1's guard relies on the
    /// nonce repeating, and a server that issues a fresh nonce per refusal
    /// bypasses it. Stopping retries alone is not enough: [`Self::authorize`]
    /// would keep sending the wrong password on later requests, locking the
    /// account more slowly.
    ///
    /// Not permanent: a later challenge with an unanswered nonce reopens the
    /// entry, so a password corrected at runtime takes effect.
    ///
    /// Only the domains `response` challenges are closed. A destination can
    /// hold a registrar's and a proxy's realm with different passwords, and
    /// the working one must keep going.
    pub fn refuse(&mut self, response: &RawMessage<'_>) {
        let www = response.www_authenticate().map(|c| (c, false));
        let proxy = response.proxy_authenticate().map(|c| (c, true));
        for (challenge, is_proxy) in www.chain(proxy) {
            let Ok(challenge) = challenge else {
                continue;
            };
            if let Some(challenge) = BearerChallenge::read(&challenge, is_proxy) {
                self.refuse_realm(challenge.proxy, &challenge.realm);
                continue;
            }
            let Some(challenge) = Challenge::read(&challenge, is_proxy) else {
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

    /// Like [`Self::refuse`], for one protection domain named outright.
    ///
    /// For a challenge the caller chose not to answer, e.g. from a party the
    /// password is not for. Learning already stored it, and
    /// [`Self::authorize`] would otherwise answer that party unasked on the
    /// next request. A later challenge with a new nonce reopens it.
    pub fn refuse_realm(&mut self, proxy: bool, realm: &str) {
        for entry in &mut self.entries {
            if entry.challenge.proxy == proxy && *entry.challenge.realm == *realm {
                entry.refused = true;
            }
        }
        for entry in &mut self.bearer {
            if entry.challenge.proxy == proxy && *entry.challenge.realm == *realm {
                entry.refused = true;
            }
        }
    }

    /// Keep a `Bearer` challenge. `carried` is the fingerprint of the token
    /// the refused request carried there, if any: that token was turned down.
    fn take_bearer(
        &mut self,
        challenge: BearerChallenge,
        call_id: &Arc<[u8]>,
        carried: Option<[u8; 32]>,
    ) -> Learned {
        let existing = self.bearer.iter_mut().find(|entry| {
            entry.challenge.proxy == challenge.proxy && entry.challenge.realm == challenge.realm
        });
        match existing {
            Some(entry) => {
                entry.challenge = challenge;
                entry.refused = false;
                entry.call_id = Arc::clone(call_id);
                if carried.is_some() {
                    entry.rejected = carried;
                }
            }
            None => self.bearer.push(BearerEntry {
                challenge,
                rejected: carried,
                refused: false,
                call_id: Arc::clone(call_id),
            }),
        }
        Learned::Retry
    }

    /// `answered`: whether the refused request answered this very challenge
    /// (same realm and nonce).
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

        // "though the request may be retried if the nonce was stale". The
        // same nonce without `stale`, on a request that answered it, means
        // the password was wrong.
        if entry.challenge.nonce == challenge.nonce && !challenge.stale {
            if answered || entry.refused {
                entry.refused = true;
                return Learned::Refused;
            }
            // A request that carried no credentials had nothing rejected
            // (§22.1). Servers that derive the nonce from the clock reuse it
            // within a second, so a SUBSCRIBE after a REGISTER gets the nonce
            // the REGISTER answered. It is still good: answer it again and
            // keep the count, since `nc` numbers every request sent with one
            // nonce (RFC 7616 §3.4). The request's own allowance caps retries.
            entry.call_id = Arc::clone(call_id);
            return Learned::Retry;
        }
        // a new nonce starts its own count; the same one marked stale does
        // not: resending 00000001 with the same nonce and cnonce would look
        // like a replay
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

/// The realm and nonce of every credential set `request` carried, and which
/// space each answered. Unparseable values count as nothing carried.
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

/// The fingerprint of the token `request` carried in a `Bearer` field of the
/// space a 401 (`Authorization`) or a 407 (`Proxy-Authorization`) answers.
fn carried_token(request: &RawMessage<'_>, proxy: bool) -> Option<[u8; 32]> {
    let field = if proxy {
        HeaderName::ProxyAuthorization
    } else {
        HeaderName::Authorization
    };
    request
        .header_values(field)
        .find_map(bearer::carried_token)
        .map(bearer::fingerprint)
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
        // a registrar's realm and a proxy's, different passwords, one wrong:
        // only the exhausted one closes
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
        // a clock-derived nonce repeats within a second: the SUBSCRIBE after
        // a REGISTER is refused with the nonce the REGISTER answered. It
        // carried no credentials, so the nonce is answered again and the
        // count continues.
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
        // RFC 7616 §3.4: nc counts the requests "sent with the nonce value".
        // Two went with n1 already, so this is the third, stale or not; a
        // second nc=00000001 would be read as a replay
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
