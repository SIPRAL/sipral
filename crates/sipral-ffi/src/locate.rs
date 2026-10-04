// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! An account whose registrar or outbound proxy is a name, located by RFC
//! 3263 with the application's resolver (ABI 0.34).
//!
//! `sipral_account_config_t::server_uri` names the server in place of
//! `registrar_address`. The procedure — NAPTR when asked for, the SRV name
//! for the account's transport, then A or AAAA, the SRV ranking and the
//! fallback to the host's own addresses — is the stack's; the lookups are the
//! application's, one at a time, the same division
//! `SIPRAL_EVENT_KIND_RESOLVE_NEEDED` makes for a dialog. Each
//! [`SipralEventKind::LookupWanted`](crate::event::SipralEventKind::LookupWanted)
//! names a query, and [`sipral_account_looked_up`] hands its answer back —
//! every one, a failure included, since the procedure waits for each.
//! [`SipralEventKind::Located`](crate::event::SipralEventKind::Located) says
//! where the account's requests go now, and
//! [`SipralEventKind::LocateFailed`](crate::event::SipralEventKind::LocateFailed)
//! that a lookup named no address. `docs/04-ua.md` has what happens between
//! them: the first REGISTER waiting for the first answer, the move to the
//! next address on a timeout, a failed transport or a 503, and the name
//! looked up again when the answer's time-to-live runs out.

use std::ffi::c_char;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use sipral_ua::{Answer, LocateError, Naptr, Query, Record, RecordType, Srv};

use crate::abi::{Number, codes, record};
use crate::error::{Fail, entry, fail};
use crate::handle::SipralHandle;
use crate::stack::{handle_failed, with_stack_at};
use crate::status::SipralStatus;
use crate::text::{required_text, text};

/// The most records one answer carries across the boundary: well past what a
/// zone publishes for one name, and short of what a length nobody set says.
const MAX_RECORDS: usize = 64;

codes! {
    /// Which kind of DNS record a lookup asks for. Names for
    /// `sipral_locate_event_t::record` and `sipral_account_looked_up`'s
    /// `record`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralDnsRecordType: u32 {
        /// Not a lookup: the value on a `SIPRAL_EVENT_KIND_LOCATED` or a
        /// `SIPRAL_EVENT_KIND_LOCATE_FAILED`.
        None = 0,
        /// RFC 3403: which services a domain offers, and under which names.
        Naptr = 1,
        /// RFC 2782: which hosts, at which ports, serve one service.
        Srv = 2,
        /// An IPv4 address.
        A = 3,
        /// An IPv6 address.
        Aaaa = 4,
    }
}

codes! {
    /// What the application's resolver said to a lookup. Names for
    /// `sipral_account_looked_up`'s `answer`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralDnsAnswer: u32 {
        /// The records it returned, in `records`. None at all reads as
        /// `SIPRAL_DNS_ANSWER_NOTHING`.
        Records = 1,
        /// The name has no record of that kind, or does not exist at all.
        /// Also the right answer from a resolver that cannot ask for the
        /// kind: a platform lookup that only knows addresses answers every
        /// NAPTR and SRV query with this, and the host's own addresses are
        /// asked for next.
        Nothing = 2,
        /// The resolver could not answer: no server reachable, a timeout, a
        /// server failure.
        Failed = 3,
    }
}

codes! {
    /// Why a lookup of an account's server named no address. Names for
    /// `sipral_locate_event_t::failure`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralLocateFailure: u32 {
        /// Nothing failed.
        None = 0,
        /// The DNS answered, and what it answered names no address of the
        /// family the account's transport can reach: no record, or an SRV
        /// target of `.`.
        NotFound = 1,
        /// The resolver failed on every lookup that could have given an
        /// address.
        Unanswered = 2,
        /// The transport has no RFC 3263 procedure: WebSocket names no SRV
        /// service and no default port, so only a numeric host, or a host
        /// with a port, can be located for it.
        Unsupported = 3,
    }
}

record! {
    /// What a [`SipralEventKind::LookupWanted`](crate::event::SipralEventKind::LookupWanted),
    /// a [`SipralEventKind::Located`](crate::event::SipralEventKind::Located)
    /// and a [`SipralEventKind::LocateFailed`](crate::event::SipralEventKind::LocateFailed)
    /// carry, the account being `sipral_event_t::account`.
    ///
    /// One struct for the three, the way `sipral_subscription_event_t`
    /// answers for two kinds: a member meaningless on one kind is zero or
    /// null there. Every pointer is the library's, valid for the duration of
    /// the callback.
    #[derive(Clone, Copy)]
    pub struct SipralLocateEvent {
        /// A [`SipralDnsRecordType`]: what to ask `name` for, on a lookup.
        pub record: Number<SipralDnsRecordType>,
        /// A [`SipralLocateFailure`]: why a lookup named no address.
        pub failure: Number<SipralLocateFailure>,
        /// The name to ask, on a lookup: `_sip._udp.example.com`, or a
        /// host. Handed back to [`sipral_account_looked_up`] with the answer.
        /// UTF-8, not NUL-terminated.
        pub name: *const c_char,
        /// How many bytes of it.
        pub name_len: usize,
        /// Where the account's server was located: every address the answer
        /// named, as `host:port` separated by commas, in RFC 3263 section
        /// 4.3's order from the one the account's requests go to now. UTF-8,
        /// not NUL-terminated.
        pub targets: *const c_char,
        /// How many bytes of it.
        pub targets_len: usize,
        /// When the name is looked up again after a failure, in
        /// milliseconds. An address an earlier answer named stays in use
        /// meanwhile.
        pub retry_in_ms: u64,
    }
}

/// A caller's record type, as the lookup's.
fn record_type(value: u32, name: &'static str) -> Result<RecordType, Fail> {
    match value {
        1 => Ok(RecordType::Naptr),
        2 => Ok(RecordType::Srv),
        3 => Ok(RecordType::A),
        4 => Ok(RecordType::Aaaa),
        other => Err(fail(
            SipralStatus::InvalidArgument,
            format!(
                "{name} is {other}, and a record type is 1 for NAPTR, 2 for SRV, 3 for A or 4 for AAAA"
            ),
        )),
    }
}

/// A record type as this ABI names it.
pub(crate) const fn named_record(record: RecordType) -> SipralDnsRecordType {
    match record {
        RecordType::Naptr => SipralDnsRecordType::Naptr,
        RecordType::Srv => SipralDnsRecordType::Srv,
        RecordType::A => SipralDnsRecordType::A,
        RecordType::Aaaa => SipralDnsRecordType::Aaaa,
    }
}

/// A reason a lookup failed, as this ABI names it.
pub(crate) const fn named_failure(reason: LocateError) -> SipralLocateFailure {
    match reason {
        LocateError::NotFound => SipralLocateFailure::NotFound,
        LocateError::Unanswered => SipralLocateFailure::Unanswered,
        LocateError::Unsupported => SipralLocateFailure::Unsupported,
        // `LocateError` is `#[non_exhaustive]`: a reason this ABI has no word
        // for yet still failed, and says nothing more
        _ => SipralLocateFailure::None,
    }
}

/// One field of a record, as the number it is, refused rather than cut
/// when it is not one.
fn field<T: core::str::FromStr>(
    fields: &[&str],
    at: usize,
    what: &str,
    index: usize,
) -> Result<T, Fail> {
    fields
        .get(at)
        .and_then(|field| field.parse::<T>().ok())
        .ok_or_else(|| {
            fail(
                SipralStatus::InvalidArgument,
                format!(
                    "record {index} of the answer has no {what} a DNS record could carry at \
                     field {at}"
                ),
            )
        })
}

/// One record the caller wrote, as the lookup takes it: the fields
/// space-separated, the time-to-live in seconds first and then the record's
/// data in its presentation form (RFC 1035 section 5.1, RFC 2782, RFC 3403).
fn record_of(written: &str, record: RecordType, index: usize) -> Result<Record, Fail> {
    let fields: Vec<&str> = written.split_ascii_whitespace().collect();
    let expected = match record {
        RecordType::A | RecordType::Aaaa => 2,
        RecordType::Srv => 5,
        RecordType::Naptr => 6,
    };
    if fields.len() != expected {
        return Err(fail(
            SipralStatus::InvalidArgument,
            format!(
                "record {index} of the answer is {written:?}: {expected} fields, the \
                 time-to-live first, make one of the kind asked for"
            ),
        ));
    }
    let ttl = Duration::from_secs(field::<u64>(&fields, 0, "time-to-live", index)?);
    let text = |at: usize| fields.get(at).copied().unwrap_or("");
    match record {
        RecordType::Naptr => Ok(Record::Naptr(Naptr {
            order: field(&fields, 1, "order", index)?,
            preference: field(&fields, 2, "preference", index)?,
            flags: text(3).trim_matches('"').into(),
            service: text(4).trim_matches('"').into(),
            replacement: text(5).into(),
            ttl,
        })),
        RecordType::Srv => Ok(Record::Srv(Srv {
            priority: field(&fields, 1, "priority", index)?,
            weight: field(&fields, 2, "weight", index)?,
            port: field(&fields, 3, "port", index)?,
            target: text(4).into(),
            ttl,
        })),
        family @ (RecordType::A | RecordType::Aaaa) => {
            let address = field::<IpAddr>(&fields, 1, "address", index)?;
            if address.is_ipv4() != (family == RecordType::A) {
                return Err(fail(
                    SipralStatus::InvalidArgument,
                    format!(
                        "record {index} of the answer names {address}, and an {} lookup \
                         answers with an {} address",
                        if family == RecordType::A { "A" } else { "AAAA" },
                        if family == RecordType::A {
                            "IPv4"
                        } else {
                            "IPv6"
                        }
                    ),
                ));
            }
            Ok(Record::Address { address, ttl })
        }
    }
}

/// What the caller's resolver said, as the lookup takes it.
fn answer_of(answer: u32, record: RecordType, records: Option<&str>) -> Result<Answer, Fail> {
    match (answer, records) {
        (1, None) => Ok(Answer::Records(Vec::new())),
        (1, Some(written)) => {
            let written: Vec<&str> = written.split(',').collect();
            if written.len() > MAX_RECORDS {
                return Err(fail(
                    SipralStatus::InvalidArgument,
                    format!(
                        "the answer has {} records, and one carries at most {MAX_RECORDS}",
                        written.len()
                    ),
                ));
            }
            written
                .iter()
                .enumerate()
                .map(|(index, one)| record_of(one, record, index))
                .collect::<Result<Vec<_>, _>>()
                .map(Answer::Records)
        }
        (2 | 3, Some(_)) => Err(fail(
            SipralStatus::InvalidArgument,
            format!("answer is {answer}, which carries no records, and records were given"),
        )),
        (2, None) => Ok(Answer::Nothing),
        (3, None) => Ok(Answer::Failed),
        (other, _) => Err(fail(
            SipralStatus::InvalidArgument,
            format!(
                "answer is {other}, and an answer is 1 for records, 2 for nothing or 3 for a \
                 resolver that failed"
            ),
        )),
    }
}

entry! {
    /// Hand the resolver's answer to a
    /// [`SIPRAL_EVENT_KIND_LOOKUP_WANTED`](crate::event::SipralEventKind::LookupWanted)
    /// back to the account that asked.
    ///
    /// `name` and `record` are the event's, as it named them; `answer` is a
    /// [`SipralDnsAnswer`]. With `SIPRAL_DNS_ANSWER_RECORDS`, `records` is
    /// what the resolver returned, every record of the kind asked for,
    /// separated by commas, each its fields separated by spaces: the
    /// time-to-live in seconds, then the data as a zone file writes it —
    /// an address for A and AAAA (`300 192.0.2.40`); priority, weight,
    /// port and target for SRV (`300 10 60 5060 sip1.example.com`); order,
    /// preference, flags, service and replacement for NAPTR, the regular
    /// expression left out since RFC 3263 follows none (`300 10 50 S
    /// SIP+D2U _sip._udp.example.com`). Null or empty for none, which
    /// reads as `SIPRAL_DNS_ANSWER_NOTHING`. Text, rather than an array of
    /// structs, because it is what a platform resolver prints and what
    /// every binding hands over as it is.
    ///
    /// Answer every lookup, a resolver that failed included: the procedure
    /// waits for each. An answer to a lookup nothing is waiting for any
    /// more — the account was located since, or it has been asked for
    /// again — is `SIPRAL_STATUS_OK` and changes nothing, as is one for an
    /// account that locates nothing.
    ///
    /// # Safety
    ///
    /// `name` must be readable for `name_len` bytes and `records` for
    /// `records_len`.
    fn sipral_account_looked_up(
        stack: SipralHandle,
        account: SipralHandle,
        name: *const c_char,
        name_len: usize,
        record: Number<SipralDnsRecordType>,
        answer: Number<SipralDnsAnswer>,
        records: *const c_char,
        records_len: usize,
        now_ms: u64,
    ) {
        let name = unsafe { required_text(name, name_len, "name") }?;
        let record = record_type(record, "record")?;
        let records = unsafe { text(records, records_len, "records") }?;
        let answer = answer_of(answer, record, records)?;
        let query = Query {
            name: Arc::from(name),
            record,
        };
        with_stack_at(stack, now_ms, |state, now| {
            let id = state.accounts.get(account).map_err(handle_failed)?;
            state
                .agent
                .looked_up(id, &query, answer, now)
                .map_err(|error| crate::call::ua_failed(&error))
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::{
        SipralDnsAnswer, SipralDnsRecordType, SipralLocateFailure, sipral_account_looked_up,
    };
    use crate::account::sipral_account_add;
    use crate::account::tests::account_config;
    use crate::call::tests::{one, start_line};
    use crate::error::last_error_text;
    use crate::event::{SipralEvent, SipralEventKind};
    use crate::handle::{SIPRAL_HANDLE_NONE, SipralHandle};
    use crate::stack::tests::{Observed, poll, stack};
    use crate::status::SipralStatus;
    use std::ffi::c_char;
    use std::ptr;

    /// What a locate event carried, copied out while the callback ran.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub(crate) struct Locating {
        pub(crate) kind: SipralEventKind,
        pub(crate) account: SipralHandle,
        pub(crate) record: u32,
        pub(crate) failure: u32,
        pub(crate) name: String,
        pub(crate) targets: String,
        pub(crate) retry_in_ms: u64,
    }

    fn owned(pointer: *const c_char, len: usize) -> String {
        if pointer.is_null() {
            return String::new();
        }
        let bytes = unsafe { std::slice::from_raw_parts(pointer.cast::<u8>(), len) };
        String::from_utf8(bytes.to_vec()).expect("UTF-8")
    }

    /// # Safety
    ///
    /// `event` must be one of the three locate kinds, as the callback hands
    /// it over.
    pub(crate) unsafe fn locating(event: &SipralEvent) -> Locating {
        let payload = unsafe { event.payload.locate };
        Locating {
            kind: event.kind,
            account: event.account,
            record: payload.record,
            failure: payload.failure,
            name: owned(payload.name, payload.name_len),
            targets: owned(payload.targets, payload.targets_len),
            retry_in_ms: payload.retry_in_ms,
        }
    }

    fn answer(
        handle: SipralHandle,
        account: SipralHandle,
        asked: &Locating,
        answer: SipralDnsAnswer,
        records: &str,
    ) -> SipralStatus {
        unsafe {
            sipral_account_looked_up(
                handle,
                account,
                asked.name.as_ptr().cast(),
                asked.name.len(),
                asked.record,
                answer as u32,
                if records.is_empty() {
                    ptr::null()
                } else {
                    records.as_ptr().cast()
                },
                records.len(),
                0,
            )
        }
    }

    /// An account that registers with `sip:pbx.example.com`, located by
    /// name rather than given an address.
    fn located_account(handle: SipralHandle, server: &'static str) -> SipralHandle {
        let mut config = account_config();
        config.registrar_address = ptr::null();
        config.registrar_address_len = 0;
        config.server_uri = server.as_ptr().cast();
        config.server_uri_len = server.len();
        let mut account = SIPRAL_HANDLE_NONE;
        let status = unsafe { sipral_account_add(handle, &raw const config, &raw mut account) };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        account
    }

    #[test]
    fn a_registrar_named_by_srv_is_asked_for_located_and_registered_with() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let account = located_account(handle, "sip:example.com");
        assert_eq!(
            unsafe { crate::account::sipral_account_register(handle, account, 0) },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        poll(handle, 0);
        let asked = observed.locating.clone();
        assert_eq!(asked.len(), 1, "{asked:?}");
        assert_eq!(asked[0].kind, SipralEventKind::LookupWanted);
        assert_eq!(asked[0].account, account);
        assert_eq!(asked[0].record, SipralDnsRecordType::Srv as u32);
        assert_eq!(asked[0].name, "_sip._udp.example.com");

        let targets = "300 0 0 5080 sip1.example.com, 300 1 0 5080 sip2.example.com";
        assert_eq!(
            answer(
                handle,
                account,
                &asked[0],
                SipralDnsAnswer::Records,
                targets
            ),
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        poll(handle, 0);
        let asked = observed.locating.clone();
        let hosts: Vec<_> = asked[1..].iter().map(|one| one.name.clone()).collect();
        assert_eq!(hosts, ["sip1.example.com", "sip2.example.com"]);
        assert!(
            asked[1..]
                .iter()
                .all(|one| one.record == SipralDnsRecordType::A as u32)
        );
        assert_eq!(
            answer(
                handle,
                account,
                &asked[1],
                SipralDnsAnswer::Records,
                "300 192.0.2.40"
            ),
            SipralStatus::Ok
        );
        assert_eq!(
            answer(
                handle,
                account,
                &asked[2],
                SipralDnsAnswer::Records,
                "300 198.51.100.41"
            ),
            SipralStatus::Ok
        );
        poll(handle, 0);
        let located = observed
            .locating
            .clone()
            .into_iter()
            .find(|one| one.kind == SipralEventKind::Located)
            .expect("located");
        assert_eq!(located.account, account);
        assert_eq!(located.targets, "192.0.2.40:5080,198.51.100.41:5080");
        assert_eq!(located.record, SipralDnsRecordType::None as u32);

        let register = one(handle);
        assert!(
            start_line(&register).starts_with("REGISTER sip:example.com "),
            "{}",
            start_line(&register)
        );
    }

    /// Until the first answer there is nowhere to send a call that names no
    /// destination of its own: a moment wrong, not a value.
    #[test]
    fn a_call_before_the_first_answer_is_the_wrong_moment() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let account = located_account(handle, "sip:example.com");
        let (status, _) =
            crate::call::tests::place(handle, account, &crate::call::tests::call_config(), 0);
        assert_eq!(status, SipralStatus::WrongState);
        assert!(
            last_error_text().contains("located"),
            "{}",
            last_error_text()
        );
    }

    #[test]
    fn a_name_that_resolves_to_nothing_is_said_to_have_failed() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let account = located_account(handle, "sip:nowhere.example.com");
        assert_eq!(
            unsafe { crate::account::sipral_account_register(handle, account, 0) },
            SipralStatus::Ok
        );
        poll(handle, 0);
        let srv = observed.locating.clone().remove(0);
        assert_eq!(
            answer(handle, account, &srv, SipralDnsAnswer::Nothing, ""),
            SipralStatus::Ok
        );
        poll(handle, 0);
        let host = observed.locating.clone().remove(1);
        assert_eq!(host.name, "nowhere.example.com");
        assert_eq!(
            answer(handle, account, &host, SipralDnsAnswer::Failed, ""),
            SipralStatus::Ok
        );
        poll(handle, 0);
        let failed = observed
            .locating
            .clone()
            .into_iter()
            .find(|one| one.kind == SipralEventKind::LocateFailed)
            .expect("failed");
        assert_eq!(failed.failure, SipralLocateFailure::Unanswered as u32);
        assert!(failed.retry_in_ms > 0);
    }

    #[test]
    fn an_answer_that_does_not_read_is_refused_and_says_where() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let account = located_account(handle, "sip:example.com");
        assert_eq!(
            unsafe { crate::account::sipral_account_register(handle, account, 0) },
            SipralStatus::Ok
        );
        poll(handle, 0);
        let asked = observed.locating.clone().remove(0);
        for (written, said) in [
            ("300 0 0 70000 sip1.example.com", "port"),
            ("300 0 0 5060", "fields"),
            ("soon 0 0 5060 sip1.example.com", "time-to-live"),
            ("300 0 0 5060 sip1.example.com,", "fields"),
        ] {
            assert_eq!(
                answer(handle, account, &asked, SipralDnsAnswer::Records, written),
                SipralStatus::InvalidArgument,
                "{written}"
            );
            assert!(
                last_error_text().contains(said),
                "{written}: {}",
                last_error_text()
            );
        }
        assert_eq!(
            answer(
                handle,
                account,
                &asked,
                SipralDnsAnswer::Nothing,
                "300 0 0 5060 x"
            ),
            SipralStatus::InvalidArgument,
            "nothing carries no records"
        );
        let status = unsafe {
            sipral_account_looked_up(handle, account, ptr::null(), 0, 2, 2, ptr::null(), 0, 0)
        };
        assert_eq!(status, SipralStatus::InvalidArgument, "a lookup has a name");
        let status = unsafe {
            sipral_account_looked_up(
                handle,
                account,
                asked.name.as_ptr().cast(),
                asked.name.len(),
                9,
                2,
                ptr::null(),
                0,
                0,
            )
        };
        assert_eq!(status, SipralStatus::InvalidArgument, "no record type 9");
        let a = Locating {
            record: SipralDnsRecordType::A as u32,
            ..asked
        };
        assert_eq!(
            answer(
                handle,
                account,
                &a,
                SipralDnsAnswer::Records,
                "300 2001:db8::1"
            ),
            SipralStatus::InvalidArgument,
            "an A lookup answers IPv4"
        );
    }

    /// A NAPTR answer, quoted the way a zone file quotes it, picks the SRV
    /// name the account's transport is served under.
    #[test]
    fn a_naptr_answer_leads_to_the_srv_name_it_names() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let mut config = account_config();
        let server = "sip:example.com";
        config.registrar_address = ptr::null();
        config.registrar_address_len = 0;
        config.server_uri = server.as_ptr().cast();
        config.server_uri_len = server.len();
        config.server_naptr = crate::media::SipralToggle::On as u32;
        let mut account = SIPRAL_HANDLE_NONE;
        let status = unsafe { sipral_account_add(handle, &raw const config, &raw mut account) };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        assert_eq!(
            unsafe { crate::account::sipral_account_register(handle, account, 0) },
            SipralStatus::Ok
        );
        poll(handle, 0);
        let naptr = observed.locating.clone().remove(0);
        assert_eq!(naptr.record, SipralDnsRecordType::Naptr as u32);
        assert_eq!(naptr.name, "example.com");
        let records = "3600 10 50 \"s\" \"SIPS+D2T\" _sips._tcp.example.com,\
                       3600 20 50 \"s\" \"SIP+D2U\" _sip._udp.proxy.example.com";
        assert_eq!(
            answer(handle, account, &naptr, SipralDnsAnswer::Records, records),
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        poll(handle, 0);
        let srv = observed.locating.clone().remove(1);
        assert_eq!(srv.record, SipralDnsRecordType::Srv as u32);
        assert_eq!(
            srv.name, "_sip._udp.proxy.example.com",
            "the one serving UDP"
        );
    }

    #[test]
    fn an_account_needs_an_address_or_a_server_to_locate_and_not_both() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let mut config = account_config();
        let server = "sip:example.com";
        config.server_uri = server.as_ptr().cast();
        config.server_uri_len = server.len();
        let mut account = SIPRAL_HANDLE_NONE;
        let status = unsafe { sipral_account_add(handle, &raw const config, &raw mut account) };
        assert_eq!(status, SipralStatus::InvalidArgument);
        assert!(
            last_error_text().contains("server_uri"),
            "{}",
            last_error_text()
        );

        config.registrar_address = ptr::null();
        config.registrar_address_len = 0;
        config.server_naptr = 3;
        let status = unsafe { sipral_account_add(handle, &raw const config, &raw mut account) };
        assert_eq!(
            status,
            SipralStatus::InvalidArgument,
            "a toggle is 0, 1 or 2"
        );

        config.server_uri = ptr::null();
        config.server_uri_len = 0;
        config.server_naptr = crate::media::SipralToggle::On as u32;
        let status = unsafe { sipral_account_add(handle, &raw const config, &raw mut account) };
        assert_eq!(
            status,
            SipralStatus::InvalidArgument,
            "NAPTR with nothing to locate"
        );
    }

    #[test]
    fn a_numeric_server_is_registered_with_and_nothing_is_asked() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let account = located_account(handle, "sip:192.0.2.9");
        assert_eq!(
            unsafe { crate::account::sipral_account_register(handle, account, 0) },
            SipralStatus::Ok
        );
        poll(handle, 0);
        assert!(
            observed
                .locating
                .iter()
                .all(|one| one.kind != SipralEventKind::LookupWanted)
        );
        assert!(start_line(&one(handle)).starts_with("REGISTER "));
    }
}
