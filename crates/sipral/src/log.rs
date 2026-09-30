// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! The engine's log: lines with a level, handed to a sink the application
//! installs, off until it does.
//!
//! A diagnostic record (`docs/14-diagnostics.md`) says what the stack decided
//! about one call; this says what the whole engine is doing, as it does it,
//! for the application's own log file. Four properties hold it up, and each
//! is tested:
//!
//! - **Off by default, cheap when off.** A [`Log`] has no sink and no level
//!   until [`Log::enable`]; asking whether a level is on is one atomic load,
//!   and nothing is formatted for a level that is off.
//! - **A flood cannot stall the stack.** Lines are admitted through a token
//!   bucket — [`BURST`] at once, [`PER_SECOND`] a second after that, on the
//!   caller's own clock — and held in a queue of at most [`QUEUE_CEILING`]
//!   lines. What the bucket or the queue turns away is counted, never waited
//!   for, and the next line delivered says how many went before it
//!   ([`LogRecord::suppressed`]). A sink that is slow slows the thread that
//!   flushes, by at most one bucket's worth of calls, and nothing else.
//! - **The sink is never called with a lock held that it could re-enter.**
//!   Producing a line only queues it; [`Log::flush`] takes the queue out
//!   under the log's own lock, lets that lock go, and only then calls the
//!   sink, one line at a time. The engine never flushes — it is driven from
//!   inside its owner's locks, `sipral-ffi`'s stack lock among them — so the
//!   owner flushes once it holds nothing: the C ABI after every entry point
//!   has let the stack go. One flush delivers at a time, so lines arrive in
//!   order and on one thread; a flush that finds another delivering leaves
//!   its lines to it.
//! - **No line carries a secret.** Every line is run through the redaction
//!   `docs/14-diagnostics.md` describes before it is queued:
//!   [`sipral_diag::redact_text`] over prose, which pseudonymises a URI's
//!   user part and every IP literal and drops credentials outright, and
//!   [`sipral_diag::redact_message`] over a whole SIP message at
//!   [`LogLevel::Trace`], which also drops `Authorization` and SDES keys. The
//!   pseudonyms are keyed with a secret the application hands to
//!   [`Log::new`], so they correlate within one log and reveal nothing
//!   outside it — or, made with [`Log::from_salt`], keyed with a salt the
//!   application keeps for the installation, so the same address gets the
//!   same pseudonym in every run and two runs' logs can be laid side by
//!   side.
//! - **A diagnostic trace, only when asked for.** [`Log::set_diagnostic`]
//!   turns on the one mode that writes SIP messages whole — users, names
//!   and addresses as they were sent — for an operator comparing two runs.
//!   Even then [`sipral_diag::strip_secrets`] takes every `Authorization`
//!   and `Proxy-Authorization` value and every SDP key (`a=crypto`, `k=`,
//!   `a=key-mgmt`) out of each message first, bytes the parser refuses
//!   included, and prose lines lose their credentials the same way. It is
//!   off by default and is never turned on by anything but that call.

use std::collections::VecDeque;
use std::fmt;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Instant;

use sipral_diag::{Mode, Redactor, redact_message, redact_text, strip_secrets, strip_secrets_text};

/// How many lines the bucket lets through at once, before the rate below
/// applies.
pub const BURST: u32 = 200;

/// How many lines a second the bucket earns back.
pub const PER_SECOND: u32 = 100;

/// How many admitted lines wait for [`Log::flush`] at most. One past it is
/// counted as suppressed rather than queued.
pub const QUEUE_CEILING: usize = 1024;

/// How many values one redactor remembers before it is replaced by a fresh
/// one. Its pseudonyms are a keyed hash, so a fresh redactor under the same
/// key writes the same ones; the replacement only bounds the memory a
/// long-running log keeps.
const REDACTOR_REUSE: u32 = 4096;

/// The shortest salt [`Log::from_salt`] takes: 128 bits, so that a pseudonym
/// cannot be reversed by trying every salt as well as every address.
pub const MIN_SALT: usize = 16;

/// A salt shorter than [`MIN_SALT`] bytes, refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SaltTooShort {
    /// How many bytes it had.
    pub len: usize,
}

impl fmt::Display for SaltTooShort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "a pseudonym salt of {} bytes is under the {MIN_SALT} a salt needs",
            self.len
        )
    }
}

impl std::error::Error for SaltTooShort {}

/// The pseudonym key an installation's salt stands for: the key
/// [`Log::from_salt`] keys its pseudonyms with, and the one a state snapshot
/// ([`crate::EngineState`]) is redacted under to agree with it.
///
/// The salt is the application's to draw once, from the platform's
/// generator, and to keep with the installation's other settings: the same
/// salt gives the same key, so the same address or user gets the same
/// pseudonym in every run, and two runs' traces compare line by line. It is
/// a secret like any key — whoever holds it can test a guessed address
/// against a pseudonym — and it must not be a seed that is written anywhere
/// in clear.
///
/// # Errors
/// [`SaltTooShort`] for a salt under [`MIN_SALT`] bytes.
pub fn pseudonym_key(salt: &[u8]) -> Result<Vec<u8>, SaltTooShort> {
    if salt.len() < MIN_SALT {
        return Err(SaltTooShort { len: salt.len() });
    }
    let mut key = salt.to_vec();
    key.extend_from_slice(b"sipral log and state pseudonyms");
    Ok(key)
}

/// How loud a line is. Higher is more detailed: a sink set to
/// [`LogLevel::Info`] receives errors, warnings and information.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LogLevel {
    /// Something failed and the application is likely to see the effect.
    Error = 1,
    /// Something went wrong that the stack worked around, or that is about
    /// to matter: a registration refused, audio that stopped arriving.
    Warn = 2,
    /// What an operator wants in a log file: a registration granted, a call
    /// arriving, confirmed or ending, media starting.
    Info = 3,
    /// Every event the engine hands out, and every decision the diagnostic
    /// record writes down.
    Debug = 4,
    /// Every SIP message, in full and redacted.
    Trace = 5,
}

impl LogLevel {
    /// The level a number names — the C ABI's `SipralLogLevel` — or `None`.
    #[must_use]
    pub const fn from_number(number: u32) -> Option<Self> {
        match number {
            1 => Some(Self::Error),
            2 => Some(Self::Warn),
            3 => Some(Self::Info),
            4 => Some(Self::Debug),
            5 => Some(Self::Trace),
            _ => None,
        }
    }

    /// The lower-case name, for a sink that writes text.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Info => "info",
            Self::Debug => "debug",
            Self::Trace => "trace",
        }
    }
}

impl fmt::Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One line, as the sink receives it. Borrowed for the call and no longer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LogRecord<'a> {
    /// How loud it is.
    pub level: LogLevel,
    /// Which part of the engine wrote it: `registration`, `call`, `media`,
    /// `decision`, `sip`, `api`, and so on. A short fixed word, never data.
    pub target: &'a str,
    /// The line, already redacted.
    pub message: &'a str,
    /// How many lines were turned away — by the rate limit or a full queue —
    /// since the line before this one was delivered. Zero almost always.
    pub suppressed: u64,
}

/// Where lines go: called on the thread that flushes, with nothing held.
pub type LogSink = Arc<dyn Fn(&LogRecord<'_>) + Send + Sync>;

/// Which way a SIP message went, for [`Log::sip_message`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Travel {
    /// It arrived.
    Received,
    /// This end wrote it.
    Sent,
}

/// The engine's log. Cheap to clone: every clone is the same log.
///
/// Created off, and handed to whatever produces lines —
/// [`crate::MediaEngine::set_log`] for the engine's own — and to whatever
/// drives the engine, which calls [`Log::flush`] once it holds no lock the
/// sink could need.
#[derive(Clone)]
pub struct Log(Arc<Shared>);

struct Shared {
    /// The most detailed level delivered, or zero for off. Read without the
    /// lock, so a producer asks for nothing and formats nothing when off.
    level: AtomicU8,
    inner: Mutex<Inner>,
}

struct Inner {
    sink: Option<LogSink>,
    queue: VecDeque<Line>,
    delivering: bool,
    bucket: Bucket,
    /// Turned away since the last line was admitted.
    pending_suppressed: u64,
    /// Turned away over the log's whole life.
    suppressed_ever: u64,
    key: Vec<u8>,
    redactor: Redactor,
    redactor_uses: u32,
    /// Whether SIP messages are written whole, secrets aside
    /// ([`Log::set_diagnostic`]).
    diagnostic: bool,
}

struct Line {
    level: LogLevel,
    target: &'static str,
    message: String,
    suppressed: u64,
}

/// A token bucket on the caller's clock.
struct Bucket {
    tokens: f64,
    at: Option<Instant>,
}

impl Bucket {
    const fn full() -> Self {
        Self {
            tokens: BURST as f64,
            at: None,
        }
    }

    /// Whether a line may pass at `now`, taking its token if so. A clock
    /// that went backwards earns nothing and costs nothing.
    fn admit(&mut self, now: Instant) -> bool {
        if let Some(then) = self.at {
            let earned = now.saturating_duration_since(then).as_secs_f64() * f64::from(PER_SECOND);
            self.tokens = (self.tokens + earned).min(f64::from(BURST));
        }
        self.at = Some(self.at.map_or(now, |then| then.max(now)));
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

impl fmt::Debug for Log {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // the pseudonym key is in here, and a derived Debug would print it
        f.debug_struct("Log")
            .field("level", &self.level())
            .finish_non_exhaustive()
    }
}

impl Log {
    /// A log that is off, pseudonymising under `key`.
    ///
    /// `key` is a secret: draw it once from the platform's generator, and do
    /// not reuse a seed that is written anywhere in clear — the signalling
    /// seed goes into every replay recording, and an IP pseudonym keyed with
    /// it could be reversed by trying every address. The same key gives the
    /// same pseudonym for the same value for the life of the log, so one
    /// call's lines can be followed through the file.
    #[must_use]
    pub fn new(key: &[u8]) -> Self {
        Self(Arc::new(Shared {
            level: AtomicU8::new(0),
            inner: Mutex::new(Inner {
                sink: None,
                queue: VecDeque::new(),
                delivering: false,
                bucket: Bucket::full(),
                pending_suppressed: 0,
                suppressed_ever: 0,
                key: key.to_vec(),
                redactor: Redactor::new(Mode::Hash(key.to_vec())),
                redactor_uses: 0,
                diagnostic: false,
            }),
        }))
    }

    /// A log that is off, pseudonymising under the key `salt` stands for
    /// ([`pseudonym_key`]): the same pseudonyms in every run of an
    /// installation that keeps its salt.
    ///
    /// # Errors
    /// [`SaltTooShort`] for a salt under [`MIN_SALT`] bytes.
    pub fn from_salt(salt: &[u8]) -> Result<Self, SaltTooShort> {
        Ok(Self::new(&pseudonym_key(salt)?))
    }

    /// Write SIP messages whole — or go back to redacting them.
    ///
    /// Off by default, and meant to stay off outside a diagnosis: with it
    /// on, a trace line at [`LogLevel::Trace`] carries every user, display
    /// name, number and address exactly as it went on the wire, and the peer
    /// it went to, so that two runs can be compared where pseudonyms would
    /// hide the difference. What never appears, in either mode, is a
    /// credential or a key: [`sipral_diag::strip_secrets`] takes every
    /// `Authorization` and `Proxy-Authorization` value, every `a=crypto`
    /// `inline:` key, every `k=` key and every `a=key-mgmt` payload out of
    /// each message first — a message the parser refuses included, which is
    /// then written stripped rather than withheld — and prose lines lose
    /// their credentials with [`sipral_diag::strip_secrets_text`], without
    /// pseudonyms either.
    pub fn set_diagnostic(&self, on: bool) {
        self.inner().diagnostic = on;
    }

    /// Whether [`Log::set_diagnostic`] turned the diagnostic trace on.
    #[must_use]
    pub fn diagnostic(&self) -> bool {
        self.inner().diagnostic
    }

    /// Deliver every line at `level` and louder to `sink`, replacing any sink
    /// already installed. Lines already queued go to the new sink.
    pub fn enable(&self, level: LogLevel, sink: LogSink) {
        let mut inner = self.inner();
        inner.sink = Some(sink);
        self.0.level.store(level as u8, Ordering::Release);
    }

    /// Change how much is delivered, keeping the sink. Nothing happens on a
    /// log with no sink: there is nowhere for the lines to go.
    pub fn set_level(&self, level: LogLevel) {
        let inner = self.inner();
        if inner.sink.is_some() {
            self.0.level.store(level as u8, Ordering::Release);
        }
    }

    /// Turn the log off: nothing more is produced, the sink is let go, and
    /// what was queued is dropped undelivered.
    pub fn disable(&self) {
        let mut inner = self.inner();
        self.0.level.store(0, Ordering::Release);
        inner.sink = None;
        inner.queue.clear();
        inner.pending_suppressed = 0;
    }

    /// The most detailed level delivered, or `None` when off.
    #[must_use]
    pub fn level(&self) -> Option<LogLevel> {
        LogLevel::from_number(u32::from(self.0.level.load(Ordering::Acquire)))
    }

    /// Whether a line at `level` would be delivered.
    #[must_use]
    pub fn enabled(&self, level: LogLevel) -> bool {
        level as u8 <= self.0.level.load(Ordering::Acquire)
    }

    /// How many lines the rate limit and the queue ceiling have turned away
    /// over this log's life.
    #[must_use]
    pub fn suppressed(&self) -> u64 {
        self.inner().suppressed_ever
    }

    /// A line of prose, redacted with [`sipral_diag::redact_text`] before it
    /// is queued. `message` is only called when `level` is on and the rate
    /// limit lets the line through, so a line that is not delivered costs
    /// neither the formatting nor the redaction.
    pub fn line(
        &self,
        level: LogLevel,
        target: &'static str,
        now: Instant,
        message: impl FnOnce() -> String,
    ) {
        self.admit(level, target, now, |redactor, diagnostic| {
            if diagnostic {
                strip_secrets_text(&message())
            } else {
                redact_text(&message(), redactor)
            }
        });
    }

    /// A whole SIP message at [`LogLevel::Trace`], redacted with
    /// [`sipral_diag::redact_message`]: credentials and SDES keys dropped,
    /// every user part, display name and IP literal pseudonymised. Bytes the
    /// parser cannot read are not written at all — only their size — since
    /// nothing could promise every identifier in them was found.
    ///
    /// With the diagnostic trace on ([`Log::set_diagnostic`]), the message
    /// and the peer are written as they are, with only the secrets taken out.
    pub fn sip_message(&self, travel: Travel, peer: SocketAddr, bytes: &[u8], now: Instant) {
        self.admit(LogLevel::Trace, "sip", now, |redactor, diagnostic| {
            let way = match travel {
                Travel::Received => "received from",
                Travel::Sent => "sent to",
            };
            if diagnostic {
                return format!(
                    "{way} {peer}, {} bytes:\n{}",
                    bytes.len(),
                    String::from_utf8_lossy(&strip_secrets(bytes))
                );
            }
            let peer = redact_text(&peer.to_string(), redactor);
            match redact_message(bytes, redactor) {
                Ok(clean) => format!(
                    "{way} {peer}, {} bytes:\n{}",
                    bytes.len(),
                    String::from_utf8_lossy(&clean)
                ),
                Err(_) => format!(
                    "{way} {peer}, {} bytes the parser does not read, withheld",
                    bytes.len()
                ),
            }
        });
    }

    fn admit(
        &self,
        level: LogLevel,
        target: &'static str,
        now: Instant,
        write: impl FnOnce(&mut Redactor, bool) -> String,
    ) {
        if !self.enabled(level) {
            return;
        }
        let mut inner = self.inner();
        if !inner.bucket.admit(now) || inner.queue.len() >= QUEUE_CEILING {
            inner.pending_suppressed = inner.pending_suppressed.saturating_add(1);
            inner.suppressed_ever = inner.suppressed_ever.saturating_add(1);
            return;
        }
        inner.redactor_uses += 1;
        if inner.redactor_uses > REDACTOR_REUSE {
            inner.redactor = Redactor::new(Mode::Hash(inner.key.clone()));
            inner.redactor_uses = 1;
        }
        let diagnostic = inner.diagnostic;
        let message = write(&mut inner.redactor, diagnostic);
        let suppressed = std::mem::take(&mut inner.pending_suppressed);
        inner.queue.push_back(Line {
            level,
            target,
            message,
            suppressed,
        });
    }

    /// Hand what is queued to the sink, and say how many lines that was.
    ///
    /// Call it holding no lock the sink could need — in particular, never
    /// from inside anything that holds the engine. Only what was queued when
    /// this began is delivered, so a sink that logs through this same log
    /// cannot keep a thread in here; a flush that finds another delivering
    /// returns zero at once, and what was queued after that one began waits
    /// in the queue for the next flush.
    #[must_use = "the count is what a caller that wants to know whether anything went reads"]
    pub fn flush(&self) -> usize {
        let (sink, mut batch) = {
            let mut inner = self.inner();
            if inner.delivering || inner.queue.is_empty() {
                return 0;
            }
            let Some(sink) = inner.sink.clone() else {
                inner.queue.clear();
                return 0;
            };
            inner.delivering = true;
            (sink, std::mem::take(&mut inner.queue))
        };
        // a sink that panics unwinds through here, and the flag has to come
        // down with it: left up, every later flush would find somebody
        // "delivering" and the log would go quiet for the rest of its life
        let _done = Delivering(self);
        let mut delivered = 0;
        while let Some(line) = batch.pop_front() {
            sink(&LogRecord {
                level: line.level,
                target: line.target,
                message: &line.message,
                suppressed: line.suppressed,
            });
            delivered += 1;
        }
        delivered
    }

    fn inner(&self) -> MutexGuard<'_, Inner> {
        // a panic in a producer leaves a queue and a few counters, whole
        // between statements
        self.0.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// A flush in progress on one log, which ends when this is dropped: at the
/// end of the batch, or while a panicking sink unwinds.
struct Delivering<'a>(&'a Log);

impl Drop for Delivering<'_> {
    fn drop(&mut self) {
        self.0.inner().delivering = false;
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BURST, Log, LogLevel, LogRecord, MIN_SALT, PER_SECOND, QUEUE_CEILING, SaltTooShort, Travel,
        pseudonym_key,
    };
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    type Seen = Arc<Mutex<Vec<(LogLevel, String, String, u64)>>>;

    fn listening(log: &Log, level: LogLevel) -> Seen {
        let seen: Seen = Arc::default();
        let into = Arc::clone(&seen);
        log.enable(
            level,
            Arc::new(move |record: &LogRecord<'_>| {
                into.lock().unwrap().push((
                    record.level,
                    record.target.to_owned(),
                    record.message.to_owned(),
                    record.suppressed,
                ));
            }),
        );
        seen
    }

    #[test]
    fn a_new_log_is_off_and_formats_nothing() {
        let log = Log::new(b"key");
        assert_eq!(log.level(), None);
        let mut formatted = false;
        log.line(LogLevel::Error, "test", Instant::now(), || {
            formatted = true;
            String::new()
        });
        assert!(!formatted, "a level that is off costs no formatting");
        assert_eq!(log.flush(), 0);
    }

    #[test]
    fn only_the_levels_asked_for_are_delivered() {
        let log = Log::new(b"key");
        let seen = listening(&log, LogLevel::Info);
        let now = Instant::now();
        for level in [
            LogLevel::Error,
            LogLevel::Warn,
            LogLevel::Info,
            LogLevel::Debug,
            LogLevel::Trace,
        ] {
            log.line(level, "test", now, || level.as_str().to_owned());
        }
        assert_eq!(log.flush(), 3);
        let levels: Vec<LogLevel> = seen.lock().unwrap().iter().map(|line| line.0).collect();
        assert_eq!(levels, [LogLevel::Error, LogLevel::Warn, LogLevel::Info]);
        log.set_level(LogLevel::Trace);
        log.line(LogLevel::Trace, "test", now, || "loud".to_owned());
        assert_eq!(log.flush(), 1);
        log.disable();
        log.line(LogLevel::Error, "test", now, || "gone".to_owned());
        assert_eq!(log.flush(), 0);
    }

    #[test]
    fn a_flood_is_cut_to_the_burst_and_the_next_line_says_how_much_went() {
        let log = Log::new(b"key");
        let seen = listening(&log, LogLevel::Debug);
        let start = Instant::now();
        let flood = BURST as usize * 50;
        for n in 0..flood {
            log.line(LogLevel::Debug, "flood", start, || format!("line {n}"));
        }
        assert_eq!(log.flush(), BURST as usize, "one burst at one instant");
        let after = start + Duration::from_secs(1);
        log.line(LogLevel::Warn, "calm", after, || "after".to_owned());
        assert_eq!(log.flush(), 1);
        let lines = seen.lock().unwrap();
        let last = lines.last().unwrap();
        assert_eq!(last.2, "after");
        assert_eq!(last.3, (flood - BURST as usize) as u64);
        assert_eq!(log.suppressed(), last.3);
        drop(lines);
        // the second after that earned another second's worth, on top of
        // what the line above left, and nothing more
        let later = after + Duration::from_secs(1);
        for _ in 0..PER_SECOND * 3 {
            log.line(LogLevel::Debug, "flood", later, String::new);
        }
        assert_eq!(log.flush(), (PER_SECOND * 2 - 1) as usize);
    }

    #[test]
    fn a_log_nobody_flushes_holds_no_more_than_its_ceiling() {
        let log = Log::new(b"key");
        let _seen = listening(&log, LogLevel::Debug);
        let mut now = Instant::now();
        for _ in 0..QUEUE_CEILING * 2 {
            now += Duration::from_secs(1);
            log.line(LogLevel::Debug, "held", now, String::new);
        }
        assert_eq!(log.flush(), QUEUE_CEILING);
        assert_eq!(log.suppressed(), QUEUE_CEILING as u64);
    }

    #[test]
    fn the_sink_runs_with_nothing_held_and_may_log_and_reconfigure_from_inside() {
        let log = Log::new(b"key");
        let inner = log.clone();
        let calls = Arc::new(Mutex::new(0_u32));
        let counted = Arc::clone(&calls);
        log.enable(
            LogLevel::Info,
            Arc::new(move |_record: &LogRecord<'_>| {
                // each of these takes the log's own lock: a sink called with
                // it held would deadlock here rather than return
                inner.line(LogLevel::Info, "again", Instant::now(), || {
                    "inside".to_owned()
                });
                inner.set_level(LogLevel::Debug);
                assert_eq!(inner.flush(), 0, "one flush delivers at a time");
                *counted.lock().unwrap() += 1;
            }),
        );
        log.line(LogLevel::Info, "first", Instant::now(), || {
            "outside".to_owned()
        });
        assert_eq!(log.flush(), 1, "only what was queued when the flush began");
        assert_eq!(log.level(), Some(LogLevel::Debug));
        assert_eq!(
            log.flush(),
            1,
            "what the sink logged waits for the next flush"
        );
        assert_eq!(*calls.lock().unwrap(), 2);
    }

    #[test]
    fn no_line_carries_a_user_an_address_or_a_credential() {
        let log = Log::new(b"key");
        let seen = listening(&log, LogLevel::Trace);
        let now = Instant::now();
        log.line(LogLevel::Warn, "api", now, || {
            "refused sip:alice@192.0.2.7:5060 with Authorization: Digest response=\"f00d\""
                .to_owned()
        });
        let message = b"INVITE sip:bob@198.51.100.4 SIP/2.0\r\n\
Via: SIP/2.0/UDP 198.51.100.4:5060;branch=z9hG4bK1\r\n\
From: \"Alice\" <sip:alice@example.com>;tag=1\r\n\
To: <sip:bob@example.com>\r\n\
Call-ID: c@d\r\n\
CSeq: 1 INVITE\r\n\
Proxy-Authorization: Digest username=\"alice\", response=\"beef\"\r\n\
Content-Type: application/sdp\r\n\
Content-Length: 60\r\n\r\n\
v=0\r\nc=IN IP4 198.51.100.4\r\na=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:QUJD\r\n";
        log.sip_message(
            Travel::Sent,
            "198.51.100.4:5060".parse().unwrap(),
            message,
            now,
        );
        log.sip_message(
            Travel::Received,
            "198.51.100.4:5060".parse().unwrap(),
            b"garbage from 198.51.100.4",
            now,
        );
        assert_eq!(log.flush(), 3);
        for (_, _, line, _) in seen.lock().unwrap().iter() {
            for secret in [
                "alice",
                "Alice",
                "bob@",
                "192.0.2.7",
                "198.51.100.4",
                "f00d",
                "beef",
                "QUJD",
            ] {
                assert!(!line.contains(secret), "{secret} in {line}");
            }
        }
    }

    #[test]
    fn one_key_gives_one_pseudonym_for_the_life_of_the_log() {
        let log = Log::new(b"key");
        let seen = listening(&log, LogLevel::Info);
        let mut now = Instant::now();
        for _ in 0..(super::REDACTOR_REUSE + 2) {
            now += Duration::from_millis(20);
            log.line(LogLevel::Info, "t", now, || "192.0.2.1".to_owned());
            let _ = log.flush();
        }
        let lines = seen.lock().unwrap();
        assert!(
            lines.iter().all(|line| line.2 == lines[0].2),
            "stable across a fresh redactor"
        );
    }

    #[test]
    fn a_sink_that_panics_once_does_not_silence_the_log() {
        let log = Log::new(b"key");
        let calls = Arc::new(Mutex::new(Vec::<String>::new()));
        let into = Arc::clone(&calls);
        log.enable(
            LogLevel::Info,
            Arc::new(move |record: &LogRecord<'_>| {
                let mut seen = into
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                seen.push(record.message.to_owned());
                let first = seen.len() == 1;
                drop(seen);
                assert!(!first, "the sink fails on its first line");
            }),
        );
        let now = Instant::now();
        log.line(LogLevel::Info, "t", now, || "first".to_owned());
        let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| log.flush()));
        assert!(unwound.is_err(), "the sink's panic reached the flush");

        log.line(LogLevel::Info, "t", now, || "second".to_owned());
        assert_eq!(log.flush(), 1, "the next flush delivers");
        assert_eq!(
            *calls
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            ["first", "second"]
        );
    }

    /// Every credential and key a message can carry, in the spellings a peer
    /// may use: the field names in any case and with space before the colon,
    /// a value folded onto a second line, bare LF line ends, two keys on one
    /// `a=crypto` line, `k=` and MIKEY.
    fn secret_bearing() -> Vec<(Vec<u8>, &'static [&'static str])> {
        const DIGEST: &[&str] = &["0badc0ffee", "d1gest-n0nce-kept?", "feedface", "5ecretpw"];
        const SDES: &[&str] = &["Rmlyc3RLZXk", "U2Vjb25kS2V5", "S0VZ", "MIKEYDATA"];
        let sdp = "v=0\r\no=alice 1 1 IN IP4 192.0.2.7\r\ns=-\r\nc=IN IP4 192.0.2.7\r\nt=0 0\r\n\
k=base64:S0VZ\r\na=key-mgmt:mikey MIKEYDATA\r\nm=audio 4000 RTP/SAVP 0\r\n\
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:Rmlyc3RLZXk|2^20|1:4;inline:U2Vjb25kS2V5|2^20|2:4\r\n";
        let invite = format!(
            "INVITE sip:bob@198.51.100.4 SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.7:5060;branch=z9hG4bK1\r\n\
From: \"Alice\" <sip:alice@example.com>;tag=1\r\n\
To: <sip:bob@example.com>\r\n\
Call-ID: c@d\r\n\
CSeq: 2 INVITE\r\n\
AUTHORIZATION : Digest username=\"alice\", response=\"0badc0ffee\",\r\n\x20\
cnonce=\"d1gest-n0nce-kept?\"\r\n\
Proxy-Authorization: Digest username=\"alice\", response=\"feedface\"\r\n\
Content-Type: application/sdp\r\n\
Content-Length: {}\r\n\r\n{sdp}",
            sdp.len()
        );
        let bare_lf = invite.replace("\r\n", "\n");
        let broken = format!(
            "{}\r\nproxy-authorization: Digest response=\"5ecretpw\"",
            &invite[..60]
        );
        let both: Vec<&'static str> = DIGEST.iter().chain(SDES).copied().collect();
        let both: &'static [&'static str] = Box::leak(both.into_boxed_slice());
        vec![
            (invite.into_bytes(), both),
            (bare_lf.into_bytes(), both),
            (broken.into_bytes(), &["5ecretpw"][..]),
        ]
    }

    #[test]
    fn no_credential_or_key_ever_reaches_a_line_in_either_mode() {
        for diagnostic in [false, true] {
            let log = Log::from_salt(b"an installation's salt").unwrap();
            log.set_diagnostic(diagnostic);
            let seen = listening(&log, LogLevel::Trace);
            let mut now = Instant::now();
            for (message, secrets) in secret_bearing() {
                now += Duration::from_millis(20);
                log.sip_message(
                    Travel::Sent,
                    "198.51.100.4:5060".parse().unwrap(),
                    &message,
                    now,
                );
                log.sip_message(
                    Travel::Received,
                    "198.51.100.4:5060".parse().unwrap(),
                    &message,
                    now,
                );
                log.line(LogLevel::Warn, "api", now, || {
                    String::from_utf8_lossy(&message).into_owned()
                });
                let _ = log.flush();
                for (_, _, line, _) in seen.lock().unwrap().drain(..) {
                    for secret in secrets {
                        assert!(
                            !line.contains(secret),
                            "{secret} with diagnostic {diagnostic}: {line}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn the_diagnostic_trace_is_off_until_asked_for_and_then_writes_messages_whole() {
        let log = Log::new(b"key");
        assert!(!log.diagnostic());
        let seen = listening(&log, LogLevel::Trace);
        let (message, _) = secret_bearing().remove(0);
        let peer = "198.51.100.4:5060".parse().unwrap();
        let now = Instant::now();
        log.sip_message(Travel::Sent, peer, &message, now);
        log.set_diagnostic(true);
        assert!(log.diagnostic());
        log.sip_message(Travel::Sent, peer, &message, now);
        log.sip_message(Travel::Received, peer, b"garbage from 198.51.100.4", now);
        log.line(LogLevel::Info, "call", now, || {
            "calling sip:bob@198.51.100.4 with Authorization: Digest response=\"f00d\"".to_owned()
        });
        assert_eq!(log.flush(), 4);
        let lines: Vec<String> = seen
            .lock()
            .unwrap()
            .iter()
            .map(|line| line.2.clone())
            .collect();
        assert!(!lines[0].contains("alice") && !lines[0].contains("198.51.100.4"));
        for whole in [
            "sent to 198.51.100.4:5060,",
            "From: \"Alice\" <sip:alice@example.com>;tag=1",
            "o=alice 1 1 IN IP4 192.0.2.7",
            "AUTHORIZATION: REDACTED\r\nProxy-Authorization: REDACTED\r\n",
        ] {
            assert!(lines[1].contains(whole), "{whole:?} not in {}", lines[1]);
        }
        assert!(
            lines[2].ends_with("garbage from 198.51.100.4"),
            "bytes the parser refuses are written, stripped: {}",
            lines[2]
        );
        assert_eq!(
            lines[3],
            "calling sip:bob@198.51.100.4 with Authorization: REDACTED"
        );

        log.set_diagnostic(false);
        log.sip_message(Travel::Sent, peer, &message, now);
        assert_eq!(log.flush(), 1);
        let back = seen.lock().unwrap().last().unwrap().2.clone();
        assert!(
            !back.contains("alice") && !back.contains("198.51.100.4"),
            "{back}"
        );
    }

    #[test]
    fn one_salt_gives_the_same_pseudonyms_in_every_run() {
        // the trial: loopback's pseudonym changed on every start, so two runs
        // could not be compared
        let run = |salt: &[u8]| {
            let log = Log::from_salt(salt).unwrap();
            let seen = listening(&log, LogLevel::Info);
            log.line(LogLevel::Info, "t", Instant::now(), || {
                "127.0.0.1 and sip:alice@192.0.2.1".to_owned()
            });
            let _ = log.flush();
            let line = seen.lock().unwrap()[0].2.clone();
            assert!(
                !line.contains("127.0.0.1") && !line.contains("alice"),
                "{line}"
            );
            line
        };
        let salt = [7_u8; MIN_SALT];
        assert_eq!(run(&salt), run(&salt), "the same salt, another run");
        assert_ne!(run(&salt), run(&[8_u8; MIN_SALT]), "another installation");
        assert_eq!(pseudonym_key(&salt), pseudonym_key(&salt));
        assert_eq!(
            Log::from_salt(&[7_u8; MIN_SALT - 1]).err(),
            Some(SaltTooShort { len: MIN_SALT - 1 })
        );
    }
}
