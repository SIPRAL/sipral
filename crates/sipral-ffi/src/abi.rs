// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! The ABI, described by the declarations that are the ABI.
//!
//! A C seam declared in four places — the Rust, the header, and three
//! bindings — is four things that have to agree, and the way they stop
//! agreeing is that somebody adds a function to one of them. The header and
//! the bindings are therefore not written: they are printed from what is
//! here, by `tools/abi-gen`, and `scripts/check.sh` prints them again and
//! fails if what is committed is not what came out.
//!
//! Nothing here is a second declaration of anything. Every macro in this
//! module emits the Rust item exactly as it would have been written by hand
//! and, beside it, a `const` saying what shape it emitted — the name, the
//! members, their types, and the documentation, all taken from the tokens the
//! declaration is made of. There is no parser for Rust anywhere in this
//! arrangement, and there is nothing for a `cfg` to hide, because the compiler
//! is what reads the source.
//!
//! What is written by hand is [`SURFACE`]: one line per item, naming it. That
//! line is the only thing a person can forget, and forgetting it is caught
//! three ways. The descriptor beside an unlisted item is dead code, and this
//! workspace builds with `-D warnings`. `scripts/check.sh` compares the items
//! the modules declare against the lines here and names the difference. And
//! the generator refuses to print a surface in which one type is reachable
//! from another that is not listed, because a header that mentions a struct it
//! never defined is not a header.
//!
//! The costs of that arrangement are in `docs/08-ffi.md`, along with what the
//! gate does not catch.

/// One parameter of an entry point, or one member of a struct.
#[derive(Clone, Copy, Debug)]
pub struct Member {
    /// What it is called, on both sides of the boundary.
    pub name: &'static str,
    /// Its type, as the Rust declaration spells it.
    pub rust_type: &'static str,
    /// Its documentation, one entry per line, as written.
    pub doc: &'static [&'static str],
}

/// One entry point.
#[derive(Clone, Copy, Debug)]
pub struct Function {
    /// The exported symbol, which is also what every binding calls it.
    pub name: &'static str,
    /// Its documentation, one entry per line, as written.
    pub doc: &'static [&'static str],
    /// Its parameters, in order.
    pub parameters: &'static [Member],
    /// What it returns, as the Rust declaration spells it.
    pub returns: &'static str,
}

/// Whether the members of a record share their storage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Shape {
    /// One after another.
    Struct,
    /// All at the same address, and only the one that was written may be read.
    Union,
}

/// One `#[repr(C)]` struct or union that crosses the boundary.
#[derive(Clone, Copy, Debug)]
pub struct Record {
    /// Its Rust name. The C name and every binding's name are derived from it.
    pub name: &'static str,
    /// Its documentation, one entry per line, as written.
    pub doc: &'static [&'static str],
    /// Struct or union.
    pub shape: Shape,
    /// Its members, in declaration order, which for a struct is also the
    /// order they sit in memory.
    pub fields: &'static [Member],
    /// How many bytes this build compiled it to, padding and all. Not the
    /// ABI — a struct of pointers is one length on a 32-bit target and
    /// another on a 64-bit one — but what this build will read and write,
    /// which is the number a C caller checks its own `sizeof` against.
    pub size: usize,
}

impl Record {
    /// Whether the first member is the `size` that makes appending a member
    /// to a released struct safe. The bindings fill it in for the caller.
    #[must_use]
    pub fn is_versioned(&self) -> bool {
        self.fields
            .first()
            .is_some_and(|first| first.name == "size")
    }

    /// What C calls it: `SipralStackConfig` is `sipral_stack_config_t`.
    #[must_use]
    pub fn c_name(&self) -> String {
        format!("{}_t", snake(self.name))
    }
}

/// The one rule for turning a Rust name into the name the C side spells:
/// `SipralStackConfig` becomes `sipral_stack_config`.
///
/// Here rather than in the generator because the library answers questions
/// about the C names too — [`crate::version::sipral_abi_struct_size`] is asked one
/// — and a derivation written twice is a derivation that can disagree with
/// itself.
#[must_use]
pub fn snake(name: &str) -> String {
    let mut out = String::new();
    let mut previous_lower = false;
    for letter in name.chars() {
        if letter.is_ascii_uppercase() {
            if previous_lower {
                out.push('_');
            }
            out.push(letter.to_ascii_lowercase());
            previous_lower = false;
        } else {
            out.push(letter);
            previous_lower = letter.is_ascii_lowercase() || letter.is_ascii_digit();
        }
    }
    out
}

/// One named number inside an enumeration.
#[derive(Clone, Copy, Debug)]
pub struct Code {
    /// Its Rust name. The C constant is built from it and the type's.
    pub name: &'static str,
    /// Its documentation, one entry per line, as written.
    pub doc: &'static [&'static str],
    /// The number, which is the part that is the ABI.
    pub value: i64,
}

/// A number spent on a feature that does not exist yet, so that two features
/// cannot arrive holding the same one.
#[derive(Clone, Copy, Debug)]
pub struct Held {
    /// The number.
    pub value: i64,
    /// What it is being held for.
    pub feature: &'static str,
}

/// One enumeration whose numbers are part of the ABI.
#[derive(Clone, Copy, Debug)]
pub struct Enumeration {
    /// Its Rust name.
    pub name: &'static str,
    /// Its documentation, one entry per line, as written.
    pub doc: &'static [&'static str],
    /// The integer type the `repr` fixes it to, as Rust spells it.
    pub width: &'static str,
    /// Its values, in declaration order.
    pub codes: &'static [Code],
    /// Numbers already spent, and on what.
    pub reserved: &'static [Held],
}

/// One published constant.
#[derive(Clone, Copy, Debug)]
pub struct Value {
    /// Its name, which is the same in every language.
    pub name: &'static str,
    /// Its documentation, one entry per line, as written.
    pub doc: &'static [&'static str],
    /// Its type, as the Rust declaration spells it.
    pub rust_type: &'static str,
    /// What it comes to. Read from the declaration itself, so an expression
    /// that changes changes this with it.
    pub value: u64,
}

/// What an alias stands for.
#[derive(Clone, Copy, Debug)]
pub enum Stands {
    /// Another name for a plain integer.
    For(&'static str),
    /// A function the caller supplies and the library calls, with its
    /// arguments and what it answers with: a plain integer, as the Rust
    /// declaration spells it, or nothing for a callback that only reports.
    /// Nothing is what every callback declared today answers with, and it is
    /// what a listener that throws instead of answering is read as, for one
    /// that does.
    Callback(&'static [Member], Option<&'static str>),
}

/// One published type alias.
#[derive(Clone, Copy, Debug)]
pub struct Alias {
    /// Its Rust name.
    pub name: &'static str,
    /// Its documentation, one entry per line, as written.
    pub doc: &'static [&'static str],
    /// What it is.
    pub stands: Stands,
}

/// Everything that crosses the C boundary.
///
/// The generator reads this and nothing else. Every list is in the order the
/// header should read in, which is the order the modules are introduced in
/// `crate`'s own documentation rather than alphabetical.
#[derive(Clone, Copy, Debug)]
pub struct Surface {
    /// The version this ABI reports, as three numbers.
    pub version: (u32, u32, u32),
    /// Names for plain integers, and the event callback.
    pub aliases: &'static [Alias],
    /// Enumerations, before the records that hold their numbers.
    pub enumerations: &'static [Enumeration],
    /// Structs and unions, in an order where nothing is used before it is
    /// defined.
    pub records: &'static [Record],
    /// Published constants, grouped as the modules declare them.
    pub constants: &'static [&'static [Value]],
    /// Entry points, in the order the header should list them.
    pub functions: &'static [Function],
}

/// Declare a `#[repr(C)]` struct or union that crosses the boundary.
///
/// The declaration is emitted exactly as it is written, and a [`Record`]
/// beside it saying what was emitted. The `#[repr(C)]` is the macro's rather
/// than the author's on purpose: `scripts/check.sh` refuses a `repr` written
/// at the top level of any module here, so a type that crosses cannot be
/// declared anywhere this does not see it.
macro_rules! record {
    // A declaration is documentation, then derives, then the type, and two
    // repetitions of attributes side by side is more than the macro parser can
    // tell apart. So the documentation is taken a line at a time and set aside
    // first, and what is left starts with something that is not a doc comment.
    (
        @doc [$($taken:literal)*]
        #[doc = $line:literal]
        $($rest:tt)*
    ) => {
        $crate::abi::record! { @doc [$($taken)* $line] $($rest)* }
    };
    (
        @doc [$($doc:literal)*]
        $(#[$attribute:meta])*
        pub struct $name:ident {
            $(
                $(#[doc = $member_doc:literal])*
                pub $member:ident: $member_type:ty,
            )*
        }
    ) => {
        $(#[doc = $doc])*
        $(#[$attribute])*
        #[repr(C)]
        pub struct $name {
            $(
                $(#[doc = $member_doc])*
                pub $member: $member_type,
            )*
        }

        impl $name {
            /// What this struct is, for the header and the bindings.
            pub(crate) const ABI: $crate::abi::Record = $crate::abi::Record {
                name: stringify!($name),
                doc: &[$($doc),*],
                shape: $crate::abi::Shape::Struct,
                fields: &[$($crate::abi::Member {
                    name: stringify!($member),
                    rust_type: stringify!($member_type),
                    doc: &[$($member_doc),*],
                }),*],
                size: ::std::mem::size_of::<$name>(),
            };
        }
    };
    (
        @doc [$($doc:literal)*]
        $(#[$attribute:meta])*
        pub union $name:ident {
            $(
                $(#[doc = $member_doc:literal])*
                pub $member:ident: $member_type:ty,
            )*
        }
    ) => {
        $(#[doc = $doc])*
        $(#[$attribute])*
        #[repr(C)]
        pub union $name {
            $(
                $(#[doc = $member_doc])*
                pub $member: $member_type,
            )*
        }

        impl $name {
            /// What this union is, for the header and the bindings.
            pub(crate) const ABI: $crate::abi::Record = $crate::abi::Record {
                name: stringify!($name),
                doc: &[$($doc),*],
                shape: $crate::abi::Shape::Union,
                fields: &[$($crate::abi::Member {
                    name: stringify!($member),
                    rust_type: stringify!($member_type),
                    doc: &[$($member_doc),*],
                }),*],
                size: ::std::mem::size_of::<$name>(),
            };
        }
    };
    ($($declaration:tt)*) => {
        $crate::abi::record! { @doc [] $($declaration)* }
    };
}

/// Declare an enumeration whose numbers are part of the ABI.
///
/// The width is written out rather than left to the compiler, because a C
/// compiler left to itself picks its own and the two do not have to agree.
/// Documentation is set aside a line at a time for the reason [`record`] is.
macro_rules! codes {
    (
        @doc [$($taken:literal)*]
        #[doc = $line:literal]
        $($rest:tt)*
    ) => {
        $crate::abi::codes! { @doc [$($taken)* $line] $($rest)* }
    };
    (
        @doc [$($doc:literal)*]
        $(#[$attribute:meta])*
        pub enum $name:ident: $width:ident {
            $(
                $(#[doc = $code_doc:literal])*
                $code:ident = $value:literal,
            )*
        }
    ) => {
        $(#[doc = $doc])*
        $(#[$attribute])*
        #[repr($width)]
        pub enum $name {
            $(
                $(#[doc = $code_doc])*
                $code = $value,
            )*
        }

        impl $name {
            /// What this enumeration is, for the header and the bindings.
            pub(crate) const ABI: $crate::abi::Enumeration = $crate::abi::Enumeration {
                name: stringify!($name),
                doc: &[$($doc),*],
                width: stringify!($width),
                codes: &[$($crate::abi::Code {
                    name: stringify!($code),
                    doc: &[$($code_doc),*],
                    value: $value,
                }),*],
                reserved: &[],
            };
        }
    };
    ($($declaration:tt)*) => {
        $crate::abi::codes! { @doc [] $($declaration)* }
    };
}

/// Declare the constants one module publishes.
///
/// The value in the descriptor is the constant itself rather than a copy of
/// the literal, so an expression that is rewritten is printed as whatever it
/// now comes to.
macro_rules! constants {
    (
        $(
            $(#[doc = $doc:literal])*
            pub const $name:ident: $type:ty = $value:expr;
        )*
    ) => {
        $(
            $(#[doc = $doc])*
            pub const $name: $type = $value;
        )*

        /// What this module publishes, for the header and the bindings.
        pub(crate) const ABI_CONSTANTS: &[$crate::abi::Value] = &[
            $($crate::abi::Value {
                name: stringify!($name),
                doc: &[$($doc),*],
                rust_type: stringify!($type),
                value: $name as u64,
            }),*
        ];
    };
}

/// Declare a published type alias, or the shape of a callback: one that only
/// reports, or one that answers.
///
/// The callback arms come first because a function type is also a type, and
/// the arms are tried in order. The answering arm comes before the
/// fire-and-forget one for the same reason: a return type is more tokens
/// than none, and a pattern that would match a shorter input is tried second.
macro_rules! alias {
    (
        $(#[doc = $doc:literal])*
        pub type $name:ident = fn($($argument:ident: $type:ty),* $(,)?) -> $answer:ty;
    ) => {
        $(#[doc = $doc])*
        pub type $name = Option<unsafe extern "C" fn($($argument: $type),*) -> $answer>;

        #[allow(non_upper_case_globals)]
        pub(crate) const $name: $crate::abi::Alias = $crate::abi::Alias {
            name: stringify!($name),
            doc: &[$($doc),*],
            stands: $crate::abi::Stands::Callback(
                &[$($crate::abi::Member {
                    name: stringify!($argument),
                    rust_type: stringify!($type),
                    doc: &[],
                }),*],
                Some(stringify!($answer)),
            ),
        };
    };
    (
        $(#[doc = $doc:literal])*
        pub type $name:ident = fn($($argument:ident: $type:ty),* $(,)?);
    ) => {
        $(#[doc = $doc])*
        pub type $name = Option<unsafe extern "C" fn($($argument: $type),*)>;

        #[allow(non_upper_case_globals)]
        pub(crate) const $name: $crate::abi::Alias = $crate::abi::Alias {
            name: stringify!($name),
            doc: &[$($doc),*],
            stands: $crate::abi::Stands::Callback(
                &[$($crate::abi::Member {
                    name: stringify!($argument),
                    rust_type: stringify!($type),
                    doc: &[],
                }),*],
                None,
            ),
        };
    };
    (
        $(#[doc = $doc:literal])*
        pub type $name:ident = $target:ty;
    ) => {
        $(#[doc = $doc])*
        pub type $name = $target;

        #[allow(non_upper_case_globals)]
        pub(crate) const $name: $crate::abi::Alias = $crate::abi::Alias {
            name: stringify!($name),
            doc: &[$($doc),*],
            stands: $crate::abi::Stands::For(stringify!($target)),
        };
    };
}

pub(crate) use {alias, codes, constants, record};

/// Every versioned struct and the length it first shipped at, for the
/// generator and for the test that says the table is complete.
///
/// The Rust name, so that it can be matched against
/// [`SURFACE`] without anything being spelled twice.
pub const MIN_SIZES: &[(&str, usize)] = &[
    ("SipralAbiVersion", crate::versioned::min_size::ABI_VERSION),
    (
        "SipralAudioDevice",
        crate::versioned::min_size::AUDIO_DEVICE,
    ),
    ("SipralAudioInfo", crate::versioned::min_size::AUDIO_INFO),
    (
        "SipralAccountConfig",
        crate::versioned::min_size::ACCOUNT_CONFIG,
    ),
    ("SipralCallConfig", crate::versioned::min_size::CALL_CONFIG),
    (
        "SipralCapabilities",
        crate::versioned::min_size::CAPABILITIES,
    ),
    (
        "SipralCodecCandidate",
        crate::versioned::min_size::CODEC_CANDIDATE,
    ),
    ("SipralCodecInfo", crate::versioned::min_size::CODEC_INFO),
    ("SipralCounters", crate::versioned::min_size::COUNTERS),
    ("SipralMediaInfo", crate::versioned::min_size::MEDIA_INFO),
    (
        "SipralMediaPacket",
        crate::versioned::min_size::MEDIA_PACKET,
    ),
    (
        "SipralPathCandidate",
        crate::versioned::min_size::PATH_CANDIDATE,
    ),
    ("SipralPollResult", crate::versioned::min_size::POLL_RESULT),
    (
        "SipralStackConfig",
        crate::versioned::min_size::STACK_CONFIG,
    ),
    (
        "SipralStackSettings",
        crate::versioned::min_size::STACK_SETTINGS,
    ),
    (
        "SipralStreamStats",
        crate::versioned::min_size::STREAM_STATS,
    ),
    (
        "SipralSubscribeConfig",
        crate::versioned::min_size::SUBSCRIBE_CONFIG,
    ),
    (
        "SipralWatchedDialog",
        crate::versioned::min_size::WATCHED_DIALOG,
    ),
    ("SipralPushEcho", crate::versioned::min_size::PUSH_ECHO),
    ("SipralTransmit", crate::versioned::min_size::TRANSMIT),
    // 32, the same literal `crate::lifecycle::SipralSuspending`'s own
    // `Versioned` impl pins its `MIN_SIZE` at — see the comment there for why
    // it is not `crate::versioned::min_size::SUSPENDING` beside the rest.
    ("SipralSuspending", 32),
    ("SipralConference", crate::versioned::min_size::CONFERENCE),
    (
        "SipralConferenceUser",
        crate::versioned::min_size::CONFERENCE_USER,
    ),
    ("SipralPresence", crate::versioned::min_size::PRESENCE),
    (
        "SipralRecordConfig",
        crate::versioned::min_size::RECORD_CONFIG,
    ),
];

/// The versioned-shaped structs with no pinned length, and why.
///
/// `sipral_event_t` and `sipral_screen_request_t` start with a `size` like the
/// rest, but the library is what fills them in: each is handed to a callback
/// as a `const` pointer and the caller reads no further than the `size` says.
/// Nothing ever declares one to us, so there is no declared size to refuse and
/// no oldest published length that matters. The exceptions are named here
/// rather than left to be noticed, because a struct that quietly went unpinned
/// would look exactly like these two.
pub const FILLED_BY_US: &[&str] = &[
    "SipralEvent",
    "SipralScreenRequest",
    "SipralProcessorFrame",
    "SipralAudioTransmit",
    "SipralLogRecord",
];

/// Everything this ABI publishes, and the only list a person maintains.
///
/// A line here is one item. Adding an item without adding its line leaves a
/// descriptor nothing reads, which is a dead-code warning and therefore a
/// failed build; `scripts/check.sh` says the same thing in a sentence.
pub const SURFACE: Surface = Surface {
    version: (
        crate::version::SIPRAL_ABI_VERSION_MAJOR,
        crate::version::SIPRAL_ABI_VERSION_MINOR,
        crate::version::SIPRAL_ABI_VERSION_PATCH,
    ),
    aliases: &[
        crate::handle::SipralHandle,
        crate::event::SipralEventCallback,
        crate::screening::SipralScreenCallback,
        crate::media::SipralProcessorCallback,
        crate::audio::SipralAudioTransmitCallback,
        crate::log::SipralLogCallback,
    ],
    enumerations: &[
        crate::status::SipralStatus::ABI,
        crate::stack::SipralTransport::ABI,
        crate::transport::SipralTransportError::ABI,
        crate::media::SipralToggle::ABI,
        crate::media::SipralSrtp::ABI,
        crate::media::SipralIce::ABI,
        crate::media::SipralCodec::ABI,
        crate::media::SipralCodecOutcome::ABI,
        crate::media::SipralPathKind::ABI,
        crate::media::SipralCandidateKind::ABI,
        crate::media::SipralPathOutcome::ABI,
        crate::media::SipralDirection::ABI,
        crate::media::SipralRtcp::ABI,
        crate::media::SipralMediaFault::ABI,
        crate::media::SipralArrival::ABI,
        crate::media::SipralSrtpSuite::ABI,
        crate::media::SipralPlayback::ABI,
        crate::call::SipralDtmf::ABI,
        crate::event::SipralEventKind::ABI,
        crate::event::SipralRegistrationState::ABI,
        crate::event::SipralRegistrationFailure::ABI,
        crate::event::SipralCallState::ABI,
        crate::event::SipralCallEndReason::ABI,
        crate::event::SipralDigitSource::ABI,
        crate::event::SipralRecoveryOutcome::ABI,
        crate::event::SipralRecoveryRung::ABI,
        crate::event::SipralRecoveryFailure::ABI,
        crate::lifecycle::SipralLink::ABI,
        crate::lifecycle::SipralRecovery::ABI,
        crate::nat::SipralNat::ABI,
        crate::nat::SipralNatMapping::ABI,
        crate::nat::SipralNatRelay::ABI,
        crate::nat::SipralTurnStream::ABI,
        crate::nat::SipralStunServerState::ABI,
        crate::subscription::SipralSubscriptionState::ABI,
        crate::subscription::SipralSubscriptionEnd::ABI,
        crate::subscription::SipralDialogPhase::ABI,
        crate::subscription::SipralDialogDirection::ABI,
        crate::subscription::SipralDialogEnded::ABI,
        crate::subscription::SipralDialogText::ABI,
        crate::audio::SipralAudio::ABI,
        crate::audio::SipralAudioActivation::ABI,
        crate::audio::SipralAudioRole::ABI,
        crate::audio::SipralAudioDirection::ABI,
        crate::audio::SipralAudioChange::ABI,
        crate::audio::SipralAudioOrigin::ABI,
        crate::identity::SipralVerstat::ABI,
        crate::identity::SipralAnswerMode::ABI,
        crate::identity::SipralRingSource::ABI,
        crate::identity::SipralIdentityText::ABI,
        crate::identity::SipralSessionTimer::ABI,
        crate::log::SipralLogLevel::ABI,
        crate::conference::SipralConferenceUpdate::ABI,
        crate::conference::SipralEndpointStatus::ABI,
        crate::conference::SipralConferenceText::ABI,
        crate::presence::SipralPresenceKind::ABI,
        crate::presence::SipralBasic::ABI,
        crate::presence::SipralActivity::ABI,
        crate::presence::SipralPublicationState::ABI,
        crate::presence::SipralPublishFailure::ABI,
    ],
    records: &[
        crate::version::SipralAbiVersion::ABI,
        crate::capabilities::SipralCapabilities::ABI,
        crate::counters::SipralCounters::ABI,
        crate::stack::SipralStackConfig::ABI,
        crate::stack::SipralPollResult::ABI,
        crate::stack::SipralStackSettings::ABI,
        crate::header::SipralHeader::ABI,
        crate::account::SipralAccountConfig::ABI,
        crate::call::SipralCallConfig::ABI,
        crate::media::SipralCodecInfo::ABI,
        crate::media::SipralCodecCandidate::ABI,
        crate::media::SipralPathCandidate::ABI,
        crate::media::SipralMediaInfo::ABI,
        crate::media::SipralStreamStats::ABI,
        crate::media::SipralMediaPacket::ABI,
        crate::media::SipralProcessorFrame::ABI,
        crate::transport::SipralTransmit::ABI,
        crate::event::SipralRegistrationEvent::ABI,
        crate::event::SipralCallEvent::ABI,
        crate::event::SipralTransferEvent::ABI,
        crate::event::SipralMediaEvent::ABI,
        crate::event::SipralRecoveryEvent::ABI,
        crate::event::SipralTransportWantedEvent::ABI,
        crate::event::SipralSubscriptionEvent::ABI,
        crate::event::SipralAnnounceEvent::ABI,
        crate::event::SipralResolveEvent::ABI,
        crate::event::SipralMessageEvent::ABI,
        crate::nat::SipralNatEvent::ABI,
        crate::nat::SipralNatRelayEvent::ABI,
        crate::event::SipralReferralEvent::ABI,
        crate::nat::SipralTurnStreamEvent::ABI,
        crate::audio::SipralAudioEvent::ABI,
        crate::nat::SipralStunServerEvent::ABI,
        crate::conference::SipralConferenceEvent::ABI,
        crate::realtime_text::SipralTextEvent::ABI,
        crate::presence::SipralPresenceEvent::ABI,
        crate::event::SipralEventPayload::ABI,
        crate::event::SipralEvent::ABI,
        crate::lifecycle::SipralSuspending::ABI,
        crate::screening::SipralScreenRequest::ABI,
        crate::subscription::SipralSubscribeConfig::ABI,
        crate::subscription::SipralWatchedDialog::ABI,
        crate::announce::SipralPushEcho::ABI,
        crate::audio::SipralAudioDevice::ABI,
        crate::audio::SipralAudioInfo::ABI,
        crate::audio::SipralAudioTransmit::ABI,
        crate::log::SipralLogRecord::ABI,
        crate::conference::SipralConference::ABI,
        crate::conference::SipralConferenceUser::ABI,
        crate::presence::SipralPresence::ABI,
        crate::siprec::SipralRecordConfig::ABI,
    ],
    constants: &[
        crate::handle::ABI_CONSTANTS,
        crate::version::ABI_CONSTANTS,
        crate::capabilities::ABI_CONSTANTS,
        crate::media::ABI_CONSTANTS,
        crate::transport::ABI_CONSTANTS,
        crate::screening::ABI_CONSTANTS,
        crate::identity::ABI_CONSTANTS,
        crate::log::ABI_CONSTANTS,
    ],
    functions: &[
        crate::error::sipral_last_error_message::ABI,
        crate::status::sipral_status_name::ABI,
        crate::version::sipral_abi_version::ABI,
        crate::version::sipral_abi_check::ABI,
        crate::version::sipral_abi_struct_size::ABI,
        crate::version::sipral_abi_versioned_count::ABI,
        crate::capabilities::sipral_capabilities::ABI,
        crate::stack::sipral_stack_create::ABI,
        crate::stack::sipral_stack_settings::ABI,
        crate::stack::sipral_stack_destroy::ABI,
        crate::stack::sipral_stack_poll::ABI,
        crate::counters::sipral_stack_counters::ABI,
        crate::screening::sipral_stack_screen::ABI,
        crate::screening::sipral_stack_invite_limit::ABI,
        crate::subscription::sipral_account_subscribe::ABI,
        crate::subscription::sipral_subscription_end::ABI,
        crate::subscription::sipral_subscription_state::ABI,
        crate::subscription::sipral_subscription_lamp::ABI,
        crate::subscription::sipral_subscription_dialog_count::ABI,
        crate::subscription::sipral_subscription_dialog_at::ABI,
        crate::subscription::sipral_subscription_dialog_text::ABI,
        crate::message::sipral_account_message::ABI,
        crate::announce::sipral_account_announce::ABI,
        crate::announce::sipral_account_refresh_binding::ABI,
        crate::announce::sipral_announcement_forget::ABI,
        crate::announce::sipral_account_push_echo::ABI,
        crate::account::sipral_account_add::ABI,
        crate::account::sipral_account_remove::ABI,
        crate::account::sipral_account_register::ABI,
        crate::account::sipral_account_unregister::ABI,
        crate::account::sipral_account_registration_state::ABI,
        crate::call::sipral_call_place::ABI,
        crate::call::sipral_call_ring::ABI,
        crate::call::sipral_call_ring_media::ABI,
        crate::call::sipral_call_answer::ABI,
        crate::call::sipral_call_answer_media::ABI,
        crate::call::sipral_call_answer_with::ABI,
        crate::call::sipral_call_reject::ABI,
        crate::call::sipral_call_hangup::ABI,
        crate::call::sipral_call_set_headers::ABI,
        crate::call::sipral_call_hold::ABI,
        crate::call::sipral_call_resume::ABI,
        crate::call::sipral_call_change_codecs::ABI,
        crate::call::sipral_call_restart_ice::ABI,
        crate::call::sipral_call_media_readdress::ABI,
        crate::identity::sipral_call_hangup_for::ABI,
        crate::identity::sipral_call_redirect::ABI,
        crate::identity::sipral_call_identity_count::ABI,
        crate::identity::sipral_call_identity_text::ABI,
        crate::call::sipral_call_join::ABI,
        crate::call::sipral_call_leave::ABI,
        crate::call::sipral_call_accept_session::ABI,
        crate::call::sipral_call_reject_session::ABI,
        crate::call::sipral_call_send_dtmf::ABI,
        crate::call::sipral_call_transfer::ABI,
        crate::call::sipral_call_consult::ABI,
        crate::call::sipral_call_transfer_to::ABI,
        crate::call::sipral_call_accept_transfer::ABI,
        crate::call::sipral_call_reject_transfer::ABI,
        crate::call::sipral_call_state::ABI,
        crate::call::sipral_call_hold_state::ABI,
        crate::media::sipral_codec_name::ABI,
        crate::media::sipral_codec_count::ABI,
        crate::media::sipral_codec_at::ABI,
        crate::media::sipral_stack_codec_order::ABI,
        crate::media::sipral_call_media::ABI,
        crate::media::sipral_media_release::ABI,
        crate::media::sipral_media_info::ABI,
        crate::media::sipral_media_codec_candidate_count::ABI,
        crate::media::sipral_media_codec_candidate_at::ABI,
        crate::media::sipral_media_path_candidate_count::ABI,
        crate::media::sipral_media_path_candidate_at::ABI,
        crate::media::sipral_media_statistics::ABI,
        crate::media::sipral_media_receive::ABI,
        crate::media::sipral_media_playback::ABI,
        crate::media::sipral_media_capture::ABI,
        crate::media::sipral_call_attach_processor::ABI,
        crate::media::sipral_call_detach_processor::ABI,
        crate::media::sipral_call_reset_processor::ABI,
        crate::media::sipral_media_mix::ABI,
        crate::media::sipral_media_poll_rtcp::ABI,
        crate::media::sipral_media_poll_transmit::ABI,
        crate::media::sipral_stack_poll_farewell::ABI,
        crate::media::sipral_media_dialling::ABI,
        crate::media::sipral_media_stop_dialling::ABI,
        crate::record::sipral_media_record_start::ABI,
        crate::record::sipral_media_record_stop::ABI,
        crate::record::sipral_media_record_state::ABI,
        crate::transport::sipral_stack_poll_transmit::ABI,
        crate::transport::sipral_stack_receive_datagram::ABI,
        crate::transport::sipral_stack_receive_stream::ABI,
        crate::transport::sipral_stack_transport_bind::ABI,
        crate::transport::sipral_stack_transport_failed::ABI,
        crate::transport::sipral_stack_stream_closed::ABI,
        crate::nat::sipral_stack_stun_servers::ABI,
        crate::nat::sipral_stack_nat_map::ABI,
        crate::nat::sipral_stack_nat_unmap::ABI,
        crate::nat::sipral_stack_poll_stun::ABI,
        crate::nat::sipral_stack_receive_stun::ABI,
        crate::nat::sipral_stack_turn_connected::ABI,
        crate::nat::sipral_stack_turn_receive::ABI,
        crate::nat::sipral_stack_turn_closed::ABI,
        crate::event::sipral_event_kind_name::ABI,
        crate::header::sipral_message_header_count::ABI,
        crate::header::sipral_message_header::ABI,
        crate::header::sipral_message_header_element_count::ABI,
        crate::header::sipral_message_header_element::ABI,
        crate::lifecycle::sipral_stack_suspending::ABI,
        crate::lifecycle::sipral_stack_resumed::ABI,
        crate::lifecycle::sipral_stack_network_changed::ABI,
        crate::lifecycle::sipral_stack_interface_lost::ABI,
        crate::lifecycle::sipral_stack_name_resolution_lost::ABI,
        crate::lifecycle::sipral_account_rebind::ABI,
        crate::lifecycle::sipral_stack_cold_start::ABI,
        crate::lifecycle::sipral_account_freeze::ABI,
        crate::lifecycle::sipral_account_thaw::ABI,
        crate::lifecycle::sipral_account_time_to_ready::ABI,
        crate::resolve::sipral_stack_resolved::ABI,
        crate::resolve::sipral_account_retarget::ABI,
        crate::diagnostics::sipral_call_record_json::ABI,
        crate::diagnostics::sipral_stack_diagnostics_json::ABI,
        crate::conference::sipral_subscription_conference::ABI,
        crate::conference::sipral_subscription_conference_user_at::ABI,
        crate::conference::sipral_subscription_conference_text::ABI,
        crate::conference::sipral_call_set_focus::ABI,
        crate::conference::sipral_call_conference_uri::ABI,
        crate::conference::sipral_call_subscribe_conference::ABI,
        crate::presence::sipral_account_publish_presence::ABI,
        crate::presence::sipral_account_unpublish_presence::ABI,
        crate::realtime_text::sipral_media_send_text::ABI,
        crate::realtime_text::sipral_media_poll_text::ABI,
        crate::realtime_text::sipral_media_receive_text::ABI,
        crate::siprec::sipral_call_record_to::ABI,
        crate::siprec::sipral_call_stop_recording_to::ABI,
        crate::siprec::sipral_media_poll_recording::ABI,
        crate::diagnostics::sipral_stack_recording_start::ABI,
        crate::diagnostics::sipral_stack_recording_stop::ABI,
        crate::audio::sipral_audio_refresh::ABI,
        crate::audio::sipral_audio_device_count::ABI,
        crate::audio::sipral_audio_device_at::ABI,
        crate::audio::sipral_audio_select::ABI,
        crate::audio::sipral_audio_selection::ABI,
        crate::audio::sipral_audio_set_gain::ABI,
        crate::audio::sipral_audio_gain::ABI,
        crate::audio::sipral_audio_set_muted::ABI,
        crate::audio::sipral_audio_muted::ABI,
        crate::audio::sipral_audio_level::ABI,
        crate::audio::sipral_audio_activate::ABI,
        crate::audio::sipral_audio_deactivate::ABI,
        crate::audio::sipral_audio_ring::ABI,
        crate::audio::sipral_audio_stop_ringing::ABI,
        crate::audio::sipral_audio_info::ABI,
        crate::log::sipral_stack_log::ABI,
        crate::log::sipral_stack_state::ABI,
        crate::ports::sipral_stack_rtp_port_reserve::ABI,
        crate::ports::sipral_stack_rtp_port_release::ABI,
    ],
};

#[cfg(test)]
mod tests {
    use super::{SURFACE, Shape, Stands, snake};
    use std::collections::HashSet;

    /// Every name a type can be referred to by, so that a member whose type is
    /// not in the surface is a test failure rather than a header that mentions
    /// a struct it never defined.
    fn declared() -> HashSet<&'static str> {
        let mut names = HashSet::new();
        for alias in SURFACE.aliases {
            names.insert(alias.name);
        }
        for enumeration in SURFACE.enumerations {
            names.insert(enumeration.name);
        }
        for record in SURFACE.records {
            names.insert(record.name);
        }
        names
    }

    /// What a type expression names, with the pointers peeled off.
    fn named(rust_type: &str) -> &str {
        rust_type
            .trim_start_matches("*const ")
            .trim_start_matches("*mut ")
            .trim()
    }

    #[test]
    fn every_type_a_member_names_is_in_the_surface() {
        let names = declared();
        let members = SURFACE
            .records
            .iter()
            .flat_map(|record| record.fields.iter().map(|field| (record.name, field)));
        for (owner, member) in members {
            let referenced = named(member.rust_type);
            if !referenced.starts_with("Sipral") {
                continue;
            }
            assert!(
                names.contains(referenced),
                "{owner}::{} names {referenced}, which the surface does not declare",
                member.name
            );
        }
    }

    #[test]
    fn every_type_a_parameter_names_is_in_the_surface() {
        let names = declared();
        let parameters = SURFACE
            .functions
            .iter()
            .flat_map(|function| function.parameters.iter().map(|p| (function.name, p)));
        for (owner, parameter) in parameters {
            let referenced = named(parameter.rust_type);
            if !referenced.starts_with("Sipral") {
                continue;
            }
            assert!(
                names.contains(referenced),
                "{owner} takes a {referenced}, which the surface does not declare"
            );
        }
    }

    #[test]
    fn a_record_is_defined_before_anything_that_holds_one() {
        let mut seen: HashSet<&str> = HashSet::new();
        for record in SURFACE.records {
            for member in record.fields {
                let referenced = named(member.rust_type);
                if !referenced.starts_with("Sipral") || member.rust_type.starts_with('*') {
                    continue;
                }
                if SURFACE.records.iter().any(|other| other.name == referenced) {
                    assert!(
                        seen.contains(referenced),
                        "{} holds a {referenced} by value and is listed before it",
                        record.name
                    );
                }
            }
            seen.insert(record.name);
        }
    }

    #[test]
    fn no_two_items_share_a_name() {
        let mut seen = HashSet::new();
        let names = SURFACE
            .aliases
            .iter()
            .map(|alias| alias.name)
            .chain(SURFACE.enumerations.iter().map(|e| e.name))
            .chain(SURFACE.records.iter().map(|r| r.name))
            .chain(SURFACE.functions.iter().map(|f| f.name))
            .chain(
                SURFACE
                    .constants
                    .iter()
                    .flat_map(|group| group.iter().map(|value| value.name)),
            );
        for name in names {
            assert!(seen.insert(name), "{name} is declared twice");
        }
    }

    /// The rule the generator prints four files with and the library answers
    /// `sipral_abi_struct_size` with. The cases are written out rather than derived,
    /// because a test that derived them would move with the rule.
    #[test]
    fn a_rust_name_becomes_the_name_c_spells() {
        assert_eq!(snake("SipralStackConfig"), "sipral_stack_config");
        assert_eq!(snake("SipralAbiVersion"), "sipral_abi_version");
        assert_eq!(snake("SipralRtcp"), "sipral_rtcp");
        assert_eq!(snake("bind_address_len"), "bind_address_len");
    }

    /// The size is the compiler's answer, carried so that the one entry point
    /// that reports it does not have to name every type.
    #[test]
    fn every_record_carries_the_length_it_was_compiled_to() {
        for record in SURFACE.records {
            assert!(record.size > 0, "{} is nothing at all", record.name);
            assert!(
                record.c_name().starts_with("sipral_") && record.c_name().ends_with("_t"),
                "{} is not a name C would spell",
                record.name
            );
            if record.is_versioned() {
                assert!(
                    record.size >= size_of::<usize>(),
                    "{} is shorter than the size member it starts with",
                    record.name
                );
            }
        }
    }

    #[test]
    fn every_entry_point_is_named_for_the_library() {
        for function in SURFACE.functions {
            assert!(
                function.name.starts_with("sipral_"),
                "{} is exported without the library's prefix",
                function.name
            );
        }
    }

    /// The size member is what makes appending to a released struct safe, so
    /// every struct a caller fills in or reads back has to have one. The ones
    /// that do not are the event payload arms, which live inside an event that
    /// carries the size for all of them, and the element of an array whose
    /// length travels beside it, which an appended member would re-stride and
    /// which therefore never grows.
    #[test]
    fn every_record_a_caller_hands_over_carries_its_own_size() {
        let inside_an_event = [
            "SipralRegistrationEvent",
            "SipralCallEvent",
            "SipralTransferEvent",
            "SipralMediaEvent",
            "SipralRecoveryEvent",
            "SipralTransportWantedEvent",
            "SipralSubscriptionEvent",
            "SipralAnnounceEvent",
            "SipralResolveEvent",
            "SipralMessageEvent",
            "SipralNatEvent",
            "SipralNatRelayEvent",
            "SipralReferralEvent",
            "SipralTurnStreamEvent",
            "SipralAudioEvent",
            "SipralStunServerEvent",
            "SipralConferenceEvent",
            "SipralTextEvent",
            "SipralPresenceEvent",
            "SipralEventPayload",
        ];
        let array_elements = ["SipralHeader"];
        for record in SURFACE.records {
            if inside_an_event.contains(&record.name) || array_elements.contains(&record.name) {
                assert!(!record.is_versioned(), "{} grew a size", record.name);
                continue;
            }
            assert!(
                record.is_versioned(),
                "{} crosses the boundary without a size member",
                record.name
            );
        }
    }

    #[test]
    fn the_event_payload_is_the_one_union() {
        let unions: Vec<&str> = SURFACE
            .records
            .iter()
            .filter(|record| record.shape == Shape::Union)
            .map(|record| record.name)
            .collect();
        assert_eq!(unions, ["SipralEventPayload"]);
    }

    #[test]
    fn the_callbacks_are_the_aliases_that_are_not_integers() {
        let callbacks: Vec<&str> = SURFACE
            .aliases
            .iter()
            .filter(|alias| matches!(alias.stands, Stands::Callback(_, _)))
            .map(|alias| alias.name)
            .collect();
        assert_eq!(
            callbacks,
            [
                "SipralEventCallback",
                "SipralScreenCallback",
                "SipralProcessorCallback",
                "SipralAudioTransmitCallback",
                "SipralLogCallback",
            ]
        );
    }
}
