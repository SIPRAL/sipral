// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The ABI, described by the declarations that are the ABI.
//!
//! The header and bindings are printed from this module by `tools/abi-gen`;
//! `scripts/check.sh` reprints them and fails if the committed copies differ.
//!
//! Each macro here emits the Rust item as written plus a `const` describing
//! it (name, members, types, docs), taken from the declaration's tokens. No
//! Rust parser is involved and no `cfg` can hide anything.
//!
//! The only hand-written list is [`SURFACE`]. A missing line is caught three
//! ways: the unread descriptor is dead code under `-D warnings`;
//! `scripts/check.sh` names the difference; and the generator refuses a type
//! reachable from the surface but not listed in it.
//!
//! Costs and gaps of this scheme: `docs/08-ffi.md`.

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
    /// Its members, in declaration order (memory order for a struct).
    pub fields: &'static [Member],
    /// Size in bytes on this build, padding included. Not portable across
    /// targets; it is what a C caller checks its `sizeof` against.
    pub size: usize,
}

impl Record {
    /// Whether the first member is the `size` that makes appending safe. The
    /// bindings fill it in for the caller.
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

/// Whether a struct starting with `size` ends exactly at its last member,
/// with no trailing padding on this target. Structs without `size` never grow.
///
/// Trailing padding is where an appended member would land on some targets:
/// an older caller declares the padded length and the library would read its
/// garbage as a set value. `ends` holds each member's end offset.
#[must_use]
pub const fn ends_with_its_last_member(names: &[&str], ends: &[usize], size: usize) -> bool {
    let [first, ..] = names else {
        return true;
    };
    if !same_text(first, "size") {
        return true;
    }
    let mut last = 0;
    let mut rest = ends;
    while let [end, after @ ..] = rest {
        if *end > last {
            last = *end;
        }
        rest = after;
    }
    last == size
}

/// `str` equality that a `const fn` can call.
const fn same_text(left: &str, right: &str) -> bool {
    let (mut left, mut right) = (left.as_bytes(), right.as_bytes());
    loop {
        match (left, right) {
            ([], []) => return true,
            ([one, left_rest @ ..], [other, right_rest @ ..]) if *one == *other => {
                left = left_rest;
                right = right_rest;
            }
            _ => return false,
        }
    }
}

/// Rust name to C name: `SipralStackConfig` becomes `sipral_stack_config`.
///
/// Here, not in the generator, because the library also answers about C
/// names ([`crate::version::sipral_abi_struct_size`]).
///
/// A capital starts a word after a lower-case letter or digit, and after a
/// capital when a lower-case letter follows: `NotAFocus` is `not_a_focus`.
#[must_use]
pub fn snake(name: &str) -> String {
    let mut out = String::new();
    let mut previous_lower = false;
    let mut previous_upper = false;
    let mut letters = name.chars().peekable();
    while let Some(letter) = letters.next() {
        if letter.is_ascii_uppercase() {
            let next_lower = letters.peek().is_some_and(char::is_ascii_lowercase);
            if previous_lower || (previous_upper && next_lower) {
                out.push('_');
            }
            out.push(letter.to_ascii_lowercase());
            previous_lower = false;
            previous_upper = true;
        } else {
            out.push(letter);
            previous_lower = letter.is_ascii_lowercase() || letter.is_ascii_digit();
            previous_upper = false;
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

/// A number reserved for a future feature, so two features cannot take it.
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
    /// Its value, read from the declaration itself.
    pub value: u64,
}

/// What an alias stands for.
#[derive(Clone, Copy, Debug)]
pub enum Stands {
    /// Another name for a plain integer.
    For(&'static str),
    /// A function the caller supplies and the library calls: its arguments,
    /// and a plain integer answer or nothing. A listener that throws reads as
    /// nothing.
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
/// The generator reads only this. Lists are in header order, the order the
/// crate documentation introduces the modules.
#[derive(Clone, Copy, Debug)]
pub struct Surface {
    /// The version this ABI reports, as three numbers.
    pub version: (u32, u32, u32),
    /// Names for plain integers, and the event callback.
    pub aliases: &'static [Alias],
    /// Enumerations, before the records that hold their numbers.
    pub enumerations: &'static [Enumeration],
    /// Structs and unions, each defined before use.
    pub records: &'static [Record],
    /// Published constants, grouped as the modules declare them.
    pub constants: &'static [&'static [Value]],
    /// Entry points, in the order the header should list them.
    pub functions: &'static [Function],
}

/// An enumeration `codes!` declared, and the integer its numbers cross as.
pub trait Enumerated {
    /// The integer the `repr` fixes it to.
    type Raw;
}

/// A parameter or a member that holds one of `E`'s numbers.
///
/// Only `E`'s integer, checked where used: building a Rust enum from an
/// unknown number would be undefined behaviour. The alias gives the header
/// the enum's `typedef` (`sipral_codec_t codec`, not `uint32_t codec`), so
/// callers and generated bindings know which numbers belong there.
pub type Number<E> = <E as Enumerated>::Raw;

/// Declare a `#[repr(C)]` struct or union that crosses the boundary.
///
/// Emits the declaration as written plus a [`Record`] describing it. The
/// macro adds `#[repr(C)]` itself: `scripts/check.sh` refuses a top-level
/// `repr` here, so no crossing type escapes this macro.
macro_rules! record {
    // Doc lines are peeled off one at a time first: two attribute repetitions
    // side by side are ambiguous to the macro parser.
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

        // checked per target: no padding on a Mac can still be padding on
        // 32-bit ARM
        const _: () = assert!(
            $crate::abi::ends_with_its_last_member(
                &[$(stringify!($member)),*],
                &[$(
                    ::std::mem::offset_of!($name, $member)
                        + ::std::mem::size_of::<$member_type>()
                ),*],
                ::std::mem::size_of::<$name>(),
            ),
            concat!(
                stringify!($name),
                " carries a size and ends in padding on this target, so the next member \
                 appended to it would start inside a length callers already declare; give it \
                 a `reserved: u32` or move a member (docs/08-ffi.md, \"Versioning\")"
            )
        );
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
/// The width is explicit because a C compiler picks its own. Docs are peeled
/// off as in [`record`].
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

        impl $crate::abi::Enumerated for $name {
            type Raw = $width;
        }
    };
    ($($declaration:tt)*) => {
        $crate::abi::codes! { @doc [] $($declaration)* }
    };
}

/// Declare the constants one module publishes.
///
/// The descriptor holds the constant itself, so a changed expression prints
/// its new value.
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
/// Callback arms come first (a function type is also a type), and the
/// answering arm before the reporting one (longer pattern first).
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

/// One [`MIN_SIZES`] line, read off the [`Record`] and the `Versioned` impl.
macro_rules! pinned {
    ($($record:path),* $(,)?) => {
        &[$((
            <$record>::ABI.name,
            <$record as $crate::versioned::Versioned>::PIN.member,
            <$record as $crate::versioned::Versioned>::MIN_SIZE,
        )),*]
    };
}

/// Every versioned struct a caller declares to us, the last member of its
/// oldest frozen version, and where that member ends on this target. Used by
/// the generator and by the completeness test. Keyed by Rust name to match
/// [`SURFACE`].
pub const MIN_SIZES: &[(&str, &str, usize)] = pinned![
    crate::version::SipralAbiVersion,
    crate::audio::SipralAudioDevice,
    crate::audio::SipralAudioInfo,
    crate::account::SipralAccountConfig,
    crate::call::SipralCallConfig,
    crate::capabilities::SipralCapabilities,
    crate::media::SipralCodecCandidate,
    crate::media::SipralCodecInfo,
    crate::counters::SipralCounters,
    crate::media::SipralMediaInfo,
    crate::media::SipralMediaPacket,
    crate::media::SipralPathCandidate,
    crate::stack::SipralPollResult,
    crate::stack::SipralStackConfig,
    crate::stack::SipralStackSettings,
    crate::media::SipralStreamStats,
    crate::subscription::SipralSubscribeConfig,
    crate::subscription::SipralWatchedDialog,
    crate::announce::SipralPushEcho,
    crate::security::SipralStirConfig,
    crate::security::SipralStreamEncryption,
    crate::inband::SipralProgressConfig,
    crate::inband::SipralConsentTone,
    crate::record::SipralRecordingOptions,
    crate::transport::SipralTransmit,
    crate::transport::SipralTransportFailure,
    crate::lifecycle::SipralSuspending,
    crate::conference::SipralConference,
    crate::conference::SipralConferenceUser,
    crate::presence::SipralPresence,
    crate::siprec::SipralRecordConfig,
    crate::local_conference::SipralLocalConferenceConfig,
    crate::local_conference::SipralLocalConferenceInfo,
    crate::local_conference::SipralLocalConferenceMember,
    crate::pin::SipralPinnedCertificate,
    crate::network_test::SipralNetworkTestConfig,
];

/// The versioned-shaped structs with no pinned length, and why.
///
/// `sipral_event_t` and `sipral_screen_request_t` have a `size` but are filled
/// by the library and passed to callbacks as `const`; no caller declares one,
/// so there is no length to pin. Named here so a new unpinned struct stands out.
pub const FILLED_BY_US: &[&str] = &[
    "SipralEvent",
    "SipralScreenRequest",
    "SipralProcessorFrame",
    "SipralAudioTransmit",
    "SipralLogRecord",
];

/// Everything this ABI publishes, and the only list a person maintains.
///
/// An item without its line leaves an unread descriptor: a dead-code warning,
/// so a failed build. `scripts/check.sh` reports it too.
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
        crate::transport::SipralTlsFailure::ABI,
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
        crate::security::SipralKeyExchange::ABI,
        crate::security::SipralMediaKind::ABI,
        crate::security::SipralStirVerification::ABI,
        crate::security::SipralAttestation::ABI,
        crate::security::SipralVerificationOutcome::ABI,
        crate::security::SipralVerificationFailure::ABI,
        crate::security::SipralVerificationStage::ABI,
        crate::event::SipralProgressKind::ABI,
        crate::event::SipralProgressTone::ABI,
        crate::event::SipralAmdVerdict::ABI,
        crate::event::SipralAmdReason::ABI,
        crate::inband::SipralDtmfDetection::ABI,
        crate::inband::SipralToneRegion::ABI,
        crate::record::SipralRecordingFormat::ABI,
        crate::record::SipralRecordingLayout::ABI,
        crate::conference::SipralConferenceUpdate::ABI,
        crate::conference::SipralEndpointStatus::ABI,
        crate::conference::SipralConferenceText::ABI,
        crate::presence::SipralPresenceKind::ABI,
        crate::presence::SipralBasic::ABI,
        crate::presence::SipralActivity::ABI,
        crate::presence::SipralPublicationState::ABI,
        crate::presence::SipralPublishFailure::ABI,
        crate::local_conference::SipralLocalConferenceChange::ABI,
        crate::local_conference::SipralDeparture::ABI,
        crate::locate::SipralDnsRecordType::ABI,
        crate::locate::SipralDnsAnswer::ABI,
        crate::locate::SipralLocateFailure::ABI,
        crate::event::SipralChallengeRefusal::ABI,
        crate::event::SipralTokenError::ABI,
        crate::network_test::SipralNetworkVerdict::ABI,
        crate::network_test::SipralNetworkProbe::ABI,
        crate::network_test::SipralNatKind::ABI,
        crate::network_test::SipralServerReach::ABI,
        crate::stack::SipralHeldAudio::ABI,
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
        crate::transport::SipralTransportFailure::ABI,
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
        crate::event::SipralVerificationEvent::ABI,
        crate::event::SipralProgressEvent::ABI,
        crate::conference::SipralConferenceEvent::ABI,
        crate::realtime_text::SipralTextEvent::ABI,
        crate::presence::SipralPresenceEvent::ABI,
        crate::transport::SipralTransportFailedEvent::ABI,
        crate::local_conference::SipralLocalConferenceEvent::ABI,
        crate::locate::SipralLocateEvent::ABI,
        crate::event::SipralChallengeEvent::ABI,
        crate::event::SipralTokenEvent::ABI,
        crate::network_test::SipralNetworkTestEvent::ABI,
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
        crate::security::SipralStirConfig::ABI,
        crate::security::SipralStreamEncryption::ABI,
        crate::inband::SipralProgressConfig::ABI,
        crate::inband::SipralConsentTone::ABI,
        crate::record::SipralRecordingOptions::ABI,
        crate::conference::SipralConference::ABI,
        crate::conference::SipralConferenceUser::ABI,
        crate::presence::SipralPresence::ABI,
        crate::siprec::SipralRecordConfig::ABI,
        crate::local_conference::SipralLocalConferenceConfig::ABI,
        crate::local_conference::SipralLocalConferenceInfo::ABI,
        crate::local_conference::SipralLocalConferenceMember::ABI,
        crate::pin::SipralPinnedCertificate::ABI,
        crate::network_test::SipralNetworkTestConfig::ABI,
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
        crate::account::sipral_account_set_access_token::ABI,
        crate::network_test::sipral_stack_network_test::ABI,
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
        crate::call::sipral_call_accept_transfer_placed::ABI,
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
        crate::media::sipral_media_set_app_rate::ABI,
        crate::media::sipral_media_attach_processor::ABI,
        crate::media::sipral_media_detach_processor::ABI,
        crate::media::sipral_media_reset_processor::ABI,
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
        crate::transport::sipral_stack_transport_failed_with::ABI,
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
        crate::audio::sipral_audio_set_system_echo_cancellation::ABI,
        crate::log::sipral_stack_log::ABI,
        crate::log::sipral_stack_state_text::ABI,
        crate::ports::sipral_stack_rtp_port_reserve::ABI,
        crate::ports::sipral_stack_rtp_port_release::ABI,
        crate::security::sipral_stack_stir::ABI,
        crate::security::sipral_call_stir_certificate::ABI,
        crate::security::sipral_media_encryption_count::ABI,
        crate::security::sipral_media_encryption_at::ABI,
        crate::inband::sipral_call_dtmf_detection::ABI,
        crate::inband::sipral_call_detect_progress::ABI,
        crate::inband::sipral_call_consent_tone::ABI,
        crate::record::sipral_media_record_start_with::ABI,
        crate::local_conference::sipral_local_conference_create::ABI,
        crate::local_conference::sipral_local_conference_destroy::ABI,
        crate::local_conference::sipral_local_conference_add::ABI,
        crate::local_conference::sipral_local_conference_remove::ABI,
        crate::local_conference::sipral_local_conference_set_muted::ABI,
        crate::local_conference::sipral_local_conference_set_gain::ABI,
        crate::local_conference::sipral_local_conference_info::ABI,
        crate::local_conference::sipral_local_conference_member_at::ABI,
        crate::local_conference::sipral_local_conference_talker_at::ABI,
        crate::local_conference::sipral_local_conference_tick::ABI,
        crate::local_conference::sipral_local_conference_poll_transmit::ABI,
        crate::local_conference::sipral_local_conference_record_start::ABI,
        crate::local_conference::sipral_local_conference_record_stop::ABI,
        crate::locate::sipral_account_looked_up::ABI,
        crate::pin::sipral_account_check_certificate::ABI,
        crate::advertise::sipral_advertised_address::ABI,
        crate::log::sipral_stack_diagnostic_trace::ABI,
        crate::stack::sipral_stack_srtp_suite_order::ABI,
        crate::audio::sipral_audio_call_set_gain::ABI,
        crate::audio::sipral_audio_call_gain::ABI,
        crate::audio::sipral_audio_call_set_muted::ABI,
        crate::audio::sipral_audio_call_muted::ABI,
        crate::audio::sipral_audio_call_level::ABI,
    ],
};

#[cfg(test)]
mod tests {
    use super::{SURFACE, Shape, Stands, snake};
    use std::collections::HashSet;

    /// Every name a type can be referred to by, so a member of an unlisted
    /// type fails here rather than in the header.
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

    /// Whether `doc` names `name` as a whole word, not a prefix or a path.
    fn names_the_type(doc: &str, name: &str) -> bool {
        doc.match_indices(name).any(|(at, _)| {
            let before = doc[..at].chars().next_back();
            let after = &doc[at + name.len()..];
            before.is_none_or(|c| !c.is_ascii_alphanumeric() && c != '_')
                && after
                    .chars()
                    .next()
                    .is_none_or(|c| !c.is_ascii_alphanumeric() && c != '_' && c != ':')
        })
    }

    /// A `u32` member whose docs name an enumeration is declared as its
    /// [`Number`](super::Number), so the header uses the `typedef`.
    #[test]
    fn a_member_documented_as_an_enumeration_is_declared_as_one() {
        let enumerations: Vec<_> = SURFACE
            .enumerations
            .iter()
            .filter(|enumeration| enumeration.width == "u32")
            .collect();
        for record in SURFACE.records {
            for member in record
                .fields
                .iter()
                .filter(|member| member.rust_type == "u32")
            {
                let doc = member.doc.join(" ");
                for enumeration in &enumerations {
                    let c_name = format!("{}_t", snake(enumeration.name));
                    assert!(
                        !names_the_type(&doc, enumeration.name) && !names_the_type(&doc, &c_name),
                        "{}::{} is documented as a {} and declared as a plain u32; declare it as \
                         Number<{}>",
                        record.name,
                        member.name,
                        enumeration.name,
                        enumeration.name
                    );
                }
            }
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

    /// The naming rule used by the generator and `sipral_abi_struct_size`.
    /// Cases written out so the test does not move with the rule.
    #[test]
    fn a_rust_name_becomes_the_name_c_spells() {
        assert_eq!(snake("SipralStackConfig"), "sipral_stack_config");
        assert_eq!(snake("SipralAbiVersion"), "sipral_abi_version");
        assert_eq!(snake("SipralRtcp"), "sipral_rtcp");
        assert_eq!(snake("bind_address_len"), "bind_address_len");
        assert_eq!(snake("NotAFocus"), "not_a_focus");
        assert_eq!(snake("G729AnnexB"), "g729_annex_b");
    }

    /// The compiler's size, carried so the entry point need not name each type.
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

    /// Every struct a caller fills or reads needs a `size`. Exceptions: event
    /// payload arms (the event carries the size) and array elements (their
    /// length travels beside them, and they never grow).
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
            "SipralVerificationEvent",
            "SipralProgressEvent",
            "SipralConferenceEvent",
            "SipralTextEvent",
            "SipralPresenceEvent",
            "SipralTransportFailedEvent",
            "SipralLocalConferenceEvent",
            "SipralLocateEvent",
            "SipralChallengeEvent",
            "SipralTokenEvent",
            "SipralNetworkTestEvent",
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
