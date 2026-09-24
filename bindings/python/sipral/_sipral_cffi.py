# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Tiberiu Balasea
#
# Printed from the declarations in crates/sipral-ffi by tools/abi-gen. Do
# not edit: `cargo run -p sipral-abi-gen` writes it again, and
# `scripts/check.sh` fails when what is committed is not what came out.
#
# The raw cffi surface over the C ABI, built in cffi's ABI mode so that
# installing this package needs no C compiler: one `cdef` naming the same
# types, constants and entry points `bindings/c/include/sipral.h` does,
# and the `dlopen` that turns it into `lib`. Every name below is spelled
# exactly as the header spells it, so `docs/08-ffi.md` reads for this
# module too.
#
# Nothing here is idiomatic. `sipral.stack`, `sipral.account` and
# `sipral.call` are written against `lib` and `ffi` by hand, the way
# `SipralAbi.swift` is the base the Swift package is written against; an
# application reaches for those rather than this module.
"""The raw cffi surface: `ffi` and `lib`, generated from crates/sipral-ffi.

See sipral.stack, sipral.account and sipral.call for the layer applications
are meant to use.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from cffi import FFI

CDEF = r"""
/**
 * An opaque reference to something this library owns.
 *
 * It is a number, not a pointer: nothing is to be read from it, and
 * nothing but this library can make one. Zero is never a live handle,
 * which is what a caller can zero a variable to.
 *
 * An account or a call handle names something only on the stack that
 * minted it. Used with any other stack — one alive beside it, or one
 * created after it was destroyed — it is `SIPRAL_STATUS_INVALID_HANDLE`.
 */
typedef uint64_t sipral_handle_t;

/**
 * The value no live handle ever takes.
 */
#define SIPRAL_HANDLE_NONE 0

/**
 * The ABI's major version. Nothing published against one major works
 * against another.
 */
#define SIPRAL_ABI_VERSION_MAJOR 0

/**
 * The ABI's minor version, raised by anything the header gains —
 * everything the generator prints, and not only a function or a struct
 * member. `sipral_abi_check` compares the major and this one; the patch it
 * does not ask about. The
 * rule for all three numbers is the Versioning section of
 * `docs/08-ffi.md`, which is where the ABI contract is written down.
 */
#define SIPRAL_ABI_VERSION_MINOR 25

/**
 * The ABI's patch version, raised by a fix that changes no declaration.
 */
#define SIPRAL_ABI_VERSION_PATCH 0

/**
 * Bits of sipral_capabilities_t::transports. A caller checks
 * `capabilities.transports & SIPRAL_TRANSPORT_BIT_TLS != 0` rather than a
 * growing list of booleans, so a transport this ABI has not learned a bit
 * for yet reads as absent rather than refusing to compile against an
 * older header.
 *
 * Named after sipral_transport_t's own numbers (`1 << (value - 1)`), so
 * a transport added there in the future gets a bit here without the two
 * numbering schemes ever being asked to agree by hand.
 */
#define SIPRAL_TRANSPORT_BIT_UDP 1

/**
 * See SIPRAL_TRANSPORT_BIT_UDP.
 */
#define SIPRAL_TRANSPORT_BIT_TCP 2

/**
 * See SIPRAL_TRANSPORT_BIT_UDP.
 */
#define SIPRAL_TRANSPORT_BIT_TLS 4

/**
 * See SIPRAL_TRANSPORT_BIT_UDP.
 */
#define SIPRAL_TRANSPORT_BIT_WS 8

/**
 * See SIPRAL_TRANSPORT_BIT_UDP.
 */
#define SIPRAL_TRANSPORT_BIT_WSS 16

/**
 * Bits of sipral_capabilities_t::features.
 */
#define SIPRAL_FEATURE_DTMF 1

/**
 * See SIPRAL_FEATURE_DTMF.
 */
#define SIPRAL_FEATURE_RTCP_MUX 2

/**
 * See SIPRAL_FEATURE_DTMF.
 */
#define SIPRAL_FEATURE_RECORDING 4

/**
 * See SIPRAL_FEATURE_DTMF.
 */
#define SIPRAL_FEATURE_MEDIA_STALL_WATCHDOG 8

/**
 * See SIPRAL_FEATURE_DTMF.
 */
#define SIPRAL_FEATURE_SRTP 16

/**
 * See SIPRAL_FEATURE_DTMF. RFC 6665 subscriptions and the
 * dialog-state package a busy lamp field is built on, reached with
 * sipral_account_subscribe.
 */
#define SIPRAL_FEATURE_SUBSCRIPTIONS 32

/**
 * See SIPRAL_FEATURE_DTMF. Opus is behind a compile-time feature,
 * because libopus is the one part of the audio path that is licensed
 * rather than written, so a build meant for hardware can leave it out.
 * The bit is how an application finds out without having to enumerate
 * the codecs, and it is set from the catalogue this build offers rather
 * than from any crate's feature flag; `SIPRAL_CODEC_OPUS` keeps its
 * number either way, since a value that has left this header is spent
 * for good.
 */
#define SIPRAL_FEATURE_OPUS 64

/**
 * DTLS-SRTP (RFC 5764): the keys for a call's media come from a
 * handshake on the media path rather than from the body of a message.
 *
 * Behind a compile-time feature for the reason Opus is: a build that
 * will only ever place SDES calls over a protected SIP transport has no
 * use for an elliptic curve, and a desk phone counts its flash. Both
 * `SIPRAL_SRTP_DTLS` and `SIPRAL_SRTP_DTLS_REQUIRED` keep their numbers
 * in a build without it — a value that has left this header is spent —
 * and naming one there answers `SIPRAL_STATUS_NOT_SUPPORTED` rather than
 * quietly placing an unencrypted call.
 *
 * An application that sets one of those policies must also drain
 * `sipral_media_poll_transmit`; see there.
 */
#define SIPRAL_FEATURE_DTLS_SRTP 128

/**
 * See SIPRAL_FEATURE_DTMF. ICE in the full role (RFC 8445), with
 * consent freshness (RFC 7675) and the SDP attributes of RFC 8839: a
 * call's media path is chosen by checking it rather than taken from what
 * the signalling said.
 *
 * Behind a compile-time feature for the reason DTLS-SRTP is, and off by
 * policy even where it is compiled in — `docs/06-nat.md` tabulates what
 * it costs on the wire and why it buys nothing against a PBX that learns
 * the caller's address from the media it receives. Both `SIPRAL_ICE_OFFERED`
 * and `SIPRAL_ICE_REQUIRED` keep their numbers in a build without it, and
 * naming one there answers `SIPRAL_STATUS_NOT_SUPPORTED`.
 *
 * An application that sets one of those policies must also drain
 * `sipral_media_poll_transmit`; see there.
 */
#define SIPRAL_FEATURE_ICE 256

/**
 * See SIPRAL_FEATURE_DTMF. STUN (RFC 8489): a stack created with
 * `SIPRAL_NAT_STUN` asks a server where its sockets appear from and
 * writes the answer in the `Contact` and in `c=` and `m=`.
 *
 * Behind a compile-time feature of its own, which brings nothing ICE
 * does not already bring. `SIPRAL_NAT_STUN` keeps its number in a build
 * without it, and naming it there answers `SIPRAL_STATUS_NOT_SUPPORTED`.
 */
#define SIPRAL_FEATURE_STUN 512

/**
 * The buffer a caller has to bring for one outgoing packet.
 *
 * Not a path MTU — RTP does not discover one — but the bound the session
 * itself builds against, so a payload larger than this is a payload no
 * codec in this build produces. It is checked before anything is encoded,
 * because a frame that was encoded and then had nowhere to go is a frame
 * lost from a stream whose timestamps have already moved past it.
 */
#define SIPRAL_MEDIA_PACKET_BYTES 1500

/**
 * The bound a datagram of control gets instead, on the way in.
 *
 * RTCP is compound: one report packet carries a sender or receiver report
 * for every source being heard, then the source description, then whatever
 * extended reports the session agreed on. A call between two ends stays
 * far inside the media bound, but nothing in RFC 3550 says it has to, and
 * what arrives is the peer's arithmetic rather than ours. So the media
 * bound stops being the reason a report is refused: an arriving datagram
 * that RFC 5761 §4 says is control gets this one, and everything else
 * still gets SIPRAL_MEDIA_PACKET_BYTES. It bounds the read, so it is
 * still a bound: a caller that says a megabyte is still refused.
 *
 * Sending is unchanged — what this stack builds is its own arithmetic, and
 * it fits in the media bound.
 */
#define SIPRAL_MEDIA_RTCP_BYTES 8192

/**
 * Room enough for any address this ABI writes, the NUL included:
 * `[2001:db8:0000:0000:0000:0000:0000:0001]:65535` and a byte to spare.
 */
#define SIPRAL_ADDRESS_BYTES 64

/**
 * The transport a stack is created with.
 *
 * Never retired: sipral_stack_transport_failed and
 * sipral_stack_stream_closed can still stop it carrying traffic, and
 * sipral_stack_transport_bind is still what brings it back, exactly
 * as when this was the only number a stack had. Zero on
 * `sipral_account_config_t::transport` and `sipral_call_config_t::transport`
 * means this one, so a caller that never binds a second transport fills
 * neither in and gets exactly what it always got.
 */
#define SIPRAL_TRANSPORT_MAIN 0

/**
 * The largest message that crosses in either direction.
 *
 * The bound the layer below parses to, which is what stops a hostile peer
 * from making the parser do unbounded work. A caller's read buffer wants
 * to be this big on a stream, where one read can hold the end of one
 * message and the start of another, and 1500 bytes or so on a datagram
 * socket, where anything larger was fragmented on the way.
 */
#define SIPRAL_MESSAGE_BYTES 65535

/**
 * The answer that lets an INVITE through, and the reason it is a status
 * code rather than a flag.
 *
 * A policy answers with what it wants said: 200 to let the call arrive,
 * or the status to refuse it with. Making acceptance 200 rather than
 * zero is the whole safety property of this mechanism — zero is what a
 * binding hands back when the application's listener threw, and what a
 * caller who filled nothing in leaves behind, and neither of those may
 * mean "let the stranger in".
 */
#define SIPRAL_SCREEN_ACCEPT 200

/* Every record, named before any of them is defined, so that a
 * declaration never has to come before the one it mentions. */
typedef struct sipral_abi_version sipral_abi_version_t;
typedef struct sipral_capabilities sipral_capabilities_t;
typedef struct sipral_counters sipral_counters_t;
typedef struct sipral_stack_config sipral_stack_config_t;
typedef struct sipral_poll_result sipral_poll_result_t;
typedef struct sipral_stack_settings sipral_stack_settings_t;
typedef struct sipral_header sipral_header_t;
typedef struct sipral_account_config sipral_account_config_t;
typedef struct sipral_call_config sipral_call_config_t;
typedef struct sipral_codec_info sipral_codec_info_t;
typedef struct sipral_codec_candidate sipral_codec_candidate_t;
typedef struct sipral_media_info sipral_media_info_t;
typedef struct sipral_stream_stats sipral_stream_stats_t;
typedef struct sipral_media_packet sipral_media_packet_t;
typedef struct sipral_processor_frame sipral_processor_frame_t;
typedef struct sipral_transmit sipral_transmit_t;
typedef struct sipral_registration_event sipral_registration_event_t;
typedef struct sipral_call_event sipral_call_event_t;
typedef struct sipral_transfer_event sipral_transfer_event_t;
typedef struct sipral_media_event sipral_media_event_t;
typedef struct sipral_recovery_event sipral_recovery_event_t;
typedef struct sipral_transport_wanted_event sipral_transport_wanted_event_t;
typedef struct sipral_subscription_event sipral_subscription_event_t;
typedef struct sipral_announce_event sipral_announce_event_t;
typedef struct sipral_resolve_event sipral_resolve_event_t;
typedef struct sipral_message_event sipral_message_event_t;
typedef struct sipral_nat_event sipral_nat_event_t;
typedef struct sipral_nat_relay_event sipral_nat_relay_event_t;
typedef union sipral_event_payload sipral_event_payload_t;
typedef struct sipral_event sipral_event_t;
typedef struct sipral_suspending sipral_suspending_t;
typedef struct sipral_screen_request sipral_screen_request_t;
typedef struct sipral_subscribe_config sipral_subscribe_config_t;
typedef struct sipral_watched_dialog sipral_watched_dialog_t;
typedef struct sipral_push_echo sipral_push_echo_t;

/**
 * The result of a call across the C ABI.
 *
 * The numbers are part of the ABI. A value keeps its meaning for the life of
 * the ABI's major version, and a new one is only ever added at the end.
 */
typedef int32_t sipral_status_t;
enum {
    /**
     * The call did what it was asked to.
     */
    SIPRAL_STATUS_OK = 0,
    /**
     * A pointer was null where one is required, a length disagreed with what
     * it describes, or a value was outside what the call accepts.
     */
    SIPRAL_STATUS_INVALID_ARGUMENT = 1,
    /**
     * The handle never came from this library, or it came from a stack
     * other than the one it was used with.
     */
    SIPRAL_STATUS_INVALID_HANDLE = 2,
    /**
     * The handle came from this library and what it named is gone: a use
     * after free, or a second free.
     */
    SIPRAL_STATUS_STALE_HANDLE = 3,
    /**
     * A versioned struct declared a size this build cannot work with, or a
     * binding asked for an ABI this library does not provide.
     */
    SIPRAL_STATUS_UNSUPPORTED_VERSION = 4,
    /**
     * The buffer supplied is too small. The length needed has been written to
     * the out parameter, and nothing was written to the buffer.
     */
    SIPRAL_STATUS_BUFFER_TOO_SMALL = 5,
    /**
     * The object is already in use by another call, including one further
     * down the same call stack. Nothing was done, and nothing blocked.
     */
    SIPRAL_STATUS_BUSY = 6,
    /**
     * The library has no room for another object of this kind.
     */
    SIPRAL_STATUS_EXHAUSTED = 7,
    /**
     * A panic was caught at the boundary. The call did not finish, and the
     * last error carries whatever the panic said.
     */
    SIPRAL_STATUS_PANIC = 8,
    /**
     * What was asked for cannot be done where the object is: answering a call
     * this end placed, holding one that is not up, sending DTMF before there
     * is a dialog to send it in. Not an argument that was wrong; a moment
     * that was.
     */
    SIPRAL_STATUS_WRONG_STATE = 9,
    /**
     * The request could not be assembled or handed to a transport. Nothing
     * went out, and nothing about the call changed.
     */
    SIPRAL_STATUS_NOT_SENT = 10,
    /**
     * The value is one this ABI has a word for and this build has no code
     * behind. Nothing was applied, and asking again will not change that.
     *
     * The third of the three answers a configuration call may give, and the
     * one that has to be told apart from the other two by a machine.
     * SIPRAL_STATUS_INVALID_ARGUMENT says the value is wrong and a
     * corrected one would be taken; this says the value is right and there is
     * nothing here to take it. SIPRAL_STATUS_UNSUPPORTED_VERSION is about
     * the shape of what crossed the boundary, not about what was set in it.
     *
     * It exists so that "accepted and ignored" is not a thing this library
     * can do. An application that gets it turns the control off, because the
     * control is genuinely dead in this build; one that gets a silence
     * instead ships a control that does nothing and finds out from a
     * customer.
     */
    SIPRAL_STATUS_NOT_SUPPORTED = 11,
};

/**
 * What a stack speaks. Names for `sipral_stack_config_t::transport`.
 *
 * Zero is not one of them: a stack is told what it is speaking, because
 * guessing wrong in the direction of the plainest transport is how a caller
 * that meant TLS ends up on the wire in the clear.
 */
typedef uint32_t sipral_transport_t;
enum {
    /**
     * UDP.
     */
    SIPRAL_TRANSPORT_UDP = 1,
    /**
     * TCP.
     */
    SIPRAL_TRANSPORT_TCP = 2,
    /**
     * TLS over TCP.
     */
    SIPRAL_TRANSPORT_TLS = 3,
    /**
     * WebSocket.
     */
    SIPRAL_TRANSPORT_WS = 4,
    /**
     * WebSocket over TLS.
     */
    SIPRAL_TRANSPORT_WSS = 5,
};

/**
 * Why a transport could not deliver. Names for
 * sipral_stack_transport_failed's `error`.
 *
 * Coarse on purpose, and it is the layer below that is coarse: a client
 * transaction informs its user and terminates on every one of these (§17), and
 * the detail belongs in the caller's log, where the real message still is.
 */
typedef uint32_t sipral_transport_error_t;
enum {
    /**
     * Anything the caller could not classify. Zero, because a caller that
     * knows only that the write failed is telling the truth by saying nothing.
     */
    SIPRAL_TRANSPORT_ERROR_OTHER = 0,
    /**
     * Nothing is listening at the far end.
     */
    SIPRAL_TRANSPORT_ERROR_CONNECTION_REFUSED = 1,
    /**
     * An established connection was reset.
     */
    SIPRAL_TRANSPORT_ERROR_CONNECTION_RESET = 2,
    /**
     * No route, or an ICMP unreachable.
     */
    SIPRAL_TRANSPORT_ERROR_UNREACHABLE = 3,
    /**
     * The connection attempt or the write timed out.
     */
    SIPRAL_TRANSPORT_ERROR_TIMED_OUT = 4,
    /**
     * The connection was closed and cannot be written to again.
     */
    SIPRAL_TRANSPORT_ERROR_CLOSED = 5,
};

/**
 * The three answers a setting can give in a struct that starts out zeroed.
 *
 * A boolean cannot carry them. Zero is what a caller who filled nothing in
 * leaves behind, so a plain `0`/`1` setting has no way to say "off" that is
 * not also "I said nothing", and the difference is the whole of B2: the
 * library must not turn a control off because the caller never touched it.
 */
typedef uint32_t sipral_toggle_t;
enum {
    /**
     * Nothing was said; whatever this build defaults to.
     */
    SIPRAL_TOGGLE_DEFAULT = 0,
    /**
     * On.
     */
    SIPRAL_TOGGLE_ON = 1,
    /**
     * Off.
     */
    SIPRAL_TOGGLE_OFF = 2,
};

/**
 * What a call or a stack says about SRTP. Names for
 * `sipral_stack_config_t::srtp` (the stack's default) and
 * `sipral_call_config_t::srtp` (a per-call override).
 *
 * Zero is not one of them, and it is not the same absence on the two
 * structs: on the stack it means this build's own built-in default
 * (`SrtpPolicy::default()`, which is SIPRAL_SRTP_NOT_OFFERED); on a
 * call it means the stack's own setting, whatever that came to. The three
 * values mean exactly what `sipral::SrtpPolicy`'s three variants mean —
 * see there for what each writes and what each answers.
 */
typedef uint32_t sipral_srtp_t;
enum {
    /**
     * SrtpPolicy::NotOffered: do not offer it, but answer an offer
     * that arrives on the secure profile with keys anyway.
     */
    SIPRAL_SRTP_NOT_OFFERED = 1,
    /**
     * SrtpPolicy::Offered: offer it, and answer a plain offer
     * plainly.
     */
    SIPRAL_SRTP_OFFERED = 2,
    /**
     * SrtpPolicy::Required: offer it, and let no stream on this call
     * carry audio unencrypted.
     */
    SIPRAL_SRTP_REQUIRED = 3,
    /**
     * SrtpPolicy::DtlsOffered: offer DTLS-SRTP (RFC 5764) on
     * `UDP/TLS/RTP/SAVP`, and answer a plain offer plainly.
     *
     * What `Offered` is for SDES, with the difference that matters: the
     * key never travels in the body, so this is the one policy here that
     * is sound over a SIP transport somebody else can read. The cost is
     * a round trip of silence at the start of every call while the
     * handshake runs, and an application that names it **must** drain
     * sipral_media_poll_transmit — a handshake whose records never
     * leave is a call that is up, silent, and reports no error.
     *
     * `SIPRAL_STATUS_NOT_SUPPORTED` in a build without
     * `SIPRAL_FEATURE_DTLS_SRTP`.
     */
    SIPRAL_SRTP_DTLS = 4,
    /**
     * SrtpPolicy::DtlsRequired: offer DTLS-SRTP, and let no stream on
     * this call carry audio any other way — an answer carrying
     * `a=crypto` included, since that key travelled in a body this
     * policy exists to avoid trusting.
     */
    SIPRAL_SRTP_DTLS_REQUIRED = 5,
};

/**
 * What a call or a stack says about ICE. Names for
 * `sipral_stack_config_t::ice` (the stack's default) and
 * `sipral_call_config_t::ice` (a per-call override).
 *
 * Zero is not one of them, and it is not the same absence on the two
 * structs: on the stack it means this build's own built-in default
 * (`IcePolicy::default()`, which is SIPRAL_ICE_OFF); on a call it
 * means the stack's own setting, whatever that came to.
 *
 * A call that offers ICE also asks for RFC 5761 multiplexing, whatever
 * `offer_rtcp_mux` says, because an ICE stream with a second component
 * needs a second address and this ABI names one.
 */
typedef uint32_t sipral_ice_t;
enum {
    /**
     * IcePolicy::Off: do not offer it, and do not answer a peer that
     * does. The default, and `docs/06-nat.md` says why at length.
     */
    SIPRAL_ICE_OFF = 1,
    /**
     * IcePolicy::Offered: offer it, and use it against a peer that
     * offers it back.
     *
     * A peer that does not — an Asterisk with `ice_support=no`, which is
     * its default — is answered without it and the call runs on the
     * signalled address and symmetric RTP, exactly as it would have. An
     * application that names this **must** drain
     * sipral_media_poll_transmit: a check that never leaves is a
     * call that never chooses a path.
     *
     * `SIPRAL_STATUS_NOT_SUPPORTED` in a build without
     * `SIPRAL_FEATURE_ICE`.
     */
    SIPRAL_ICE_OFFERED = 2,
    /**
     * IcePolicy::Required: offer it, and let no stream on this call
     * carry audio on a path ICE did not check.
     *
     * Each of the three ways a peer can fail to do ICE ends the call's
     * media with `SIPRAL_EVENT_KIND_MEDIA_FAILED` instead of falling
     * back. That is the whole difference between this and `Offered`.
     */
    SIPRAL_ICE_REQUIRED = 3,
};

/**
 * One codec this ABI has a number for. Names for every member that says
 * which.
 *
 * A value here is permanent, and that is all it is: a number that has left
 * this header is spent for good, so a binding compiled against one keeps
 * working whatever a later build contains. Whether *this* build can produce
 * the codec is a different question, and `SIPRAL_FEATURE_*` together with
 * `sipral_codec_at` are what answer it. A settings screen that offers this
 * list unfiltered is a settings screen with controls that do nothing, which
 * is the mistake `sipral_capabilities` exists to prevent.
 */
typedef uint32_t sipral_codec_t;
enum {
    /**
     * No codec: the call has none, or the event is not about one.
     */
    SIPRAL_CODEC_UNKNOWN = 0,
    /**
     * G.711 mu-law, payload type 0.
     */
    SIPRAL_CODEC_PCMU = 1,
    /**
     * G.711 A-law, payload type 8.
     */
    SIPRAL_CODEC_PCMA = 2,
    /**
     * G.722, wideband at the price of a narrowband stream.
     */
    SIPRAL_CODEC_G722 = 3,
    /**
     * Opus. Declared in every build, whether or not this one linked
     * libopus, for the reason the enumeration above gives. Whether the
     * codec is here is `SIPRAL_FEATURE_OPUS` and the list
     * `sipral_codec_at` enumerates, never the presence of this name.
     */
    SIPRAL_CODEC_OPUS = 4,
    /**
     * G.729 with Annex A, payload type 18: eight kilobits of narrowband
     * speech. In every build and in no default offer: a call offers it
     * only when a codec order names `G729`. It offers `annexb=yes`,
     * answers with the offer's `annexb`, and uses Annex B's silence
     * compression where both descriptions allow it.
     */
    SIPRAL_CODEC_G729 = 5,
};

/**
 * What became of one codec this call's catalogue could have used. Names
 * for sipral_codec_candidate_t::outcome.
 *
 * D5's codec half: a negotiation that ends in G.711 when the site
 * configured Opus is a support call, and the answer to it is a list
 * saying which of the two things happened — the far end never named
 * Opus, or it named it and something ahead of it in this end's order
 * won.
 */
typedef uint32_t sipral_codec_outcome_t;
enum {
    /**
     * Not an outcome: either the candidate is from a build this ABI has
     * no number for, or the struct was never filled in.
     */
    SIPRAL_CODEC_OUTCOME_UNKNOWN = 0,
    /**
     * This is what the call agreed on. Exactly one candidate carries it,
     * and it names the same codec as `sipral_media_info_t::codec`.
     */
    SIPRAL_CODEC_OUTCOME_CHOSEN = 1,
    /**
     * The far end's description did not name it, so it was never in the
     * running. The commonest answer, and the one that says the question
     * is about the far end's configuration rather than this one's.
     */
    SIPRAL_CODEC_OUTCOME_NOT_NAMED = 2,
    /**
     * The far end named it and this end had something better: the codec
     * in `outranked_by` came first in this call's order.
     */
    SIPRAL_CODEC_OUTCOME_OUTRANKED = 3,
};

/**
 * Which way audio may flow, as seen from here. Names for every `direction`.
 */
typedef uint32_t sipral_direction_t;
enum {
    /**
     * Not negotiated.
     */
    SIPRAL_DIRECTION_UNKNOWN = 0,
    /**
     * Both ways.
     */
    SIPRAL_DIRECTION_SEND_RECV = 1,
    /**
     * This end sends and does not receive, which is what holding the far end
     * looks like from here.
     */
    SIPRAL_DIRECTION_SEND_ONLY = 2,
    /**
     * This end receives and does not send.
     */
    SIPRAL_DIRECTION_RECV_ONLY = 3,
    /**
     * Neither way, and the stream stays in the session.
     */
    SIPRAL_DIRECTION_INACTIVE = 4,
};

/**
 * Where control traffic goes. Names for sipral_media_info_t::rtcp.
 */
typedef uint32_t sipral_rtcp_t;
enum {
    /**
     * Not negotiated.
     */
    SIPRAL_RTCP_UNKNOWN = 0,
    /**
     * One port carries both (RFC 5761), which happens only where both ends
     * asked for it.
     */
    SIPRAL_RTCP_MUXED = 1,
    /**
     * A port of its own at each end.
     */
    SIPRAL_RTCP_SEPARATE_PORT = 2,
    /**
     * None at all: the peer said it is not using RTCP.
     */
    SIPRAL_RTCP_OFF = 3,
};

/**
 * Why media failed. Names for `sipral_media_event_t::fault`.
 *
 * The sentence beside it says which case of the kind it was; this is the part
 * a machine acts on, and the two are never the same thing.
 */
typedef uint32_t sipral_media_fault_t;
enum {
    /**
     * Nothing failed.
     */
    SIPRAL_MEDIA_FAULT_NONE = 0,
    /**
     * The negotiation settled on something this build cannot encode or
     * decode, which means the peer answered with a format that was not in the
     * offer.
     */
    SIPRAL_MEDIA_FAULT_UNSUPPORTED_CODEC = 1,
    /**
     * The two descriptions agree on nothing that can carry audio.
     */
    SIPRAL_MEDIA_FAULT_NO_COMMON_CODEC = 2,
    /**
     * One end refused the stream with a port of zero. The call is up and
     * carries no audio, which is a thing a peer is allowed to want.
     */
    SIPRAL_MEDIA_FAULT_STREAM_REFUSED = 3,
    /**
     * There is no session description to work from.
     */
    SIPRAL_MEDIA_FAULT_NO_DESCRIPTION = 4,
    /**
     * A description could not be read.
     */
    SIPRAL_MEDIA_FAULT_BAD_DESCRIPTION = 5,
    /**
     * The recording stopped writing: the disk filled, the file went away.
     */
    SIPRAL_MEDIA_FAULT_RECORDING = 6,
    /**
     * The codec refused a frame.
     */
    SIPRAL_MEDIA_FAULT_CODEC = 7,
    /**
     * Something else the layer below reported and this ABI has no word for.
     */
    SIPRAL_MEDIA_FAULT_OTHER = 8,
    /**
     * ICE could not carry this call: the far end described none this
     * stack could use and the policy was `SIPRAL_ICE_REQUIRED`, the far
     * end took `a=rtcp-mux` out of an answer to an ICE offer, or consent
     * to send on the pair that was chosen was withdrawn part-way through
     * (RFC 7675 §5).
     *
     * A code of its own because it is the one an application can act on
     * differently: the call is up and the signalling is sound, and what
     * changed is only that no path could be checked. A deployment with a
     * non-ICE profile to fall back to falls back here.
     */
    SIPRAL_MEDIA_FAULT_ICE = 9,
};

/**
 * What a datagram handed to sipral_media_receive turned out to be.
 */
typedef uint32_t sipral_arrival_t;
enum {
    /**
     * Something this ABI has no word for.
     */
    SIPRAL_ARRIVAL_UNKNOWN = 0,
    /**
     * Audio, held for playout.
     */
    SIPRAL_ARRIVAL_QUEUED = 1,
    /**
     * Audio that was not used: malformed, late, duplicated, from the wrong
     * address, or on a payload type nobody negotiated. The counters in
     * sipral_stream_stats_t say which, over the call.
     */
    SIPRAL_ARRIVAL_DROPPED = 2,
    /**
     * A reception or sender report, folded into the statistics.
     */
    SIPRAL_ARRIVAL_CONTROL = 3,
    /**
     * The far end says it is leaving the session (RFC 3550 §6.6). Audio will
     * stop; the call has not ended until signalling says so.
     */
    SIPRAL_ARRIVAL_GOODBYE = 4,
    /**
     * Control traffic that was not believed: from the wrong address, or not a
     * well-formed compound packet.
     */
    SIPRAL_ARRIVAL_CONTROL_REFUSED = 5,
    /**
     * A record of the DTLS-SRTP handshake that keys this call, which has
     * been taken. Whatever it owes the far end in reply is waiting in
     * sipral_media_poll_transmit, and this is the signal to drain it.
     */
    SIPRAL_ARRIVAL_HANDSHAKE = 6,
    /**
     * Something arrived on a call that agreed to be encrypted and has no
     * keys yet, so there was nothing to verify it with. The ordinary way
     * this happens is a peer that starts sending the moment its own half
     * of the handshake finishes, which is before ours does.
     */
    SIPRAL_ARRIVAL_NOT_KEYED = 7,
};

/**
 * The SRTP transform a call is running. Names for
 * `sipral_media_event_t::suite`.
 */
typedef uint32_t sipral_srtp_suite_t;
enum {
    /**
     * No transform: the event is not about one, or the call is not
     * encrypted.
     */
    SIPRAL_SRTP_SUITE_UNKNOWN = 0,
    /**
     * `AES_CM_128_HMAC_SHA1_80`, the one every implementation has.
     */
    SIPRAL_SRTP_SUITE_AES_CM80 = 1,
    /**
     * `AES_CM_128_HMAC_SHA1_32`, the same cipher with a shorter tag.
     */
    SIPRAL_SRTP_SUITE_AES_CM32 = 2,
    /**
     * `F8_128_HMAC_SHA1_80`, which is what 3GPP asks for. Reachable by
     * SDES only; RFC 5764 §4.1.2 defines no DTLS-SRTP profile for it.
     */
    SIPRAL_SRTP_SUITE_AES_F8 = 3,
};

/**
 * Where the frame sipral_media_playback just produced came from.
 */
typedef uint32_t sipral_playback_t;
enum {
    /**
     * Something this ABI has no word for.
     */
    SIPRAL_PLAYBACK_UNKNOWN = 0,
    /**
     * A packet the far end sent.
     */
    SIPRAL_PLAYBACK_PACKET = 1,
    /**
     * One it sent and this end did not get, filled in by the concealment.
     */
    SIPRAL_PLAYBACK_CONCEALED = 2,
    /**
     * Comfort noise, from an RFC 3389 payload the far end sent instead of
     * audio.
     */
    SIPRAL_PLAYBACK_COMFORT_NOISE = 3,
    /**
     * Nothing was due: the buffer is still filling, or the far end has
     * stopped.
     */
    SIPRAL_PLAYBACK_SILENCE = 4,
};

/**
 * Which way a digit goes to the far end. Names for
 * sipral_call_send_dtmf's `via`.
 *
 * The choice is per send, not per call, because it is a fact about the peer
 * rather than about this end, and the way to find out which one a peer takes
 * is to try. A carrier that ignores one of these ignores it silently.
 */
typedef uint32_t sipral_dtmf_t;
enum {
    /**
     * In the media, as an RFC 4733 named telephone event. What to reach for:
     * it is the only one carried end to end by every gateway on the path, and
     * the only one whose timing survives transcoding.
     *
     * It is one rather than zero on purpose. Zero is what a caller who
     * filled nothing in leaves behind, and the way a digit travels is the
     * one setting here that a peer can ignore in silence: a call that
     * meant INFO and sent nothing at all looks, from this end, exactly
     * like a call that sent it. So zero names no form and is refused.
     */
    SIPRAL_DTMF_RTP = 1,
    /**
     * An INFO per digit carrying `application/dtmf-relay`, which states the
     * signal and how long it was held.
     */
    SIPRAL_DTMF_INFO_RELAY = 2,
    /**
     * An INFO per digit carrying `application/dtmf`, whose whole body is the
     * character. Some switches take only this one.
     */
    SIPRAL_DTMF_INFO_PLAIN = 3,
};

/**
 * What an event is about.
 *
 * The numbers are part of the ABI and are only ever added to. A binding
 * that meets a kind it does not know must ignore that event rather than
 * refuse it, which is what makes adding one safe.
 *
 * Numbers already spent on features this build does not have:
 * - 16: the set of audio devices changed (A2)
 */
typedef uint32_t sipral_event_kind_t;
enum {
    /**
     * The stack is running on this thread.
     *
     * The first event on every stack, delivered by the first poll and never
     * again. A binding that has a callback to hand out, a queue to open or a
     * thread to name has somewhere definite to do it, before anything that
     * matters can arrive.
     */
    SIPRAL_EVENT_KIND_STARTED = 1,
    /**
     * A registration moved: it went out, it took, it is being refreshed, it
     * was given up, or it failed. `payload.registration` says which, and
     * `account` says whose.
     */
    SIPRAL_EVENT_KIND_REGISTRATION_CHANGED = 2,
    /**
     * Somebody is calling. Answer, ring, or reject it.
     */
    SIPRAL_EVENT_KIND_INCOMING_CALL = 3,
    /**
     * A call this end placed is getting somewhere short of an answer.
     */
    SIPRAL_EVENT_KIND_CALL_PROGRESS = 4,
    /**
     * A proxy forked the INVITE and a second phone is ringing.
     * `payload.call.other` is the branch that has just appeared.
     */
    SIPRAL_EVENT_KIND_CALL_FORKED = 5,
    /**
     * The call is up.
     */
    SIPRAL_EVENT_KIND_CALL_CONFIRMED = 6,
    /**
     * The session inside a live call changed: a hold, a resume, or an offer
     * either end made and had accepted.
     */
    SIPRAL_EVENT_KIND_SESSION_CHANGED = 7,
    /**
     * The far end offered a change this stack has no policy for. The
     * transaction is held open: answer it or refuse it, or the call ends.
     */
    SIPRAL_EVENT_KIND_SESSION_OFFERED = 8,
    /**
     * A change this end offered was refused. The session stands as it was.
     */
    SIPRAL_EVENT_KIND_SESSION_CHANGE_FAILED = 9,
    /**
     * The far end asked this one to call somebody else.
     */
    SIPRAL_EVENT_KIND_TRANSFER_REQUESTED = 10,
    /**
     * A transfer this end asked for is under way.
     */
    SIPRAL_EVENT_KIND_TRANSFER_PROGRESS = 11,
    /**
     * And how it ended.
     */
    SIPRAL_EVENT_KIND_TRANSFER_DONE = 12,
    /**
     * A call arrived carrying a `Replaces` and took over one already up.
     * `payload.call.other` is the one being replaced.
     */
    SIPRAL_EVENT_KIND_CALL_REPLACED = 13,
    /**
     * The call is over, and its handle is stale from here on.
     */
    SIPRAL_EVENT_KIND_CALL_ENDED = 14,
    /**
     * A subscription moved: it was asked for, granted, put on probation,
     * scheduled for another attempt, or ended.
     *
     * A1. `payload.subscription` says which one and where it is now, and
     * `reason` why it is not live when it is not. Not sent on every
     * refresh — a lamp does not move because a refresh was scheduled —
     * and not sent for a notification arriving, which is
     * SIPRAL_EVENT_KIND_NOTIFIED instead.
     */
    SIPRAL_EVENT_KIND_SUBSCRIPTION_CHANGED = 15,
    /**
     * What one call's media cost, delivered once, after
     * `SIPRAL_EVENT_KIND_CALL_ENDED`.
     *
     * A6's second consumer. `payload.media.statistics` points at the
     * completed record; it is the library's and lives as long as the callback
     * does. The stream is gone by the time this arrives, which is why the
     * numbers travel in the event rather than behind a lookup that would now
     * fail.
     */
    SIPRAL_EVENT_KIND_MEDIA_STATISTICS = 17,
    /**
     * A request grew too large for a datagram (RFC 3261 §18.1.1) and this
     * stack has no stream transport open to the destination it names.
     * `payload.transport_wanted` says where it was going, over what
     * protocol, and how it measured against the datagram it did not fit.
     *
     * B1. Answered with
     * sipral_stack_transport_bind:
     * once the application binds a transport to that destination, the
     * stack sends the request again by itself and this ABI raises
     * nothing further about it — there is no "it went" event, the same
     * way there is none for an ordinary request that fit the first time.
     */
    SIPRAL_EVENT_KIND_TRANSPORT_WANTED = 18,
    /**
     * Nothing has arrived on the media path for longer than the configured
     * threshold, while signalling is perfectly happy.
     *
     * B5. `payload.media.silent_for_ms` says how long. The call is untouched:
     * whether to hang up over silence is a decision with a person on the other
     * end of it.
     */
    SIPRAL_EVENT_KIND_MEDIA_STALLED = 19,
    /**
     * A call a push announced never arrived.
     *
     * C2, and not an error. A wake-up chain has a notification service,
     * a proxy, a bucket timer and a radio in it, and when a call does not
     * come through it this is the only place that says which end gave up:
     * the push was delivered, this device woke, refreshed its binding,
     * and no INVITE followed. `payload.announce` says which announcement
     * and how long it was waited for; the screen the application raised
     * can come down.
     */
    SIPRAL_EVENT_KIND_ANNOUNCED_CALL_MISSING = 20,
    /**
     * Audio is running: the negotiation settled and an RTP session is open.
     *
     * A4's reporting half and the first half of D5: `payload.media.codec` is
     * what the two ends agreed on. This is the moment to mint the call's
     * media handle with `sipral_call_media`, and `sipral_media_info` on it
     * says the rest.
     */
    SIPRAL_EVENT_KIND_MEDIA_STARTED = 21,
    /**
     * The session changed under a live call: a hold, a resume, a peer that
     * moved its media address, or a re-negotiation onto another codec.
     */
    SIPRAL_EVENT_KIND_MEDIA_CHANGED = 22,
    /**
     * Packets are arriving again. `payload.media.silent_for_ms` says how long
     * the gap turned out to be.
     */
    SIPRAL_EVENT_KIND_MEDIA_RESUMED = 23,
    /**
     * Media could not be started or could not be kept. The call itself is
     * untouched; `payload.media.fault` and `payload.media.reason` say why.
     */
    SIPRAL_EVENT_KIND_MEDIA_FAILED = 24,
    /**
     * A recording stopped on its own, part-way through: the disk filled, the
     * file went away, the volume was unmounted.
     *
     * Never an abort. `payload.media.recorded_ms` says how much audio reached
     * the file before it stopped, and the call carries on without it.
     */
    SIPRAL_EVENT_KIND_RECORDING_STOPPED = 25,
    /**
     * The far end pressed a key: an RFC 4733 named telephone event, or an
     * INFO carrying `application/dtmf-relay` or `application/dtmf`.
     *
     * One per keypress, not one per packet: an RFC 4733 digit goes out as
     * a run of updates and then its closing packet three times, and the
     * layer below collapses them on the timestamp that identifies the
     * event; an INFO is one request. `payload.media.digit` is the
     * character, `event_code` the number behind it for the events no
     * keypad has a key for, `held_ms` how long it lasted, and `source`
     * a `SIPRAL_DIGIT_SOURCE` naming which of the two reported it.
     * `held_ms` zero means either of two different facts: an
     * `application/dtmf` INFO never carries a duration at all, and a
     * peer using the other form may have said `Duration=0` and held the
     * key for no time at all — this C ABI does not tell the two apart.
     */
    SIPRAL_EVENT_KIND_DIGIT_RECEIVED = 26,
    /**
     * An INFO this end sent for `sipral_call_send_dtmf` reached a final
     * answer. `payload.call.digit` is the character and
     * `payload.call.status_code` what the far end answered — a 415 from
     * a switch that does not take this `Content-Type` included, so the
     * application learns which of the two INFO forms to try without
     * guessing from silence. A digit that waited behind another and whose
     * own INFO could then not be sent at all is reported the same way,
     * with 503: nothing reached the far end for that one, and no digit
     * after it is sent.
     */
    SIPRAL_EVENT_KIND_DTMF_SENT = 27,
    /**
     * The lifecycle machine settled: a registrar answered again and
     * proved a path this stack had stopped believing in, or every rung
     * of a recovery ladder was climbed and none of them worked.
     * `payload.recovery` says which, and carries what the ladder that
     * got there actually knows. `crates/sipral-ffi/src/lifecycle.rs`
     * and `docs/16-lifecycle.md` are the ladder this reports on.
     */
    SIPRAL_EVENT_KIND_RECOVERY = 28,
    /**
     * A dialog's next hop is a name, and this library does not look
     * names up.
     *
     * RFC 3263 §4's TARGET, before any NAPTR, SRV or A lookup: the
     * route set and the remote target say where this dialog's requests
     * should go, and what they say is not where they are going. Nothing
     * here owns a resolver — nothing here owns a socket either — so the
     * answer is the application's, through
     * sipral_stack_resolved,
     * with `payload.resolve.dialog` as the handle it takes.
     *
     * **Ignoring it is legitimate and is the common case.** The dialog
     * keeps the flow its first message travelled on, which §8.1.2 allows
     * as an alternate address and which is the only thing that survives
     * a NAT. Nothing times out, nothing retries, and no second event
     * says the first went unanswered.
     */
    SIPRAL_EVENT_KIND_RESOLVE_NEEDED = 29,
    /**
     * A notification arrived on a subscription, and has been answered.
     *
     * A1's other half. The NOTIFY is in `message`, whole and unparsed,
     * which is where every package this ABI has no reader for is read
     * from. `payload.subscription.has_dialog_info` says the body was
     * `application/dialog-info+xml` and could be read, and the picture it
     * updated is behind
     * sipral_subscription_dialog_count.
     * A body that could not be read arrives here all the same, with that
     * member zero and the request whole: a lamp showing what was last
     * known beats one showing what a malformed document happened to
     * contain.
     */
    SIPRAL_EVENT_KIND_NOTIFIED = 30,
    /**
     * The INVITE for a call a push had already announced has arrived
     * (RFC 8599).
     *
     * C2's other half. Queued immediately before the
     * SIPRAL_EVENT_KIND_INCOMING_CALL naming the same call, and never
     * without one, so that an application reading its events in order
     * knows which screen the call belongs to before it is told there is a
     * call at all. That is the whole point: on a phone the ringing screen
     * exists first, and a stack that reports the INVITE without saying
     * which announcement it answers has made the application guess.
     *
     * `call` is the call, and `payload.announce.announcement` what
     * announced it. That announcement is spent: it is not waited for any
     * more, and `sipral_announcement_forget` on it answers
     * `SIPRAL_STATUS_WRONG_STATE` rather than taking a screen down twice.
     */
    SIPRAL_EVENT_KIND_CALL_ANNOUNCED = 31,
    /**
     * The handshake that keys a call finished, and audio can move
     * (RFC 5764).
     *
     * Only DTLS-SRTP produces it, and it is the moment the call becomes
     * what it agreed to be: between `SIPRAL_EVENT_KIND_MEDIA_STARTED`
     * and this one the stream exists, has an address and a codec, and
     * carries nothing in either direction. An application that draws a
     * padlock draws it here.
     *
     * `call` is the call and `payload.media.suite` is the transform the
     * handshake chose — the signalling does not, which is why there is
     * an event for it at all. A call keyed by SDES never produces one,
     * because such a call is keyed before its session is opened.
     *
     * A handshake that does not finish produces
     * `SIPRAL_EVENT_KIND_MEDIA_FAILED` instead, and the call is left up:
     * whether to hang it up is a decision with a person on the other end
     * of it.
     */
    SIPRAL_EVENT_KIND_MEDIA_SECURED = 32,
    /**
     * `sipral_media_event_t`: ICE chose the path this call's media takes
     * (RFC 8445 §8.1.1), and audio can move.
     *
     * The moment the connectivity checks stop, and the answer to "why is
     * this call sending to an address the signalling never named" —
     * which, behind a NAT, is the ordinary outcome rather than a fault.
     * It arrives again if a nomination of higher priority replaces the
     * pair part-way through the call.
     *
     * The two addresses of the pair are deliberately not carried here,
     * for the reason `SIPRAL_EVENT_KIND_MEDIA_SECURED` gives about its
     * own: every packet `sipral_media_capture` and
     * `sipral_media_poll_transmit` hand back already names the
     * destination to send it to, so an application that puts this
     * stack's media on a socket at all has the address the moment it
     * matters. `sipral_media_statistics` does not repeat it either.
     *
     * A call not using ICE never emits it, and that is most calls: the
     * policy is `SIPRAL_ICE_OFF` unless something asked otherwise.
     */
    SIPRAL_EVENT_KIND_MEDIA_PATH_CHOSEN = 33,
    /**
     * A MESSAGE arrived (RFC 3428 §7) and has already been answered:
     * 200, because this stack delivers rather than relays.
     * `payload.message` carries the body, and `account`/`call` on
     * `sipral_event_t` say where it was addressed and whether it rode
     * inside a call's dialog.
     */
    SIPRAL_EVENT_KIND_MESSAGE_RECEIVED = 34,
    /**
     * A MESSAGE `sipral_account_message` sent reached its final answer,
     * or never will. `payload.message.status_code` is 200, a 202 from a
     * relay, a refusal, or the 408/503 this stack reports for one that
     * timed out or lost its transport.
     */
    SIPRAL_EVENT_KIND_MESSAGE_SENT = 35,
    /**
     * A `message-summary` `NOTIFY` reported the state of a mailbox
     * (RFC 3842 §3.9). `payload.message` carries the counts of the
     * `voice-message` class, the one a phone's message-waiting light is
     * about.
     */
    SIPRAL_EVENT_KIND_MESSAGES_WAITING = 36,
    /**
     * The account this call belongs to asked for an RFC 6035 voice
     * quality report and the attempt to publish it has now been made,
     * once, after `SIPRAL_EVENT_KIND_CALL_ENDED`.
     *
     * `payload.media.quality_report_sent` says whether the PUBLISH
     * left this end — not whether a collector accepted it, which this
     * stack never waits to learn. Raised only when the account named
     * a collector to publish to at all
     * (`sipral_account_settings_t::quality_report_uri`); a call whose
     * account named none raises nothing here, since nothing was ever
     * attempted.
     */
    SIPRAL_EVENT_KIND_QUALITY_REPORT_SENT = 37,
    /**
     * The call this one was joined to has ended, taking the local
     * conference of two down with it.
     *
     * `sipral_call_join` paired the two calls and neither one ever
     * called `sipral_call_leave` — the partner's own call simply ended
     * first, the same way any call does, and this is the half of that
     * this call has to be told: the pairing does not outlive either
     * side of it. `call` is the survivor; its own session is untouched
     * and carries on exactly as an unjoined call always has, on
     * whatever `sipral_media_playback`/`sipral_media_capture` it is
     * next given directly rather than through `sipral_media_mix`.
     */
    SIPRAL_EVENT_KIND_MEDIA_UNJOINED = 38,
    /**
     * A STUN server said where one of this end's sockets appears from,
     * said it has moved, or never answered (RFC 8489). Only on a stack
     * created with `SIPRAL_NAT_STUN`.
     *
     * `payload.nat` says which socket and what it came to. For a
     * signalling socket the work is already done by the time this
     * arrives: every account whose `Contact` named the socket names the
     * public address now, and each one holding a binding has sent the
     * REGISTER that says so. For a media socket
     * `sipral_stack_nat_map` named, this is the moment a call can be
     * placed, rung or answered on it — before it, that is
     * `SIPRAL_STATUS_WRONG_STATE`. A socket the server never answered
     * for is described by its own address, as it would have been with
     * no STUN at all. `account` and `call` are `SIPRAL_HANDLE_NONE`:
     * a socket is neither.
     */
    SIPRAL_EVENT_KIND_NAT_MAPPING = 39,
    /**
     * A TURN server allocated a relay for a media socket
     * `sipral_stack_nat_map` named, or gave none (RFC 8656). Only on a
     * stack created with a `turn_server`.
     *
     * `payload.relay` says which socket and what it came to. Allocated,
     * it is the moment a call can be placed, rung or answered on the
     * socket with the relay as its relayed ICE candidate — before it,
     * that is `SIPRAL_STATUS_WRONG_STATE`, as it is while the STUN
     * answer is awaited. Failed, the call goes without one. `account`
     * and `call` are `SIPRAL_HANDLE_NONE`: a socket is neither.
     */
    SIPRAL_EVENT_KIND_NAT_RELAY = 40,
};

/**
 * Where a registration is. Names for `sipral_registration_event_t::state`.
 */
typedef uint32_t sipral_registration_state_t;
enum {
    /**
     * The account is gone, or has never been asked about.
     */
    SIPRAL_REGISTRATION_STATE_UNKNOWN = 0,
    /**
     * Configured and not registered. Nothing has been sent.
     */
    SIPRAL_REGISTRATION_STATE_IDLE = 1,
    /**
     * A REGISTER is in flight and there is no binding yet.
     */
    SIPRAL_REGISTRATION_STATE_REGISTERING = 2,
    /**
     * The registrar holds a binding.
     */
    SIPRAL_REGISTRATION_STATE_REGISTERED = 3,
    /**
     * A refresh is in flight. The binding stands until it is answered.
     */
    SIPRAL_REGISTRATION_STATE_REFRESHING = 4,
    /**
     * Something recoverable went wrong and the next attempt is scheduled.
     */
    SIPRAL_REGISTRATION_STATE_RETRYING = 5,
    /**
     * The binding was given up on purpose.
     */
    SIPRAL_REGISTRATION_STATE_UNREGISTERED = 6,
    /**
     * The registrar refused in a way that trying again cannot fix.
     */
    SIPRAL_REGISTRATION_STATE_FAILED = 7,
    /**
     * A binding a registrar really granted, over a transport that has since
     * been suspended or lost, which nothing has proved since.
     *
     * Not registered, because it is no longer evidence; not failed, because
     * nothing refused it. A monotonic clock does not advance while a machine
     * sleeps, so a stack that slept eight hours comes back believing eight
     * milliseconds passed and every binding still valid — this is the state
     * that says otherwise, and an application that shows a line as ready on
     * the strength of it will show it ready when it is not.
     */
    SIPRAL_REGISTRATION_STATE_UNVERIFIED = 8,
    /**
     * A binding read back from a snapshot rather than granted in this
     * process. It has not been proved either.
     */
    SIPRAL_REGISTRATION_STATE_RESTORED = 9,
    /**
     * The account was configured with no registrar and never registers:
     * a trunk that knows this end by its address. It starts here and
     * stays here, and `sipral_account_register` refuses it. Not idle,
     * which is one `sipral_account_register` away from a binding.
     */
    SIPRAL_REGISTRATION_STATE_NOT_REGISTERING = 10,
};

/**
 * Why a registration is not live. Names for
 * `sipral_registration_event_t::failure`.
 */
typedef uint32_t sipral_registration_failure_t;
enum {
    /**
     * Nothing failed.
     */
    SIPRAL_REGISTRATION_FAILURE_NONE = 0,
    /**
     * The registrar refused, and will refuse the same request again.
     */
    SIPRAL_REGISTRATION_FAILURE_REJECTED = 1,
    /**
     * The password was wrong, or there was none to answer with.
     */
    SIPRAL_REGISTRATION_FAILURE_BAD_CREDENTIALS = 2,
    /**
     * The registrar is not answering, or says it cannot serve this now.
     */
    SIPRAL_REGISTRATION_FAILURE_UNREACHABLE = 3,
    /**
     * The registrar moved. Following it needs an address, which is the
     * caller's to resolve.
     */
    SIPRAL_REGISTRATION_FAILURE_REDIRECTED = 4,
};

/**
 * Where a call is. Names for `sipral_call_event_t::state`, and what
 * `sipral_call_state` writes.
 */
typedef uint32_t sipral_call_state_t;
enum {
    /**
     * The call is gone, or has never been asked about.
     */
    SIPRAL_CALL_STATE_UNKNOWN = 0,
    /**
     * The INVITE has gone and nothing has come back.
     */
    SIPRAL_CALL_STATE_CALLING = 1,
    /**
     * Somebody is calling and this end has not answered.
     */
    SIPRAL_CALL_STATE_INCOMING = 2,
    /**
     * The far end is ringing, or this end said it is.
     */
    SIPRAL_CALL_STATE_RINGING = 3,
    /**
     * There is audio before anybody answered.
     */
    SIPRAL_CALL_STATE_EARLY_MEDIA = 4,
    /**
     * Up.
     */
    SIPRAL_CALL_STATE_CONFIRMED = 5,
    /**
     * Up, in order to be transferred: the second leg of an attended transfer.
     */
    SIPRAL_CALL_STATE_CONSULTING = 6,
    /**
     * A CANCEL or a BYE has gone and is not answered yet.
     */
    SIPRAL_CALL_STATE_TERMINATING = 7,
    /**
     * Over.
     */
    SIPRAL_CALL_STATE_TERMINATED = 8,
};

/**
 * Why a call is over. Names for `sipral_call_event_t::end_reason`.
 */
typedef uint32_t sipral_call_end_reason_t;
enum {
    /**
     * The call is not over.
     */
    SIPRAL_CALL_END_REASON_NONE = 0,
    /**
     * This end hung up.
     */
    SIPRAL_CALL_END_REASON_LOCAL_HANGUP = 1,
    /**
     * The far end hung up.
     */
    SIPRAL_CALL_END_REASON_REMOTE_HANGUP = 2,
    /**
     * The far end refused it: busy, declined, not found.
     */
    SIPRAL_CALL_END_REASON_REFUSED = 3,
    /**
     * Given up before it was answered, from either end.
     */
    SIPRAL_CALL_END_REASON_CANCELLED = 4,
    /**
     * Nothing came back, or the transport died.
     */
    SIPRAL_CALL_END_REASON_UNREACHABLE = 5,
    /**
     * Another branch of the same fork was kept and this one was not.
     */
    SIPRAL_CALL_END_REASON_FORK_LOST = 6,
    /**
     * The branch was still ringing when the answer window closed.
     */
    SIPRAL_CALL_END_REASON_ABANDONED = 7,
    /**
     * The session timer ran out and no refresh arrived.
     */
    SIPRAL_CALL_END_REASON_EXPIRED = 8,
};

/**
 * Which of the two ways this stack accepts a digit reported the one
 * SIPRAL_EVENT_KIND_DIGIT_RECEIVED carries. Names for
 * `sipral_media_event_t::source`.
 */
typedef uint32_t sipral_digit_source_t;
enum {
    /**
     * RFC 4733: a named telephone event in the RTP stream.
     */
    SIPRAL_DIGIT_SOURCE_RTP = 0,
    /**
     * RFC 3261's INFO method (RFC 6086), carrying `application/dtmf-relay`
     * or `application/dtmf`.
     */
    SIPRAL_DIGIT_SOURCE_INFO = 1,
};

/**
 * What a SIPRAL_EVENT_KIND_RECOVERY reports happened, for
 * `payload.recovery.state`. Names for the two ways `sipral_ua`'s
 * lifecycle machine settles: a registrar answered again, or a recovery
 * ladder ran out of rungs.
 */
typedef uint32_t sipral_recovery_outcome_t;
enum {
    /**
     * Never written by this build.
     */
    SIPRAL_RECOVERY_OUTCOME_UNKNOWN = 0,
    /**
     * A registrar answered again: what was distrusted is proved.
     */
    SIPRAL_RECOVERY_OUTCOME_RUNNING = 1,
    /**
     * Every rung was climbed and none of them worked.
     */
    SIPRAL_RECOVERY_OUTCOME_GAVE_UP = 2,
};

/**
 * The last rung a recovery ladder tried before it gave up, for
 * SIPRAL_EVENT_KIND_RECOVERY's `payload.recovery.rung`. Meaningful
 * only when `payload.recovery.state` is
 * SIPRAL_RECOVERY_OUTCOME_GAVE_UP. Names for `sipral_ua::Rung`, minus
 * Rung::GiveUp itself: `sipral_ua` reports the rung before it that
 * asked for something and went unanswered, not the give-up rung that
 * follows it.
 */
typedef uint32_t sipral_recovery_rung_t;
enum {
    /**
     * The ladder did not give up.
     */
    SIPRAL_RECOVERY_RUNG_NONE = 0,
    /**
     * Nothing was believed any more, and nothing was sent.
     */
    SIPRAL_RECOVERY_RUNG_DISTRUST = 1,
    /**
     * A REGISTER, and a re-SUBSCRIBE for what was demoted alongside it,
     * went out or could not.
     */
    SIPRAL_RECOVERY_RUNG_REREGISTER = 2,
    /**
     * The application was asked for a transport.
     */
    SIPRAL_RECOVERY_RUNG_WANT_TRANSPORT = 3,
    /**
     * The application was asked for an address.
     */
    SIPRAL_RECOVERY_RUNG_WANT_ADDRESS = 4,
};

/**
 * Why a recovery ladder gave up, for SIPRAL_EVENT_KIND_RECOVERY's
 * `payload.recovery.reason`. Names for `sipral_ua::RecoveryFailure`.
 */
typedef uint32_t sipral_recovery_failure_t;
enum {
    /**
     * The ladder did not give up.
     */
    SIPRAL_RECOVERY_FAILURE_NONE = 0,
    /**
     * Every REGISTER that could be sent was sent and none of them was
     * answered.
     */
    SIPRAL_RECOVERY_FAILURE_UNREACHABLE = 1,
    /**
     * A transport was asked for and the application did not bind one.
     */
    SIPRAL_RECOVERY_FAILURE_NO_TRANSPORT = 2,
    /**
     * An address was asked for and the application did not supply one.
     */
    SIPRAL_RECOVERY_FAILURE_UNRESOLVED = 3,
};

/**
 * What kind of link the application is on. Names for `from_link` and
 * `to_link` on sipral_stack_network_changed.
 *
 * Coarse on purpose: nothing here changes what is sent, and the one
 * value that changes what is *done* is SIPRAL_LINK_DOWN. The rest is
 * carried so that a change of kind over an unchanged address — a tunnel
 * coming up, a phone moving from Wi-Fi to a mobile network that kept the
 * address — is visible as a change at all.
 */
typedef uint32_t sipral_link_t;
enum {
    /**
     * There is no usable interface.
     */
    SIPRAL_LINK_DOWN = 0,
    /**
     * Cable.
     */
    SIPRAL_LINK_WIRED = 1,
    /**
     * Wireless local network.
     */
    SIPRAL_LINK_WIFI = 2,
    /**
     * A mobile network.
     */
    SIPRAL_LINK_CELLULAR = 3,
    /**
     * A tunnel over one of the others.
     */
    SIPRAL_LINK_TUNNEL = 4,
};

/**
 * What a change of network is worth doing about. Names for
 * sipral_stack_network_changed's `out_recovery`.
 *
 * Returned from the call itself, so an application does not have to read
 * an event to find out whether anything happened: a laptop that flips
 * between two access points all day gets SIPRAL_RECOVERY_NOTHING
 * every time and never sends a REGISTER over it.
 */
typedef uint32_t sipral_recovery_t;
enum {
    /**
     * Never written by this build.
     */
    SIPRAL_RECOVERY_UNKNOWN = 0,
    /**
     * Nothing this stack uses is different. Nothing is done and nothing
     * is sent.
     */
    SIPRAL_RECOVERY_NOTHING = 1,
    /**
     * The address still stands, so the transports do. What is upstream
     * of it may not.
     */
    SIPRAL_RECOVERY_REREGISTER = 2,
    /**
     * A wake: the transport already there is used first, and a new one
     * is asked for only once it turns out to be dead. Never returned by
     * this entry point; it is what sipral_stack_resumed starts.
     */
    SIPRAL_RECOVERY_REPROVE = 3,
    /**
     * The address is gone. Everything bound to it is unusable and the
     * application has to open a transport again.
     */
    SIPRAL_RECOVERY_REBUILD = 4,
    /**
     * Packets can leave and names cannot be turned into addresses.
     */
    SIPRAL_RECOVERY_RESOLVE = 5,
    /**
     * There is no interface. Nothing is tried until there is one.
     */
    SIPRAL_RECOVERY_DETACH = 6,
};

/**
 * What a stack does about a NAT in front of it. Names for
 * `sipral_stack_config_t::nat`.
 *
 * Zero is not one of them: it means this build's own built-in default,
 * which is SIPRAL_NAT_OFF. `docs/06-nat.md` says why that is the
 * default and what `rport` and symmetric RTP already carry without it.
 */
typedef uint32_t sipral_nat_t;
enum {
    /**
     * Ask nobody. Every address this stack writes is the one the
     * application gave it.
     */
    SIPRAL_NAT_OFF = 1,
    /**
     * Ask the STUN server `sipral_stack_config_t::stun_server` names
     * where each socket appears from, and write that instead: the
     * signalling socket's in the `Contact`, a media socket's in `c=` and
     * `m=`.
     *
     * `SIPRAL_STATUS_NOT_SUPPORTED` in a build without
     * `SIPRAL_FEATURE_STUN`.
     */
    SIPRAL_NAT_STUN = 2,
};

/**
 * What a socket's mapping came to. Names for
 * `sipral_nat_event_t::mapping`.
 */
typedef uint32_t sipral_nat_mapping_t;
enum {
    /**
     * The first answer: the socket appears at `public`.
     */
    SIPRAL_NAT_MAPPING_LEARNED = 1,
    /**
     * A later answer named another address: the NAT let the mapping go
     * and made a new one, or the network under the socket changed.
     * `previous` is what it was. About a signalling socket, or a media
     * socket still waiting for its call.
     */
    SIPRAL_NAT_MAPPING_MOVED = 2,
    /**
     * The server did not answer, in five and a half seconds, or refused.
     * The socket is described by its own address, exactly as it would
     * have been with `SIPRAL_NAT_OFF`; a signalling socket asks again at
     * its next refresh.
     */
    SIPRAL_NAT_MAPPING_UNANSWERED = 3,
};

/**
 * What a media socket's relay came to. Names for
 * `sipral_nat_relay_event_t::outcome`.
 */
typedef uint32_t sipral_nat_relay_t;
enum {
    /**
     * The TURN server allocated a relay for the socket: `relayed` is
     * the address it relays from. A call placed, rung or answered on
     * the socket from now on offers it as its relayed ICE candidate.
     */
    SIPRAL_NAT_RELAY_ALLOCATED = 1,
    /**
     * There is no relay for the socket: the server refused (`code` says
     * with what), did not answer in thirty-nine and a half seconds, or
     * took back an allocation it had made. A call on the socket goes
     * without one, and ICE finds what path it can on the rest.
     */
    SIPRAL_NAT_RELAY_FAILED = 2,
};

/**
 * Where a subscription is. Names for
 * `sipral_subscription_event_t::state` and for
 * sipral_subscription_state's `out_state`.
 */
typedef uint32_t sipral_subscription_state_t;
enum {
    /**
     * The handle names nothing: never minted here, or ended and let go.
     */
    SIPRAL_SUBSCRIPTION_STATE_UNKNOWN = 0,
    /**
     * A SUBSCRIBE is on its way and nothing has answered it yet.
     */
    SIPRAL_SUBSCRIPTION_STATE_REQUESTING = 1,
    /**
     * The notifier has it and has not decided. RFC 6665 §4.1.3's
     * `pending` is "insufficient policy information to grant or deny the
     * subscription yet", and nothing is known about the watched thing
     * until this becomes SIPRAL_SUBSCRIPTION_STATE_ACTIVE.
     */
    SIPRAL_SUBSCRIPTION_STATE_PENDING = 2,
    /**
     * Granted, and notifications are arriving.
     */
    SIPRAL_SUBSCRIPTION_STATE_ACTIVE = 3,
    /**
     * Not live, and a fresh attempt is scheduled. The handle stays
     * valid: §4.1.2.2's new attempt is "an unrelated initial SUBSCRIBE
     * request with a freshly generated Call-ID and a new, unique From
     * tag", and this ABI keeps one name over both of them.
     */
    SIPRAL_SUBSCRIPTION_STATE_RETRYING = 4,
    /**
     * Over, with nothing more coming. The handle names nothing from
     * here on.
     */
    SIPRAL_SUBSCRIPTION_STATE_ENDED = 5,
};

/**
 * Why a subscription is not live. Names for
 * `sipral_subscription_event_t::reason`.
 *
 * Zero unless the state is SIPRAL_SUBSCRIPTION_STATE_RETRYING or
 * SIPRAL_SUBSCRIPTION_STATE_ENDED. The first nine are what a
 * `Subscription-State: terminated` said in its `reason` parameter (RFC
 * 6665 §4.1.3), and the rest are what happened here instead.
 */
typedef uint32_t sipral_subscription_end_t;
enum {
    /**
     * Never written by this build.
     */
    SIPRAL_SUBSCRIPTION_END_UNKNOWN = 0,
    /**
     * `deactivated`: the notifier wants this subscription started again
     * at once.
     */
    SIPRAL_SUBSCRIPTION_END_DEACTIVATED = 1,
    /**
     * `probation`: started again, but not immediately.
     */
    SIPRAL_SUBSCRIPTION_END_PROBATION = 2,
    /**
     * `rejected`: the notifier will not serve it, and asking again is
     * pointless.
     */
    SIPRAL_SUBSCRIPTION_END_REJECTED = 3,
    /**
     * `timeout`: it ran out rather than being refreshed.
     */
    SIPRAL_SUBSCRIPTION_END_TIMEOUT = 4,
    /**
     * `giveup`: the notifier could not decide and stopped trying.
     */
    SIPRAL_SUBSCRIPTION_END_GAVE_UP = 5,
    /**
     * `noresource`: what was being watched does not exist any more.
     */
    SIPRAL_SUBSCRIPTION_END_NO_RESOURCE = 6,
    /**
     * `invariant`: the watched thing cannot change, so there is nothing
     * to notify about.
     */
    SIPRAL_SUBSCRIPTION_END_INVARIANT = 7,
    /**
     * `terminated` with no reason parameter at all.
     */
    SIPRAL_SUBSCRIPTION_END_UNSTATED = 8,
    /**
     * This end gave it up: sipral_subscription_end. It wins over
     * whatever the notifier's closing notification said its own reason
     * was, because the application asked for this one to stop and that
     * is the answer to why it is not live.
     */
    SIPRAL_SUBSCRIPTION_END_UNSUBSCRIBED = 9,
    /**
     * The notifier answered 489: it does not know this event package.
     */
    SIPRAL_SUBSCRIPTION_END_BAD_EVENT = 10,
    /**
     * The notifier refused the SUBSCRIBE with a status trying again
     * cannot fix.
     */
    SIPRAL_SUBSCRIPTION_END_REFUSED = 11,
    /**
     * The SUBSCRIBE was redirected, and following a redirect for one is
     * not something this stack does by itself.
     */
    SIPRAL_SUBSCRIPTION_END_REDIRECTED = 12,
    /**
     * Nothing answered: the notifier could not be reached at all.
     */
    SIPRAL_SUBSCRIPTION_END_UNREACHABLE = 13,
    /**
     * The SUBSCRIBE was answered and the first NOTIFY never arrived
     * (§4.1.2.4's timer N, 64·T1).
     */
    SIPRAL_SUBSCRIPTION_END_NO_NOTIFY = 14,
    /**
     * What the notifier granted ran out with no refresh answered.
     */
    SIPRAL_SUBSCRIPTION_END_EXPIRED = 15,
};

/**
 * What one watched dialog is doing, and what a lamp is lit from. Names
 * for `sipral_watched_dialog_t::phase` and for
 * sipral_subscription_lamp's `out_phase`.
 *
 * RFC 4235 §3.7.1's states, with the order they rank in for a lamp:
 * anything ringing beats anything settled, which is §3.7.2's virtual
 * state machine over every dialog of one resource.
 */
typedef uint32_t sipral_dialog_phase_t;
enum {
    /**
     * Nothing is going on: no dialog, or every one of them terminated.
     * This is what an idle lamp shows.
     */
    SIPRAL_DIALOG_PHASE_IDLE = 0,
    /**
     * A request went out and nothing has answered.
     */
    SIPRAL_DIALOG_PHASE_TRYING = 1,
    /**
     * Something answered without ringing yet.
     */
    SIPRAL_DIALOG_PHASE_PROCEEDING = 2,
    /**
     * Ringing.
     */
    SIPRAL_DIALOG_PHASE_EARLY = 3,
    /**
     * A call is up.
     */
    SIPRAL_DIALOG_PHASE_CONFIRMED = 4,
    /**
     * This dialog is over. Never sipral_subscription_lamp's answer,
     * which is SIPRAL_DIALOG_PHASE_IDLE when every dialog has ended.
     */
    SIPRAL_DIALOG_PHASE_TERMINATED = 5,
    /**
     * The notifier named a state this build has no number for.
     */
    SIPRAL_DIALOG_PHASE_UNKNOWN = 6,
};

/**
 * Which end started a watched dialog. Names for
 * `sipral_watched_dialog_t::direction`.
 */
typedef uint32_t sipral_dialog_direction_t;
enum {
    /**
     * The notifier did not say.
     */
    SIPRAL_DIALOG_DIRECTION_UNKNOWN = 0,
    /**
     * The watched end placed the call.
     */
    SIPRAL_DIALOG_DIRECTION_LOCALLY = 1,
    /**
     * The watched end was called.
     */
    SIPRAL_DIALOG_DIRECTION_REMOTELY = 2,
};

/**
 * How a watched dialog ended. Names for
 * `sipral_watched_dialog_t::ended`, and zero while it has not.
 */
typedef uint32_t sipral_dialog_ended_t;
enum {
    /**
     * It has not ended, or the notifier did not say how.
     */
    SIPRAL_DIALOG_ENDED_UNKNOWN = 0,
    /**
     * The caller gave up before it was answered.
     */
    SIPRAL_DIALOG_ENDED_CANCELLED = 1,
    /**
     * The called end refused it.
     */
    SIPRAL_DIALOG_ENDED_REJECTED = 2,
    /**
     * A `Replaces` took it over.
     */
    SIPRAL_DIALOG_ENDED_REPLACED = 3,
    /**
     * The watched end hung up.
     */
    SIPRAL_DIALOG_ENDED_LOCAL_BYE = 4,
    /**
     * The far end hung up.
     */
    SIPRAL_DIALOG_ENDED_REMOTE_BYE = 5,
    /**
     * Something went wrong with it.
     */
    SIPRAL_DIALOG_ENDED_ERROR = 6,
    /**
     * Nothing answered in time.
     */
    SIPRAL_DIALOG_ENDED_TIMEOUT = 7,
};

/**
 * Which piece of text sipral_subscription_dialog_text is being asked
 * for.
 *
 * Every one of them is what the notifier wrote, unparsed: a display name
 * is whatever it put there, and an identity is a URI in the form it sent
 * it in.
 */
typedef uint32_t sipral_dialog_text_t;
enum {
    /**
     * Never asked for.
     */
    SIPRAL_DIALOG_TEXT_UNKNOWN = 0,
    /**
     * The notifier's own name for this dialog, which is what it will
     * keep using for it.
     */
    SIPRAL_DIALOG_TEXT_ID = 1,
    /**
     * The dialog's `Call-ID`, when the notifier sent one.
     */
    SIPRAL_DIALOG_TEXT_CALL_ID = 2,
    /**
     * Who the watched end is, as a URI.
     */
    SIPRAL_DIALOG_TEXT_LOCAL_IDENTITY = 3,
    /**
     * And the display name beside it.
     */
    SIPRAL_DIALOG_TEXT_LOCAL_DISPLAY = 4,
    /**
     * Who the other end is, as a URI. This is the one a lamp shows
     * beside a ringing extension.
     */
    SIPRAL_DIALOG_TEXT_REMOTE_IDENTITY = 5,
    /**
     * And the display name beside it.
     */
    SIPRAL_DIALOG_TEXT_REMOTE_DISPLAY = 6,
    /**
     * Where requests for the watched end would be sent.
     */
    SIPRAL_DIALOG_TEXT_LOCAL_TARGET = 7,
    /**
     * And for the other end.
     */
    SIPRAL_DIALOG_TEXT_REMOTE_TARGET = 8,
};

/**
 * The one callback a stack has.
 *
 * It is called from inside `sipral_stack_poll`, on the thread that called
 * it, with the `user_data` the stack was created with, and never on two
 * threads at once for one stack. It must not unwind. Nothing is held
 * while it runs, so it may call back into the library, the stack it was
 * given included: see crate::stack.
 */
typedef void (*sipral_event_callback_t)(const sipral_event_t *event, void *user_data);

/**
 * The screening policy: consulted once for every INVITE, before it has
 * any effect. Installed with crate::screening::sipral_stack_screen.
 *
 * **It runs with the stack's own lock held**, which is the opposite of
 * sipral_event_callback_t and is the
 * whole reason this type's module documentation exists — read it there.
 * In consequence: **this callback must not call back into the stack it
 * was given**, on this thread or on any other. Doing so does not
 * deadlock — every entry point that takes a stack takes its lock
 * without waiting and answers `SIPRAL_STATUS_BUSY` rather than block —
 * but it is refused outright rather than relied on, and a policy that
 * tries it gets an error code back instead of the call it wanted made.
 * A *different* stack is unaffected. It must not unwind, for the same
 * reason nothing in this ABI may: a panic that reached C across this
 * boundary would take the host process with it.
 *
 * `request` and everything it points at belong to the library and are
 * valid for the duration of this one call and no longer.
 *
 * **The answer is a SIP status code, and the numbers are chosen so that
 * no answer at all is a refusal.** `SIPRAL_SCREEN_ACCEPT` — 200 — lets
 * the INVITE through, exactly as it would arrive with no policy
 * installed. Anything else is a refusal, answered with that status when
 * that status refuses — 400 to 699 — and with 500 when it does not.
 *
 * Three ranges do not refuse, and each fails the same way. Zero is what
 * a binding hands back when the application's own listener threw and
 * the exception was caught at the boundary, and it is no status at all.
 * A 1xx is a provisional answer: it would leave the caller ringing at a
 * call this end has already forgotten, holding a server transaction
 * nothing here will ever answer. A 2xx that is not the one acceptance
 * is spelled with accepts nothing, and a 3xx redirects nowhere without
 * a `Contact` this ABI has no way to give it. So a policy whose answer
 * went missing does not let a stranger in on the strength of it, and a
 * policy that meant to refuse and named a number that cannot refuse is
 * a bug to fix rather than a reason to wave one through.
 */
typedef uint32_t (*sipral_screen_callback_t)(const sipral_screen_request_t *request, void *user_data);

/**
 * Echo cancellation, gain control or noise suppression, run over one
 * frame, or told to forget what it has learned — sipral_processor_frame_t
 * says which. Installed with sipral_call_attach_processor.
 *
 * **It runs with this call's media locked**, which is the opposite of
 * crate::event::SipralEventCallback and the reason
 * sipral_call_attach_processor's own doc comment says so before it
 * says anything else — read it there. In consequence: **this callback
 * must not call back into the media handle it was attached through**,
 * on this thread or on any other. It must not unwind, for the same
 * reason nothing in this ABI may.
 *
 * `frame` and everything it points at belong to the library and are
 * valid for the duration of this one call and no longer.
 */
typedef void (*sipral_processor_callback_t)(const sipral_processor_frame_t *frame, void *user_data);

/**
 * The version of the ABI this library provides.
 *
 * Set `size` to `sizeof(sipral_abi_version_t)` before the call.
 */
struct sipral_abi_version {
    /**
     * How many bytes of this struct the library filled in.
     */
    size_t size;
    /**
     * Nothing built against another major version will work.
     */
    uint32_t major;
    /**
     * A build with a higher minor has everything a lower one had.
     */
    uint32_t minor;
    /**
     * A fix that changed no declaration.
     */
    uint32_t patch;
};

/**
 * What this build of the library can do: codecs compiled in, transports
 * this ABI carries signalling over, and which optional features are
 * present.
 *
 * Nothing here is configuration — this answers "can this build ever do X",
 * never "is X turned on for this stack". `sipral_stack_settings` answers
 * that once a stack exists, and `sipral_codec_count` /
 * `sipral_stack_codec_order` already enumerate the codecs this reports only
 * the count of, so this does not repeat what they say.
 *
 * Set `size` to `sizeof(sipral_capabilities_t)` before the call.
 */
struct sipral_capabilities {
    /**
     * How many bytes of this struct the library filled in.
     */
    size_t size;
    /**
     * How many codecs this build contains. `sipral_codec_count` gives the
     * same number; `sipral_codec_at` says which, and in what order they are
     * offered by default.
     */
    size_t codec_count;
    /**
     * Which transports this build carries signalling over, as the bits
     * named `SIPRAL_TRANSPORT_BIT_*`.
     */
    uint32_t transports;
    /**
     * Which optional features this build has compiled in, as the bits named
     * `SIPRAL_FEATURE_*`.
     */
    uint32_t features;
};

/**
 * D3's flat set of health counters for one stack, since it was created.
 *
 * Every member here is monotonic except `active_calls`, which is a gauge:
 * it can be read as smaller than an earlier reading, and none of the others
 * ever will be. Set `size` to `sizeof(sipral_counters_t)` before the call.
 */
struct sipral_counters {
    /**
     * How many bytes of this struct the library filled in.
     */
    size_t size;
    /**
     * A REGISTER went out, counted once per attempt including a retry.
     */
    uint64_t registrations_attempted;
    /**
     * The registrar granted a binding.
     */
    uint64_t registrations_succeeded;
    /**
     * The registrar refused, and will refuse the same request again.
     */
    uint64_t registrations_failed_rejected;
    /**
     * The password was wrong, or there was none to answer a challenge with.
     */
    uint64_t registrations_failed_bad_credentials;
    /**
     * The registrar did not answer, or said it could not serve this now.
     */
    uint64_t registrations_failed_unreachable;
    /**
     * The registrar moved.
     */
    uint64_t registrations_failed_redirected;
    /**
     * This end hung up.
     */
    uint64_t calls_ended_local_hangup;
    /**
     * The far end hung up.
     */
    uint64_t calls_ended_remote_hangup;
    /**
     * The far end refused it: busy, declined, not found.
     */
    uint64_t calls_ended_refused;
    /**
     * Given up before it was answered, from either end.
     */
    uint64_t calls_ended_cancelled;
    /**
     * Nothing came back, or the transport died.
     */
    uint64_t calls_ended_unreachable;
    /**
     * Another branch of the same fork was kept and this one was not.
     */
    uint64_t calls_ended_fork_lost;
    /**
     * The branch was still ringing when the answer window closed.
     */
    uint64_t calls_ended_abandoned;
    /**
     * The session timer ran out and no refresh arrived.
     */
    uint64_t calls_ended_expired;
    /**
     * How many times inbound audio stopped for longer than the configured
     * threshold while signalling stayed healthy (B5).
     */
    uint64_t media_gaps;
    /**
     * How many times a call's jitter buffer had to shrink or stretch the
     * stream to keep its delay where it was aiming.
     */
    uint64_t jitter_buffer_events;
    /**
     * How many times a request would not fit a datagram and there was no
     * stream to the destination to put it on, so the stack asked for one
     * (RFC 3261 §18.1.1, B1).
     *
     * A request promoted onto a connection that already existed does not
     * raise it; those are in the diagnostic record instead.
     */
    uint64_t stream_transport_wanted;
    /**
     * Calls with media running right now. The one gauge in this struct: it
     * moves both ways, and it is what every other member here is not.
     */
    uint64_t active_calls;
    /**
     * Events a poll raised and had nowhere to queue, because the
     * callback had not kept up and the outbox was already at its ceiling
     * (task 8.4.21). Appended here rather than woven in among the
     * others: it counts something about delivery itself rather than
     * about a call or a registration, and a build from before it existed
     * still reads every counter that did.
     */
    uint64_t events_dropped;
    /**
     * RTCP goodbyes dropped, oldest first, because the application had
     * not called `sipral_stack_poll_farewell` and the queue behind it
     * was already at its ceiling. Appended at the tail for the same
     * reason `events_dropped` was: a build from before this member
     * existed still reads every counter that did.
     */
    uint64_t farewells_dropped;
    /**
     * INVITEs a `sipral_stack_screen` policy refused (A8, D7).
     */
    uint64_t screened_refused_by_policy;
    /**
     * INVITEs refused because their source was offering them faster
     * than `sipral_stack_invite_limit` allows.
     */
    uint64_t screened_refused_by_rate;
    /**
     * INVITEs refused because every seat this stack keeps for a source
     * it is watching belonged to one still spending, and this source
     * could not be limited either — a flood from many addresses at
     * once rather than one calling too fast.
     */
    uint64_t screened_refused_by_crowding;
    /**
     * INVITEs refused 403 for naming a call they had no standing to
     * replace (RFC 3891 §3).
     */
    uint64_t screened_refused_by_replaces;
};

/**
 * What a stack is created with.
 *
 * Set `size` to `sizeof(sipral_stack_config_t)` and zero the rest before
 * filling anything in. Four members have to be filled: the callback, the
 * transport, the address this end is reachable at, and the entropy. Nothing
 * here can be guessed on the caller's behalf.
 */
struct sipral_stack_config {
    /**
     * `sizeof` this struct, as the caller's header declares it.
     */
    size_t size;
    /**
     * Where events go. Required: a stack with nowhere to report to is a
     * stack whose failures are invisible.
     */
    sipral_event_callback_t event_callback;
    /**
     * Handed back to the callback untouched. The library never reads it.
     */
    void *event_user_data;
    /**
     * A sipral_transport_t.
     */
    uint32_t transport;
    /**
     * The address the far end reaches this one at, as `host:port`, UTF-8 and
     * not NUL-terminated.
     *
     * It goes in every `Via`, so it is the address a response has to come
     * back to rather than whatever a wildcard socket was bound to. Nothing
     * here opens a socket or resolves a name.
     */
    const char *bind_address;
    /**
     * How many bytes of it.
     */
    size_t bind_address_len;
    /**
     * What to put in `User-Agent` on every request this stack originates —
     * REGISTER and INVITE — or null for none.
     *
     * Not on responses, and not on a request sent inside a dialog: those are
     * written a layer below this one, which has no opinion about product
     * names. The field is optional on every method — §20 Table 3 marks it `o`
     * throughout — so a message that goes out without it is still well formed.
     */
    const char *user_agent;
    /**
     * How many bytes of it.
     */
    size_t user_agent_len;
    /**
     * Thirty-two bytes of entropy, from the platform's own generator.
     *
     * Every branch parameter, tag and `Call-ID` is derived from it, and
     * §19.3 wants a tag unguessable — cryptographically random, not a
     * counter or a clock. Two stacks must never be given the same bytes.
     *
     * Not the media keys: those come from `media_seed`, and the reason
     * they are a separate draw is that a replay recording carries this
     * one in clear.
     */
    const uint8_t *entropy;
    /**
     * How many bytes of it. Thirty-two.
     */
    size_t entropy_len;
    /**
     * T1 in milliseconds, or zero for the 500 ms of §17.1.1.1.
     *
     * In force on every transport: 64·T1 is how long a transaction has to
     * finish, whether or not anything retransmits.
     */
    uint64_t timer_t1_ms;
    /**
     * T2 in milliseconds, or zero for four seconds.
     *
     * The cap on the doubling that starts at T1, and therefore only a figure
     * on a transport that retransmits. Setting it on anything but UDP is
     * `SIPRAL_STATUS_INVALID_ARGUMENT` rather than a value nothing reads.
     */
    uint64_t timer_t2_ms;
    /**
     * T4 in milliseconds, or zero for five seconds.
     *
     * How long a message lingers in the network, which is what timers I and K
     * wait out. Zero on a transport that delivers for us, so it is refused
     * there the same way T2 is.
     */
    uint64_t timer_t4_ms;
    /**
     * The codecs to offer, in the order to offer them: their names, separated
     * by commas, as UTF-8 and not NUL-terminated. Null for everything this
     * build contains, quality first.
     *
     * A4. The order is the whole of the negotiation's outcome — RFC 3264 §6.1
     * has the peer's preference decide among what both ends list — and it is
     * configured per site rather than fixed, because a carrier that bills by
     * the minute wants the narrowband codec first and a company on its own
     * network wants the wideband one.
     *
     * A name this build has no encoder for is `SIPRAL_STATUS_NOT_SUPPORTED`
     * here, with the names it does have in the last error. It is never taken
     * and ignored: a setting that is accepted and then quietly dropped is the
     * failure neither end can see.
     */
    const char *codecs;
    /**
     * How many bytes of it.
     */
    size_t codecs_len;
    /**
     * How long a frame is, in milliseconds, or zero for twenty.
     *
     * Twenty is what every peer expects and what every codec here cuts
     * cleanly. Opus has a fixed set of frame durations and encodes nothing
     * else, so an interval it has no size for is refused while Opus is one of
     * the codecs offered.
     */
    uint32_t frame_ms;
    /**
     * Whether to offer RFC 4733 named events, as a `SipralToggle`. On by
     * default: a phone that cannot send a digit cannot navigate a menu.
     */
    uint32_t offer_dtmf;
    /**
     * Whether to ask for RFC 5761 multiplexing, as a `SipralToggle`.
     *
     * Off by default. §5.1.1 only permits it where both ends asked, and the
     * equipment this stack is deployed against does not; asking unasked costs
     * a line in every offer and buys a port on the calls where nobody answers.
     */
    uint32_t offer_rtcp_mux;
    /**
     * Whether to stop sending during silence, as a `SipralToggle`.
     *
     * Off by default. It halves the bandwidth of a call in which one person is
     * listening, and it costs the far end's own stall watchdog a reason to
     * fire — this stack sends no comfort noise of its own to say the silence
     * is deliberate, so a gap looks the same from there as a stream that died.
     */
    uint32_t silence_suppression;
    /**
     * Whether inbound audio that stops is reported, as a `SipralToggle`. On by
     * default; this is B5.
     */
    uint32_t media_stall_watchdog;
    /**
     * How long inbound audio may stop before that is reported, in
     * milliseconds, or zero for this build's own figure.
     *
     * Setting it with the watchdog switched off is
     * `SIPRAL_STATUS_INVALID_ARGUMENT` rather than a value nothing reads.
     */
    uint64_t media_stall_ms;
    /**
     * What the wall clock read when the stack was created, as seconds since
     * 1 January 1970, or zero.
     *
     * The one number a stack that reads no clock cannot work out: RFC 3550
     * §6.4.1 has a sender report carry "the wall clock time when this report
     * was sent", and a monotonic instant is not one. Zero means the reports
     * count from the Unix epoch, which costs nothing a caller is likely to
     * miss — the round trip the far end computes is a difference, not an
     * absolute — and costs the correlation of this call's media with anything
     * else's.
     */
    uint64_t media_clock_unix_seconds;
    /**
     * Thirty-two more bytes of entropy, for the media keys, and **not
     * the same bytes as `entropy`**.
     *
     * Every SRTP master key this stack offers or answers with is derived
     * from these and from nothing else. They are a second draw rather
     * than a slice of the first because a replay recording writes
     * `entropy` into the file in clear: one generator for both would put
     * every key the stack will ever offer into every recording it makes.
     *
     * Handing the same bytes twice is refused rather than accepted
     * quietly. This is the only place in the library that can see both.
     */
    const uint8_t *media_seed;
    /**
     * How many bytes of it. Thirty-two.
     */
    size_t media_seed_len;
    /**
     * What every call on this stack does about SRTP unless
     * `sipral_call_config_t::srtp` says otherwise for it: a
     * `SipralSrtp`, or zero for this build's own built-in default, which
     * is `SIPRAL_SRTP_NOT_OFFERED` — nothing here offers encryption
     * until it is asked to. Any other value is
     * `SIPRAL_STATUS_INVALID_ARGUMENT`, and nothing is built.
     */
    uint32_t srtp;
    /**
     * What every call on this stack does about ICE unless
     * `sipral_call_config_t::ice` says otherwise for it: a `SipralIce`,
     * or zero for this build's own built-in default, which is
     * `SIPRAL_ICE_OFF` — nothing here offers ICE until it is asked to,
     * for the reason `docs/06-nat.md` tabulates. Any other value is
     * `SIPRAL_STATUS_INVALID_ARGUMENT`, and nothing is built.
     *
     * Appended at the tail (task 8.6.16); the pinned `MIN_SIZE` is
     * unmoved.
     */
    uint32_t ice;
    /**
     * What this stack does about a NAT in front of it: a `SipralNat`, or
     * zero for this build's own built-in default, which is
     * `SIPRAL_NAT_OFF`. `SIPRAL_NAT_STUN` asks `stun_server` where each
     * socket appears from and writes the answer where a far end reads
     * it — see crate::nat. Any other value is
     * `SIPRAL_STATUS_INVALID_ARGUMENT`, and nothing is built.
     *
     * Appended at the tail (task 8.5.5), with the two below; the pinned
     * `MIN_SIZE` is unmoved.
     */
    uint32_t nat;
    /**
     * The STUN server `SIPRAL_NAT_STUN` asks, as `host:port`: an
     * address, not a name, since resolving one is the application's.
     * Required with `SIPRAL_NAT_STUN` and refused without it, since a
     * server nothing asks is a setting nothing reads. Copied; the
     * caller's buffer is its own again when this returns.
     */
    const char *stun_server;
    /**
     * How many bytes of it.
     */
    size_t stun_server_len;
    /**
     * Whether G.729's Annex B — silence compression: SID frames and
     * nothing in a pause, and the comfort noise both ends make from
     * them — is allowed on this stack's calls, as a `SipralToggle`. On
     * by default, which is what `G729` means with no parameter (RFC
     * 4856 §2.1.9): an offer says `annexb=yes`, and an answer says
     * `yes` only where the offer allowed it. Off, both say `annexb=no`,
     * which RFC 3551 §4.5.6 makes the far end's cue to send no SID
     * frames, and this end sends none either. A per-call codec order
     * keeps the stack's setting. Nothing changes for a call that does
     * not run G.729, so the setting is taken whatever `codecs` names:
     * a call's own order may name G.729 when the stack's does not.
     *
     * Appended at the tail (task 8.6.15); the pinned `MIN_SIZE` is
     * unmoved.
     */
    uint32_t g729_annex_b;
    /**
     * A TURN server (RFC 8656) to allocate a relay on for every media
     * socket `sipral_stack_nat_map` names, as `host:port`: an address,
     * not a name. The relay becomes the relayed ICE candidate of the call
     * placed, rung or answered on that socket — the path of last resort,
     * used only when no cheaper pair answers — and goes back to the
     * server when the call ends. See crate::nat.
     *
     * Optional, and only with `SIPRAL_NAT_STUN`, since it rides on the
     * same media-socket calls; it may be the same address as
     * `stun_server`. `turn_username` and `turn_password` are then
     * required: a TURN server that hands out relays to anyone is one
     * somebody else is already using. `SIPRAL_STATUS_NOT_SUPPORTED` in
     * a build without `SIPRAL_FEATURE_ICE`, which is the only thing that
     * can use a relay. Copied; the caller's buffer is its own again when
     * this returns.
     *
     * Appended at the tail (task 8.5.5), with the five below; the pinned
     * `MIN_SIZE` is unmoved.
     */
    const char *turn_server;
    /**
     * How many bytes of it.
     */
    size_t turn_server_len;
    /**
     * The user name of the long-term credential the TURN server knows
     * this end by (RFC 8489 §9.2).
     */
    const char *turn_username;
    /**
     * How many bytes of it.
     */
    size_t turn_username_len;
    /**
     * Its password. Copied into memory that is overwritten when the
     * stack is destroyed, and never written to a log, an event or an
     * error text.
     */
    const char *turn_password;
    /**
     * How many bytes of it.
     */
    size_t turn_password_len;
};

/**
 * What one call to sipral_stack_poll did.
 *
 * Set `size` to `sizeof(sipral_poll_result_t)` before the call.
 */
struct sipral_poll_result {
    /**
     * How many bytes of this struct the library filled in.
     */
    size_t size;
    /**
     * Events handed to the callback during this poll.
     */
    size_t events_delivered;
    /**
     * Events the stack raised that this ABI has no word for yet.
     *
     * Counted rather than delivered: an event carrying nothing a binding can
     * act on is noise, and a number that is not zero is the honest measure of
     * how far this vocabulary is behind the stack's.
     */
    size_t events_unclaimed;
    /**
     * Bytes the stack produced and this build had nowhere to send.
     *
     * Zero since crate::transport gave them somewhere to go: what the stack
     * writes waits in it until `sipral_stack_poll_transmit` takes it, and a
     * poll no longer empties the queue on its way past. The member stays
     * because a released one always does, and because a build that has to drop
     * a message again would have somewhere to say so.
     */
    size_t transmits_discarded;
    /**
     * Whether there is a deadline at all. Zero means nothing is scheduled and
     * the next poll can wait for input.
     */
    uint32_t has_deadline;
    /**
     * How long from `now_ms` until the stack has something to do, when
     * `has_deadline` says there is one. Zero means it is already due.
     */
    uint64_t next_poll_in_ms;
};

/**
 * What a stack is actually running with.
 *
 * A configuration call that answers `SIPRAL_STATUS_OK` has applied what it was
 * given, and this is where the caller reads back what that came to. It matters
 * because a zero in the config means "the default": a caller that left the
 * timers alone has no other way to learn which figures it is retransmitting
 * on, and one that set them has no other way to be sure.
 *
 * Set `size` to `sizeof(sipral_stack_settings_t)` before the call.
 */
struct sipral_stack_settings {
    /**
     * How many bytes of this struct the library filled in.
     */
    size_t size;
    /**
     * The sipral_transport_t this stack speaks.
     */
    uint32_t transport;
    /**
     * Whether this stack retransmits anything itself.
     *
     * Zero on a transport that delivers for us, which is every one but UDP.
     * The two timers that only exist to pace a retransmission read as their
     * defaults there, and mean nothing.
     */
    uint32_t retransmits;
    /**
     * T1 in milliseconds, with the default filled in.
     */
    uint64_t timer_t1_ms;
    /**
     * T2 in milliseconds, with the default filled in.
     */
    uint64_t timer_t2_ms;
    /**
     * T4 in milliseconds, with the default filled in.
     */
    uint64_t timer_t4_ms;
    /**
     * How many codecs this stack offers. `sipral_stack_codec_order` says
     * which, and in what order.
     */
    size_t codec_count;
    /**
     * How long a frame is, with the default filled in.
     */
    uint32_t frame_ms;
    /**
     * Whether named events are offered, as a `SipralToggle`. Never the
     * default value: this says what the setting came to, not what was passed.
     */
    uint32_t offer_dtmf;
    /**
     * Whether RTCP multiplexing is asked for, as a `SipralToggle`.
     */
    uint32_t offer_rtcp_mux;
    /**
     * Whether sending stops during silence, as a `SipralToggle`.
     */
    uint32_t silence_suppression;
    /**
     * How long inbound audio may stop before it is reported, with the default
     * filled in. Zero when the watchdog is off, which is the one case where
     * there is no figure to give.
     */
    uint64_t media_stall_ms;
    /**
     * Whether G.729's Annex B is allowed, as a `SipralToggle`, with the
     * default filled in.
     *
     * Appended at the tail (task 8.6.15); the pinned `MIN_SIZE` is
     * unmoved.
     */
    uint32_t g729_annex_b;
};

/**
 * One header field an application hands over: a name and a value, UTF-8,
 * neither NUL-terminated.
 *
 * Always an element of an array whose length travels beside it, which is
 * why it carries no `size`: an array is strided by the length of its
 * element, so a member appended here would move every element after the
 * first. A header field is a name and a value, and this never grows.
 */
struct sipral_header {
    /**
     * The field name, `X-Conversation-Id`. A compact form is the field it
     * abbreviates.
     */
    const char *name;
    /**
     * How many bytes of it.
     */
    size_t name_len;
    /**
     * The value, as it goes on the line after the colon. Null or empty
     * for a field with an empty value.
     */
    const char *value;
    /**
     * How many bytes of it.
     */
    size_t value_len;
};

/**
 * What an account is configured with.
 *
 * Set `size` to `sizeof(sipral_account_config_t)` and zero the rest before
 * filling anything in.
 */
struct sipral_account_config {
    /**
     * `sizeof` this struct, as the caller's header declares it.
     */
    size_t size;
    /**
     * The address of record, `sip:alice@example.com`. UTF-8, not
     * NUL-terminated.
     */
    const char *aor;
    /**
     * How many bytes of it.
     */
    size_t aor_len;
    /**
     * Where the REGISTER is addressed, `sip:example.com`, no user part.
     *
     * A `registrar_len` of zero makes an account that never registers: a
     * trunk that knows this end by the address its requests come from.
     * Its state is `SIPRAL_REGISTRATION_STATE_NOT_REGISTERING` for as long
     * as it exists, and `sipral_account_register` refuses it.
     */
    const char *registrar;
    /**
     * How many bytes of it.
     */
    size_t registrar_len;
    /**
     * Where this endpoint can be reached, as it goes in `Contact`.
     */
    const char *contact;
    /**
     * How many bytes of it.
     */
    size_t contact_len;
    /**
     * Where this account's requests go, as `host:port`: the registrar's
     * address for an account that registers, and the outbound proxy for
     * one configured with no registrar. A call that names no destination
     * of its own goes here either way, so it is required either way. An
     * address, not a name: RFC 3263 resolution is the caller's.
     */
    const char *registrar_address;
    /**
     * How many bytes of it.
     */
    size_t registrar_address_len;
    /**
     * The display name that goes in `From`, or null for none.
     */
    const char *display_name;
    /**
     * How many bytes of it.
     */
    size_t display_name_len;
    /**
     * The user name to answer a challenge with, or null for an account that
     * answers none.
     */
    const char *auth_user;
    /**
     * How many bytes of it.
     */
    size_t auth_user_len;
    /**
     * The password that goes with it. Copied out of the caller's memory; what
     * happens to the caller's copy is the caller's.
     */
    const char *auth_password;
    /**
     * How many bytes of it.
     */
    size_t auth_password_len;
    /**
     * The `+sip.instance` URN of RFC 5626 §4.1, or null for none.
     */
    const char *instance_id;
    /**
     * How many bytes of it.
     */
    size_t instance_id_len;
    /**
     * How long a binding to ask for, or zero for an hour.
     *
     * A `delta-seconds`, so §20.19 bounds it at 2³²−1 and anything above that
     * is refused rather than sent as a number no registrar will read. What the
     * registrar grants wins over the request either way, and the granted
     * figure is what `sipral_registration_event_t::expires_ms` carries — that
     * is where the effective value is read back, not here.
     */
    uint64_t expires_seconds;
    /**
     * Header fields to put on every REGISTER this account sends, in the
     * order given, or null for none.
     *
     * Checked when the account is added, as `sipral_call_config_t::headers`
     * is, against what the stack writes on a REGISTER: `Expires` is the
     * stack's there, because it is `expires_seconds`, and `Supported` is the
     * application's, because a registration asking for a GRUU has to say
     * so. Refused for an account with no registrar, which sends no REGISTER
     * to put them on.
     */
    const sipral_header_t *headers;
    /**
     * How many elements `headers` has.
     */
    size_t headers_len;
    /**
     * Which transport this account's REGISTER and every request it
     * places go out on: SIPRAL_TRANSPORT_MAIN
     * for zero, which is what a caller that leaves this at zero already
     * gets, or a further number
     * sipral_stack_transport_bind
     * has bound. A number this stack has never bound is
     * `SIPRAL_STATUS_INVALID_ARGUMENT`, naming it.
     *
     * Appended at the tail (task 8.4.10); the pinned `MIN_SIZE` is
     * unmoved, and what a caller built before this member existed never
     * sent reads as the zero that already means "the main transport".
     */
    uint32_t transport;
    /**
     * The push notification service to be woken through, as its
     * registered name: `apns`, `fcm`, `webpush` (RFC 8599 §4.1.1). Null
     * for an account that is not woken by push, which is every account on
     * a machine that does not suspend.
     *
     * These four go on the `Contact` of this account's REGISTER and on no
     * other request, ever: §4.1 says so because a `pn-prid` in the
     * `Contact` of an INVITE hands the far end a token that wakes this
     * device whenever it likes. The de-registration that gives the binding
     * up leaves the identifier out, which §4.1.2 also requires.
     */
    const char *push_provider;
    /**
     * How many bytes of it.
     */
    size_t push_provider_len;
    /**
     * The resource identifier the service issued for this installation —
     * the device token. Required when `push_provider` is given, and
     * refused without one.
     *
     * Whatever it holds is percent-escaped where the SIP grammar needs it
     * (§8.7), because an APNs token carries `=` and a Web Push identifier
     * is a whole URL.
     */
    const char *push_prid;
    /**
     * How many bytes of it.
     */
    size_t push_prid_len;
    /**
     * The extra value a service needs beside the identifier: the
     * application bundle for Apple, the sender for Firebase. §4.1.1 makes
     * it mandatory "if required for the specific PNS", so it is optional
     * here and the service decides.
     */
    const char *push_param;
    /**
     * How many bytes of it.
     */
    size_t push_param_len;
    /**
     * Nonzero to say this device can send a binding refresh without being
     * woken by a push, which §4.1.4 makes it declare with a
     * `+sip.pnsreg` media feature tag.
     *
     * It is the application's fact and not this library's to guess: a
     * process the operating system has suspended has no timer that runs,
     * and one that claims otherwise gets a registrar that stops sending
     * the wake-ups the device is relying on.
     */
    uint32_t push_wakes_itself;
    /**
     * Where this account's end-of-call voice quality reports go (RFC
     * 6035, carried by a PUBLISH, RFC 3903), or null to send none.
     *
     * Appended at the tail (task 8.6.9); the pinned `MIN_SIZE` is
     * unmoved, and what a caller built before this member existed
     * never sent reads as the null that already means "send none".
     */
    const char *quality_report_uri;
    /**
     * How many bytes of it.
     */
    size_t quality_report_uri_len;
};

/**
 * What a call is placed with.
 *
 * Set `size` to `sizeof(sipral_call_config_t)` and zero the rest before
 * filling anything in.
 */
struct sipral_call_config {
    /**
     * `sizeof` this struct, as the caller's header declares it.
     */
    size_t size;
    /**
     * Who to call, as a URI. UTF-8, not NUL-terminated.
     */
    const char *target;
    /**
     * How many bytes of it.
     */
    size_t target_len;
    /**
     * The session description to offer, for a call this stack manages no
     * audio for.
     *
     * Exactly one of this and `media_address` is set. Two descriptions of one
     * session is one too many, and neither is a call whose answer would have
     * to be written into the ACK.
     */
    const uint8_t *sdp;
    /**
     * How many bytes of it.
     */
    size_t sdp_len;
    /**
     * Where to send the INVITE, as `host:port`, or null to send it where the
     * account registers — which is the outbound proxy for a registered line,
     * and the reason a phone behind a NAT works at all.
     */
    const char *destination;
    /**
     * How many bytes of it.
     */
    size_t destination_len;
    /**
     * Whether to keep every branch a proxy forks the INVITE into. Zero keeps
     * the first that answers and hangs up the rest, which is what a telephone
     * does.
     */
    uint32_t keep_all_forks;
    /**
     * Where this end will receive media, as `host:port`, for a call this
     * stack describes and runs the audio of.
     *
     * The application owns the socket, so it is the only one that can say. Set
     * it and the offer is written from this stack's codec order, the answer is
     * read, and the call gets a media session that `crate::media` and
     * `crate::record` reach. Leave it null and set `sdp` instead for a call
     * where the application describes its own session and runs its own RTP.
     */
    const char *media_address;
    /**
     * How many bytes of it.
     */
    size_t media_address_len;
    /**
     * Header fields to put on the INVITE, in the order given, or null for
     * none.
     *
     * Each is checked before anything is built: the name a token, the value
     * one line of text, and not a field the stack writes on a call itself.
     * Those are listed in `docs/04-ua.md` with the reason for each, and
     * `User-Agent` joins them when `sipral_stack_config_t::user_agent` is
     * set. A refusal is `SIPRAL_STATUS_INVALID_ARGUMENT` naming the element,
     * and no call.
     */
    const sipral_header_t *headers;
    /**
     * How many elements `headers` has.
     */
    size_t headers_len;
    /**
     * What this call does about SRTP, overriding
     * `sipral_stack_config_t::srtp` for it: a `SipralSrtp`, or zero to
     * take the stack's own setting. Any other value is
     * `SIPRAL_STATUS_INVALID_ARGUMENT`, and nothing is built.
     *
     * Read only for a call this stack describes the media of —
     * `media_address` set — and otherwise not this ABI's to act on: a
     * call placed with `sdp` is a session the application wrote, and
     * SRTP in it is the application's own line to write or not.
     */
    uint32_t srtp;
    /**
     * Which transport the INVITE goes out on, read only together with
     * `destination`: SIPRAL_TRANSPORT_MAIN
     * for zero, or a further number
     * sipral_stack_transport_bind
     * has bound. Nonzero with `destination` null is
     * `SIPRAL_STATUS_INVALID_ARGUMENT`: a call with no destination
     * override already goes out on its account's own transport, and
     * there is nothing to combine this with.
     *
     * Appended at the tail (task 8.4.10); the pinned `MIN_SIZE` is
     * unmoved.
     */
    uint32_t transport;
    /**
     * What this call offers and in what order, overriding
     * `sipral_stack_config_t::codecs` for it: codec names separated by
     * commas, as `sipral_codec_info_t::name` spells them, UTF-8 and not
     * NUL-terminated. Null for the stack's own order.
     *
     * Everything else the stack's catalogue carries — frame length,
     * named events, multiplexing, and SRTP where `srtp` here does not
     * override it — is kept, because a call that names its codecs has
     * said nothing about any of those. A name this build has no encoder
     * for, a name given twice, and a stray comma are each
     * `SIPRAL_STATUS_INVALID_ARGUMENT` naming what was wrong, and no
     * call.
     *
     * Read only for a call this stack describes the media of —
     * `media_address` set — for the reason `srtp` gives: a call placed
     * with `sdp` is a session the application wrote, and the order in it
     * is already the application's own. The names are still checked, so
     * that a caller who has one wrong learns it here either way.
     *
     * Appended at the tail (task 8.4.13); the pinned `MIN_SIZE` is
     * unmoved.
     */
    const char *codecs;
    /**
     * How many bytes of it.
     */
    size_t codecs_len;
    /**
     * What this call does about ICE, overriding
     * `sipral_stack_config_t::ice` for it: a `SipralIce`, or zero to
     * take the stack's own setting. Any other value is
     * `SIPRAL_STATUS_INVALID_ARGUMENT`, and nothing is built.
     *
     * Read only for a call this stack describes the media of —
     * `media_address` set — for the reason `srtp` gives: a call placed
     * with `sdp` is a session the application wrote, and the candidates
     * in it are already the application's own to write or not.
     *
     * Appended at the tail (task 8.6.16); the pinned `MIN_SIZE` is
     * unmoved.
     */
    uint32_t ice;
};

/**
 * One codec this build contains.
 *
 * Set `size` to `sizeof(sipral_codec_info_t)` before the call.
 */
struct sipral_codec_info {
    /**
     * How many bytes of this struct the library filled in.
     */
    size_t size;
    /**
     * A sipral_codec_t.
     */
    uint32_t codec;
    /**
     * The RTP timestamp clock, in hertz, which is what goes on the
     * `a=rtpmap` line.
     */
    uint32_t clock_rate;
    /**
     * The rate the codec actually hears at, which is what the samples crossing
     * this ABI are in. G.722's two differ, and RFC 3551 §4.5.2 says so.
     */
    uint32_t sample_rate;
    /**
     * The payload type RFC 3551 table 4 assigns it, when it has one.
     */
    uint32_t static_payload_type;
    /**
     * Whether it has one. Opus does not: it is newer than the table and
     * always travels as a dynamic type.
     */
    uint32_t has_static_payload_type;
};

/**
 * One codec this call could have used, and what became of it.
 *
 * Set `size` to `sizeof(sipral_codec_candidate_t)` before the call.
 *
 * The list is what the negotiation itself decided, kept from the moment
 * it decided it. It is not worked out again when it is asked for, because
 * a second run against a description that has since been renegotiated
 * would disagree with the first in exactly the case somebody is
 * debugging.
 */
struct sipral_codec_candidate {
    /**
     * How many bytes of this struct the library filled in.
     */
    size_t size;
    /**
     * A sipral_codec_t: the candidate itself.
     */
    uint32_t codec;
    /**
     * A sipral_codec_outcome_t: what became of it.
     */
    uint32_t outcome;
    /**
     * A sipral_codec_t: what beat it, when `outcome` is
     * `SIPRAL_CODEC_OUTCOME_OUTRANKED`. `SIPRAL_CODEC_UNKNOWN`
     * otherwise, because nothing beat a codec that was never named and
     * nothing beat the one that won.
     */
    uint32_t outranked_by;
};

/**
 * What one call's media settled on, and what it is doing now.
 *
 * A4's reporting half and as much of D5 as this stack knows: the codec that
 * was agreed, the number it travels under, and the shape of the stream around
 * it. What is deliberately not here is why each other candidate lost —
 * RFC 3264 §6.1 leaves that decision with the peer, and a reason invented on
 * this side would be a reason nobody can act on.
 *
 * Set `size` to `sizeof(sipral_media_info_t)` before the call.
 */
struct sipral_media_info {
    /**
     * How many bytes of this struct the library filled in.
     */
    size_t size;
    /**
     * A sipral_codec_t: what the two ends agreed on.
     */
    uint32_t codec;
    /**
     * The payload type on the wire. It is the offer's own number and not
     * necessarily ours: the two ends pick their own numbers for a format
     * with no static one, so a peer that numbers it 111 has said what we
     * say with 96.
     */
    uint32_t payload_type;
    /**
     * The RTP timestamp clock, in hertz.
     */
    uint32_t clock_rate;
    /**
     * The rate the samples crossing this ABI are at.
     */
    uint32_t sample_rate;
    /**
     * How long a frame is, in milliseconds.
     */
    uint32_t frame_ms;
    /**
     * Samples in one frame: exactly what sipral_media_playback fills and
     * what sipral_media_capture wants.
     */
    size_t frame_samples;
    /**
     * A sipral_direction_t.
     */
    uint32_t direction;
    /**
     * Whether this end is meant to be sending. Zero while it holds the far
     * end, or while the far end has refused to receive.
     */
    uint32_t sending;
    /**
     * Whether this end is meant to be receiving.
     */
    uint32_t receiving;
    /**
     * Whether RFC 4733 named events were agreed.
     */
    uint32_t has_dtmf;
    /**
     * The payload type they travel under, when they were.
     */
    uint32_t dtmf_payload_type;
    /**
     * A sipral_rtcp_t.
     */
    uint32_t rtcp;
    /**
     * Whether the stream is keyed.
     */
    uint32_t secured;
    /**
     * Whether a recording is running on this call.
     */
    uint32_t recording;
    /**
     * How much audio it has taken.
     */
    uint64_t recorded_ms;
    /**
     * Whether the watchdog currently considers inbound audio stopped.
     */
    uint32_t stalled;
};

/**
 * What one call's media has cost, and what it is costing now.
 *
 * A6. Cheap enough to read at the frame rate of a user interface — everything
 * in it is already counted and nothing walks a history — and complete enough
 * to keep as the record of a call, which is the same struct delivered with
 * `SIPRAL_EVENT_KIND_MEDIA_STATISTICS` when the call ends.
 *
 * The three delays are in microseconds and not milliseconds. Jitter on a
 * healthy call is a fraction of a millisecond, and a figure that reads zero
 * whenever things are going well is a figure nobody looks at twice.
 *
 * Set `size` to `sizeof(sipral_stream_stats_t)` before the call.
 */
struct sipral_stream_stats {
    /**
     * How many bytes of this struct the library filled in.
     */
    size_t size;
    /**
     * A sipral_codec_t: what the call settled on, which is the first thing
     * anybody looking at a bad call wants to know.
     */
    uint32_t codec;
    /**
     * Whether a round-trip time is known. Zero until a report has come back,
     * which on a short call may be never: the first one is deliberately
     * delayed (RFC 3550 §6.2) and a peer that sends no RTCP never provides
     * one.
     */
    uint32_t has_round_trip;
    /**
     * The round trip, from RTCP.
     */
    uint64_t round_trip_us;
    /**
     * Packets this end has put on the wire.
     */
    uint64_t packets_sent;
    /**
     * Payload octets in them, not counting headers.
     */
    uint64_t octets_sent;
    /**
     * Packets taken in and held for playout.
     */
    uint64_t packets_received;
    /**
     * Sequence numbers that came due with nothing in them.
     */
    uint64_t packets_lost;
    /**
     * Packets that arrived behind the playout point.
     */
    uint64_t packets_late;
    /**
     * Packets thrown out of the window before they could be played.
     */
    uint64_t packets_overflowed;
    /**
     * Packets whose sequence number was already held.
     */
    uint64_t packets_duplicated;
    /**
     * Packets accepted after a higher sequence number had already arrived.
     */
    uint64_t packets_reordered;
    /**
     * Frames dropped in a pause to bring the delay down. Deliberate, and
     * inaudible when the pause is real.
     */
    uint64_t frames_shrunk;
    /**
     * Frames the concealment was asked to invent in a pause to push the delay
     * up.
     */
    uint64_t frames_stretched;
    /**
     * How far behind the newest packet the playout point is: the delay the
     * far end's voice is actually suffering.
     */
    uint64_t delay_us;
    /**
     * What the buffer is aiming at, from the arrival times it has seen.
     */
    uint64_t target_delay_us;
    /**
     * Interarrival jitter, the smoothed mean deviation of transit time
     * (RFC 3550 §6.4.1).
     */
    uint64_t jitter_us;
    /**
     * Frames concealed as a fraction of frames played, over the last ten
     * seconds or so. The counters above say what the call has cost; this says
     * whether it is bad right now.
     */
    float loss_rate;
    /**
     * One number for a bar on a screen: a hundred for a call with nothing
     * wrong with it, zero for one nobody can hold. Not a mean opinion score,
     * and deliberately not shaped like one.
     */
    float score;
    /**
     * Whether the numbers say this call is in trouble now.
     */
    uint32_t suffering;
    /**
     * How long since a packet last arrived. A live call sits at one frame.
     */
    uint64_t silent_for_ms;
    /**
     * Whether an RFC 3611 VoIP Metrics report is available at all —
     * zero until this stream has identified a source to report on.
     * Every `voip_*` member below is meaningless while this is zero.
     *
     * Appended at the tail (task 8.6.9); the pinned `MIN_SIZE` is
     * unmoved, and what a caller built before these members existed
     * never sent reads them all as zero, this one included.
     */
    uint32_t has_voip_metrics;
    /**
     * RFC 3611 SS4.7.1's loss rate, as its own 256ths (multiply by
     * 100 and divide by 256 for a percentage).
     */
    uint32_t voip_loss_rate_256;
    /**
     * RFC 3611 SS4.7.1's discard rate, as its own 256ths.
     */
    uint32_t voip_discard_rate_256;
    /**
     * RFC 3611 SS4.7.2's burst density, as its own 256ths.
     */
    uint32_t voip_burst_density_256;
    /**
     * RFC 3611 SS4.7.2's mean burst duration.
     */
    uint64_t voip_burst_duration_us;
    /**
     * RFC 3611 SS4.7.2's gap density, as its own 256ths.
     */
    uint32_t voip_gap_density_256;
    /**
     * RFC 3611 SS4.7.2's mean gap duration.
     */
    uint64_t voip_gap_duration_us;
    /**
     * RFC 3611 SS4.7.2's `Gmin`: the burst/gap classification
     * threshold this stream's jitter buffer used, fixed for the
     * stream's whole life.
     */
    uint32_t voip_gmin;
    /**
     * RFC 3611 SS4.7.3's end-system delay. Zero for every build of
     * this stack today: SS4.7.3 defines it as the sending side's own
     * accumulation and encoding delay added to the receiving side's,
     * and nothing here has visibility into the sending side's half.
     */
    uint64_t voip_end_system_delay_us;
    /**
     * RFC 3611 SS4.7.7's nominal jitter buffer delay.
     */
    uint64_t voip_jitter_buffer_nominal_us;
    /**
     * RFC 3611 SS4.7.7's current maximum jitter buffer delay.
     */
    uint64_t voip_jitter_buffer_maximum_us;
    /**
     * RFC 3611 SS4.7.7's absolute maximum jitter buffer delay.
     */
    uint64_t voip_jitter_buffer_abs_max_us;
    /**
     * Whether `voip_r_factor` is available: zero when the active
     * codec is one ITU-T G.113 tabulates no `Ie`/`Bpl` for (RFC 3611
     * SS4.7.5's own `127` "unavailable" sentinel).
     */
    uint32_t has_voip_r_factor;
    /**
     * RFC 3611 SS4.7.5's R factor, `0..=100`.
     */
    uint32_t voip_r_factor;
    /**
     * Whether `voip_mos_lq_x10` is available, for the same reason as
     * `has_voip_r_factor`.
     */
    uint32_t has_voip_mos_lq;
    /**
     * RFC 3611 SS4.7.5's estimated listening-quality MOS, in tenths
     * (`14..=50`).
     */
    uint32_t voip_mos_lq_x10;
    /**
     * Whether `voip_mos_cq_x10` is available, for the same reason.
     */
    uint32_t has_voip_mos_cq;
    /**
     * RFC 3611 SS4.7.5's estimated conversational-quality MOS, in
     * tenths.
     */
    uint32_t voip_mos_cq_x10;
};

/**
 * One datagram on its way out, written into the caller's own buffers.
 *
 * The caller fills in `size`, the two pointers and the two capacities; the
 * library fills in the two lengths and the bytes. A `len` of zero means there
 * was nothing to send, which on a capture is an ordinary answer: this end may
 * be holding the far end, or silence suppression may have swallowed the frame.
 *
 * Both buffers are checked before anything is produced. A packet that was
 * built and then had nowhere to go would be a packet missing from a stream
 * whose timestamps had already moved past it.
 */
struct sipral_media_packet {
    /**
     * `sizeof` this struct, as the caller's header declares it.
     */
    size_t size;
    /**
     * Where to write the packet. At least SIPRAL_MEDIA_PACKET_BYTES.
     */
    uint8_t *data;
    /**
     * How much room `data` has.
     */
    size_t capacity;
    /**
     * How much was written. Zero means there was nothing to send.
     */
    size_t len;
    /**
     * Where to write the destination, as `host:port` with a trailing NUL. Null
     * with a capacity of zero for a caller that does not want it.
     */
    char *destination;
    /**
     * How much room `destination` has. At least SIPRAL_ADDRESS_BYTES when
     * it is not null.
     */
    size_t destination_capacity;
    /**
     * How many bytes of it were written, the NUL not counted.
     */
    size_t destination_len;
};

/**
 * What sipral_processor_callback_t is handed for one call: an ordinary
 * frame to process, or a request to forget what has been learned.
 *
 * Filled by the library and handed to the callback as a `const`
 * pointer, the same shape crate::screening::SipralScreenRequest is:
 * read `size` before anything past it, and read nothing once the
 * callback has returned — `near_end`, `far_end` and `out` borrow from
 * buffers that belong to this one call and are not this ABI's to keep
 * alive a moment longer.
 */
struct sipral_processor_frame {
    /**
     * How many bytes of this struct the library filled in.
     */
    size_t size;
    /**
     * 0 for an ordinary frame; 1 for a request to forget whatever state
     * the processor holds — a device change or a codec change mid-call
     * asks for this, and `near_end`, `far_end` and `out`, with the three
     * lengths beside them, are all null and zero when it is set.
     */
    uint32_t reset;
    /**
     * The frame just captured from the microphone. Null when `reset` is
     * set.
     */
    const int16_t *near_end;
    /**
     * How many samples `near_end` is. Always the same number as
     * `far_end_len` and `out_len` — carried three times, once beside
     * each buffer, because that is the one buffer each binding marshals
     * on its own. 0 when `reset` is set.
     */
    size_t near_end_len;
    /**
     * The far-end audio rendered to the loudspeaker over the same span
     * of time as `near_end`, the same length. Null when `reset` is set.
     */
    const int16_t *far_end;
    /**
     * How many samples `far_end` is. See `near_end_len`. 0 when `reset`
     * is set.
     */
    size_t far_end_len;
    /**
     * Where the callback writes the frame that replaces `near_end` —
     * every sample of it, since what is not written is read back as
     * whatever was there before. Null when `reset` is set, since there
     * is nothing to write.
     */
    int16_t *out;
    /**
     * How many samples `out` has room for, which is also how many the
     * callback has to write. See `near_end_len`. 0 when `reset` is set.
     */
    size_t out_len;
};

/**
 * One message on its way out, written into the caller's own buffers.
 *
 * The caller fills in `size`, the three pointers and the three capacities; the
 * library fills in everything else. A `len` of zero means the stack had nothing
 * to send, which is how the draining loop ends.
 *
 * The two address buffers are checked before a message is taken, so the address
 * side is never the reason one is held. The payload buffer is not: a message
 * too long for it is kept and offered again, because a message the stack has
 * already committed to is not one this ABI may drop.
 */
struct sipral_transmit {
    /**
     * `sizeof` this struct, as the caller's header declares it.
     */
    size_t size;
    /**
     * Which transport to write to: SIPRAL_TRANSPORT_MAIN for a stack
     * that never bound another, or the number
     * sipral_stack_transport_bind gave whichever account or call
     * this message belongs to.
     */
    uint32_t transport;
    /**
     * What that transport speaks, as a `SipralTransport`.
     *
     * Carried because it is the message's and not the socket's: §18.1.1 lets a
     * request that outgrew a datagram go out on a stream instead, and the
     * transport it ends up on is the one this says. Zero for a protocol this
     * ABI has no number for.
     */
    uint32_t protocol;
    /**
     * Where to write the message. Nothing is written unless the whole of it
     * fits.
     */
    uint8_t *data;
    /**
     * How much room `data` has.
     */
    size_t capacity;
    /**
     * How much was written — or, when the call answered
     * `SIPRAL_STATUS_BUFFER_TOO_SMALL`, how much room the message needs.
     */
    size_t len;
    /**
     * Where to write the destination, as `host:port` with a trailing NUL. Null
     * with a capacity of zero for a caller whose socket is connected and
     * already knows.
     */
    char *destination;
    /**
     * How much room `destination` has. At least SIPRAL_ADDRESS_BYTES when
     * it is not null.
     */
    size_t destination_capacity;
    /**
     * How many bytes of it were written, the NUL not counted.
     */
    size_t destination_len;
    /**
     * Where to write the address to send *from*, in the same shape.
     *
     * RFC 3581 §4: "The response MUST be sent from the same address and port
     * that the corresponding request was received on", which a caller listening
     * on a wildcard address cannot work out for itself. Empty — a `source_len`
     * of zero — means the transport's own address, which is the answer for
     * every request this stack originates.
     */
    char *source;
    /**
     * How much room `source` has. At least SIPRAL_ADDRESS_BYTES when it is
     * not null.
     */
    size_t source_capacity;
    /**
     * How many bytes of it were written, the NUL not counted.
     */
    size_t source_len;
};

/**
 * What a SIPRAL_EVENT_KIND_REGISTRATION_CHANGED carries.
 */
struct sipral_registration_event {
    /**
     * A sipral_registration_state_t.
     */
    uint32_t state;
    /**
     * A sipral_registration_failure_t, zero when nothing failed.
     */
    uint32_t failure;
    /**
     * The status the registrar answered with, or zero when none arrived.
     */
    uint32_t status_code;
    /**
     * The binding's granted lifetime, zero unless it is live.
     */
    uint64_t expires_ms;
    /**
     * How long until the refresh, zero unless one is scheduled.
     */
    uint64_t refresh_in_ms;
    /**
     * How long until the next attempt. Only meaningful while the state is
     * retrying, which is exactly when the stack is going to try again.
     */
    uint64_t retry_in_ms;
};

/**
 * What every call event carries.
 *
 * Not every member means something in every kind, and the ones that do not
 * are zero. A zero here always reads as absent rather than as a value.
 */
struct sipral_call_event {
    /**
     * A sipral_call_state_t.
     */
    uint32_t state;
    /**
     * A sipral_call_end_reason_t, zero while the call is alive.
     */
    uint32_t end_reason;
    /**
     * The status a response carried, or zero.
     */
    uint32_t status_code;
    /**
     * The other call this event is also about: the sibling of a fork, or the
     * call that was replaced. SIPRAL_HANDLE_NONE otherwise.
     */
    sipral_handle_t other;
    /**
     * Whether this end has asked the far end to stop sending.
     */
    uint32_t held_here;
    /**
     * Whether the far end has asked this one to.
     */
    uint32_t held_there;
    /**
     * What this end is describing, and how long it is.
     */
    const uint8_t *local_sdp;
    /**
     * How many bytes of it.
     */
    size_t local_sdp_len;
    /**
     * And what the far end is.
     */
    const uint8_t *remote_sdp;
    /**
     * How many bytes of it.
     */
    size_t remote_sdp_len;
    /**
     * When a refused session change goes out again by itself, zero when it is
     * not going to.
     */
    uint64_t retry_in_ms;
    /**
     * The `From` URI of the request that created this call: as written in
     * the header, without the angle brackets and without header
     * parameters such as `tag`. The same on every event of this call.
     * Null and zero when this build has none to report.
     */
    const uint8_t *from_uri;
    /**
     * How many bytes of it.
     */
    size_t from_uri_len;
    /**
     * That `From`'s display name, quotes and backslash escapes resolved
     * (RFC 3261 §25.1). Null and zero when the header named none.
     */
    const uint8_t *from_display;
    /**
     * How many bytes of it.
     */
    size_t from_display_len;
    /**
     * The `To` URI of the request that created this call, as written in
     * the header.
     */
    const uint8_t *to_uri;
    /**
     * How many bytes of it.
     */
    size_t to_uri_len;
    /**
     * The `Call-ID` of the request that created this call.
     */
    const uint8_t *call_id;
    /**
     * How many bytes of it.
     */
    size_t call_id_len;
    /**
     * The digit an INFO this end sent named, for
     * SIPRAL_EVENT_KIND_DTMF_SENT. Zero for every other kind.
     */
    uint32_t digit;
};

/**
 * What a transfer event carries.
 */
struct sipral_transfer_event {
    /**
     * What the far end's own call is doing, or zero.
     */
    uint32_t status_code;
    /**
     * Whether the request named a dialog to replace, which is what makes a
     * transfer attended rather than blind.
     */
    uint32_t attended;
    /**
     * Who to call, as UTF-8. Not NUL-terminated.
     */
    const char *target;
    /**
     * How many bytes of it.
     */
    size_t target_len;
};

/**
 * What a media event carries.
 *
 * As with a call event, not every member means something in every kind, and
 * the ones that do not are zero or null.
 */
struct sipral_media_event {
    /**
     * A sipral_codec_t: what the negotiation
     * settled on, zero where the event is not about a codec.
     */
    uint32_t codec;
    /**
     * A sipral_direction_t: which way audio
     * may flow, as seen from here.
     */
    uint32_t direction;
    /**
     * How long the stream has been silent, for a stall and for its recovery.
     */
    uint64_t silent_for_ms;
    /**
     * How much audio reached the file, for a recording that stopped by
     * itself.
     */
    uint64_t recorded_ms;
    /**
     * A sipral_media_fault_t, zero when
     * nothing failed.
     */
    uint32_t fault;
    /**
     * The sentence behind `fault`, as UTF-8. Not NUL-terminated, and null
     * when nothing failed.
     */
    const char *reason;
    /**
     * How many bytes of it.
     */
    size_t reason_len;
    /**
     * What the stream cost, for the kind that carries it, and null for every
     * other. It belongs to the library and lives as long as the callback.
     */
    const sipral_stream_stats_t *statistics;
    /**
     * The key the far end pressed, as its character, and zero for an event
     * no keypad has a key for.
     */
    uint32_t digit;
    /**
     * The RFC 4733 event code behind `digit`. Codes at and above sixteen are
     * real events that are not keys.
     */
    uint32_t event_code;
    /**
     * How long the far end held it. Zero either for an `application/dtmf`
     * INFO, which carries no duration at all, or for the other form's
     * own `Duration=0` — a peer that held the key for no time at all.
     * The Rust facade keeps the two apart; this ABI does not.
     */
    uint64_t held_ms;
    /**
     * A sipral_srtp_suite_t: the transform
     * this call's media is protected with, for
     * SIPRAL_EVENT_KIND_MEDIA_SECURED and zero on every other kind.
     */
    uint32_t suite;
    /**
     * A sipral_digit_source_t: which of the two ways this stack accepts a
     * digit reported this one, for SIPRAL_EVENT_KIND_DIGIT_RECEIVED.
     */
    uint32_t source;
    /**
     * Whether the RFC 6035 PUBLISH left this end, for
     * SIPRAL_EVENT_KIND_QUALITY_REPORT_SENT and zero on every other
     * kind. Not whether a collector accepted it.
     */
    uint32_t quality_report_sent;
};

/**
 * What a SIPRAL_EVENT_KIND_RECOVERY carries: the lifecycle machine
 * settling, either by proving the path again or by giving the ladder up.
 */
struct sipral_recovery_event {
    /**
     * A sipral_recovery_outcome_t.
     */
    uint32_t state;
    /**
     * A sipral_recovery_rung_t: the last rung tried. Zero unless `state`
     * is SIPRAL_RECOVERY_OUTCOME_GAVE_UP.
     */
    uint32_t rung;
    /**
     * A sipral_recovery_failure_t. Zero unless `state` is
     * SIPRAL_RECOVERY_OUTCOME_GAVE_UP.
     */
    uint32_t reason;
    /**
     * Bindings the ladder never proved. Meaningful only when `state` is
     * SIPRAL_RECOVERY_OUTCOME_GAVE_UP.
     */
    uint32_t unverified;
};

/**
 * What a SIPRAL_EVENT_KIND_TRANSPORT_WANTED carries: a request RFC
 * 3261 §18.1.1 would not let out over a datagram, and nowhere open to
 * send it instead.
 */
struct sipral_transport_wanted_event {
    /**
     * What to open, as a
     * sipral_transport_t. Zero for a
     * protocol this build has no number for, which
     * `sipral_stack_transport_bind` then cannot be asked to open
     * either — nothing this build originates ever measures against a
     * protocol like that, so this is the layer below having grown one
     * rather than a caller mistake.
     */
    uint32_t protocol;
    /**
     * Where to, as `host:port`. Not NUL-terminated.
     */
    const char *destination;
    /**
     * How many bytes of it.
     */
    size_t destination_len;
    /**
     * How large the request came out, in bytes as they would have gone
     * on the wire.
     */
    size_t request_bytes;
    /**
     * The largest it could have been and still fitted a datagram: the
     * path MTU less the §18.1.1 headroom where the MTU is known, 1300
     * where it is not.
     */
    uint32_t limit_bytes;
};

/**
 * What a SIPRAL_EVENT_KIND_SUBSCRIPTION_CHANGED and a
 * SIPRAL_EVENT_KIND_NOTIFIED carry.
 *
 * The subscription names itself here rather than in `sipral_event_t`,
 * which has room for an account and a call and not for every kind of
 * handle this ABI mints. The account is not carried at all: a caller
 * asked for the subscription on one, and a sibling from a fork belongs
 * to the same one as the subscription it forked from.
 */
struct sipral_subscription_event {
    /**
     * Which subscription. Minted by `sipral_account_subscribe`, or by
     * this ABI when a fork made one nobody asked for.
     */
    sipral_handle_t subscription;
    /**
     * A sipral_subscription_state_t.
     */
    uint32_t state;
    /**
     * A sipral_subscription_end_t:
     * why it is not live. Zero while it is.
     */
    uint32_t reason;
    /**
     * The SIP status a response gave for it, when one did. Zero
     * otherwise.
     */
    uint32_t status_code;
    /**
     * Whether the notification carried dialog state this build could
     * read. Zero on every kind but SIPRAL_EVENT_KIND_NOTIFIED, and
     * zero there for a body in any other form or none at all.
     */
    uint32_t has_dialog_info;
    /**
     * What the notifier granted, in milliseconds. Zero until one has.
     */
    uint64_t expires_ms;
    /**
     * How long until this stack refreshes it, in milliseconds.
     */
    uint64_t refresh_in_ms;
    /**
     * How long until the next attempt, in milliseconds, when the state
     * is `SIPRAL_SUBSCRIPTION_STATE_RETRYING`. Zero otherwise, which
     * includes every subscription that has ended for good.
     */
    uint64_t retry_in_ms;
    /**
     * The subscription this one forked from
     * ([RFC 6665 §4.1.4]), or `SIPRAL_HANDLE_NONE`. A sibling is a
     * subscription of its own from here on, with its own dialog, its own
     * refresh and its own state; RFC 4235 §3.9 makes this the normal case
     * for dialog state, one per device the watched address is registered
     * on.
     *
     * [RFC 6665 §4.1.4]: https://www.rfc-editor.org/rfc/rfc6665#section-4.1.4
     */
    sipral_handle_t forked_from;
};

/**
 * What a SIPRAL_EVENT_KIND_CALL_ANNOUNCED and a
 * SIPRAL_EVENT_KIND_ANNOUNCED_CALL_MISSING carry.
 */
struct sipral_announce_event {
    /**
     * Which announcement. Minted by `sipral_account_announce`, and it
     * names nothing once either of these two events has been raised
     * about it.
     */
    sipral_handle_t announcement;
    /**
     * How long the call was waited for, in milliseconds. Meaningful only
     * on SIPRAL_EVENT_KIND_ANNOUNCED_CALL_MISSING.
     */
    uint64_t waited_ms;
};

/**
 * What a SIPRAL_EVENT_KIND_RESOLVE_NEEDED carries: the name a dialog's
 * next hop is written as, and the handle an answer takes.
 */
struct sipral_resolve_event {
    /**
     * The dialog this is about, and what
     * sipral_stack_resolved
     * is answered with. Minted by the library, valid while the dialog
     * is, and answering for one that has ended changes nothing rather
     * than failing.
     */
    sipral_handle_t dialog;
    /**
     * The host to resolve, as the URI spells it — a name, or a literal
     * address, which is still reported because the flow the dialog is on
     * may legitimately differ from it. An IPv6 literal carries its
     * brackets (RFC 3261 §19.1.1). Not NUL-terminated.
     */
    const char *host;
    /**
     * How many bytes of it.
     */
    size_t host_len;
    /**
     * The port the URI gave, or zero for none. Zero is not 5060: RFC
     * 3263 §4.2 leaves the choice to whoever does the lookup, because
     * an SRV answer carries a port of its own.
     */
    uint32_t port;
    /**
     * The transport the URI or the scheme named, as a
     * sipral_transport_t, or zero for
     * neither — which leaves §4.1's NAPTR step to the caller, and is
     * also what a protocol this build has no number for reads as.
     */
    uint32_t protocol;
};

/**
 * What a SIPRAL_EVENT_KIND_MESSAGE_RECEIVED, a
 * SIPRAL_EVENT_KIND_MESSAGE_SENT and a
 * SIPRAL_EVENT_KIND_MESSAGES_WAITING carry.
 *
 * One struct for all three, the way sipral_subscription_event_t answers
 * for two kinds: a member meaningless on one kind is zero or null there.
 * The whole request or response, when there is one, rides in
 * `sipral_event_t::message` instead — `attach` points it at the same
 * bytes `content_type` and `body` are read out of, so both are valid for
 * exactly as long as the callback is.
 */
struct sipral_message_event {
    /**
     * SIPRAL_EVENT_KIND_MESSAGE_SENT: which send, minted by
     * `sipral_account_message`. SIPRAL_HANDLE_NONE on the other two
     * kinds, and names nothing once this event has been raised about it.
     */
    sipral_handle_t message;
    /**
     * SIPRAL_EVENT_KIND_MESSAGES_WAITING: which subscription reported
     * it. SIPRAL_HANDLE_NONE on the other two kinds, which are not
     * subscriptions.
     */
    sipral_handle_t subscription;
    /**
     * SIPRAL_EVENT_KIND_MESSAGE_SENT: the final status. Zero on the
     * other two kinds.
     */
    uint32_t status_code;
    /**
     * SIPRAL_EVENT_KIND_MESSAGE_RECEIVED: the `Content-Type` of the
     * body, as written. Null on the other two kinds, and on a MESSAGE
     * with no body at all.
     */
    const char *content_type;
    /**
     * How many bytes of it.
     */
    size_t content_type_len;
    /**
     * SIPRAL_EVENT_KIND_MESSAGE_RECEIVED: the body. Null the same as
     * `content_type`.
     */
    const uint8_t *body;
    /**
     * How many bytes of it.
     */
    size_t body_len;
    /**
     * SIPRAL_EVENT_KIND_MESSAGES_WAITING: RFC 3842 §3.5's status
     * line, 1 for `yes` and 0 for `no`. Meaningless on the other two
     * kinds.
     */
    uint32_t waiting;
    /**
     * SIPRAL_EVENT_KIND_MESSAGES_WAITING: new messages of the
     * `voice-message` class (RFC 3458 §6.2), the one a phone's
     * message-waiting light is about. Zero when the body named no
     * `voice-message` line, which a boolean-only notification does.
     */
    uint32_t new_messages;
    /**
     * The same, old.
     */
    uint32_t old_messages;
    /**
     * New messages flagged urgent.
     */
    uint32_t urgent_new_messages;
    /**
     * Old messages flagged urgent.
     */
    uint32_t urgent_old_messages;
    /**
     * SIPRAL_EVENT_KIND_MESSAGES_WAITING: `Message-Account`, when the
     * notifier sent one (RFC 3842 §3.5 makes it mandatory only for a
     * subscription to a group or collection of accounts). Null on the
     * other two kinds, and on a body that named none.
     */
    const char *message_account;
    /**
     * How many bytes of it.
     */
    size_t message_account_len;
};

/**
 * What a SIPRAL_EVENT_KIND_NAT_MAPPING
 * carries.
 *
 * The three addresses are `host:port`, not NUL-terminated, and the
 * library's: valid for as long as the callback runs.
 */
struct sipral_nat_event {
    /**
     * A sipral_nat_mapping_t.
     */
    uint32_t mapping;
    /**
     * Nonzero for a signalling socket — a transport of this stack's —
     * and zero for a media socket sipral_stack_nat_map named.
     */
    uint32_t signalling;
    /**
     * The transport, when `signalling` is nonzero: `SIPRAL_TRANSPORT_MAIN`
     * or a number `sipral_stack_transport_bind` bound. Zero otherwise,
     * which is not a transport here.
     */
    uint32_t transport;
    /**
     * How many accounts' `Contact` moved to `public` because of this —
     * each one that holds a binding, or is getting one, has registered it
     * already. Zero for a media socket, and for an answer no account's
     * `Contact` named the socket in.
     */
    uint32_t accounts;
    /**
     * The socket, as the application named it.
     */
    const char *local;
    /**
     * How many bytes of it.
     */
    size_t local_len;
    /**
     * Where the server saw it: the public address. Empty for
     * `SIPRAL_NAT_MAPPING_UNANSWERED`.
     */
    const char *mapped;
    /**
     * How many bytes of it.
     */
    size_t mapped_len;
    /**
     * What it was before, for `SIPRAL_NAT_MAPPING_MOVED`. Empty
     * otherwise.
     */
    const char *previous;
    /**
     * How many bytes of it.
     */
    size_t previous_len;
};

/**
 * What a SIPRAL_EVENT_KIND_NAT_RELAY
 * carries.
 *
 * The addresses and the reason are text, not NUL-terminated, and the
 * library's: valid for as long as the callback runs. Nothing of the
 * credential is in any of them.
 */
struct sipral_nat_relay_event {
    /**
     * A sipral_nat_relay_t.
     */
    uint32_t outcome;
    /**
     * For `SIPRAL_NAT_RELAY_FAILED`, the STUN error code the server
     * refused with — 401 for a credential it does not accept, 486 for a
     * user at its allocation quota, 508 for a server with nothing left —
     * and zero when there was none: no answer at all, or an answer this
     * end could not accept. Zero for `SIPRAL_NAT_RELAY_ALLOCATED`.
     */
    uint32_t code;
    /**
     * The media socket, as `sipral_stack_nat_map` named it.
     */
    const char *local;
    /**
     * How many bytes of it.
     */
    size_t local_len;
    /**
     * The relayed address, `host:port`. Empty for
     * `SIPRAL_NAT_RELAY_FAILED`.
     */
    const char *relayed;
    /**
     * How many bytes of it.
     */
    size_t relayed_len;
    /**
     * Where the server saw the socket from, when it said. Empty
     * otherwise.
     */
    const char *mapped;
    /**
     * How many bytes of it.
     */
    size_t mapped_len;
    /**
     * Why there is no relay, in English, for a log. Empty for
     * `SIPRAL_NAT_RELAY_ALLOCATED`.
     */
    const char *reason;
    /**
     * How many bytes of it.
     */
    size_t reason_len;
};

/**
 * The arm of an event that its kind names.
 *
 * Reading any other arm reads bytes the library did not write for it.
 */
union sipral_event_payload {
    /**
     * For SIPRAL_EVENT_KIND_REGISTRATION_CHANGED.
     */
    sipral_registration_event_t registration;
    /**
     * For every call kind.
     */
    sipral_call_event_t call;
    /**
     * For SIPRAL_EVENT_KIND_TRANSFER_REQUESTED,
     * SIPRAL_EVENT_KIND_TRANSFER_PROGRESS and
     * SIPRAL_EVENT_KIND_TRANSFER_DONE.
     */
    sipral_transfer_event_t transfer;
    /**
     * For every media kind: started, changed, stalled, resumed, failed, the
     * end-of-call statistics, and a recording that stopped by itself.
     */
    sipral_media_event_t media;
    /**
     * For SIPRAL_EVENT_KIND_RECOVERY.
     */
    sipral_recovery_event_t recovery;
    /**
     * For SIPRAL_EVENT_KIND_TRANSPORT_WANTED.
     */
    sipral_transport_wanted_event_t transport_wanted;
    /**
     * For SIPRAL_EVENT_KIND_SUBSCRIPTION_CHANGED and
     * SIPRAL_EVENT_KIND_NOTIFIED.
     */
    sipral_subscription_event_t subscription;
    /**
     * For SIPRAL_EVENT_KIND_CALL_ANNOUNCED and
     * SIPRAL_EVENT_KIND_ANNOUNCED_CALL_MISSING.
     */
    sipral_announce_event_t announce;
    /**
     * For SIPRAL_EVENT_KIND_RESOLVE_NEEDED.
     */
    sipral_resolve_event_t resolve;
    /**
     * For SIPRAL_EVENT_KIND_MESSAGE_RECEIVED,
     * SIPRAL_EVENT_KIND_MESSAGE_SENT and
     * SIPRAL_EVENT_KIND_MESSAGES_WAITING.
     */
    sipral_message_event_t message;
    /**
     * For SIPRAL_EVENT_KIND_NAT_MAPPING.
     */
    sipral_nat_event_t nat;
    /**
     * For SIPRAL_EVENT_KIND_NAT_RELAY.
     */
    sipral_nat_relay_event_t relay;
};

/**
 * Something the library has to tell the application.
 *
 * The pointer handed to the callback is the library's, and it is valid for
 * the duration of that call and no longer. `size` says how much of the
 * struct this build filled in, and a binding reads no further than that. The
 * union stays the last member for the same reason: an arm that grows grows
 * the tail, which is the one place a released struct may change.
 */
struct sipral_event {
    /**
     * How many bytes of this struct are meaningful.
     */
    size_t size;
    /**
     * The stack it is about.
     */
    sipral_handle_t stack;
    /**
     * What it is.
     */
    sipral_event_kind_t kind;
    /**
     * The account it is about, or SIPRAL_HANDLE_NONE.
     */
    sipral_handle_t account;
    /**
     * The call it is about, or SIPRAL_HANDLE_NONE.
     */
    sipral_handle_t call;
    /**
     * The SIP message behind it, whole and unparsed, when there is one.
     *
     * A reason phrase, a `Retry-After`, the `Contact` of a redirect and the
     * caller's display name all live here and none of them is worth a member
     * of its own. Null when the event came from no single message.
     */
    const uint8_t *message;
    /**
     * How many bytes of it.
     */
    size_t message_len;
    /**
     * The arm sipral_event_t::kind names.
     */
    sipral_event_payload_t payload;
};

/**
 * What was standing when the process was told it is about to stop
 * (sipral_stack_suspending's `out_report`).
 *
 * Set `size` to `sizeof(sipral_suspending_t)` before the call. Counts
 * and nothing else, because the window this is produced in is one where
 * an allocation that grows with the number of accounts is a cost with no
 * upper bound worth paying. Everything in it is already past tense by
 * the time it is read: the bindings have stopped being evidence, the
 * subscriptions have stopped being evidence, and nothing was sent about
 * either.
 */
struct sipral_suspending {
    /**
     * How many bytes of this struct the library filled in.
     */
    size_t size;
    /**
     * Bindings that read as live and do not any more.
     */
    size_t unverified;
    /**
     * Subscriptions whose last notification stopped being evidence.
     */
    size_t subscriptions;
    /**
     * Calls that were up. Nothing was sent about them and nothing was
     * changed: a lid closing and opening again is seconds, and hanging
     * up a live call because the machine blinked is worse than finding
     * out a few seconds later that it is gone.
     */
    size_t calls;
};

/**
 * What sipral_screen_callback_t reads about one INVITE, before it has
 * had any effect at all.
 *
 * Filled by the library and handed to the callback as a `const`
 * pointer, the same shape crate::event::SipralEvent is: read `size`
 * before anything past it, and read nothing once the callback has
 * returned, since `message` — and `source`, when it is not null —
 * borrow from a request that is still in the middle of being processed
 * and are not this ABI's to keep alive a moment longer. The answer does
 * not travel in here: the callback returns it.
 */
struct sipral_screen_request {
    /**
     * How many bytes of this struct the library filled in.
     */
    size_t size;
    /**
     * The stack the INVITE arrived on.
     */
    sipral_handle_t stack;
    /**
     * The far end of the bytes it arrived in, as `host:port` — the same
     * text form every address in this ABI takes. Null and zero for a
     * byte stream the application bound without naming its far end.
     */
    const char *source;
    /**
     * How many bytes of it.
     */
    size_t source_len;
    /**
     * The INVITE, whole and unparsed. `sipral_message_header` and its
     * three companions read any header out of these bytes the way they
     * read any other message this ABI hands over.
     */
    const uint8_t *message;
    /**
     * How many bytes of it.
     */
    size_t message_len;
};

/**
 * What to watch, and how. Handed to sipral_account_subscribe.
 *
 * Set `size` to `sizeof(sipral_subscribe_config_t)` before the call.
 * Everything but `target` and `package` may be left zero.
 */
struct sipral_subscribe_config {
    /**
     * How long this struct is, as the caller's header declares it.
     */
    size_t size;
    /**
     * What to watch, as a SIP URI: `sip:2001@pbx.example.com`.
     */
    const char *target;
    /**
     * How many bytes of it.
     */
    size_t target_len;
    /**
     * The event package, as the token that names it: `dialog` for a busy
     * lamp field (RFC 4235 §3.1), `message-summary` for message waiting
     * (RFC 3842 §3), `presence` (RFC 3856 §6.1).
     *
     * It goes out exactly as written here, because §8.2.1 compares it
     * byte for byte.
     */
    const char *package;
    /**
     * How many bytes of it.
     */
    size_t package_len;
    /**
     * The `Accept` value, when the package's default body type is not
     * the one wanted. Null sends no `Accept` at all, which §3.1.3 makes
     * the package's default — `application/dialog-info+xml` for
     * `dialog`.
     *
     * Sending the wrong one is worse than sending none: §4.1.2.1 has the
     * notifier answer 406 for a type it cannot generate, so nothing is
     * guessed on a caller's behalf.
     */
    const char *accept;
    /**
     * How many bytes of it.
     */
    size_t accept_len;
    /**
     * How long to ask for, in seconds, or zero for this build's default
     * of one hour.
     *
     * What the notifier grants wins (§3.1.1: "The period of time in the
     * response is the one that defines the duration of the
     * subscription"), and the refresh is scheduled against that rather
     * than against this.
     */
    uint32_t expires_seconds;
    /**
     * Where to send the SUBSCRIBE, as `host:port`, or null to send it
     * where the account registers — which is the outbound proxy for a
     * registered line, and the reason a phone behind a NAT is reachable
     * at all.
     */
    const char *destination;
    /**
     * How many bytes of it.
     */
    size_t destination_len;
    /**
     * Which transport it goes out on, read only together with
     * `destination`, exactly as `sipral_call_config_t::transport` is.
     * Nonzero with `destination` null is
     * `SIPRAL_STATUS_INVALID_ARGUMENT`.
     */
    uint32_t transport;
};

/**
 * One dialog a `dialog` subscription has been told about, with the text
 * left behind: sipral_subscription_dialog_text reads that, because a
 * pointer into this library's own memory would be a pointer a caller
 * could outlive.
 */
struct sipral_watched_dialog {
    /**
     * How many bytes of this struct the library filled in.
     */
    size_t size;
    /**
     * A sipral_dialog_phase_t.
     */
    uint32_t phase;
    /**
     * A sipral_dialog_direction_t.
     */
    uint32_t direction;
    /**
     * A sipral_dialog_ended_t, and zero while the dialog has not.
     */
    uint32_t ended;
    /**
     * The SIP status behind how it ended, when the notifier sent one.
     * Zero otherwise.
     */
    uint32_t status_code;
    /**
     * How long it has been up, in milliseconds, when the notifier sent a
     * duration. Zero otherwise.
     */
    uint64_t duration_ms;
};

/**
 * What the registrar said about push, in the 2xx to a REGISTER that
 * asked for it (RFC 8599 §8.2).
 */
struct sipral_push_echo {
    /**
     * How many bytes of this struct the library filled in.
     */
    size_t size;
    /**
     * Whether the network said it will ask for notifications of the type
     * this account asked for. Zero means it did not say so, which §4.1.1
     * makes "MUST NOT assume they are coming" rather than "they are not":
     * an application that suspends itself on the strength of a push it
     * was never promised stops ringing.
     */
    uint32_t accepted;
    /**
     * Whether `refresh_lead_ms` was sent at all.
     */
    uint32_t has_refresh_lead;
    /**
     * How long before the binding lapses the network insists on seeing a
     * refresh, from a `sip.pnsreg` indicator (§4.1.4), in milliseconds.
     * Zero when the network sent none, which `has_refresh_lead` is how to
     * tell from a lead of zero.
     */
    uint64_t refresh_lead_ms;
};

/**
 * Copy the calling thread's last error message into `buffer`.
 *
 * The message is UTF-8 and is written with a trailing NUL, which is not
 * counted in the length. `out_len`, when it is not null, always receives
 * the number of bytes the message needs including that NUL, so a caller
 * that passes a capacity of zero and a null buffer gets the length back
 * and `SIPRAL_STATUS_BUFFER_TOO_SMALL`. Nothing is written to a buffer
 * too small to hold the whole message: a truncated one would cut a
 * multi-byte character in half.
 *
 * The message describes the last call this thread made and nothing else.
 * The next call on this thread replaces it, a call that succeeds empties
 * it — including one that succeeded around a nested call that did not —
 * and this call leaves it alone, so it can be read twice. It is never
 * shared with another thread.
 *
 * Safety
 *
 * `buffer` must be writable for `capacity` bytes or null with a capacity
 * of zero, and `out_len` must point to one `size_t` or be null.
 */
sipral_status_t sipral_last_error_message(char *buffer, size_t capacity, size_t *out_len);

/**
 * The short name of a status code, as a static NUL-terminated string, or
 * null for a number that is not a status code.
 *
 * The string belongs to the library and lives as long as it is loaded.
 * It is meant for a log line; the last error is the sentence for a human.
 *
 * Safety
 *
 * Reads no memory the caller owns, and is safe to call from any thread.
 */
const char *sipral_status_name(int32_t status);

/**
 * Report the ABI version this library provides.
 *
 * Safety
 *
 * `out_version` must point at a `sipral_abi_version_t` whose `size`
 * member says how long it is.
 */
sipral_status_t sipral_abi_version(sipral_abi_version_t *out_version);

/**
 * Whether this library can serve a binding generated against
 * `major`.`minor`. Called once, at load, before anything else: by the
 * binding itself where its language gives it somewhere to call from, and
 * by the application where it does not. The Versioning section of
 * `docs/08-ffi.md` says which binding is which.
 *
 * `SIPRAL_STATUS_UNSUPPORTED_VERSION` when it cannot, with a last error
 * naming both versions, which is what the binding should put in the
 * exception it throws. The patch number is not asked for: it never
 * changes a declaration, so it cannot make two builds disagree.
 *
 * Safety
 *
 * Reads no memory the caller owns, and is safe to call from any thread.
 */
sipral_status_t sipral_abi_check(uint32_t major, uint32_t minor);

/**
 * How many bytes this build compiled one of the ABI's structs to.
 *
 * `name` is what the header calls the type — `sipral_stack_config_t` —
 * as bytes and a length, the way every string crosses here. A name this
 * build has no struct for is `SIPRAL_STATUS_INVALID_ARGUMENT`, which is
 * the answer a caller holding somebody else's header gets.
 *
 * Nothing in the library needs asking: the `size` member a struct
 * carries settles a disagreement in the ordinary course of a call. This
 * is for finding out there is one before making it. A package built
 * against one header and loaded over a native library from another
 * shows up here as a `sizeof` that differs, in one call at load, rather
 * than in whichever member happened to move.
 *
 * Safety
 *
 * `name` must be readable for `name_len` bytes, and `out_size` must
 * point at one `size_t`.
 */
sipral_status_t sipral_abi_struct_size(const char *name, size_t name_len, size_t *out_size);

/**
 * How many of the ABI's structs carry a `size` member.
 *
 * The companion to `sipral_abi_struct_size`, and the part of the check a
 * caller cannot write for itself. A caller that compares lengths holds
 * a list of the structs it knows about, and the list is what goes
 * stale: a struct this ABI gained is one nobody thought to ask about,
 * and a length check that covers all but the newest still passes. Ask
 * for this number, compare it with the length of that list, and the day
 * the ABI grows another the caller is told.
 *
 * Safety
 *
 * `out_count` must point at one `size_t`.
 */
sipral_status_t sipral_abi_versioned_count(size_t *out_count);

/**
 * What this build of the library can do, in one call.
 *
 * Names no stack, and answers the same way before any stack is created
 * as after: a build's capabilities do not change while it runs. Safe to
 * call from any thread, at any time, including from inside the event
 * callback.
 *
 * Safety
 *
 * `out_capabilities` must point at a `sipral_capabilities_t` whose
 * `size` member says how long it is.
 */
sipral_status_t sipral_capabilities(sipral_capabilities_t *out_capabilities);

/**
 * Create a stack, and write its handle to `out_stack`.
 *
 * The handle is written only if this returns `SIPRAL_STATUS_OK`. A stack
 * that is created must be destroyed with sipral_stack_destroy.
 *
 * A process holds 256 stacks at once. The next is
 * `SIPRAL_STATUS_EXHAUSTED` until one of them is destroyed and no poll is
 * still running on it.
 *
 * Safety
 *
 * `config` must point at a `sipral_stack_config_t` whose `size` member
 * says how long it is, with every pointer in it readable for the length
 * beside it, and `out_stack` at one `sipral_handle_t`.
 */
sipral_status_t sipral_stack_create(const sipral_stack_config_t *config, sipral_handle_t *out_stack);

/**
 * Read back what a stack is running with.
 *
 * Every value here was either given at creation or defaulted there, and
 * none of it changes afterwards. It is the other half of a configuration
 * call that answered `SIPRAL_STATUS_OK`: the call says the value was
 * taken, this says what it came to.
 *
 * Safety
 *
 * `out_settings` must point at a `sipral_stack_settings_t` whose `size`
 * member says how long it is.
 */
sipral_status_t sipral_stack_settings(sipral_handle_t stack, sipral_stack_settings_t *out_settings);

/**
 * Destroy a stack.
 *
 * The handle is dead the moment this returns, and a second destroy is
 * `SIPRAL_STATUS_STALE_HANDLE` rather than a corrupted heap. Called from
 * inside the callback it is still safe: what the poll is holding stays
 * alive until that poll returns. Called from inside a frame of one of its
 * calls — a processor — it is `SIPRAL_STATUS_BUSY` and nothing is freed,
 * because freeing the stack ends that call's media and the frame is
 * holding it. No account is de-registered and no call is hung up; a stack
 * that has to leave politely does that first.
 *
 * Safety
 *
 * Safe to call with any handle value. Reads no memory the caller owns.
 */
sipral_status_t sipral_stack_destroy(sipral_handle_t stack);

/**
 * Let the stack do its work, and deliver what it has to say.
 *
 * `now_ms` is the caller's monotonic clock in milliseconds. It must not
 * fall more than fifty milliseconds behind the last one this stack saw —
 * signalling may be called from any thread, and two of them reading the
 * same clock a moment apart is not a caller mistake — and a jump further
 * back than that is `SIPRAL_STATUS_INVALID_ARGUMENT` with nothing
 * delivered.
 *
 * The event callback is called from inside this function, on this
 * thread, and with nothing held: the stack's work is done and its lock
 * let go before the first event is handed over, so the callback may call
 * back into the library, this stack included. A poll that finds another
 * poll of the same stack already delivering — which is what a poll from
 * inside the callback always finds — does the stack's work and leaves its
 * events to that one, so they arrive in the order they were raised and
 * never on two threads at once.
 *
 * `result` may be null for a caller that does not want the counts.
 *
 * A poll is also where the stack writes: a retransmission falls due, a
 * registration is refreshed, a transaction gives up and says so. What it
 * wrote is taken with `sipral_stack_poll_transmit`, which is drained after
 * every poll and left alone by the next one — see crate::transport for
 * the loop in full.
 *
 * Safety
 *
 * `result` must be null or point at a `sipral_poll_result_t` whose `size`
 * member says how long it is.
 */
sipral_status_t sipral_stack_poll(sipral_handle_t stack, uint64_t now_ms, sipral_poll_result_t *result);

/**
 * D3's health counters for one stack, since it was created.
 *
 * Cheap enough to sample on a timer and ship as telemetry: reading this
 * is one struct copy on top of the call itself, the same as
 * `sipral_media_statistics` and for the same reason — nothing here walks
 * the call table or a session to answer.
 *
 * Safety
 *
 * `out_counters` must point at a `sipral_counters_t` whose `size` member
 * says how long it is.
 */
sipral_status_t sipral_stack_counters(sipral_handle_t stack, sipral_counters_t *out_counters);

/**
 * Install, replace, or remove the screening policy for one stack.
 *
 * Every INVITE that survives sipral_stack_invite_limit reaches this
 * callback before anything else does: before ringing, before
 * `SIPRAL_EVENT_KIND_INCOMING_CALL`, before a call handle exists for
 * anybody to answer or reject. What the callback refuses is answered
 * with the SIP status it named — when that status refuses, and with 500
 * when it does not — and forgotten — no event, no handle,
 * nothing for the application to clean up — and what it takes, by
 * answering `SIPRAL_SCREEN_ACCEPT`, arrives exactly as it would with no
 * policy installed at all.
 *
 * `callback` given as `NULL` removes the policy: every INVITE reaches
 * the application again, the way it did before this was ever called.
 * Calling this a second time with a callback replaces the first outright,
 * on this stack alone — a different stack's policy, if it has one, is
 * untouched.
 *
 * The rule that the callback must not call back into this stack, and
 * must not unwind, is on sipral_screen_callback_t and is the reason
 * this module's own documentation exists; read it there before wiring
 * one up.
 *
 * Safety
 *
 * `callback`, when not null, is called on whichever thread is inside an
 * entry point that is feeding this stack bytes, for as long as the
 * policy stays installed. `user_data` is handed back to it untouched on
 * every call and read by nothing here.
 *
 * **Whatever `user_data` points at has to outlive the last call, and the
 * last call is not `sipral_stack_destroy` returning.** A destroy takes
 * this thread's share of the stack away; a receive already running on
 * another thread holds one of its own until it is done, and the policy
 * it is in the middle of asking is still asked. So the moment to free
 * what the pointer names is once no thread is inside this stack any
 * more, which is the application's own knowledge and not something this
 * ABI can answer. Replacing the policy, or removing it with `NULL`, has
 * the same shape: it takes the stack's lock, so it cannot run while a
 * policy is being asked, and once it returns the callback that was
 * there is not asked again.
 */
sipral_status_t sipral_stack_screen(sipral_handle_t stack, sipral_screen_callback_t callback, void *user_data);

/**
 * How fast one source address may offer this stack an INVITE (A8).
 *
 * `burst` calls from one address are let through at once; one more is
 * earned every `every_ms` after that. What either number means is
 * exactly what Rate already means by it — `sipral_stack_create`'s
 * default is ten at once and one every two thousand milliseconds,
 * loose on purpose, because in most deployments every legitimate call
 * arrives from the one address a phone registered with.
 *
 * A `burst` of zero, or an `every_ms` of zero, is
 * `SIPRAL_STATUS_INVALID_ARGUMENT` and changes nothing: the first admits
 * no call ever, the first or the one after a week of quiet, and the
 * second earns a token in no time, which is a limit that never limits —
 * Rate::unlimited is how the Rust API says that on purpose, and
 * there is deliberately no way to ask for it from C, since a deployment
 * that wants no floor at all can simply never call this.
 *
 * The floor is asked before sipral_stack_screen's own policy is: a
 * source that has exhausted it never reaches the callback at all, and is
 * counted in `sipral_counters_t::screened_refused_by_rate` or
 * `screened_refused_by_crowding`, never in `screened_refused_by_policy`.
 *
 * **It counts by source address, so it counts nothing it cannot name.**
 * An INVITE that arrived on a byte stream the application bound without
 * saying where the far end is has no address on it, and this floor lets
 * every one of those through to the policy — which is where a caller who
 * cannot identify a stream's far end has to decide, the same way
 * sipral_screen_request_t::source being null is what it has to decide
 * on. Naming the far end in `sipral_stack_transport_bind`'s `remote` is
 * what puts a stream under this floor at all.
 *
 * Safety
 *
 * Safe to call with any handle value.
 */
sipral_status_t sipral_stack_invite_limit(sipral_handle_t stack, uint64_t every_ms, uint32_t burst);

/**
 * Watch something at the far end (A1).
 *
 * One SUBSCRIBE goes out on `account`'s transport, to `account`'s
 * address, and the handle written back names the subscription from now
 * until it ends. Nothing has happened yet when this returns: the request
 * is in the transmit queue, and
 * `SIPRAL_EVENT_KIND_SUBSCRIPTION_CHANGED` reports each step of what
 * becomes of it.
 *
 * A subscription refreshes itself for as long as it is live, at a
 * fraction of what the notifier granted, and starts a fresh one by itself
 * after something recoverable — both under this same handle. What ends
 * it for good is sipral_subscription_end, or an event saying it
 * ended with no retry, and the handle names nothing after that.
 *
 * Safety
 *
 * `config` must point at a `sipral_subscribe_config_t` whose `size`
 * member says how long it is, with every pointer in it readable for the
 * length beside it. `out_subscription` must point at one
 * `sipral_handle_t`.
 */
sipral_status_t sipral_account_subscribe(sipral_handle_t stack, sipral_handle_t account, const sipral_subscribe_config_t *config, sipral_handle_t *out_subscription, uint64_t now_ms);

/**
 * Give a subscription up.
 *
 * A SUBSCRIBE with `Expires: 0` (§4.1.2.3), and the subscription is not
 * over when this returns: §4.4.1 makes it live "until the NOTIFY
 * transaction with a `Subscription-State` of `terminated` completes", so
 * the closing notification is still answered and
 * `SIPRAL_EVENT_KIND_SUBSCRIPTION_CHANGED` with
 * `SIPRAL_SUBSCRIPTION_END_UNSUBSCRIBED` says when it has. One that has
 * no dialog yet has nothing to send this in and ends at once.
 *
 * The handle stays usable until that event arrives, and names nothing
 * after it.
 *
 * Safety
 *
 * Safe to call with any handle value.
 */
sipral_status_t sipral_subscription_end(sipral_handle_t stack, sipral_handle_t subscription, uint64_t now_ms);

/**
 * Where a subscription is, without waiting for its next event.
 *
 * SIPRAL_SUBSCRIPTION_STATE_UNKNOWN for a handle that names nothing,
 * which is what a subscription that has ended leaves behind — and a
 * status of `SIPRAL_STATUS_OK` all the same, because "it is over" is an
 * answer to this question rather than a failure of it.
 *
 * Safety
 *
 * `out_state` must point at one `uint32_t`.
 */
sipral_status_t sipral_subscription_state(sipral_handle_t stack, sipral_handle_t subscription, uint32_t *out_state);

/**
 * What a lamp for this subscription should show (A1).
 *
 * RFC 4235 §3.7.2's virtual state machine over every dialog the notifier
 * has told this subscription about: anything ringing beats anything
 * settled, and SIPRAL_DIALOG_PHASE_IDLE is what is left once they
 * have all ended. One call and one number, which is what a busy lamp
 * field is; sipral_subscription_dialog_count and the two after it
 * are for an application that wants to show who is on the call as well.
 *
 * `SIPRAL_STATUS_NOT_SUPPORTED` for a subscription that has no dialog
 * state at all — one to another package, or one that is not live, whose
 * last notification stopped being evidence the moment it stopped being
 * refreshed.
 *
 * Safety
 *
 * `out_phase` must point at one `uint32_t`.
 */
sipral_status_t sipral_subscription_lamp(sipral_handle_t stack, sipral_handle_t subscription, uint32_t *out_phase);

/**
 * How many dialogs this subscription has been told about.
 *
 * They are in the order they were first heard of, and the index one has
 * here is stable only until the next notification arrives: a dialog that
 * ended is dropped from the table, and the numbering closes up behind
 * it. Read a dialog out in the same breath as the count, and read them
 * both again on the next
 * SIPRAL_EVENT_KIND_NOTIFIED.
 *
 * Safety
 *
 * `out_count` must point at one `size_t`.
 */
sipral_status_t sipral_subscription_dialog_count(sipral_handle_t stack, sipral_handle_t subscription, size_t *out_count);

/**
 * One of them, by index.
 *
 * Safety
 *
 * `out_dialog` must point at a `sipral_watched_dialog_t` whose `size`
 * member says how long it is.
 */
sipral_status_t sipral_subscription_dialog_at(sipral_handle_t stack, sipral_handle_t subscription, size_t index, sipral_watched_dialog_t *out_dialog);

/**
 * A piece of text about one of them, copied into the caller's buffer.
 *
 * The same shape `sipral_last_error_message` has, and for the same
 * reason: the text belongs to the library and a pointer to it would be
 * one a caller could outlive. `out_needed` always receives the number of
 * bytes the text needs including the trailing NUL, so a caller that
 * brought nothing can ask with `capacity` zero and then ask again with
 * room. A buffer too small for the whole of it is
 * `SIPRAL_STATUS_BUFFER_TOO_SMALL` with nothing written to it.
 *
 * A piece the notifier did not send is one byte: the NUL.
 *
 * Safety
 *
 * `buffer` must be writable for `capacity` bytes, and `out_needed` must
 * point at one `size_t`.
 */
sipral_status_t sipral_subscription_dialog_text(sipral_handle_t stack, sipral_handle_t subscription, size_t index, uint32_t which, char *buffer, size_t capacity, size_t *out_needed);

/**
 * Send an instant message outside any dialog (RFC 3428 §3).
 *
 * One MESSAGE goes out on `account`'s transport, to `target`. The
 * handle written back names the send until its outcome arrives as
 * `SIPRAL_EVENT_KIND_MESSAGE_SENT`, whether or not the request reached a
 * transport at all.
 *
 * `body` is taken whole, including any byte a header field would
 * refuse — it is a body, not a header — and `content_type` is checked
 * the way any text argument at this boundary is.
 *
 * Safety
 *
 * `target` and `content_type` must be readable for their lengths, and
 * UTF-8. `body` must be readable for `body_len` bytes, or null with a
 * length of zero. `out_message` must point at one `sipral_handle_t`.
 */
sipral_status_t sipral_account_message(sipral_handle_t stack, sipral_handle_t account, const char *target, size_t target_len, const char *content_type, size_t content_type_len, const uint8_t *body, size_t body_len, sipral_handle_t *out_message, uint64_t now_ms);

/**
 * A call is expected on this account, announced by a push (C2).
 *
 * `caller` is whoever the notification said is calling, as a SIP URI.
 * The binding is refreshed at once on whatever path exists — §4.1.3
 * makes that a MUST for a woken agent, and a transport the application
 * has not opened yet is the ordinary shape of a wake-up, so the REGISTER
 * is owed and goes the moment one is bound.
 *
 * Exactly one of the two values written back names something, and which
 * one is a race the caller cannot control:
 *
 * - `out_announcement` when nothing has arrived yet. The INVITE that
 *   matches will be reported as `SIPRAL_EVENT_KIND_CALL_ANNOUNCED`
 *   naming this announcement, immediately before the
 *   `SIPRAL_EVENT_KIND_INCOMING_CALL` for the same call; and
 *   `SIPRAL_EVENT_KIND_ANNOUNCED_CALL_MISSING` when none does.
 * - `out_call` when the INVITE beat the push. The screen just raised
 *   belongs to that call handle, and no announcement was recorded for it
 *   to answer. A `SIPRAL_EVENT_KIND_CALL_ANNOUNCED` still arrives for it
 *   when the incoming-call event has not been delivered yet, because the
 *   two are queued together and in that order; once it has, this return
 *   value is the only word about the match there will be.
 *
 * An account with no registrar has no binding to refresh, and for one of
 * those only the matching happens.
 *
 * Safety
 *
 * `caller` must be readable for `caller_len` bytes, and each of
 * `out_announcement` and `out_call` must point at one `sipral_handle_t`.
 */
sipral_status_t sipral_account_announce(sipral_handle_t stack, sipral_handle_t account, const char *caller, size_t caller_len, sipral_handle_t *out_announcement, sipral_handle_t *out_call, uint64_t now_ms);

/**
 * Refresh the binding now, without announcing anything (C3).
 *
 * For the periodic wake-up a proxy sends to keep a suspended device's
 * binding alive (RFC 8599 §5.5). A push is evidence that the path to the
 * proxy is working, so a back-off earned by an earlier outage is not
 * what to wait for now and is dropped.
 *
 * Nothing is sent when a REGISTER is already in flight, which is already
 * the fastest path, or when the registration has failed in a way trying
 * again cannot fix — repeating a password that was refused is how an
 * account gets locked out, and a push does not change that. Both of those
 * are `SIPRAL_STATUS_OK`: the refresh was asked for and the answer is
 * that nothing needed sending.
 *
 * `SIPRAL_STATUS_INVALID_ARGUMENT` for an account that never registers,
 * which has no binding to refresh: it is the account that is wrong for
 * this call, not the build that is missing the feature. A send that could
 * not happen because no transport is bound yet is reported too, and is
 * not fatal: the refresh is remembered and goes out the moment one is.
 *
 * Safety
 *
 * Safe to call with any handle value.
 */
sipral_status_t sipral_account_refresh_binding(sipral_handle_t stack, sipral_handle_t account, uint64_t now_ms);

/**
 * Stop expecting an announced call.
 *
 * The user dismissed the screen, or the application decided the wake-up
 * was stale. `SIPRAL_STATUS_WRONG_STATE` when it had already been
 * fulfilled or had already expired, which is not a mistake: the event
 * that said so and this call can cross.
 *
 * Safety
 *
 * Safe to call with any handle value.
 */
sipral_status_t sipral_announcement_forget(sipral_handle_t stack, sipral_handle_t announcement);

/**
 * What the registrar said about push, in the 2xx to the REGISTER that
 * asked for it.
 *
 * `SIPRAL_STATUS_NOT_SUPPORTED` when this account did not ask for push,
 * or when no binding it could have been said about is standing — none
 * granted yet, one given up, or one that has lapsed.
 *
 * Safety
 *
 * `out_echo` must point at a `sipral_push_echo_t` whose `size` member
 * says how long it is.
 */
sipral_status_t sipral_account_push_echo(sipral_handle_t stack, sipral_handle_t account, sipral_push_echo_t *out_echo);

/**
 * Configure an account, and write its handle to `out_account`.
 *
 * Nothing is sent. The account exists until sipral_account_remove or
 * until the stack is destroyed.
 *
 * Safety
 *
 * `config` must point at a `sipral_account_config_t` whose `size` member
 * says how long it is, with every pointer in it readable for the length
 * beside it, and `out_account` at one `sipral_handle_t`.
 */
sipral_status_t sipral_account_add(sipral_handle_t stack, const sipral_account_config_t *config, sipral_handle_t *out_account);

/**
 * Forget an account, and everything scheduled for it.
 *
 * Nothing is sent: an account being removed may be one whose registrar is
 * unreachable, and waiting on that is not this call's job. Give the
 * binding up politely with sipral_account_unregister first when it
 * matters.
 *
 * Safety
 *
 * Safe to call with any handle values.
 */
sipral_status_t sipral_account_remove(sipral_handle_t stack, sipral_handle_t account);

/**
 * Register, and keep the binding alive until told otherwise.
 *
 * Refreshes, credential retries and the back-off after an outage all
 * happen without another call. What stops them is
 * sipral_account_unregister, or a refusal that trying again cannot
 * fix. Every step of it arrives as a `SIPRAL_EVENT_KIND_REGISTRATION_CHANGED`.
 *
 * An account configured with no registrar never registers, and this
 * answers `SIPRAL_STATUS_INVALID_ARGUMENT` for it with nothing sent.
 *
 * Safety
 *
 * Safe to call with any handle values.
 */
sipral_status_t sipral_account_register(sipral_handle_t stack, sipral_handle_t account, uint64_t now_ms);

/**
 * Give the binding up: a REGISTER with `Expires: 0` (§10.2.2).
 *
 * Only this device's binding. A `Contact: *` would remove every binding
 * the address of record has, including the one belonging to the desk
 * phone somebody else is holding.
 *
 * An account configured with no registrar has no binding to give up, and
 * is refused the way `sipral_account_register` refuses it.
 *
 * Safety
 *
 * Safe to call with any handle values.
 */
sipral_status_t sipral_account_unregister(sipral_handle_t stack, sipral_handle_t account, uint64_t now_ms);

/**
 * Where an account's registration is, as a `SipralRegistrationState`.
 *
 * An account configured with no registrar answers
 * `SIPRAL_REGISTRATION_STATE_NOT_REGISTERING`, always.
 *
 * Safety
 *
 * `out_state` must point at one `uint32_t`.
 */
sipral_status_t sipral_account_registration_state(sipral_handle_t stack, sipral_handle_t account, uint32_t *out_state);

/**
 * Place a call, and write its handle to `out_call`.
 *
 * The handle exists from here on, before any dialog does, because there
 * has to be something to hang up with while the INVITE is still in
 * flight. A proxy that forks the INVITE gives the branches handles of
 * their own, reported as `SIPRAL_EVENT_KIND_CALL_FORKED`.
 *
 * With `media_address` set, the offer is this stack's to write and the
 * call gets audio of its own: `SIPRAL_EVENT_KIND_MEDIA_STARTED` says when,
 * and `crate::media` carries the packets from then on. `config.srtp`
 * overrides `sipral_stack_config_t::srtp` for such a call; it is read for
 * no other kind.
 *
 * Safety
 *
 * `config` must point at a `sipral_call_config_t` whose `size` member
 * says how long it is, with every pointer in it readable for the length
 * beside it, and `out_call` at one `sipral_handle_t`.
 */
sipral_status_t sipral_call_place(sipral_handle_t stack, sipral_handle_t account, const sipral_call_config_t *config, sipral_handle_t *out_call, uint64_t now_ms);

/**
 * Say a call that came in is ringing.
 *
 * A description makes it a 183 Session Progress rather than a 180
 * Ringing, because 180 with a body is a contradiction the far end has to
 * guess at. Pass none for the ordinary case.
 *
 * Safety
 *
 * `sdp` must be null or readable for `sdp_len` bytes.
 */
sipral_status_t sipral_call_ring(sipral_handle_t stack, sipral_handle_t call, const uint8_t *sdp, size_t sdp_len, uint64_t now_ms);

/**
 * Say a call that came in is ringing, with this stack running the audio
 * before anybody answers.
 *
 * The answer to the offer the INVITE carried is written from this
 * stack's codec order, against `config.media_address` — where this end
 * will receive media, which only the application can say because it owns
 * the socket — and the session opens on it there and then: the far end
 * hears whatever the application plays before anybody picks up.
 * `SIPRAL_EVENT_KIND_MEDIA_STARTED` follows.
 *
 * `config.srtp` overrides the stack's own SRTP policy for this call, the
 * same way it does on `sipral_call_place`; it is the one way an incoming
 * call can choose its own SRTP policy at all, since
 * `sipral_call_answer_media` reads no configuration of its own. Once
 * this has set it, `sipral_call_answer_media` keeps it: it is answering
 * a call that already has a catalogue, not choosing one.
 *
 * `config.codecs` overrides the stack's codec order for this call in the
 * same way and for the same window: the answer written here is written
 * from it, and `sipral_call_answer_media` keeps what it settled.
 *
 * `sipral_call_answer_media` after this reuses the session and the
 * description written here rather than negotiating a second one. What
 * the 200 OK it sends carries then follows RFC 3262 §5 and RFC 6337
 * §3.1.1 exactly, from whether this call's 183 went out reliably — see
 * `docs/05-media.md`, "Ringing with media".
 *
 * Every other member of `config` — `target`, `sdp`, `destination`,
 * `transport`, `keep_all_forks`, `headers` — names something a call to
 * place would need, and this call already exists; setting one of them
 * is `SIPRAL_STATUS_INVALID_ARGUMENT` naming it.
 *
 * An INVITE that carried no offer is `SIPRAL_STATUS_WRONG_STATE`, with
 * nothing sent: the offer this end would make instead belongs in no
 * provisional response this stack can follow up (RFC 3261 §13.2.1,
 * RFC 6337 §3.1.2).
 *
 * Calling this twice on one call is `SIPRAL_STATUS_WRONG_STATE`, and so is
 * calling it after a `sipral_call_ring` that sent a description of the
 * application's own: every description in the responses to one INVITE
 * has to be that same one (RFC 3261 §13.2.1, RFC 6337 §3.1.1). After a
 * `sipral_call_ring` that sent none, it is not.
 *
 * Safety
 *
 * `config` must point at a `sipral_call_config_t` whose `size` member
 * says how long it is, with `media_address` readable for
 * `media_address_len` bytes.
 */
sipral_status_t sipral_call_ring_media(sipral_handle_t stack, sipral_handle_t call, const sipral_call_config_t *config, uint64_t now_ms);

/**
 * Answer a call that came in.
 *
 * `sdp` is the answer to the offer the INVITE carried, and is required:
 * answering with nothing puts the offer on this end and the answer in the
 * far end's ACK, which this ABI has no way to hand back.
 *
 * Safety
 *
 * `sdp` must be readable for `sdp_len` bytes.
 */
sipral_status_t sipral_call_answer(sipral_handle_t stack, sipral_handle_t call, const uint8_t *sdp, size_t sdp_len, uint64_t now_ms);

/**
 * Answer a call that came in, and let this stack run its audio.
 *
 * The answer to the offer the INVITE carried is written from this stack's
 * codec order, against `media_address` — where this end will receive
 * media, which only the application can say because it owns the socket.
 * `SIPRAL_EVENT_KIND_MEDIA_STARTED` follows once the stream is open.
 *
 * The other half of `sipral_call_place` with `media_address` set, and the
 * alternative to `sipral_call_answer`, which answers with a description
 * the application wrote and leaves the audio to it.
 *
 * On a call `sipral_call_ring_media` already rang, nothing is written and
 * no second session opens: the 183's description and session stand,
 * `SIPRAL_EVENT_KIND_MEDIA_STARTED` has already been reported, and
 * `media_address` must still be an address and a port but is not used.
 * The 200 OK repeats that description when the 183 went out unreliably and
 * carries none when it went out reliably (RFC 6337 §3.1.1).
 *
 * Safety
 *
 * `media_address` must be readable for `media_address_len` bytes.
 */
sipral_status_t sipral_call_answer_media(sipral_handle_t stack, sipral_handle_t call, const char *media_address, size_t media_address_len, uint64_t now_ms);

/**
 * Refuse a call that came in, with a response code of your choosing.
 *
 * 486 Busy Here for a line that is in use, 603 Decline for a person who
 * does not want to talk. The difference is what a proxy does next.
 *
 * Safety
 *
 * Safe to call with any handle values.
 */
sipral_status_t sipral_call_reject(sipral_handle_t stack, sipral_handle_t call, uint32_t code, uint64_t now_ms);

/**
 * Hang up, whatever the call is doing.
 *
 * A CANCEL before it is answered, a BYE after, a refusal for one that
 * came in and has not been answered. A call that is already ending is
 * left alone rather than refused.
 *
 * Safety
 *
 * Safe to call with any handle values.
 */
sipral_status_t sipral_call_hangup(sipral_handle_t stack, sipral_handle_t call, uint64_t now_ms);

/**
 * Set the header fields that go on what this call sends at the
 * application's request, from now until they are set again.
 *
 * They go on the 180 or 183 from `sipral_call_ring`, the 200 from
 * `sipral_call_answer` and `sipral_call_answer_media`, the refusal from
 * `sipral_call_reject`, the refusal or the BYE that `sipral_call_hangup`
 * turns into, and the re-INVITE or UPDATE that `sipral_call_hold` and
 * `sipral_call_resume` send. Kept rather than spent on the first of those,
 * so that a field set before ringing is on the 200 as well. Never on a
 * CANCEL, which a proxy answers and replaces with its own, and never on
 * what the stack sends by itself: a session refresh, or the BYE for a 2xx
 * that was never acknowledged or for a fork that lost.
 *
 * Replaces what was set before, whole, and a `headers_len` of zero takes
 * every field off. Each field is checked first, as it is on
 * `sipral_call_config_t::headers`, and a refusal names the element, keeps
 * none of the new fields and leaves the old ones in place. Nothing is
 * sent.
 *
 * Safety
 *
 * `headers` must be null with `headers_len` zero, or readable for
 * `headers_len` elements, each with a name and a value readable for the
 * lengths beside them.
 */
sipral_status_t sipral_call_set_headers(sipral_handle_t stack, sipral_handle_t call, const sipral_header_t *headers, size_t headers_len);

/**
 * Put a call on hold (RFC 3264 §8.4).
 *
 * The description is the stack's to write: the one already negotiated
 * with every stream's direction changed. Asking for a hold that is
 * already in place, or already on its way, sends nothing and succeeds.
 *
 * Asked for while another session change is running in the call, in
 * either direction, it succeeds and waits: its request goes once that
 * change is over (RFC 3261 §14.1), and the outcome arrives as
 * `SIPRAL_EVENT_KIND_SESSION_CHANGED` or
 * `SIPRAL_EVENT_KIND_SESSION_CHANGE_FAILED` like any other. What waits
 * is the state asked for last, so a resume asked for behind a hold still
 * on its way goes after it. One still waiting when the call ends is
 * never sent, and `SIPRAL_EVENT_KIND_CALL_ENDED` is the last word on it.
 *
 * Safety
 *
 * Safe to call with any handle values.
 */
sipral_status_t sipral_call_hold(sipral_handle_t stack, sipral_handle_t call, uint64_t now_ms);

/**
 * Take it off hold again.
 *
 * Every stream goes back to the direction it had before, which is not
 * always both ways: one that was offered receive-only is resumed
 * receive-only. It waits for a change already running exactly as
 * `sipral_call_hold` does.
 *
 * Safety
 *
 * Safe to call with any handle values.
 */
sipral_status_t sipral_call_resume(sipral_handle_t stack, sipral_handle_t call, uint64_t now_ms);

/**
 * Offer a call again on another list of codecs (RFC 3264 §8.3.2).
 *
 * `codecs` names them the way `sipral_call_config_t::codecs` does:
 * separated by commas, in the order to offer them. Only the codecs
 * change. Everything else the call has agreed is offered again as it
 * is — its media address, its SRTP key or DTLS fingerprint, its ICE
 * credentials — so nothing is re-keyed and nothing restarts, and a call
 * on hold stays on hold: `sipral_call_resume` takes it off, on the new
 * list. A dynamic payload type keeps the codec it has named on this
 * call, and a codec new to it gets a number nothing has had.
 *
 * The list becomes the call's own once the far end accepts it, and
 * `SIPRAL_EVENT_KIND_MEDIA_CHANGED` names the codec its answer settled
 * on. A refusal arrives as `SIPRAL_EVENT_KIND_SESSION_CHANGE_FAILED` and
 * leaves the call on the list it had.
 *
 * For a call whose media the stack describes: one placed or answered
 * with `media_address` set. `SIPRAL_STATUS_NOT_SUPPORTED` for a name
 * this build has no codec behind; `SIPRAL_STATUS_INVALID_ARGUMENT` for a
 * list that is empty, names a codec twice or has a stray comma;
 * `SIPRAL_STATUS_WRONG_STATE` for a call the stack writes no description
 * for, one with none agreed yet, one whose stream was refused (a change
 * of codecs does not bring it back), one still early with a far end that
 * never listed UPDATE, or while another change is on its way;
 * `SIPRAL_STATUS_EXHAUSTED` when a codec new to the call finds every
 * dynamic payload type number already taken.
 *
 * Safety
 *
 * `codecs` must be readable for `codecs_len` bytes.
 */
sipral_status_t sipral_call_change_codecs(sipral_handle_t stack, sipral_handle_t call, const char *codecs, size_t codecs_len, uint64_t now_ms);

/**
 * Join two active calls into a local conference of three: from here on,
 * each call's far end hears the other's far end and this end's own
 * microphone, mixed. sipral_media_mix
 * drives one frame of it at a time, on the two calls' own media
 * handles; this only records the pairing.
 *
 * Nothing like a SIP conference server: neither far end's own signalling
 * ever names the other, and this stack sends no `Refer-To`. Both calls
 * must already have media running — placed or answered with
 * `media_address` set, and negotiated — and must agree on a sample rate
 * and a frame length, since nothing here resamples.
 *
 * `SIPRAL_STATUS_INVALID_ARGUMENT` for `call_a == call_b`;
 * `SIPRAL_STATUS_WRONG_STATE` for a call with no running session, a call
 * already joined to another, or two calls whose sessions would decode
 * at different rates or cut audio into frames of different lengths.
 *
 * Safety
 *
 * Safe to call with any handle values.
 */
sipral_status_t sipral_call_join(sipral_handle_t stack, sipral_handle_t call_a, sipral_handle_t call_b);

/**
 * Take `call` back out of the pair it is in.
 *
 * Neither call's session is touched: each one goes back to carrying its
 * own audio directly, through `sipral_media_playback` and
 * `sipral_media_capture`, exactly as an unjoined call always has.
 *
 * `SIPRAL_STATUS_WRONG_STATE` for a call that is not currently joined to
 * another.
 *
 * Safety
 *
 * Safe to call with any handle values.
 */
sipral_status_t sipral_call_leave(sipral_handle_t stack, sipral_handle_t call);

/**
 * Accept a change the far end offered, reported as
 * `SIPRAL_EVENT_KIND_SESSION_OFFERED`.
 *
 * `sdp` is the answer to the offer it carried, and is left out only for a
 * request that carried none. A re-INVITE nobody answers is retransmitted
 * and then ends the call, so this or sipral_call_reject_session has
 * to follow that event.
 *
 * Only for a call the application describes. One this stack describes
 * answers its own re-offers, from the same codec order, before the poll
 * that saw the request returns — so the event never arrives and this is
 * `SIPRAL_STATUS_WRONG_STATE`.
 *
 * Safety
 *
 * `sdp` must be null or readable for `sdp_len` bytes.
 */
sipral_status_t sipral_call_accept_session(sipral_handle_t stack, sipral_handle_t call, const uint8_t *sdp, size_t sdp_len, uint64_t now_ms);

/**
 * Refuse one instead. The session stands exactly as it was (§14.1).
 *
 * 488 Not Acceptable Here is the code that says the description was the
 * problem rather than the request.
 *
 * As with sipral_call_accept_session, only for a call the application
 * describes.
 *
 * Safety
 *
 * Safe to call with any handle values.
 */
sipral_status_t sipral_call_reject_session(sipral_handle_t stack, sipral_handle_t call, uint32_t code, uint64_t now_ms);

/**
 * Send DTMF on a call that is up, in whichever of the three forms the far
 * end takes.
 *
 * `digits` are `0` to `9`, `*`, `#` and `A` to `D`, the sixteen events of
 * RFC 4733 §3.2, in the order they were pressed, checked as a whole
 * before anything goes out: one character no keypad has, anywhere in the
 * string, sends nothing, not even the keys ahead of it. `duration_ms` is
 * how long each one lasts, or zero for the hundred milliseconds every
 * one of the three forms defaults to.
 *
 * `via` is a sipral_dtmf_t, and it is chosen per send rather than per
 * call: which form a peer accepts is a fact about the peer, and an
 * application that has just learned the answer for this one must not have
 * to tear the call down to act on it. `SIPRAL_DTMF_RTP` puts the digits in
 * the media, where they replace the audio for as long as they last and
 * queue behind each other. The two INFO forms put one request per digit
 * in the dialog, but not all at once: over UDP, overlapping non-INVITE
 * transactions can arrive in any order, so the next digit's INFO waits
 * for the one before it to reach a final answer. A 2xx sends it; a
 * refusal, a timeout or a transport failure ends the sequence there
 * instead, and the digits still waiting are discarded rather than sent
 * out of order — the digit that ended it is what
 * `SIPRAL_EVENT_KIND_DTMF_SENT` names, and nothing is reported for the
 * ones it took down with it. Digits handed over while an INFO of this
 * call is still unanswered queue behind the ones already waiting, as the
 * media's do, rather than go out at once. A call holds at most sixty-four
 * INFO digits at once, the one in flight included; a string that would
 * take it past that is refused whole with `SIPRAL_STATUS_INVALID_ARGUMENT`,
 * the same as one with a character no keypad has, and nothing of it is
 * sent.
 *
 * `SIPRAL_STATUS_NOT_SUPPORTED` from `SIPRAL_DTMF_RTP` on a call whose
 * negotiation settled on no telephone event payload type: the key is a
 * real key and this call has nowhere in the media to put it. The INFO
 * forms need a dialog rather than a negotiation, and answer
 * `SIPRAL_STATUS_WRONG_STATE` before there is one.
 *
 * Safety
 *
 * `digits` must be readable for `digits_len` bytes.
 */
sipral_status_t sipral_call_send_dtmf(sipral_handle_t stack, sipral_handle_t call, const char *digits, size_t digits_len, uint32_t via, uint32_t duration_ms, uint64_t now_ms);

/**
 * Ask the far end to call somebody else, and hang up when it has
 * (RFC 3515).
 *
 * A blind transfer: nobody consults the destination first. This end stays
 * in the call until the transfer has succeeded, because hanging up first
 * turns a transfer that failed into a call that vanished. Progress
 * arrives as `SIPRAL_EVENT_KIND_TRANSFER_PROGRESS` and then
 * `SIPRAL_EVENT_KIND_TRANSFER_DONE`.
 *
 * Safety
 *
 * `target` must be readable for `target_len` bytes.
 */
sipral_status_t sipral_call_transfer(sipral_handle_t stack, sipral_handle_t call, const char *target, size_t target_len, uint64_t now_ms);

/**
 * Call the transfer target, so that there is somebody to hand the call
 * to, and write the new call's handle to `out_consultation`.
 *
 * The consultation leg of an attended transfer. It is answered like any
 * other call, and sipral_call_transfer_to is what follows. Putting
 * `call` on hold first is the application's: it is a session change, and
 * this stack does not make those uninvited.
 *
 * `media_address` is `SIPRAL_STATUS_NOT_SUPPORTED` here. The media engine
 * places and answers calls; it does not consult, and a consultation leg
 * registered with it by hand would be one it has described nothing for.
 * A consultation with audio is placed with `sdp` and run by the
 * application, as every call was before this stack carried media.
 *
 * Safety
 *
 * As sipral_call_place.
 */
sipral_status_t sipral_call_consult(sipral_handle_t stack, sipral_handle_t call, const sipral_call_config_t *config, sipral_handle_t *out_consultation, uint64_t now_ms);

/**
 * Hand `call` to the far end of `other` (RFC 3891).
 *
 * The attended half of a transfer: `other` is normally the consultation
 * call, and the party at its far end replaces the call it already has
 * rather than answering a second one. Any call that is up may be named.
 *
 * Safety
 *
 * Safe to call with any handle values.
 */
sipral_status_t sipral_call_transfer_to(sipral_handle_t stack, sipral_handle_t call, sipral_handle_t other, uint64_t now_ms);

/**
 * Take a transfer that was asked for, place the call it names the way
 * sipral_call_place places one, and write its handle to
 * `out_placed`.
 *
 * `config.target` is not read: the far end already said where this goes
 * when it asked for the transfer, and a target of the caller's own would
 * be a second one contradicting it — `SIPRAL_STATUS_INVALID_ARGUMENT`
 * naming it. Everything else in `config` means what it means on
 * `sipral_call_place`: `sdp` for a description the application wrote and
 * runs the audio of, `media_address` for one this stack writes and runs
 * (`config.srtp` overriding the stack's own policy for it, the same
 * way), `headers`, `destination`, `transport` and `keep_all_forks` for
 * the INVITE this places. `Replaces` and `Referred-By` among `headers`
 * are `SIPRAL_STATUS_INVALID_ARGUMENT`, nothing sent and the transfer still
 * there to take: that INVITE takes both from the REFER. Giving neither
 * `sdp` nor `media_address` is
 * `SIPRAL_STATUS_INVALID_ARGUMENT`, for the same reason it is on
 * `sipral_call_place`: the answer to an offerless INVITE has nowhere to
 * go but the ACK, and this ABI hands nothing back from there.
 *
 * Safety
 *
 * `config` must point at a `sipral_call_config_t` whose `size` member
 * says how long it is, with every pointer in it readable for the length
 * beside it, and `out_placed` at one `sipral_handle_t`.
 */
sipral_status_t sipral_call_accept_transfer(sipral_handle_t stack, sipral_handle_t call, const sipral_call_config_t *config, sipral_handle_t *out_placed, uint64_t now_ms);

/**
 * Refuse one instead.
 *
 * Safety
 *
 * Safe to call with any handle values.
 */
sipral_status_t sipral_call_reject_transfer(sipral_handle_t stack, sipral_handle_t call, uint32_t code, uint64_t now_ms);

/**
 * Where a call is, as a `SipralCallState`.
 *
 * A call that is over answers `SIPRAL_CALL_STATE_TERMINATED` until the
 * poll that delivers `SIPRAL_EVENT_KIND_CALL_ENDED` retires its handle, and
 * `SIPRAL_STATUS_STALE_HANDLE` after that.
 *
 * Safety
 *
 * `out_state` must point at one `uint32_t`.
 */
sipral_status_t sipral_call_state(sipral_handle_t stack, sipral_handle_t call, uint32_t *out_state);

/**
 * Which way a call is held: `out_here` is set when this end asked the far
 * end to stop sending, `out_there` when the far end asked this one.
 * Either may be null.
 *
 * Safety
 *
 * `out_here` and `out_there` must each be null or point at one
 * `uint32_t`.
 */
sipral_status_t sipral_call_hold_state(sipral_handle_t stack, sipral_handle_t call, uint32_t *out_here, uint32_t *out_there);

/**
 * The name of a codec, as a static NUL-terminated string, or null for a
 * number this build has no codec for.
 *
 * It is spelled as IANA registered it, which is also how it goes on an
 * `a=rtpmap` line. The string belongs to the library and lives as long as
 * it is loaded.
 *
 * Safety
 *
 * Reads no memory the caller owns, and is safe to call from any thread.
 */
const char *sipral_codec_name(uint32_t codec);

/**
 * How many codecs this build contains.
 *
 * A compile-time fact, and the reason A4 starts here rather than at a
 * configuration: no setting can add a codec that was not linked.
 *
 * Safety
 *
 * `out_count` must point at one `size_t`.
 */
sipral_status_t sipral_codec_count(size_t *out_count);

/**
 * One of them, by index, from zero to what `sipral_codec_count` said.
 *
 * The order is this build's own preference, quality first, which is what
 * is offered when nobody has said otherwise — all of it but G.729, which
 * is listed last and offered only where a codec order names it.
 *
 * Safety
 *
 * `out_info` must point at a `sipral_codec_info_t` whose `size` member
 * says how long it is.
 */
sipral_status_t sipral_codec_at(size_t index, sipral_codec_info_t *out_info);

/**
 * The codecs this stack offers, in the order it offers them.
 *
 * The other half of the configuration: `codecs` in
 * `sipral_stack_config_t` says what to offer, and this says what that came
 * to. `out_count` always receives the number there are, so a caller that
 * passes a capacity of zero and a null buffer learns how much room to
 * bring and gets `SIPRAL_STATUS_BUFFER_TOO_SMALL`.
 *
 * Safety
 *
 * `out_codecs` must be writable for `capacity` `uint32_t` or null with a
 * capacity of zero, and `out_count` must point at one `size_t` or be null.
 */
sipral_status_t sipral_stack_codec_order(sipral_handle_t stack, uint32_t *out_codecs, size_t capacity, size_t *out_count);

/**
 * A handle on one call's media, written to `out_media`.
 *
 * Mint it once the call's negotiation has settled —
 * `SIPRAL_EVENT_KIND_MEDIA_STARTED` is the moment, and minting from inside
 * that event's callback is allowed — and hand it to every `sipral_media_`
 * entry point in place of the stack and the call. None of those takes the
 * stack's lock, which is the point: the thread that carries a call's audio
 * is never refused a frame because signalling, the event callback or
 * another call is busy.
 *
 * `SIPRAL_STATUS_WRONG_STATE` for a call with no media: one placed with a
 * description of the caller's own, or one whose negotiation has not
 * settled. The handle is written only if this returns `SIPRAL_STATUS_OK`.
 *
 * The handle outlives the call. Once the call ends, or its stack is
 * destroyed, every media entry point answers `SIPRAL_STATUS_WRONG_STATE`
 * on it; a hold, a resume or a change of codec keeps it working. Each
 * handle minted is released once with `sipral_media_release`, and asking
 * twice for the same call gives two.
 *
 * Safety
 *
 * `out_media` must point at one `sipral_handle_t`.
 */
sipral_status_t sipral_call_media(sipral_handle_t stack, sipral_handle_t call, sipral_handle_t *out_media);

/**
 * Let a media handle go.
 *
 * Its one matching free, whether or not its call is still up and whether
 * or not its stack still exists. The session is not touched: it belongs to
 * the call and ends when the call does, so releasing a handle mid-call
 * stops nothing but the handle. A handle released twice is
 * `SIPRAL_STATUS_STALE_HANDLE` the second time.
 *
 * Safety
 *
 * Safe to call with any handle value. Reads no memory the caller owns.
 */
sipral_status_t sipral_media_release(sipral_handle_t media);

/**
 * What one call's media settled on.
 *
 * Safety
 *
 * `out_info` must point at a `sipral_media_info_t` whose `size` member
 * says how long it is.
 */
sipral_status_t sipral_media_info(sipral_handle_t media, sipral_media_info_t *out_info);

/**
 * How many codecs were in the running on this call.
 *
 * This call's own catalogue, which is the stack's order unless
 * `sipral_call_config_t::codecs` named another. Zero is an answer, not a
 * failure: a call negotiated from a description with no media line in it
 * had nothing in the running at all.
 *
 * Safety
 *
 * `out_count` must point at one `size_t`.
 */
sipral_status_t sipral_media_codec_candidate_count(sipral_handle_t media, size_t *out_count);

/**
 * One of them, by index, from zero to what
 * `sipral_media_codec_candidate_count` said, in this call's own order.
 *
 * D5 in one place: what this end offered, what the far end named, and
 * which of the two ran out first. An index past the end is
 * `SIPRAL_STATUS_INVALID_ARGUMENT` naming how many there are.
 *
 * Safety
 *
 * `out_candidate` must point at a `sipral_codec_candidate_t` whose `size`
 * member says how long it is.
 */
sipral_status_t sipral_media_codec_candidate_at(sipral_handle_t media, size_t index, sipral_codec_candidate_t *out_candidate);

/**
 * What one call's media has cost, and what it is costing now.
 *
 * A6's live half. `now_ms` is the caller's monotonic clock, as everywhere
 * else, because "how long since a packet arrived" is a question about the
 * present and nothing here reads a clock to answer it. Like every media
 * entry point, this does not move the stack's own clock: it is read at the
 * frame rate of a user interface, often from the thread that draws one,
 * and a reading a millisecond behind the last poll is not a caller bug.
 *
 * The end-of-call record arrives instead as
 * `SIPRAL_EVENT_KIND_MEDIA_STATISTICS`, because by then the stream is
 * gone and this answers `SIPRAL_STATUS_WRONG_STATE`.
 *
 * Safety
 *
 * `out_stats` must point at a `sipral_stream_stats_t` whose `size` member
 * says how long it is.
 */
sipral_status_t sipral_media_statistics(sipral_handle_t media, uint64_t now_ms, sipral_stream_stats_t *out_stats);

/**
 * Take a datagram off the media socket.
 *
 * One entry point for both sockets: RTP and RTCP are told apart by
 * RFC 5761 §4's rule on the payload type field, so a caller that put both
 * on one socket does not have to sort them, and one that did not can hand
 * over whichever arrived.
 *
 * `data` is written through. A secured stream is opened in place, and a
 * caller that needs the ciphertext afterwards keeps its own copy.
 *
 * `out_arrival` may be null for a caller that does not want to know what
 * the datagram turned out to be.
 *
 * `now_ms` is when it arrived, on the stack's clock. Reading it here moves
 * nothing: the network thread and the poll thread read that clock apart,
 * and a datagram a millisecond behind the last poll is not refused.
 *
 * Safety
 *
 * `data` must be readable and writable for `len` bytes, `from` readable
 * for `from_len`, and `out_arrival` must point at one `uint32_t` or be
 * null.
 */
sipral_status_t sipral_media_receive(sipral_handle_t media, uint8_t *data, size_t len, const char *from, size_t from_len, uint64_t now_ms, uint32_t *out_arrival);

/**
 * Take the frame that is due for the earpiece, and say where it came from.
 *
 * Exactly `sipral_media_info_t::frame_samples` samples are written, and a
 * smaller buffer is `SIPRAL_STATUS_BUFFER_TOO_SMALL` with the number
 * needed in `out_written`. Every source fills the frame, concealment and
 * silence included: a device handed nothing for one frame plays whatever
 * was in its buffer last, and that is a far worse sound than the one being
 * concealed.
 *
 * Safety
 *
 * `samples` must be writable for `capacity` `int16_t`, `out_written` must
 * point at one `size_t` or be null, and `out_source` at one `uint32_t` or
 * be null.
 */
sipral_status_t sipral_media_playback(sipral_handle_t media, int16_t *samples, size_t capacity, size_t *out_written, uint32_t *out_source);

/**
 * Put one frame from the microphone on the wire.
 *
 * `sample_count` is `sipral_media_info_t::frame_samples` and nothing else:
 * a codec cuts one frame at one length, and half a frame encoded as a
 * whole one is what a peer hears as a stutter.
 *
 * A `len` of zero in the packet means the frame was deliberately not sent:
 * this end is holding the far end, silence suppression swallowed it, or
 * ICE has not chosen a path for this call yet. The RTP timestamp moves by
 * a frame in the first two cases, because RFC 3550 §5.1 makes it a
 * measure of time rather than of packets; in the third nothing is
 * encoded at all, since there is no packet for the timestamp to belong
 * to and a codec that carries state would have moved it for nothing.
 *
 * `now_ms` is read as the stack reads it and moves nothing, as with every
 * media entry point. It is what tells ICE that traffic went out on the
 * pair it chose, which is what RFC 8445 §11 lets it stop sending
 * keepalives for.
 *
 * Safety
 *
 * `samples` must be readable for `sample_count` `int16_t`, and `packet`
 * must point at a `sipral_media_packet_t` whose `size` member says how
 * long it is and whose buffers are writable for the capacities beside
 * them.
 */
sipral_status_t sipral_media_capture(sipral_handle_t media, uint64_t now_ms, const int16_t *samples, size_t sample_count, sipral_media_packet_t *packet);

/**
 * Run `process` over every frame captured on this call, against the
 * far-end audio this call played MediaSession::render_delay earlier
 * — echo cancellation, gain control and noise suppression are all this
 * one seam, and `docs/05-media.md` says why.
 *
 * What was attached before is dropped, along with the echo path it had
 * learned. Attaching mid-call is allowed and costs the first few hundred
 * milliseconds of a fresh adaptation, the same price a call pays at its
 * start.
 *
 * **`process` runs with this call's media locked**, the same as
 * crate::screening::SipralScreenCallback and unlike
 * crate::event::SipralEventCallback: it is called from inside
 * sipral_media_playback (to learn what the loudspeaker was just
 * given) and inside sipral_media_capture (to run the frame just
 * captured), and — with sipral_processor_frame_t's `reset` set — whenever
 * this call's media forgets what it has learned, a device change or a
 * codec change mid-call. All three run on whichever thread called the
 * entry point that triggered them. In consequence, **it must not call
 * back into the media handle it was attached through**, on this thread
 * or on any other — doing so does not deadlock, since every media entry
 * point takes its session's lock without waiting and answers
 * `SIPRAL_STATUS_BUSY` rather than block, but it is refused outright
 * rather than relied on. A *different* call's media, or this stack's
 * own entry points, are unaffected. It must not unwind: a panic that
 * reached C across this boundary would take the host process with it,
 * the same rule every callback in this ABI is held to.
 *
 * `user_data` is handed back to `process` untouched on every call, read
 * by nothing here, and has to outlive the last one — which the caller
 * who installed it is the one to know is over:
 * `sipral_call_detach_processor` or the call ending are the two ways.
 *
 * Safety
 *
 * `process` is called on whichever thread calls
 * sipral_media_playback or sipral_media_capture on this call,
 * for as long as the processor stays attached, and `user_data` has to
 * outlive the last such call.
 */
sipral_status_t sipral_call_attach_processor(sipral_handle_t media, sipral_processor_callback_t process, void *user_data);

/**
 * Stop running the processor sipral_call_attach_processor attached,
 * if there was one.
 *
 * `out_was_attached`, when not null, says whether there was one to stop:
 * 1 if a processor was attached and is now detached, 0 if there was
 * none. The frames the application hands over reach the encoder
 * untouched again from the next one, and the loudspeaker history kept
 * for it is released. Once this returns, `process` is not called again
 * for this attachment — the moment `user_data` may be freed.
 *
 * Safety
 *
 * `out_was_attached` must point at one `uint32_t` or be null.
 */
sipral_status_t sipral_call_detach_processor(sipral_handle_t media, uint32_t *out_was_attached);

/**
 * Forget the echo path, the noise floor and the gain the attached
 * processor has learned, keeping the processor itself attached.
 *
 * What a device change asks for: the estimate was built for a different
 * loudspeaker and a different microphone, and carrying it forward makes
 * the processor fight it for a while instead of adapting cleanly. Calls
 * the `process` given to sipral_call_attach_processor with
 * sipral_processor_frame_t's `reset` set.
 *
 * `out_was_attached`, when not null, says whether there was a processor
 * to reset: 1 if there was, 0 if there was none.
 *
 * Safety
 *
 * `out_was_attached` must point at one `uint32_t` or be null.
 */
sipral_status_t sipral_call_reset_processor(sipral_handle_t media, uint32_t *out_was_attached);

/**
 * One frame of a local conference of two calls: decode what `media_a`'s
 * and `media_b`'s far ends each sent, mix what each of the three
 * parties — the two far ends and this end — is owed, and send the two
 * frames the far ends are owed.
 *
 * `sipral_call_join` must already have paired the two calls these two
 * handles belong to. Nothing here checks that itself: checking it would
 * mean taking the stack's lock on every frame, which is exactly what a
 * media handle exists to avoid, so this mixes whatever two handles it is
 * given — the same trust every other `sipral_media_` entry point places
 * in the caller having minted the handle from a call worth acting on.
 *
 * `mic` is this end's own frame, `mic_count` long; `local` is filled
 * with what this end's own loudspeaker is owed, `local_count` long. Both
 * are `sipral_media_info_t::frame_samples` on a call this pair actually
 * agreed on — `sipral_call_join` already made that the same on both.
 * `packet_a` and `packet_b` are filled the way `sipral_media_capture`
 * fills one, each with what its own call's far end is now owed: `mic`
 * mixed with the *other* far end's frame rather than `mic` alone, which
 * is also what each call's own recording keeps if one is running.
 *
 * Drive a joined pair from one thread, one frame at a time. The two
 * sessions are locked together for the length of the call, in a fixed
 * order that does not depend on which handle is named first, so a
 * second `sipral_media_mix` on the same pair waits for this one rather
 * than deadlocking against it — but a thread still calling
 * `sipral_media_playback`/`sipral_media_capture` on either call alone at
 * the same time is a second driver this mix does not know about.
 *
 * Safety
 *
 * `mic` must be readable for `mic_count` `int16_t` and `local` writable
 * for `local_count` `int16_t`, the two must not overlap, and
 * `packet_a` and `packet_b` must each point at a
 * `sipral_media_packet_t` as `sipral_media_capture` describes.
 */
sipral_status_t sipral_media_mix(sipral_handle_t media_a, sipral_handle_t media_b, uint64_t now_ms, const int16_t *mic, size_t mic_count, int16_t *local, size_t local_count, sipral_media_packet_t *packet_a, sipral_media_packet_t *packet_b);

/**
 * The control traffic this call has due.
 *
 * A `len` of zero in the packet means nothing is due yet. RFC 3550 §6.3
 * decides when, and at most one report is due at a time, so one call per
 * frame is enough.
 *
 * It asks one call rather than the whole stack, so the thread that sends
 * a call's audio sends its reports too, on the same socket and without
 * reaching the stack: call it after every frame that goes out, and
 * whenever `sipral_stack_poll` reports a deadline while a call is not
 * capturing. On a call that negotiated no RTCP it answers zero for ever.
 *
 * `now_ms` is read as the stack reads it and moves nothing, as with every
 * media entry point.
 *
 * Safety
 *
 * `packet` must point at a `sipral_media_packet_t` as
 * sipral_media_capture describes.
 */
sipral_status_t sipral_media_poll_rtcp(sipral_handle_t media, uint64_t now_ms, sipral_media_packet_t *packet);

/**
 * A datagram this call owes the far end that is neither audio nor a
 * report: today, a record of the DTLS-SRTP handshake that keys it.
 *
 * A `len` of zero means nothing is due. On a call that is not keyed by a
 * handshake — every call in a build without `SIPRAL_FEATURE_DTLS_SRTP`,
 * and every SDES or plain call in a build with it — that is the answer
 * for ever, and calling this costs one comparison.
 *
 * **Drain it to empty**, in a loop, after every `sipral_media_receive`
 * that answered `SIPRAL_ARRIVAL_HANDSHAKE` and at every deadline
 * `sipral_stack_poll` names. A handshake whose records never leave is a
 * ClientHello that never goes out: the call rings, answers, carries no
 * audio in either direction, and reports nothing wrong for the two
 * minutes it takes to give up. That is the one failure this entry point
 * exists to prevent, and there is no way to notice it from the outside.
 *
 * `now_ms` is read as the stack reads it and moves nothing, as with every
 * media entry point.
 *
 * Safety
 *
 * `packet` must point at a `sipral_media_packet_t` as
 * sipral_media_capture describes.
 */
sipral_status_t sipral_media_poll_transmit(sipral_handle_t media, uint64_t now_ms, sipral_media_packet_t *packet);

/**
 * The RTCP goodbye of a call whose media has ended (task 8.4.21).
 *
 * `MediaEngine::release` builds the BYE RFC 3550 §6.3.7 owes the far end
 * the moment a call's session stops, but by then the call's media
 * handle is already gone — every `sipral_media_` entry point on it
 * answers `SIPRAL_STATUS_WRONG_STATE` — so this is a stack-level call
 * instead, the one place left that still knows the goodbye belonged to
 * that call.
 *
 * `out_call` is written with the handle of the call the goodbye
 * belonged to — `SIPRAL_HANDLE_NONE` when nothing was waiting. The
 * call itself is already over; the handle is there only so the
 * application knows which media socket to send the datagram from, since
 * it owns that socket and this ABI never did. Passing it to any other
 * entry point answers whatever a stale handle of its kind already
 * answers.
 *
 * One at a time, like every other poll in this crate: call it after
 * every `sipral_stack_poll` that delivered `SIPRAL_EVENT_KIND_CALL_ENDED`
 * for a call this stack was running media on, and keep calling until
 * `out_packet` comes back with a `len` of zero. A call whose media never
 * ran leaves nothing here, but for one thing.
 *
 * A call given a relay on a TURN server (`turn_server` on the stack's
 * configuration) gives it back through here too: the Refresh with a
 * lifetime of zero that RFC 8656 §8 deletes an allocation with,
 * addressed to the TURN server, from the same socket. It is queued when
 * the call ends, whether or not its media ever ran, and earlier when the
 * call turns out not to use the relay at all — its ICE policy is off, or
 * the far end answered without ICE — so polling here after every
 * `sipral_stack_poll`, not only the ones that ended a call, gives the
 * relay back sooner.
 *
 * Safety
 *
 * `out_call` must point at one `sipral_handle_t`, and `out_packet` at a
 * `sipral_media_packet_t` as sipral_media_capture describes.
 */
sipral_status_t sipral_stack_poll_farewell(sipral_handle_t stack, sipral_handle_t *out_call, sipral_media_packet_t *out_packet);

/**
 * Whether a digit is going out or waiting to, and how many have not
 * started yet.
 *
 * Either out parameter may be null. A user interface that greys out the
 * keypad while a number is being sent wants the first; one that shows how
 * much of a pasted number is left wants the second.
 *
 * Safety
 *
 * `out_dialling` must point at one `uint32_t` or be null, and
 * `out_waiting` at one `size_t` or be null.
 */
sipral_status_t sipral_media_dialling(sipral_handle_t media, uint32_t *out_dialling, size_t *out_waiting);

/**
 * Drop everything queued and stop the digit going out.
 *
 * The digit in flight gets no closing packet, which is right for a call
 * whose media is being taken away: there is nowhere left to send one.
 *
 * Safety
 *
 * Reads no memory the caller owns.
 */
sipral_status_t sipral_media_stop_dialling(sipral_handle_t media);

/**
 * Start recording this call to `path`.
 *
 * Both directions, mixed, as WAVE. It can be started and stopped as often
 * as the person on the phone presses the button, and each recording is a
 * file of its own: a path written to twice would have two headers in it.
 *
 * `SIPRAL_STATUS_WRONG_STATE` for a call whose media has ended and for one
 * already being recorded — two writers on one stream would interleave
 * frames into both files. `SIPRAL_STATUS_INVALID_ARGUMENT` when the file
 * system refuses the path, with what it said in the last error.
 *
 * The file is made with this call's media held, so this call's audio
 * waits for the file system to answer and no other call's does.
 *
 * Safety
 *
 * `path` must be readable for `path_len` bytes.
 */
sipral_status_t sipral_media_record_start(sipral_handle_t media, const char *path, size_t path_len);

/**
 * Stop it, and close the file.
 *
 * `SIPRAL_STATUS_WRONG_STATE` when nothing is being recorded. A failure
 * here leaves a file with all of the audio in it and zeroes in the two
 * header fields, which is recoverable and is said rather than hidden.
 *
 * Safety
 *
 * Safe to call with any handle value.
 */
sipral_status_t sipral_media_record_stop(sipral_handle_t media);

/**
 * Whether a recording is running on this call, and how much audio it has
 * taken. Either out parameter may be null.
 *
 * The length is of the audio written, not of the file: the header in front
 * of it is not a recording of anything.
 *
 * Safety
 *
 * `out_recording` must point at one `uint32_t` or be null, and
 * `out_recorded_ms` at one `uint64_t` or be null.
 */
sipral_status_t sipral_media_record_state(sipral_handle_t media, uint32_t *out_recording, uint64_t *out_recorded_ms);

/**
 * Take the next message the stack wants written.
 *
 * One at a time, like every other poll here: a caller loops until the
 * message comes back with a `len` of zero. Call it after every
 * `sipral_stack_poll` and after every call that hands bytes in, since both
 * are moments the stack writes at.
 *
 * A message longer than `capacity` is `SIPRAL_STATUS_BUFFER_TOO_SMALL` with
 * the length it needs in `len`, and it is *kept*: the next call with room
 * for it hands over that same message, before anything queued behind it. So
 * a caller that brought no buffer at all — a null `data` with a capacity of
 * zero — learns what to bring without losing the message it asked about.
 *
 * Safety
 *
 * `transmit` must point at a `sipral_transmit_t` whose `size` member says
 * how long it is and whose buffers are writable for the capacities beside
 * them.
 */
sipral_status_t sipral_stack_poll_transmit(sipral_handle_t stack, sipral_transmit_t *transmit);

/**
 * Hand over one datagram, whole, and say where it came from.
 *
 * `from` is the far end, as `host:port`. `to` is the address the datagram
 * arrived on, which RFC 3581 §4 makes the address the response has to go
 * out from; null with a length of zero means the address this stack was
 * created with, which is the answer for a socket bound to one address.
 *
 * A WebSocket frame comes in here too: RFC 7118 §4.2 puts one SIP message
 * in each, so it arrives whole the way a datagram does.
 *
 * Bytes that are not a message are `SIPRAL_STATUS_INVALID_ARGUMENT` with
 * the parse error in the last error. That is an ordinary morning on a
 * public SIP port and costs exactly this one packet: log it and carry on.
 *
 * Safety
 *
 * `data` must be readable for `len` bytes, `from` for `from_len`, and `to`
 * for `to_len`.
 */
sipral_status_t sipral_stack_receive_datagram(sipral_handle_t stack, uint32_t transport, const uint8_t *data, size_t len, const char *from, size_t from_len, const char *to, size_t to_len, uint64_t now_ms);

/**
 * Hand over bytes off a connection, in whatever sizes the reads came in.
 *
 * Not a message: a fragment of a framing the layer below reassembles on
 * `Content-Length` (§18.3), and one call may hold several messages, half of
 * one, or none at all. No addresses travel with it, because a connection
 * has one far end and it was named when the transport was bound.
 *
 * Framing that cannot be read is fatal to the connection, and unlike a
 * datagram it cannot be resynchronised: the transport is already retired by
 * the time this answers `SIPRAL_STATUS_INVALID_ARGUMENT`, and the socket
 * should be closed. A read of zero bytes is the far end closing, which is
 * sipral_stack_stream_closed and not this.
 *
 * Safety
 *
 * `data` must be readable for `len` bytes.
 */
sipral_status_t sipral_stack_receive_stream(sipral_handle_t stack, uint32_t transport, const uint8_t *data, size_t len, uint64_t now_ms);

/**
 * Say that a transport is open and may be written to — the main one
 * again, or a further one this stack has not had before.
 *
 * The one way back from sipral_stack_transport_failed, the way a
 * stream stack names its far end, and the way a further transport enters
 * the table at all. `transport` is SIPRAL_TRANSPORT_MAIN to (re)bind
 * the main one, or any other number: one this stack already has rebinds
 * it, and one it does not opens it — the number is the caller's own
 * choice, the same as `sipral_account_config_t::transport` and
 * `sipral_call_config_t::transport` read it. `out_transport_id` may be
 * null; when it is not, it receives that same number, which is where a
 * caller answering
 * SIPRAL_EVENT_KIND_TRANSPORT_WANTED
 * reads back the id it just gave one of those two configs.
 *
 * `protocol` is a crate::stack::SipralTransport.
 * Rebinding an existing transport takes zero to mean "whatever it
 * already speaks" and anything else has to agree with that or this is
 * `SIPRAL_STATUS_INVALID_ARGUMENT` — a stack retransmits or does not
 * according to what a transport was opened speaking, and changing that
 * underneath the timers would be a transport configured out of RFC 3261
 * §17 halfway through a call. Opening a new one needs a protocol to
 * speak, so zero there is the same refusal for the opposite reason:
 * nothing to fall back on.
 *
 * `local` is the address the far end reaches this one at, as `host:port`.
 * `remote` is the far end of a connection, and is refused on a datagram
 * transport, which has many.
 *
 * This is also how a request
 * SIPRAL_EVENT_KIND_TRANSPORT_WANTED
 * named gets to leave: once this returns `SIPRAL_STATUS_OK` for the
 * protocol and destination the event gave, the stack sends the request
 * again by itself on the next `sipral_stack_poll` — there is no further
 * event about that one request.
 *
 * Safety
 *
 * `local` must be readable for `local_len` bytes, `remote` for
 * `remote_len`, and `out_transport_id`, when it is not null, must point
 * at one `uint32_t`.
 */
sipral_status_t sipral_stack_transport_bind(sipral_handle_t stack, uint32_t transport, uint32_t protocol, const char *local, size_t local_len, const char *remote, size_t remote_len, uint64_t now_ms, uint32_t *out_transport_id);

/**
 * Say that a transport failed, and that whatever was written to it did not
 * arrive.
 *
 * The transport is retired: every transaction waiting on it fails now, and
 * the calls and registrations behind them are reported on the next
 * `sipral_stack_poll` — nothing is delivered from inside this call, here as
 * everywhere else. Nothing can be sent until
 * sipral_stack_transport_bind brings one back.
 *
 * So this is not the call for one `sendto` that was refused. An ICMP
 * unreachable is one destination saying no, and a stack that retired its
 * socket over it would drop the calls that were fine. This is for the
 * socket that is over.
 *
 * Safety
 *
 * Safe to call with any handle value. Reads no memory the caller owns.
 */
sipral_status_t sipral_stack_transport_failed(sipral_handle_t stack, uint32_t transport, uint32_t error, uint64_t now_ms);

/**
 * Say that a connection closed: the far end went away, or a read returned
 * zero.
 *
 * The same retirement as sipral_stack_transport_failed, and a separate
 * call because it is a separate thing to have happened. An orderly close is
 * not an error the caller has to invent a kind for, and a stack that made it
 * one would have the two indistinguishable in a log for ever after.
 *
 * Safety
 *
 * Safe to call with any handle value. Reads no memory the caller owns.
 */
sipral_status_t sipral_stack_stream_closed(sipral_handle_t stack, uint32_t transport, uint64_t now_ms);

/**
 * Ask where a media socket appears from, before a call is described
 * on it.
 *
 * `local` is the address the socket is bound to, as `host:port` — the
 * same text the call's `media_address` will be. The request is waiting
 * in sipral_stack_poll_stun when this returns, the answer goes in
 * through sipral_stack_receive_stun, and
 * `SIPRAL_EVENT_KIND_NAT_MAPPING` says what it came to, within five and
 * a half seconds whatever the server does. From then on a call placed,
 * rung or answered with that `media_address` is described by the public
 * address, and asks for `a=rtcp-mux`, since one mapping describes one
 * port. Placing one before the answer is `SIPRAL_STATUS_WRONG_STATE`.
 *
 * Until that call, the socket is asked again every twenty-five seconds,
 * as the signalling socket is: nothing else crosses its NAT binding
 * while it waits, and an answer minutes old names a mapping the NAT may
 * have let go. Keep sending what `sipral_stack_poll_stun` hands out for
 * it and handing in what arrives; an answer that differs is
 * `SIPRAL_NAT_MAPPING_MOVED`, and the call is described by it. At most
 * one request per socket waits in the queue.
 *
 * The mapping is spent by the call it describes. A socket used for a
 * second call is named here again — nothing kept the first answer true
 * in between.
 *
 * `SIPRAL_STATUS_WRONG_STATE` on a stack created without
 * `SIPRAL_NAT_STUN`, and `SIPRAL_STATUS_INVALID_ARGUMENT` for a
 * signalling socket of the stack's own, which is kept mapped already.
 *
 * Safety
 *
 * `local` must be readable for `local_len` bytes.
 */
sipral_status_t sipral_stack_nat_map(sipral_handle_t stack, const char *local, size_t local_len, uint64_t now_ms);

/**
 * Take the next STUN request a media socket has to send.
 *
 * The same record and the same rules as `sipral_stack_poll_transmit`,
 * on a queue of its own: loop until `len` comes back zero, after every
 * sipral_stack_nat_map, every sipral_stack_receive_stun and
 * every `sipral_stack_poll`, since the stack retransmits a request
 * nobody answered. `source` is always written, and it is the socket to
 * send from — the whole point is the address the server sees it come
 * from, so sending it from any other socket learns the wrong one.
 * `transport` is zero and names nothing here, and `protocol` is UDP.
 *
 * Safety
 *
 * `transmit` must point at a `sipral_transmit_t` whose `size` member says
 * how long it is and whose buffers are writable for the capacities beside
 * them.
 */
sipral_status_t sipral_stack_poll_stun(sipral_handle_t stack, sipral_transmit_t *transmit);

/**
 * Hand over a datagram that arrived on a media socket
 * sipral_stack_nat_map named, before a call has media on it.
 *
 * `to` is the socket it arrived on, as `local` was given there; `from`
 * is where it came from. `SIPRAL_STATUS_OK` when it was the STUN
 * server's answer, which is then the stack's and nobody else's;
 * `SIPRAL_STATUS_INVALID_ARGUMENT` for anything else — early media from
 * a far end, a datagram from a stranger, an answer from any address but
 * the server's — which costs that one datagram and nothing more. Only
 * the server's own address is believed, and only an answer to a request
 * this stack sent: that is the whole defence against a forged answer
 * naming an address of the attacker's choosing as this end's own.
 *
 * Safety
 *
 * `data` must be readable for `len` bytes, `from` for `from_len`, and
 * `to` for `to_len`.
 */
sipral_status_t sipral_stack_receive_stun(sipral_handle_t stack, const uint8_t *data, size_t len, const char *from, size_t from_len, const char *to, size_t to_len, uint64_t now_ms);

/**
 * The short name of an event kind, as a static NUL-terminated
 * string, or null for a number this build has no kind for.
 *
 * The string belongs to the library and lives as long as it is
 * loaded. A number that is reserved for a feature this build does
 * not have answers null, the same as one that was never spent: a
 * name for something that cannot arrive would be a name for
 * nothing.
 *
 * Safety
 *
 * Reads no memory the caller owns, and is safe to call from any
 * thread.
 */
const char *sipral_event_kind_name(uint32_t kind);

/**
 * How many lines a header field is on, in a whole SIP message.
 *
 * The message is any SIP message in bytes: the one an event carries in
 * `sipral_event_t::message`, or one the application came by some other
 * way. The name is matched the way the parser matches it, without regard to
 * case, and a compact form and its long form are one field (RFC 3261
 * §7.3.3): `i` counts the `Call-ID` lines, and `Call-ID` counts a line
 * written `i:`. A field that is not there is a count of zero, not a
 * failure.
 *
 * Safety
 *
 * `message` must be readable for `message_len` bytes and `name` for
 * `name_len`, and `out_count` must point at one `size_t`.
 */
sipral_status_t sipral_message_header_count(const uint8_t *message, size_t message_len, const char *name, size_t name_len, size_t *out_count);

/**
 * Where one line of a header field is, in a whole SIP message.
 *
 * `index` counts from zero in the order the lines arrived, and has to be
 * below what `sipral_message_header_count` says for the same name: past it
 * is `SIPRAL_STATUS_INVALID_ARGUMENT`. `out_offset` and `out_len` then say
 * where the value sits inside `message`, trimmed at both ends and otherwise
 * as it arrived, a line fold included. An offset rather than a pointer,
 * because the bytes are the caller's, and a binding that copied them across
 * the boundary holds its own copy.
 *
 * One line of a field whose value is a comma-separated list may hold
 * several values; `sipral_message_header_element` reaches those.
 *
 * Safety
 *
 * As `sipral_message_header_count`, with `out_offset` and `out_len` each
 * pointing at one `size_t`.
 */
sipral_status_t sipral_message_header(const uint8_t *message, size_t message_len, const char *name, size_t name_len, size_t index, size_t *out_offset, size_t *out_len);

/**
 * How many values a field whose value is a comma-separated list holds,
 * across every line it is on.
 *
 * RFC 3261 §7.3.1 makes two values on one line, with a comma between them,
 * and the same two values on two lines one and the same message, and a
 * proxy is free to turn either into the other. So this counts values
 * rather than lines, split at every comma that is not inside quotes or
 * angle brackets. Otherwise as `sipral_message_header_count`.
 *
 * Only for a field defined as a list: `P-Asserted-Identity`, `Diversion`,
 * `Contact`, `Supported`. Any other is split at a comma its value holds as
 * text, like the one in a `Date` or the ones between the parameters of a
 * challenge, and `sipral_message_header_count` is the call for it.
 *
 * Safety
 *
 * As `sipral_message_header_count`.
 */
sipral_status_t sipral_message_header_element_count(const uint8_t *message, size_t message_len, const char *name, size_t name_len, size_t *out_count);

/**
 * Where one value of a list field is, across every line the field is on.
 *
 * `index` counts values in the order they arrived, and has to be below what
 * `sipral_message_header_element_count` says for the same name. Otherwise
 * as `sipral_message_header`.
 *
 * Safety
 *
 * As `sipral_message_header`.
 */
sipral_status_t sipral_message_header_element(const uint8_t *message, size_t message_len, const char *name, size_t name_len, size_t index, size_t *out_offset, size_t *out_len);

/**
 * The operating system says this process stops shortly.
 *
 * Everything reached from here is synchronous, bounded by the number of
 * accounts and subscriptions, and cannot fail. Nothing is sent — see
 * `docs/16-lifecycle.md` for why a graceful de-registration is the wrong
 * thing to attempt in this window rather than the obvious one — and
 * nothing stays scheduled: a stack that is suspended and never resumed
 * has no deadline to fire and no work left behind.
 *
 * Calls that are up are left exactly as they are. A lid closing and
 * opening again is seconds, and hanging up a live call because the
 * machine blinked is worse than finding out a few seconds later that it
 * is gone.
 *
 * `out_report` receives what was found: bindings that stopped being
 * evidence, subscriptions whose last notification stopped being
 * evidence, and calls left untouched.
 *
 * Safety
 *
 * `out_report` must point at a `sipral_suspending_t` whose `size` member
 * says how long it is.
 */
sipral_status_t sipral_stack_suspending(sipral_handle_t stack, uint64_t now_ms, sipral_suspending_t *out_report);

/**
 * The process is awake again.
 *
 * Arbitrary time has passed — arbitrary, not measurable, because the
 * clock this stack is driven by did not run while the machine was
 * suspended — and every transport may be dead. What was believed is
 * dropped and proved again: the transport already there is used first,
 * because most wakes are short and it still works, and
 * sipral_account_rebind is how the application hands over a new one
 * once this stack says it needs one.
 *
 * Safe to call without a matching sipral_stack_suspending. Some
 * platforms only notify on the way back.
 *
 * Safety
 *
 * Safe to call with any handle value.
 */
sipral_status_t sipral_stack_resumed(sipral_handle_t stack, uint64_t now_ms);

/**
 * The network is a different one, described before and after in as much
 * detail as the decision needs.
 *
 * `from_link`/`to_link` is a sipral_link_t. `*_address` is the local
 * address this stack's transports are bound to, as an IPv4 or IPv6
 * literal with no port — a change of it invalidates every transport and
 * every binding at once. `*_interface` is the platform's own identity
 * for the interface, never parsed and only ever compared to another one
 * of itself; two networks can hand out the same address, and a phone
 * that walks from one office to another gets away with it until a call
 * comes in. `*_resolves` is whether a name can become an address there,
 * because that is the one failure that leaves everything else looking
 * healthy. Any of the four address or interface arguments may be null
 * with a length of zero, for a fact the application has none to give.
 *
 * `out_recovery` receives what was decided, as a sipral_recovery_t, so
 * this is safe to call as often as the platform delivers the
 * notification — most of the time nothing this stack uses is different,
 * and `SIPRAL_RECOVERY_NOTHING` is the whole of what happens. It may be
 * null.
 *
 * Safety
 *
 * Every address and interface pointer must be readable for the length
 * beside it or null with a length of zero, and `out_recovery` must point
 * at one `uint32_t` or be null.
 */
sipral_status_t sipral_stack_network_changed(sipral_handle_t stack, uint32_t from_link, const char *from_address, size_t from_address_len, const char *from_interface, size_t from_interface_len, uint32_t from_resolves, uint32_t to_link, const char *to_address, size_t to_address_len, const char *to_interface, size_t to_interface_len, uint32_t to_resolves, uint64_t now_ms, uint32_t *out_recovery);

/**
 * There is no usable interface.
 *
 * Distinct from sipral_stack_name_resolution_lost because the
 * recovery is the opposite one: with nothing that can leave, nothing is
 * tried and nothing is scheduled, which is the cheapest this stack ever
 * is. The way out is sipral_stack_network_changed, the notification
 * every platform delivers when an interface comes back.
 *
 * Safety
 *
 * Safe to call with any handle value.
 */
sipral_status_t sipral_stack_interface_lost(sipral_handle_t stack, uint64_t now_ms);

/**
 * Names no longer become addresses.
 *
 * The dangerous one: the interface is up and packets leave, so
 * everything reads healthy, while every address this stack learned from
 * a name may now stand for somewhere else. A binding whose registrar was
 * written as a name stops being evidence; one pointed at a literal
 * address never needed a resolver and is left running.
 *
 * Safety
 *
 * Safe to call with any handle value.
 */
sipral_status_t sipral_stack_name_resolution_lost(sipral_handle_t stack, uint64_t now_ms);

/**
 * Point an account at a transport and an address again.
 *
 * `remote` is the far end this account's requests go to now, as
 * `host:port`. `contact` is where this endpoint can be reached, as it
 * goes in `Contact`; it is not optional, because after a change of
 * address the old one names somewhere the far end cannot reach, and a
 * stack that let it stand would register a binding that silently
 * receives nothing.
 *
 * `transport` must be one this stack already has —
 * SIPRAL_TRANSPORT_MAIN or
 * a further one sipral_stack_transport_bind
 * has bound — and any other number is `SIPRAL_STATUS_INVALID_ARGUMENT`:
 * this call points an account at a transport, it does not open one.
 *
 * Safe to call whether or not this stack is waiting for it. When it is,
 * answering climbs the next rung at once rather than waiting out the
 * rest of the back-off — the application answering in milliseconds is
 * the normal case, and there is nothing to be gained by making a wake
 * take a further half minute. When it is not, this still repoints the
 * account, and the next REGISTER this stack sends for it — a refresh, or
 * the next rung of a ladder started afterwards — uses what was given
 * here.
 *
 * Safety
 *
 * `remote` must be readable for `remote_len` bytes and `contact` for
 * `contact_len` bytes.
 */
sipral_status_t sipral_account_rebind(sipral_handle_t stack, sipral_handle_t account, uint32_t transport, const char *remote, size_t remote_len, const char *contact, size_t contact_len, uint64_t now_ms);

/**
 * Say the process has just started, so that time to ready is measured
 * from somewhere.
 *
 * The zero of sipral_account_time_to_ready, and a declaration rather
 * than something this library could observe: a stack is created long
 * before the launch it belongs to is over, and only the application
 * knows which moment its users are waiting from. Every account's
 * measurement is cleared and taken again, so calling this twice restarts
 * the clock rather than confusing two launches.
 *
 * Safety
 *
 * Safe to call with any handle value.
 */
sipral_status_t sipral_stack_cold_start(sipral_handle_t stack, uint64_t now_ms);

/**
 * Write an account's registration down, so a later start can carry it on
 * instead of paying for a whole handshake.
 *
 * `out_len` receives how many bytes it takes whether or not there was
 * room, so a caller passing a null `buffer` and a `capacity` of zero is
 * asking how much room to bring and gets `SIPRAL_STATUS_BUFFER_TOO_SMALL`
 * with the answer — that is the question, not a failure. Nothing is
 * written to a buffer too short.
 *
 * **The bytes are opaque, and reading them is not part of this ABI.**
 * They carry a version, and a build reads only the layouts it was made
 * for; an application that parses them is an application that stops
 * working when the layout grows a field. Storing them is the
 * application's, and so is protecting them: a snapshot is not a secret,
 * but it names an address of record, which is a record of who uses this
 * device.
 *
 * `SIPRAL_STATUS_WRONG_STATE` when there is nothing worth keeping — an
 * account that has never registered, one that never will, one whose
 * registration failed, or one whose binding has been given up. A cold
 * start after that is an ordinary cold start, which is what would have
 * happened anyway.
 *
 * The clock is read and not moved: this writes nothing and sends
 * nothing, so a snapshot taken on the way into suspend cannot be what
 * stops a later `now_ms` from being accepted.
 *
 * Safety
 *
 * `buffer` must be writable for `capacity` bytes or be null with a
 * `capacity` of zero, and `out_len` must point at one `size_t` or be
 * null.
 */
sipral_status_t sipral_account_freeze(sipral_handle_t stack, sipral_handle_t account, uint8_t *buffer, size_t capacity, size_t *out_len, uint64_t now_ms);

/**
 * Read one back, on an account that has been added and has not
 * registered.
 *
 * `asleep_ms` is how long the snapshot sat unused, and it is the
 * caller's to supply because nothing here reads a wall clock and a
 * monotonic instant does not survive the process that minted it. The
 * application is the only one that knows whether this is a wake from
 * suspend or a cold launch a week later. What is left of the binding's
 * life is what was left when it was written down, less that.
 *
 * The account comes up in
 * SIPRAL_REGISTRATION_STATE_RESTORED
 * rather than registered: a binding nobody has confirmed since the
 * machine slept is a belief, not evidence, and the refresh this books is
 * what turns one into the other.
 *
 * Refused, with the account left exactly as it was:
 * `SIPRAL_STATUS_UNSUPPORTED_VERSION` for bytes a newer build wrote,
 * `SIPRAL_STATUS_NOT_SUPPORTED` for an account that does not register at
 * all, and `SIPRAL_STATUS_INVALID_ARGUMENT` for bytes that are not a
 * snapshot, are damaged, or are another account's — an address of record
 * that is not this account's is the one mix-up that would otherwise send
 * a REGISTER for somebody else.
 *
 * Safety
 *
 * `snapshot` must be readable for `snapshot_len` bytes.
 */
sipral_status_t sipral_account_thaw(sipral_handle_t stack, sipral_handle_t account, const uint8_t *snapshot, size_t snapshot_len, uint64_t asleep_ms, uint64_t now_ms);

/**
 * How long this account took to become reachable, measured from
 * sipral_stack_cold_start.
 *
 * The number a queue needs: how long it rings each agent before giving
 * up and trying the next one has to be longer than this, or a phone that
 * was asleep is skipped every time and its owner is told the queue was
 * quiet.
 *
 * `out_has_value` is zero, and `out_ms` zero with it, until there is an
 * answer — before the account has registered, for an account that never
 * registers, and always when no cold start was ever declared, because
 * nothing marks the moment those became reachable. Zero milliseconds
 * with `out_has_value` set is a real answer and a different one.
 *
 * Safety
 *
 * `out_has_value` must point at one `uint32_t` and `out_ms` at one
 * `uint64_t`.
 */
sipral_status_t sipral_account_time_to_ready(sipral_handle_t stack, sipral_handle_t account, uint32_t *out_has_value, uint64_t *out_ms);

/**
 * Say where a dialog's next hop actually is.
 *
 * The answer to
 * SIPRAL_EVENT_KIND_RESOLVE_NEEDED,
 * with `dialog` the handle that event carried. `addresses` is
 * comma-separated `host:port`, **in RFC 3263 §4.3 priority order**: the
 * first one this stack already has an open transport of the wanted
 * protocol for is taken, and the ones after it are kept for this stack
 * to try in turn if that one goes on to fail. A list is therefore not a
 * convenience — it is what makes failover possible at all, and one
 * address is a list of one that cannot fail over.
 *
 * `protocol` is a sipral_transport_t when
 * the lookup named one, which a NAPTR or SRV answer does, and zero when
 * it did not — an A lookup with nothing above it — in which case the flow
 * keeps speaking whatever it already spoke. It is looked for, never
 * opened: nothing here owns a socket, so a protocol nothing has bound is
 * not something this can invent. An address on one is passed over, and
 * answering again after
 * sipral_stack_transport_bind
 * is how it gets another chance.
 *
 * `SIPRAL_STATUS_OK` with nothing changed is the honest answer in two
 * cases, and neither is an error: the dialog has ended, and none of the
 * addresses is one this stack can reach on the protocol asked for. The
 * flow stands exactly as it did.
 *
 * There is no `now_ms` here on purpose. Every other call that changes
 * what this stack will send takes the time because something it does is
 * timed; this one only writes an address down.
 *
 * Safety
 *
 * `addresses` must be readable for `addresses_len` bytes.
 */
sipral_status_t sipral_stack_resolved(sipral_handle_t stack, sipral_handle_t dialog, const char *addresses, size_t addresses_len, uint32_t protocol);

/**
 * Point an account's registration at another address.
 *
 * For a registrar named by a record with more than one target, and for
 * the one after it when the first stops answering. The binding's
 * `Call-ID`, its sequence number and its credentials are all kept, so
 * the next REGISTER reads to the registrar as the same device
 * continuing, not as a second one arriving — which is the whole of the
 * saving and the reason this is not "remove the account and add it
 * again".
 *
 * A REGISTER already in flight or already booked for this account is
 * superseded at once rather than waited out. Retargeting to the address
 * an account is already using is `SIPRAL_STATUS_OK` and sends nothing.
 *
 * `registrar_address` is `host:port`, not a name: resolving one is the
 * application's, here as everywhere else in this module.
 * `SIPRAL_STATUS_NOT_SUPPORTED` for an account with no registrar — a
 * trunk authenticated by address has nothing to retarget, and
 * `sipral_account_config_t::registrar_address` is where its outbound
 * proxy is set.
 *
 * Safety
 *
 * `registrar_address` must be readable for `registrar_address_len`
 * bytes.
 */
sipral_status_t sipral_account_retarget(sipral_handle_t stack, sipral_handle_t account, const char *registrar_address, size_t registrar_address_len, uint64_t now_ms);

/**
 * Copy one call's diagnostic record into `buffer`, as the JSON
 * `docs/14-diagnostics.md` describes.
 *
 * Readable at any point in the call's life, and for as long after it as
 * the endpoint has not evicted the record to make room for a newer one —
 * `sipral_stack_config_t` has no member for the ceiling yet, so today
 * that is sipral_core::diag::RecordLimits::DEFAULT. A call whose
 * record has been evicted, or that has had nothing decided about it yet,
 * answers `SIPRAL_STATUS_OK` with `{}`: an empty record is still a
 * record, and refusing to read one that happens to be empty would make
 * a caller unable to tell "nothing yet" from "something went wrong".
 *
 * `SIPRAL_STATUS_BUFFER_TOO_SMALL` when `buffer` cannot hold the whole
 * document, with the length needed in `out_len`.
 *
 * Safety
 *
 * `buffer` must be writable for `capacity` bytes or be null with a
 * capacity of zero, and `out_len` must point at one `size_t` or be null.
 */
sipral_status_t sipral_call_record_json(sipral_handle_t stack, sipral_handle_t call, char *buffer, size_t capacity, size_t *out_len);

/**
 * Copy the whole diagnostic document into `buffer`: what a bug report
 * carries, as the JSON `docs/14-diagnostics.md` describes.
 *
 * That is the endpoint's own record — everything decided outside any
 * call — and then one record per call still held, in the same document,
 * with the number of records evicted to make room. It is deliberately
 * the whole of it rather than the endpoint's half: a report that arrives
 * without the calls it is about answers nothing, and
 * sipral_call_record_json is already the way to ask about one call.
 *
 * `SIPRAL_STATUS_BUFFER_TOO_SMALL` when `buffer` cannot hold the whole
 * document, with the length needed in `out_len`.
 *
 * Safety
 *
 * `buffer` must be writable for `capacity` bytes or be null with a
 * capacity of zero, and `out_len` must point at one `size_t` or be null.
 */
sipral_status_t sipral_stack_diagnostics_json(sipral_handle_t stack, char *buffer, size_t capacity, size_t *out_len);

/**
 * Start recording the signalling this stack is fed from here on
 * (`docs/18-replay.md`), with the same seed `sipral_stack_create` built
 * it with. Read crate::diagnostics before reaching for this: what it
 * records and what it deliberately never does is written down there
 * once rather than repeated at each of these three entry points.
 *
 * `note` is one line of prose for whoever opens the file later, or null
 * for none.
 *
 * A recording already running is replaced, not refused: see
 * crate::diagnostics for why that is the right answer here and the
 * wrong one for `sipral_media_record_start`.
 *
 * Safety
 *
 * `note` must be readable for `note_len` bytes or be null with a length
 * of zero.
 */
sipral_status_t sipral_stack_recording_start(sipral_handle_t stack, const char *note, size_t note_len);

/**
 * Stop the recording sipral_stack_recording_start began, and copy
 * the text of it into `buffer` (`docs/18-replay.md`).
 *
 * `SIPRAL_STATUS_WRONG_STATE` when no recording is running, the same
 * answer `sipral_media_record_stop` gives for the same question about
 * an audio recording. `SIPRAL_STATUS_WRONG_STATE` again, with the reason
 * in the last error, when something this session was fed could not go
 * in the recording — a message with a body that is not text is the one
 * way that happens — in which case nothing is written to `buffer` and
 * the recording is not produced at all: a text format that quietly left
 * out the one message it could not spell would replay into a different
 * session and say nothing about it.
 *
 * `SIPRAL_STATUS_BUFFER_TOO_SMALL` when `buffer` cannot hold the whole
 * text, with the length needed in `out_len` — asking again with a bigger
 * buffer answers the same recording rather than stopping a new one,
 * so a caller that does not yet know how big a buffer to bring may ask
 * twice: once to be told, once to be handed the text. Once a call here
 * copies the whole of it out, the recording is gone from the stack, the
 * same as `sipral_last_error_message` empties the slot it reads on a
 * call that succeeds.
 *
 * Safety
 *
 * `buffer` must be writable for `capacity` bytes or be null with a
 * capacity of zero, and `out_len` must point at one `size_t` or be null.
 */
sipral_status_t sipral_stack_recording_stop(sipral_handle_t stack, char *buffer, size_t capacity, size_t *out_len);

"""

ffi = FFI()
ffi.cdef(CDEF)


def _library_name() -> str:
    """What the crate's `cdylib` is called on this platform."""
    if sys.platform == "darwin":
        return "libsipral_ffi.dylib"
    if sys.platform == "win32":
        return "sipral_ffi.dll"
    return "libsipral_ffi.so"


def _candidates() -> list[Path]:
    """Where the library might be, in the order it is looked for.

    `SIPRAL_LIBRARY` first, whether it names the library file itself
    or the directory holding it; then beside this package, for a
    wheel that bundled the library next to the Python; then the
    repository's own `target/release` and `target/debug`, for
    working against a checkout with no install step at all.
    """
    name = _library_name()
    found: list[Path] = []
    override = os.environ.get("SIPRAL_LIBRARY")
    if override:
        given = Path(override)
        found.append(given if given.is_file() else given / name)
    package_dir = Path(__file__).resolve().parent
    found.append(package_dir / name)
    repository = package_dir.parents[2] if len(package_dir.parents) > 2 else None
    if repository is not None:
        found.append(repository / "target" / "release" / name)
        found.append(repository / "target" / "debug" / name)
    return found


def _load():
    tried = _candidates()
    for candidate in tried:
        if candidate.is_file():
            return ffi.dlopen(str(candidate))
    searched = "\n".join(f"  {candidate}" for candidate in tried)
    raise OSError(
        "sipral: could not find "
        + _library_name()
        + ". Tried:\n"
        + searched
        + "\n\nBuild it with `cargo build --release -p sipral-ffi`, "
        "or set SIPRAL_LIBRARY to its path or its directory."
    )


lib = _load()

# Checked once, at import, the way every other binding checks itself at
# load: sipral_abi_check is called with the major and minor this file was
# printed from, so a library that cannot serve them is refused here, in
# a sentence naming both, rather than in whichever call first reads a
# member that is not there.
_abi_status = lib.sipral_abi_check(lib.SIPRAL_ABI_VERSION_MAJOR, lib.SIPRAL_ABI_VERSION_MINOR)
if _abi_status != lib.SIPRAL_STATUS_OK:
    raise OSError(
        f"sipral: this build of the library does not implement ABI "
        f"{lib.SIPRAL_ABI_VERSION_MAJOR}.{lib.SIPRAL_ABI_VERSION_MINOR}, which this binding was "
        "generated against; regenerate the binding or rebuild the library"
    )

