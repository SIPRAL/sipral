# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek
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
 * A number, not a pointer: nothing is read from it, and only this
 * library makes one. Zero is never a live handle.
 *
 * An account or call handle is valid only on the stack that minted it;
 * on any other stack it is `SIPRAL_STATUS_INVALID_HANDLE`.
 */
typedef uint64_t sipral_handle_t;

/**
 * The value no live handle ever takes.
 */
#define SIPRAL_HANDLE_NONE 0

/**
 * The ABI's major version. Nothing published against one major works
 * against another; within one, a binding built against a minor works
 * against a library at that minor or any later one.
 */
#define SIPRAL_ABI_VERSION_MAJOR 1

/**
 * The ABI's minor version, raised by anything the header gains. Rules:
 * Versioning section of `docs/08-ffi.md`.
 */
#define SIPRAL_ABI_VERSION_MINOR 2

/**
 * The ABI's patch version, raised by a fix that changes no declaration.
 */
#define SIPRAL_ABI_VERSION_PATCH 0

/**
 * Bits of sipral_capabilities_t::transports. A transport this ABI has no
 * bit for yet reads as absent.
 *
 * Derived from sipral_transport_t's numbers (`1 << (value - 1)`), so the
 * two numberings never have to be kept in step by hand.
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
 * See SIPRAL_FEATURE_DTMF. Opus is behind a compile-time feature
 * (libopus is licensed, not written here). Set from the codec catalogue,
 * not from a crate feature flag. `SIPRAL_CODEC_OPUS` keeps its number either way.
 */
#define SIPRAL_FEATURE_OPUS 64

/**
 * DTLS-SRTP (RFC 5764): media keys come from a handshake on the media path.
 *
 * Behind a compile-time feature. `SIPRAL_SRTP_DTLS` and
 * `SIPRAL_SRTP_DTLS_REQUIRED` keep their numbers in a build without it and
 * answer `SIPRAL_STATUS_NOT_SUPPORTED` there, never an unencrypted call.
 *
 * An application that sets one of those policies must also drain
 * `sipral_media_poll_transmit`; see there.
 */
#define SIPRAL_FEATURE_DTLS_SRTP 128

/**
 * See SIPRAL_FEATURE_DTMF. ICE in the full role (RFC 8445), with
 * consent freshness (RFC 7675) and the SDP attributes of RFC 8839.
 *
 * Behind a compile-time feature and off by policy (`docs/06-nat.md`).
 * `SIPRAL_ICE_OFFERED` and `SIPRAL_ICE_REQUIRED` keep their numbers in a
 * build without it and answer `SIPRAL_STATUS_NOT_SUPPORTED` there.
 *
 * An application that sets one of those policies must also drain
 * `sipral_media_poll_transmit`; see there.
 */
#define SIPRAL_FEATURE_ICE 256

/**
 * See SIPRAL_FEATURE_DTMF. STUN (RFC 8489): a stack created with
 * `SIPRAL_NAT_STUN` learns its public address and writes it in `Contact`,
 * `c=` and `m=`. Without the feature, `SIPRAL_NAT_STUN` answers
 * `SIPRAL_STATUS_NOT_SUPPORTED`.
 */
#define SIPRAL_FEATURE_STUN 512

/**
 * See SIPRAL_FEATURE_DTMF. A TURN server over TCP or TLS
 * (RFC 8656 §3.1): `sipral_stack_config_t::turn_transport` and
 * `SIPRAL_EVENT_KIND_TURN_STREAM`. Comes with `SIPRAL_FEATURE_ICE`;
 * without it a non-UDP `turn_transport` answers `SIPRAL_STATUS_NOT_SUPPORTED`.
 */
#define SIPRAL_FEATURE_TURN_STREAM 1024

/**
 * See SIPRAL_FEATURE_DTMF. The built-in audio engine
 * (`sipral_stack_config_t::audio` = `SIPRAL_AUDIO_DEVICE`, and the
 * `sipral_audio_*` entry points). Clear where there is no backend (Linux,
 * Android below API 28); `SIPRAL_AUDIO_DEVICE` then answers
 * `SIPRAL_STATUS_NOT_SUPPORTED`. On Android it is the phone's answer, read
 * at call time. This crate's own answer: the engine is not under the facade.
 */
#define SIPRAL_FEATURE_AUDIO_DEVICE 2048

/**
 * See SIPRAL_FEATURE_DTMF. Caller identity on every call event:
 * asserted identity behind `trusted_peers` (RFC 3325), `verstat`,
 * `Privacy`, `Diversion`, `History-Info`, `Answer-Mode`, `Alert-Info`;
 * end causes (RFC 3326) and `sipral_call_hangup_for`;
 * `sipral_call_redirect`; an account's `privacy` and `session_timer`.
 */
#define SIPRAL_FEATURE_CALLER_IDENTITY 4096

/**
 * See SIPRAL_FEATURE_DTMF. A call follows a network change:
 * `SIPRAL_EVENT_KIND_CALL_ADDRESS_WANTED` and `sipral_call_media_readdress`.
 */
#define SIPRAL_FEATURE_CALL_READDRESS 8192

/**
 * See SIPRAL_FEATURE_DTMF. The redacted, rate-limited log callback
 * (`sipral_stack_log`) and the state snapshot (`sipral_stack_state_text`).
 * Set in every build.
 */
#define SIPRAL_FEATURE_LOGGING 16384

/**
 * See SIPRAL_FEATURE_DTMF. Stack ceilings (`max_dialogs`,
 * `max_server_transactions`, `diagnostic_decisions`, `diagnostic_records`),
 * `SIPRAL_STATUS_LIMIT_REACHED`, and the counters in `sipral_counters_t`.
 */
#define SIPRAL_FEATURE_LIMITS 32768

/**
 * See SIPRAL_FEATURE_DTMF. STIR/SHAKEN (RFC 8224, RFC 8588): signing
 * (`stir_key`, `stir_certificate_url`) and verification
 * (`sipral_stack_stir`, `SIPRAL_EVENT_KIND_CALLER_VERIFICATION`,
 * `sipral_call_stir_certificate`). Behind a compile-time feature, on by default.
 */
#define SIPRAL_FEATURE_STIR 65536

/**
 * See SIPRAL_FEATURE_DTMF. SRTP policy and suites per account,
 * `SIPRAL_SRTP_DTLS_OR_SDES`, `SIPRAL_STATUS_SECURITY_POLICY`, and
 * `sipral_media_encryption_at`.
 */
#define SIPRAL_FEATURE_SRTP_POLICY 131072

/**
 * See SIPRAL_FEATURE_DTMF. In-band signals: DTMF detection
 * (`sipral_stack_config_t::dtmf_detection`, `sipral_call_dtmf_detection`,
 * `SIPRAL_EVENT_KIND_IN_BAND_DIGIT`) and generation (`SIPRAL_DTMF_IN_BAND`),
 * progress and answering-machine detection (`sipral_call_detect_progress`,
 * `SIPRAL_EVENT_KIND_PROGRESS_DETECTED`), and `sipral_call_consent_tone`.
 */
#define SIPRAL_FEATURE_IN_BAND_SIGNALS 262144

/**
 * See SIPRAL_FEATURE_DTMF. Recording formats
 * (`sipral_media_record_start_with`): mixed or stereo, WAV/RF64,
 * checkpointed, Ogg Opus with SIPRAL_FEATURE_OPUS; and L16 at 8 and 16 kHz.
 */
#define SIPRAL_FEATURE_RECORDING_FORMATS 524288

/**
 * See SIPRAL_FEATURE_DTMF. SIPREC (RFC 7866): `sipral_call_record_to`
 * and `sipral_media_poll_recording`.
 */
#define SIPRAL_FEATURE_SIPREC 1048576

/**
 * See SIPRAL_FEATURE_DTMF. Conference package (RFC 4575,
 * `sipral_subscription_conference`), focus `isfocus` (RFC 4579,
 * `sipral_call_conference_uri`), presence publish (RFC 3903) and watch (RFC 3856).
 */
#define SIPRAL_FEATURE_CONFERENCE 2097152

/**
 * See SIPRAL_FEATURE_DTMF. Real-time text (RFC 4103): `text_address`,
 * `sipral_media_send_text`, `SIPRAL_EVENT_KIND_TEXT_RECEIVED`.
 */
#define SIPRAL_FEATURE_REALTIME_TEXT 4194304

/**
 * See SIPRAL_FEATURE_DTMF. RTP/AVPF with Generic NACK and reduced-size
 * RTCP (RFC 4585, RFC 5506): `feedback`, reported in `sipral_media_info_t`.
 */
#define SIPRAL_FEATURE_RTCP_FEEDBACK 8388608

/**
 * See SIPRAL_FEATURE_DTMF. A local conference of calls on any codec
 * and rate: `sipral_local_conference_create`,
 * `SIPRAL_EVENT_KIND_LOCAL_CONFERENCE_CHANGED`.
 */
#define SIPRAL_FEATURE_LOCAL_CONFERENCE 16777216

/**
 * The buffer a caller has to bring for one outgoing packet.
 *
 * The bound the session builds against, not a path MTU. Checked before
 * anything is encoded, so a frame is never encoded and then lost.
 */
#define SIPRAL_MEDIA_PACKET_BYTES 1500

/**
 * The bound for an incoming datagram that RFC 5761 §4 classifies as control.
 *
 * Compound RTCP from a peer may exceed the media bound (RFC 3550 sets no
 * limit). Everything else still gets SIPRAL_MEDIA_PACKET_BYTES; outgoing
 * RTCP always fits the media bound.
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
 * Never removed from the table; failure stops it, sipral_stack_transport_bind restores
 * it. Zero in `sipral_account_config_t::transport` and `sipral_call_config_t::transport`
 * means this one.
 */
#define SIPRAL_TRANSPORT_MAIN 0

/**
 * The largest message that crosses in either direction.
 *
 * Bounds the parser's work against a hostile peer. Size stream read buffers to this; about
 * 1500 bytes suffices on a datagram socket.
 */
#define SIPRAL_MESSAGE_BYTES 65535

/**
 * The longest `sipral_transport_failure_t::detail` accepted. Longer is refused, not cut.
 */
#define SIPRAL_TRANSPORT_DETAIL_BYTES 1024

/**
 * The answer that lets an INVITE through.
 *
 * Any other answer refuses. Acceptance is 200, not zero, because zero is
 * what a binding returns when the listener threw, or what an unfilled
 * answer leaves; neither may admit a call.
 */
#define SIPRAL_SCREEN_ACCEPT 200

/**
 * The default burst: ten INVITEs from one address at once.
 *
 * With SIPRAL_INVITE_LIMIT_EVERY_MS, the floor every stack starts with.
 * An INVITE past it is answered 480 and counted in
 * `sipral_counters_t::screened_refused_by_rate`; no event is raised.
 */
#define SIPRAL_INVITE_LIMIT_BURST 10

/**
 * The default interval: one more INVITE every two seconds.
 */
#define SIPRAL_INVITE_LIMIT_EVERY_MS 2000

/**
 * The voice-agent preset's burst: 128 at once.
 *
 * For a headless service taking every call from one trunk or proxy. Use
 * with SIPRAL_INVITE_LIMIT_VOICE_AGENT_EVERY_MS. Equal to the default
 * `max_dialogs`, so a rush hits that ceiling (503) before the rate.
 */
#define SIPRAL_INVITE_LIMIT_VOICE_AGENT_BURST 128

/**
 * The voice-agent preset's interval: one more INVITE every 50 ms.
 */
#define SIPRAL_INVITE_LIMIT_VOICE_AGENT_EVERY_MS 50

/**
 * Bits of `sipral_call_event_t::privacy` and of
 * `sipral_account_config_t::privacy` (RFC 3323 §4.2): `header`, obscure
 * the fields that could identify the caller.
 */
#define SIPRAL_PRIVACY_HEADER 1

/**
 * `session`: hide the session description from the far end.
 */
#define SIPRAL_PRIVACY_SESSION 2

/**
 * `user`: user-level privacy.
 */
#define SIPRAL_PRIVACY_USER 4

/**
 * `id` (RFC 3325 §9.3): keep the asserted identity inside the trust
 * domain. What "withhold my number" asks for.
 */
#define SIPRAL_PRIVACY_ID 8

/**
 * `critical`: fail the call rather than go without the privacy asked
 * for.
 */
#define SIPRAL_PRIVACY_CRITICAL 16

/**
 * `none`: no privacy, stated. Read only; an account asks for none by
 * leaving every bit clear.
 */
#define SIPRAL_PRIVACY_NONE 32

/**
 * The longest text sipral_stack_state_text writes, NUL included; a
 * buffer this size always fits.
 */
#define SIPRAL_STATE_TEXT_MAX 16384

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
typedef struct sipral_path_candidate sipral_path_candidate_t;
typedef struct sipral_media_info sipral_media_info_t;
typedef struct sipral_stream_stats sipral_stream_stats_t;
typedef struct sipral_media_packet sipral_media_packet_t;
typedef struct sipral_processor_frame sipral_processor_frame_t;
typedef struct sipral_transmit sipral_transmit_t;
typedef struct sipral_transport_failure sipral_transport_failure_t;
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
typedef struct sipral_referral_event sipral_referral_event_t;
typedef struct sipral_turn_stream_event sipral_turn_stream_event_t;
typedef struct sipral_audio_event sipral_audio_event_t;
typedef struct sipral_stun_server_event sipral_stun_server_event_t;
typedef struct sipral_verification_event sipral_verification_event_t;
typedef struct sipral_progress_event sipral_progress_event_t;
typedef struct sipral_conference_event sipral_conference_event_t;
typedef struct sipral_text_event sipral_text_event_t;
typedef struct sipral_presence_event sipral_presence_event_t;
typedef struct sipral_transport_failed_event sipral_transport_failed_event_t;
typedef struct sipral_local_conference_event sipral_local_conference_event_t;
typedef struct sipral_locate_event sipral_locate_event_t;
typedef struct sipral_challenge_event sipral_challenge_event_t;
typedef struct sipral_token_event sipral_token_event_t;
typedef struct sipral_network_test_event sipral_network_test_event_t;
typedef union sipral_event_payload sipral_event_payload_t;
typedef struct sipral_event sipral_event_t;
typedef struct sipral_suspending sipral_suspending_t;
typedef struct sipral_screen_request sipral_screen_request_t;
typedef struct sipral_subscribe_config sipral_subscribe_config_t;
typedef struct sipral_watched_dialog sipral_watched_dialog_t;
typedef struct sipral_push_echo sipral_push_echo_t;
typedef struct sipral_audio_device sipral_audio_device_t;
typedef struct sipral_audio_info sipral_audio_info_t;
typedef struct sipral_audio_transmit sipral_audio_transmit_t;
typedef struct sipral_log_record sipral_log_record_t;
typedef struct sipral_stir_config sipral_stir_config_t;
typedef struct sipral_stream_encryption sipral_stream_encryption_t;
typedef struct sipral_progress_config sipral_progress_config_t;
typedef struct sipral_consent_tone sipral_consent_tone_t;
typedef struct sipral_recording_options sipral_recording_options_t;
typedef struct sipral_conference sipral_conference_t;
typedef struct sipral_conference_user sipral_conference_user_t;
typedef struct sipral_presence sipral_presence_t;
typedef struct sipral_record_config sipral_record_config_t;
typedef struct sipral_local_conference_config sipral_local_conference_config_t;
typedef struct sipral_local_conference_info sipral_local_conference_info_t;
typedef struct sipral_local_conference_member sipral_local_conference_member_t;
typedef struct sipral_pinned_certificate sipral_pinned_certificate_t;
typedef struct sipral_network_test_config sipral_network_test_config_t;

/**
 * The result of a call across the C ABI.
 *
 * The numbers are ABI: stable for the major version, new ones only at the
 * end. 17 is reserved forever and never returned.
 *
 * Typed `int32_t`: zero is success, failures are positive, none negative.
 * Read an unknown status from a newer library as a failure.
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
     * No room: an object table is full, the RTP port range is spent, or a
     * call's queue (DTMF, payload types, real-time text) is full. Nothing
     * was done; the last error says which. `SIPRAL_STATUS_LIMIT_REACHED`
     * is the application's own ceiling.
     */
    SIPRAL_STATUS_EXHAUSTED = 7,
    /**
     * A panic was caught at the boundary. The call did not finish; the last
     * error carries the panic's message.
     */
    SIPRAL_STATUS_PANIC = 8,
    /**
     * Not possible in the object's current state, e.g. answering a call
     * this end placed, or DTMF before there is a dialog.
     */
    SIPRAL_STATUS_WRONG_STATE = 9,
    /**
     * The request could not be assembled or handed to a transport. Nothing
     * went out, and the call did not change.
     */
    SIPRAL_STATUS_NOT_SENT = 10,
    /**
     * The value is valid in this ABI but this build has no code for it.
     * Nothing was applied, and retrying will not help. Unlike
     * SIPRAL_STATUS_INVALID_ARGUMENT, the value is not wrong; unlike
     * SIPRAL_STATUS_UNSUPPORTED_VERSION, it is not about struct shape.
     * Exists so that nothing is ever silently accepted and ignored.
     */
    SIPRAL_STATUS_NOT_SUPPORTED = 11,
    /**
     * A byte stream carried something that starts no known message. A
     * stream has no resync point: close the connection. The last error
     * says what was lost.
     */
    SIPRAL_STATUS_STREAM_BROKEN = 12,
    /**
     * An audio device id the engine never listed. Refused before any
     * platform call; `sipral_audio_device_at` lists the ids.
     */
    SIPRAL_STATUS_NO_SUCH_DEVICE = 13,
    /**
     * The audio device cannot serve: no channels in that direction,
     * unplugged, or the platform refused it. The last error says which.
     */
    SIPRAL_STATUS_DEVICE_UNUSABLE = 14,
    /**
     * The platform did not answer about its audio devices within
     * `sipral_stack_config_t::audio_probe_ms`. Nothing was done.
     */
    SIPRAL_STATUS_DEVICE_TIMED_OUT = 15,
    /**
     * The stack already holds or awaits `sipral_stack_config_t::max_dialogs`
     * calls. Nothing went out. An ended call makes room; a higher limit
     * needs a new stack.
     */
    SIPRAL_STATUS_LIMIT_REACHED = 16,
    /**
     * Refused by the security policy (ABI 0.31): unencrypted audio where
     * SRTP is required, or a policy weaker than the account's. A refused
     * INVITE was answered 488; an outgoing call never left.
     */
    SIPRAL_STATUS_SECURITY_POLICY = 18,
    /**
     * The recording file would not take a write (disk full, volume gone).
     * A bad path is `SIPRAL_STATUS_INVALID_ARGUMENT` instead. The recording
     * stopped; the file holds audio up to the last checkpoint.
     */
    SIPRAL_STATUS_RECORDING_FAILED = 19,
    /**
     * The call never negotiated this, e.g. text on a call with no `m=text`
     * stream. Only a new accepted offer changes it.
     */
    SIPRAL_STATUS_NOT_NEGOTIATED = 20,
    /**
     * The far end's Contact never carried `isfocus` (RFC 4579 §4.1), so
     * there is no conference to name or subscribe to.
     */
    SIPRAL_STATUS_NOT_A_FOCUS = 21,
    /**
     * The transport has failed or closed and was not bound again. Nothing
     * went out. Reconnect, call `sipral_stack_transport_bind`, retry.
     */
    SIPRAL_STATUS_TRANSPORT_DOWN = 22,
    /**
     * A local conference would not take the call (ABI 0.32): full, the
     * call is already conferenced or joined with `sipral_call_join`, or its
     * codec rate is not mixed. The last error says which.
     */
    SIPRAL_STATUS_CONFERENCE_REFUSED = 23,
    /**
     * `now_ms` was more than 50 ms behind the last reading this stack saw
     * (ABI 0.33). Nothing was done and the clock did not move; read the
     * clock again and retry. Repeated, it means the clock went backwards.
     */
    SIPRAL_STATUS_CLOCK_BEHIND = 24,
    /**
     * The TLS certificate's SHA-256 fingerprint differs from
     * `sipral_account_config_t::tls_pin_sha256` (ABI 0.34). Refuse the
     * handshake (`docs/22-tls.md`).
     */
    SIPRAL_STATUS_CERTIFICATE_REFUSED = 25,
    /**
     * About to advertise an address the peer cannot reach (ABI 0.34):
     * loopback to a remote peer, or the unspecified address in a `Contact`.
     * Nothing was sent; the last error names both addresses.
     * `sipral_advertised_address` finds the right one.
     */
    SIPRAL_STATUS_UNREACHABLE_ADDRESS = 26,
};

/**
 * What a stack speaks. Names for `sipral_stack_config_t::transport`. Zero is
 * not one, so a caller who meant TLS is never put on the wire in the clear.
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
 * Why a transport could not deliver. Names for sipral_stack_transport_failed's `error`.
 *
 * Coarse on purpose: a client transaction terminates on every one of these (§17); the
 * detail belongs in the caller's log.
 */
typedef uint32_t sipral_transport_error_t;
enum {
    /**
     * Anything the caller could not classify.
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
 * Why a TLS connection was refused, as the platform's TLS library said it. Names for
 * `sipral_transport_failure_t::tls` and `sipral_transport_failed_event_t::tls`.
 *
 * Sipral links no TLS library (`docs/22-tls.md`); the stack only carries the application's
 * classification. A connection never answered is `SIPRAL_TRANSPORT_ERROR_CONNECTION_REFUSED`
 * with this left at none.
 */
typedef uint32_t sipral_tls_failure_t;
enum {
    /**
     * Not a TLS failure, or one the application could not classify.
     */
    SIPRAL_TLS_FAILURE_NONE = 0,
    /**
     * No trusted authority: self-signed, an unprovided private CA, or not the pinned one.
     */
    SIPRAL_TLS_FAILURE_UNTRUSTED = 1,
    /**
     * The certificate is trusted and names another server.
     */
    SIPRAL_TLS_FAILURE_NAME_MISMATCH = 2,
    /**
     * The certificate has expired, or is not valid yet.
     */
    SIPRAL_TLS_FAILURE_EXPIRED = 3,
    /**
     * The handshake failed: no common version or cipher, a server alert, or no TLS there.
     */
    SIPRAL_TLS_FAILURE_HANDSHAKE_REFUSED = 4,
};

/**
 * The three answers a setting can give in a struct that starts out zeroed.
 *
 * Not a boolean: zero must mean "unset", so the library never turns a
 * control off because the caller left it zeroed.
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
 * Zero means "unset": on the stack, the built-in default
 * SIPRAL_SRTP_NOT_OFFERED; on a call, the stack's setting.
 * `docs/05-media.md` details each value.
 */
typedef uint32_t sipral_srtp_t;
enum {
    /**
     * Do not offer it, but answer an offer on the secure profile with keys.
     */
    SIPRAL_SRTP_NOT_OFFERED = 1,
    /**
     * Offer it, and answer a plain offer plainly.
     */
    SIPRAL_SRTP_OFFERED = 2,
    /**
     * Offer it, and let no stream on this call carry audio unencrypted.
     */
    SIPRAL_SRTP_REQUIRED = 3,
    /**
     * Offer DTLS-SRTP (RFC 5764) on `UDP/TLS/RTP/SAVP`, and answer a plain
     * offer plainly.
     *
     * The key never travels in the body, so this is sound over a readable
     * SIP transport. Costs a round trip of silence at call start. The
     * application **must** drain sipral_media_poll_transmit, or the
     * call is up, silent, and reports no error.
     *
     * `SIPRAL_STATUS_NOT_SUPPORTED` in a build without
     * `SIPRAL_FEATURE_DTLS_SRTP`.
     */
    SIPRAL_SRTP_DTLS = 4,
    /**
     * Offer DTLS-SRTP and allow no other keying, including an answer
     * carrying `a=crypto`.
     */
    SIPRAL_SRTP_DTLS_REQUIRED = 5,
    /**
     * DTLS-SRTP with SDES fallback, never unencrypted. The offer is one
     * `RTP/SAVP` stream with both fingerprint and crypto lines; the answer
     * decides. An incoming offer is answered the way it was keyed; a plain
     * one is refused with 488.
     *
     * `SIPRAL_STATUS_NOT_SUPPORTED` in a build without
     * `SIPRAL_FEATURE_DTLS_SRTP`.
     */
    SIPRAL_SRTP_DTLS_OR_SDES = 6,
    /**
     * Offer SDES on plain `RTP/AVP` ("SRTP optional"): encrypted when the
     * answer takes an `a=crypto` line, plain otherwise. For servers that
     * reject `RTP/SAVP` with 488. Not standard (RFC 4568 defines the
     * attribute for secure profiles). An incoming `RTP/AVP` offer with a
     * usable line is answered with a key, anything else as `Offered`.
     */
    SIPRAL_SRTP_BEST_EFFORT = 7,
};

/**
 * What a call or a stack says about ICE. Names for
 * `sipral_stack_config_t::ice` (the stack's default) and
 * `sipral_call_config_t::ice` (a per-call override).
 *
 * Zero means "unset": on the stack, the built-in default
 * SIPRAL_ICE_OFF; on a call, the stack's setting.
 *
 * A call that offers ICE also asks for RFC 5761 multiplexing, whatever
 * `offer_rtcp_mux` says: this ABI names one address per stream.
 */
typedef uint32_t sipral_ice_t;
enum {
    /**
     * Do not offer it, and do not answer a peer that does. The default;
     * `docs/06-nat.md` says why.
     */
    SIPRAL_ICE_OFF = 1,
    /**
     * Offer it, and use it against a peer that offers it back.
     *
     * A peer without ICE gets the call on the signalled address and
     * symmetric RTP. The application **must** drain
     * sipral_media_poll_transmit, or no path is ever chosen.
     *
     * `SIPRAL_STATUS_NOT_SUPPORTED` in a build without
     * `SIPRAL_FEATURE_ICE`.
     */
    SIPRAL_ICE_OFFERED = 2,
    /**
     * Offer it, and let no stream carry audio on a path ICE did not check.
     *
     * A peer that fails ICE ends the call's media with
     * `SIPRAL_EVENT_KIND_MEDIA_FAILED` instead of falling back.
     */
    SIPRAL_ICE_REQUIRED = 3,
    /**
     * Be an ICE-lite endpoint (RFC 8445 §2.5): `a=ice-lite`, one host
     * candidate, answer a full peer's checks, use the pair it nominates.
     *
     * **Only for a server reachable at the address it advertises** (its
     * own, or a one-to-one NAT's via `sipral_stack_nat_map`); never for a
     * softphone. RFC 8445 Appendix A: lite "will not function when a lite
     * implementation is placed behind a NAT". A peer with no ICE, or lite
     * itself, gets the signalled address. The application still drains
     * `sipral_media_poll_transmit` for check answers.
     *
     * `SIPRAL_STATUS_NOT_SUPPORTED` in a build without
     * `SIPRAL_FEATURE_ICE`.
     */
    SIPRAL_ICE_LITE = 4,
};

/**
 * One codec this ABI has a number for.
 *
 * Values are permanent. Whether this build contains a codec is answered by
 * `SIPRAL_FEATURE_*` and `sipral_codec_at`, not by this list.
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
     * Opus. Declared in every build; presence is `SIPRAL_FEATURE_OPUS`.
     */
    SIPRAL_CODEC_OPUS = 4,
    /**
     * G.729 Annex A, payload type 18. Offered only when a codec order names
     * `G729`; offers `annexb=yes`, answers with the offer's `annexb`.
     */
    SIPRAL_CODEC_G729 = 5,
    /**
     * L16 at 8 kHz mono, dynamic payload type `L16/8000`. Offered only
     * when a codec order names it.
     */
    SIPRAL_CODEC_L16_NARROWBAND = 6,
    /**
     * L16 at 16 kHz mono, `L16/16000`. Offered only when a codec order
     * names it.
     */
    SIPRAL_CODEC_L16_WIDEBAND = 7,
};

/**
 * What became of one codec this call's catalogue could have used. Names
 * for sipral_codec_candidate_t::outcome.
 */
typedef uint32_t sipral_codec_outcome_t;
enum {
    /**
     * Not an outcome: unknown to this ABI, or the struct was never filled.
     */
    SIPRAL_CODEC_OUTCOME_UNKNOWN = 0,
    /**
     * What the call agreed on. Exactly one candidate carries it, the same
     * codec as `sipral_media_info_t::codec`.
     */
    SIPRAL_CODEC_OUTCOME_CHOSEN = 1,
    /**
     * The far end's description did not name it.
     */
    SIPRAL_CODEC_OUTCOME_NOT_NAMED = 2,
    /**
     * The far end named it and this end had something better: the codec
     * in `outranked_by` came first in this call's order.
     */
    SIPRAL_CODEC_OUTCOME_OUTRANKED = 3,
};

/**
 * Whether a sipral_path_candidate_t is a candidate pair or a relay.
 */
typedef uint32_t sipral_path_kind_t;
enum {
    /**
     * Not a kind: the struct was never filled in.
     */
    SIPRAL_PATH_KIND_UNKNOWN = 0,
    /**
     * A candidate pair the call's ICE checklist held (RFC 8445
     * §6.1.2).
     */
    SIPRAL_PATH_KIND_PAIR = 1,
    /**
     * An allocation on a TURN server the call's agent held (RFC 8656).
     */
    SIPRAL_PATH_KIND_RELAY = 2,
};

/**
 * The kind of an ICE candidate (RFC 8445 §5.1.1). Names for
 * sipral_path_candidate_t::local_kind and `remote_kind`.
 */
typedef uint32_t sipral_candidate_kind_t;
enum {
    /**
     * Not known: a relay's server, which is no candidate, or the far
     * end of a pair a lite end took from a nomination and never learned
     * the kind of.
     */
    SIPRAL_CANDIDATE_KIND_UNKNOWN = 0,
    /**
     * An address a socket of the host's own is bound to.
     */
    SIPRAL_CANDIDATE_KIND_HOST = 1,
    /**
     * The address a NAT maps the host's socket to, as a STUN or TURN
     * server saw it.
     */
    SIPRAL_CANDIDATE_KIND_SERVER_REFLEXIVE = 2,
    /**
     * An address a connectivity check revealed (RFC 8445 §7.3.1.3).
     */
    SIPRAL_CANDIDATE_KIND_PEER_REFLEXIVE = 3,
    /**
     * An address on a TURN server that relays for the host.
     */
    SIPRAL_CANDIDATE_KIND_RELAYED = 4,
};

/**
 * What became of one path a call's ICE agent tried. Names for
 * sipral_path_candidate_t::outcome.
 */
typedef uint32_t sipral_path_outcome_t;
enum {
    /**
     * Not an outcome: unknown to this ABI, or the struct was never filled.
     */
    SIPRAL_PATH_OUTCOME_UNKNOWN = 0,
    /**
     * The path the call's media takes: the selected pair (RFC 8445
     * §8.1.2), or the relay it runs through.
     */
    SIPRAL_PATH_OUTCOME_SELECTED = 1,
    /**
     * A pair whose check succeeded, with nothing selected yet.
     */
    SIPRAL_PATH_OUTCOME_VALID = 2,
    /**
     * Nothing has decided it yet: a pair frozen, waiting its turn or
     * with its check on the wire; a relay still being allocated.
     */
    SIPRAL_PATH_OUTCOME_WAITING = 3,
    /**
     * A pair whose check succeeded, with a pair of higher priority
     * selected over it.
     */
    SIPRAL_PATH_OUTCOME_OUTRANKED = 4,
    /**
     * A pair another was nominated ahead of: its check had not finished
     * when the selection took it off the checklist (RFC 8445 §8.1.2),
     * or it succeeded after a lower one was nominated.
     */
    SIPRAL_PATH_OUTCOME_NOMINATED_ELSEWHERE = 5,
    /**
     * A pair whose check was never answered (RFC 8489 §6.2.1).
     */
    SIPRAL_PATH_OUTCOME_TIMED_OUT = 6,
    /**
     * A pair the far end refused; `code` is the STUN error code (RFC
     * 8445 §7.2.5.2.4).
     */
    SIPRAL_PATH_OUTCOME_REFUSED = 7,
    /**
     * A pair whose answer came from an address other than the one its
     * check went to (RFC 8445 §7.2.5.2.1): a NAT between rewriting it.
     */
    SIPRAL_PATH_OUTCOME_NOT_SYMMETRIC = 8,
    /**
     * A pair whose answer named no address to form a valid pair from.
     */
    SIPRAL_PATH_OUTCOME_UNUSABLE = 9,
    /**
     * A relayed pair the relay would not let the far end through for,
     * or a relay whose allocation the server refused; `code` is the
     * TURN server's error code, zero when it gave none (RFC 8656 §9,
     * §7.3).
     */
    SIPRAL_PATH_OUTCOME_RELAY_REFUSED = 10,
    /**
     * A pair never checked: the pair limit discarded it (RFC 8445
     * §6.1.2.5), or its checklist ended before its turn came.
     */
    SIPRAL_PATH_OUTCOME_NOT_CHECKED = 11,
    /**
     * A relay held, that no selected pair runs through — or none yet.
     */
    SIPRAL_PATH_OUTCOME_HELD = 12,
    /**
     * A relay given back: ICE concluded on a pair that does not use it
     * (RFC 8445 §8.3.1), or this branch of a forked call let go of it.
     */
    SIPRAL_PATH_OUTCOME_RELEASED = 13,
    /**
     * A relay the server took back; `code` is its error code, zero when
     * a refresh went unanswered (RFC 8656 §8).
     */
    SIPRAL_PATH_OUTCOME_LOST = 14,
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
 * Why media failed, for a machine to act on. Names for
 * `sipral_media_event_t::fault`.
 */
typedef uint32_t sipral_media_fault_t;
enum {
    /**
     * Nothing failed.
     */
    SIPRAL_MEDIA_FAULT_NONE = 0,
    /**
     * The peer answered with a format this build cannot encode or decode.
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
     * (RFC 7675 §5). Signalling is still sound; an application may fall
     * back to a non-ICE profile.
     */
    SIPRAL_MEDIA_FAULT_ICE = 9,
    /**
     * The SRTP policy refused the far end's description: a plain answer
     * (hung up with `Reason` 488) or a plain re-offer (refused with 488,
     * old keys kept).
     */
    SIPRAL_MEDIA_FAULT_SECURITY_POLICY = 10,
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
     * A DTLS-SRTP handshake record, taken. Drain
     * sipral_media_poll_transmit for the reply.
     */
    SIPRAL_ARRIVAL_HANDSHAKE = 6,
    /**
     * Arrived on an encrypted call before its keys exist; usually a peer
     * that sends as soon as its half of the handshake ends.
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
    /**
     * `AES_256_CM_HMAC_SHA1_80` (RFC 6188). SDES only.
     */
    SIPRAL_SRTP_SUITE_AES256_CM80 = 4,
    /**
     * `AES_256_CM_HMAC_SHA1_32` (RFC 6188). SDES only.
     */
    SIPRAL_SRTP_SUITE_AES256_CM32 = 5,
    /**
     * `AEAD_AES_128_GCM` (RFC 7714). DTLS-SRTP profile 0x0007.
     */
    SIPRAL_SRTP_SUITE_AEAD_AES128_GCM = 6,
    /**
     * `AEAD_AES_256_GCM` (RFC 7714). DTLS-SRTP profile 0x0008, preferred
     * between two ends of this stack.
     */
    SIPRAL_SRTP_SUITE_AEAD_AES256_GCM = 7,
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
 * Which way a digit goes to the far end: sipral_call_send_dtmf's `via`. Chosen per
 * send, since it is a fact about the peer, and a peer ignores an unsupported one silently.
 */
typedef uint32_t sipral_dtmf_t;
enum {
    /**
     * In the media, as an RFC 4733 telephone event: the one to reach for, carried end to
     * end and surviving transcoding. One, not zero: zero is an unfilled field, refused.
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
    /**
     * In the media, as the key's two tones written into the audio in place of the microphone,
     * for a far end that listens only to the audio. `SIPRAL_DTMF_RTP` falls back to this on a
     * call with no telephone event.
     */
    SIPRAL_DTMF_IN_BAND = 4,
};

/**
 * What an event is about. Numbers are only ever added; a binding must
 * ignore a kind it does not know.
 *
 * Numbers already spent on features this build does not have:
 * - 16: held for the set of audio devices changed (A2), which shipped as 43 in the wave that allocated its number; spent all the same
 * - 44: held for a second audio device event, which the audio engine did not need; spent all the same
 */
typedef uint32_t sipral_event_kind_t;
enum {
    /**
     * The stack is running on this thread: the first event, delivered
     * once by the first poll.
     */
    SIPRAL_EVENT_KIND_STARTED = 1,
    /**
     * A registration moved. `payload.registration` says how, and
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
     * And how it ended: the far end's final status, a 2xx hanging this
     * call up. A refused REFER (RFC 3515 §2.4.2) ends here with its status,
     * a timeout as 408, a transport failure as 503; the call stays up.
     */
    SIPRAL_EVENT_KIND_TRANSFER_DONE = 12,
    /**
     * A call arrived carrying a `Replaces` and took over one already up.
     * `payload.call.other` is the one being replaced.
     */
    SIPRAL_EVENT_KIND_CALL_REPLACED = 13,
    /**
     * The call is over; its handle is stale from here on. `message` is
     * the refusal, or the far end's BYE or CANCEL, or null.
     */
    SIPRAL_EVENT_KIND_CALL_ENDED = 14,
    /**
     * A1. A subscription moved: asked for, granted, on probation,
     * retrying, or ended. `payload.subscription` says which and where it
     * is, `reason` why it is not live. Not sent per refresh or per NOTIFY.
     */
    SIPRAL_EVENT_KIND_SUBSCRIPTION_CHANGED = 15,
    /**
     * A6. What one call's media cost, once, after
     * `SIPRAL_EVENT_KIND_CALL_ENDED`. `payload.media.statistics` points
     * at the record, library-owned and valid for the callback.
     */
    SIPRAL_EVENT_KIND_MEDIA_STATISTICS = 17,
    /**
     * B1. A request grew too large for a datagram (RFC 3261 §18.1.1) and
     * no stream transport is open to its destination; it was refused with
     * `SIPRAL_STATUS_NOT_SENT`. `payload.transport_wanted` says where.
     * Bind with
     * sipral_stack_transport_bind
     * and ask again.
     */
    SIPRAL_EVENT_KIND_TRANSPORT_WANTED = 18,
    /**
     * B5. No media has arrived for longer than the configured threshold.
     * `payload.media.silent_for_ms` says how long. The call is left up.
     */
    SIPRAL_EVENT_KIND_MEDIA_STALLED = 19,
    /**
     * C2. A call a push announced never arrived: the device woke and
     * refreshed, and no INVITE followed. `payload.announce` says which
     * announcement and how long it was waited for.
     */
    SIPRAL_EVENT_KIND_ANNOUNCED_CALL_MISSING = 20,
    /**
     * A4, D5. Audio is running; `payload.media.codec` is the agreed codec.
     * Mint the media handle now with `sipral_call_media`.
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
     * A recording stopped on its own (disk full, file gone).
     * `payload.media.recorded_ms` says how much was written.
     */
    SIPRAL_EVENT_KIND_RECORDING_STOPPED = 25,
    /**
     * The far end pressed a key (RFC 4733 event, or INFO with
     * `application/dtmf-relay` or `application/dtmf`), one per press.
     * `payload.media` gives `digit`, `event_code`, `held_ms` and `source`.
     * `held_ms` zero means no duration or `Duration=0`, not told apart.
     */
    SIPRAL_EVENT_KIND_DIGIT_RECEIVED = 26,
    /**
     * An INFO from `sipral_call_send_dtmf` got a final answer:
     * `payload.call.digit` and `payload.call.status_code` (415: try the
     * other INFO form). An unsendable queued digit reports 503 and stops
     * the rest.
     */
    SIPRAL_EVENT_KIND_DTMF_SENT = 27,
    /**
     * The lifecycle ladder settled: a path proved again, or every rung
     * failed. `payload.recovery` says which (`docs/16-lifecycle.md`).
     */
    SIPRAL_EVENT_KIND_RECOVERY = 28,
    /**
     * A dialog's next hop is a name to resolve (RFC 3263 §4 TARGET).
     * Answer with
     * sipral_stack_resolved
     * and `payload.resolve.dialog`. **Ignoring it is fine**: the dialog
     * keeps its first flow (§8.1.2), which survives a NAT.
     */
    SIPRAL_EVENT_KIND_RESOLVE_NEEDED = 29,
    /**
     * A1. A notification arrived and was answered; the NOTIFY is in
     * `message`. `payload.subscription.has_dialog_info` says the body was
     * readable dialog-info, read via
     * sipral_subscription_dialog_count.
     * An unreadable body arrives with it zero; the old picture is kept.
     */
    SIPRAL_EVENT_KIND_NOTIFIED = 30,
    /**
     * C2. The INVITE for a call a push announced arrived (RFC 8599),
     * queued just before its SIPRAL_EVENT_KIND_INCOMING_CALL.
     * `payload.announce.announcement` is now spent:
     * `sipral_announcement_forget` answers `SIPRAL_STATUS_WRONG_STATE`.
     */
    SIPRAL_EVENT_KIND_CALL_ANNOUNCED = 31,
    /**
     * The DTLS-SRTP handshake finished and audio can move (RFC 5764).
     * `payload.media.suite` is the chosen transform. SDES calls never
     * raise it; a failed handshake raises `SIPRAL_EVENT_KIND_MEDIA_FAILED`
     * and leaves the call up.
     */
    SIPRAL_EVENT_KIND_MEDIA_SECURED = 32,
    /**
     * ICE chose this call's media path (RFC 8445 §8.1.1), and audio can
     * move; again if a higher-priority pair replaces it. Addresses are not
     * carried: each outgoing packet names its destination. Never raised
     * without ICE (default `SIPRAL_ICE_OFF`).
     */
    SIPRAL_EVENT_KIND_MEDIA_PATH_CHOSEN = 33,
    /**
     * A MESSAGE arrived (RFC 3428 §7) and was answered 200.
     * `payload.message` carries the body; `call` is set if it was in-dialog.
     */
    SIPRAL_EVENT_KIND_MESSAGE_RECEIVED = 34,
    /**
     * A MESSAGE from `sipral_account_message` got its final answer:
     * `payload.message.status_code` (408/503 for timeout or transport).
     */
    SIPRAL_EVENT_KIND_MESSAGE_SENT = 35,
    /**
     * A `message-summary` NOTIFY reported a mailbox (RFC 3842 §3.9);
     * `payload.message` has the `voice-message` counts.
     */
    SIPRAL_EVENT_KIND_MESSAGES_WAITING = 36,
    /**
     * The RFC 6035 quality report PUBLISH was attempted once, after
     * `SIPRAL_EVENT_KIND_CALL_ENDED`, if `quality_report_uri` was set.
     * `payload.media.quality_report_sent` says it left, not that it landed.
     */
    SIPRAL_EVENT_KIND_QUALITY_REPORT_SENT = 37,
    /**
     * The call this one was joined to ended. `call` is the survivor and
     * carries on unjoined, fed directly rather than by `sipral_media_mix`.
     */
    SIPRAL_EVENT_KIND_MEDIA_UNJOINED = 38,
    /**
     * A STUN server reported, moved or never answered for a socket
     * (RFC 8489). Only with `SIPRAL_NAT_STUN`. `payload.nat` says which.
     * Signalling sockets are already re-registered; a media socket from
     * `sipral_stack_nat_map` is now usable for calls (before, that is
     * `SIPRAL_STATUS_WRONG_STATE`). `account`, `call`: none.
     */
    SIPRAL_EVENT_KIND_NAT_MAPPING = 39,
    /**
     * A TURN server allocated a relay for a `sipral_stack_nat_map` socket,
     * or gave none (RFC 8656). Only with a `turn_server`. `payload.relay`
     * says which; once allocated, calls may use it (before, that is
     * `SIPRAL_STATUS_WRONG_STATE`). `account`, `call`: none.
     */
    SIPRAL_EVENT_KIND_NAT_RELAY = 40,
    /**
     * An out-of-dialog REFER asks this end to place a call (RFC 3515),
     * with `sipral_stack_config_t::referrals` on. `call` is the referral's
     * handle, taken only by `sipral_call_accept_transfer` (202, places the
     * call) or `sipral_call_reject_transfer`; either spends it. `account`
     * is the line, `message` the REFER, `payload.referral` the target.
     * **The application decides each time**: `referred_by` is unverified.
     * If left unanswered, raised again with only `status_code` set, and
     * the handle is stale.
     */
    SIPRAL_EVENT_KIND_REFERRAL = 41,
    /**
     * A media socket's TCP/TLS connection to a TURN server
     * (`turn_transport`, RFC 8656 §3.1) is to be opened or closed.
     * `payload.turn_stream` says which. On `SIPRAL_TURN_STREAM_OPEN`, open
     * it (TLS checked against the server name), then call
     * `sipral_stack_turn_connected`, `sipral_stack_turn_receive` and
     * `sipral_stack_turn_closed`. On `SIPRAL_TURN_STREAM_CLOSE`, flush and
     * close. `account`, `call`: none.
     */
    SIPRAL_EVENT_KIND_TURN_STREAM = 42,
    /**
     * The audio engine's devices moved (with `SIPRAL_AUDIO_DEVICE`).
     * `payload.audio` says what and whether the system or the engine did
     * it. `account`, `call`: none.
     */
    SIPRAL_EVENT_KIND_AUDIO_DEVICES_CHANGED = 43,
    /**
     * The network changed and this call's media address is gone. Raised
     * per call by `sipral_stack_network_changed` on
     * `SIPRAL_RECOVERY_REBUILD`: after `sipral_account_rebind`, pass a new
     * socket address to `sipral_call_media_readdress`.
     */
    SIPRAL_EVENT_KIND_CALL_ADDRESS_WANTED = 45,
    /**
     * The STUN server in use changed, or all failed
     * (`payload.stun_server`). A server fails after 5.5 s and is skipped
     * for 30 s, doubling up to ten minutes. Sockets move on by themselves.
     * `account`, `call`: none.
     */
    SIPRAL_EVENT_KIND_STUN_SERVER = 46,
    /**
     * Caller verification (RFC 8224, RFC 8588); `payload.verification`.
     * `CERTIFICATE_WANTED`: fetch `certificate_url` and pass it (or
     * nothing) to `sipral_call_stir_certificate`; the call waits.
     * `VERIFIED`: the verdict, just before the call's
     * `SIPRAL_EVENT_KIND_INCOMING_CALL`, or with `refused` set before its
     * `SIPRAL_EVENT_KIND_CALL_ENDED`. `message` is the INVITE.
     */
    SIPRAL_EVENT_KIND_CALLER_VERIFICATION = 47,
    /**
     * A keypad digit heard as tones (with DTMF detection enabled), once
     * per press. A press also sent as a named event is reported once as
     * `SIPRAL_EVENT_KIND_DIGIT_RECEIVED`; tones alone wait 250 ms.
     */
    SIPRAL_EVENT_KIND_IN_BAND_DIGIT = 48,
    /**
     * What `sipral_call_detect_progress` heard: a progress tone, the
     * special information tone, who answered, or a machine's beep
     * (`payload.progress`).
     */
    SIPRAL_EVENT_KIND_PROGRESS_DETECTED = 49,
    /**
     * A `conference` subscription's picture changed or the conference
     * ended (RFC 4575 §4.6); `payload.conference`. Read the picture with
     * `sipral_subscription_conference`. Out-of-order documents raise
     * nothing; after a loss the stack asks for full state.
     */
    SIPRAL_EVENT_KIND_CONFERENCE_CHANGED = 50,
    /**
     * Real-time text from the far end (RFC 4103), in order, UTF-8 in
     * `payload.text`: BACKSPACE erases, U+2028 is a new line, BELL alerts,
     * U+FFFD marks each unrecovered lost block (§5.3), counted in `missing`.
     */
    SIPRAL_EVENT_KIND_TEXT_RECEIVED = 51,
    /**
     * Presence moved: a `presence` subscription's PIDF (RFC 3856), or this
     * account's publication (RFC 3903). `payload.presence.kind` says
     * which.
     */
    SIPRAL_EVENT_KIND_PRESENCE_CHANGED = 52,
    /**
     * A signalling transport stopped: reported failed or closed, bad
     * stream bytes, or a keep-alive unanswered for ten seconds (RFC 5626
     * §4.4.1). `payload.transport_failed` says why. Until
     * `sipral_stack_transport_bind` restores it, requests get
     * `SIPRAL_STATUS_TRANSPORT_DOWN`. `account`, `call`: none.
     */
    SIPRAL_EVENT_KIND_TRANSPORT_FAILED = 53,
    /**
     * A local conference changed: membership, talkers, or recording
     * (`payload.local_conference`). `account`, `call`: none.
     */
    SIPRAL_EVENT_KIND_LOCAL_CONFERENCE_CHANGED = 54,
    /**
     * A DNS lookup is wanted to locate an account's server (RFC 3263).
     * Pass every answer, failures included, to `sipral_account_looked_up`.
     */
    SIPRAL_EVENT_KIND_LOOKUP_WANTED = 55,
    /**
     * An account's server was located: `payload.locate.targets`, the
     * address in use first.
     */
    SIPRAL_EVENT_KIND_LOCATED = 56,
    /**
     * Locating an account's server failed; `retry_in_ms` says when it
     * retries. An earlier address stays in use.
     */
    SIPRAL_EVENT_KIND_LOCATE_FAILED = 57,
    /**
     * A challenge was not answered because it came from outside the
     * account's protection domain (RFC 3261 §22.1): an answer would feed
     * an offline password guess. `payload.challenge` says who and why.
     */
    SIPRAL_EVENT_KIND_CHALLENGE_DECLINED = 58,
    /**
     * The account's server wants an OAuth 2.0 token (RFC 8898) and has
     * none acceptable. Check `payload.token.authz_server` against trusted
     * servers (§2.1.1), then pass a token to
     * `sipral_account_set_access_token`.
     */
    SIPRAL_EVENT_KIND_TOKEN_REQUIRED = 59,
    /**
     * A `sipral_stack_network_test` finished; `payload.network_test`.
     */
    SIPRAL_EVENT_KIND_NETWORK_TEST = 60,
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
     * A binding a registrar granted, over a transport since suspended or
     * lost, which nothing has proved since.
     *
     * A monotonic clock does not advance while a machine sleeps, so after
     * sleep every binding would otherwise look valid. Do not show the line
     * as ready in this state.
     */
    SIPRAL_REGISTRATION_STATE_UNVERIFIED = 8,
    /**
     * A binding read back from a snapshot rather than granted in this
     * process. It has not been proved either.
     */
    SIPRAL_REGISTRATION_STATE_RESTORED = 9,
    /**
     * The account has no registrar and never registers (a trunk that
     * knows this end by address). `sipral_account_register` refuses it.
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
    /**
     * The account's `Contact` is unreachable for the registrar (loopback
     * or unspecified); nothing was sent. Fix with `sipral_account_rebind`.
     */
    SIPRAL_REGISTRATION_FAILURE_UNREACHABLE_CONTACT = 5,
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
 * Which way a digit arrived. Names for `sipral_media_event_t::source`.
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
    /**
     * The two tones themselves, heard in the far end's audio, for
     * SIPRAL_EVENT_KIND_IN_BAND_DIGIT.
     */
    SIPRAL_DIGIT_SOURCE_IN_BAND = 2,
};

/**
 * What a SIPRAL_EVENT_KIND_RECOVERY reports, for
 * `payload.recovery.state`.
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
 * The last rung tried before giving up, for `payload.recovery.rung`.
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
 * `payload.recovery.reason`.
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
 * What kind of link the application is on: `from_link` and `to_link` on
 * sipral_stack_network_changed.
 *
 * Only SIPRAL_LINK_DOWN changes what is done. The rest makes a change
 * of kind over an unchanged address (a tunnel, Wi-Fi to cellular) visible.
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
 * What a change of network is worth doing about:
 * sipral_stack_network_changed's `out_recovery`. Returned directly, so
 * a laptop flipping access points gets SIPRAL_RECOVERY_NOTHING without
 * reading an event or sending a REGISTER.
 */
typedef uint32_t sipral_recovery_t;
enum {
    /**
     * Never written by this build.
     */
    SIPRAL_RECOVERY_UNKNOWN = 0,
    /**
     * Nothing this stack uses is different; nothing is done or sent.
     */
    SIPRAL_RECOVERY_NOTHING = 1,
    /**
     * The address stands, so the transports do; what is upstream may not.
     */
    SIPRAL_RECOVERY_REREGISTER = 2,
    /**
     * A wake: the existing transport is tried first, a new one asked for
     * only if it is dead. Started by sipral_stack_resumed, never
     * returned here.
     */
    SIPRAL_RECOVERY_REPROVE = 3,
    /**
     * The address is gone; the application must open a transport again.
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
 * `sipral_stack_config_t::nat`. Zero means the built-in default, SIPRAL_NAT_OFF.
 */
typedef uint32_t sipral_nat_t;
enum {
    /**
     * Ask nobody: every address written is the one the application gave.
     */
    SIPRAL_NAT_OFF = 1,
    /**
     * Ask `stun_server` where each socket appears from and write that instead.
     * `SIPRAL_STATUS_NOT_SUPPORTED` without `SIPRAL_FEATURE_STUN`.
     */
    SIPRAL_NAT_STUN = 2,
};

/**
 * What a socket's mapping came to. Names for `sipral_nat_event_t::mapping`.
 */
typedef uint32_t sipral_nat_mapping_t;
enum {
    /**
     * The first answer: the socket appears at `public`.
     */
    SIPRAL_NAT_MAPPING_LEARNED = 1,
    /**
     * A later answer named another address; `previous` is the old one. Signalling socket, or a
     * media socket still waiting for its call.
     */
    SIPRAL_NAT_MAPPING_MOVED = 2,
    /**
     * No answer within five and a half seconds, or refused. The socket is described by its own
     * address; a signalling socket asks again at its next refresh.
     */
    SIPRAL_NAT_MAPPING_UNANSWERED = 3,
};

/**
 * What a media socket's relay came to. Names for `sipral_nat_relay_event_t::outcome`.
 */
typedef uint32_t sipral_nat_relay_t;
enum {
    /**
     * The relay exists at `relayed`; later calls on the socket offer it as an ICE candidate.
     */
    SIPRAL_NAT_RELAY_ALLOCATED = 1,
    /**
     * No relay: refused (see `code`), no answer in 39.5 seconds, or allocation lost. Calls on
     * the socket go without one.
     */
    SIPRAL_NAT_RELAY_FAILED = 2,
};

/**
 * What to do with a media socket's TURN connection. Names for
 * `sipral_turn_stream_event_t::state`.
 */
typedef uint32_t sipral_turn_stream_t;
enum {
    /**
     * Open a connection from `local` to `server` over `protocol` (TLS verified by the
     * platform), then call `sipral_stack_turn_connected`, or `sipral_stack_turn_closed` on failure. Calls
     * on the socket before that answer `SIPRAL_STATUS_WRONG_STATE`.
     */
    SIPRAL_TURN_STREAM_OPEN = 1,
    /**
     * Nothing more will be written for `local`: flush `sipral_stack_poll_farewell` and
     * `sipral_stack_poll_stun` for it, then close it.
     */
    SIPRAL_TURN_STREAM_CLOSE = 2,
};

/**
 * What happened to the STUN servers. Names for `sipral_stun_server_event_t::state`.
 */
typedef uint32_t sipral_stun_server_state_t;
enum {
    /**
     * Another server is in use now: failover, an earlier one answering again, or a new list.
     */
    SIPRAL_STUN_SERVER_STATE_CHANGED = 1,
    /**
     * Every server failed and is backing off; `server` is the last. Sockets keep what they
     * learned. Said once until a server answers again.
     */
    SIPRAL_STUN_SERVER_STATE_ALL_FAILED = 2,
};

/**
 * Where a subscription is: `sipral_subscription_event_t::state` and
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
     * The notifier has not decided (RFC 6665 §4.1.3 `pending`); nothing
     * is known until SIPRAL_SUBSCRIPTION_STATE_ACTIVE.
     */
    SIPRAL_SUBSCRIPTION_STATE_PENDING = 2,
    /**
     * Granted, and notifications are arriving.
     */
    SIPRAL_SUBSCRIPTION_STATE_ACTIVE = 3,
    /**
     * Not live, and a fresh attempt is scheduled (§4.1.2.2: new
     * `Call-ID` and `From` tag). The handle stays valid across both.
     */
    SIPRAL_SUBSCRIPTION_STATE_RETRYING = 4,
    /**
     * Over, nothing more coming. The handle names nothing from here on.
     */
    SIPRAL_SUBSCRIPTION_STATE_ENDED = 5,
};

/**
 * Why a subscription is not live: `sipral_subscription_event_t::reason`.
 *
 * Zero unless SIPRAL_SUBSCRIPTION_STATE_RETRYING or
 * SIPRAL_SUBSCRIPTION_STATE_ENDED. The first eight are the `reason` of
 * `Subscription-State: terminated` (RFC 6665 §4.1.3); the rest happened
 * here.
 */
typedef uint32_t sipral_subscription_end_t;
enum {
    /**
     * Never written by this build.
     */
    SIPRAL_SUBSCRIPTION_END_UNKNOWN = 0,
    /**
     * `deactivated`: the notifier wants it started again at once.
     */
    SIPRAL_SUBSCRIPTION_END_DEACTIVATED = 1,
    /**
     * `probation`: started again, but not immediately.
     */
    SIPRAL_SUBSCRIPTION_END_PROBATION = 2,
    /**
     * `rejected`: the notifier will not serve it; do not ask again.
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
     * `invariant`: the watched thing cannot change.
     */
    SIPRAL_SUBSCRIPTION_END_INVARIANT = 7,
    /**
     * `terminated` with no reason parameter at all.
     */
    SIPRAL_SUBSCRIPTION_END_UNSTATED = 8,
    /**
     * This end gave it up with sipral_subscription_end. Wins over
     * the notifier's closing reason.
     */
    SIPRAL_SUBSCRIPTION_END_UNSUBSCRIBED = 9,
    /**
     * The notifier answered 489: it does not know this event package.
     */
    SIPRAL_SUBSCRIPTION_END_BAD_EVENT = 10,
    /**
     * Refused with a status a retry cannot fix.
     */
    SIPRAL_SUBSCRIPTION_END_REFUSED = 11,
    /**
     * Redirected; this stack does not follow redirects for SUBSCRIBE.
     */
    SIPRAL_SUBSCRIPTION_END_REDIRECTED = 12,
    /**
     * Nothing answered: the notifier could not be reached at all.
     */
    SIPRAL_SUBSCRIPTION_END_UNREACHABLE = 13,
    /**
     * Answered, but the first NOTIFY never came (§4.1.2.4's timer N,
     * 64·T1).
     */
    SIPRAL_SUBSCRIPTION_END_NO_NOTIFY = 14,
    /**
     * What the notifier granted ran out with no refresh answered.
     */
    SIPRAL_SUBSCRIPTION_END_EXPIRED = 15,
};

/**
 * What one watched dialog is doing, and what a lamp shows:
 * `sipral_watched_dialog_t::phase` and sipral_subscription_lamp's
 * `out_phase`. RFC 4235 §3.7.1's states, ranked as §3.7.2 ranks them.
 */
typedef uint32_t sipral_dialog_phase_t;
enum {
    /**
     * No dialog, or all terminated: an idle lamp.
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
     * which is SIPRAL_DIALOG_PHASE_IDLE then.
     */
    SIPRAL_DIALOG_PHASE_TERMINATED = 5,
    /**
     * The notifier named a state this build has no number for.
     */
    SIPRAL_DIALOG_PHASE_UNKNOWN = 6,
};

/**
 * Which end started a watched dialog: `sipral_watched_dialog_t::direction`.
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
 * How a watched dialog ended: `sipral_watched_dialog_t::ended`, zero
 * while it has not.
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
 * Which text sipral_subscription_dialog_text reads. Each is what the
 * notifier wrote, unparsed.
 */
typedef uint32_t sipral_dialog_text_t;
enum {
    /**
     * Never asked for.
     */
    SIPRAL_DIALOG_TEXT_UNKNOWN = 0,
    /**
     * The notifier's own id for this dialog.
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
     * Who the other end is, as a URI: what a lamp shows when ringing.
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
 * Who pumps a stack's audio: `sipral_stack_config_t::audio`.
 *
 * Zero is application mode, so a configuration written against an
 * earlier header keeps pumping its own frames.
 */
typedef uint32_t sipral_audio_t;
enum {
    /**
     * The application opens the devices and pumps frames through
     * `sipral_media_capture` and `sipral_media_playback`.
     */
    SIPRAL_AUDIO_APPLICATION = 0,
    /**
     * The library opens the devices and pumps every managed call; the
     * packets reach the application through `audio_transmit_callback`.
     * `SIPRAL_STATUS_NOT_SUPPORTED` without a backend for the platform,
     * as `SIPRAL_FEATURE_AUDIO_DEVICE` says.
     */
    SIPRAL_AUDIO_DEVICE = 1,
};

/**
 * When the devices are opened, in device mode:
 * `sipral_stack_config_t::audio_activation`.
 */
typedef uint32_t sipral_audio_activation_t;
enum {
    /**
     * With the first managed call's media or ring; closed with the last.
     */
    SIPRAL_AUDIO_ACTIVATION_AUTOMATIC = 0,
    /**
     * Only between `sipral_audio_activate` and `sipral_audio_deactivate`:
     * for CallKit and the telecom framework, which own the audio session.
     */
    SIPRAL_AUDIO_ACTIVATION_MANUAL = 1,
};

/**
 * What a device is used for.
 */
typedef uint32_t sipral_audio_role_t;
enum {
    /**
     * The call's microphone.
     */
    SIPRAL_AUDIO_ROLE_MICROPHONE = 1,
    /**
     * The call's loudspeaker or earpiece.
     */
    SIPRAL_AUDIO_ROLE_SPEAKER = 2,
    /**
     * Where an incoming call is announced, which may differ from where
     * it is answered.
     */
    SIPRAL_AUDIO_ROLE_RINGER = 3,
};

/**
 * Which way audio flows, for gain, mute and the meter.
 */
typedef uint32_t sipral_audio_direction_t;
enum {
    /**
     * From the microphone. Its gain is the microphone gain.
     */
    SIPRAL_AUDIO_DIRECTION_INPUT = 1,
    /**
     * To the loudspeaker. Its gain is the volume.
     */
    SIPRAL_AUDIO_DIRECTION_OUTPUT = 2,
};

/**
 * What changed, on `SIPRAL_EVENT_KIND_AUDIO_DEVICES_CHANGED`.
 */
typedef uint32_t sipral_audio_change_t;
enum {
    /**
     * A device arrived or left. Every valid id stays valid: a device
     * that left keeps its row, marked absent.
     */
    SIPRAL_AUDIO_CHANGE_LIST_CHANGED = 1,
    /**
     * The system's default for `direction` moved. A role on a chosen
     * device stays; one on the system's route follows with
     * `SIPRAL_AUDIO_CHANGE_REOPENED`.
     */
    SIPRAL_AUDIO_CHANGE_DEFAULT_CHANGED = 2,
    /**
     * `role` is on `device` because `sipral_audio_select` said so.
     */
    SIPRAL_AUDIO_CHANGE_SELECTED = 3,
    /**
     * The device `role` ran on went away; the reopen is reported apart.
     */
    SIPRAL_AUDIO_CHANGE_LOST = 4,
    /**
     * `role` is running on `device` again.
     */
    SIPRAL_AUDIO_CHANGE_REOPENED = 5,
    /**
     * `role` could not be opened on anything; that direction is
     * silence until a device arrives.
     */
    SIPRAL_AUDIO_CHANGE_UNAVAILABLE = 6,
};

/**
 * Who made a change. An application must not answer either by
 * re-applying its own choice.
 */
typedef uint32_t sipral_audio_origin_t;
enum {
    /**
     * The operating system, or a person at a socket.
     */
    SIPRAL_AUDIO_ORIGIN_SYSTEM = 1,
    /**
     * The engine.
     */
    SIPRAL_AUDIO_ORIGIN_ENGINE = 2,
};

/**
 * The verdict a terminating network reached on the caller's number
 * (3GPP TS 24.229's `verstat`, the mark STIR/SHAKEN leaves). Names for
 * `sipral_call_event_t::verstat`.
 */
typedef uint32_t sipral_verstat_t;
enum {
    /**
     * Nothing said, or said by a peer the account does not trust.
     */
    SIPRAL_VERSTAT_NONE = 0,
    /**
     * `TN-Validation-Passed`.
     */
    SIPRAL_VERSTAT_PASSED = 1,
    /**
     * `TN-Validation-Failed`.
     */
    SIPRAL_VERSTAT_FAILED = 2,
    /**
     * `No-TN-Validation`.
     */
    SIPRAL_VERSTAT_NOT_VALIDATED = 3,
    /**
     * Some other value.
     */
    SIPRAL_VERSTAT_OTHER = 4,
};

/**
 * `Answer-Mode` and `Priv-Answer-Mode` (RFC 5373 §3). Names for
 * `sipral_call_event_t::answer_mode` and `priv_answer_mode`.
 */
typedef uint32_t sipral_answer_mode_t;
enum {
    /**
     * The INVITE carried no such field.
     */
    SIPRAL_ANSWER_MODE_NONE = 0,
    /**
     * `Manual`: wait for the user.
     */
    SIPRAL_ANSWER_MODE_MANUAL = 1,
    /**
     * `Auto`: answer without waiting for the user.
     */
    SIPRAL_ANSWER_MODE_AUTO = 2,
    /**
     * Any other value, which RFC 5373 has ignored.
     */
    SIPRAL_ANSWER_MODE_OTHER = 3,
};

/**
 * Where the ring says the caller is. Names for
 * `sipral_call_event_t::ring_source`.
 */
typedef uint32_t sipral_ring_source_t;
enum {
    /**
     * Nothing said.
     */
    SIPRAL_RING_SOURCE_UNKNOWN = 0,
    /**
     * Another extension of the same switch.
     */
    SIPRAL_RING_SOURCE_INTERNAL = 1,
    /**
     * The outside world.
     */
    SIPRAL_RING_SOURCE_EXTERNAL = 2,
};

/**
 * Which list, and which piece of each entry, sipral_call_identity_count
 * and sipral_call_identity_text are asked about.
 */
typedef uint32_t sipral_identity_text_t;
enum {
    /**
     * Never asked for.
     */
    SIPRAL_IDENTITY_TEXT_UNKNOWN = 0,
    /**
     * `P-Asserted-Identity`: the URI of each asserted party.
     */
    SIPRAL_IDENTITY_TEXT_ASSERTED = 1,
    /**
     * And each one's display name.
     */
    SIPRAL_IDENTITY_TEXT_ASSERTED_DISPLAY = 2,
    /**
     * `Remote-Party-ID`: the URI of each party named.
     */
    SIPRAL_IDENTITY_TEXT_REMOTE_PARTY = 3,
    /**
     * And each one's display name.
     */
    SIPRAL_IDENTITY_TEXT_REMOTE_PARTY_DISPLAY = 4,
    /**
     * `Diversion`, most recent first: who the call was diverted from.
     */
    SIPRAL_IDENTITY_TEXT_DIVERSION = 5,
    /**
     * And the display name beside it.
     */
    SIPRAL_IDENTITY_TEXT_DIVERSION_DISPLAY = 6,
    /**
     * And why: `no-answer`, `user-busy`, `unconditional` and the rest.
     */
    SIPRAL_IDENTITY_TEXT_DIVERSION_REASON = 7,
    /**
     * `History-Info`: the URI of each target the request was sent to.
     */
    SIPRAL_IDENTITY_TEXT_HISTORY = 8,
    /**
     * And each entry's `index`.
     */
    SIPRAL_IDENTITY_TEXT_HISTORY_INDEX = 9,
    /**
     * Every `Alert-Info` URI.
     */
    SIPRAL_IDENTITY_TEXT_ALERT_INFO = 10,
    /**
     * Every `info=` value on `Alert-Info`.
     */
    SIPRAL_IDENTITY_TEXT_ALERT_NAME = 11,
    /**
     * The canonical calling number a valid PASSporT was found for
     * (RFC 8224 §6.2): one entry, or none. ABI 0.31.
     */
    SIPRAL_IDENTITY_TEXT_VERIFIED_ORIG = 12,
    /**
     * Its origination identifier (RFC 8588 §5), a UUID.
     */
    SIPRAL_IDENTITY_TEXT_VERIFIED_ORIGID = 13,
    /**
     * The URL of the certificate it was verified against, or that could
     * not be had.
     */
    SIPRAL_IDENTITY_TEXT_VERIFICATION_CERTIFICATE = 14,
    /**
     * Why it did not verify, in words, for a log.
     */
    SIPRAL_IDENTITY_TEXT_VERIFICATION_DETAIL = 15,
};

/**
 * How an account's calls ask for a session timer (RFC 4028). Names for
 * `sipral_account_config_t::session_timer`.
 */
typedef uint32_t sipral_session_timer_t;
enum {
    /**
     * The stack's default: thirty minutes, RFC 4028 §4's recommendation.
     */
    SIPRAL_SESSION_TIMER_DEFAULT = 0,
    /**
     * Ask for none. A far end that insists on one is still honoured.
     */
    SIPRAL_SESSION_TIMER_OFF = 1,
    /**
     * Ask for `session_interval_seconds`, at least 90 (§5's floor).
     */
    SIPRAL_SESSION_TIMER_INTERVAL = 2,
};

/**
 * Log verbosity, for sipral_stack_log and sipral_log_record_t::level.
 * Each level includes the ones below it.
 */
typedef uint32_t sipral_log_level_t;
enum {
    /**
     * The log is off; the initial state.
     */
    SIPRAL_LOG_LEVEL_OFF = 0,
    /**
     * A failure the application is likely to notice.
     */
    SIPRAL_LOG_LEVEL_ERROR = 1,
    /**
     * Something worked around or about to matter: a registration
     * refused, audio that stopped arriving.
     */
    SIPRAL_LOG_LEVEL_WARN = 2,
    /**
     * Operator-level: registrations, calls arriving, confirmed or ending,
     * media starting.
     */
    SIPRAL_LOG_LEVEL_INFO = 3,
    /**
     * Every event raised, every diagnostic decision, every refused ABI call.
     */
    SIPRAL_LOG_LEVEL_DEBUG = 4,
    /**
     * Every SIP message in and out, whole and redacted.
     */
    SIPRAL_LOG_LEVEL_TRACE = 5,
};

/**
 * How a stream's SRTP keys were exchanged
 * (`sipral_stream_encryption_t::key_exchange`, `sipral_media_event_t::key_exchange`).
 */
typedef uint32_t sipral_key_exchange_t;
enum {
    /**
     * None: the stream is not encrypted, or the event is not about one.
     */
    SIPRAL_KEY_EXCHANGE_NONE = 0,
    /**
     * In the SDP (RFC 4568 `a=crypto`): as protected as the signalling.
     */
    SIPRAL_KEY_EXCHANGE_SDES = 1,
    /**
     * DTLS on the media path (RFC 5764), checked against the signalled
     * fingerprint.
     */
    SIPRAL_KEY_EXCHANGE_DTLS = 2,
};

/**
 * What a stream carries. Names for `sipral_stream_encryption_t::media`.
 */
typedef uint32_t sipral_media_kind_t;
enum {
    /**
     * Something this ABI has no word for.
     */
    SIPRAL_MEDIA_KIND_UNKNOWN = 0,
    /**
     * `m=audio`.
     */
    SIPRAL_MEDIA_KIND_AUDIO = 1,
};

/**
 * What an account does with incoming `Identity` header fields
 * (RFC 8224 §6.2). Values of `sipral_account_config_t::stir_verification`.
 */
typedef uint32_t sipral_stir_verification_t;
enum {
    /**
     * This build's default, which is `REPORT`.
     */
    SIPRAL_STIR_VERIFICATION_DEFAULT = 0,
    /**
     * Verify nothing.
     */
    SIPRAL_STIR_VERIFICATION_OFF = 1,
    /**
     * Verify, report the verdict, deliver every call. Active only once
     * the stack has trust anchors (`sipral_stack_stir`).
     */
    SIPRAL_STIR_VERIFICATION_REPORT = 2,
    /**
     * Verify and refuse what does not verify (RFC 8224 §6.2.2): 428 no
     * `Identity`, 436 certificate unavailable, 437 untrusted, 438 bad
     * signature, 403 "Stale Date". Active even with no anchors, where
     * nothing verifies.
     */
    SIPRAL_STIR_VERIFICATION_STRICT = 3,
};

/**
 * SHAKEN attestation level (RFC 8588 §4), for
 * `sipral_account_config_t::stir_attestation` and the verdict fields.
 */
typedef uint32_t sipral_attestation_t;
enum {
    /**
     * None said: on an account, full attestation; on a verdict, a
     * PASSporT with no SHAKEN claims, or no valid one.
     */
    SIPRAL_ATTESTATION_NONE = 0,
    /**
     * Full: the signer knows the caller and that the number is theirs.
     */
    SIPRAL_ATTESTATION_A = 1,
    /**
     * Partial: the signer knows the caller, not the number.
     */
    SIPRAL_ATTESTATION_B = 2,
    /**
     * Gateway: the signer knows only where the call entered its network.
     */
    SIPRAL_ATTESTATION_C = 3,
};

/**
 * What a verification came to (`sipral_verification_event_t::outcome`,
 * `sipral_call_event_t::verification`).
 */
typedef uint32_t sipral_verification_outcome_t;
enum {
    /**
     * Nothing verified: the account does not verify, or no anchors.
     */
    SIPRAL_VERIFICATION_OUTCOME_NONE = 0,
    /**
     * Signed by a certificate with authority over the calling number,
     * fresh, for the numbers the request names.
     */
    SIPRAL_VERIFICATION_OUTCOME_VALID = 1,
    /**
     * One was there and does not hold: `failure` says why.
     */
    SIPRAL_VERIFICATION_OUTCOME_INVALID = 2,
    /**
     * Nothing to verify: no `Identity`, or only unsupported extensions.
     */
    SIPRAL_VERIFICATION_OUTCOME_ABSENT = 3,
};

/**
 * Why a verification did not hold (`sipral_verification_event_t::failure`,
 * `sipral_call_event_t::verification_failure`).
 */
typedef uint32_t sipral_verification_failure_t;
enum {
    /**
     * Nothing failed.
     */
    SIPRAL_VERIFICATION_FAILURE_NONE = 0,
    /**
     * No `Identity` header field.
     */
    SIPRAL_VERIFICATION_FAILURE_NO_IDENTITY = 1,
    /**
     * Only ones naming a `ppt` this end does not support.
     */
    SIPRAL_VERIFICATION_FAILURE_UNSUPPORTED_PPT = 2,
    /**
     * The header field or its PASSporT is not well formed.
     */
    SIPRAL_VERIFICATION_FAILURE_MALFORMED = 3,
    /**
     * Signed with an algorithm other than ES256.
     */
    SIPRAL_VERIFICATION_FAILURE_UNSUPPORTED_ALGORITHM = 4,
    /**
     * `iat` outside the freshness window.
     */
    SIPRAL_VERIFICATION_FAILURE_STALE = 5,
    /**
     * The certificate could not be fetched, or did not arrive in time.
     */
    SIPRAL_VERIFICATION_FAILURE_CERTIFICATE_UNAVAILABLE = 6,
    /**
     * What the `info` URL yielded is not a chain this end can read.
     */
    SIPRAL_VERIFICATION_FAILURE_CERTIFICATE_UNREADABLE = 7,
    /**
     * The chain leads to no trust anchor.
     */
    SIPRAL_VERIFICATION_FAILURE_UNTRUSTED = 8,
    /**
     * A certificate in it is outside its validity period.
     */
    SIPRAL_VERIFICATION_FAILURE_EXPIRED = 9,
    /**
     * The chain breaks a rule of path validation.
     */
    SIPRAL_VERIFICATION_FAILURE_INVALID_CHAIN = 10,
    /**
     * The signature does not verify.
     */
    SIPRAL_VERIFICATION_FAILURE_BAD_SIGNATURE = 11,
    /**
     * The certificate has no authority over the calling number.
     */
    SIPRAL_VERIFICATION_FAILURE_NUMBER_NOT_COVERED = 12,
    /**
     * Signed for another calling number than the request names.
     */
    SIPRAL_VERIFICATION_FAILURE_ORIG_MISMATCH = 13,
    /**
     * Signed for another called number.
     */
    SIPRAL_VERIFICATION_FAILURE_DEST_MISMATCH = 14,
};

/**
 * Which half of a verification an event reports
 * (`sipral_verification_event_t::stage`).
 */
typedef uint32_t sipral_verification_stage_t;
enum {
    /**
     * Never sent.
     */
    SIPRAL_VERIFICATION_STAGE_UNKNOWN = 0,
    /**
     * Fetch the certificate at `certificate_url` and pass it to
     * `sipral_call_stir_certificate` (or nothing, if unavailable). The
     * call waits unannounced until then or `certificate_wait_ms`.
     */
    SIPRAL_VERIFICATION_STAGE_CERTIFICATE_WANTED = 1,
    /**
     * The verdict. `SIPRAL_EVENT_KIND_INCOMING_CALL` follows, or
     * `SIPRAL_EVENT_KIND_CALL_ENDED` when `refused` is set.
     */
    SIPRAL_VERIFICATION_STAGE_VERIFIED = 2,
};

/**
 * What a SIPRAL_EVENT_KIND_PROGRESS_DETECTED heard. Names for
 * `sipral_progress_event_t::what`.
 */
typedef uint32_t sipral_progress_kind_t;
enum {
    /**
     * Never written by this build.
     */
    SIPRAL_PROGRESS_KIND_UNKNOWN = 0,
    /**
     * A call-progress tone: `tone`, and `at_ms` when its first burst began.
     */
    SIPRAL_PROGRESS_KIND_TONE = 1,
    /**
     * The special information tone (the call failed): `sit_hz_*` and
     * `sit_ms_*` as measured, `at_ms` when the first began.
     */
    SIPRAL_PROGRESS_KIND_SPECIAL_INFORMATION = 2,
    /**
     * Who answered: `verdict`, `reason`, `at_ms` after answer,
     * `initial_silence_ms`, `greeting_ms` and `words`.
     */
    SIPRAL_PROGRESS_KIND_ANSWERED_BY = 3,
    /**
     * A machine's record beep: `frequency_hz`, `length_ms`, and `at_ms`
     * when it ended, after answer.
     */
    SIPRAL_PROGRESS_KIND_BEEP = 4,
};

/**
 * A call-progress tone. Names for `sipral_progress_event_t::tone`.
 */
typedef uint32_t sipral_progress_tone_t;
enum {
    /**
     * Not a tone, or one this build has no name for.
     */
    SIPRAL_PROGRESS_TONE_UNKNOWN = 0,
    /**
     * The exchange is ready for digits.
     */
    SIPRAL_PROGRESS_TONE_DIAL = 1,
    /**
     * The far end is being alerted.
     */
    SIPRAL_PROGRESS_TONE_RINGBACK = 2,
    /**
     * The far end is busy.
     */
    SIPRAL_PROGRESS_TONE_BUSY = 3,
    /**
     * The network is congested: congestion, or reorder.
     */
    SIPRAL_PROGRESS_TONE_CONGESTION = 4,
    /**
     * A second call is waiting.
     */
    SIPRAL_PROGRESS_TONE_CALL_WAITING = 5,
    /**
     * The special information tone.
     */
    SIPRAL_PROGRESS_TONE_SPECIAL_INFORMATION = 6,
};

/**
 * Who answered. Names for `sipral_progress_event_t::verdict`.
 */
typedef uint32_t sipral_amd_verdict_t;
enum {
    /**
     * Not a verdict.
     */
    SIPRAL_AMD_VERDICT_UNKNOWN = 0,
    /**
     * A person.
     */
    SIPRAL_AMD_VERDICT_HUMAN = 1,
    /**
     * An answering machine or a voice mailbox.
     */
    SIPRAL_AMD_VERDICT_MACHINE = 2,
    /**
     * The evidence does not say.
     */
    SIPRAL_AMD_VERDICT_NOT_SURE = 3,
};

/**
 * Which rule decided who answered. Names for
 * `sipral_progress_event_t::reason`.
 */
typedef uint32_t sipral_amd_reason_t;
enum {
    /**
     * Not a verdict.
     */
    SIPRAL_AMD_REASON_NONE = 0,
    /**
     * A short greeting, then silence: somebody said hello and waits.
     */
    SIPRAL_AMD_REASON_SHORT_GREETING = 1,
    /**
     * More words than a person answers with.
     */
    SIPRAL_AMD_REASON_TOO_MANY_WORDS = 2,
    /**
     * A greeting longer than a person gives.
     */
    SIPRAL_AMD_REASON_LONG_GREETING = 3,
    /**
     * Nobody spoke.
     */
    SIPRAL_AMD_REASON_INITIAL_SILENCE = 4,
    /**
     * No rule decided in the time allowed.
     */
    SIPRAL_AMD_REASON_TIMEOUT = 5,
};

/**
 * When a call listens for keypad digits in the far end's audio. Names
 * for `sipral_stack_config_t::dtmf_detection` and
 * sipral_call_dtmf_detection's `mode`.
 */
typedef uint32_t sipral_dtmf_detection_t;
enum {
    /**
     * Only when no telephone event was negotiated, since the far end
     * then has no other way to send a digit.
     */
    SIPRAL_DTMF_DETECTION_AUTO = 0,
    /**
     * Never. Digits arrive only as RFC 4733 events or by INFO.
     */
    SIPRAL_DTMF_DETECTION_OFF = 1,
    /**
     * On every call. A press the far end sends both as an event and in
     * the audio is reported once, as the event.
     */
    SIPRAL_DTMF_DETECTION_ALWAYS = 2,
};

/**
 * Whose call-progress tones to listen for. Names for
 * `sipral_progress_config_t::region`.
 */
typedef uint32_t sipral_tone_region_t;
enum {
    /**
     * The 425 Hz tones common to the CEPT administrations.
     */
    SIPRAL_TONE_REGION_EUROPE = 0,
    /**
     * The United States and Canada.
     */
    SIPRAL_TONE_REGION_NORTH_AMERICA = 1,
    /**
     * The United Kingdom.
     */
    SIPRAL_TONE_REGION_UNITED_KINGDOM = 2,
};

/**
 * The file format of a recording. Names for
 * `sipral_recording_options_t::format`.
 */
typedef uint32_t sipral_recording_format_t;
enum {
    /**
     * Sixteen-bit PCM in RIFF/WAVE, becoming RF64 past four gibibytes.
     */
    SIPRAL_RECORDING_FORMAT_WAV = 0,
    /**
     * Opus in Ogg (RFC 7845), where `SIPRAL_FEATURE_OPUS` says the build
     * has the encoder; `SIPRAL_STATUS_NOT_SUPPORTED` where it does not.
     */
    SIPRAL_RECORDING_FORMAT_OGG_OPUS = 1,
};

/**
 * How the two directions of a call share a recording. Names for
 * `sipral_recording_options_t::layout`.
 */
typedef uint32_t sipral_recording_layout_t;
enum {
    /**
     * One channel: both directions, each at half level, summed.
     */
    SIPRAL_RECORDING_LAYOUT_MIXED = 0,
    /**
     * Two channels: this end on the left, the far end on the right.
     */
    SIPRAL_RECORDING_LAYOUT_STEREO = 1,
};

/**
 * What one conference document did. Names for
 * `sipral_conference_event_t::update`.
 */
typedef uint32_t sipral_conference_update_t;
enum {
    /**
     * Never written by this build.
     */
    SIPRAL_CONFERENCE_UPDATE_UNKNOWN = 0,
    /**
     * It was merged into the picture.
     */
    SIPRAL_CONFERENCE_UPDATE_APPLIED = 1,
    /**
     * Deleted by the focus; the subscription ends (RFC 4575 §4.6).
     */
    SIPRAL_CONFERENCE_UPDATE_ENDED = 2,
};

/**
 * Where one endpoint of a conference is (RFC 4575 §5.7.2). Names for
 * `sipral_conference_user_t::status`.
 */
typedef uint32_t sipral_endpoint_status_t;
enum {
    /**
     * Absent or not in the schema.
     */
    SIPRAL_ENDPOINT_STATUS_UNKNOWN = 0,
    /**
     * `pending`: waiting for policy or for the focus.
     */
    SIPRAL_ENDPOINT_STATUS_PENDING = 1,
    /**
     * `dialing-out`: the focus is calling it.
     */
    SIPRAL_ENDPOINT_STATUS_DIALING_OUT = 2,
    /**
     * `dialing-in`: it is calling the focus.
     */
    SIPRAL_ENDPOINT_STATUS_DIALING_IN = 3,
    /**
     * `alerting`: it is ringing.
     */
    SIPRAL_ENDPOINT_STATUS_ALERTING = 4,
    /**
     * `on-hold`.
     */
    SIPRAL_ENDPOINT_STATUS_ON_HOLD = 5,
    /**
     * `connected`: it is in the conference.
     */
    SIPRAL_ENDPOINT_STATUS_CONNECTED = 6,
    /**
     * `muted-via-focus`: in, and muted by the focus.
     */
    SIPRAL_ENDPOINT_STATUS_MUTED_VIA_FOCUS = 7,
    /**
     * `disconnecting`.
     */
    SIPRAL_ENDPOINT_STATUS_DISCONNECTING = 8,
    /**
     * `disconnected`: it has left.
     */
    SIPRAL_ENDPOINT_STATUS_DISCONNECTED = 9,
};

/**
 * Which text sipral_subscription_conference_text reads, as the focus
 * wrote it. The first three ignore `index`; the rest are about that user.
 */
typedef uint32_t sipral_conference_text_t;
enum {
    /**
     * Never asked for.
     */
    SIPRAL_CONFERENCE_TEXT_UNKNOWN = 0,
    /**
     * The conference's URI, the `entity` of `conference-info`.
     */
    SIPRAL_CONFERENCE_TEXT_ENTITY = 1,
    /**
     * Its `subject`.
     */
    SIPRAL_CONFERENCE_TEXT_SUBJECT = 2,
    /**
     * Its `display-text`.
     */
    SIPRAL_CONFERENCE_TEXT_DISPLAY_TEXT = 3,
    /**
     * A user's `entity`: the address of record it takes part as.
     */
    SIPRAL_CONFERENCE_TEXT_USER_ENTITY = 4,
    /**
     * A user's `display-text`.
     */
    SIPRAL_CONFERENCE_TEXT_USER_DISPLAY_TEXT = 5,
    /**
     * The `entity` of a user's first endpoint: the device it is on.
     */
    SIPRAL_CONFERENCE_TEXT_USER_ENDPOINT = 6,
};

/**
 * What a SIPRAL_EVENT_KIND_PRESENCE_CHANGED is about.
 * Names for `sipral_presence_event_t::kind`.
 */
typedef uint32_t sipral_presence_kind_t;
enum {
    /**
     * Never written by this build.
     */
    SIPRAL_PRESENCE_KIND_UNKNOWN = 0,
    /**
     * A `presence` subscription was told about the presentity.
     */
    SIPRAL_PRESENCE_KIND_WATCHED = 1,
    /**
     * This account's own published presence moved.
     */
    SIPRAL_PRESENCE_KIND_PUBLICATION = 2,
};

/**
 * PIDF's `basic` (RFC 3863 §4.1.4). Names for `sipral_presence_t::basic`
 * and `sipral_presence_event_t::basic`.
 */
typedef uint32_t sipral_basic_t;
enum {
    /**
     * Not said. A document published with this is refused, since
     * §4.1.3 wants one.
     */
    SIPRAL_BASIC_UNKNOWN = 0,
    /**
     * Reachable.
     */
    SIPRAL_BASIC_OPEN = 1,
    /**
     * Not reachable.
     */
    SIPRAL_BASIC_CLOSED = 2,
};

/**
 * What the person behind a presentity is doing: the RPID activities
 * (RFC 4480 §3.2) phones show. Names for `sipral_presence_t::activity`
 * and `sipral_presence_event_t::activity`.
 */
typedef uint32_t sipral_activity_t;
enum {
    /**
     * None said. Published, the document carries no person at all.
     */
    SIPRAL_ACTIVITY_NONE = 0,
    /**
     * `away`.
     */
    SIPRAL_ACTIVITY_AWAY = 1,
    /**
     * `busy`.
     */
    SIPRAL_ACTIVITY_BUSY = 2,
    /**
     * `on-the-phone`.
     */
    SIPRAL_ACTIVITY_ON_THE_PHONE = 3,
    /**
     * `meeting`.
     */
    SIPRAL_ACTIVITY_MEETING = 4,
    /**
     * `vacation`.
     */
    SIPRAL_ACTIVITY_VACATION = 5,
    /**
     * Another activity, which this ABI has no number for.
     */
    SIPRAL_ACTIVITY_OTHER = 6,
};

/**
 * What became of this account's published presence. Names for
 * `sipral_presence_event_t::publication_state`.
 */
typedef uint32_t sipral_publication_state_t;
enum {
    /**
     * Not a publication event.
     */
    SIPRAL_PUBLICATION_STATE_UNKNOWN = 0,
    /**
     * The compositor holds it: published, modified or refreshed.
     */
    SIPRAL_PUBLICATION_STATE_PUBLISHED = 1,
    /**
     * It was taken away (`sipral_account_unpublish_presence`).
     */
    SIPRAL_PUBLICATION_STATE_REMOVED = 2,
    /**
     * Its lifetime ran out with no refresh; the next publish starts it
     * afresh.
     */
    SIPRAL_PUBLICATION_STATE_EXPIRED = 3,
    /**
     * The compositor refused, or never answered.
     */
    SIPRAL_PUBLICATION_STATE_FAILED = 4,
};

/**
 * Why a publication failed. Names for `sipral_presence_event_t::failure`.
 */
typedef uint32_t sipral_publish_failure_t;
enum {
    /**
     * Nothing failed.
     */
    SIPRAL_PUBLISH_FAILURE_NONE = 0,
    /**
     * 489: the compositor does not know the `presence` package. Nothing
     * more is sent.
     */
    SIPRAL_PUBLISH_FAILURE_BAD_EVENT = 1,
    /**
     * 423 with no `Min-Expires` this stack could meet.
     */
    SIPRAL_PUBLISH_FAILURE_INTERVAL_TOO_BRIEF = 2,
    /**
     * A 2xx without the `SIP-ETag` every one must carry.
     */
    SIPRAL_PUBLISH_FAILURE_NO_ENTITY_TAG = 3,
    /**
     * Any other refusal, a challenge nothing could answer among them;
     * `status_code` says which.
     */
    SIPRAL_PUBLISH_FAILURE_REFUSED = 4,
    /**
     * No answer at all.
     */
    SIPRAL_PUBLISH_FAILURE_UNREACHABLE = 5,
};

/**
 * What a `SIPRAL_EVENT_KIND_LOCAL_CONFERENCE_CHANGED` reports
 * (`sipral_local_conference_event_t::change`).
 */
typedef uint32_t sipral_local_conference_change_t;
enum {
    /**
     * Never written by this build.
     */
    SIPRAL_LOCAL_CONFERENCE_CHANGE_UNKNOWN = 0,
    /**
     * `member` joined (a call, or this end at creation).
     */
    SIPRAL_LOCAL_CONFERENCE_CHANGE_JOINED = 1,
    /**
     * `member` left, for the reason `departure` gives.
     */
    SIPRAL_LOCAL_CONFERENCE_CHANGE_LEFT = 2,
    /**
     * The talkers changed: see `talkers`, `loudest` and
     * `sipral_local_conference_talker_at`.
     */
    SIPRAL_LOCAL_CONFERENCE_CHANGE_TALKERS = 3,
    /**
     * The recording stopped because the file refused a write; it holds
     * audio up to its last checkpoint.
     */
    SIPRAL_LOCAL_CONFERENCE_CHANGE_RECORDING_STOPPED = 4,
};

/**
 * Why a member left (`sipral_local_conference_event_t::departure`).
 */
typedef uint32_t sipral_departure_t;
enum {
    /**
     * Nobody left.
     */
    SIPRAL_DEPARTURE_NONE = 0,
    /**
     * `sipral_local_conference_remove` took it out.
     */
    SIPRAL_DEPARTURE_REMOVED = 1,
    /**
     * Its call's media ended.
     */
    SIPRAL_DEPARTURE_ENDED = 2,
    /**
     * Its call moved to a codec the conference cannot mix.
     */
    SIPRAL_DEPARTURE_INCOMPATIBLE = 3,
};

/**
 * Which kind of DNS record a lookup asks for. Names for
 * `sipral_locate_event_t::record` and `sipral_account_looked_up`'s
 * `record`.
 */
typedef uint32_t sipral_dns_record_type_t;
enum {
    /**
     * Not a lookup: the value on a `SIPRAL_EVENT_KIND_LOCATED` or a
     * `SIPRAL_EVENT_KIND_LOCATE_FAILED`.
     */
    SIPRAL_DNS_RECORD_TYPE_NONE = 0,
    /**
     * RFC 3403: which services a domain offers, and under which names.
     */
    SIPRAL_DNS_RECORD_TYPE_NAPTR = 1,
    /**
     * RFC 2782: which hosts, at which ports, serve one service.
     */
    SIPRAL_DNS_RECORD_TYPE_SRV = 2,
    /**
     * An IPv4 address.
     */
    SIPRAL_DNS_RECORD_TYPE_A = 3,
    /**
     * An IPv6 address.
     */
    SIPRAL_DNS_RECORD_TYPE_AAAA = 4,
};

/**
 * What the application's resolver said to a lookup. Names for
 * `sipral_account_looked_up`'s `answer`.
 */
typedef uint32_t sipral_dns_answer_t;
enum {
    /**
     * The records it returned, in `records`. None at all reads as
     * `SIPRAL_DNS_ANSWER_NOTHING`.
     */
    SIPRAL_DNS_ANSWER_RECORDS = 1,
    /**
     * No record of that kind, or no such name. Also the answer from a
     * resolver that cannot ask for that kind (NAPTR, SRV).
     */
    SIPRAL_DNS_ANSWER_NOTHING = 2,
    /**
     * The resolver could not answer: no server reachable, a timeout, a
     * server failure.
     */
    SIPRAL_DNS_ANSWER_FAILED = 3,
};

/**
 * Why a lookup of an account's server named no address. Names for
 * `sipral_locate_event_t::failure`.
 */
typedef uint32_t sipral_locate_failure_t;
enum {
    /**
     * Nothing failed.
     */
    SIPRAL_LOCATE_FAILURE_NONE = 0,
    /**
     * The DNS named no reachable address: no record, or an SRV target
     * of `.`.
     */
    SIPRAL_LOCATE_FAILURE_NOT_FOUND = 1,
    /**
     * The resolver failed on every lookup that could give an address.
     */
    SIPRAL_LOCATE_FAILURE_UNANSWERED = 2,
    /**
     * The transport has no RFC 3263 procedure (WebSocket); only a
     * numeric host or a host with a port works.
     */
    SIPRAL_LOCATE_FAILURE_UNSUPPORTED = 3,
};

/**
 * Why an account's password did not answer a challenge. Names for
 * `sipral_challenge_event_t::refusal`.
 */
typedef uint32_t sipral_challenge_refusal_t;
enum {
    /**
     * Never written by this build.
     */
    SIPRAL_CHALLENGE_REFUSAL_UNKNOWN = 0,
    /**
     * The challenge came from beyond the account's own server.
     */
    SIPRAL_CHALLENGE_REFUSAL_NOT_THE_ACCOUNTS_SERVER = 1,
    /**
     * The account's server asked for a realm not the account's (e.g. a
     * proxy relaying a far end's challenge).
     */
    SIPRAL_CHALLENGE_REFUSAL_NOT_THE_ACCOUNTS_REALM = 2,
};

/**
 * What the server said was wrong with the token (RFC 6750 §3.1).
 */
typedef uint32_t sipral_token_error_t;
enum {
    /**
     * The server named no error: no token was offered yet.
     */
    SIPRAL_TOKEN_ERROR_NONE = 0,
    /**
     * `invalid_request`: the request was malformed.
     */
    SIPRAL_TOKEN_ERROR_INVALID_REQUEST = 1,
    /**
     * `invalid_token`: the token is expired, revoked, malformed or
     * otherwise invalid. A new one is needed.
     */
    SIPRAL_TOKEN_ERROR_INVALID_TOKEN = 2,
    /**
     * `insufficient_scope`: the token does not cover what was asked;
     * `scope` says what would.
     */
    SIPRAL_TOKEN_ERROR_INSUFFICIENT_SCOPE = 3,
    /**
     * `invalid_scope`.
     */
    SIPRAL_TOKEN_ERROR_INVALID_SCOPE = 4,
    /**
     * Another code, as written in `error_code`.
     */
    SIPRAL_TOKEN_ERROR_OTHER = 5,
};

/**
 * What a network test, or one part of it, comes to. Names for
 * `sipral_network_test_event_t::verdict` and `echo_verdict`.
 */
typedef uint32_t sipral_network_verdict_t;
enum {
    /**
     * Nothing was tested.
     */
    SIPRAL_NETWORK_VERDICT_UNKNOWN = 0,
    /**
     * Calls should work and sound right.
     */
    SIPRAL_NETWORK_VERDICT_GOOD = 1,
    /**
     * Calls should work, perhaps not everywhere or at best quality.
     */
    SIPRAL_NETWORK_VERDICT_ACCEPTABLE = 2,
    /**
     * Calls are likely to fail or to sound bad.
     */
    SIPRAL_NETWORK_VERDICT_POOR = 3,
};

/**
 * Whether a part of a network test was tried, and how it went. Names
 * for `sipral_network_test_event_t::stun`, `turn` and `echo`.
 */
typedef uint32_t sipral_network_probe_t;
enum {
    /**
     * Not part of this test.
     */
    SIPRAL_NETWORK_PROBE_NOT_TESTED = 0,
    /**
     * The server answered; for the echo, audio came back and was measured.
     */
    SIPRAL_NETWORK_PROBE_SUCCEEDED = 1,
    /**
     * It did not.
     */
    SIPRAL_NETWORK_PROBE_FAILED = 2,
};

/**
 * What a STUN answer says about the NAT in front of this end. Names for
 * `sipral_network_test_event_t::nat`. Approximate: says nothing about
 * filtering (RFC 4787).
 */
typedef uint32_t sipral_nat_kind_t;
enum {
    /**
     * No answer to read.
     */
    SIPRAL_NAT_KIND_UNKNOWN = 0,
    /**
     * No translation: the server saw the socket's own address.
     */
    SIPRAL_NAT_KIND_OPEN = 1,
    /**
     * The address was translated and the port kept.
     */
    SIPRAL_NAT_KIND_PORT_PRESERVED = 2,
    /**
     * The port was changed too.
     */
    SIPRAL_NAT_KIND_PORT_CHANGED = 3,
};

/**
 * What the account's server did with the test's `OPTIONS`. Names for
 * `sipral_network_test_event_t::server`.
 */
typedef uint32_t sipral_server_reach_t;
enum {
    /**
     * Not part of this test.
     */
    SIPRAL_SERVER_REACH_NOT_TESTED = 0,
    /**
     * Any final answer; see `server_status` and `server_round_trip_ms`.
     */
    SIPRAL_SERVER_REACH_ANSWERED = 1,
    /**
     * No answer before the request, or the test, timed out.
     */
    SIPRAL_SERVER_REACH_TIMED_OUT = 2,
    /**
     * The transport refused the request or failed under it.
     */
    SIPRAL_SERVER_REACH_TRANSPORT_FAILED = 3,
};

/**
 * What a held party is sent: `sipral_stack_config_t::held_audio`.
 */
typedef uint32_t sipral_held_audio_t;
enum {
    /**
     * Silence, in either mode.
     */
    SIPRAL_HELD_AUDIO_DEFAULT = 0,
    /**
     * Silence.
     */
    SIPRAL_HELD_AUDIO_SILENCE = 1,
    /**
     * The frames the application hands over, as they are.
     */
    SIPRAL_HELD_AUDIO_APPLICATION = 2,
};

/**
 * The one callback a stack has.
 *
 * Called inside `sipral_stack_poll` on its thread, never concurrently
 * for one stack. Must not unwind. May call back into the library
 * (`docs/08-ffi.md`, "The shape").
 */
typedef void (*sipral_event_callback_t)(const sipral_event_t *event, void *user_data);

/**
 * The screening policy: called once per INVITE, before it has any
 * effect. Installed with sipral_stack_screen.
 *
 * **It runs with the stack's lock held** (see the module docs), unlike
 * sipral_event_callback_t. **It must
 * not call back into the stack it was given**, from any thread; such a
 * call is answered `SIPRAL_STATUS_BUSY`. Another stack is fine. It must
 * not unwind across the boundary.
 *
 * `request` and what it points at are valid for this call only.
 *
 * **The answer is a SIP status code.** `SIPRAL_SCREEN_ACCEPT` (200) lets
 * the INVITE through as if no policy were installed. 400 to 699 refuses
 * with that status. Anything else refuses with 500: zero (a listener that
 * threw), a 1xx (would leave the transaction open), another 2xx, or a 3xx
 * (no `Contact` to redirect to).
 */
typedef uint32_t (*sipral_screen_callback_t)(const sipral_screen_request_t *request, void *user_data);

/**
 * Echo cancellation, gain control or noise suppression, run over one
 * frame, or told to forget what it has learned — sipral_processor_frame_t
 * says which. Installed with sipral_media_attach_processor.
 *
 * **It runs with this call's media locked** (see
 * sipral_media_attach_processor): it must not call into the media
 * handle it was attached through, on any thread, and must not unwind.
 *
 * `frame` and what it points at are library-owned, valid only during the
 * call.
 */
typedef void (*sipral_processor_callback_t)(const sipral_processor_frame_t *frame, void *user_data);

/**
 * Where the packets the engine encodes go: the application's, called
 * on the engine's thread with one `sipral_audio_transmit_t` per packet.
 */
typedef void (*sipral_audio_transmit_callback_t)(const sipral_audio_transmit_t *transmit, void *user_data);

/**
 * Where a stack's log lines go. Installed with
 * sipral_stack_log.
 *
 * Called on the thread that just finished a call into this stack, with
 * nothing held, so it may call back into the library. One line at a
 * time, never on two threads at once. It must not unwind.
 *
 * `record` and what it points at are valid for this call only.
 */
typedef void (*sipral_log_callback_t)(const sipral_log_record_t *record, void *user_data);

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
    /**
     * Zero. Pads to alignment so later members never land in padding.
     */
    uint32_t reserved;
};

/**
 * What this build can do: codecs, signalling transports, optional features.
 *
 * Not configuration: `sipral_stack_settings` answers what a stack has on.
 *
 * Set `size` to `sizeof(sipral_capabilities_t)` before the call.
 */
struct sipral_capabilities {
    /**
     * How many bytes of this struct the library filled in.
     */
    size_t size;
    /**
     * How many codecs this build contains (same as `sipral_codec_count`).
     */
    size_t codec_count;
    /**
     * Transports for signalling, as `SIPRAL_TRANSPORT_BIT_*` bits.
     */
    uint32_t transports;
    /**
     * Compiled-in features, as `SIPRAL_FEATURE_*` bits.
     */
    uint32_t features;
};

/**
 * D3's flat set of health counters for one stack, since it was created.
 * All monotonic except the gauge `active_calls`. Set `size` to
 * `sizeof(sipral_counters_t)` before the call.
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
     * Inbound audio stopped past the threshold while signalling was fine (B5).
     */
    uint64_t media_gaps;
    /**
     * Jitter buffer shrink or stretch adjustments.
     */
    uint64_t jitter_buffer_events;
    /**
     * A request too big for a datagram with no stream to its destination,
     * so one was requested (RFC 3261 §18.1.1, B1). Reuse of an existing
     * connection does not count.
     */
    uint64_t stream_transport_wanted;
    /**
     * Calls with media running now; the only gauge.
     */
    uint64_t active_calls;
    /**
     * Events dropped because the outbox was at its ceiling (task 8.4.21).
     */
    uint64_t events_dropped;
    /**
     * RTCP goodbyes dropped, oldest first, because
     * `sipral_stack_poll_farewell` was not keeping up.
     */
    uint64_t farewells_dropped;
    /**
     * INVITEs a `sipral_stack_screen` policy refused (A8, D7).
     */
    uint64_t screened_refused_by_policy;
    /**
     * INVITEs refused for exceeding `sipral_stack_invite_limit`.
     */
    uint64_t screened_refused_by_rate;
    /**
     * INVITEs refused because every tracked-source seat was taken: a
     * flood from many addresses.
     */
    uint64_t screened_refused_by_crowding;
    /**
     * INVITEs refused 403 for an unauthorised Replaces (RFC 3891 §3).
     */
    uint64_t screened_refused_by_replaces;
    /**
     * Requests resent by RFC 3261 timers A and E, plus ACKs resent for a
     * repeated 2xx. UDP only; a rising value means packet loss.
     */
    uint64_t requests_retransmitted;
    /**
     * Responses resent: timer G, reliable provisional timer, and repeats
     * for a retransmitted request.
     */
    uint64_t responses_retransmitted;
    /**
     * Transactions ended by timers B, F, H and L, or an unPRACKed
     * reliable provisional response.
     */
    uint64_t transactions_timed_out;
    /**
     * Requests answered `503` because the stack was at
     * `max_server_transactions`, or an INVITE was at `max_dialogs`.
     */
    uint64_t requests_refused_at_limit;
};

/**
 * What a stack is created with. Set `size` to `sizeof(sipral_stack_config_t)`
 * and zero the rest first. Required: the callback, the transport, the reachable
 * address, the entropy, and a media seed different from the entropy.
 */
struct sipral_stack_config {
    /**
     * `sizeof` this struct, as the caller's header declares it.
     */
    size_t size;
    /**
     * Where events go. Required.
     */
    sipral_event_callback_t event_callback;
    /**
     * Handed back to the callback untouched. The library never reads it.
     */
    void *event_user_data;
    /**
     * A sipral_transport_t.
     */
    sipral_transport_t transport;
    /**
     * The address the far end reaches this one at, as `host:port`, UTF-8 and
     * not NUL-terminated. It goes in every `Via`.
     */
    const char *bind_address;
    /**
     * How many bytes of it.
     */
    size_t bind_address_len;
    /**
     * `User-Agent` for every REGISTER and INVITE this stack originates, or null
     * for none (optional per §20 Table 3).
     */
    const char *user_agent;
    /**
     * How many bytes of it.
     */
    size_t user_agent_len;
    /**
     * Thirty-two bytes from the platform's generator. Every branch, tag and
     * `Call-ID` derives from it, and §19.3 wants a tag unguessable. Never
     * shared between stacks. Media keys come from `media_seed`.
     */
    const uint8_t *entropy;
    /**
     * How many bytes of it. Thirty-two.
     */
    size_t entropy_len;
    /**
     * T1 in milliseconds, or zero for the 500 ms of §17.1.1.1.
     */
    uint64_t timer_t1_ms;
    /**
     * T2 in milliseconds, or zero for four seconds. UDP only; set on another
     * transport it is `SIPRAL_STATUS_INVALID_ARGUMENT`.
     */
    uint64_t timer_t2_ms;
    /**
     * T4 in milliseconds, or zero for five seconds. UDP only, like T2.
     */
    uint64_t timer_t4_ms;
    /**
     * The codecs to offer, in order (A4, RFC 3264 §6.1): comma-separated names,
     * UTF-8, not NUL-terminated; null for every codec built in. An unknown name is
     * `SIPRAL_STATUS_NOT_SUPPORTED`, with the known names in the last error.
     */
    const char *codecs;
    /**
     * How many bytes of it.
     */
    size_t codecs_len;
    /**
     * Frame length in milliseconds, or zero for twenty. Must suit Opus if offered.
     */
    uint32_t frame_ms;
    /**
     * Whether to offer RFC 4733 named events, as a `sipral_toggle_t`. On by default.
     */
    sipral_toggle_t offer_dtmf;
    /**
     * Whether to ask for RFC 5761 multiplexing (§5.1.1), as a `sipral_toggle_t`.
     * Off by default.
     */
    sipral_toggle_t offer_rtcp_mux;
    /**
     * Whether to stop sending during silence, as a `sipral_toggle_t`. Off by
     * default: with no comfort noise, the gap looks like a dead stream.
     */
    sipral_toggle_t silence_suppression;
    /**
     * Whether inbound audio that stops is reported (B5), as a `sipral_toggle_t`.
     * On by default.
     */
    sipral_toggle_t media_stall_watchdog;
    /**
     * How long inbound audio may stop before it is reported, in milliseconds,
     * or zero for the default. Refused with the watchdog off.
     */
    uint64_t media_stall_ms;
    /**
     * The wall clock at creation, in seconds since the Unix epoch, for RFC 3550
     * §6.4.1 sender reports; zero to wait for `sipral_stack_stir`'s `unix_seconds`.
     */
    uint64_t media_clock_unix_seconds;
    /**
     * Thirty-two more bytes for the media keys, **not the same bytes as
     * `entropy`**, which recordings write in clear. The same bytes are refused.
     */
    const uint8_t *media_seed;
    /**
     * How many bytes of it. Thirty-two.
     */
    size_t media_seed_len;
    /**
     * Default SRTP for every call: a `sipral_srtp_t`, or zero for
     * `SIPRAL_SRTP_NOT_OFFERED`. `sipral_call_config_t::srtp` overrides it.
     */
    sipral_srtp_t srtp;
    /**
     * Default ICE for every call: a `sipral_ice_t`, or zero for `SIPRAL_ICE_OFF`
     * (`docs/06-nat.md`). `sipral_call_config_t::ice` overrides it.
     */
    sipral_ice_t ice;
    /**
     * A `sipral_nat_t`, or zero for `SIPRAL_NAT_OFF`. `SIPRAL_NAT_STUN` asks
     * `stun_server` where each socket appears from (`docs/06-nat.md`).
     */
    sipral_nat_t nat;
    /**
     * The STUN server, as a `host:port` address. Required with and only with
     * `SIPRAL_NAT_STUN`. Copied.
     */
    const char *stun_server;
    /**
     * How many bytes of it.
     */
    size_t stun_server_len;
    /**
     * Whether G.729 Annex B is allowed, as a `sipral_toggle_t`. On by default (RFC
     * 4856 §2.1.9); off, SDP says `annexb=no` (RFC 3551 §4.5.6).
     */
    sipral_toggle_t g729_annex_b;
    /**
     * A TURN server (RFC 8656), as `host:port`, to relay every media socket
     * `sipral_stack_nat_map` names (`docs/06-nat.md`). Only with `SIPRAL_NAT_STUN`,
     * needs `turn_username` and `turn_password`, and `SIPRAL_FEATURE_ICE`. Copied.
     */
    const char *turn_server;
    /**
     * How many bytes of it.
     */
    size_t turn_server_len;
    /**
     * The TURN long-term credential's user name (RFC 8489 §9.2).
     */
    const char *turn_username;
    /**
     * How many bytes of it.
     */
    size_t turn_username_len;
    /**
     * Its password. Copied, wiped at destroy, never logged.
     */
    const char *turn_password;
    /**
     * How many bytes of it.
     */
    size_t turn_password_len;
    /**
     * Whether an out-of-dialog REFER (RFC 3515 §4.1) reaches the application, as
     * a `sipral_toggle_t`. **Off by default**: each is refused 403, since an
     * unauthenticated peer could make the phone dial anywhere. On, each is raised
     * as `SIPRAL_EVENT_KIND_REFERRAL`.
     */
    sipral_toggle_t referrals;
    /**
     * Whether an account behind a NAT sends a double CRLF to its registrar every
     * `registrar_keepalive_ms` over UDP, as a `sipral_toggle_t`. **On by default.**
     * Without it an address-and-port filtering NAT (RFC 4787 §5) drops a later
     * INVITE; registrars ignore it (RFC 3261 §7.5). See `docs/06-nat.md`.
     */
    sipral_toggle_t registrar_keepalive;
    /**
     * Keep-alive interval in milliseconds, or zero for 25 s (RFC 5626 §4.4.2),
     * jittered to 80-100%. From 1 000 to 120 000 (RFC 4787 REQ-5), and only with
     * `registrar_keepalive` on.
     */
    uint64_t registrar_keepalive_ms;
    /**
     * How media sockets reach `turn_server`, as a `sipral_transport_t`: UDP (or
     * zero), TCP, or TLS (RFC 8656 §4.1). Over TCP or TLS the application opens a
     * connection when `SIPRAL_EVENT_KIND_TURN_STREAM` asks.
     */
    sipral_transport_t turn_transport;
    /**
     * Who pumps audio, as a `sipral_audio_t`: zero or `SIPRAL_AUDIO_APPLICATION`
     * for the application; `SIPRAL_AUDIO_DEVICE` for the library, which needs
     * `audio_transmit_callback` and `SIPRAL_FEATURE_AUDIO_DEVICE`.
     */
    sipral_audio_t audio;
    /**
     * When devices open in device mode: a `sipral_audio_activation_t`, or zero for
     * `SIPRAL_AUDIO_ACTIVATION_AUTOMATIC`.
     */
    sipral_audio_activation_t audio_activation;
    /**
     * Device mode: receives each encoded packet on the engine's thread.
     * Required with `SIPRAL_AUDIO_DEVICE`.
     */
    sipral_audio_transmit_callback_t audio_transmit_callback;
    /**
     * Handed back to `audio_transmit_callback` unread.
     */
    void *audio_transmit_user_data;
    /**
     * How long a device call may block before `SIPRAL_STATUS_DEVICE_TIMED_OUT`,
     * in milliseconds; zero for three seconds.
     */
    uint64_t audio_probe_ms;
    /**
     * The device rate in device mode; zero for 48000.
     */
    uint32_t audio_device_rate_hz;
    /**
     * The most calls at once, either direction, or zero for 128. Past it an
     * INVITE gets `503` with `Retry-After: 2` (RFC 3261 §21.5.4), and a placed
     * call is `SIPRAL_STATUS_LIMIT_REACHED`. See `docs/19-numbers.md`.
     */
    uint32_t max_dialogs;
    /**
     * The most server transactions (RFC 3261 §17.2) at once, or zero for 256;
     * past it a stateless `503`. A BYE is never refused.
     */
    uint32_t max_server_transactions;
    /**
     * D1: how many decisions each diagnostic record keeps, or zero for 64.
     */
    uint32_t diagnostic_decisions;
    /**
     * D1: how many calls have a diagnostic record at once, or zero for 32; the
     * oldest is dropped and counted.
     */
    uint32_t diagnostic_records;
    /**
     * When a call listens for in-band keypad digits, as a
     * sipral_dtmf_detection_t; zero for calls with no telephone event. Placed
     * here to avoid tail padding.
     */
    sipral_dtmf_detection_t dtmf_detection;
    /**
     * Fallback STUN servers, comma-separated `host:port`, tried in order when
     * `stun_server` fails; a failed one is skipped from 30 s up to ten minutes.
     * Only with `stun_server`. Copied.
     */
    const char *stun_fallbacks;
    /**
     * How many bytes of it.
     */
    size_t stun_fallbacks_len;
    /**
     * The lowest RTP port handed out (`sipral_stack_rtp_port_reserve`), or zero
     * with `rtp_port_max` for none. Even ports only (RFC 3550 §11).
     */
    uint32_t rtp_port_min;
    /**
     * The highest port of that range, or zero with `rtp_port_min`.
     */
    uint32_t rtp_port_max;
    /**
     * The SRTP suites calls offer and accept unless the account names its own:
     * names from RFC 4568 section 6.2 and RFC 7714 section 14.2, comma-separated,
     * preferred first; null for the build's order.
     */
    const char *srtp_suites;
    /**
     * How many bytes of it.
     */
    size_t srtp_suites_len;
    /**
     * The path MTU in bytes, or zero for unknown (RFC 3261 section 18.1.1).
     * At least 576 (RFC 791).
     */
    uint32_t path_mtu;
    /**
     * Largest request sent over UDP once no stream can be had, in bytes; zero
     * for never. **A deliberate deviation from RFC 3261 section 18.1.1**, for
     * UDP-only servers. At most 65 507.
     */
    uint32_t datagram_without_stream_bytes;
    /**
     * A per-installation salt (at least 16 bytes) so pseudonyms match across
     * runs; null keys them from `media_seed`. Secret. Copied.
     */
    const uint8_t *pseudonym_salt;
    /**
     * How many bytes of it.
     */
    size_t pseudonym_salt_len;
    /**
     * A `sipral_toggle_t`: whether the trace writes SIP messages unpseudonymised;
     * off by default. Credentials and keys are always removed.
     */
    sipral_toggle_t diagnostic_trace;
    /**
     * Zero.
     */
    uint32_t reserved;
    /**
     * A `sipral_toggle_t`: whether device mode uses the platform's echo
     * cancellation; on by default.
     */
    sipral_toggle_t system_echo_cancellation;
    /**
     * Zero.
     */
    uint32_t reserved_35;
    /**
     * A sipral_held_audio_t: what a held party is sent (RFC 3264 §8.4). Zero
     * is silence.
     */
    sipral_held_audio_t held_audio;
    /**
     * Zero.
     */
    uint32_t reserved_36;
};

/**
 * What one call to sipral_stack_poll did. Set `size` first.
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
     * Events this ABI has no word for yet. Counted, not delivered.
     */
    size_t events_unclaimed;
    /**
     * Bytes this build had nowhere to send; zero, kept for ABI stability.
     */
    size_t transmits_discarded;
    /**
     * Whether there is a deadline. Zero: wait for input.
     */
    uint32_t has_deadline;
    /**
     * Milliseconds from `now_ms` until the stack is due. Zero: due now.
     */
    uint64_t next_poll_in_ms;
};

/**
 * What a stack is running with, defaults filled in. Set `size` first.
 */
struct sipral_stack_settings {
    /**
     * How many bytes of this struct the library filled in.
     */
    size_t size;
    /**
     * The sipral_transport_t this stack speaks.
     */
    sipral_transport_t transport;
    /**
     * Whether this stack retransmits; zero on every transport but UDP.
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
     * How many codecs this stack offers (`sipral_stack_codec_order`).
     */
    size_t codec_count;
    /**
     * How long a frame is, with the default filled in.
     */
    uint32_t frame_ms;
    /**
     * Whether named events are offered, as a `sipral_toggle_t`.
     */
    sipral_toggle_t offer_dtmf;
    /**
     * Whether RTCP multiplexing is asked for, as a `sipral_toggle_t`.
     */
    sipral_toggle_t offer_rtcp_mux;
    /**
     * Whether sending stops during silence, as a `sipral_toggle_t`.
     */
    sipral_toggle_t silence_suppression;
    /**
     * The media stall interval in milliseconds; zero when the watchdog is off.
     */
    uint64_t media_stall_ms;
    /**
     * Whether G.729 Annex B is allowed, as a `sipral_toggle_t`.
     */
    sipral_toggle_t g729_annex_b;
    /**
     * Whether an out-of-dialog REFER reaches the application, as a `sipral_toggle_t`.
     */
    sipral_toggle_t referrals;
    /**
     * The registrar keep-alive in milliseconds; zero when off.
     */
    uint64_t registrar_keepalive_ms;
    /**
     * The most calls the stack holds at once.
     */
    uint32_t max_dialogs;
    /**
     * The most server transactions at once.
     */
    uint32_t max_server_transactions;
    /**
     * How many decisions a diagnostic record keeps.
     */
    uint32_t diagnostic_decisions;
    /**
     * How many diagnostic records the stack keeps.
     */
    uint32_t diagnostic_records;
    /**
     * The RTP port range, as given; both zero for none.
     */
    uint32_t rtp_port_min;
    /**
     * See `rtp_port_min`.
     */
    uint32_t rtp_port_max;
    /**
     * The path MTU as given, zero for unknown (ABI 0.34).
     */
    uint32_t path_mtu;
    /**
     * The largest request sent over UDP once no stream is coming; zero for never.
     */
    uint32_t datagram_without_stream_bytes;
    /**
     * How many SRTP suites calls use by default (`sipral_stack_srtp_suite_order`).
     */
    uint32_t srtp_suite_count;
    /**
     * A `sipral_toggle_t`: whether a `pseudonym_salt` was given. Never the salt.
     */
    sipral_toggle_t pseudonym_salted;
    /**
     * A `sipral_toggle_t`: whether the trace writes whole messages now.
     */
    sipral_toggle_t diagnostic_trace;
    /**
     * A `sipral_toggle_t`: whether the platform's echo cancellation is asked for.
     */
    sipral_toggle_t system_echo_cancellation;
};

/**
 * One header field an application hands over: a name and a value, UTF-8,
 * neither NUL-terminated.
 *
 * No `size` member: it is an array element, so it never grows.
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
 * What an account is configured with. Set `size` to
 * `sizeof(sipral_account_config_t)` and zero the rest first.
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
     * A `registrar_len` of zero makes a trunk that never registers: its
     * state stays `SIPRAL_REGISTRATION_STATE_NOT_REGISTERING`, and
     * `sipral_account_register` refuses it.
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
     * Where this account's requests go, as `host:port`: the registrar, or
     * the outbound proxy for an account with no registrar. Calls without
     * a destination go here too. Required unless `server_uri` is given;
     * an address, not a name.
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
     * The user name to answer a challenge with, or null for none.
     */
    const char *auth_user;
    /**
     * How many bytes of it.
     */
    size_t auth_user_len;
    /**
     * The password that goes with it, copied.
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
     * Above 2³²−1 is refused (§20.19 `delta-seconds`). The registrar's
     * grant wins, and is read back in
     * `sipral_registration_event_t::expires_ms`.
     */
    uint64_t expires_seconds;
    /**
     * Header fields for every REGISTER of this account, in order, or null.
     *
     * Checked on add as `sipral_call_config_t::headers` is: `Expires` is
     * the stack's (`expires_seconds`), `Supported` the application's (for
     * GRUU). Refused for an account with no registrar.
     */
    const sipral_header_t *headers;
    /**
     * How many elements `headers` has.
     */
    size_t headers_len;
    /**
     * The transport for this account's REGISTER and requests:
     * SIPRAL_TRANSPORT_MAIN
     * for zero, or a number
     * sipral_stack_transport_bind
     * has bound. An unbound number is `SIPRAL_STATUS_INVALID_ARGUMENT`.
     */
    uint32_t transport;
    /**
     * The push service to be woken through, by registered name: `apns`,
     * `fcm`, `webpush` (RFC 8599 §4.1.1). Null for no push.
     *
     * The push parameters go only on this account's REGISTER `Contact`
     * (§4.1): on an INVITE `pn-prid` would let the far end wake this
     * device at will. De-registration leaves the identifier out (§4.1.2).
     */
    const char *push_provider;
    /**
     * How many bytes of it.
     */
    size_t push_provider_len;
    /**
     * The device token the service issued. Required with
     * `push_provider`, and refused without it. Percent-escaped where SIP
     * needs it (§8.7): APNs tokens carry `=`, Web Push ids are URLs.
     */
    const char *push_prid;
    /**
     * How many bytes of it.
     */
    size_t push_prid_len;
    /**
     * The extra value a service needs: the bundle for Apple, the sender
     * for Firebase. Optional; §4.1.1 lets the service decide.
     */
    const char *push_param;
    /**
     * How many bytes of it.
     */
    size_t push_param_len;
    /**
     * Nonzero when this device can refresh its binding without a push,
     * declared with `+sip.pnsreg` (§4.1.4). Only the application knows:
     * a suspended process runs no timer, and a false claim stops the
     * registrar's wake-ups.
     */
    uint32_t push_wakes_itself;
    /**
     * Where end-of-call quality reports go (RFC 6035 over PUBLISH, RFC
     * 3903), or null for none.
     */
    const char *quality_report_uri;
    /**
     * How many bytes of it.
     */
    size_t quality_report_uri_len;
    /**
     * A sipral_session_timer_t: how this account's calls ask for a
     * session timer (RFC 4028). Zero is the default, thirty minutes.
     */
    sipral_session_timer_t session_timer;
    /**
     * The interval to ask for under `SIPRAL_SESSION_TIMER_INTERVAL`, in
     * seconds: at least 90, RFC 4028 §5's floor. Read for nothing else.
     */
    uint64_t session_interval_seconds;
    /**
     * `SIPRAL_PRIVACY_*` bits: place every call anonymously (RFC 3323).
     * `From` becomes `"Anonymous" <sip:anonymous@anonymous.invalid>`,
     * `Privacy` carries the bits, and `P-Asserted-Identity` goes only to
     * a peer in `trusted_peers`. Zero asks for none.
     */
    uint32_t privacy;
    /**
     * Trusted peers (RFC 3325's trust domain), comma-separated IP
     * addresses. Only their asserted identity is read
     * (`sipral_call_event_t::asserted_uri`). Once any are named, calls to
     * other peers carry no `P-Asserted-Identity` or `P-Preferred-Identity`.
     * Null trusts nobody.
     */
    const char *trusted_peers;
    /**
     * How many bytes of it.
     */
    size_t trusted_peers_len;
    /**
     * A `sipral_srtp_t` over the stack's `srtp`, or zero for the stack's.
     * A call may be stricter, never looser
     * (`SIPRAL_STATUS_SECURITY_POLICY`); an INVITE it cannot meet gets
     * 488.
     */
    sipral_srtp_t srtp;
    /**
     * The SRTP suites, most preferred first, comma-separated, as RFC 4568
     * §6.2 and RFC 7714 §14.2 name them:
     * `AEAD_AES_256_GCM,AES_CM_128_HMAC_SHA1_80`. Used for SDES and the
     * DTLS-SRTP profiles; GCM only if named. Null for this build's own.
     * Each line goes in the INVITE: more than two or three need a stream
     * transport.
     */
    const char *srtp_suites;
    /**
     * How many bytes of it.
     */
    size_t srtp_suites_len;
    /**
     * A `sipral_stir_verification_t`: what to do with received `Identity`
     * fields (RFC 8224 §6.2). Zero reports, once `sipral_stack_stir` gave
     * trust anchors.
     */
    sipral_stir_verification_t stir_verification;
    /**
     * The P-256 key this account signs calls with (RFC 8224 §6.1): the
     * bare 32-octet scalar, or `EC PRIVATE KEY` / `PRIVATE KEY` in DER or
     * PEM. Null signs nothing. Needs the wall clock from
     * `sipral_stack_stir`, else `SIPRAL_STATUS_WRONG_STATE`.
     */
    const uint8_t *stir_key;
    /**
     * How many bytes of it.
     */
    size_t stir_key_len;
    /**
     * Where the chain for `stir_key` is published (`x5u` and `info`).
     * Required with `stir_key`, and only with it.
     */
    const char *stir_certificate_url;
    /**
     * How many bytes of it.
     */
    size_t stir_certificate_url_len;
    /**
     * The number this account signs as, canonicalised by RFC 8224 §8.3's
     * first step, or null for `aor`'s user part.
     */
    const char *stir_orig;
    /**
     * How many bytes of it.
     */
    size_t stir_orig_len;
    /**
     * The origination id every signed call claims (RFC 8588 §5), a UUID,
     * or null for one the stack draws.
     */
    const char *stir_origid;
    /**
     * How many bytes of it.
     */
    size_t stir_origid_len;
    /**
     * A `sipral_attestation_t` (RFC 8588 §4); zero is full, `A`.
     */
    sipral_attestation_t stir_attestation;
    /**
     * A `sipral_toggle_t`: whether an encrypted call may be recorded
     * (`sipral_call_record_to`) in the clear. Off by default: copies go as
     * SRTP with SDES keys (RFC 4568), and a stream the server refuses
     * that way gets nothing (RFC 7866 §12.2).
     *
     * Sixty-four bits wide so it starts past an older layout's trailing
     * padding, which old callers may leave unwritten.
     */
    uint64_t recording_in_clear;
    /**
     * How often, in milliseconds, to keep the flow to the registrar (or
     * outbound proxy) open regardless of STUN; zero defers to
     * `sipral_stack_config_t::registrar_keepalive`.
     *
     * For a NAT that forgets UDP flows before the REGISTER refresh. UDP
     * sends a lone double CRLF (RFC 3261 §7.5); TCP and TLS ping at this
     * interval (RFC 5626 §4.4.1). Jittered to 80-100%. From 1 000 to
     * 120 000, else `SIPRAL_STATUS_INVALID_ARGUMENT`.
     */
    uint64_t keepalive_ms;
    /**
     * The server as a URI whose host RFC 3263 locates
     * (`sip:pbx.example.com`, `sips:example.com:5061`), in place of
     * `registrar_address`: exactly one is given. The registrar, or the
     * outbound proxy for an account that does not register.
     *
     * Lookups go to the application's resolver via
     * `SIPRAL_EVENT_KIND_LOOKUP_WANTED` and `sipral_account_looked_up`;
     * ordering, SRV ranking and fallback are the stack's. The first
     * REGISTER waits for the first answer; a call before it with no
     * destination is `SIPRAL_STATUS_WRONG_STATE`. An out-of-dialog
     * request that times out, fails its transport or gets 503 moves to
     * the next address (§4.3). The name is looked up again when the TTL
     * runs out or recovery asks. A port skips SRV; a numeric host asks
     * nothing.
     */
    const char *server_uri;
    /**
     * How many bytes of it.
     */
    size_t server_uri_len;
    /**
     * The SHA-256 fingerprint of the one TLS certificate this account
     * trusts, for a self-signed PBX: 64 hex digits, any case, colons and
     * spaces ignored, bare or after `sha256 Fingerprint=` (openssl),
     * `sha-256 ` (RFC 8122) or `SHA256=`, any case. Anything else is
     * `SIPRAL_STATUS_INVALID_ARGUMENT`. Null for none.
     *
     * The application's verifier asks `sipral_account_check_certificate`;
     * with a pin the fingerprint is the whole verdict (`docs/22-tls.md`).
     */
    const char *tls_pin_sha256;
    /**
     * How many bytes of it.
     */
    size_t tls_pin_sha256_len;
    /**
     * A `sipral_toggle_t`: ask NAPTR before SRV for `server_uri`'s domain
     * (RFC 3263 §4.1). Off by default; refused without `server_uri`.
     */
    sipral_toggle_t server_naptr;
    /**
     * Zero.
     */
    uint32_t reserved;
    /**
     * A sipral_transport_t: the protocol of a connection of this
     * account's own to its server, which the application opens, or zero.
     *
     * For an account on TCP or TLS beside one on the stack's UDP, in one
     * stack. With TCP, TLS, WS or WSS the stack raises
     * `SIPRAL_EVENT_KIND_TRANSPORT_WANTED` with the protocol and address
     * (`request_bytes` and `limit_bytes` zero); the account then uses
     * whatever transport of that protocol the application binds there with
     * `sipral_stack_transport_bind`, including one bound before. Until
     * then the REGISTER waits; after ten seconds it fails as unreachable
     * and the retry asks again. A non-registering account asks on add;
     * any account asks again when the connection fails or closes. A call
     * before the bind is `SIPRAL_STATUS_TRANSPORT_DOWN`. In-call requests
     * keep their INVITE's connection, and requests arriving on it match
     * this account first. `SIPRAL_TRANSPORT_UDP` only describes
     * `transport`.
     */
    sipral_transport_t stream_protocol;
    /**
     * Zero.
     */
    uint32_t reserved_35;
    /**
     * The realms the password answers, one per line (a realm may hold a
     * comma, never a line break), or null for the default.
     *
     * The password answers only the account's own server (RFC 3261
     * §22.1). By default that is the realms of the server's first
     * challenge and of every REGISTER challenge; a proxy relaying a far
     * end's 401 gets nothing, and `SIPRAL_EVENT_KIND_CHALLENGE_DECLINED`
     * says so. When calls are challenged under a realm REGISTERs never
     * see (an SBC or proxy with its own realm), name all of them here.
     * Empty lines are skipped; realms compare exactly (§22.1).
     */
    const char *realms;
    /**
     * How many bytes of it.
     */
    size_t realms_len;
};

/**
 * What a call is placed with.
 *
 * Set `size` to `sizeof(sipral_call_config_t)` and zero the rest before filling it in.
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
     * The session description to offer, for a call whose audio the application runs.
     * Exactly one of this and `media_address` is set.
     */
    const uint8_t *sdp;
    /**
     * How many bytes of it.
     */
    size_t sdp_len;
    /**
     * Where to send the INVITE, as `host:port`, or null for where the account registers
     * (the outbound proxy of a registered line).
     */
    const char *destination;
    /**
     * How many bytes of it.
     */
    size_t destination_len;
    /**
     * Nonzero keeps every branch a proxy forks the INVITE into. Zero keeps the first that
     * answers and hangs up the rest.
     */
    uint32_t keep_all_forks;
    /**
     * Where this end receives media, as `host:port`, for a call whose audio this stack runs.
     *
     * Set, the offer is written from this stack's codec order and the call gets a media
     * session the `sipral_media_*` entry points reach. Null: set `sdp` instead.
     */
    const char *media_address;
    /**
     * How many bytes of it.
     */
    size_t media_address_len;
    /**
     * Header fields to put on the INVITE, in order, or null for none.
     *
     * Each is checked first: the name a token, the value one line, and not a field the
     * stack writes itself (`docs/04-ua.md`; `User-Agent` too when
     * `sipral_stack_config_t::user_agent` is set). A refusal is
     * `SIPRAL_STATUS_INVALID_ARGUMENT` naming the element, and no call.
     */
    const sipral_header_t *headers;
    /**
     * How many elements `headers` has.
     */
    size_t headers_len;
    /**
     * What this call does about SRTP, overriding `sipral_stack_config_t::srtp`: a
     * `sipral_srtp_t`, or zero for the stack's setting. Any other value is
     * `SIPRAL_STATUS_INVALID_ARGUMENT`. Read only with `media_address` set.
     */
    sipral_srtp_t srtp;
    /**
     * Which transport the INVITE goes out on, read only with `destination`:
     * SIPRAL_TRANSPORT_MAIN for zero, or a
     * number sipral_stack_transport_bind
     * has bound. Nonzero with `destination` null is `SIPRAL_STATUS_INVALID_ARGUMENT`.
     */
    uint32_t transport;
    /**
     * What this call offers and in what order, overriding `sipral_stack_config_t::codecs`:
     * codec names separated by commas, as `sipral_codec_info_t::name` spells them, UTF-8,
     * not NUL-terminated. Null for the stack's order.
     *
     * The rest of the stack's catalogue (frame length, events, multiplexing, SRTP) is kept.
     * An unknown name, a repeated name or a stray comma is `SIPRAL_STATUS_INVALID_ARGUMENT`.
     * Applied only with `media_address` set, but the names are checked either way.
     */
    const char *codecs;
    /**
     * How many bytes of it.
     */
    size_t codecs_len;
    /**
     * What this call does about ICE, overriding `sipral_stack_config_t::ice`: a `sipral_ice_t`,
     * or zero for the stack's setting. Any other value is `SIPRAL_STATUS_INVALID_ARGUMENT`.
     * Read only with `media_address` set.
     */
    sipral_ice_t ice;
    /**
     * Where this call's real-time text arrives (RFC 4103), as `host:port` of a second
     * socket the application bound, not NUL-terminated; null for no text. Set, the
     * description carries an `m=text` stream for T.140 with redundancy, carried by
     * `sipral_media_send_text`, `sipral_media_poll_text` and `sipral_media_receive_text`.
     *
     * Read only with `media_address`. Not offered with SRTP, DTLS-SRTP or ICE: the text
     * stream has no key or candidates of its own, and clear text beside encrypted audio is
     * worse.
     */
    const char *text_address;
    /**
     * How many bytes of it.
     */
    size_t text_address_len;
    /**
     * Whether this call asks for RTCP feedback: a `sipral_toggle_t`. On offers RTP/AVPF
     * (RFC 4585) with Generic NACKs and reduced-size RTCP (RFC 5506). Off by default,
     * because a far end that knows only RTP/AVP refuses the profile. Read only with
     * `media_address`. An offer on a feedback profile is answered on it regardless
     * (RFC 4585 §4.1); the NACKs and reduced-size RTCP are agreed only when this is on.
     */
    sipral_toggle_t feedback;
    /**
     * Nonzero to say this end is the focus of a conference (RFC 4579
     * §3.3): `isfocus` goes on the Contact of every message this call
     * sends from here on.
     */
    uint32_t focus;
    /**
     * Nonzero to follow a 3xx to its `Contact` targets (RFC 3261 §8.1.3.4), most preferred
     * first, as new INVITEs of the same call. Not followed: a target already tried, a 380, a
     * 6xx, a forked call, past eight redirections. Zero (default) ends the call with
     * `SIPRAL_EVENT_KIND_CALL_ENDED` carrying the 3xx status and readable `Contact` addresses.
     * Added in ABI 1.2.
     */
    uint32_t follow_redirects;
    /**
     * Zero. Pads the struct to a multiple of its alignment, so a member a later version
     * appends never lands in padding. The library reads nothing from it.
     */
    uint32_t reserved;
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
    sipral_codec_t codec;
    /**
     * The RTP timestamp clock, in hertz, which is what goes on the
     * `a=rtpmap` line.
     */
    uint32_t clock_rate;
    /**
     * The codec's own rate, which the samples crossing this ABI use. G.722's
     * differs from its clock (RFC 3551 §4.5.2).
     */
    uint32_t sample_rate;
    /**
     * The payload type RFC 3551 table 4 assigns it, when it has one.
     */
    uint32_t static_payload_type;
    /**
     * Whether it has one. Opus does not.
     */
    uint32_t has_static_payload_type;
    /**
     * Zero. Pads to the alignment so later members start past this
     * header's length. Written zero, never read.
     */
    uint32_t reserved;
};

/**
 * One codec this call could have used, and what became of it.
 *
 * Set `size` to `sizeof(sipral_codec_candidate_t)` before the call.
 *
 * Recorded when the negotiation decided, never recomputed.
 */
struct sipral_codec_candidate {
    /**
     * How many bytes of this struct the library filled in.
     */
    size_t size;
    /**
     * A sipral_codec_t: the candidate itself.
     */
    sipral_codec_t codec;
    /**
     * A sipral_codec_outcome_t: what became of it.
     */
    sipral_codec_outcome_t outcome;
    /**
     * A sipral_codec_t: what beat it, when `outcome` is
     * `SIPRAL_CODEC_OUTCOME_OUTRANKED`; `SIPRAL_CODEC_UNKNOWN` otherwise.
     */
    sipral_codec_t outranked_by;
    /**
     * Zero. Pads to the alignment so later members start past this
     * header's length. Written zero, never read.
     */
    uint32_t reserved;
};

/**
 * One path a call's ICE agent tried — a candidate pair it checked, or a
 * relay it held — and what became of it, with its two addresses written
 * into the caller's own buffers.
 *
 * The caller fills in `size`, the two pointers and the two capacities;
 * the library fills in the rest. Null with capacity zero skips an address.
 * Recorded as each outcome happened, since RFC 8445 §8.1.2 drops losing
 * pairs from the checklist on selection.
 */
struct sipral_path_candidate {
    /**
     * `sizeof` this struct, as the caller's header declares it.
     */
    size_t size;
    /**
     * The pair's priority (RFC 8445 §6.1.2.3), as this end's role
     * computes it; zero for a relay.
     */
    uint64_t priority;
    /**
     * A sipral_path_kind_t.
     */
    sipral_path_kind_t kind;
    /**
     * A sipral_path_outcome_t.
     */
    sipral_path_outcome_t outcome;
    /**
     * For `SIPRAL_PATH_OUTCOME_REFUSED`, the STUN error code the far end
     * answered with; for `SIPRAL_PATH_OUTCOME_RELAY_REFUSED` and
     * `SIPRAL_PATH_OUTCOME_LOST`, the TURN server's, zero when it gave
     * none. Zero otherwise.
     */
    uint32_t code;
    /**
     * A sipral_candidate_kind_t: what `local` is.
     */
    sipral_candidate_kind_t local_kind;
    /**
     * A sipral_candidate_kind_t: what `remote` is, when it is a
     * candidate at all.
     */
    sipral_candidate_kind_t remote_kind;
    /**
     * Zero. Keeps the layout identical on 32- and 64-bit targets. Written
     * zero, never read.
     */
    uint32_t reserved;
    /**
     * Where to write the local address, `host:port` with a trailing NUL:
     * for a pair, the candidate its checks left from; for a relay, the
     * relayed address.
     */
    char *local;
    /**
     * How much room `local` has. At least SIPRAL_ADDRESS_BYTES when
     * it is not null.
     */
    size_t local_capacity;
    /**
     * How many bytes of it were written, the NUL not counted. Zero for
     * a relay that has no relayed address.
     */
    size_t local_len;
    /**
     * Where to write the far address, `host:port` with a trailing NUL:
     * for a pair, the far end's candidate; for a relay, the TURN
     * server.
     */
    char *remote;
    /**
     * How much room `remote` has. At least SIPRAL_ADDRESS_BYTES
     * when it is not null.
     */
    size_t remote_capacity;
    /**
     * How many bytes of it were written, the NUL not counted.
     */
    size_t remote_len;
};

/**
 * What one call's media settled on, and what it is doing now.
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
    sipral_codec_t codec;
    /**
     * The payload type on the wire: the offer's number, not necessarily
     * ours.
     */
    uint32_t payload_type;
    /**
     * The RTP timestamp clock, in hertz.
     */
    uint32_t clock_rate;
    /**
     * The rate the samples crossing this ABI are at: the codec's, or the
     * one sipral_media_set_app_rate chose.
     */
    uint32_t sample_rate;
    /**
     * How long a frame is, in milliseconds.
     */
    uint32_t frame_ms;
    /**
     * Samples in one frame: exactly what sipral_media_playback fills and
     * what sipral_media_capture wants, at `sample_rate`.
     */
    size_t frame_samples;
    /**
     * A sipral_direction_t.
     */
    sipral_direction_t direction;
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
    sipral_rtcp_t rtcp;
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
    /**
     * Whether the call agreed a real-time text stream (RFC 4103), which
     * `sipral_media_send_text` writes to.
     */
    uint32_t has_text;
    /**
     * Whether the audio stream runs RTP/AVPF (RFC 4585): both ends named
     * a feedback profile.
     */
    uint32_t feedback;
    /**
     * Whether both ends agreed Generic NACKs (`a=rtcp-fb:* nack`), so
     * that a gap in what arrives is asked for again.
     */
    uint32_t generic_nack;
    /**
     * Whether both ends agreed reduced-size RTCP (RFC 5506,
     * `a=rtcp-rsize`).
     */
    uint32_t reduced_size;
    /**
     * Zero. Pads to the alignment so later members start past this
     * header's length. Written zero, never read.
     */
    uint32_t reserved;
};

/**
 * What one call's media has cost, and what it is costing now.
 *
 * Cheap enough to read at UI frame rate. The same struct arrives with
 * `SIPRAL_EVENT_KIND_MEDIA_STATISTICS` when the call ends. Delays are in
 * microseconds, since healthy jitter is below a millisecond.
 *
 * Set `size` to `sizeof(sipral_stream_stats_t)` before the call.
 */
struct sipral_stream_stats {
    /**
     * How many bytes of this struct the library filled in.
     */
    size_t size;
    /**
     * A sipral_codec_t: what the call settled on.
     */
    sipral_codec_t codec;
    /**
     * Whether a round-trip time is known. Zero until a report comes back,
     * which may be never (RFC 3550 §6.2 delays the first one).
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
     * Frames dropped in a pause to bring the delay down.
     */
    uint64_t frames_shrunk;
    /**
     * Frames concealment invented in a pause to push the delay up.
     */
    uint64_t frames_stretched;
    /**
     * How far behind the newest packet the playout point is.
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
     * Frames concealed as a fraction of frames played, over about the last
     * ten seconds.
     */
    float loss_rate;
    /**
     * 100 for a flawless call, 0 for an unusable one. Not a MOS.
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
     * Whether an RFC 3611 VoIP Metrics report is available. Every `voip_*`
     * member is meaningless while this is zero.
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
     * RFC 3611 SS4.7.2's `Gmin`, the burst/gap threshold, fixed per stream.
     */
    uint32_t voip_gmin;
    /**
     * RFC 3611 SS4.7.3's end-system delay. Always zero: it needs the
     * sending side's delay, which this end cannot see.
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
     * Whether `voip_r_factor` is available: zero when ITU-T G.113 has no
     * `Ie`/`Bpl` for the codec (RFC 3611 SS4.7.5's `127` sentinel).
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
    /**
     * Frames played empty because the jitter buffer ran dry while the far
     * end was still sending. Not lost packets (`packets_lost`), so the
     * `voip_*` rates miss it (RFC 3611 SS4.7.1 counts packets);
     * `loss_rate`, `score` and `suffering` include it.
     */
    uint64_t frames_underrun;
    /**
     * Whether the stream runs RTP/AVPF (RFC 4585). The counts below stay
     * zero otherwise.
     */
    uint32_t feedback;
    /**
     * The `trr-int` both ends agreed: the least time between two
     * regular reports, in milliseconds. Zero for none.
     */
    uint32_t trr_interval_ms;
    /**
     * Generic NACKs this end sent, each asking for one or more packets.
     */
    uint64_t nacks_sent;
    /**
     * The packets those NACKs asked for.
     */
    uint64_t packets_nacked;
    /**
     * Generic NACKs the far end sent.
     */
    uint64_t nacks_received;
    /**
     * The packets those asked this end for.
     */
    uint64_t packets_asked_for;
    /**
     * Early RTCP packets this end sent.
     */
    uint64_t early_packets;
    /**
     * Reduced-size RTCP packets this end sent (RFC 5506).
     */
    uint64_t reduced_size_packets;
    /**
     * Feedback held back for lack of RTCP bandwidth.
     */
    uint64_t feedback_suppressed;
};

/**
 * One datagram on its way out, written into the caller's own buffers.
 *
 * The caller fills in `size`, the two pointers and the two capacities; the
 * library fills in the two lengths and the bytes. A `len` of zero means
 * nothing to send (held, or silence suppression). Both buffers are checked
 * before anything is produced.
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
    /**
     * What to send it over, as a `sipral_transport_t`. `SIPRAL_TRANSPORT_UDP`
     * is a datagram from the media socket. With a TURN server over TCP or
     * TLS (`turn_transport`), relayed traffic says so, `destination` is the
     * server, and the bytes go in order on that connection, never as a
     * datagram.
     */
    sipral_transport_t protocol;
    /**
     * Zero. Pads to the alignment so later members start past this
     * header's length. Set zero on input; written zero, never read.
     */
    uint32_t reserved;
};

/**
 * What sipral_processor_callback_t is handed for one call: an ordinary
 * frame to process, or a request to forget what has been learned.
 *
 * Library-owned, passed as a `const` pointer. Read `size` first; read
 * nothing after the callback returns, since the buffers are borrowed.
 */
struct sipral_processor_frame {
    /**
     * How many bytes of this struct the library filled in.
     */
    size_t size;
    /**
     * 0 for an ordinary frame; 1 to forget learned state (device or codec
     * change). When 1, all three buffers are null and lengths zero.
     */
    uint32_t reset;
    /**
     * The frame just captured from the microphone. Null on reset.
     */
    const int16_t *near_end;
    /**
     * Samples in `near_end`; always equal to `far_end_len` and `out_len`.
     * 0 on reset.
     */
    size_t near_end_len;
    /**
     * The far-end audio played over the same span as `near_end`. Null on
     * reset.
     */
    const int16_t *far_end;
    /**
     * Samples in `far_end`. 0 on reset.
     */
    size_t far_end_len;
    /**
     * Where the callback writes the replacement for `near_end`; every
     * sample must be written. Null on reset.
     */
    int16_t *out;
    /**
     * Samples `out` holds, all of which must be written. 0 on reset.
     */
    size_t out_len;
};

/**
 * One message on its way out, written into the caller's own buffers.
 *
 * The caller fills `size`, the three pointers and the three capacities; the library fills
 * the rest. A `len` of zero means nothing to send, which ends the draining loop. Address
 * buffers are checked before a message is taken. A payload buffer too small leaves the
 * message queued and offered again: a committed message is never dropped.
 */
struct sipral_transmit {
    /**
     * `sizeof` this struct, as the caller's header declares it.
     */
    size_t size;
    /**
     * Which transport to write to: SIPRAL_TRANSPORT_MAIN, or a number
     * sipral_stack_transport_bind bound for the owning account or call.
     */
    uint32_t transport;
    /**
     * What that transport speaks, as a `sipral_transport_t`. Per message, since §18.1.1
     * can move a request onto a stream. Zero for a protocol with no ABI number.
     */
    sipral_transport_t protocol;
    /**
     * Where to write the message. Nothing is written unless all of it fits.
     */
    uint8_t *data;
    /**
     * How much room `data` has.
     */
    size_t capacity;
    /**
     * How much was written, or after `SIPRAL_STATUS_BUFFER_TOO_SMALL`, how much is needed.
     */
    size_t len;
    /**
     * Where to write the destination, `host:port` with a trailing NUL. Null with capacity zero
     * for a connected socket.
     */
    char *destination;
    /**
     * Room in `destination`: at least SIPRAL_ADDRESS_BYTES when not null.
     */
    size_t destination_capacity;
    /**
     * How many bytes of it were written, the NUL not counted.
     */
    size_t destination_len;
    /**
     * Where to write the address to send *from*, in the same shape. RFC 3581 §4: a response
     * leaves from the address its request arrived on, which a wildcard listener cannot tell.
     * `source_len` zero means the transport's own address.
     */
    char *source;
    /**
     * Room in `source`: at least SIPRAL_ADDRESS_BYTES when not null.
     */
    size_t source_capacity;
    /**
     * How many bytes of it were written, the NUL not counted.
     */
    size_t source_len;
};

/**
 * A failed transport and why, for sipral_stack_transport_failed_with. All caller-filled;
 * `detail` is the platform's own optional sentence, passed through unparsed.
 */
struct sipral_transport_failure {
    /**
     * `sizeof` this struct, as the caller's header declares it.
     */
    size_t size;
    /**
     * Which transport: SIPRAL_TRANSPORT_MAIN or a bound number.
     */
    uint32_t transport;
    /**
     * A sipral_transport_error_t.
     */
    sipral_transport_error_t error;
    /**
     * A sipral_tls_failure_t; `SIPRAL_TLS_FAILURE_NONE` unless TLS refused.
     */
    sipral_tls_failure_t tls;
    /**
     * The platform's words, not NUL-terminated. Null with length zero for none.
     */
    const char *detail;
    /**
     * How many bytes of it; at most SIPRAL_TRANSPORT_DETAIL_BYTES.
     */
    size_t detail_len;
};

/**
 * What a SIPRAL_EVENT_KIND_REGISTRATION_CHANGED carries.
 */
struct sipral_registration_event {
    /**
     * A sipral_registration_state_t.
     */
    sipral_registration_state_t state;
    /**
     * A sipral_registration_failure_t, zero when nothing failed.
     */
    sipral_registration_failure_t failure;
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
     * How long until the next attempt; meaningful only while retrying.
     */
    uint64_t retry_in_ms;
};

/**
 * What every call event carries. Members that do not apply are zero,
 * and zero always means absent.
 */
struct sipral_call_event {
    /**
     * A sipral_call_state_t.
     */
    sipral_call_state_t state;
    /**
     * A sipral_call_end_reason_t, zero while the call is alive.
     */
    sipral_call_end_reason_t end_reason;
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
     * The creating request's `From` URI, as written, without brackets or
     * header parameters. Null and zero when unavailable.
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
    /**
     * For SIPRAL_EVENT_KIND_CALL_ENDED: the SIP cause in the far end's
     * `Reason` (RFC 3326). 200 on a CANCEL means answered elsewhere.
     */
    uint32_t cause_sip;
    /**
     * The Q.850 cause from `Reason` (16 normal, 17 busy), or zero.
     */
    uint32_t cause_q850;
    /**
     * The `text` of the first `Reason` value, unquoted. Null and zero
     * when there was none.
     */
    const uint8_t *cause_text;
    /**
     * How many bytes of it.
     */
    size_t cause_text_len;
    /**
     * Whether an incoming INVITE came from a `trusted_peers` peer. If not,
     * the asserted identity and `verstat` are empty (RFC 3325 §8).
     */
    uint32_t identity_trusted;
    /**
     * The first `P-Asserted-Identity`, else a `Remote-Party-ID`, as
     * written. Null and zero when none.
     */
    const uint8_t *asserted_uri;
    /**
     * How many bytes of it.
     */
    size_t asserted_uri_len;
    /**
     * That identity's display name. Null and zero when it named none.
     */
    const uint8_t *asserted_display;
    /**
     * How many bytes of it.
     */
    size_t asserted_display_len;
    /**
     * A sipral_verstat_t: what the
     * network concluded about the caller's number.
     */
    sipral_verstat_t verstat;
    /**
     * The `SIPRAL_PRIVACY_*` bits the caller's `Privacy` asked for.
     */
    uint32_t privacy;
    /**
     * The top-most `Diversion` (RFC 5806), as written. Null and zero
     * when none.
     */
    const uint8_t *diverted_from;
    /**
     * How many bytes of it.
     */
    size_t diverted_from_len;
    /**
     * Why: its `reason`. Null and zero when none.
     */
    const uint8_t *diversion_reason;
    /**
     * How many bytes of it.
     */
    size_t diversion_reason_len;
    /**
     * How many `Diversion` values the INVITE carried.
     */
    uint32_t diversion_count;
    /**
     * How many `History-Info` entries it carried.
     */
    uint32_t history_count;
    /**
     * A sipral_answer_mode_t: the
     * INVITE's `Answer-Mode` (RFC 5373).
     */
    sipral_answer_mode_t answer_mode;
    /**
     * Whether that field said `;require`: the caller would rather the
     * call be refused, with a 403, than answered any other way.
     */
    uint32_t answer_mode_required;
    /**
     * The same for `Priv-Answer-Mode`, which RFC 5373 §4.2 holds to a
     * stricter policy.
     */
    uint32_t priv_answer_mode;
    /**
     * Whether that field said `;require`.
     */
    uint32_t priv_answer_mode_required;
    /**
     * Whether the call asked to be auto-answered after `answer_after_ms`
     * (`Answer-Mode: Auto`, `answer-after`, `info=alert-autoanswer`).
     */
    uint32_t has_answer_after;
    /**
     * After how long, when `has_answer_after` is set.
     */
    uint64_t answer_after_ms;
    /**
     * A sipral_ring_source_t: whether
     * the ring says the caller is internal or external.
     */
    sipral_ring_source_t ring_source;
    /**
     * The first `Alert-Info` URI, without the angle brackets. Null and
     * zero when none. `sipral_call_identity_text` reads the rest.
     */
    const uint8_t *alert_info;
    /**
     * How many bytes of it.
     */
    size_t alert_info_len;
    /**
     * A sipral_verification_outcome_t: this stack's own verdict (RFC 8224
     * §6.2), unlike the network's `verstat`. Zero when not verified.
     */
    sipral_verification_outcome_t verification;
    /**
     * A sipral_attestation_t: the
     * level a valid SHAKEN PASSporT claimed.
     */
    sipral_attestation_t attestation;
    /**
     * A sipral_verification_failure_t: why the verdict did not hold.
     */
    sipral_verification_failure_t verification_failure;
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
 * What a media event carries. Members that do not apply are zero or null.
 */
struct sipral_media_event {
    /**
     * A sipral_codec_t: what the negotiation
     * settled on, zero where the event is not about a codec.
     */
    sipral_codec_t codec;
    /**
     * A sipral_direction_t: which way audio
     * may flow, as seen from here.
     */
    sipral_direction_t direction;
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
    sipral_media_fault_t fault;
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
     * How long the key was held. Zero for no duration or `Duration=0`.
     */
    uint64_t held_ms;
    /**
     * A sipral_srtp_suite_t, for SIPRAL_EVENT_KIND_MEDIA_SECURED and the
     * encryption report.
     */
    sipral_srtp_suite_t suite;
    /**
     * A sipral_digit_source_t: which of the two ways this stack accepts a
     * digit reported this one, for SIPRAL_EVENT_KIND_DIGIT_RECEIVED.
     */
    sipral_digit_source_t source;
    /**
     * Whether the RFC 6035 PUBLISH left this end, for
     * SIPRAL_EVENT_KIND_QUALITY_REPORT_SENT.
     */
    uint32_t quality_report_sent;
    /**
     * A sipral_key_exchange_t, on the start, change and secure kinds.
     */
    sipral_key_exchange_t key_exchange;
    /**
     * Whether the stream is encrypted now; zero until a DTLS-SRTP
     * handshake ends.
     */
    uint32_t encrypted;
    /**
     * Whether DTLS-SRTP checked the far end's certificate against the
     * fingerprint. Never for SDES.
     */
    uint32_t authenticated;
};

/**
 * What a SIPRAL_EVENT_KIND_RECOVERY carries.
 */
struct sipral_recovery_event {
    /**
     * A sipral_recovery_outcome_t.
     */
    sipral_recovery_outcome_t state;
    /**
     * A sipral_recovery_rung_t: the last rung tried. Zero unless `state`
     * is SIPRAL_RECOVERY_OUTCOME_GAVE_UP.
     */
    sipral_recovery_rung_t rung;
    /**
     * A sipral_recovery_failure_t. Zero unless `state` is
     * SIPRAL_RECOVERY_OUTCOME_GAVE_UP.
     */
    sipral_recovery_failure_t reason;
    /**
     * Bindings the ladder never proved. Meaningful only when `state` is
     * SIPRAL_RECOVERY_OUTCOME_GAVE_UP.
     */
    uint32_t unverified;
};

/**
 * What a SIPRAL_EVENT_KIND_TRANSPORT_WANTED carries: a request RFC
 * 3261 §18.1.1 kept off a datagram, with no stream open for it.
 */
struct sipral_transport_wanted_event {
    /**
     * What to open, as a sipral_transport_t; zero for an unknown one.
     */
    sipral_transport_t protocol;
    /**
     * Where to, as `host:port`. Not NUL-terminated.
     */
    const char *destination;
    /**
     * How many bytes of it.
     */
    size_t destination_len;
    /**
     * The request's size in bytes, as it would go on the wire.
     */
    size_t request_bytes;
    /**
     * The largest size that fits a datagram: path MTU less the §18.1.1
     * headroom, or 1300 when the MTU is unknown.
     */
    uint32_t limit_bytes;
};

/**
 * What a SIPRAL_EVENT_KIND_SUBSCRIPTION_CHANGED and a
 * SIPRAL_EVENT_KIND_NOTIFIED carry.
 */
struct sipral_subscription_event {
    /**
     * Which subscription, minted by `sipral_account_subscribe` or by this
     * ABI for a fork sibling.
     */
    sipral_handle_t subscription;
    /**
     * A sipral_subscription_state_t.
     */
    sipral_subscription_state_t state;
    /**
     * A sipral_subscription_end_t:
     * why it is not live. Zero while it is.
     */
    sipral_subscription_end_t reason;
    /**
     * The SIP status a response gave for it, when one did. Zero
     * otherwise.
     */
    uint32_t status_code;
    /**
     * Whether the notification carried readable dialog state. Zero on
     * every kind but SIPRAL_EVENT_KIND_NOTIFIED.
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
     * is `SIPRAL_SUBSCRIPTION_STATE_RETRYING`. Zero otherwise.
     */
    uint64_t retry_in_ms;
    /**
     * The subscription this one forked from (RFC 6665 §4.1.4), or
     * `SIPRAL_HANDLE_NONE`. A sibling is a full subscription (RFC 4235
     * §3.9: one per device).
     */
    sipral_handle_t forked_from;
};

/**
 * What a SIPRAL_EVENT_KIND_CALL_ANNOUNCED and a
 * SIPRAL_EVENT_KIND_ANNOUNCED_CALL_MISSING carry.
 */
struct sipral_announce_event {
    /**
     * Which announcement, minted by `sipral_account_announce`. Stale once
     * either of these two events has been raised about it.
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
     * The handle
     * sipral_stack_resolved
     * takes; stale once the dialog ends.
     */
    sipral_handle_t dialog;
    /**
     * The host as the URI spells it; IPv6 literals keep brackets (RFC
     * 3261 §19.1.1). Not NUL-terminated.
     */
    const char *host;
    /**
     * How many bytes of it.
     */
    size_t host_len;
    /**
     * The URI's port, or zero for none. Zero is not 5060: an SRV answer
     * carries its own port (RFC 3263 §4.2).
     */
    uint32_t port;
    /**
     * The transport named, as a sipral_transport_t, or zero, leaving
     * §4.1's NAPTR step to the caller.
     */
    sipral_transport_t protocol;
};

/**
 * What the three message kinds carry; inapplicable members are zero.
 * `content_type` and `body` point into `sipral_event_t::message`.
 */
struct sipral_message_event {
    /**
     * SIPRAL_EVENT_KIND_MESSAGE_SENT: which send; stale after this.
     */
    sipral_handle_t message;
    /**
     * SIPRAL_EVENT_KIND_MESSAGES_WAITING: which subscription reported
     * it. SIPRAL_HANDLE_NONE on the other kinds.
     */
    sipral_handle_t subscription;
    /**
     * SIPRAL_EVENT_KIND_MESSAGE_SENT: the final status. Zero on the
     * other two kinds.
     */
    uint32_t status_code;
    /**
     * SIPRAL_EVENT_KIND_MESSAGE_RECEIVED: the body's `Content-Type`, as
     * written. Null on the other kinds and for an empty MESSAGE.
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
     * line, 1 for `yes` and 0 for `no`.
     */
    uint32_t waiting;
    /**
     * SIPRAL_EVENT_KIND_MESSAGES_WAITING: new `voice-message` messages
     * (RFC 3458 §6.2). Zero when the body had no such line.
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
     * SIPRAL_EVENT_KIND_MESSAGES_WAITING: `Message-Account`, when sent
     * (RFC 3842 §3.5). Null otherwise.
     */
    const char *message_account;
    /**
     * How many bytes of it.
     */
    size_t message_account_len;
};

/**
 * What a SIPRAL_EVENT_KIND_NAT_MAPPING carries.
 * The addresses are `host:port`, not NUL-terminated, valid only during the callback.
 */
struct sipral_nat_event {
    /**
     * A sipral_nat_mapping_t.
     */
    sipral_nat_mapping_t mapping;
    /**
     * Nonzero for a signalling socket, zero for a media socket.
     */
    uint32_t signalling;
    /**
     * The transport, when `signalling` is nonzero; zero otherwise.
     */
    uint32_t transport;
    /**
     * How many accounts' `Contact` moved to `public`; bound ones have registered it already.
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
     * The public address. Empty for `SIPRAL_NAT_MAPPING_UNANSWERED`.
     */
    const char *mapped;
    /**
     * How many bytes of it.
     */
    size_t mapped_len;
    /**
     * The old address, for `SIPRAL_NAT_MAPPING_MOVED`. Empty otherwise.
     */
    const char *previous;
    /**
     * How many bytes of it.
     */
    size_t previous_len;
};

/**
 * What a SIPRAL_EVENT_KIND_NAT_RELAY carries.
 * Text is not NUL-terminated, valid only during the callback, and holds no credential.
 */
struct sipral_nat_relay_event {
    /**
     * A sipral_nat_relay_t.
     */
    sipral_nat_relay_t outcome;
    /**
     * For `SIPRAL_NAT_RELAY_FAILED`, the STUN error code (401 bad credential, 486 quota, 508
     * no capacity), or zero when there was no usable answer. Zero for `ALLOCATED`.
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
     * The relayed `host:port`. Empty for `SIPRAL_NAT_RELAY_FAILED`.
     */
    const char *relayed;
    /**
     * How many bytes of it.
     */
    size_t relayed_len;
    /**
     * Where the server saw the socket from, when it said. Empty otherwise.
     */
    const char *mapped;
    /**
     * How many bytes of it.
     */
    size_t mapped_len;
    /**
     * Why there is no relay, in English. Empty for `SIPRAL_NAT_RELAY_ALLOCATED`.
     */
    const char *reason;
    /**
     * How many bytes of it.
     */
    size_t reason_len;
};

/**
 * What a SIPRAL_EVENT_KIND_REFERRAL carries: a REFER outside any
 * dialog, or the word that one lapsed.
 */
struct sipral_referral_event {
    /**
     * Zero while the referral waits. On the lapse event, the status the
     * stack answered (408), and every other member is zero or null.
     */
    uint32_t status_code;
    /**
     * Whether `Refer-To` named a dialog to replace (RFC 3891): an
     * attended transfer.
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
    /**
     * Its `Referred-By` (RFC 3892), UTF-8, unverified. Null when absent or
     * repeated (§2.1). Not NUL-terminated.
     */
    const char *referred_by;
    /**
     * How many bytes of it.
     */
    size_t referred_by_len;
};

/**
 * What a SIPRAL_EVENT_KIND_TURN_STREAM carries.
 * Addresses are not NUL-terminated, valid only during the callback.
 */
struct sipral_turn_stream_event {
    /**
     * A sipral_turn_stream_t.
     */
    sipral_turn_stream_t state;
    /**
     * `SIPRAL_TRANSPORT_TCP` or `SIPRAL_TRANSPORT_TLS`, as `turn_transport` named.
     */
    sipral_transport_t protocol;
    /**
     * The media socket; the connection's name in the calls that take one.
     */
    const char *local;
    /**
     * How many bytes of it.
     */
    size_t local_len;
    /**
     * The TURN server, `host:port`, as `turn_server` named it.
     */
    const char *server;
    /**
     * How many bytes of it.
     */
    size_t server_len;
};

/**
 * What `SIPRAL_EVENT_KIND_AUDIO_DEVICES_CHANGED` carries.
 */
struct sipral_audio_event {
    /**
     * A `sipral_audio_change_t`.
     */
    sipral_audio_change_t change;
    /**
     * A `sipral_audio_origin_t`.
     */
    sipral_audio_origin_t origin;
    /**
     * A `sipral_audio_role_t`, for a change about one role; zero otherwise.
     */
    sipral_audio_role_t role;
    /**
     * A `sipral_audio_direction_t`, for `SIPRAL_AUDIO_CHANGE_DEFAULT_CHANGED`;
     * zero otherwise.
     */
    sipral_audio_direction_t direction;
    /**
     * The device the change is about, or zero.
     */
    uint32_t device;
};

/**
 * What a SIPRAL_EVENT_KIND_STUN_SERVER carries.
 * Addresses are not NUL-terminated, valid only during the callback.
 */
struct sipral_stun_server_event {
    /**
     * A sipral_stun_server_state_t.
     */
    sipral_stun_server_state_t state;
    /**
     * The server in use now (`CHANGED`) or the last that failed (`ALL_FAILED`).
     */
    const char *server;
    /**
     * How many bytes of it.
     */
    size_t server_len;
    /**
     * For `CHANGED`, the previous server. Empty otherwise.
     */
    const char *previous;
    /**
     * How many bytes of it.
     */
    size_t previous_len;
};

/**
 * What a SIPRAL_EVENT_KIND_CALLER_VERIFICATION carries: one half of
 * the verification of who is calling (RFC 8224 §6.2).
 */
struct sipral_verification_event {
    /**
     * A sipral_verification_stage_t:
     * the certificate is wanted, or the verdict is in.
     */
    sipral_verification_stage_t stage;
    /**
     * A sipral_verification_outcome_t,
     * for a verdict.
     */
    sipral_verification_outcome_t outcome;
    /**
     * A sipral_verification_failure_t:
     * why it did not hold.
     */
    sipral_verification_failure_t failure;
    /**
     * A sipral_attestation_t: the
     * level a valid SHAKEN PASSporT claimed.
     */
    sipral_attestation_t attestation;
    /**
     * A sipral_verstat_t: the `verstat`
     * this verdict comes to (3GPP TS 24.229).
     */
    sipral_verstat_t verstat;
    /**
     * The response RFC 8224 §6.2.2 prescribes for the failure, zero for
     * a valid one. Sent only when `refused` is set.
     */
    uint32_t response_code;
    /**
     * Whether the call was refused with it, which only a strict account
     * does.
     */
    uint32_t refused;
    /**
     * The certificate URL: to fetch, or that was verified. UTF-8, not
     * NUL-terminated; null and zero when none.
     */
    const char *certificate_url;
    /**
     * How many bytes of it.
     */
    size_t certificate_url_len;
    /**
     * The calling number a valid PASSporT was signed for, canonical.
     */
    const char *orig;
    /**
     * How many bytes of it.
     */
    size_t orig_len;
    /**
     * The origination identifier a valid SHAKEN PASSporT claimed (RFC
     * 8588 §5), a UUID.
     */
    const char *origid;
    /**
     * How many bytes of it.
     */
    size_t origid_len;
    /**
     * Why it did not hold, in more words than `failure`, for a log.
     */
    const char *detail;
    /**
     * How many bytes of it.
     */
    size_t detail_len;
};

/**
 * What a SIPRAL_EVENT_KIND_PROGRESS_DETECTED carries. `what` says
 * which of the other members mean anything; the rest are zero.
 */
struct sipral_progress_event {
    /**
     * A sipral_progress_kind_t.
     */
    sipral_progress_kind_t what;
    /**
     * A sipral_progress_tone_t, for a tone.
     */
    sipral_progress_tone_t tone;
    /**
     * A sipral_amd_verdict_t, for who answered.
     */
    sipral_amd_verdict_t verdict;
    /**
     * A sipral_amd_reason_t, for who answered.
     */
    sipral_amd_reason_t reason;
    /**
     * When, in milliseconds: the tone's first burst, or after answer.
     */
    uint64_t at_ms;
    /**
     * How long after answer the first word began, or the silence if
     * nobody spoke.
     */
    uint64_t initial_silence_ms;
    /**
     * From the first word's start to the last word's end.
     */
    uint64_t greeting_ms;
    /**
     * How many words were heard.
     */
    uint32_t words;
    /**
     * The beep's frequency, in hertz, as measured.
     */
    uint32_t frequency_hz;
    /**
     * How long the beep sounded.
     */
    uint64_t length_ms;
    /**
     * The special information tone's first frequency, as measured.
     */
    uint32_t sit_hz_1;
    /**
     * Its second.
     */
    uint32_t sit_hz_2;
    /**
     * Its third.
     */
    uint32_t sit_hz_3;
    /**
     * How long the first sounded.
     */
    uint32_t sit_ms_1;
    /**
     * The second.
     */
    uint32_t sit_ms_2;
    /**
     * The third.
     */
    uint32_t sit_ms_3;
};

/**
 * What a SIPRAL_EVENT_KIND_CONFERENCE_CHANGED carries.
 */
struct sipral_conference_event {
    /**
     * Which subscription.
     */
    sipral_handle_t subscription;
    /**
     * A sipral_conference_update_t.
     */
    sipral_conference_update_t update;
    /**
     * The current document version; zero once ended.
     */
    uint32_t version;
    /**
     * How many users the picture holds.
     */
    uint32_t users;
};

/**
 * What a SIPRAL_EVENT_KIND_TEXT_RECEIVED carries; the
 * text is valid during the callback.
 */
struct sipral_text_event {
    /**
     * What the far end typed, UTF-8, not NUL-terminated.
     */
    const char *text;
    /**
     * How many bytes of it.
     */
    size_t text_len;
    /**
     * Unrecoverable lost blocks, each marked in `text` by U+FFFD.
     */
    uint32_t missing;
};

/**
 * What a SIPRAL_EVENT_KIND_PRESENCE_CHANGED carries. The
 * text is valid only during the callback.
 */
struct sipral_presence_event {
    /**
     * A sipral_presence_kind_t.
     */
    sipral_presence_kind_t kind;
    /**
     * SIPRAL_PRESENCE_KIND_WATCHED: which subscription;
     * `SIPRAL_HANDLE_NONE` for a publication.
     */
    sipral_handle_t subscription;
    /**
     * SIPRAL_PRESENCE_KIND_WATCHED: a sipral_basic_t, open when any
     * of the presentity's tuples is open.
     */
    sipral_basic_t basic;
    /**
     * SIPRAL_PRESENCE_KIND_WATCHED: a sipral_activity_t, the first
     * the person listed.
     */
    sipral_activity_t activity;
    /**
     * SIPRAL_PRESENCE_KIND_WATCHED: the presentity, as the document
     * named it. Not NUL-terminated.
     */
    const char *entity;
    /**
     * How many bytes of it.
     */
    size_t entity_len;
    /**
     * SIPRAL_PRESENCE_KIND_WATCHED: the first note, the document's
     * own or else a tuple's. Null when there is none.
     */
    const char *note;
    /**
     * How many bytes of it.
     */
    size_t note_len;
    /**
     * SIPRAL_PRESENCE_KIND_PUBLICATION: a sipral_publication_state_t.
     */
    sipral_publication_state_t publication_state;
    /**
     * SIPRAL_PRESENCE_KIND_PUBLICATION: a sipral_publish_failure_t
     * when the state is SIPRAL_PUBLICATION_STATE_FAILED.
     */
    sipral_publish_failure_t failure;
    /**
     * SIPRAL_PRESENCE_KIND_PUBLICATION: the status the compositor
     * answered with, when one did.
     */
    uint32_t status_code;
    /**
     * SIPRAL_PRESENCE_KIND_PUBLICATION: the lifetime granted, in
     * milliseconds, when it was published.
     */
    uint64_t expires_ms;
    /**
     * SIPRAL_PRESENCE_KIND_PUBLICATION: how long until the stack
     * refreshes it, in milliseconds.
     */
    uint64_t refresh_in_ms;
};

/**
 * `SIPRAL_EVENT_KIND_TRANSPORT_FAILED`: a signalling transport stopped carrying traffic.
 * The text is the library's, valid during the callback.
 */
struct sipral_transport_failed_event {
    /**
     * Which transport: SIPRAL_TRANSPORT_MAIN or a bound number.
     */
    uint32_t transport;
    /**
     * What it spoke, as a `sipral_transport_t`.
     */
    sipral_transport_t protocol;
    /**
     * A sipral_transport_error_t; `SIPRAL_TRANSPORT_ERROR_CLOSED` for a closed connection.
     */
    sipral_transport_error_t error;
    /**
     * A sipral_tls_failure_t, when TLS refused.
     */
    sipral_tls_failure_t tls;
    /**
     * The platform's sentence as handed over. Null with length zero for none.
     */
    const char *detail;
    /**
     * How many bytes of it.
     */
    size_t detail_len;
};

/**
 * What a `SIPRAL_EVENT_KIND_LOCAL_CONFERENCE_CHANGED` carries.
 */
struct sipral_local_conference_event {
    /**
     * The conference.
     */
    sipral_handle_t conference;
    /**
     * A sipral_local_conference_change_t.
     */
    sipral_local_conference_change_t change;
    /**
     * A sipral_departure_t, for `SIPRAL_LOCAL_CONFERENCE_CHANGE_LEFT`.
     */
    sipral_departure_t departure;
    /**
     * Who joined or left (a call, or the conference handle for this end);
     * `SIPRAL_HANDLE_NONE` otherwise.
     */
    sipral_handle_t member;
    /**
     * Members now, this end included.
     */
    uint32_t members;
    /**
     * Members talking now.
     */
    uint32_t talkers;
    /**
     * The loudest of them, or `SIPRAL_HANDLE_NONE`.
     */
    sipral_handle_t loudest;
};

/**
 * What a SIPRAL_EVENT_KIND_LOOKUP_WANTED,
 * a SIPRAL_EVENT_KIND_LOCATED
 * and a SIPRAL_EVENT_KIND_LOCATE_FAILED
 * carry, the account being `sipral_event_t::account`.
 *
 * A member meaningless on a kind is zero or null. Every pointer is the
 * library's, valid for the duration of the callback.
 */
struct sipral_locate_event {
    /**
     * A sipral_dns_record_type_t: what to ask `name` for, on a lookup.
     */
    sipral_dns_record_type_t record;
    /**
     * A sipral_locate_failure_t: why a lookup named no address.
     */
    sipral_locate_failure_t failure;
    /**
     * The name to ask, on a lookup: `_sip._udp.example.com`, or a
     * host. Handed back to sipral_account_looked_up with the answer.
     * UTF-8, not NUL-terminated.
     */
    const char *name;
    /**
     * How many bytes of it.
     */
    size_t name_len;
    /**
     * Every located address, comma-separated `host:port`, in RFC 3263
     * section 4.3 order, the one in use first. UTF-8, not NUL-terminated.
     */
    const char *targets;
    /**
     * How many bytes of it.
     */
    size_t targets_len;
    /**
     * Milliseconds until the retry after a failure; an earlier address
     * stays in use meanwhile.
     */
    uint64_t retry_in_ms;
};

/**
 * What a SIPRAL_EVENT_KIND_CHALLENGE_DECLINED carries: who asked for
 * the account's password, and why it was not given.
 */
struct sipral_challenge_event {
    /**
     * A sipral_challenge_refusal_t.
     */
    sipral_challenge_refusal_t refusal;
    /**
     * Where the challenged request went, as `host:port`. Not
     * NUL-terminated.
     */
    const char *server;
    /**
     * How many bytes of it.
     */
    size_t server_len;
    /**
     * The challenged realms, separated by line feeds (a realm may hold a
     * comma, never a line break). UTF-8, not NUL-terminated.
     */
    const char *realms;
    /**
     * How many bytes of it.
     */
    size_t realms_len;
};

/**
 * What a SIPRAL_EVENT_KIND_TOKEN_REQUIRED carries (RFC 8898 §4).
 * Texts are UTF-8, not NUL-terminated, empty when absent.
 */
struct sipral_token_event {
    /**
     * A sipral_token_error_t.
     */
    sipral_token_error_t error;
    /**
     * A `sipral_toggle_t`: on for a proxy's 407, off for a 401.
     */
    sipral_toggle_t proxy;
    /**
     * Where the challenged request went, as `host:port`.
     */
    const char *server;
    /**
     * How many bytes of it.
     */
    size_t server_len;
    /**
     * The protection domain, empty when the challenge named none.
     */
    const char *realm;
    /**
     * How many bytes of it.
     */
    size_t realm_len;
    /**
     * The scope the token has to carry: space-separated strings the
     * authorization server defines (RFC 6749 §3.3).
     */
    const char *scope;
    /**
     * How many bytes of it.
     */
    size_t scope_len;
    /**
     * The authorization server: an `https` URI, or empty if it was not one.
     */
    const char *authz_server;
    /**
     * How many bytes of it.
     */
    size_t authz_server_len;
    /**
     * The `error` code as the server wrote it, for `Other`.
     */
    const char *error_code;
    /**
     * How many bytes of it.
     */
    size_t error_code_len;
};

/**
 * What a SIPRAL_EVENT_KIND_NETWORK_TEST
 * carries (ABI 1.2). The event's `account` and `call` are the probed
 * account and the echo call. The addresses are `host:port`, not
 * NUL-terminated, owned by the library, valid during the callback.
 */
struct sipral_network_test_event {
    /**
     * The number sipral_stack_network_test gave the test.
     */
    uint32_t test;
    /**
     * A sipral_network_verdict_t: the worst of the parts tested.
     */
    sipral_network_verdict_t verdict;
    /**
     * A sipral_network_probe_t: whether a STUN server answered.
     */
    sipral_network_probe_t stun;
    /**
     * A sipral_nat_kind_t, from that answer.
     */
    sipral_nat_kind_t nat;
    /**
     * A sipral_network_probe_t: whether a TURN relay was allocated.
     */
    sipral_network_probe_t turn;
    /**
     * A `sipral_transport_t` the TURN server was reached over, or zero.
     */
    sipral_transport_t turn_protocol;
    /**
     * A sipral_server_reach_t.
     */
    sipral_server_reach_t server;
    /**
     * The status the server answered with, or zero.
     */
    uint32_t server_status;
    /**
     * From sending the `OPTIONS` to its answer, in milliseconds.
     */
    uint32_t server_round_trip_ms;
    /**
     * A sipral_network_probe_t: whether echo audio came back.
     */
    sipral_network_probe_t echo;
    /**
     * A sipral_network_verdict_t for the echo alone.
     */
    sipral_network_verdict_t echo_verdict;
    /**
     * Packets lost or too late to play, as a percentage of those due.
     */
    float loss_percent;
    /**
     * Interarrival jitter (RFC 3550 §6.4.1), in milliseconds.
     */
    float jitter_ms;
    /**
     * Nonzero when RTCP brought a round trip back in time.
     */
    uint32_t has_round_trip;
    /**
     * That round trip, in milliseconds.
     */
    uint32_t round_trip_ms;
    /**
     * Half the round trip plus jitter buffer delay, in milliseconds.
     */
    uint32_t one_way_delay_ms;
    /**
     * G.107's transmission rating R, 0 to 100, for concealed G.711.
     */
    uint32_t r_factor;
    /**
     * Conversational MOS estimated from R, 1.0 to 4.5.
     */
    float mos;
    /**
     * The socket the STUN answer was about.
     */
    const char *local;
    /**
     * How many bytes of it.
     */
    size_t local_len;
    /**
     * Where the STUN server saw it. Empty without an answer.
     */
    const char *mapped;
    /**
     * How many bytes of it.
     */
    size_t mapped_len;
};

/**
 * The arm of an event that its kind names. The rest of the union is
 * zeroed, so members appended later read as zero.
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
     * For the three transfer kinds.
     */
    sipral_transfer_event_t transfer;
    /**
     * For every media kind.
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
     * For the three message kinds.
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
    /**
     * For SIPRAL_EVENT_KIND_REFERRAL.
     */
    sipral_referral_event_t referral;
    /**
     * For SIPRAL_EVENT_KIND_TURN_STREAM.
     */
    sipral_turn_stream_event_t turn_stream;
    /**
     * For SIPRAL_EVENT_KIND_AUDIO_DEVICES_CHANGED.
     */
    sipral_audio_event_t audio;
    /**
     * For SIPRAL_EVENT_KIND_STUN_SERVER.
     */
    sipral_stun_server_event_t stun_server;
    /**
     * For SIPRAL_EVENT_KIND_CALLER_VERIFICATION.
     */
    sipral_verification_event_t verification;
    /**
     * For SIPRAL_EVENT_KIND_PROGRESS_DETECTED.
     */
    sipral_progress_event_t progress;
    /**
     * For SIPRAL_EVENT_KIND_CONFERENCE_CHANGED.
     */
    sipral_conference_event_t conference;
    /**
     * For SIPRAL_EVENT_KIND_TEXT_RECEIVED.
     */
    sipral_text_event_t text;
    /**
     * For SIPRAL_EVENT_KIND_PRESENCE_CHANGED.
     */
    sipral_presence_event_t presence;
    /**
     * For SIPRAL_EVENT_KIND_TRANSPORT_FAILED.
     */
    sipral_transport_failed_event_t transport_failed;
    /**
     * For SIPRAL_EVENT_KIND_LOCAL_CONFERENCE_CHANGED.
     */
    sipral_local_conference_event_t local_conference;
    /**
     * For SIPRAL_EVENT_KIND_LOOKUP_WANTED, SIPRAL_EVENT_KIND_LOCATED
     * and SIPRAL_EVENT_KIND_LOCATE_FAILED.
     */
    sipral_locate_event_t locate;
    /**
     * For SIPRAL_EVENT_KIND_CHALLENGE_DECLINED.
     */
    sipral_challenge_event_t challenge;
    /**
     * For SIPRAL_EVENT_KIND_TOKEN_REQUIRED.
     */
    sipral_token_event_t token;
    /**
     * For SIPRAL_EVENT_KIND_NETWORK_TEST.
     */
    sipral_network_test_event_t network_test;
};

/**
 * Something the library has to tell the application.
 *
 * Library-owned, valid for the callback only. Read no further than
 * `size`; the union stays last so growth only extends the tail.
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
     * The SIP message behind it, whole and unparsed, or null.
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
 * What was standing when sipral_stack_suspending was called. Set
 * `size` to `sizeof(sipral_suspending_t)` first.
 *
 * Counts only: no allocation in the suspend window. All of it is past
 * tense when read, and nothing was sent about any of it.
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
     * Calls that were up, left untouched: hanging up because the machine
     * blinked is worse than learning later that a call is gone.
     */
    size_t calls;
};

/**
 * What sipral_screen_callback_t reads about one INVITE, before it has
 * had any effect.
 *
 * Read `size` first, like sipral_event_t. `message` and
 * `source` borrow from a request still being processed: read nothing after
 * the callback returns.
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
     * The far end of the bytes, as `host:port`. Null and zero for a byte
     * stream bound without naming its far end.
     */
    const char *source;
    /**
     * How many bytes of it.
     */
    size_t source_len;
    /**
     * The INVITE, whole and unparsed; `sipral_message_header` and its
     * companions read headers out of it.
     */
    const uint8_t *message;
    /**
     * How many bytes of it.
     */
    size_t message_len;
};

/**
 * What to watch, and how. Handed to sipral_account_subscribe. Set
 * `size` to `sizeof(sipral_subscribe_config_t)`; all but `target` and
 * `package` may be zero.
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
     * The event package token: `dialog` for a busy lamp field (RFC 4235
     * §3.1), `message-summary` (RFC 3842 §3), `presence` (RFC 3856 §6.1).
     * Sent exactly as written, since §8.2.1 compares it byte for byte.
     */
    const char *package;
    /**
     * How many bytes of it.
     */
    size_t package_len;
    /**
     * The `Accept` value, when the package's default body type is not
     * wanted. Null sends none, which means the default (§3.1.3); a wrong
     * one gets 406 (§4.1.2.1), so nothing is guessed.
     */
    const char *accept;
    /**
     * How many bytes of it.
     */
    size_t accept_len;
    /**
     * Seconds to ask for, or zero for one hour. The notifier's grant wins
     * (§3.1.1), and the refresh follows the grant.
     */
    uint32_t expires_seconds;
    /**
     * Where to send the SUBSCRIBE, as `host:port`, or null for where the
     * account registers (the outbound proxy, which keeps NAT working).
     */
    const char *destination;
    /**
     * How many bytes of it.
     */
    size_t destination_len;
    /**
     * The transport, read only with `destination`, as
     * `sipral_call_config_t::transport` is. Nonzero without `destination`
     * is `SIPRAL_STATUS_INVALID_ARGUMENT`.
     */
    uint32_t transport;
    /**
     * Zero. Pads the struct to a multiple of its alignment, so a member
     * appended later never lands in padding. Never read.
     */
    uint32_t reserved;
};

/**
 * One dialog a `dialog` subscription was told about. Its text is read
 * with sipral_subscription_dialog_text, so no pointer can dangle.
 */
struct sipral_watched_dialog {
    /**
     * How many bytes of this struct the library filled in.
     */
    size_t size;
    /**
     * A sipral_dialog_phase_t.
     */
    sipral_dialog_phase_t phase;
    /**
     * A sipral_dialog_direction_t.
     */
    sipral_dialog_direction_t direction;
    /**
     * A sipral_dialog_ended_t, and zero while the dialog has not.
     */
    sipral_dialog_ended_t ended;
    /**
     * The SIP status behind how it ended, or zero.
     */
    uint32_t status_code;
    /**
     * How long it has been up, in milliseconds, or zero.
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
     * Whether the network promised pushes of the requested type. Zero
     * means not promised (§4.1.1): do not suspend relying on a push.
     */
    uint32_t accepted;
    /**
     * Whether `refresh_lead_ms` was sent at all.
     */
    uint32_t has_refresh_lead;
    /**
     * How long before expiry the network wants a refresh, from
     * `sip.pnsreg` (§4.1.4), in milliseconds; zero when not sent.
     */
    uint64_t refresh_lead_ms;
};

/**
 * One device, as `sipral_audio_device_at` fills it in. Set `size` to
 * `sizeof(sipral_audio_device_t)` before the call.
 */
struct sipral_audio_device {
    /**
     * How many bytes of this struct the library filled in.
     */
    size_t size;
    /**
     * The engine's name for the device: stable across refreshes, never
     * reused, never zero. What `sipral_audio_select` takes.
     */
    uint32_t id;
    /**
     * Channels it captures; zero for a device that is no microphone.
     */
    uint32_t input_channels;
    /**
     * How many channels it plays; zero likewise.
     */
    uint32_t output_channels;
    /**
     * One when the system records from it by default.
     */
    uint32_t default_input;
    /**
     * One when the system plays to it by default.
     */
    uint32_t default_output;
    /**
     * One when the last refresh found it. An absent device keeps its row
     * and id, so a saved selection still names something.
     */
    uint32_t present;
};

/**
 * What the engine is doing, as `sipral_audio_info` fills it in. Set
 * `size` to `sizeof(sipral_audio_info_t)` before the call.
 */
struct sipral_audio_info {
    /**
     * How many bytes of this struct the library filled in.
     */
    size_t size;
    /**
     * One while the devices are open and the pump is running.
     */
    uint32_t active;
    /**
     * One when the platform's own processing sits behind the microphone:
     * the voice-processing unit on macOS and iOS, a communications stream
     * on Windows (a virtual cable cancels nothing). For echo removal
     * regardless, attach a processor per call; the engine tells each
     * managed call `render_delay_ms` itself, after every device change.
     */
    uint32_t system_echo_cancellation;
    /**
     * The loudspeaker-to-microphone delay the devices report, in
     * milliseconds.
     */
    uint64_t render_delay_ms;
    /**
     * The rate the microphone runs at, or zero when it is not open.
     */
    uint32_t microphone_rate_hz;
    /**
     * The rate the loudspeaker runs at, or zero when it is not open.
     */
    uint32_t speaker_rate_hz;
    /**
     * The device the microphone is running on, or zero.
     */
    uint32_t microphone;
    /**
     * The device the loudspeaker is running on, or zero.
     */
    uint32_t speaker;
    /**
     * The device the ringer is running on, or zero when the ring goes
     * through the loudspeaker.
     */
    uint32_t ringer;
    /**
     * Zero. Pads the struct to a multiple of its alignment, so a member
     * appended later never lands in padding. Written zero, never read.
     */
    uint32_t reserved;
};

/**
 * One packet the engine encoded, handed to
 * `sipral_stack_config_t::audio_transmit_callback`: send it from the
 * call's media socket and return.
 *
 * Read `size` before anything past it, and nothing once the callback
 * returns. The callback runs on the engine's thread, once per frame per
 * call; it may call the media entry points and must not destroy the stack.
 */
struct sipral_audio_transmit {
    /**
     * How many bytes of this struct the library filled in.
     */
    size_t size;
    /**
     * The call whose socket this leaves from.
     */
    sipral_handle_t call;
    /**
     * A `sipral_transport_t`: UDP is a datagram from the media socket; TCP
     * and TLS are bytes to write in order on the socket's TURN connection.
     */
    sipral_transport_t protocol;
    /**
     * Zero. Keeps later members at the same offsets on 32- and 64-bit
     * targets. Written zero, never read.
     */
    uint32_t reserved;
    /**
     * Where to send it, `host:port`, UTF-8 and not NUL-terminated.
     */
    const char *destination;
    /**
     * How many bytes of it.
     */
    size_t destination_len;
    /**
     * The octets.
     */
    const uint8_t *payload;
    /**
     * How many of them.
     */
    size_t payload_len;
};

/**
 * One log line, as sipral_log_callback_t reads it.
 *
 * Read `size` first, and nothing after the callback returns: the strings
 * live for the call only.
 */
struct sipral_log_record {
    /**
     * How many bytes of this struct the library filled in.
     */
    size_t size;
    /**
     * The stack the line is about.
     */
    sipral_handle_t stack;
    /**
     * A `sipral_log_level_t`, never `SIPRAL_LOG_LEVEL_OFF`.
     */
    sipral_log_level_t level;
    /**
     * Which part of the stack wrote it — `registration`, `call`,
     * `media`, `decision`, `sip`, `api` — as UTF-8, not NUL-terminated.
     */
    const char *target;
    /**
     * How many bytes of it.
     */
    size_t target_len;
    /**
     * The line, already redacted, as UTF-8, not NUL-terminated. A
     * `SIPRAL_LOG_LEVEL_TRACE` line holding a whole message has line
     * breaks in it.
     */
    const char *message;
    /**
     * How many bytes of it.
     */
    size_t message_len;
    /**
     * Lines dropped by the rate limit or queue since the previous line.
     */
    uint64_t suppressed;
};

/**
 * How a stack verifies the callers of the calls its accounts receive.
 *
 * Set `size` to `sizeof(sipral_stir_config_t)` and zero the rest first.
 */
struct sipral_stir_config {
    /**
     * `sizeof` this struct, as the caller's header declares it.
     */
    size_t size;
    /**
     * Trust anchors (in SHAKEN, the STI-PA roots), PEM or DER,
     * concatenated. Null and zero for none: reporting accounts then verify
     * nothing.
     */
    const uint8_t *anchors;
    /**
     * How many bytes of them.
     */
    size_t anchors_len;
    /**
     * Allowed `iat` skew either way, in seconds; zero for 60 (RFC 8224 §6.2).
     */
    uint64_t freshness_seconds;
    /**
     * How long a call waits for `sipral_call_stir_certificate`, in ms,
     * before the certificate counts as unavailable; zero for 4000.
     */
    uint64_t certificate_wait_ms;
    /**
     * The wall clock at `now_ms`, in Unix seconds, or zero to keep the
     * previous one. The first call must set it. Not taken from
     * `sipral_stack_config_t::media_clock_unix_seconds`, which has no
     * `now_ms`. A stack with no media clock also dates RTCP sender reports
     * by it.
     */
    uint64_t unix_seconds;
    /**
     * A `sipral_toggle_t`: whether a TNAuthList service provider code
     * (RFC 8226 §9) covers every calling number. Off by default; a SHAKEN
     * deployment, whose certificates carry codes, turns it on. ABI 0.32.
     */
    sipral_toggle_t accept_service_provider_codes;
    /**
     * Zero. Pads the struct to its alignment so an appended member starts
     * past the declared length. Never read.
     */
    uint32_t reserved;
};

/**
 * How one stream of a call is protected.
 *
 * Set `size` to `sizeof(sipral_stream_encryption_t)` before the call.
 */
struct sipral_stream_encryption {
    /**
     * How many bytes of this struct the library filled in.
     */
    size_t size;
    /**
     * A sipral_media_kind_t: what the stream carries.
     */
    sipral_media_kind_t media;
    /**
     * Whether it is encrypted now. Zero while waiting for its keys.
     */
    uint32_t encrypted;
    /**
     * A sipral_key_exchange_t: how its keys were exchanged.
     */
    sipral_key_exchange_t key_exchange;
    /**
     * A sipral_srtp_suite_t: the transform it runs, once it runs one.
     */
    sipral_srtp_suite_t suite;
    /**
     * Whether the key exchange authenticated the far end: set for
     * DTLS-SRTP after a handshake matching the fingerprint; never for
     * SDES, which is only as authentic as the signalling.
     */
    uint32_t authenticated;
    /**
     * Agreed to be encrypted and still waiting for keys.
     */
    uint32_t awaiting_keys;
};

/**
 * How sipral_call_detect_progress listens. A zero member is its
 * default. Set `size` to `sizeof(sipral_progress_config_t)`.
 */
struct sipral_progress_config {
    /**
     * `sizeof` this struct, as the caller's header declares it.
     */
    size_t size;
    /**
     * A `sipral_toggle_t`: on (the default) listens with what follows,
     * off stops listening and reads nothing else.
     */
    sipral_toggle_t listen;
    /**
     * A sipral_tone_region_t. Europe by default.
     */
    sipral_tone_region_t region;
    /**
     * A `sipral_toggle_t`: whether to decide who answered. On by default.
     */
    sipral_toggle_t answering_machine;
    /**
     * A `sipral_toggle_t`: whether to listen for the beep after a verdict
     * of a machine. On by default.
     */
    sipral_toggle_t beep;
    /**
     * How long after the verdict to listen for the beep. Thirty
     * seconds by default.
     */
    uint32_t beep_window_ms;
    /**
     * The longest silence after answer before the verdict is not sure.
     * 3000 by default.
     */
    uint32_t max_initial_silence_ms;
    /**
     * The longest greeting a person gives. 1600 by default.
     */
    uint32_t max_greeting_ms;
    /**
     * The silence after a greeting that says a person is waiting. 700
     * by default.
     */
    uint32_t silence_after_greeting_ms;
    /**
     * The most words a person's greeting has. 4 by default.
     */
    uint32_t max_words;
    /**
     * The shortest run of speech that is a word. 120 by default.
     */
    uint32_t min_word_ms;
    /**
     * The shortest silence that separates two words. 60 by default.
     */
    uint32_t min_word_gap_ms;
    /**
     * The longest the decision may take, from answer. 6000 by default.
     */
    uint32_t max_decision_ms;
    /**
     * How far above the noise floor a frame must be to be speech, in
     * dB. 6 by default.
     */
    uint32_t min_speech_above_floor_db;
    /**
     * The shortest beep. 120 by default.
     */
    uint32_t beep_min_ms;
    /**
     * The longest beep: anything held longer is a tone, not a beep.
     * This build's own default unless set.
     */
    uint32_t beep_max_ms;
    /**
     * How many whole cycles of a repeating cadence are heard before the
     * tone is reported, from one to four. One by default.
     */
    uint32_t tone_cycles;
};

/**
 * The beep sipral_call_consent_tone plays. A zero member is its
 * default. Set `size` to `sizeof(sipral_consent_tone_t)`.
 */
struct sipral_consent_tone {
    /**
     * `sizeof` this struct, as the caller's header declares it.
     */
    size_t size;
    /**
     * A `sipral_toggle_t`: on (the default) beeps as what follows says,
     * off plays no tone and reads nothing else.
     */
    sipral_toggle_t enabled;
    /**
     * Its frequency, from 300 to 3400 Hz. 1400 by default.
     */
    uint32_t frequency_hz;
    /**
     * How far below 0 dBm0 it sounds, from 3 to 40 dB: 18 is a beep at
     * −18 dBm0, the default.
     */
    uint32_t attenuation_db;
    /**
     * How long each beep lasts, from 50 to 2000 ms. 200 by default.
     */
    uint32_t length_ms;
    /**
     * How often it repeats, start to start: longer than a beep and at
     * most ten minutes. Fifteen seconds by default.
     */
    uint32_t interval_ms;
    /**
     * A `sipral_toggle_t`: whether this end hears it too. On by default.
     */
    sipral_toggle_t local;
};

/**
 * How sipral_media_record_start_with writes a recording. Zero in
 * every member but `size` is sipral_media_record_start's file.
 *
 * Set `size` to `sizeof(sipral_recording_options_t)` before the call.
 */
struct sipral_recording_options {
    /**
     * `sizeof` this struct, as the caller's header declares it.
     */
    size_t size;
    /**
     * A sipral_recording_format_t.
     */
    sipral_recording_format_t format;
    /**
     * A sipral_recording_layout_t.
     */
    sipral_recording_layout_t layout;
    /**
     * The rate the file is written at, in hertz, or zero for the rate the
     * call's codec hears at when the recording starts (48 kHz for Ogg
     * Opus on a call at a rate Opus does not take). WAV takes 8000 to
     * 48000; Ogg Opus takes 8000, 12000, 16000, 24000 and 48000.
     */
    uint32_t sample_rate;
    /**
     * An Ogg Opus recording's bitrate in bits a second, all channels
     * together, or zero for libopus's own choice. Not read for WAV.
     */
    uint32_t bitrate;
    /**
     * How often, in milliseconds, what has been written is made to
     * survive a crash, or zero for every five seconds.
     */
    uint32_t checkpoint_ms;
    /**
     * Zero; never read. Pads the struct to its alignment so a member added
     * later never lands in padding of an older caller's struct.
     */
    uint32_t reserved;
};

/**
 * A conference as a `conference` subscription holds it, read with
 * sipral_subscription_conference.
 */
struct sipral_conference {
    /**
     * How many bytes of this struct the library filled in.
     */
    size_t size;
    /**
     * The version of the last document merged.
     */
    uint32_t version;
    /**
     * Users held, indexed by sipral_subscription_conference_user_at.
     */
    uint32_t users;
    /**
     * Whether `user-count` was sent; it may differ from `users`.
     */
    uint32_t has_user_count;
    /**
     * That count, when it said.
     */
    uint32_t user_count;
    /**
     * `active`: 1 true, 2 false, 0 not said.
     */
    uint32_t active;
    /**
     * Its `locked`, the same way.
     */
    uint32_t locked;
};

/**
 * One user of a conference, read with
 * sipral_subscription_conference_user_at; its text is read with
 * sipral_subscription_conference_text.
 */
struct sipral_conference_user {
    /**
     * How many bytes of this struct the library filled in.
     */
    size_t size;
    /**
     * How many endpoints (devices) the user joined from.
     */
    uint32_t endpoints;
    /**
     * A sipral_endpoint_status_t of the first endpoint.
     */
    sipral_endpoint_status_t status;
    /**
     * Media streams of the first endpoint.
     */
    uint32_t media;
    /**
     * Zero. Pads to alignment so later members never land in padding.
     */
    uint32_t reserved;
};

/**
 * This account's presence for sipral_account_publish_presence. Set
 * `size` to `sizeof(sipral_presence_t)` and zero the rest first.
 */
struct sipral_presence {
    /**
     * `sizeof` this struct, as the caller's header declares it.
     */
    size_t size;
    /**
     * A sipral_basic_t, open or closed. Required.
     */
    sipral_basic_t basic;
    /**
     * A sipral_activity_t; SIPRAL_ACTIVITY_NONE publishes no
     * person at all. SIPRAL_ACTIVITY_OTHER is refused: there is no
     * name to publish it under.
     */
    sipral_activity_t activity;
    /**
     * A note a buddy list shows beside the name, UTF-8 and not
     * NUL-terminated, or null for none.
     */
    const char *note;
    /**
     * How many bytes of it.
     */
    size_t note_len;
};

/**
 * Where a call is recorded, as sipral_call_record_to takes it.
 *
 * Set `size` to `sizeof(sipral_record_config_t)` and zero the rest
 * before filling anything in.
 */
struct sipral_record_config {
    /**
     * `sizeof` this struct, as the caller's header declares it.
     */
    size_t size;
    /**
     * The recording server's URI. Required, not NUL-terminated.
     */
    const char *server;
    /**
     * How many bytes of it.
     */
    size_t server_len;
    /**
     * `host:port` to send the INVITE to; null for the account's route.
     */
    const char *destination;
    /**
     * How many bytes of it.
     */
    size_t destination_len;
    /**
     * The transport for `destination`, as in
     * `sipral_call_config_t::transport`; read only with `destination`.
     */
    uint32_t transport;
    /**
     * Required bound socket, `host:port`, for this end's audio (label `1`).
     */
    const char *this_end;
    /**
     * How many bytes of it.
     */
    size_t this_end_len;
    /**
     * Required distinct socket for the far end's audio (label `2`).
     */
    const char *far_end;
    /**
     * How many bytes of it.
     */
    size_t far_end_len;
};

/**
 * How `sipral_local_conference_create` makes a conference. All zero but
 * `size`: sixteen members, this end in, 16 kHz.
 *
 * Set `size` to `sizeof(sipral_local_conference_config_t)` first.
 */
struct sipral_local_conference_config {
    /**
     * `sizeof` this struct, as the caller's header declares it.
     */
    size_t size;
    /**
     * Most members at once, this end included; zero for 16, at most 1024.
     */
    uint32_t max_members;
    /**
     * A `sipral_toggle_t`: whether this end takes part. On unless
     * `SIPRAL_TOGGLE_OFF`; without it the conference only bridges calls.
     */
    sipral_toggle_t local;
    /**
     * This end's frame rate in application mode, in Hz: 8000, 16000,
     * 32000 or 48000, zero for 16000. A tick is 20 ms of it. In device
     * mode the engine converts the devices to it.
     */
    uint32_t sample_rate;
    /**
     * Zero. Pads the struct to its alignment so an appended member starts
     * past the declared length. Never read.
     */
    uint32_t reserved;
};

/**
 * A conference as it stands: `sipral_local_conference_info`.
 *
 * Set `size` to `sizeof(sipral_local_conference_info_t)` first.
 */
struct sipral_local_conference_info {
    /**
     * How many bytes of this struct the library filled in.
     */
    size_t size;
    /**
     * Members, this end included.
     */
    uint32_t members;
    /**
     * The most it holds.
     */
    uint32_t capacity;
    /**
     * Members talking in the last tick.
     */
    uint32_t talkers;
    /**
     * 1 when this end takes part.
     */
    uint32_t local;
    /**
     * The rate of this end's frames, in hertz.
     */
    uint32_t sample_rate;
    /**
     * Samples in one of this end's frames: twenty milliseconds.
     */
    uint32_t frame_samples;
    /**
     * 1 while the conference is being recorded.
     */
    uint32_t recording;
    /**
     * Recorded so far, while recording.
     */
    uint64_t recorded_ms;
    /**
     * Packets dropped because nobody polled for them in time.
     */
    uint64_t packets_dropped;
};

/**
 * One member of a conference: `sipral_local_conference_member_at`.
 *
 * Set `size` to `sizeof(sipral_local_conference_member_t)` first.
 */
struct sipral_local_conference_member {
    /**
     * How many bytes of this struct the library filled in.
     */
    size_t size;
    /**
     * The call, or the conference's own handle for this end.
     */
    sipral_handle_t member;
    /**
     * 1 when it was talking in the last tick, muted or not.
     */
    uint32_t talking;
    /**
     * 1 when nobody hears it.
     */
    uint32_t muted_input;
    /**
     * 1 when it hears nothing.
     */
    uint32_t muted_output;
    /**
     * Level of what it says, in `sipral_audio_set_gain` steps (256 = unity).
     */
    uint32_t gain_input;
    /**
     * The level of what it hears, in the same steps.
     */
    uint32_t gain_output;
    /**
     * Zero. Pads the struct to its alignment so an appended member starts
     * past the declared length. Written as zero, never read.
     */
    uint32_t reserved;
};

/**
 * What sipral_account_check_certificate found: whether the account's
 * pin decided, and what the certificate's dates say.
 *
 * Set `size` to `sizeof(sipral_pinned_certificate_t)` before the call.
 */
struct sipral_pinned_certificate {
    /**
     * How many bytes of this struct the library filled in.
     */
    size_t size;
    /**
     * The certificate's `notBefore`, in seconds since 1 January 1970,
     * or zero when its DER could not be read that far.
     */
    uint64_t not_before;
    /**
     * Its `notAfter`, the same way.
     */
    uint64_t not_after;
    /**
     * One: pinned and matching, accept. Zero: no pin, platform checks apply.
     */
    uint32_t pinned;
    /**
     * One when past `not_after`. Still accepted (a lapsed self-signed PBX
     * would go silent); worth a warning.
     */
    uint32_t expired;
    /**
     * One when before `not_before`. Still accepted.
     */
    uint32_t not_yet_valid;
    /**
     * Zero.
     */
    uint32_t reserved;
};

/**
 * What sipral_stack_network_test tests. Zero in any member but
 * `size` leaves that part out or takes its default.
 *
 * Set `size` to `sizeof(sipral_network_test_config_t)` before the call.
 */
struct sipral_network_test_config {
    /**
     * `sizeof` this struct, as the caller's header declares it.
     */
    size_t size;
    /**
     * The account whose server to probe, or `SIPRAL_HANDLE_NONE`.
     */
    sipral_handle_t account;
    /**
     * A UDP socket the application bound for the test, `host:port`, not
     * NUL-terminated; null for the signalling socket only and no relay.
     */
    const char *probe_socket;
    /**
     * How many bytes of it.
     */
    size_t probe_socket_len;
    /**
     * A call to an echo service, hung up by the test, or `SIPRAL_HANDLE_NONE`.
     */
    sipral_handle_t echo_call;
    /**
     * How long the echo is measured. 8000 by default.
     */
    uint32_t echo_ms;
    /**
     * Test deadline, 30000 by default; a part silent by then failed.
     */
    uint32_t timeout_ms;
};

/**
 * Copy the calling thread's last error message into `buffer`.
 *
 * UTF-8 with a trailing NUL. `out_needed`, when not null, always receives
 * the size including the NUL; a null buffer with capacity zero returns
 * it with `SIPRAL_STATUS_BUFFER_TOO_SMALL`. A buffer too small gets
 * nothing, never a truncated message.
 *
 * It describes this thread's last call: the next call replaces it, a
 * success empties it, and this call leaves it alone.
 *
 * Safety
 *
 * `buffer` must be writable for `capacity` bytes or null with a capacity
 * of zero, and `out_needed` must point to one `size_t` or be null.
 */
sipral_status_t sipral_last_error_message(char *buffer, size_t capacity, size_t *out_needed);

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
 * `major`.`minor`: same major and a minor no later than this library's.
 * Called once at load, before anything else.
 *
 * `SIPRAL_STATUS_UNSUPPORTED_VERSION` otherwise, with a last error naming
 * both versions. The patch never changes a declaration, so it is not asked.
 *
 * Safety
 *
 * Reads no memory the caller owns, and is safe to call from any thread.
 */
sipral_status_t sipral_abi_check(uint32_t major, uint32_t minor);

/**
 * How many bytes this build compiled one of the ABI's structs to.
 *
 * `name` is the header's type name, e.g. `sipral_stack_config_t`. An
 * unknown name is `SIPRAL_STATUS_INVALID_ARGUMENT`. Lets a binding detect
 * a header mismatch at load.
 *
 * Safety
 *
 * `name` must be readable for `name_len` bytes, and `out_size` must
 * point at one `size_t`.
 */
sipral_status_t sipral_abi_struct_size(const char *name, size_t name_len, size_t *out_size);

/**
 * How many of the ABI's structs carry a `size` member.
 * Compare it with the caller's own list of structs, so a struct added to
 * the ABI is not missed by `sipral_abi_struct_size` checks.
 *
 * Safety
 *
 * `out_count` must point at one `size_t`.
 */
sipral_status_t sipral_abi_versioned_count(size_t *out_count);

/**
 * What this build of the library can do, in one call.
 *
 * Answers the same before and after any stack exists. Safe from any
 * thread, including the event callback.
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
 * The handle is written only on `SIPRAL_STATUS_OK` and must be freed with
 * sipral_stack_destroy. A process holds 256 stacks; the next is
 * `SIPRAL_STATUS_EXHAUSTED` until one is destroyed and no poll still runs on it.
 *
 * Safety
 *
 * `config` must point at a `sipral_stack_config_t` whose `size` member
 * says how long it is, with every pointer in it readable for the length
 * beside it, and `out_stack` at one `sipral_handle_t`.
 */
sipral_status_t sipral_stack_create(const sipral_stack_config_t *config, sipral_handle_t *out_stack);

/**
 * Read back what a stack is running with, defaults filled in.
 *
 * Safety
 *
 * `out_settings` must point at a `sipral_stack_settings_t` whose `size`
 * member says how long it is.
 */
sipral_status_t sipral_stack_settings(sipral_handle_t stack, sipral_stack_settings_t *out_settings);

/**
 * Destroy a stack. The handle is dead on return; a second destroy is
 * `SIPRAL_STATUS_STALE_HANDLE`. Safe inside the callback. Inside a frame of one
 * of its calls it is `SIPRAL_STATUS_BUSY`. Nothing is sent: hang up, unmap and
 * send what `sipral_stack_poll_farewell` and `sipral_stack_poll_stun` give
 * first, or TURN relays linger up to ten minutes.
 *
 * Safety
 *
 * Safe to call with any handle value. Reads no memory the caller owns.
 */
sipral_status_t sipral_stack_destroy(sipral_handle_t stack);

/**
 * Let the stack do its work, and deliver what it has to say.
 *
 * `now_ms` is the caller's monotonic clock in milliseconds; more than fifty
 * behind is `SIPRAL_STATUS_CLOCK_BEHIND`. The callback runs inside this call,
 * on this thread, with nothing held. `result` may be null. Drain
 * `sipral_stack_poll_transmit` after every poll (`docs/08-ffi.md`).
 *
 * Safety
 *
 * `result` must be null or point at a `sipral_poll_result_t` whose `size`
 * member says how long it is.
 */
sipral_status_t sipral_stack_poll(sipral_handle_t stack, uint64_t now_ms, sipral_poll_result_t *result);

/**
 * D3's health counters for one stack, since it was created.
 * One struct copy, cheap enough to sample on a timer.
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
 * Every INVITE that passes sipral_stack_invite_limit reaches this
 * callback before ringing, before `SIPRAL_EVENT_KIND_INCOMING_CALL` and
 * before a call handle exists. A refused INVITE gets the named status
 * (500 if it does not refuse) and is forgotten: no event, no handle. One
 * answered `SIPRAL_SCREEN_ACCEPT` arrives as with no policy.
 *
 * `NULL` removes the policy. A second call replaces the first, on this
 * stack only.
 *
 * The no re-entry and no unwind rules are on sipral_screen_callback_t.
 *
 * Safety
 *
 * `callback`, when not null, is called on whichever thread is feeding
 * this stack bytes, while the policy is installed. `user_data` is handed
 * back untouched and never read here.
 *
 * **`user_data` must outlive the last call, which may come after
 * `sipral_stack_destroy` returns:** a receive already running on another
 * thread holds its own share of the stack and still asks the policy. Free
 * it once no thread is inside this stack. Replacing or removing the
 * policy takes the lock, so once it returns the old callback is not asked
 * again.
 */
sipral_status_t sipral_stack_screen(sipral_handle_t stack, sipral_screen_callback_t callback, void *user_data);

/**
 * How fast one source address may offer this stack an INVITE (A8).
 *
 * `burst` calls from one address pass at once; one more is earned every
 * `every_ms` (see Rate). The default is ten, then one every 2000 ms;
 * loose because most legitimate calls come from the registrar's address.
 *
 * A zero `burst` or zero `every_ms` is `SIPRAL_STATUS_INVALID_ARGUMENT`
 * and changes nothing: one admits no call, the other never limits.
 *
 * The floor is checked before sipral_stack_screen's policy: a source
 * past it never reaches the callback and is counted in
 * `screened_refused_by_rate` or `screened_refused_by_crowding`.
 *
 * **It counts by source address.** An INVITE on a byte stream bound
 * without a far end has no address and always passes to the policy (where
 * sipral_screen_request_t::source is null). Naming `remote` in
 * `sipral_stack_transport_bind` puts a stream under this floor.
 *
 * Safety
 *
 * Safe to call with any handle value.
 */
sipral_status_t sipral_stack_invite_limit(sipral_handle_t stack, uint64_t every_ms, uint32_t burst);

/**
 * Watch something at the far end.
 *
 * One SUBSCRIBE is queued on `account`'s transport and address, and the
 * handle names the subscription until it ends.
 * `SIPRAL_EVENT_KIND_SUBSCRIPTION_CHANGED` reports each step. It
 * refreshes and retries recoverable failures under the same handle;
 * sipral_subscription_end or an end with no retry finishes it.
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
 * Give a subscription up with `Expires: 0` (§4.1.2.3).
 *
 * It stays live until the closing NOTIFY completes (§4.4.1);
 * `SIPRAL_EVENT_KIND_SUBSCRIPTION_CHANGED` with
 * `SIPRAL_SUBSCRIPTION_END_UNSUBSCRIBED` says when. Without a dialog yet
 * it ends at once. The handle is usable until that event.
 *
 * Safety
 *
 * Safe to call with any handle value.
 */
sipral_status_t sipral_subscription_end(sipral_handle_t stack, sipral_handle_t subscription, uint64_t now_ms);

/**
 * Where a subscription is, without waiting for its next event.
 * SIPRAL_SUBSCRIPTION_STATE_UNKNOWN, with `SIPRAL_STATUS_OK`, for a
 * handle that names nothing, as an ended one does.
 *
 * Safety
 *
 * `out_state` must point at one `uint32_t`.
 */
sipral_status_t sipral_subscription_state(sipral_handle_t stack, sipral_handle_t subscription, sipral_subscription_state_t *out_state);

/**
 * What a lamp for this subscription should show: RFC 4235 §3.7.2's
 * virtual state machine over every known dialog, ringing beating
 * settled, SIPRAL_DIALOG_PHASE_IDLE once all ended. The dialog
 * functions below give the detail.
 *
 * `SIPRAL_STATUS_NOT_SUPPORTED` for a subscription with no dialog state:
 * another package, or not live (its last notification is stale).
 *
 * Safety
 *
 * `out_phase` must point at one `uint32_t`.
 */
sipral_status_t sipral_subscription_lamp(sipral_handle_t stack, sipral_handle_t subscription, sipral_dialog_phase_t *out_phase);

/**
 * How many dialogs this subscription has been told about, in order first
 * heard. Indexes hold only until the next notification, which drops
 * ended dialogs; read again on each
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
 * `out_needed` always receives the size with the trailing NUL; ask with
 * `capacity` zero, then with room. Too small a buffer is
 * `SIPRAL_STATUS_BUFFER_TOO_SMALL`, nothing written. A piece the notifier
 * did not send is just the NUL.
 *
 * Safety
 *
 * `buffer` must be writable for `capacity` bytes or be null with a
 * capacity of zero, and `out_needed` must point at one `size_t` or be
 * null.
 */
sipral_status_t sipral_subscription_dialog_text(sipral_handle_t stack, sipral_handle_t subscription, size_t index, sipral_dialog_text_t which, char *buffer, size_t capacity, size_t *out_needed);

/**
 * Send an instant message outside any dialog (RFC 3428 §3).
 *
 * The handle written back names the send until
 * `SIPRAL_EVENT_KIND_MESSAGE_SENT` reports its outcome, even a transport
 * failure. `body` is taken as raw bytes.
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
 * `caller` is the SIP URI the push named. The binding is refreshed at
 * once (§4.1.3); with no transport bound yet, the REGISTER goes when one
 * is. Without a registrar, only the matching happens.
 *
 * Exactly one of the two outputs names something:
 *
 * - `out_announcement` when nothing arrived yet. The matching INVITE
 *   raises `SIPRAL_EVENT_KIND_CALL_ANNOUNCED` right before its
 *   `SIPRAL_EVENT_KIND_INCOMING_CALL`, or
 *   `SIPRAL_EVENT_KIND_ANNOUNCED_CALL_MISSING` if none comes.
 * - `out_call` when the INVITE beat the push. If the incoming-call event
 *   was already delivered, this is the only report of the match.
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
 * For a proxy's periodic wake-up (RFC 8599 §5.5). A push proves the path
 * works, so any back-off from an earlier outage is dropped.
 *
 * `SIPRAL_STATUS_OK` without sending when a REGISTER is in flight or the
 * failure is permanent (retrying a refused password locks accounts out).
 * `SIPRAL_STATUS_INVALID_ARGUMENT` for an account that never registers.
 * With no transport bound yet the failure is reported, and the refresh
 * goes out once one is.
 *
 * Safety
 *
 * Safe to call with any handle value.
 */
sipral_status_t sipral_account_refresh_binding(sipral_handle_t stack, sipral_handle_t account, uint64_t now_ms);

/**
 * Stop expecting an announced call. `SIPRAL_STATUS_WRONG_STATE` when it
 * was already fulfilled or expired; the event and this call can cross.
 *
 * Safety
 *
 * Safe to call with any handle value.
 */
sipral_status_t sipral_announcement_forget(sipral_handle_t stack, sipral_handle_t announcement);

/**
 * What the registrar said about push in its 2xx to REGISTER.
 * `SIPRAL_STATUS_NOT_SUPPORTED` when the account did not ask for push or
 * has no standing binding.
 *
 * Safety
 *
 * `out_echo` must point at a `sipral_push_echo_t` whose `size` member
 * says how long it is.
 */
sipral_status_t sipral_account_push_echo(sipral_handle_t stack, sipral_handle_t account, sipral_push_echo_t *out_echo);

/**
 * Configure an account and write its handle to `out_account`. Nothing is
 * sent. It lives until sipral_account_remove or the stack's end.
 *
 * Safety
 *
 * `config` must point at a `sipral_account_config_t` whose `size` member
 * says how long it is, with every pointer in it readable for the length
 * beside it, and `out_account` at one `sipral_handle_t`.
 */
sipral_status_t sipral_account_add(sipral_handle_t stack, const sipral_account_config_t *config, sipral_handle_t *out_account);

/**
 * Forget an account and everything scheduled for it. Nothing is sent: its
 * registrar may be unreachable. Call sipral_account_unregister first
 * to give the binding up.
 *
 * Safety
 *
 * Safe to call with any handle values.
 */
sipral_status_t sipral_account_remove(sipral_handle_t stack, sipral_handle_t account);

/**
 * Register, and keep the binding alive until told otherwise.
 *
 * Refreshes, credential retries and back-off happen on their own until
 * sipral_account_unregister or a refusal retrying cannot fix. Each
 * step arrives as `SIPRAL_EVENT_KIND_REGISTRATION_CHANGED`. An account
 * with no registrar gets `SIPRAL_STATUS_INVALID_ARGUMENT`, nothing sent.
 *
 * Safety
 *
 * Safe to call with any handle values.
 */
sipral_status_t sipral_account_register(sipral_handle_t stack, sipral_handle_t account, uint64_t now_ms);

/**
 * Give the binding up: a REGISTER with `Expires: 0` (§10.2.2).
 *
 * Only this device's binding: `Contact: *` would remove every binding of
 * the address of record. An account with no registrar is refused as
 * `sipral_account_register` refuses it.
 *
 * Safety
 *
 * Safe to call with any handle values.
 */
sipral_status_t sipral_account_unregister(sipral_handle_t stack, sipral_handle_t account, uint64_t now_ms);

/**
 * Where an account's registration is, as a `sipral_registration_state_t`;
 * always `SIPRAL_REGISTRATION_STATE_NOT_REGISTERING` with no registrar.
 *
 * Safety
 *
 * `out_state` must point at one `uint32_t`.
 */
sipral_status_t sipral_account_registration_state(sipral_handle_t stack, sipral_handle_t account, sipral_registration_state_t *out_state);

/**
 * Give an account the OAuth 2.0 access token its server asked for
 * (RFC 8898), replacing any it had. A `token_len` of zero removes it; a
 * password stays.
 *
 * Answers `SIPRAL_EVENT_KIND_TOKEN_REQUIRED`, or renews ahead of expiry.
 * From the next request, a `Bearer` challenge from the account's own
 * server (and every request its cached challenge covers) gets
 * `Authorization: Bearer <token>` (RFC 6750 §2.1); with `Digest` and
 * `Bearer` offered for one realm, the token answers. A refused token is
 * never resent. Nothing is sent now; a registration that failed for want
 * of a token restarts with `sipral_account_register`.
 *
 * The application fetches tokens. The token is copied, kept out of logs
 * and diagnostics, and wiped when replaced. A token that is not RFC 6750
 * §2.1's `b64token` is `SIPRAL_STATUS_INVALID_ARGUMENT`, nothing changed,
 * the error not describing it.
 *
 * Safety
 *
 * `token` must be readable for `token_len` bytes, or be null with a
 * length of zero.
 */
sipral_status_t sipral_account_set_access_token(sipral_handle_t stack, sipral_handle_t account, const char *token, size_t token_len);

/**
 * Test the network before a call: STUN, TURN, the account's server and,
 * with an echo call, the audio path (ABI 1.2). The result arrives from a
 * later `sipral_stack_poll` as `SIPRAL_EVENT_KIND_NETWORK_TEST` carrying
 * `*out_test`. Tests may run side by side.
 *
 * `SIPRAL_STATUS_WRONG_STATE` for a `probe_socket` without a STUN server
 * or an account not located yet; `SIPRAL_STATUS_INVALID_ARGUMENT` for a
 * `probe_socket` that is not an address or is a signalling socket.
 * Nothing starts when anything is refused.
 *
 * Safety
 *
 * `config` must point at a `sipral_network_test_config_t` whose `size`
 * member says how long it is, with `probe_socket` readable for
 * `probe_socket_len` bytes; `out_test` must point at one `uint32_t`.
 */
sipral_status_t sipral_stack_network_test(sipral_handle_t stack, const sipral_network_test_config_t *config, uint64_t now_ms, uint32_t *out_test);

/**
 * Place a call, and write its handle to `out_call`.
 *
 * The handle exists before any dialog, so the INVITE can be hung up while in flight.
 * Branches a proxy forks get their own handles (`SIPRAL_EVENT_KIND_CALL_FORKED`).
 *
 * With `media_address` set the stack writes the offer and runs the audio:
 * `SIPRAL_EVENT_KIND_MEDIA_STARTED` says when, and `sipral_media_*` carry the packets.
 *
 * Safety
 *
 * `config` must point at a `sipral_call_config_t` whose `size` member says how long it is,
 * with every pointer in it readable for the length beside it, and `out_call` at one
 * `sipral_handle_t`.
 */
sipral_status_t sipral_call_place(sipral_handle_t stack, sipral_handle_t account, const sipral_call_config_t *config, sipral_handle_t *out_call, uint64_t now_ms);

/**
 * Say a call that came in is ringing.
 *
 * A description makes it a 183 rather than a 180, since a 180 with a body is ambiguous.
 *
 * Safety
 *
 * `sdp` must be null or readable for `sdp_len` bytes.
 */
sipral_status_t sipral_call_ring(sipral_handle_t stack, sipral_handle_t call, const uint8_t *sdp, size_t sdp_len, uint64_t now_ms);

/**
 * Say a call that came in is ringing, with this stack running the audio before anybody
 * answers.
 *
 * The answer to the INVITE's offer is written from this stack's codec order against
 * `config.media_address`, and the session opens at once: the far end hears what the
 * application plays. `SIPRAL_EVENT_KIND_MEDIA_STARTED` follows. `config.srtp` and
 * `config.codecs` override the stack's for this call, and `sipral_call_answer_media` keeps
 * what was settled here; it is the only way an incoming call chooses its own SRTP policy.
 *
 * `sipral_call_answer_media` then reuses this session and description. What its 200 OK
 * carries follows RFC 3262 §5 and RFC 6337 §3.1.1, by whether the 183 went out reliably
 * (`docs/05-media.md`, "Ringing with media").
 *
 * Setting `target`, `sdp`, `destination`, `transport`, `keep_all_forks` or `headers` is
 * `SIPRAL_STATUS_INVALID_ARGUMENT` naming it. `SIPRAL_STATUS_WRONG_STATE`, with nothing
 * sent: an INVITE with no offer (RFC 3261 §13.2.1, RFC 6337 §3.1.2); a second call of this;
 * a call after a `sipral_call_ring` that sent the application's own description
 * (RFC 3261 §13.2.1, RFC 6337 §3.1.1).
 *
 * Safety
 *
 * `config` must point at a `sipral_call_config_t` whose `size` member says how long it is,
 * with `media_address` readable for `media_address_len` bytes.
 */
sipral_status_t sipral_call_ring_media(sipral_handle_t stack, sipral_handle_t call, const sipral_call_config_t *config, uint64_t now_ms);

/**
 * Answer a call that came in with `sdp`, the answer to the INVITE's offer (required).
 *
 * Safety
 *
 * `sdp` must be readable for `sdp_len` bytes.
 */
sipral_status_t sipral_call_answer(sipral_handle_t stack, sipral_handle_t call, const uint8_t *sdp, size_t sdp_len, uint64_t now_ms);

/**
 * Answer a call that came in, and let this stack run its audio.
 *
 * The answer is written from this stack's codec order against `media_address`.
 * `SIPRAL_EVENT_KIND_MEDIA_STARTED` follows once the stream is open.
 *
 * On a call `sipral_call_ring_media` already rang, the 183's description and session
 * stand and `media_address` must still parse but is unused. The 200 OK repeats that
 * description if the 183 went unreliably and carries none if reliably (RFC 6337 §3.1.1).
 *
 * Safety
 *
 * `media_address` must be readable for `media_address_len` bytes.
 */
sipral_status_t sipral_call_answer_media(sipral_handle_t stack, sipral_handle_t call, const char *media_address, size_t media_address_len, uint64_t now_ms);

/**
 * Answer a call that came in with media this stack describes, from `config`:
 * `sipral_call_answer_media` with the members `sipral_call_ring_media` reads. Any other
 * member set is `SIPRAL_STATUS_INVALID_ARGUMENT` naming it. On a call already rung with
 * media, only `focus` changes anything.
 *
 * Safety
 *
 * `config` must point at a `sipral_call_config_t` whose `size` member says how long it is,
 * with every pointer in it readable for the length beside it.
 */
sipral_status_t sipral_call_answer_with(sipral_handle_t stack, sipral_handle_t call, const sipral_call_config_t *config, uint64_t now_ms);

/**
 * Refuse a call that came in with a response code of your choosing: 486 for a line in use,
 * 603 for a person who declines. A proxy acts differently on each.
 *
 * Safety
 *
 * Safe to call with any handle values.
 */
sipral_status_t sipral_call_reject(sipral_handle_t stack, sipral_handle_t call, uint32_t code, uint64_t now_ms);

/**
 * Hang up, whatever the call is doing: CANCEL before an answer, BYE after, a refusal for
 * an unanswered incoming call. A call already ending is left alone.
 *
 * Safety
 *
 * Safe to call with any handle values.
 */
sipral_status_t sipral_call_hangup(sipral_handle_t stack, sipral_handle_t call, uint64_t now_ms);

/**
 * Set the header fields that go on what this call sends at the application's request,
 * until set again.
 *
 * They go on the responses of `sipral_call_ring`, `sipral_call_answer`,
 * `sipral_call_answer_media` and `sipral_call_reject`, the refusal or BYE of
 * `sipral_call_hangup`, and the re-INVITE or UPDATE of `sipral_call_hold` and
 * `sipral_call_resume`. Kept across them. Never on a CANCEL (a proxy replaces it) or on
 * what the stack sends by itself.
 *
 * Replaces the previous set whole; `headers_len` zero clears it. Each field is checked as
 * on `sipral_call_config_t::headers`; a refusal names the element and keeps the old set.
 *
 * Safety
 *
 * `headers` must be null with `headers_len` zero, or readable for `headers_len` elements,
 * each with a name and a value readable for the lengths beside them.
 */
sipral_status_t sipral_call_set_headers(sipral_handle_t stack, sipral_handle_t call, const sipral_header_t *headers, size_t headers_len);

/**
 * Put a call on hold (RFC 3264 §8.4).
 *
 * The stack writes the description: the negotiated one with every direction changed. A
 * hold already in place or on its way sends nothing and succeeds.
 *
 * While another session change runs, it succeeds and waits until that is over
 * (RFC 3261 §14.1); the outcome arrives as `SIPRAL_EVENT_KIND_SESSION_CHANGED` or
 * `SIPRAL_EVENT_KIND_SESSION_CHANGE_FAILED`. Only the last state asked for waits, so a
 * resume asked for while a hold is still on its way goes after it. One still waiting
 * when the call ends is never sent.
 *
 * Safety
 *
 * Safe to call with any handle values.
 */
sipral_status_t sipral_call_hold(sipral_handle_t stack, sipral_handle_t call, uint64_t now_ms);

/**
 * Take it off hold. Each stream returns to its previous direction (a receive-only one stays
 * receive-only), and waits for a running change as `sipral_call_hold` does.
 *
 * Safety
 *
 * Safe to call with any handle values.
 */
sipral_status_t sipral_call_resume(sipral_handle_t stack, sipral_handle_t call, uint64_t now_ms);

/**
 * Offer a call again on another list of codecs (RFC 3264 §8.3.2).
 *
 * `codecs` is as `sipral_call_config_t::codecs`. Only the codecs change: address, keys,
 * fingerprint and ICE credentials are offered as they are, and a held call stays held. A
 * dynamic payload type keeps its codec; a new codec gets an unused number.
 *
 * The list becomes the call's once accepted; `SIPRAL_EVENT_KIND_MEDIA_CHANGED` names the
 * codec settled on. A refusal arrives as `SIPRAL_EVENT_KIND_SESSION_CHANGE_FAILED`.
 *
 * For a call placed or answered with `media_address`. `SIPRAL_STATUS_NOT_SUPPORTED`: a name
 * with no codec in this build. `SIPRAL_STATUS_INVALID_ARGUMENT`: an empty list, a repeated
 * name or a stray comma. `SIPRAL_STATUS_WRONG_STATE`: no stack-written description, none
 * agreed yet, a refused stream, an early call whose far end never listed UPDATE, or
 * another change on its way. `SIPRAL_STATUS_EXHAUSTED`: no dynamic payload type left.
 *
 * Safety
 *
 * `codecs` must be readable for `codecs_len` bytes.
 */
sipral_status_t sipral_call_change_codecs(sipral_handle_t stack, sipral_handle_t call, const char *codecs, size_t codecs_len, uint64_t now_ms);

/**
 * Restart ICE on a call (RFC 8445 §9): offer it again with new credentials and check every
 * pair again once the far end answers.
 *
 * The last description is offered again with new `ice-ufrag` and `ice-pwd`
 * (RFC 8839 §4.4.1.1.1), the candidates still held, and the same role. Nothing reaches the
 * agent until the far end accepts (§4.4). The old pair carries audio meanwhile, and the new
 * selection arrives as `SIPRAL_EVENT_KIND_MEDIA_PATH_CHOSEN`. A refusal arrives as
 * `SIPRAL_EVENT_KIND_SESSION_CHANGE_FAILED` and leaves ICE as it was.
 *
 * The remedy for lost consent (`SIPRAL_MEDIA_FAULT_ICE`) and a local network change. For a
 * call placed or answered with `media_address`. `SIPRAL_STATUS_WRONG_STATE`: no
 * stack-written description, no ICE agent, no description yet, or another change on its
 * way. `SIPRAL_STATUS_NOT_SUPPORTED` from a build without ICE.
 *
 * Safety
 *
 * Safe to call with any handle values.
 */
sipral_status_t sipral_call_restart_ice(sipral_handle_t stack, sipral_handle_t call, uint64_t now_ms);

/**
 * Describe a call's media at a socket the application bound on a new network and offer it
 * to the far end (RFC 3264 §8.3.1), as `SIPRAL_EVENT_KIND_CALL_ADDRESS_WANTED` asks.
 *
 * `media_address` is the new socket, `host:port`; `public_address` is where it appears
 * from outside, or null with length zero. The re-INVITE moves only `c=` and the `m=` port,
 * and carries the account's current `Contact`, so `sipral_account_rebind` goes first. The
 * new socket is the call's whatever the answer: `SIPRAL_EVENT_KIND_SESSION_CHANGED` and
 * `SIPRAL_EVENT_KIND_MEDIA_CHANGED`, or `SIPRAL_EVENT_KIND_SESSION_CHANGE_FAILED`.
 *
 * For a call placed or answered with `media_address`. `SIPRAL_STATUS_WRONG_STATE`: no
 * stack-written description, a session running ICE (moved by a restart instead), no
 * description yet, or another change on its way.
 *
 * Safety
 *
 * `media_address` must be readable for `media_address_len` bytes, and `public_address` for
 * `public_address_len` bytes or null with a length of zero.
 */
sipral_status_t sipral_call_media_readdress(sipral_handle_t stack, sipral_handle_t call, const char *media_address, size_t media_address_len, const char *public_address, size_t public_address_len, uint64_t now_ms);

/**
 * End a call and say why (RFC 3326): what `sipral_call_hangup` does, with
 * a `Reason` on the BYE or the CANCEL it turns into.
 *
 * `sip_cause` (SIP status) and `q850_cause` (Q.850) are each zero for none;
 * neither is a plain hangup. `text` goes on the first value written. On
 * refusing an unanswered incoming call only the Q.850 value goes
 * (RFC 6432).
 *
 * Safety
 *
 * `text` must be readable for `text_len` bytes or null with a length of
 * zero.
 */
sipral_status_t sipral_call_hangup_for(sipral_handle_t stack, sipral_handle_t call, uint32_t sip_cause, uint32_t q850_cause, const char *text, size_t text_len, uint64_t now_ms);

/**
 * Answer a call that came in with a 3xx: somewhere else to try
 * (RFC 3261 §21.3), and why (RFC 5806).
 *
 * `status_code` is 300 to 399. `targets` is comma-separated URIs in
 * preference order, required except for 380. `reason`, when given, adds a
 * `Diversion` with that reason token naming the called address.
 * `SIPRAL_STATUS_INVALID_ARGUMENT` for a bad status or target;
 * `SIPRAL_STATUS_WRONG_STATE` for a call not waiting to be answered.
 *
 * Safety
 *
 * `targets` must be readable for `targets_len` bytes and `reason` for
 * `reason_len` bytes, each or null with a length of zero.
 */
sipral_status_t sipral_call_redirect(sipral_handle_t stack, sipral_handle_t call, uint32_t status_code, const char *targets, size_t targets_len, const char *reason, size_t reason_len, uint64_t now_ms);

/**
 * How many entries one of a call's identity lists has. Every piece of an
 * entry gives the same count. Read once from the INVITE; zero for a call
 * this end placed.
 *
 * Safety
 *
 * `out_count` must point at one `size_t`.
 */
sipral_status_t sipral_call_identity_count(sipral_handle_t stack, sipral_handle_t call, sipral_identity_text_t which, size_t *out_count);

/**
 * One piece of one entry of a call's identity lists, copied into the
 * caller's buffer with a trailing NUL.
 *
 * `out_needed` always receives the bytes needed including the NUL; ask
 * with `capacity` zero, then again with room. Too small is
 * `SIPRAL_STATUS_BUFFER_TOO_SMALL` with nothing written. A missing piece
 * is just the NUL. An index past the end is `SIPRAL_STATUS_INVALID_ARGUMENT`.
 *
 * Safety
 *
 * `buffer` must be writable for `capacity` bytes or null with a capacity
 * of zero, and `out_needed` must point at one `size_t` or be null.
 */
sipral_status_t sipral_call_identity_text(sipral_handle_t stack, sipral_handle_t call, size_t index, sipral_identity_text_t which, char *buffer, size_t capacity, size_t *out_needed);

/**
 * Join two active calls into a local three-way conference: each far end hears the other
 * and this end's microphone, mixed. sipral_media_mix
 * drives it one frame at a time; this only records the pairing.
 *
 * No SIP conference: neither far end is told. Both calls need running media and the same
 * sample rate and frame length, since nothing resamples.
 *
 * `SIPRAL_STATUS_INVALID_ARGUMENT` for `call_a == call_b`; `SIPRAL_STATUS_WRONG_STATE` for a
 * call with no running session, one already joined, or mismatched rate or frame length.
 *
 * Safety
 *
 * Safe to call with any handle values.
 */
sipral_status_t sipral_call_join(sipral_handle_t stack, sipral_handle_t call_a, sipral_handle_t call_b);

/**
 * Take `call` back out of its pair. Neither session is touched; each call carries its own
 * audio again. `SIPRAL_STATUS_WRONG_STATE` for a call not joined.
 *
 * Safety
 *
 * Safe to call with any handle values.
 */
sipral_status_t sipral_call_leave(sipral_handle_t stack, sipral_handle_t call);

/**
 * Accept a change the far end offered (`SIPRAL_EVENT_KIND_SESSION_OFFERED`).
 *
 * `sdp`, the answer, is required (RFC 3264 §5): null or empty is
 * `SIPRAL_STATUS_INVALID_ARGUMENT` and the request still waits. An unanswered re-INVITE
 * ends the call, so this or sipral_call_reject_session must follow the event. An offer
 * in a PRACK (RFC 3262 §5) is answered the same way, in the PRACK's 2xx.
 *
 * Only for a call the application describes; a stack-described call answers its own
 * re-offers, so this is `SIPRAL_STATUS_WRONG_STATE` there.
 *
 * Safety
 *
 * `sdp` must be null or readable for `sdp_len` bytes.
 */
sipral_status_t sipral_call_accept_session(sipral_handle_t stack, sipral_handle_t call, const uint8_t *sdp, size_t sdp_len, uint64_t now_ms);

/**
 * Refuse one instead; the session stands as it was (§14.1). 488 Not Acceptable Here says
 * the description was the problem. Only for a call the application describes.
 *
 * Safety
 *
 * Safe to call with any handle values.
 */
sipral_status_t sipral_call_reject_session(sipral_handle_t stack, sipral_handle_t call, uint32_t code, uint64_t now_ms);

/**
 * Send DTMF on a call that is up, in the form the far end takes.
 *
 * `digits` are `0`-`9`, `*`, `#` and `A`-`D`, the sixteen events of
 * RFC 4733 §3.2, in the order they were pressed. The whole string is checked first: one
 * bad character sends nothing. `duration_ms` is each tone's length, or zero for 100 ms.
 *
 * `via` is a sipral_dtmf_t. `SIPRAL_DTMF_RTP` puts the digits in the media, replacing the
 * audio while they last, queued. The INFO forms send one request per digit, each after the
 * previous one's final answer, since UDP may reorder overlapping transactions. A refusal,
 * timeout or transport failure ends the sequence: `SIPRAL_EVENT_KIND_DTMF_SENT` names that
 * digit, and the rest are discarded unreported. Digits handed over meanwhile queue behind.
 * A call holds at most sixty-four INFO digits, the one in flight included; a string past
 * that is refused whole with `SIPRAL_STATUS_INVALID_ARGUMENT`.
 *
 * `SIPRAL_DTMF_RTP` without a negotiated telephone event writes the tones into the audio,
 * as `SIPRAL_DTMF_IN_BAND` always does. The media forms are `SIPRAL_STATUS_WRONG_STATE`
 * before there is media, the INFO forms before there is a dialog.
 *
 * Safety
 *
 * `digits` must be readable for `digits_len` bytes.
 */
sipral_status_t sipral_call_send_dtmf(sipral_handle_t stack, sipral_handle_t call, const char *digits, size_t digits_len, sipral_dtmf_t via, uint32_t duration_ms, uint64_t now_ms);

/**
 * Ask the far end to call somebody else, and hang up when it has (RFC 3515).
 *
 * A blind transfer. This end stays in the call until the transfer succeeds, so a failed
 * transfer does not lose the call. Progress arrives as `SIPRAL_EVENT_KIND_TRANSFER_PROGRESS`,
 * then `SIPRAL_EVENT_KIND_TRANSFER_DONE`.
 *
 * Safety
 *
 * `target` must be readable for `target_len` bytes.
 */
sipral_status_t sipral_call_transfer(sipral_handle_t stack, sipral_handle_t call, const char *target, size_t target_len, uint64_t now_ms);

/**
 * Call the transfer target, and write the new call's handle to `out_consultation`.
 *
 * The consultation leg of an attended transfer; sipral_call_transfer_to follows.
 * Holding `call` first is the application's choice. `media_address` is
 * `SIPRAL_STATUS_NOT_SUPPORTED` here: place the consultation with `sdp` and run its audio.
 *
 * Safety
 *
 * As sipral_call_place.
 */
sipral_status_t sipral_call_consult(sipral_handle_t stack, sipral_handle_t call, const sipral_call_config_t *config, sipral_handle_t *out_consultation, uint64_t now_ms);

/**
 * Hand `call` to the far end of `other` (RFC 3891): the attended half of a transfer, where
 * `other` is normally the consultation call. Any call that is up may be named.
 *
 * Safety
 *
 * Safe to call with any handle values.
 */
sipral_status_t sipral_call_transfer_to(sipral_handle_t stack, sipral_handle_t call, sipral_handle_t other, uint64_t now_ms);

/**
 * Take a transfer that was asked for, place the call it names as sipral_call_place
 * does, and write its handle to `out_placed`.
 *
 * `config.target` set is `SIPRAL_STATUS_INVALID_ARGUMENT`: the REFER names the target.
 * Every other member means what it means on `sipral_call_place`. `Replaces` or
 * `Referred-By` among `headers` is `SIPRAL_STATUS_INVALID_ARGUMENT` with the transfer still
 * waiting: the INVITE takes both from the REFER. Neither `sdp` nor `media_address` is
 * `SIPRAL_STATUS_INVALID_ARGUMENT`, as on `sipral_call_place`.
 *
 * `call` may be a referral's handle (`SIPRAL_EVENT_KIND_REFERRAL`, a REFER outside any
 * dialog), placed from the account the event names. Its handle is stale once the REFER is
 * answered; one refused before anything was sent is still there to take.
 *
 * A call that cannot be sent after the 202 ends the subscription with RFC 3515 §2.4.5's
 * 503, and this answers `SIPRAL_STATUS_NOT_SENT`.
 *
 * Safety
 *
 * `config` must point at a `sipral_call_config_t` whose `size` member says how long it is,
 * with every pointer in it readable for the length beside it, and `out_placed` at one
 * `sipral_handle_t`.
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
 * Take a transfer asked for inside `call` with a call the application placed itself,
 * `placed`, and report that call's progress to the far end as if the REFER had placed it
 * (ABI 1.2).
 *
 * For an application that reaches the target its own way, such as a bridge. The REFER is
 * answered 202 (RFC 3515 §2.4.2); `placed` then reports each provisional status in a
 * NOTIFY (§2.4.5), and its final status ends the subscription (§2.4.7). A `placed` already
 * up is reported with a 200 at once. Ending `call` stays the application's.
 *
 * `SIPRAL_STATUS_WRONG_STATE` when nothing waits on `call` (a referral's handle included),
 * or `placed` is `call`, is over, or already reports to another REFER. A refusal leaves the
 * REFER waiting.
 *
 * Safety
 *
 * Safe to call with any handle values.
 */
sipral_status_t sipral_call_accept_transfer_placed(sipral_handle_t stack, sipral_handle_t call, sipral_handle_t placed, uint64_t now_ms);

/**
 * Where a call is, as a `sipral_call_state_t`.
 *
 * A call that is over answers `SIPRAL_CALL_STATE_TERMINATED` until the poll delivering
 * `SIPRAL_EVENT_KIND_CALL_ENDED` retires its handle, then `SIPRAL_STATUS_STALE_HANDLE`. A
 * referral's handle is `SIPRAL_STATUS_WRONG_STATE`: there is no call yet.
 *
 * Safety
 *
 * `out_state` must point at one `uint32_t`.
 */
sipral_status_t sipral_call_state(sipral_handle_t stack, sipral_handle_t call, sipral_call_state_t *out_state);

/**
 * Which way a call is held: `out_here` when this end asked the far end to stop sending,
 * `out_there` when the far end asked. Either may be null.
 *
 * Safety
 *
 * `out_here` and `out_there` must each be null or point at one `uint32_t`.
 */
sipral_status_t sipral_call_hold_state(sipral_handle_t stack, sipral_handle_t call, uint32_t *out_here, uint32_t *out_there);

/**
 * The name of a codec, as a static NUL-terminated string, or null for a
 * number this build has no codec for.
 *
 * Spelled as IANA registered it; L16 carries its rate (`L16/8000`,
 * `L16/16000`), as in a codec order. Owned by the library, valid while
 * it is loaded.
 *
 * Safety
 *
 * Reads no memory the caller owns, and is safe to call from any thread.
 */
const char *sipral_codec_name(sipral_codec_t codec);

/**
 * How many codecs this build contains, fixed at compile time.
 *
 * Safety
 *
 * `out_count` must point at one `size_t`.
 */
sipral_status_t sipral_codec_count(size_t *out_count);

/**
 * One of them, by index, from zero to what `sipral_codec_count` said.
 *
 * In this build's preference order, the default offer; G.729 comes last
 * and is offered only when a codec order names it.
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
 * What `sipral_stack_config_t::codecs` came to. `out_count` always gets
 * the total; a short buffer (or null with zero capacity) gets
 * `SIPRAL_STATUS_BUFFER_TOO_SMALL`.
 *
 * Safety
 *
 * `out_codecs` must be writable for `capacity` `uint32_t` or null with a
 * capacity of zero, and `out_count` must point at one `size_t` or be null.
 */
sipral_status_t sipral_stack_codec_order(sipral_handle_t stack, sipral_codec_t *out_codecs, size_t capacity, size_t *out_count);

/**
 * A handle on one call's media, written to `out_media`.
 *
 * Mint it once negotiation settles (`SIPRAL_EVENT_KIND_MEDIA_STARTED`,
 * callback included) and pass it to every `sipral_media_` entry point.
 * None of those takes the stack's lock.
 *
 * `SIPRAL_STATUS_WRONG_STATE` for a call with no media. Written only on
 * `SIPRAL_STATUS_OK`.
 *
 * The handle outlives the call: after the call ends or the stack is
 * destroyed, media entry points answer `SIPRAL_STATUS_WRONG_STATE`. Hold,
 * resume and codec changes keep it valid. Each handle is released once with
 * `sipral_media_release`; asking twice gives two.
 *
 * Safety
 *
 * `out_media` must point at one `sipral_handle_t`.
 */
sipral_status_t sipral_call_media(sipral_handle_t stack, sipral_handle_t call, sipral_handle_t *out_media);

/**
 * Let a media handle go.
 *
 * Valid whether or not the call or stack still exists. The session is not
 * touched; releasing mid-call stops nothing. A second release is
 * `SIPRAL_STATUS_STALE_HANDLE`.
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
 * This call's catalogue: the stack's order unless
 * `sipral_call_config_t::codecs` named another. Zero is a valid answer.
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
 * An index past the end is `SIPRAL_STATUS_INVALID_ARGUMENT`.
 *
 * Safety
 *
 * `out_candidate` must point at a `sipral_codec_candidate_t` whose `size`
 * member says how long it is.
 */
sipral_status_t sipral_media_codec_candidate_at(sipral_handle_t media, size_t index, sipral_codec_candidate_t *out_candidate);

/**
 * How many paths this call's ICE agent tried: every candidate pair its
 * checklist held, then every relay it held.
 *
 * Zero for a call not using ICE. A restart (RFC 8445 §9) starts the list
 * again.
 *
 * Safety
 *
 * `out_count` must point at one `size_t`.
 */
sipral_status_t sipral_media_path_candidate_count(sipral_handle_t media, size_t *out_count);

/**
 * One of them, by index, from zero to what
 * `sipral_media_path_candidate_count` said: the pairs in the order the
 * checklist took them in, then the relays.
 *
 * An index past the end is `SIPRAL_STATUS_INVALID_ARGUMENT`; an address
 * buffer smaller than `SIPRAL_ADDRESS_BYTES` is
 * `SIPRAL_STATUS_BUFFER_TOO_SMALL`, before anything is written.
 *
 * Safety
 *
 * `out_candidate` must point at a `sipral_path_candidate_t` whose `size`
 * member says how long it is, and its two address buffers, when not
 * null, must be writable for the capacities beside them.
 */
sipral_status_t sipral_media_path_candidate_at(sipral_handle_t media, size_t index, sipral_path_candidate_t *out_candidate);

/**
 * What one call's media has cost, and what it is costing now.
 *
 * `now_ms` is the caller's monotonic clock; it does not move the stack's
 * clock. The end-of-call record arrives as
 * `SIPRAL_EVENT_KIND_MEDIA_STATISTICS`; by then this answers
 * `SIPRAL_STATUS_WRONG_STATE`.
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
 * RTP and RTCP are told apart by RFC 5761 §4, so either socket's traffic
 * goes here.
 *
 * `data` is decrypted in place; keep a copy if the ciphertext is needed.
 * `out_arrival` may be null. `now_ms` is the arrival time on the stack's
 * clock and moves nothing.
 *
 * Safety
 *
 * `data` must be readable and writable for `len` bytes, `from` readable
 * for `from_len`, and `out_arrival` must point at one `uint32_t` or be
 * null.
 */
sipral_status_t sipral_media_receive(sipral_handle_t media, uint8_t *data, size_t len, const char *from, size_t from_len, uint64_t now_ms, sipral_arrival_t *out_arrival);

/**
 * Take the frame that is due for the earpiece, and say where it came from.
 *
 * Exactly `sipral_media_info_t::frame_samples` samples are written, and a
 * smaller buffer is `SIPRAL_STATUS_BUFFER_TOO_SMALL` with the number
 * needed in `out_written`. Every source fills the whole frame, silence
 * included.
 *
 * Safety
 *
 * `samples` must be writable for `capacity` `int16_t`, `out_written` must
 * point at one `size_t` or be null, and `out_source` at one `uint32_t` or
 * be null.
 */
sipral_status_t sipral_media_playback(sipral_handle_t media, int16_t *samples, size_t capacity, size_t *out_written, sipral_playback_t *out_source);

/**
 * Put one frame from the microphone on the wire.
 *
 * `sample_count` must equal `sipral_media_info_t::frame_samples`.
 *
 * A packet `len` of zero means the frame was deliberately not sent: held
 * by the far end, suppressed as silence, or ICE has no path yet. The RTP
 * timestamp still advances in the first two cases (RFC 3550 §5.1); in the
 * third nothing is encoded. While this end holds the far end, silence
 * goes out instead of the microphone.
 *
 * `now_ms` moves nothing; it tells ICE traffic went out on the chosen pair
 * (RFC 8445 §11 keepalives).
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
 * Choose the rate this call's frames cross the boundary at in
 * application mode: what `sipral_media_playback` fills and what
 * `sipral_media_capture` takes, whatever rate the codec runs at.
 *
 * `hz` is 8000, 16000, 24000 or 48000; 0 (the start) is the codec's rate.
 * The frame keeps its duration (20 ms at 24 kHz is 480 samples), and
 * `sipral_media_info_t::sample_rate`/`frame_samples` follow at once. The
 * library resamples both ways and follows codec renegotiation; processors,
 * recordings and detectors stay at the codec's rate.
 *
 * Any other rate is `SIPRAL_STATUS_INVALID_ARGUMENT`, setting unchanged.
 * `SIPRAL_STATUS_WRONG_STATE` in device mode. `sipral_media_mix` refuses
 * a pair while either call has its own rate.
 *
 * Safety
 *
 * Reads no memory the caller owns.
 */
sipral_status_t sipral_media_set_app_rate(sipral_handle_t media, uint32_t hz);

/**
 * Run `callback` over every captured frame, against the far-end audio
 * played a render delay earlier: the seam for echo cancellation, gain
 * control and noise suppression (`docs/05-media.md`).
 *
 * Replaces any previous processor and its learned state. Attaching
 * mid-call costs a fresh adaptation.
 *
 * **`callback` runs with this call's media locked**, unlike the event
 * callback: inside sipral_media_playback, inside
 * sipral_media_capture, and with sipral_processor_frame_t's `reset`
 * set on a device or codec change, on the thread that called in. **From
 * inside it, call nothing on any media handle or this call's stack**:
 * such calls answer `SIPRAL_STATUS_BUSY`. This rules out two processors
 * deadlocking across calls. It must not unwind.
 *
 * `user_data` is handed back untouched and must outlive the last call,
 * which ends when `sipral_media_detach_processor` or
 * `sipral_media_release` returns.
 *
 * Safety
 *
 * `callback` is called on whichever thread calls
 * sipral_media_playback or sipral_media_capture on this call,
 * for as long as the processor stays attached, and `user_data` has to
 * outlive the last such call.
 */
sipral_status_t sipral_media_attach_processor(sipral_handle_t media, sipral_processor_callback_t callback, void *user_data);

/**
 * Stop running the processor sipral_media_attach_processor attached,
 * if there was one.
 *
 * `out_was_attached`, when not null, gets 1 if one was detached, else 0.
 * Once this returns, `callback` is not called again and `user_data` may
 * be freed.
 *
 * Safety
 *
 * `out_was_attached` must point at one `uint32_t` or be null.
 */
sipral_status_t sipral_media_detach_processor(sipral_handle_t media, uint32_t *out_was_attached);

/**
 * Forget the echo path, the noise floor and the gain the attached
 * processor has learned, keeping the processor itself attached.
 *
 * For a device change. Calls the sipral_media_attach_processor
 * callback with sipral_processor_frame_t's `reset` set.
 *
 * `out_was_attached`, when not null, gets 1 if a processor exists, else 0.
 *
 * Safety
 *
 * `out_was_attached` must point at one `uint32_t` or be null.
 */
sipral_status_t sipral_media_reset_processor(sipral_handle_t media, uint32_t *out_was_attached);

/**
 * One frame of a two-call local conference: decode both far ends, mix
 * what each of the three parties is owed, and send the two far-end frames.
 *
 * `sipral_call_join` must already have paired the calls. Not checked here,
 * since that would take the stack's lock every frame.
 *
 * `mic` (`mic_count`) is this end's frame; `local` (`local_count`) gets
 * what this end's speaker is owed. Both are
 * `sipral_media_info_t::frame_samples`. `packet_a`/`packet_b` are filled
 * as by `sipral_media_capture`, each with `mic` mixed with the other far
 * end; recordings keep the same.
 *
 * Drive a joined pair from one thread. Concurrent mixes of the same pair
 * serialize without deadlock, but calling `sipral_media_playback` or
 * `sipral_media_capture` on either call meanwhile is a second driver.
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
 * A `len` of zero means nothing is due. RFC 3550 §6.3 decides when; at
 * most one report is due at a time.
 *
 * Call it after every outgoing frame, and at each `sipral_stack_poll`
 * deadline while not capturing. Always zero without negotiated RTCP.
 * `now_ms` moves nothing.
 *
 * Safety
 *
 * `packet` must point at a `sipral_media_packet_t` as
 * sipral_media_capture describes.
 */
sipral_status_t sipral_media_poll_rtcp(sipral_handle_t media, uint64_t now_ms, sipral_media_packet_t *packet);

/**
 * A datagram this call owes the far end that is neither audio nor a
 * report: DTLS-SRTP handshake records and ICE checks.
 *
 * A `len` of zero means nothing is due; always so on a call without a
 * handshake or ICE, at the cost of one comparison.
 *
 * **Drain it to empty** after every `sipral_media_receive` that answered
 * `SIPRAL_ARRIVAL_HANDSHAKE` and at every `sipral_stack_poll` deadline.
 * Otherwise the call connects, carries no audio, and reports nothing for
 * the two minutes until it gives up. `now_ms` moves nothing.
 *
 * Safety
 *
 * `packet` must point at a `sipral_media_packet_t` as
 * sipral_media_capture describes.
 */
sipral_status_t sipral_media_poll_transmit(sipral_handle_t media, uint64_t now_ms, sipral_media_packet_t *packet);

/**
 * The RTCP goodbye of a call whose media has ended.
 *
 * The RFC 3550 §6.3.7 BYE is built when the session stops, after the
 * media handle stops working, so it is polled from the stack.
 *
 * `out_call` gets the call it belonged to, or `SIPRAL_HANDLE_NONE` when
 * nothing was waiting. The call is over; the handle only says which media
 * socket to send from.
 *
 * One at a time: after each `sipral_stack_poll` that delivered
 * `SIPRAL_EVENT_KIND_CALL_ENDED`, call until `packet` has `len` zero.
 *
 * A TURN relay (`turn_server`) is given back here too: the zero-lifetime
 * Refresh of RFC 8656 §8, to the TURN server, from the same socket. It is
 * queued at call end, or earlier when the call does not use the relay, so
 * polling after every `sipral_stack_poll` releases it sooner.
 *
 * Safety
 *
 * `out_call` must point at one `sipral_handle_t`, and `packet` at a
 * `sipral_media_packet_t` as sipral_media_capture describes.
 */
sipral_status_t sipral_stack_poll_farewell(sipral_handle_t stack, sipral_handle_t *out_call, sipral_media_packet_t *packet);

/**
 * Whether a digit is going out or waiting to, and how many have not
 * started yet.
 *
 * Either out parameter may be null.
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
 * The digit in flight gets no closing packet.
 *
 * Safety
 *
 * Reads no memory the caller owns.
 */
sipral_status_t sipral_media_stop_dialling(sipral_handle_t media);

/**
 * Start recording this call to `path`: both directions mixed, as WAVE.
 * Each start makes a new file.
 *
 * `SIPRAL_STATUS_WRONG_STATE` when the media has ended or a recording is
 * already running. `SIPRAL_STATUS_INVALID_ARGUMENT` when the file system
 * refuses the path, with its reason in the last error. The file is created
 * with this call's media held, so only this call's audio waits on it.
 *
 * Safety
 *
 * `path` must be readable for `path_len` bytes.
 */
sipral_status_t sipral_media_record_start(sipral_handle_t media, const char *path, size_t path_len);

/**
 * Stop the recording and close the file.
 *
 * `SIPRAL_STATUS_WRONG_STATE` when nothing is being recorded. On failure
 * the file holds all the audio but zero header lengths.
 *
 * Safety
 *
 * Safe to call with any handle value.
 */
sipral_status_t sipral_media_record_stop(sipral_handle_t media);

/**
 * Whether a recording is running on this call, and how much audio it has
 * taken (audio only, not the header). Either out parameter may be null.
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
 * Loop until `len` is zero, after every `sipral_stack_poll` and every call that hands bytes
 * in. A message longer than `capacity` is `SIPRAL_STATUS_BUFFER_TOO_SMALL` with the needed
 * length in `len` and is kept for the next call, ahead of the queue; a null `data` with
 * capacity zero thus asks for the length.
 *
 * Safety
 *
 * `transmit` must point at a `sipral_transmit_t` whose `size` member says how long it is and
 * whose buffers are writable for the capacities beside them.
 */
sipral_status_t sipral_stack_poll_transmit(sipral_handle_t stack, sipral_transmit_t *transmit);

/**
 * Hand over one datagram, whole, with its source.
 *
 * `from` is the far end as `host:port`. `to` is the receiving address, which the response
 * leaves from (RFC 3581 §4); length zero means the stack's creation address. Frames from a
 * WebSocket the application runs come here too (RFC 7118 §4.2).
 *
 * Non-SIP bytes are `SIPRAL_STATUS_INVALID_ARGUMENT` with the parse error as last error;
 * only that packet is lost.
 *
 * Safety
 *
 * `data` must be readable for `len` bytes, `from` for `from_len`, and `to` for `to_len`.
 */
sipral_status_t sipral_stack_receive_datagram(sipral_handle_t stack, uint32_t transport, const uint8_t *data, size_t len, const char *from, size_t from_len, const char *to, size_t to_len, uint64_t now_ms);

/**
 * Hand over bytes read off a connection, in whatever sizes the reads came in.
 *
 * A fragment of the `Content-Length` framing (§18.3): may hold several messages or none. A
 * stack-run WebSocket's handshake and frames come here too. Unreadable framing cannot be
 * resynchronised: the transport is retired before `SIPRAL_STATUS_INVALID_ARGUMENT` returns;
 * close the socket. A zero-byte read is sipral_stack_stream_closed, not this.
 *
 * Safety
 *
 * `data` must be readable for `len` bytes.
 */
sipral_status_t sipral_stack_receive_stream(sipral_handle_t stack, uint32_t transport, const uint8_t *data, size_t len, uint64_t now_ms);

/**
 * Say that a transport is open: the main one again, or a new one.
 *
 * The way back after sipral_stack_transport_failed and the way new transports enter the
 * table. `transport` is SIPRAL_TRANSPORT_MAIN or any caller-chosen number; a known one
 * is rebound, an unknown one opened. `out_transport_id`, if not null, receives the same
 * number.
 *
 * `protocol` is a sipral_transport_t. On rebind, zero keeps the current
 * protocol and anything different is `SIPRAL_STATUS_INVALID_ARGUMENT`: switching it under
 * running RFC 3261 §17 timers is not allowed. Opening a new transport requires a protocol.
 *
 * `local` is the address the far end reaches, `host:port`. `remote` names a connection's far
 * end, is refused on a datagram transport, and length zero omits it. On WS/WSS, `remote`
 * makes the stack run the WebSocket: the handshake comes out of
 * sipral_stack_poll_transmit and reads go to sipral_stack_receive_stream.
 *
 * After a
 * SIPRAL_EVENT_KIND_TRANSPORT_WANTED,
 * binding what it named and asking again sends the request on the new stream.
 *
 * Safety
 *
 * `local` must be readable for `local_len` bytes, `remote` for `remote_len`, and
 * `out_transport_id`, when it is not null, must point at one `uint32_t`.
 */
sipral_status_t sipral_stack_transport_bind(sipral_handle_t stack, uint32_t transport, sipral_transport_t protocol, const char *local, size_t local_len, const char *remote, size_t remote_len, uint64_t now_ms, uint32_t *out_transport_id);

/**
 * Say that a transport failed and what was written to it did not arrive.
 *
 * The transport is retired: its transactions fail now, effects are reported on the next
 * `sipral_stack_poll`, and nothing is sent until sipral_stack_transport_bind. Not for one
 * refused `sendto`: retiring the socket over an ICMP unreachable drops healthy calls.
 *
 * Also answers a `SIPRAL_EVENT_KIND_TRANSPORT_WANTED` the application could not honour:
 * on the number it would have bound, waiting requests stop waiting (RFC 3261 §18.1.1:
 * trimmed into a datagram if it fits, else ended with 513). A never-bound number is
 * `SIPRAL_STATUS_INVALID_ARGUMENT` when nothing waits.
 *
 * The next poll raises `SIPRAL_EVENT_KIND_TRANSPORT_FAILED` before the effects.
 * sipral_stack_transport_failed_with adds the TLS reason.
 *
 * Safety
 *
 * Safe to call with any handle value. Reads no memory the caller owns.
 */
sipral_status_t sipral_stack_transport_failed(sipral_handle_t stack, uint32_t transport, sipral_transport_error_t error, uint64_t now_ms);

/**
 * Say that a transport failed, with the TLS library's reason.
 *
 * Does what sipral_stack_transport_failed does, and carries `failure->tls` and
 * `failure->detail` to `SIPRAL_EVENT_KIND_TRANSPORT_FAILED`. A connection that failed before
 * any handshake belongs here too. A transport already down is not retired again but the
 * event is still raised, so each failed reconnect is reported.
 *
 * `SIPRAL_STATUS_INVALID_ARGUMENT`, retiring nothing, for a TLS reason on a non-TLS/WSS
 * transport, or a detail over SIPRAL_TRANSPORT_DETAIL_BYTES or not UTF-8.
 *
 * Safety
 *
 * `failure` must point at a `sipral_transport_failure_t` whose `size` member says how long
 * it is, and its `detail` must be readable for `detail_len` bytes.
 */
sipral_status_t sipral_stack_transport_failed_with(sipral_handle_t stack, const sipral_transport_failure_t *failure, uint64_t now_ms);

/**
 * Say that a connection closed: the far end left, or a read returned zero.
 *
 * Retires like sipral_stack_transport_failed, but kept separate so an orderly close is
 * distinguishable in logs. The event says `SIPRAL_TRANSPORT_ERROR_CLOSED`.
 *
 * Safety
 *
 * Safe to call with any handle value. Reads no memory the caller owns.
 */
sipral_status_t sipral_stack_stream_closed(sipral_handle_t stack, uint32_t transport, uint64_t now_ms);

/**
 * Replace the STUN server list without recreating the stack.
 *
 * `servers` is comma-separated `host:port` in order of preference. Every mapped socket is
 * asked again at once and keeps its answer until the new server replies; servers kept from
 * the old list keep their back-off. On a `SIPRAL_NAT_OFF` stack the main transport starts
 * being mapped; further datagram transports join at their next `sipral_stack_transport_bind`.
 *
 * An empty list stops asking: `Contact`s move back to socket addresses and re-register, and
 * named media sockets are forgotten. `SIPRAL_STATUS_INVALID_ARGUMENT` for that with a TURN
 * server configured, or for a bad entry. `SIPRAL_STATUS_NOT_SUPPORTED` for a list without
 * `SIPRAL_FEATURE_STUN`.
 *
 * Safety
 *
 * `servers` must be readable for `servers_len` bytes.
 */
sipral_status_t sipral_stack_stun_servers(sipral_handle_t stack, const char *servers, size_t servers_len, uint64_t now_ms);

/**
 * Ask where a media socket appears from, before a call is described on it.
 *
 * `local` is the bound `host:port`, the same text as the call's `media_address`. The request
 * waits in sipral_stack_poll_stun; hand the answer to sipral_stack_receive_stun.
 * `SIPRAL_EVENT_KIND_NAT_MAPPING` reports within 5.5 seconds. A call on that
 * `media_address` is then described by the public address and asks for `a=rtcp-mux`.
 * Placing one before the answer is `SIPRAL_STATUS_WRONG_STATE`.
 *
 * Until the call, the socket is asked again every twenty-five seconds to keep the NAT
 * binding alive; keep draining the queue. At most one request per socket waits there. The
 * call spends the mapping: name the socket again for a second call.
 *
 * `SIPRAL_STATUS_WRONG_STATE` without `SIPRAL_NAT_STUN`; `SIPRAL_STATUS_INVALID_ARGUMENT`
 * for one of the stack's own signalling sockets.
 *
 * Safety
 *
 * `local` must be readable for `local_len` bytes.
 */
sipral_status_t sipral_stack_nat_map(sipral_handle_t stack, const char *local, size_t local_len, uint64_t now_ms);

/**
 * Say that a media socket sipral_stack_nat_map named will carry no call, and release it.
 *
 * Its refreshes stop and a waiting request is dropped. A TURN relay is released with a
 * Refresh of lifetime zero (RFC 8656 §8), waiting in sipral_stack_poll_stun. If its
 * Allocate is still unanswered, a late answer is accepted through
 * sipral_stack_receive_stun for up to forty seconds and released the same way. Without
 * this call the server holds the allocation until its lifetime expires, up to ten minutes
 * after `sipral_stack_destroy`.
 *
 * Use it for a closed socket, a call not placed, and every named socket before destroy. A
 * socket already used by a call, or never named, is a no-op.
 *
 * `SIPRAL_STATUS_WRONG_STATE` without `SIPRAL_NAT_STUN`; `SIPRAL_STATUS_INVALID_ARGUMENT`
 * for one of the stack's own signalling sockets.
 *
 * Safety
 *
 * `local` must be readable for `local_len` bytes.
 */
sipral_status_t sipral_stack_nat_unmap(sipral_handle_t stack, const char *local, size_t local_len, uint64_t now_ms);

/**
 * Take the next STUN request a media socket has to send.
 *
 * Same record and rules as `sipral_stack_poll_transmit`, on its own queue: loop until `len`
 * is zero after every sipral_stack_nat_map, sipral_stack_receive_stun and
 * `sipral_stack_poll`. Send from `source` exactly: the server reports the address it sees.
 * `transport` is zero. `protocol` is UDP for a datagram, or TCP/TLS for bytes to write on
 * the TURN connection from `source`.
 *
 * A call on a relayed socket also sends here until it has a media handle: Binding
 * indications keeping the NAT open and the allocation refresh. After that they leave via
 * `sipral_media_poll_transmit`.
 *
 * Safety
 *
 * `transmit` must point at a `sipral_transmit_t` whose `size` member says how long it is
 * and whose buffers are writable for the capacities beside them.
 */
sipral_status_t sipral_stack_poll_stun(sipral_handle_t stack, sipral_transmit_t *transmit);

/**
 * Hand over a datagram that arrived on a media socket sipral_stack_nat_map named,
 * before a call has media on it.
 *
 * Everything arriving on the socket comes here until the call's media handle exists:
 * - TURN answers to what the call's relay sent (an unanswered refresh loses the relay);
 * - the far end's early ICE checks: those signed with this call's password are kept, the
 *   newest sixteen, and answered when the session opens (RFC 8445 §7.3), unless older than
 *   39.5 seconds or the call ended;
 * - between `SIPRAL_EVENT_KIND_MEDIA_STARTED` and `sipral_call_media`, anything, as through
 *   `sipral_media_receive`.
 *
 * A socket shared by forked branches (`keep_all_forks`) keeps coming here; each datagram goes
 * to the branch matching its ICE fragment, transaction or source (RFC 8839 §7.3). A stack
 * without STUN accepts only that and returns `SIPRAL_STATUS_WRONG_STATE` otherwise.
 *
 * `to` is the receiving socket as named, `from` the sender. `SIPRAL_STATUS_OK` when taken;
 * `SIPRAL_STATUS_INVALID_ARGUMENT` for anything else, dropping only that datagram. Only
 * answers from the server's own address to this stack's own requests are believed: that is
 * the defence against a forged mapping.
 *
 * Safety
 *
 * `data` must be readable for `len` bytes, `from` for `from_len`, and `to` for `to_len`.
 */
sipral_status_t sipral_stack_receive_stun(sipral_handle_t stack, const uint8_t *data, size_t len, const char *from, size_t from_len, const char *to, size_t to_len, uint64_t now_ms);

/**
 * Say that the connection a `SIPRAL_TURN_STREAM_OPEN` asked for is open (for TLS, with the
 * handshake done and the certificate checked by the platform).
 *
 * The socket's Allocate then waits in sipral_stack_poll_stun marked with `protocol`;
 * the answer comes back through sipral_stack_turn_receive.
 *
 * `SIPRAL_STATUS_INVALID_ARGUMENT` for a socket with no requested connection,
 * `SIPRAL_STATUS_WRONG_STATE` without `SIPRAL_NAT_STUN`.
 *
 * Safety
 *
 * `local` must be readable for `local_len` bytes.
 */
sipral_status_t sipral_stack_turn_connected(sipral_handle_t stack, const char *local, size_t local_len, uint64_t now_ms);

/**
 * Hand over bytes read from a media socket's TURN connection, in any chunking.
 *
 * Messages are reassembled (RFC 8656 §12.5) and routed like a datagram from the server: to
 * the socket's relay, or to the call holding it (agent or media, audio included). Read the
 * connection for as long as it is open; replies leave through `sipral_media_poll_transmit`.
 *
 * `SIPRAL_STATUS_STREAM_BROKEN` when the bytes are not TURN framing: close the connection.
 * The relay is lost with it and no `SIPRAL_TURN_STREAM_CLOSE` follows.
 * `SIPRAL_STATUS_INVALID_ARGUMENT` for a socket with no open connection.
 *
 * Safety
 *
 * `local` must be readable for `local_len` bytes, and `data` for `len`.
 */
sipral_status_t sipral_stack_turn_receive(sipral_handle_t stack, const char *local, size_t local_len, const uint8_t *data, size_t len, uint64_t now_ms);

/**
 * Say that a media socket's TURN connection closed, or could not be opened.
 *
 * The allocation was tied to the connection (RFC 8656 §3.2), so the relay is gone: one in
 * progress becomes `SIPRAL_NAT_RELAY_FAILED`; a call using it loses that path when consent
 * expires (RFC 7675). Name the socket again to get a new connection. `SIPRAL_STATUS_OK` for
 * a connection already released.
 *
 * Safety
 *
 * `local` must be readable for `local_len` bytes.
 */
sipral_status_t sipral_stack_turn_closed(sipral_handle_t stack, const char *local, size_t local_len, uint64_t now_ms);

/**
 * The short name of an event kind, as a static NUL-terminated
 * string, or null for a number this build has no kind for
 * (reserved numbers included).
 *
 * The string belongs to the library and lives as long as it is
 * loaded.
 *
 * Safety
 *
 * Reads no caller memory; safe from any thread.
 */
const char *sipral_event_kind_name(sipral_event_kind_t kind);

/**
 * How many lines a header field is on, in a whole SIP message.
 *
 * The name is case-insensitive and a compact form equals its long form
 * (RFC 3261 §7.3.3). An absent field counts zero, not a failure.
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
 * `index` is in arrival order, below `sipral_message_header_count`, else
 * `SIPRAL_STATUS_INVALID_ARGUMENT`. `out_offset` and `out_len` locate the
 * value inside `message`, trimmed, line folds kept. For single list values
 * use `sipral_message_header_element`.
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
 * Per RFC 3261 §7.3.1 one line with commas equals several lines, so this
 * splits at commas outside quotes and angle brackets. Only for list
 * fields (`Diversion`, `Contact`...); a `Date` would split wrongly.
 *
 * Safety
 *
 * As `sipral_message_header_count`.
 */
sipral_status_t sipral_message_header_element_count(const uint8_t *message, size_t message_len, const char *name, size_t name_len, size_t *out_count);

/**
 * Where one value of a list field is, across every line the field is on.
 *
 * `index` is below `sipral_message_header_element_count`. Otherwise as
 * `sipral_message_header`.
 *
 * Safety
 *
 * As `sipral_message_header`.
 */
sipral_status_t sipral_message_header_element(const uint8_t *message, size_t message_len, const char *name, size_t name_len, size_t index, size_t *out_offset, size_t *out_len);

/**
 * The operating system says this process stops shortly.
 *
 * Synchronous, bounded by accounts and subscriptions, infallible. Nothing
 * is sent (`docs/16-lifecycle.md` says why de-registering here is wrong)
 * and nothing stays scheduled. Calls are left as they are. `out_report`
 * receives the counts.
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
 * An unmeasurable time passed and any transport may be dead. Beliefs are
 * dropped and proved again, on the existing transport first (most wakes
 * are short); sipral_account_rebind supplies a new one when asked.
 * Safe without a matching sipral_stack_suspending: some platforms
 * only notify on the way back.
 *
 * Safety
 *
 * Safe to call with any handle value.
 */
sipral_status_t sipral_stack_resumed(sipral_handle_t stack, uint64_t now_ms);

/**
 * The network changed; before and after are described.
 *
 * `*_link` is a sipral_link_t. `*_address` is the local address the
 * transports are bound to, an IP literal without port; a change
 * invalidates every transport and binding. `*_interface` is the
 * platform's interface id, only compared, since two networks can hand out
 * the same address. `*_resolves` says whether names resolve there, the
 * one failure that looks healthy. Address and interface may be null with
 * zero length.
 *
 * `out_recovery`, which may be null, receives a sipral_recovery_t.
 * Cheap enough to call on every notification: usually the answer is
 * `SIPRAL_RECOVERY_NOTHING` and nothing happens.
 *
 * Safety
 *
 * Every address and interface pointer must be readable for the length
 * beside it or null with a length of zero, and `out_recovery` must point
 * at one `uint32_t` or be null.
 */
sipral_status_t sipral_stack_network_changed(sipral_handle_t stack, sipral_link_t from_link, const char *from_address, size_t from_address_len, const char *from_interface, size_t from_interface_len, uint32_t from_resolves, sipral_link_t to_link, const char *to_address, size_t to_address_len, const char *to_interface, size_t to_interface_len, uint32_t to_resolves, uint64_t now_ms, sipral_recovery_t *out_recovery);

/**
 * There is no usable interface. Nothing is tried or scheduled until
 * sipral_stack_network_changed reports one back; the opposite of
 * sipral_stack_name_resolution_lost.
 *
 * Safety
 *
 * Safe to call with any handle value.
 */
sipral_status_t sipral_stack_interface_lost(sipral_handle_t stack, uint64_t now_ms);

/**
 * Names no longer become addresses.
 *
 * Everything looks healthy while every address learned from a name may
 * be wrong. Bindings whose registrar is a name stop being trusted; ones
 * aimed at a literal address keep running.
 *
 * Safety
 *
 * Safe to call with any handle value.
 */
sipral_status_t sipral_stack_name_resolution_lost(sipral_handle_t stack, uint64_t now_ms);

/**
 * Point an account at a transport and an address again.
 *
 * `remote` is where its requests go, `host:port`. `contact` is required:
 * after an address change the old one is unreachable, and keeping it
 * would register a binding that receives nothing.
 *
 * `transport` must already exist:
 * SIPRAL_TRANSPORT_MAIN or
 * one sipral_stack_transport_bind
 * bound; anything else is `SIPRAL_STATUS_INVALID_ARGUMENT`. This does not
 * open one.
 *
 * When recovery is waiting for it, the next rung runs at once instead of
 * waiting out the back-off. Otherwise the account is still repointed and
 * the next REGISTER uses it.
 *
 * Safety
 *
 * `remote` must be readable for `remote_len` bytes and `contact` for
 * `contact_len` bytes.
 */
sipral_status_t sipral_account_rebind(sipral_handle_t stack, sipral_handle_t account, uint32_t transport, const char *remote, size_t remote_len, const char *contact, size_t contact_len, uint64_t now_ms);

/**
 * Mark the process start, the zero of sipral_account_time_to_ready.
 *
 * Only the application knows the moment its users wait from. Each call
 * clears and restarts every account's measurement.
 * Safety
 *
 * Safe to call with any handle value.
 */
sipral_status_t sipral_stack_cold_start(sipral_handle_t stack, uint64_t now_ms);

/**
 * Write an account's registration down, so a later start can carry it
 * on without a full handshake.
 *
 * `out_len` always receives the size; a null `buffer` with `capacity`
 * zero asks for it and gets `SIPRAL_STATUS_BUFFER_TOO_SMALL`. Nothing is
 * written to a short buffer.
 *
 * **The bytes are opaque; parsing them is not part of this ABI.** They are
 * versioned and a build reads only its known layouts. Storing and
 * protecting them is the application's: they name an address of record.
 *
 * `SIPRAL_STATUS_WRONG_STATE` when there is nothing to keep: never
 * registered, never will, failed, or given up. The clock is read, not
 * moved, so a snapshot on the way into suspend cannot reject a later
 * `now_ms`.
 * Safety
 *
 * `buffer` must be writable for `capacity` bytes or be null with a
 * `capacity` of zero, and `out_len` must point at one `size_t` or be
 * null.
 */
sipral_status_t sipral_account_freeze(sipral_handle_t stack, sipral_handle_t account, uint8_t *buffer, size_t capacity, size_t *out_len, uint64_t now_ms);

/**
 * Read one back, on an account that was added and has not registered.
 *
 * `asleep_ms` is how long the snapshot sat unused: only the application
 * knows, since no wall clock is read here and instants die with the
 * process. The binding keeps what it had left, less that.
 *
 * The account comes up
 * SIPRAL_REGISTRATION_STATE_RESTORED,
 * not registered, until the refresh this books confirms it.
 *
 * Refused with the account unchanged: `SIPRAL_STATUS_UNSUPPORTED_VERSION`
 * for bytes a newer build wrote, `SIPRAL_STATUS_NOT_SUPPORTED` for an
 * account that does not register, `SIPRAL_STATUS_INVALID_ARGUMENT` for
 * bytes that are not a snapshot, are damaged, or belong to another
 * address of record (which would register somebody else).
 *
 * Safety
 *
 * `snapshot` must be readable for `snapshot_len` bytes.
 */
sipral_status_t sipral_account_thaw(sipral_handle_t stack, sipral_handle_t account, const uint8_t *snapshot, size_t snapshot_len, uint64_t asleep_ms, uint64_t now_ms);

/**
 * How long this account took to become reachable, from
 * sipral_stack_cold_start. A queue's ring timeout must exceed it, or
 * a waking phone is always skipped.
 *
 * `out_has_value` and `out_ms` are zero until there is an answer: before
 * registration, for an account that never registers, or with no cold
 * start declared. Zero with `out_has_value` set is a real answer.
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
 * comma-separated `host:port` in RFC 3263 §4.3 priority order: the first
 * one with an open transport of the wanted protocol is taken, the rest
 * are kept for failover.
 *
 * `protocol` is a sipral_transport_t when the lookup named one (NAPTR,
 * SRV), or zero to keep the flow's protocol. It is never opened: an
 * address on an unbound protocol is passed over; answer again after
 * sipral_stack_transport_bind.
 *
 * `SIPRAL_STATUS_OK` with nothing changed when no address is reachable.
 * `SIPRAL_STATUS_STALE_HANDLE` for a dialog that has ended. No `now_ms`:
 * nothing here is timed.
 *
 * Safety
 *
 * `addresses` must be readable for `addresses_len` bytes.
 */
sipral_status_t sipral_stack_resolved(sipral_handle_t stack, sipral_handle_t dialog, const char *addresses, size_t addresses_len, sipral_transport_t protocol);

/**
 * Point an account's registration at another address.
 *
 * For a registrar with several targets. The binding's `Call-ID`,
 * sequence and credentials are kept, so the registrar sees the same
 * device continuing. A REGISTER in flight or booked is superseded at
 * once; retargeting to the current address is `SIPRAL_STATUS_OK` and
 * sends nothing.
 *
 * `registrar_address` is `host:port`, not a name.
 * `SIPRAL_STATUS_NOT_SUPPORTED` for an account with no registrar.
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
 * Readable during the call and after it, until the record is evicted
 * (`sipral_stack_config_t::diagnostic_records` are kept, 32 when zero).
 * An evicted or still empty record answers `SIPRAL_STATUS_OK` with `{}`.
 *
 * `SIPRAL_STATUS_BUFFER_TOO_SMALL` when `buffer` cannot hold the whole
 * document, with the length needed in `out_needed`.
 *
 * Safety
 *
 * `buffer` must be writable for `capacity` bytes or be null with a
 * capacity of zero, and `out_needed` must point at one `size_t` or be null.
 */
sipral_status_t sipral_call_record_json(sipral_handle_t stack, sipral_handle_t call, char *buffer, size_t capacity, size_t *out_needed);

/**
 * Copy the whole diagnostic document into `buffer`: what a bug report
 * carries, as the JSON `docs/14-diagnostics.md` describes.
 *
 * The endpoint's own record (decisions outside any call), then one record
 * per call still held, and the count of evicted records.
 *
 * `SIPRAL_STATUS_BUFFER_TOO_SMALL` when `buffer` cannot hold the whole
 * document, with the length needed in `out_needed`.
 *
 * Safety
 *
 * `buffer` must be writable for `capacity` bytes or be null with a
 * capacity of zero, and `out_needed` must point at one `size_t` or be null.
 */
sipral_status_t sipral_stack_diagnostics_json(sipral_handle_t stack, char *buffer, size_t capacity, size_t *out_needed);

/**
 * What a `conference` subscription holds about the conference as a
 * whole (RFC 4575 §5.5). `SIPRAL_STATUS_NOT_SUPPORTED` when it holds
 * none: another package, no document yet, or not live.
 *
 * Safety
 *
 * `out_conference` must point at a `sipral_conference_t` whose `size`
 * member says how long it is.
 */
sipral_status_t sipral_subscription_conference(sipral_handle_t stack, sipral_handle_t subscription, sipral_conference_t *out_conference);

/**
 * One user of the conference, by index, in the order the focus first
 * named them. The index is stable only until the next
 * `SIPRAL_EVENT_KIND_CONFERENCE_CHANGED`.
 *
 * Safety
 *
 * `out_user` must point at a `sipral_conference_user_t` whose `size`
 * member says how long it is.
 */
sipral_status_t sipral_subscription_conference_user_at(sipral_handle_t stack, sipral_handle_t subscription, size_t index, sipral_conference_user_t *out_user);

/**
 * Text about the conference or a user, as `which` (a
 * sipral_conference_text_t) and `index` say. `out_needed` gets the bytes
 * needed including the NUL; a small buffer is
 * `SIPRAL_STATUS_BUFFER_TOO_SMALL` with nothing written; absent text is
 * just the NUL.
 *
 * Safety
 *
 * `buffer` must be writable for `capacity` bytes or be null with a
 * capacity of zero, and `out_needed` must point at one `size_t` or be
 * null.
 */
sipral_status_t sipral_subscription_conference_text(sipral_handle_t stack, sipral_handle_t subscription, size_t index, sipral_conference_text_t which, char *buffer, size_t capacity, size_t *out_needed);

/**
 * Put (`focus` 1) or remove (0) `isfocus` on this call's `Contact` from
 * the next message on (RFC 4579 §4.2): the answer, or the next re-INVITE
 * or UPDATE on an established call.
 *
 * Safety
 *
 * Safe to call with any handle value.
 */
sipral_status_t sipral_call_set_focus(sipral_handle_t stack, sipral_handle_t call, uint32_t focus);

/**
 * The conference URI when the far end's `Contact` has `isfocus` (RFC 4579
 * §4.2), copied as `sipral_subscription_conference_text` copies.
 * `SIPRAL_STATUS_NOT_A_FOCUS` otherwise.
 *
 * Safety
 *
 * `buffer` must be writable for `capacity` bytes or be null with a
 * capacity of zero, and `out_needed` must point at one `size_t` or be
 * null.
 */
sipral_status_t sipral_call_conference_uri(sipral_handle_t stack, sipral_handle_t call, char *buffer, size_t capacity, size_t *out_needed);

/**
 * Subscribe to the conference package of the call's focus (RFC 4579
 * §3.4), outside the call's dialog, from the call's account. The
 * subscription outlives the call. `SIPRAL_STATUS_NOT_A_FOCUS` when the
 * far end is not a focus.
 *
 * Safety
 *
 * `out_subscription` must point at one `sipral_handle_t`.
 */
sipral_status_t sipral_call_subscribe_conference(sipral_handle_t stack, sipral_handle_t call, sipral_handle_t *out_subscription, uint64_t now_ms);

/**
 * Publish this account's presence (RFC 3903, RFC 3856 §6.2). Later calls
 * modify the same publication; the stack refreshes it until
 * sipral_account_unpublish_presence.
 *
 * The PUBLISH is only queued on return; the outcome arrives as
 * `SIPRAL_EVENT_KIND_PRESENCE_CHANGED` with `SIPRAL_PRESENCE_KIND_PUBLICATION`.
 *
 * Safety
 *
 * `presence` must point at a `sipral_presence_t` whose `size` member
 * says how long it is, with its pointer readable for the length beside
 * it.
 */
sipral_status_t sipral_account_publish_presence(sipral_handle_t stack, sipral_handle_t account, const sipral_presence_t *presence, uint64_t now_ms);

/**
 * Take this account's published presence away (RFC 3903 §4.5):
 * `SIPRAL_PUBLICATION_STATE_REMOVED` says when it is gone.
 *
 * `SIPRAL_STATUS_WRONG_STATE` for an account that has published none.
 *
 * Safety
 *
 * Safe to call with any handle value.
 */
sipral_status_t sipral_account_unpublish_presence(sipral_handle_t stack, sipral_handle_t account, uint64_t now_ms);

/**
 * Queue text the user typed for the far end, UTF-8.
 * Sent every 300 ms within the far end's rate, with `red` redundancy
 * when agreed. CR, LF or CR LF is a new line; U+0008 erases.
 *
 * `SIPRAL_STATUS_NOT_NEGOTIATED` without a text stream;
 * `SIPRAL_STATUS_EXHAUSTED` when the queue is full (nothing queued).
 *
 * Safety
 *
 * `text` must be readable for `text_len` bytes.
 */
sipral_status_t sipral_media_send_text(sipral_handle_t media, const char *text, size_t text_len);

/**
 * The next datagram due on the call's text socket.
 * `len` zero means nothing due; poll again at the stack's deadline. Send
 * from the `text_address` socket, not the audio one.
 *
 * Safety
 *
 * `packet` must point at a `sipral_media_packet_t` as
 * `sipral_media_capture` describes.
 */
sipral_status_t sipral_media_poll_text(sipral_handle_t media, uint64_t now_ms, sipral_media_packet_t *packet);

/**
 * Take a datagram off the call's text socket.
 * `out_taken` is 1 when it was this call's text, else 0 (not RTP, other
 * payload type, not the latched source, or no text stream).
 *
 * Safety
 *
 * `data` must be readable for `len` bytes, `from` for `from_len`, and
 * `out_taken` must point at one `uint32_t` or be null.
 */
sipral_status_t sipral_media_receive_text(sipral_handle_t media, const uint8_t *data, size_t len, const char *from, size_t from_len, uint64_t now_ms, uint32_t *out_taken);

/**
 * Record a call to a recording server (RFC 7866), and write the
 * recording session's handle to `out_recording`.
 *
 * `SIPRAL_STATUS_WRONG_STATE` before `SIPRAL_EVENT_KIND_MEDIA_STARTED`,
 * for a call whose media this stack does not run, or one already
 * recorded. Sent from the call's account; a stream transport when too
 * large for UDP. Stopped by sipral_call_stop_recording_to,
 * `sipral_call_hangup` on it, or the server hanging up.
 *
 * Safety
 *
 * `config` must point at a `sipral_record_config_t` whose `size` member
 * says how long it is, with every pointer in it readable for the length
 * beside it, and `out_recording` at one `sipral_handle_t`.
 */
sipral_status_t sipral_call_record_to(sipral_handle_t stack, sipral_handle_t call, const sipral_record_config_t *config, sipral_handle_t *out_recording, uint64_t now_ms);

/**
 * Stop copies at once and hang up the recording session. `call` is the
 * recorded call. `SIPRAL_STATUS_WRONG_STATE` when nothing records it.
 *
 * Safety
 *
 * Safe to call with any handle values.
 */
sipral_status_t sipral_call_stop_recording_to(sipral_handle_t stack, sipral_handle_t call, uint64_t now_ms);

/**
 * The next copy of this call's audio for its recording server.
 * `len` zero means none waiting. `out_far_end` is 0 to send from
 * `this_end`, 1 from `far_end`. Drain every frame: copies older than a
 * second are dropped, oldest first.
 *
 * Safety
 *
 * `packet` must point at a `sipral_media_packet_t` as
 * `sipral_media_capture` describes, and `out_far_end` at one
 * `uint32_t`.
 */
sipral_status_t sipral_media_poll_recording(sipral_handle_t media, sipral_media_packet_t *packet, uint32_t *out_far_end);

/**
 * Start recording the signalling this stack is fed (`docs/18-replay.md`).
 * Starting moves the stack onto a fresh seed derived one way from
 * `entropy`; the recording carries that seed, never `entropy`, and
 * stopping moves the stack on again. It records what arrives, never what
 * this end sent.
 *
 * `note` is one line of prose for whoever opens the file later, or null
 * for none.
 *
 * A running recording is replaced, not refused: nothing is written until
 * `sipral_stack_recording_stop`.
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
 * `SIPRAL_STATUS_WRONG_STATE` when no recording is running. Also
 * `SIPRAL_STATUS_WRONG_STATE`, with the reason in the last error, when a
 * message could not go in the text format (a non-text body); then nothing
 * is produced, since a recording missing a message would replay differently.
 *
 * `SIPRAL_STATUS_BUFFER_TOO_SMALL` when `buffer` cannot hold the whole
 * text, with the length needed in `out_needed`; asking again returns the
 * same recording. Once copied out whole, the recording is gone from the stack.
 *
 * Safety
 *
 * `buffer` must be writable for `capacity` bytes or be null with a
 * capacity of zero, and `out_needed` must point at one `size_t` or be null.
 */
sipral_status_t sipral_stack_recording_stop(sipral_handle_t stack, char *buffer, size_t capacity, size_t *out_needed);

/**
 * Ask the platform for its devices and say how many the list holds.
 *
 * Known devices keep their ids; gone ones keep their rows, marked absent.
 * For a settings screen, not polling: the engine refreshes on platform
 * notices. `SIPRAL_STATUS_DEVICE_TIMED_OUT` past `audio_probe_ms`, with
 * the list unchanged.
 *
 * Safety
 *
 * `out_count` must point at one `size_t` or be null.
 */
sipral_status_t sipral_audio_refresh(sipral_handle_t stack, size_t *out_count);

/**
 * How many devices the list holds, present or not.
 *
 * The first read of a list asks the platform, so no refresh is needed.
 * `SIPRAL_STATUS_DEVICE_TIMED_OUT` past `audio_probe_ms`; the next read
 * asks again.
 *
 * Safety
 *
 * `out_count` must point at one `size_t`.
 */
sipral_status_t sipral_audio_device_count(sipral_handle_t stack, size_t *out_count);

/**
 * The device at `index` in the list, and its name into `buffer`.
 *
 * `SIPRAL_STATUS_INVALID_ARGUMENT` past the end. The name is UTF-8 with a
 * trailing NUL; `out_needed`, when not null, receives its length with the
 * NUL. `SIPRAL_STATUS_BUFFER_TOO_SMALL` writes neither `buffer` nor
 * `out_device`.
 *
 * Safety
 *
 * `out_device` must point at a `sipral_audio_device_t` whose `size`
 * member says how long it is; `buffer` must be writable for `capacity`
 * bytes or null with a capacity of zero; `out_needed` must point at one
 * `size_t` or be null.
 */
sipral_status_t sipral_audio_device_at(sipral_handle_t stack, size_t index, sipral_audio_device_t *out_device, char *buffer, size_t capacity, size_t *out_needed);

/**
 * Put a role on a device, or back on the system's route with a
 * `device` of zero.
 *
 * Refused before any platform call, changing nothing:
 * `SIPRAL_STATUS_NO_SUCH_DEVICE` for an unknown id,
 * `SIPRAL_STATUS_DEVICE_UNUSABLE` for a device absent or without channels
 * in the role's direction, `SIPRAL_STATUS_NOT_SUPPORTED` where the
 * platform cannot separate the role (on macOS the microphone follows the
 * system's input).
 *
 * While active the role reopens at once, keeping gain and mute, and
 * `SIPRAL_AUDIO_CHANGE_SELECTED` follows. A chosen device that is
 * unplugged stays the preference and is used again when it returns.
 *
 * Safety
 *
 * Reads no memory the caller owns.
 */
sipral_status_t sipral_audio_select(sipral_handle_t stack, sipral_audio_role_t role, uint32_t device);

/**
 * What a role was asked to be on (zero: the system's route) and what it
 * runs on (zero: not open). They differ while a chosen device is absent.
 *
 * Safety
 *
 * Each out parameter must point at one `uint32_t` or be null.
 */
sipral_status_t sipral_audio_selection(sipral_handle_t stack, sipral_audio_role_t role, uint32_t *out_selected, uint32_t *out_running);

/**
 * Set the gain of one direction, fixed-point with 256 for unity, capped
 * at 1024. Input is the microphone gain, output the volume. Applied to
 * the frames, not the OS control, and kept across device changes.
 *
 * Safety
 *
 * Reads no memory the caller owns.
 */
sipral_status_t sipral_audio_set_gain(sipral_handle_t stack, sipral_audio_direction_t direction, uint32_t gain);

/**
 * The gain of one direction, in the steps `sipral_audio_set_gain` takes.
 *
 * Safety
 *
 * `out_gain` must point at one `uint32_t`.
 */
sipral_status_t sipral_audio_gain(sipral_handle_t stack, sipral_audio_direction_t direction, uint32_t *out_gain);

/**
 * Mute or unmute one direction, kept across device changes. A muted
 * microphone sends silence, so the far end hears a stream, not a gap.
 *
 * Safety
 *
 * Reads no memory the caller owns.
 */
sipral_status_t sipral_audio_set_muted(sipral_handle_t stack, sipral_audio_direction_t direction, uint32_t muted);

/**
 * Whether one direction is muted: one or zero into `out_muted`.
 *
 * Safety
 *
 * `out_muted` must point at one `uint32_t`.
 */
sipral_status_t sipral_audio_muted(sipral_handle_t stack, sipral_audio_direction_t direction, uint32_t *out_muted);

/**
 * The meter of one direction: the peak sample of the last 100 ms, 0 to
 * 32767, held one to two windows. Cheap to poll per frame; zero while
 * nothing is open.
 *
 * Safety
 *
 * `out_peak` must point at one `uint32_t`.
 */
sipral_status_t sipral_audio_level(sipral_handle_t stack, sipral_audio_direction_t direction, uint32_t *out_peak);

/**
 * Open the devices and start the pump now. The only way under
 * `SIPRAL_AUDIO_ACTIVATION_MANUAL`; early under automatic activation.
 * `SIPRAL_STATUS_DEVICE_UNUSABLE` or `SIPRAL_STATUS_DEVICE_TIMED_OUT` for
 * a direction that failed: the engine is still active, silent there.
 *
 * Safety
 *
 * Reads no memory the caller owns.
 */
sipral_status_t sipral_audio_activate(sipral_handle_t stack);

/**
 * Close the devices and stop the pump. The calls stay attached and get
 * their audio back on the next activation.
 *
 * Safety
 *
 * Reads no memory the caller owns.
 */
sipral_status_t sipral_audio_deactivate(sipral_handle_t stack);

/**
 * Ring on the ringer's device (or the loudspeaker) until
 * `sipral_audio_stop_ringing`, or once when `looped` is zero. Mono 16-bit
 * samples at `sample_rate_hz`, copied before return. Under automatic
 * activation a ring opens the devices.
 *
 * Safety
 *
 * `samples` must be readable for `sample_count` `int16_t`.
 */
sipral_status_t sipral_audio_ring(sipral_handle_t stack, const int16_t *samples, size_t sample_count, uint32_t sample_rate_hz, uint32_t looped);

/**
 * Stop the ring. Under automatic activation, with no call up, the
 * devices close with it.
 *
 * Safety
 *
 * Reads no memory the caller owns.
 */
sipral_status_t sipral_audio_stop_ringing(sipral_handle_t stack);

/**
 * What the engine is doing: whether it is active, whether the platform
 * cancels echo, the delay a canceller needs, and where each role runs.
 *
 * Safety
 *
 * `out_info` must point at a `sipral_audio_info_t` whose `size` member
 * says how long it is.
 */
sipral_status_t sipral_audio_info(sipral_handle_t stack, sipral_audio_info_t *out_info);

/**
 * Turn the platform's echo cancellation on or off on a running stack:
 * `on` is a `sipral_toggle_t`, and zero leaves it.
 *
 * Open devices are reopened at once with or without the platform
 * processing, on the same devices with gain and mute, each reported as
 * `SIPRAL_AUDIO_CHANGE_REOPENED`. A call hears a short gap; a refused
 * direction is `SIPRAL_AUDIO_CHANGE_UNAVAILABLE`. Closed devices use it
 * on the next open. `sipral_audio_info_t` says what the platform did.
 * `SIPRAL_STATUS_WRONG_STATE` in application mode.
 *
 * Safety
 *
 * Reads no memory the caller owns.
 */
sipral_status_t sipral_audio_set_system_echo_cancellation(sipral_handle_t stack, sipral_toggle_t on);

/**
 * Send this stack's log to `callback`, at `level` and louder, or turn it
 * off with `SIPRAL_LOG_LEVEL_OFF` or a null callback.
 *
 * Off by default and free when off. A second call replaces callback and
 * level on this stack; queued lines go to the new callback. Turning off
 * drops the queue. Details: `docs/17-observability.md`. A level above
 * `SIPRAL_LOG_LEVEL_TRACE` is `SIPRAL_STATUS_INVALID_ARGUMENT`.
 *
 * Safety
 *
 * `callback`, when not null, is called inside later calls into this stack,
 * after the stack is released (see sipral_log_callback_t). `user_data`
 * must stay valid until the log is replaced or off and no thread is
 * inside this stack.
 */
sipral_status_t sipral_stack_log(sipral_handle_t stack, sipral_log_level_t level, sipral_log_callback_t callback, void *user_data);

/**
 * Copy a redacted snapshot of this stack into `buffer` for a crash
 * report: accounts and registrations, calls and states, transports, media
 * sessions, last refused calls, queues, RTP port range and counters. At
 * most `SIPRAL_STATE_TEXT_MAX` bytes with the NUL.
 *
 * Safe from any thread and never waits. If another thread holds the
 * stack, the last snapshot kept by a poll (at most once a second) is
 * returned, and its first line says so. A media session busy on a frame
 * is reported as busy.
 *
 * `SIPRAL_STATUS_BUFFER_TOO_SMALL`, with the length needed in `out_needed`,
 * when it does not fit; `out_needed` may be null.
 *
 * Safety
 *
 * `buffer` must be writable for `capacity` bytes or be null with a
 * capacity of zero, and `out_needed` must point at one `size_t` or be null.
 */
sipral_status_t sipral_stack_state_text(sipral_handle_t stack, char *buffer, size_t capacity, size_t *out_needed);

/**
 * Reserve a free even port from this stack's RTP range, with the odd
 * port above it kept for RTCP, and write it to `out_port`.
 *
 * `SIPRAL_STATUS_EXHAUSTED` when every pair is taken (the last error
 * gives the range size). `SIPRAL_STATUS_WRONG_STATE` without a range.
 *
 * Safety
 *
 * `out_port` must point at one `uint32_t`.
 */
sipral_status_t sipral_stack_rtp_port_reserve(sipral_handle_t stack, uint32_t *out_port);

/**
 * Give back a reserved port no call used. A port a call took comes back
 * by itself. `SIPRAL_STATUS_INVALID_ARGUMENT` for one not reserved,
 * including a second release.
 *
 * Safety
 *
 * Safe to call with any handle value.
 */
sipral_status_t sipral_stack_rtp_port_release(sipral_handle_t stack, uint32_t port);

/**
 * Verify incoming callers against `config`'s trust anchors from now on
 * (RFC 8224 §6.2).
 *
 * Replaces any earlier setting. Reporting accounts verify only with at
 * least one anchor; `SIPRAL_STIR_VERIFICATION_STRICT` accounts always do.
 * `config.unix_seconds` sets the wall clock at `now_ms`; zero keeps the
 * previous one and is `SIPRAL_STATUS_WRONG_STATE` the first time. A stack
 * whose accounts only sign also calls this, with no anchors.
 *
 * `SIPRAL_STATUS_INVALID_ARGUMENT` for anchors that are not P-256
 * certificates; `SIPRAL_STATUS_NOT_SUPPORTED` without `SIPRAL_FEATURE_STIR`.
 *
 * Safety
 *
 * `config` must point at a `sipral_stir_config_t` whose `size` member
 * says how long it is, with `anchors` readable for `anchors_len` bytes.
 */
sipral_status_t sipral_stack_stir(sipral_handle_t stack, const sipral_stir_config_t *config, uint64_t now_ms);

/**
 * The certificate chain for a call's `Identity`, fetched from the URL of
 * `SIPRAL_VERIFICATION_STAGE_CERTIFICATE_WANTED`: PEM or DER, signing
 * certificate first. Null and zero if it could not be fetched.
 *
 * The verdict is reached and the call delivered or refused before this
 * returns; the events come from the next `sipral_stack_poll`.
 * `SIPRAL_STATUS_STALE_HANDLE` for a call no longer waiting.
 *
 * Safety
 *
 * `chain` must be readable for `chain_len` bytes, or null with a length
 * of zero.
 */
sipral_status_t sipral_call_stir_certificate(sipral_handle_t stack, sipral_handle_t call, const uint8_t *chain, size_t chain_len, uint64_t now_ms);

/**
 * How many streams one call's encryption report has (one audio stream).
 *
 * Safety
 *
 * `out_count` must point at one `size_t`.
 */
sipral_status_t sipral_media_encryption_count(sipral_handle_t media, size_t *out_count);

/**
 * How one stream of a call is protected now. An index past the end is
 * `SIPRAL_STATUS_INVALID_ARGUMENT`.
 *
 * Safety
 *
 * `out_stream` must point at a `sipral_stream_encryption_t` whose `size`
 * member says how long it is.
 */
sipral_status_t sipral_media_encryption_at(sipral_handle_t media, size_t index, sipral_stream_encryption_t *out_stream);

/**
 * Listen for keypad digits in the far-end audio as `mode` (a
 * sipral_dtmf_detection_t) says. `SIPRAL_STATUS_WRONG_STATE` if this
 * stack does not run the call's media.
 *
 * Safety
 *
 * Safe to call with any handle values.
 */
sipral_status_t sipral_call_dtmf_detection(sipral_handle_t stack, sipral_handle_t call, sipral_dtmf_detection_t mode);

/**
 * Listen for call progress and decide who answered, as `config` says;
 * `config.listen` off stops. Call right after `sipral_call_place`. Each
 * finding is a `SIPRAL_EVENT_KIND_PROGRESS_DETECTED`.
 *
 * `SIPRAL_STATUS_WRONG_STATE` if this stack does not run the call's media;
 * `SIPRAL_STATUS_INVALID_ARGUMENT` for a bad value, changing nothing.
 *
 * Safety
 *
 * `config` must point at a `sipral_progress_config_t` whose `size`
 * member says how long it is.
 */
sipral_status_t sipral_call_detect_progress(sipral_handle_t stack, sipral_handle_t call, const sipral_progress_config_t *config);

/**
 * Beep while the call is recorded, as `tone` says; `tone.enabled` off
 * silences it. Applies at once to a running recording.
 *
 * `SIPRAL_STATUS_WRONG_STATE` if this stack does not run the call's media;
 * `SIPRAL_STATUS_INVALID_ARGUMENT` naming the bad member, changing nothing.
 *
 * Safety
 *
 * `tone` must point at a `sipral_consent_tone_t` whose `size` member
 * says how long it is.
 */
sipral_status_t sipral_call_consent_tone(sipral_handle_t stack, sipral_handle_t call, const sipral_consent_tone_t *tone);

/**
 * Start recording this call to `path` as `options` say. With every option
 * zero this is sipral_media_record_start.
 *
 * `SIPRAL_STATUS_INVALID_ARGUMENT` for invalid options or a refused path;
 * `SIPRAL_STATUS_NOT_SUPPORTED` for Ogg Opus in a build without Opus;
 * `SIPRAL_STATUS_RECORDING_FAILED` when the header could not be written.
 *
 * Safety
 *
 * `path` must be readable for `path_len` bytes, and `options` must point
 * at a `sipral_recording_options_t` whose `size` member says how long
 * it is.
 */
sipral_status_t sipral_media_record_start_with(sipral_handle_t media, const char *path, size_t path_len, const sipral_recording_options_t *options);

/**
 * Make a local conference on this stack, holding only this end if it
 * takes part, and write its handle to `out_conference`.
 *
 * In device mode the engine carries it at once, opening the devices
 * under automatic activation.
 *
 * `SIPRAL_STATUS_CONFERENCE_REFUSED` for a rate other than 8, 16, 32 or
 * 48 kHz, or more than 1024 members.
 *
 * Safety
 *
 * `config` must point at a `sipral_local_conference_config_t` whose
 * `size` says how long it is, and `out_conference` at one `sipral_handle_t`.
 */
sipral_status_t sipral_local_conference_create(sipral_handle_t stack, const sipral_local_conference_config_t *config, sipral_handle_t *out_conference);

/**
 * End a conference. Its calls carry their own audio again (in device
 * mode the engine takes them back), a running recording is finished, and
 * the handle is stale.
 *
 * Safety
 *
 * Safe to call with any handle value.
 */
sipral_status_t sipral_local_conference_destroy(sipral_handle_t conference);

/**
 * Add a call, from the next tick, at its codec's rate; its far end hears
 * everybody but itself.
 *
 * The call needs running media. `SIPRAL_STATUS_CONFERENCE_REFUSED` when
 * full, for a call already in a conference or joined with
 * `sipral_call_join`, or for an unmixable codec (rate not 8, 16, 32 or
 * 48 kHz, or frames over 60 ms).
 *
 * Safety
 *
 * Safe to call with any handle values.
 */
sipral_status_t sipral_local_conference_add(sipral_handle_t conference, sipral_handle_t call);

/**
 * Take a call out, from the next tick. Its media is the application's
 * again (in device mode, the engine's).
 *
 * `SIPRAL_STATUS_WRONG_STATE` for a call that is not in it.
 *
 * Safety
 *
 * Safe to call with any handle values.
 */
sipral_status_t sipral_local_conference_remove(sipral_handle_t conference, sipral_handle_t call);

/**
 * Mute or unmute one direction of a member from the next tick: input
 * (others stop hearing it) or output (it stops hearing).
 * `direction` is `SIPRAL_AUDIO_DIRECTION_INPUT` or `_OUTPUT`; `member` is a
 * call in the conference, or the conference handle for this end.
 *
 * `SIPRAL_STATUS_WRONG_STATE` for a member that is not in it.
 *
 * Safety
 *
 * Safe to call with any handle values.
 */
sipral_status_t sipral_local_conference_set_muted(sipral_handle_t conference, sipral_handle_t member, sipral_audio_direction_t direction, uint32_t muted);

/**
 * Set one direction's level for a member, from the next tick, in
 * `sipral_audio_set_gain` steps: 256 unity, 1024 at most. Input is what
 * others hear of it; output is what it hears.
 *
 * Safety
 *
 * Safe to call with any handle values.
 */
sipral_status_t sipral_local_conference_set_gain(sipral_handle_t conference, sipral_handle_t member, sipral_audio_direction_t direction, uint32_t gain);

/**
 * How the conference stands.
 *
 * Safety
 *
 * `out_info` must point at a `sipral_local_conference_info_t` whose
 * `size` says how long it is.
 */
sipral_status_t sipral_local_conference_info(sipral_handle_t conference, sipral_local_conference_info_t *out_info);

/**
 * One member by index: this end first if it takes part, then calls in
 * join order. Stable until the next join or leave.
 *
 * `SIPRAL_STATUS_INVALID_ARGUMENT` for an index past the last member.
 *
 * Safety
 *
 * `out_member` must point at a `sipral_local_conference_member_t` whose
 * `size` says how long it is.
 */
sipral_status_t sipral_local_conference_member_at(sipral_handle_t conference, size_t index, sipral_local_conference_member_t *out_member);

/**
 * Who talked in the last tick, loudest at index zero. Muted members are
 * never listed.
 *
 * `SIPRAL_STATUS_INVALID_ARGUMENT` past the last talker (count in
 * `sipral_local_conference_info_t::talkers`).
 *
 * Safety
 *
 * `out_member` must point at one `sipral_handle_t`.
 */
sipral_status_t sipral_local_conference_talker_at(sipral_handle_t conference, size_t index, sipral_handle_t *out_member);

/**
 * 20 ms of conference in application mode. `mic` is this end's frame,
 * `sipral_local_conference_info_t::frame_samples` long; `speaker` gets
 * what this end hears, same length, written to `out_written`. Without
 * this end, `mic` may be null and `speaker` gets silence.
 *
 * Call every 20 ms from the audio thread, then drain
 * `sipral_local_conference_poll_transmit`.
 *
 * `SIPRAL_STATUS_WRONG_STATE` in device mode;
 * `SIPRAL_STATUS_INVALID_ARGUMENT` for a wrong frame length;
 * `SIPRAL_STATUS_BUFFER_TOO_SMALL` for a short speaker buffer, with the
 * length needed in `out_written`.
 *
 * Safety
 *
 * `mic` readable for `mic_count` `int16_t`, `speaker` writable for
 * `capacity` `int16_t`, `out_written` one `size_t` or null.
 */
sipral_status_t sipral_local_conference_tick(sipral_handle_t conference, uint64_t now_ms, const int16_t *mic, size_t mic_count, int16_t *speaker, size_t capacity, size_t *out_written);

/**
 * The oldest packet a member's call owes its far end, in application
 * mode. `out_call` names the call whose socket sends it; `packet` is
 * filled as by `sipral_media_capture`. `len` zero with
 * `SIPRAL_HANDLE_NONE` means nothing waits. Drain after every tick.
 *
 * Safety
 *
 * `out_call` must point at one `sipral_handle_t`, and `packet` at a
 * `sipral_media_packet_t` as `sipral_media_capture` describes.
 */
sipral_status_t sipral_local_conference_poll_transmit(sipral_handle_t conference, sipral_handle_t *out_call, sipral_media_packet_t *packet);

/**
 * Record the whole conference mix to `path`, one channel, as `options`
 * say (WAV or Ogg Opus, at the conference rate unless another is named).
 *
 * `SIPRAL_STATUS_WRONG_STATE` if already recording;
 * `SIPRAL_STATUS_INVALID_ARGUMENT` for stereo, unusable options or a
 * refused path; `SIPRAL_STATUS_RECORDING_FAILED` if the header write fails.
 *
 * Safety
 *
 * `path` readable for `path_len` bytes; `options` a
 * `sipral_recording_options_t` whose `size` says how long it is.
 */
sipral_status_t sipral_local_conference_record_start(sipral_handle_t conference, const char *path, size_t path_len, const sipral_recording_options_t *options);

/**
 * Stop recording the conference, and finish the file.
 *
 * `SIPRAL_STATUS_WRONG_STATE` when nothing is being recorded.
 *
 * Safety
 *
 * Safe to call with any handle value.
 */
sipral_status_t sipral_local_conference_record_stop(sipral_handle_t conference);

/**
 * Hand the resolver's answer to a
 * SIPRAL_EVENT_KIND_LOOKUP_WANTED
 * back to the account that asked.
 *
 * `name` and `record` are the event's; `answer` is a sipral_dns_answer_t.
 * With `SIPRAL_DNS_ANSWER_RECORDS`, `records` is comma-separated records,
 * each space-separated: TTL in seconds, then zone-file data. A/AAAA:
 * `300 192.0.2.40`; SRV: `300 10 60 5060 sip1.example.com`; NAPTR
 * without the regexp: `300 10 50 S SIP+D2U _sip._udp.example.com`.
 * Null or empty reads as `SIPRAL_DNS_ANSWER_NOTHING`.
 *
 * Answer every lookup, failures included: the procedure waits for each.
 * An answer nothing waits for any more is `SIPRAL_STATUS_OK` and changes
 * nothing.
 *
 * Safety
 *
 * `name` must be readable for `name_len` bytes and `records` for
 * `records_len`.
 */
sipral_status_t sipral_account_looked_up(sipral_handle_t stack, sipral_handle_t account, const char *name, size_t name_len, sipral_dns_record_type_t record, sipral_dns_answer_t answer, const char *records, size_t records_len, uint64_t now_ms);

/**
 * Check the server's leaf certificate (DER) against the account's pin:
 * SHA-256 over the bytes, constant-time. `unix_seconds` is used only for
 * the reported dates.
 *
 * `SIPRAL_STATUS_OK` with `pinned` 1: accept. With `pinned` 0: no pin,
 * platform checks decide. `SIPRAL_STATUS_CERTIFICATE_REFUSED`: refuse;
 * nothing written.
 *
 * Safety
 *
 * `certificate` must be readable for `certificate_len` bytes, and
 * `out_pinned` must point at a `sipral_pinned_certificate_t` whose
 * `size` member says how long it is.
 */
sipral_status_t sipral_account_check_certificate(sipral_handle_t stack, sipral_handle_t account, const uint8_t *certificate, size_t certificate_len, uint64_t unix_seconds, sipral_pinned_certificate_t *out_pinned);

/**
 * The `host:port` to advertise for a socket bound at `bound` whose
 * traffic goes to `peer` (both `host:port` addresses, not names),
 * NUL-terminated into `buffer`.
 *
 * A specific address is used as is; loopback toward a non-loopback
 * `peer` is `SIPRAL_STATUS_UNREACHABLE_ADDRESS`. A wildcard bind uses
 * the OS route toward `peer` (found without sending);
 * `SIPRAL_STATUS_TRANSPORT_DOWN` when there is none. Any thread.
 * `out_needed` gets the length with the NUL; `buffer` may be null with
 * `capacity` zero; `SIPRAL_STATUS_BUFFER_TOO_SMALL` writes nothing.
 *
 * Safety
 *
 * `bound` and `peer` must be readable for their lengths, `buffer` must
 * be writable for `capacity` bytes or be null with a capacity of zero,
 * and `out_needed` must point at one `size_t` or be null.
 */
sipral_status_t sipral_advertised_address(const char *bound, size_t bound_len, const char *peer, size_t peer_len, char *buffer, size_t capacity, size_t *out_needed);

/**
 * Turn the diagnostic trace on or off: `on` is a `sipral_toggle_t`, zero
 * leaves it (ABI 0.34).
 *
 * On, the trace level writes whole SIP messages with the peer and no
 * pseudonyms, to compare runs. Credentials and keys are never written
 * (list in `sipral_stack_config_t::diagnostic_trace`). Off, the trace is
 * pseudonymised. Only applies at `SIPRAL_LOG_LEVEL_TRACE`.
 *
 * Safety
 *
 * Safe to call with any handle value.
 */
sipral_status_t sipral_stack_diagnostic_trace(sipral_handle_t stack, sipral_toggle_t on);

/**
 * The SRTP suites calls use by default, in order, as `sipral_srtp_suite_t`
 * numbers. `out_count` always receives the total; too small a capacity is
 * `SIPRAL_STATUS_BUFFER_TOO_SMALL`.
 *
 * Safety
 *
 * `out_suites` must be writable for `capacity` `uint32_t` or null with a
 * capacity of zero, and `out_count` must point at one `size_t` or be null.
 */
sipral_status_t sipral_stack_srtp_suite_order(sipral_handle_t stack, sipral_srtp_suite_t *out_suites, size_t capacity, size_t *out_count);

/**
 * Set one call's own gain in one direction, on top of the stack's, in
 * `sipral_audio_set_gain` steps. Input is what the microphone sends that
 * call; output is how loud it plays. Kept through hold and conference,
 * gone when the call ends.
 *
 * In a local conference it acts on the call's path, on top of the
 * conference's member controls: input on what its far end hears, output
 * on what it says into the conference.
 * `SIPRAL_STATUS_WRONG_STATE` when the engine is not carrying the call's
 * media: before it starts, after it ends, or in application mode.
 *
 * Safety
 *
 * Reads no memory the caller owns.
 */
sipral_status_t sipral_audio_call_set_gain(sipral_handle_t stack, sipral_handle_t call, sipral_audio_direction_t direction, uint32_t gain);

/**
 * One call's own gain in one direction, in `sipral_audio_set_gain` steps.
 *
 * Safety
 *
 * `out_gain` must point at one `uint32_t`.
 */
sipral_status_t sipral_audio_call_gain(sipral_handle_t stack, sipral_handle_t call, sipral_audio_direction_t direction, uint32_t *out_gain);

/**
 * Mute or unmute one call in one direction while other calls go on (a
 * consultation). A muted direction sends silence. Kept, dropped and
 * refused as `sipral_audio_call_set_gain` is, conference included.
 *
 * Safety
 *
 * Reads no memory the caller owns.
 */
sipral_status_t sipral_audio_call_set_muted(sipral_handle_t stack, sipral_handle_t call, sipral_audio_direction_t direction, uint32_t muted);

/**
 * Whether one call is muted in one direction: one or zero.
 *
 * Safety
 *
 * `out_muted` must point at one `uint32_t`.
 */
sipral_status_t sipral_audio_call_muted(sipral_handle_t stack, sipral_handle_t call, sipral_audio_direction_t direction, uint32_t *out_muted);

/**
 * One call's meter in one direction, after its own gain and mute: what
 * `sipral_audio_level` reads, for one call of several.
 *
 * Safety
 *
 * `out_peak` must point at one `uint32_t`.
 */
sipral_status_t sipral_audio_call_level(sipral_handle_t stack, sipral_handle_t call, sipral_audio_direction_t direction, uint32_t *out_peak);

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


# Every struct and union the header declares, with how long tools/abi-gen
# worked it out to be on each of the three layouts the ABI ships for:
# 64-bit pointers (p64), then 32-bit pointers with 64-bit integers aligned
# to four (p32a4, i386) and to eight (p32a8, ARM and Windows x86). A size
# test holds this binding's own layout of each record, and the library's
# answer from sipral_abi_struct_size, to the number for the layout it runs
# on; bindings/c/abi-layout.c holds a C compiler to all three.
RECORD_LAYOUTS: dict[str, tuple[int, int, int]] = {
    "sipral_abi_version_t": (24, 20, 20),
    "sipral_capabilities_t": (24, 16, 16),
    "sipral_counters_t": (232, 228, 232),
    "sipral_stack_config_t": (432, 296, 304),
    "sipral_poll_result_t": (48, 28, 32),
    "sipral_stack_settings_t": (136, 128, 136),
    "sipral_header_t": (32, 16, 16),
    "sipral_account_config_t": (464, 256, 264),
    "sipral_call_config_t": (160, 92, 92),
    "sipral_codec_info_t": (32, 28, 28),
    "sipral_codec_candidate_t": (24, 20, 20),
    "sipral_path_candidate_t": (88, 60, 64),
    "sipral_media_info_t": (104, 92, 96),
    "sipral_stream_stats_t": (328, 312, 328),
    "sipral_media_packet_t": (64, 36, 36),
    "sipral_processor_frame_t": (64, 32, 32),
    "sipral_transmit_t": (88, 48, 48),
    "sipral_transport_failure_t": (40, 24, 24),
    "sipral_registration_event_t": (40, 36, 40),
    "sipral_call_event_t": (328, 208, 216),
    "sipral_transfer_event_t": (24, 16, 16),
    "sipral_media_event_t": (96, 80, 80),
    "sipral_recovery_event_t": (16, 16, 16),
    "sipral_transport_wanted_event_t": (40, 20, 20),
    "sipral_subscription_event_t": (56, 56, 56),
    "sipral_announce_event_t": (16, 16, 16),
    "sipral_resolve_event_t": (32, 24, 24),
    "sipral_message_event_t": (96, 64, 64),
    "sipral_nat_event_t": (64, 40, 40),
    "sipral_nat_relay_event_t": (72, 40, 40),
    "sipral_referral_event_t": (40, 24, 24),
    "sipral_turn_stream_event_t": (40, 24, 24),
    "sipral_audio_event_t": (20, 20, 20),
    "sipral_stun_server_event_t": (40, 20, 20),
    "sipral_verification_event_t": (96, 60, 60),
    "sipral_progress_event_t": (80, 80, 80),
    "sipral_conference_event_t": (24, 20, 24),
    "sipral_text_event_t": (24, 12, 12),
    "sipral_presence_event_t": (88, 64, 72),
    "sipral_transport_failed_event_t": (32, 24, 24),
    "sipral_local_conference_event_t": (40, 40, 40),
    "sipral_locate_event_t": (48, 32, 32),
    "sipral_challenge_event_t": (40, 20, 20),
    "sipral_token_event_t": (88, 48, 48),
    "sipral_network_test_event_t": (104, 88, 88),
    "sipral_event_payload_t": (328, 208, 216),
    "sipral_event_t": (384, 248, 264),
    "sipral_suspending_t": (32, 16, 16),
    "sipral_screen_request_t": (48, 28, 32),
    "sipral_subscribe_config_t": (88, 48, 48),
    "sipral_watched_dialog_t": (32, 28, 32),
    "sipral_push_echo_t": (24, 20, 24),
    "sipral_audio_device_t": (32, 28, 28),
    "sipral_audio_info_t": (48, 44, 48),
    "sipral_audio_transmit_t": (56, 36, 40),
    "sipral_log_record_t": (64, 40, 48),
    "sipral_stir_config_t": (56, 44, 48),
    "sipral_stream_encryption_t": (32, 28, 28),
    "sipral_progress_config_t": (72, 68, 68),
    "sipral_consent_tone_t": (32, 28, 28),
    "sipral_recording_options_t": (32, 28, 28),
    "sipral_conference_t": (32, 28, 28),
    "sipral_conference_user_t": (24, 20, 20),
    "sipral_presence_t": (32, 20, 20),
    "sipral_record_config_t": (80, 40, 40),
    "sipral_local_conference_config_t": (24, 20, 20),
    "sipral_local_conference_info_t": (56, 48, 48),
    "sipral_local_conference_member_t": (40, 36, 40),
    "sipral_pinned_certificate_t": (40, 36, 40),
    "sipral_network_test_config_t": (48, 36, 40),
}
