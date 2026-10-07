# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek

"""Named integers, built from ``lib`` instead of copied out of it by hand.

The C header numbers a value once (`docs/08-ffi.md`, "A numbered space has
one declaration") and `tools/abi-gen` prints the same numbers into every
binding, this one included. Hand-writing a second Python enum for, say,
`sipral_event_kind_t` would be a second declaration a task like 8.6.5 or
8.6.9 -- each of which is allowed to spend an event kind the header already
reserved for it -- could add a value to without this module noticing. So
every enum here is read off `lib`'s own attribute names at import time: a
regenerated `_sipral_cffi.py` is the only file a new value ever has to reach.
"""

from __future__ import annotations

import enum

from ._sipral_cffi import lib

__all__ = [
    "Status",
    "EventKind",
    "CallState",
    "CallEndReason",
    "RegistrationState",
    "Arrival",
    "DigitSource",
    "DtmfVia",
    "DtmfDetection",
    "ToneRegion",
    "ProgressKind",
    "ProgressTone",
    "AmdVerdict",
    "AmdReason",
    "RecordingFormat",
    "RecordingLayout",
    "LocalConferenceChange",
    "Departure",
    "Direction",
    "MediaFault",
    "Ice",
    "Nat",
    "NatMapping",
    "NatRelay",
    "PathKind",
    "PathOutcome",
    "CandidateKind",
    "Transport",
    "TransportError",
    "TlsFailure",
    "TurnStream",
    "StunServerState",
    "SrtpSuite",
    "Srtp",
    "RegistrationFailure",
    "DnsRecordType",
    "DnsAnswer",
    "LocateFailure",
    "Feature",
    "AudioMode",
    "AudioActivation",
    "AudioRole",
    "AudioDirection",
    "AudioChange",
    "AudioOrigin",
    "Link",
    "Recovery",
    "Verstat",
    "Privacy",
    "AnswerMode",
    "RingSource",
    "IdentityText",
    "SessionTimer",
    "LogLevel",
    "KeyExchange",
    "MediaKind",
    "StirVerification",
    "Attestation",
    "VerificationOutcome",
    "VerificationFailure",
    "VerificationStage",
    "Codec",
    "SubscriptionState",
    "ConferenceUpdate",
    "EndpointStatus",
    "ConferenceText",
    "PresenceKind",
    "Basic",
    "Activity",
    "PublicationState",
    "PublishFailure",
    "ChallengeRefusal",
    "HeldAudio",
    "NetworkVerdict",
    "NetworkProbe",
    "NatKind",
    "ServerReach",
]


def _members(prefix: str, *, exclude: tuple[str, ...] = ()) -> dict[str, int]:
    """Every integer attribute of ``lib`` named ``prefix`` plus a suffix.

    ``exclude`` keeps one numbered space from swallowing another that
    happens to share its start -- `SIPRAL_CODEC_OUTCOME_` out of
    `SIPRAL_CODEC_`, for instance.
    """
    found: dict[str, int] = {}
    for name in dir(lib):
        if not name.startswith(prefix):
            continue
        if any(name.startswith(bad) for bad in exclude):
            continue
        short = name[len(prefix) :]
        if not short:
            continue
        found[short] = int(getattr(lib, name))
    return found


def _enum(python_name: str, prefix: str, *, exclude: tuple[str, ...] = ()) -> type[enum.IntEnum]:
    return enum.IntEnum(python_name, _members(prefix, exclude=exclude))


def _flags(python_name: str, prefix: str) -> type[enum.IntFlag]:
    return enum.IntFlag(python_name, _members(prefix))


#: A `sipral_status_t`. Application code rarely builds one of these itself --
#: :func:`sipral.errors.check` already turns a bad one into
#: :class:`sipral.errors.SipralError` -- but it is here for a caller that
#: wants to branch on `SIPRAL_STATUS_BUSY` without catching an exception for
#: an ordinary, expected contention.
Status = _enum("Status", "SIPRAL_STATUS_")

#: A `sipral_event_kind_t`. `Event.kind` in :mod:`sipral.events` is always a
#: plain `int`, never this enum, because a kind this build does not yet know
#: -- one spent by a task that ran after this package was generated against
#: -- must still be readable rather than raising `ValueError` on the way
#: into an enum member that does not exist yet. Look values up here instead:
#: ``EventKind(event.kind).name`` when the kind is a known one, and
#: `event.kind_name` (read from `sipral_event_kind_name`, which the library
#: itself keeps current) either way.
EventKind = _enum("EventKind", "SIPRAL_EVENT_KIND_")

#: A `sipral_call_state_t`, read from `sipral_call_state` or carried on a
#: call event.
CallState = _enum("CallState", "SIPRAL_CALL_STATE_")

#: A `sipral_call_end_reason_t`, meaningful once `CallState.TERMINATED`.
CallEndReason = _enum("CallEndReason", "SIPRAL_CALL_END_REASON_")

#: A `sipral_registration_state_t`, read from
#: `sipral_account_registration_state` or carried on
#: `SIPRAL_EVENT_KIND_REGISTRATION_CHANGED`.
RegistrationState = _enum("RegistrationState", "SIPRAL_REGISTRATION_STATE_")

#: A `sipral_arrival_t`: what `sipral_media_receive` made of one datagram.
Arrival = _enum("Arrival", "SIPRAL_ARRIVAL_")

#: A `sipral_digit_source_t`: which of the two ways a digit arrived.
DigitSource = _enum("DigitSource", "SIPRAL_DIGIT_SOURCE_")

#: A `sipral_dtmf_t`: which way `sipral_call_send_dtmf` sends a digit.
#: Excludes `sipral_dtmf_detection_t`, which shares the start.
DtmfVia = _enum("DtmfVia", "SIPRAL_DTMF_", exclude=("SIPRAL_DTMF_DETECTION_",))

#: A `sipral_dtmf_detection_t`: when a call listens for digits in the far
#: end's audio (`Stack(dtmf_detection=...)`, `Call.set_dtmf_detection`).
DtmfDetection = _enum("DtmfDetection", "SIPRAL_DTMF_DETECTION_")

#: A `sipral_tone_region_t`: whose call-progress tones
#: :meth:`sipral.call.Call.detect_progress` listens for.
ToneRegion = _enum("ToneRegion", "SIPRAL_TONE_REGION_")

#: A `sipral_progress_kind_t`: what `SIPRAL_EVENT_KIND_PROGRESS_DETECTED`
#: heard, ``fields["what"]``.
ProgressKind = _enum("ProgressKind", "SIPRAL_PROGRESS_KIND_")

#: A `sipral_progress_tone_t`, ``fields["tone"]`` on a progress event.
ProgressTone = _enum("ProgressTone", "SIPRAL_PROGRESS_TONE_")

#: A `sipral_amd_verdict_t`: who answered, ``fields["verdict"]``.
AmdVerdict = _enum("AmdVerdict", "SIPRAL_AMD_VERDICT_")

#: A `sipral_amd_reason_t`: which rule decided, ``fields["reason"]``.
AmdReason = _enum("AmdReason", "SIPRAL_AMD_REASON_")

#: A `sipral_recording_format_t`, for :meth:`sipral.media.Media.record`.
RecordingFormat = _enum("RecordingFormat", "SIPRAL_RECORDING_FORMAT_")

#: A `sipral_recording_layout_t`: one channel, or this end left and the far
#: end right.
RecordingLayout = _enum("RecordingLayout", "SIPRAL_RECORDING_LAYOUT_")

#: A `sipral_direction_t`: which way audio may flow, as seen from here.
Direction = _enum("Direction", "SIPRAL_DIRECTION_")

#: A `sipral_media_fault_t`, on a media event that reports one.
MediaFault = _enum("MediaFault", "SIPRAL_MEDIA_FAULT_")

#: A `sipral_ice_t`: `sipral_stack_config_t::ice` (the stack's default) and
#: `sipral_call_config_t::ice` (a per-call override). `docs/06-nat.md`
#: says why `OFF` is the default.
Ice = _enum("Ice", "SIPRAL_ICE_")

#: A `sipral_nat_t`: `sipral_stack_config_t::nat`. Excludes the mapping and
#: relay outcome spaces below, which share the same `SIPRAL_NAT_` start.
Nat = _enum("Nat", "SIPRAL_NAT_", exclude=("SIPRAL_NAT_MAPPING_", "SIPRAL_NAT_RELAY_"))

#: A `sipral_nat_mapping_t`, carried on `SIPRAL_EVENT_KIND_NAT_MAPPING`.
NatMapping = _enum("NatMapping", "SIPRAL_NAT_MAPPING_")

#: A `sipral_nat_relay_t`, carried on `SIPRAL_EVENT_KIND_NAT_RELAY`.
NatRelay = _enum("NatRelay", "SIPRAL_NAT_RELAY_")

#: A `sipral_path_kind_t`: whether one of `Media.path_candidates()` is a
#: candidate pair or a relay.
PathKind = _enum("PathKind", "SIPRAL_PATH_KIND_")

#: A `sipral_path_outcome_t`: what became of one of `Media.path_candidates()`.
PathOutcome = _enum("PathOutcome", "SIPRAL_PATH_OUTCOME_")

#: A `sipral_candidate_kind_t`: the kind of an ICE candidate (RFC 8445
#: Section 5.1.1), a path's `local_kind` and `remote_kind`.
CandidateKind = _enum("CandidateKind", "SIPRAL_CANDIDATE_KIND_")
#: A `SipralTransport`: what a transport speaks, and what
#: `sipral_stack_config_t::turn_transport` reaches the TURN server over.
#: Excludes the capability bits, the error codes and `SIPRAL_TRANSPORT_MAIN`,
#: which share the same start and are not protocols.
Transport = _enum(
    "Transport",
    "SIPRAL_TRANSPORT_",
    exclude=(
        "SIPRAL_TRANSPORT_BIT_",
        "SIPRAL_TRANSPORT_ERROR_",
        "SIPRAL_TRANSPORT_MAIN",
        "SIPRAL_TRANSPORT_DETAIL_BYTES",
    ),
)

#: A `SipralTransportError`: what went wrong with a transport, carried on
#: `SIPRAL_EVENT_KIND_TRANSPORT_FAILED` as ``fields["error"]``.
TransportError = _enum("TransportError", "SIPRAL_TRANSPORT_ERROR_")

#: A `SipralTlsFailure`: why TLS refused a connection, carried on
#: `SIPRAL_EVENT_KIND_TRANSPORT_FAILED` as ``fields["tls"]`` -- ``UNTRUSTED``,
#: ``NAME_MISMATCH``, ``EXPIRED``, ``HANDSHAKE_REFUSED``, or ``NONE``.
TlsFailure = _enum("TlsFailure", "SIPRAL_TLS_FAILURE_")

#: A `sipral_turn_stream_t`, carried on `SIPRAL_EVENT_KIND_TURN_STREAM`:
#: open the media socket's connection to the TURN server, or close it.
TurnStream = _enum("TurnStream", "SIPRAL_TURN_STREAM_")

#: A `sipral_stun_server_state_t`, carried on
#: `SIPRAL_EVENT_KIND_STUN_SERVER`: the server in use moved, or every one in
#: the list failed.
StunServerState = _enum("StunServerState", "SIPRAL_STUN_SERVER_STATE_")

#: A `sipral_srtp_suite_t`, carried in `payload.media.suite` on
#: `SIPRAL_EVENT_KIND_MEDIA_SECURED`: the transform a call is running, from
#: `AES_CM80` to RFC 7714's `AEAD_AES256_GCM`.
SrtpSuite = _enum("SrtpSuite", "SIPRAL_SRTP_SUITE_")

#: A `sipral_srtp_t`: what a stack, an account or a call asks of SRTP, the
#: ``srtp`` argument -- ``BEST_EFFORT`` offers SDES on plain ``RTP/AVP``.
Srtp = _enum("Srtp", "SIPRAL_SRTP_", exclude=("SIPRAL_SRTP_SUITE_",))

#: A `sipral_registration_failure_t`: why a registration failed,
#: ``fields["failure"]`` on `SIPRAL_EVENT_KIND_REGISTRATION_CHANGED` --
#: ``UNREACHABLE_CONTACT`` for a `Contact` the registrar cannot reach.
RegistrationFailure = _enum("RegistrationFailure", "SIPRAL_REGISTRATION_FAILURE_")

#: A `sipral_dns_record_type_t`: what a lookup asks a name for,
#: ``fields["record"]`` on `SIPRAL_EVENT_KIND_LOOKUP_WANTED`.
DnsRecordType = _enum("DnsRecordType", "SIPRAL_DNS_RECORD_TYPE_")

#: A `sipral_dns_answer_t`: what a resolver said, as a
#: :data:`sipral.locate.Resolver` returns it.
DnsAnswer = _enum("DnsAnswer", "SIPRAL_DNS_ANSWER_")

#: A `sipral_locate_failure_t`: why a server was not located,
#: ``fields["failure"]`` on `SIPRAL_EVENT_KIND_LOCATE_FAILED`.
LocateFailure = _enum("LocateFailure", "SIPRAL_LOCATE_FAILURE_")

#: The `SIPRAL_FEATURE_*` bits of `sipral_capabilities_t::features`: what
#: this build of the library has compiled in, read with
#: :func:`sipral.features` before a stack is created.
Feature = _flags("Feature", "SIPRAL_FEATURE_")

#: A `sipral_audio_t`: who pumps a stack's audio. ``DEVICE`` has the library
#: open the platform's own microphone and loudspeaker; ``APPLICATION`` leaves
#: the frames to :class:`sipral.media.Media`. Only the two values themselves:
#: `SIPRAL_AUDIO_` also starts every other audio space below.
AudioMode = enum.IntEnum(
    "AudioMode",
    {
        name: int(getattr(lib, f"SIPRAL_AUDIO_{name}"))
        for name in ("APPLICATION", "DEVICE")
    },
)

#: A `sipral_audio_activation_t`: when device mode opens the devices.
AudioActivation = _enum("AudioActivation", "SIPRAL_AUDIO_ACTIVATION_")

#: A `sipral_audio_role_t`: what a device is used for -- the call's
#: microphone, its loudspeaker, or the ringer that announces a call.
AudioRole = _enum("AudioRole", "SIPRAL_AUDIO_ROLE_")

#: A `sipral_audio_direction_t`: ``INPUT`` (the microphone, whose gain is the
#: microphone gain) or ``OUTPUT`` (the loudspeaker, whose gain is the volume).
AudioDirection = _enum("AudioDirection", "SIPRAL_AUDIO_DIRECTION_")

#: A `sipral_audio_change_t`, on `SIPRAL_EVENT_KIND_AUDIO_DEVICES_CHANGED`.
AudioChange = _enum("AudioChange", "SIPRAL_AUDIO_CHANGE_")

#: A `sipral_audio_origin_t`: whether the operating system or the engine
#: made an audio change.
AudioOrigin = _enum("AudioOrigin", "SIPRAL_AUDIO_ORIGIN_")

#: A `sipral_link_t`: what kind of network a stack is on, for
#: :meth:`sipral.stack.Stack.move_to`.
Link = _enum("Link", "SIPRAL_LINK_")

#: A `sipral_recovery_t`: what a network change made the stack do. Excludes
#: the ladder's own outcome, rung and failure spaces, which share the start.
Recovery = _enum(
    "Recovery",
    "SIPRAL_RECOVERY_",
    exclude=("SIPRAL_RECOVERY_OUTCOME_", "SIPRAL_RECOVERY_RUNG_", "SIPRAL_RECOVERY_FAILURE_"),
)

#: A `sipral_verstat_t`: what the network concluded about a caller's number,
#: believed only from a trusted peer.
Verstat = _enum("Verstat", "SIPRAL_VERSTAT_")

#: The `SIPRAL_PRIVACY_*` bits (RFC 3323): what a caller's `Privacy` asked
#: for, and what an account asks for on every call it places.
Privacy = _flags("Privacy", "SIPRAL_PRIVACY_")

#: A `sipral_answer_mode_t` (RFC 5373).
AnswerMode = _enum("AnswerMode", "SIPRAL_ANSWER_MODE_")

#: A `sipral_ring_source_t`: whether a call is internal or external, from
#: RFC 7462's `Alert-Info` URNs.
RingSource = _enum("RingSource", "SIPRAL_RING_SOURCE_")

#: A `sipral_identity_text_t`: which list :meth:`sipral.call.Call.identity`
#: reads.
IdentityText = _enum("IdentityText", "SIPRAL_IDENTITY_TEXT_")

#: A `sipral_session_timer_t`: an account's session timer (RFC 4028).
SessionTimer = _enum("SessionTimer", "SIPRAL_SESSION_TIMER_")

#: A `sipral_log_level_t`: how loud a line of :meth:`sipral.Stack.set_log`
#: is, and how much a stack delivers. ``OFF`` is what a stack starts with.
LogLevel = _enum("LogLevel", "SIPRAL_LOG_LEVEL_")

#: A `sipral_key_exchange_t`: how a stream's SRTP keys were exchanged, in
#: the encryption report and on the media events.
KeyExchange = _enum("KeyExchange", "SIPRAL_KEY_EXCHANGE_")

#: A `sipral_media_kind_t`: what a stream of the encryption report carries.
MediaKind = _enum("MediaKind", "SIPRAL_MEDIA_KIND_")

#: A `sipral_stir_verification_t`: what an account does with the `Identity`
#: of the calls it receives (RFC 8224).
StirVerification = _enum("StirVerification", "SIPRAL_STIR_VERIFICATION_")

#: A `sipral_attestation_t` (RFC 8588): ``NONE`` for no SHAKEN claim.
Attestation = _enum("Attestation", "SIPRAL_ATTESTATION_")

#: A `sipral_verification_outcome_t`: what this stack's own check of a
#: caller came to.
VerificationOutcome = _enum("VerificationOutcome", "SIPRAL_VERIFICATION_OUTCOME_")

#: A `sipral_verification_failure_t`: why it did not hold.
VerificationFailure = _enum("VerificationFailure", "SIPRAL_VERIFICATION_FAILURE_")

#: A `sipral_verification_stage_t`: which half of a caller's verification
#: `SIPRAL_EVENT_KIND_CALLER_VERIFICATION` reports.
VerificationStage = _enum("VerificationStage", "SIPRAL_VERIFICATION_STAGE_")

#: A `sipral_codec_t`: the codec a call runs, ``info()["codec"]`` -- L16 at
#: 8 or 16 kHz (``L16_NARROWBAND``, ``L16_WIDEBAND``) only when the stack's
#: codec order names ``L16/8000`` or ``L16/16000``. Excludes the codec
#: outcome space, which shares the start.
Codec = _enum("Codec", "SIPRAL_CODEC_", exclude=("SIPRAL_CODEC_OUTCOME_",))

#: A `sipral_subscription_state_t`: where a subscription is
#: (:attr:`sipral.subscription.Subscription.state`).
SubscriptionState = _enum("SubscriptionState", "SIPRAL_SUBSCRIPTION_STATE_")

#: A `sipral_conference_update_t`: what one conference document did,
#: :attr:`sipral.events.ConferenceNotice.update`.
ConferenceUpdate = _enum("ConferenceUpdate", "SIPRAL_CONFERENCE_UPDATE_")

#: What a `SIPRAL_EVENT_KIND_LOCAL_CONFERENCE_CHANGED` says happened, as
#: :attr:`sipral.events.LocalConferenceNotice.change`: a member joined or
#: left, who is talking changed, or the recording stopped by itself.
LocalConferenceChange = _enum("LocalConferenceChange", "SIPRAL_LOCAL_CONFERENCE_CHANGE_")

#: Why a member left a local conference, as
#: :attr:`sipral.events.LocalConferenceNotice.departure`.
Departure = _enum("Departure", "SIPRAL_DEPARTURE_")

#: A `sipral_endpoint_status_t`: where one endpoint of a conference is (RFC
#: 4575 §5.7.2).
EndpointStatus = _enum("EndpointStatus", "SIPRAL_ENDPOINT_STATUS_")

#: A `sipral_conference_text_t`: which piece of a conference's text is read.
ConferenceText = _enum("ConferenceText", "SIPRAL_CONFERENCE_TEXT_")

#: A `sipral_presence_kind_t`: whether a presence event is about a watched
#: presentity or this account's own publication.
PresenceKind = _enum("PresenceKind", "SIPRAL_PRESENCE_KIND_")

#: A `sipral_basic_t`: PIDF's ``basic``, open or closed (RFC 3863).
Basic = _enum("Basic", "SIPRAL_BASIC_")

#: A `sipral_activity_t`: the RPID activity phones show (RFC 4480).
Activity = _enum("Activity", "SIPRAL_ACTIVITY_")

#: A `sipral_publication_state_t`: what became of this account's published
#: presence.
PublicationState = _enum("PublicationState", "SIPRAL_PUBLICATION_STATE_")

#: A `sipral_publish_failure_t`: why a publication failed.
PublishFailure = _enum("PublishFailure", "SIPRAL_PUBLISH_FAILURE_")

#: A `sipral_challenge_refusal_t`: why an account's password was not given to
#: a challenge, ``fields["refusal"]`` on `SIPRAL_EVENT_KIND_CHALLENGE_DECLINED`.
ChallengeRefusal = _enum("ChallengeRefusal", "SIPRAL_CHALLENGE_REFUSAL_")

#: A `sipral_token_error_t`: what an account's server said was wrong with the
#: access token it was given, ``fields["error"]`` on
#: `SIPRAL_EVENT_KIND_TOKEN_REQUIRED` (RFC 6750 section 3.1).
TokenError = _enum("TokenError", "SIPRAL_TOKEN_ERROR_")

#: A `sipral_network_verdict_t`: what a network test came to,
#: ``fields["verdict"]`` and ``fields["echo_verdict"]`` on
#: `SIPRAL_EVENT_KIND_NETWORK_TEST`.
NetworkVerdict = _enum("NetworkVerdict", "SIPRAL_NETWORK_VERDICT_")

#: A `sipral_network_probe_t`: whether one part of a network test was tried
#: and how it went.
NetworkProbe = _enum("NetworkProbe", "SIPRAL_NETWORK_PROBE_")

#: A `sipral_nat_kind_t`: what a STUN answer says about the NAT in front of
#: this end.
NatKind = _enum("NatKind", "SIPRAL_NAT_KIND_")

#: A `sipral_server_reach_t`: what the account's server did with a network
#: test's ``OPTIONS``.
ServerReach = _enum("ServerReach", "SIPRAL_SERVER_REACH_")

#: A `sipral_held_audio_t`: what a party this end holds is sent,
#: ``Stack(held_audio=...)``.
HeldAudio = _enum("HeldAudio", "SIPRAL_HELD_AUDIO_")
