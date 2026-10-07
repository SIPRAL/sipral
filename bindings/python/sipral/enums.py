# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek

"""Named integers, built from ``lib`` instead of copied out of it by hand.

Each enum is read off `lib`'s attribute names at import time, so the C
header stays the only declaration and a regenerated `_sipral_cffi.py` is
all a new value needs.
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

    ``exclude`` drops other spaces sharing the prefix, e.g.
    `SIPRAL_CODEC_OUTCOME_` under `SIPRAL_CODEC_`.
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


#: A `sipral_status_t`, for branching on e.g. `BUSY` without an exception.
Status = _enum("Status", "SIPRAL_STATUS_")

#: A `sipral_event_kind_t`. `Event.kind` stays a plain `int` so unknown kinds
#: do not raise; use ``EventKind(event.kind)`` for known ones, or
#: `event.kind_name` always.
EventKind = _enum("EventKind", "SIPRAL_EVENT_KIND_")

#: A `sipral_call_state_t`.
CallState = _enum("CallState", "SIPRAL_CALL_STATE_")

#: A `sipral_call_end_reason_t`, meaningful once `CallState.TERMINATED`.
CallEndReason = _enum("CallEndReason", "SIPRAL_CALL_END_REASON_")

#: A `sipral_registration_state_t`.
RegistrationState = _enum("RegistrationState", "SIPRAL_REGISTRATION_STATE_")

#: A `sipral_arrival_t`: what `sipral_media_receive` made of one datagram.
Arrival = _enum("Arrival", "SIPRAL_ARRIVAL_")

#: A `sipral_digit_source_t`: which of the two ways a digit arrived.
DigitSource = _enum("DigitSource", "SIPRAL_DIGIT_SOURCE_")

#: A `sipral_dtmf_t`: how :meth:`sipral.call.Call.send_dtmf` sends a digit.
DtmfVia = _enum("DtmfVia", "SIPRAL_DTMF_", exclude=("SIPRAL_DTMF_DETECTION_",))

#: A `sipral_dtmf_detection_t`: when to detect digits in the far end's audio.
DtmfDetection = _enum("DtmfDetection", "SIPRAL_DTMF_DETECTION_")

#: A `sipral_tone_region_t` for :meth:`sipral.call.Call.detect_progress`.
ToneRegion = _enum("ToneRegion", "SIPRAL_TONE_REGION_")

#: A `sipral_progress_kind_t`, ``fields["what"]`` on a progress event.
ProgressKind = _enum("ProgressKind", "SIPRAL_PROGRESS_KIND_")

#: A `sipral_progress_tone_t`, ``fields["tone"]`` on a progress event.
ProgressTone = _enum("ProgressTone", "SIPRAL_PROGRESS_TONE_")

#: A `sipral_amd_verdict_t`: who answered, ``fields["verdict"]``.
AmdVerdict = _enum("AmdVerdict", "SIPRAL_AMD_VERDICT_")

#: A `sipral_amd_reason_t`: which rule decided, ``fields["reason"]``.
AmdReason = _enum("AmdReason", "SIPRAL_AMD_REASON_")

#: A `sipral_recording_format_t`, for :meth:`sipral.media.Media.record`.
RecordingFormat = _enum("RecordingFormat", "SIPRAL_RECORDING_FORMAT_")

#: A `sipral_recording_layout_t`: mono, or this end left, far end right.
RecordingLayout = _enum("RecordingLayout", "SIPRAL_RECORDING_LAYOUT_")

#: A `sipral_direction_t`: which way audio may flow, as seen from here.
Direction = _enum("Direction", "SIPRAL_DIRECTION_")

#: A `sipral_media_fault_t`, on a media event that reports one.
MediaFault = _enum("MediaFault", "SIPRAL_MEDIA_FAULT_")

#: A `sipral_ice_t`, per stack or per call; `docs/06-nat.md` says why `OFF`
#: is the default.
Ice = _enum("Ice", "SIPRAL_ICE_")

#: A `sipral_nat_t`.
Nat = _enum("Nat", "SIPRAL_NAT_", exclude=("SIPRAL_NAT_MAPPING_", "SIPRAL_NAT_RELAY_"))

#: A `sipral_nat_mapping_t`, carried on `SIPRAL_EVENT_KIND_NAT_MAPPING`.
NatMapping = _enum("NatMapping", "SIPRAL_NAT_MAPPING_")

#: A `sipral_nat_relay_t`, carried on `SIPRAL_EVENT_KIND_NAT_RELAY`.
NatRelay = _enum("NatRelay", "SIPRAL_NAT_RELAY_")

#: A `sipral_path_kind_t`: candidate pair or relay.
PathKind = _enum("PathKind", "SIPRAL_PATH_KIND_")

#: A `sipral_path_outcome_t`: what became of one of `Media.path_candidates()`.
PathOutcome = _enum("PathOutcome", "SIPRAL_PATH_OUTCOME_")

#: A `sipral_candidate_kind_t` (RFC 8445 Section 5.1.1).
CandidateKind = _enum("CandidateKind", "SIPRAL_CANDIDATE_KIND_")
#: A `SipralTransport`: UDP, TCP or TLS.
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

#: A `SipralTransportError`, ``fields["error"]`` on a transport failure.
TransportError = _enum("TransportError", "SIPRAL_TRANSPORT_ERROR_")

#: A `SipralTlsFailure`, ``fields["tls"]`` on a transport failure.
TlsFailure = _enum("TlsFailure", "SIPRAL_TLS_FAILURE_")

#: A `sipral_turn_stream_t`: open or close a TURN connection.
TurnStream = _enum("TurnStream", "SIPRAL_TURN_STREAM_")

#: A `sipral_stun_server_state_t`: server moved, or all failed.
StunServerState = _enum("StunServerState", "SIPRAL_STUN_SERVER_STATE_")

#: A `sipral_srtp_suite_t`: the SRTP transform in use.
SrtpSuite = _enum("SrtpSuite", "SIPRAL_SRTP_SUITE_")

#: A `sipral_srtp_t`, the ``srtp`` argument; ``BEST_EFFORT`` offers SDES on
#: plain ``RTP/AVP``.
Srtp = _enum("Srtp", "SIPRAL_SRTP_", exclude=("SIPRAL_SRTP_SUITE_",))

#: A `sipral_registration_failure_t`, ``fields["failure"]`` on a
#: registration event.
RegistrationFailure = _enum("RegistrationFailure", "SIPRAL_REGISTRATION_FAILURE_")

#: A `sipral_dns_record_type_t`, ``fields["record"]`` on a lookup request.
DnsRecordType = _enum("DnsRecordType", "SIPRAL_DNS_RECORD_TYPE_")

#: A `sipral_dns_answer_t`, returned by a :data:`sipral.locate.Resolver`.
DnsAnswer = _enum("DnsAnswer", "SIPRAL_DNS_ANSWER_")

#: A `sipral_locate_failure_t`, ``fields["failure"]`` on a locate failure.
LocateFailure = _enum("LocateFailure", "SIPRAL_LOCATE_FAILURE_")

#: The `SIPRAL_FEATURE_*` bits :func:`sipral.features` returns.
Feature = _flags("Feature", "SIPRAL_FEATURE_")

#: A `sipral_audio_t`: ``DEVICE`` (the library drives the platform devices)
#: or ``APPLICATION`` (frames via :class:`sipral.media.Media`). Listed by
#: name because `SIPRAL_AUDIO_` prefixes the other audio spaces too.
AudioMode = enum.IntEnum(
    "AudioMode",
    {
        name: int(getattr(lib, f"SIPRAL_AUDIO_{name}"))
        for name in ("APPLICATION", "DEVICE")
    },
)

#: A `sipral_audio_activation_t`: when device mode opens the devices.
AudioActivation = _enum("AudioActivation", "SIPRAL_AUDIO_ACTIVATION_")

#: A `sipral_audio_role_t`: microphone, loudspeaker or ringer.
AudioRole = _enum("AudioRole", "SIPRAL_AUDIO_ROLE_")

#: A `sipral_audio_direction_t`: ``INPUT`` or ``OUTPUT``.
AudioDirection = _enum("AudioDirection", "SIPRAL_AUDIO_DIRECTION_")

#: A `sipral_audio_change_t`, on `SIPRAL_EVENT_KIND_AUDIO_DEVICES_CHANGED`.
AudioChange = _enum("AudioChange", "SIPRAL_AUDIO_CHANGE_")

#: A `sipral_audio_origin_t`: the system or the engine.
AudioOrigin = _enum("AudioOrigin", "SIPRAL_AUDIO_ORIGIN_")

#: A `sipral_link_t` for :meth:`sipral.stack.Stack.move_to`.
Link = _enum("Link", "SIPRAL_LINK_")

#: A `sipral_recovery_t`: what a network change made the stack do.
Recovery = _enum(
    "Recovery",
    "SIPRAL_RECOVERY_",
    exclude=("SIPRAL_RECOVERY_OUTCOME_", "SIPRAL_RECOVERY_RUNG_", "SIPRAL_RECOVERY_FAILURE_"),
)

#: A `sipral_verstat_t`, believed only from a trusted peer.
Verstat = _enum("Verstat", "SIPRAL_VERSTAT_")

#: The `SIPRAL_PRIVACY_*` bits (RFC 3323).
Privacy = _flags("Privacy", "SIPRAL_PRIVACY_")

#: A `sipral_answer_mode_t` (RFC 5373).
AnswerMode = _enum("AnswerMode", "SIPRAL_ANSWER_MODE_")

#: A `sipral_ring_source_t`: internal or external (RFC 7462).
RingSource = _enum("RingSource", "SIPRAL_RING_SOURCE_")

#: A `sipral_identity_text_t` for :meth:`sipral.call.Call.identity`.
IdentityText = _enum("IdentityText", "SIPRAL_IDENTITY_TEXT_")

#: A `sipral_session_timer_t`: an account's session timer (RFC 4028).
SessionTimer = _enum("SessionTimer", "SIPRAL_SESSION_TIMER_")

#: A `sipral_log_level_t`; a stack starts at ``OFF``.
LogLevel = _enum("LogLevel", "SIPRAL_LOG_LEVEL_")

#: A `sipral_key_exchange_t`: how SRTP keys were exchanged.
KeyExchange = _enum("KeyExchange", "SIPRAL_KEY_EXCHANGE_")

#: A `sipral_media_kind_t`: what a stream of the encryption report carries.
MediaKind = _enum("MediaKind", "SIPRAL_MEDIA_KIND_")

#: A `sipral_stir_verification_t` (RFC 8224).
StirVerification = _enum("StirVerification", "SIPRAL_STIR_VERIFICATION_")

#: A `sipral_attestation_t` (RFC 8588): ``NONE`` for no SHAKEN claim.
Attestation = _enum("Attestation", "SIPRAL_ATTESTATION_")

#: A `sipral_verification_outcome_t`.
VerificationOutcome = _enum("VerificationOutcome", "SIPRAL_VERIFICATION_OUTCOME_")

#: A `sipral_verification_failure_t`: why it did not hold.
VerificationFailure = _enum("VerificationFailure", "SIPRAL_VERIFICATION_FAILURE_")

#: A `sipral_verification_stage_t`: certificate wanted, or verdict.
VerificationStage = _enum("VerificationStage", "SIPRAL_VERIFICATION_STAGE_")

#: A `sipral_codec_t`, ``info()["codec"]``; L16 only when the codec order
#: names ``L16/8000`` or ``L16/16000``.
Codec = _enum("Codec", "SIPRAL_CODEC_", exclude=("SIPRAL_CODEC_OUTCOME_",))

#: A `sipral_subscription_state_t`.
SubscriptionState = _enum("SubscriptionState", "SIPRAL_SUBSCRIPTION_STATE_")

#: A `sipral_conference_update_t`.
ConferenceUpdate = _enum("ConferenceUpdate", "SIPRAL_CONFERENCE_UPDATE_")

#: What a local conference change was.
LocalConferenceChange = _enum("LocalConferenceChange", "SIPRAL_LOCAL_CONFERENCE_CHANGE_")

#: Why a member left a local conference.
Departure = _enum("Departure", "SIPRAL_DEPARTURE_")

#: A `sipral_endpoint_status_t` (RFC 4575 §5.7.2).
EndpointStatus = _enum("EndpointStatus", "SIPRAL_ENDPOINT_STATUS_")

#: A `sipral_conference_text_t`: which piece of a conference's text is read.
ConferenceText = _enum("ConferenceText", "SIPRAL_CONFERENCE_TEXT_")

#: A `sipral_presence_kind_t`: watched presentity or own publication.
PresenceKind = _enum("PresenceKind", "SIPRAL_PRESENCE_KIND_")

#: A `sipral_basic_t`: PIDF's ``basic``, open or closed (RFC 3863).
Basic = _enum("Basic", "SIPRAL_BASIC_")

#: A `sipral_activity_t`: the RPID activity phones show (RFC 4480).
Activity = _enum("Activity", "SIPRAL_ACTIVITY_")

#: A `sipral_publication_state_t`.
PublicationState = _enum("PublicationState", "SIPRAL_PUBLICATION_STATE_")

#: A `sipral_publish_failure_t`: why a publication failed.
PublishFailure = _enum("PublishFailure", "SIPRAL_PUBLISH_FAILURE_")

#: A `sipral_challenge_refusal_t`: why a challenge was not answered.
ChallengeRefusal = _enum("ChallengeRefusal", "SIPRAL_CHALLENGE_REFUSAL_")

#: A `sipral_token_error_t` (RFC 6750 section 3.1).
TokenError = _enum("TokenError", "SIPRAL_TOKEN_ERROR_")

#: A `sipral_network_verdict_t`, for a network test and its echo part.
NetworkVerdict = _enum("NetworkVerdict", "SIPRAL_NETWORK_VERDICT_")

#: A `sipral_network_probe_t`: one part of a network test.
NetworkProbe = _enum("NetworkProbe", "SIPRAL_NETWORK_PROBE_")

#: A `sipral_nat_kind_t`: the NAT a STUN answer revealed.
NatKind = _enum("NatKind", "SIPRAL_NAT_KIND_")

#: A `sipral_server_reach_t`: the server's reply to a test ``OPTIONS``.
ServerReach = _enum("ServerReach", "SIPRAL_SERVER_REACH_")

#: A `sipral_held_audio_t`: what a held party hears.
HeldAudio = _enum("HeldAudio", "SIPRAL_HELD_AUDIO_")
