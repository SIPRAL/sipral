# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Tiberiu Balasea

"""What ``Stack`` puts on ``stack.events`` and on each ``Call.events``.

`sipral_event_t` and the arm its `kind` names are handed to the C callback
as a pointer valid for the length of that one call and no longer
(`docs/08-ffi.md`, "Signalling across the boundary"). So decoding happens
once, synchronously, inside the callback in :mod:`sipral.stack`, and what
crosses into asyncio afterwards is a plain :class:`Event` holding Python
`bytes` and `int`, never a `cffi` pointer.
"""

from __future__ import annotations

import dataclasses

from ._sipral_cffi import ffi, lib
from .enums import (
    Activity,
    AnswerMode,
    Attestation,
    AudioChange,
    AudioDirection,
    AudioOrigin,
    AudioRole,
    Basic,
    ConferenceUpdate,
    Departure,
    KeyExchange,
    LocalConferenceChange,
    PresenceKind,
    Privacy,
    PublicationState,
    PublishFailure,
    RingSource,
    VerificationFailure,
    VerificationOutcome,
    VerificationStage,
    Verstat,
)

__all__ = [
    "Answering",
    "AudioNotice",
    "CallerIdentity",
    "ConferenceNotice",
    "EndCause",
    "Event",
    "LocalConferenceNotice",
    "Presence",
    "Protection",
    "TypedText",
    "Verification",
]


def _bytes(pointer, length: int) -> bytes | None:
    """Copy ``length`` bytes out from under a pointer good only for now."""
    if pointer == ffi.NULL or length == 0:
        return None
    return bytes(ffi.buffer(pointer, length))


def _text(pointer, length: int) -> str | None:
    raw = _bytes(pointer, length)
    return None if raw is None else raw.decode("utf-8", "replace")


def _statistics(pointer) -> dict[str, object] | None:
    """`sipral_stream_stats_t*`, copied field by field, or ``None``."""
    if pointer == ffi.NULL:
        return None
    stats = pointer[0]
    return {
        "codec": int(stats.codec),
        "round_trip_us": int(stats.round_trip_us) if stats.has_round_trip else None,
        "packets_sent": int(stats.packets_sent),
        "octets_sent": int(stats.octets_sent),
        "packets_received": int(stats.packets_received),
        "packets_lost": int(stats.packets_lost),
        "packets_late": int(stats.packets_late),
        "packets_overflowed": int(stats.packets_overflowed),
        "packets_duplicated": int(stats.packets_duplicated),
        "packets_reordered": int(stats.packets_reordered),
        "delay_us": int(stats.delay_us),
        "target_delay_us": int(stats.target_delay_us),
        "jitter_us": int(stats.jitter_us),
        "loss_rate": float(stats.loss_rate),
        "score": float(stats.score),
        "suffering": bool(stats.suffering),
        "silent_for_ms": int(stats.silent_for_ms),
        "frames_underrun": int(stats.frames_underrun),
    }


@dataclasses.dataclass(frozen=True)
class Event:
    """One event, decoded whole out of ``sipral_event_t`` while it was live.

    ``kind`` is always the raw `sipral_event_kind_t` number, never
    `sipral.enums.EventKind`: a kind this build's generated bindings do not
    know about yet -- because it was spent by another task after this
    package was regenerated against -- must still come through rather than
    raising on the way into an enum with no member for it. ``kind_name`` is
    `sipral_event_kind_name`'s own answer for it, which the library keeps
    current even when this binding's `enums.py` has not been regenerated.

    ``fields`` carries whatever :func:`_decode_payload` could read out of
    the union arm ``kind`` names; a kind this module has no decoder for
    yet -- the same situation as an unknown ``kind`` -- leaves it empty
    rather than raising, so a listener sees a generic event instead of an
    exception it did not ask for.
    """

    kind: int
    kind_name: str
    stack: int
    account: int
    call: int
    message: bytes | None
    fields: dict[str, object]

    @property
    def identity(self) -> "CallerIdentity | None":
        """Who is calling, beyond `From`, on every event of an incoming call
        -- ``None`` on an event that is not about a call."""
        if self.kind not in _CALL_KINDS:
            return None
        f = self.fields
        return CallerIdentity(
            trusted=bool(f["identity_trusted"]),
            asserted_uri=f["asserted_uri"],
            asserted_display=f["asserted_display"],
            verstat=Verstat(f["verstat"]),
            privacy=Privacy(f["privacy"]),
            diverted_from=f["diverted_from"],
            diversion_reason=f["diversion_reason"],
            diversion_count=int(f["diversion_count"]),
            history_count=int(f["history_count"]),
            verification=VerificationOutcome(f["verification"]),
            attestation=Attestation(f["attestation"]),
            verification_failure=VerificationFailure(f["verification_failure"]),
        )

    @property
    def verification(self) -> "Verification | None":
        """`SIPRAL_EVENT_KIND_CALLER_VERIFICATION`, typed: the certificate
        this stack's verification service wants (``stage`` is
        ``CERTIFICATE_WANTED``; fetch ``certificate_url`` and hand it to
        :meth:`sipral.stack.Stack.stir_certificate`), or its verdict on the
        caller. ``None`` on any other event."""
        if self.kind != lib.SIPRAL_EVENT_KIND_CALLER_VERIFICATION:
            return None
        f = self.fields
        return Verification(
            stage=VerificationStage(f["stage"]),
            outcome=VerificationOutcome(f["outcome"]),
            failure=VerificationFailure(f["failure"]),
            attestation=Attestation(f["attestation"]),
            verstat=Verstat(f["verstat"]),
            response_code=int(f["response_code"]),
            refused=bool(f["refused"]),
            certificate_url=f["certificate_url"],
            orig=f["orig"],
            origid=f["origid"],
            detail=f["detail"],
        )

    @property
    def protection(self) -> "Protection | None":
        """How the call's media is protected, on the media events that
        start, change or secure it -- the encryption report as it stood.
        ``None`` on any other event."""
        if self.kind not in _PROTECTION_KINDS:
            return None
        f = self.fields
        return Protection(
            key_exchange=KeyExchange(f["key_exchange"]),
            encrypted=bool(f["encrypted"]),
            authenticated=bool(f["authenticated"]),
            suite=int(f["suite"]),
        )

    @property
    def answering(self) -> "Answering | None":
        """How an incoming call asked to be answered and announced -- ``None``
        on an event that is not about a call."""
        if self.kind not in _CALL_KINDS:
            return None
        f = self.fields
        return Answering(
            answer_mode=AnswerMode(f["answer_mode"]),
            answer_mode_required=bool(f["answer_mode_required"]),
            priv_answer_mode=AnswerMode(f["priv_answer_mode"]),
            priv_answer_mode_required=bool(f["priv_answer_mode_required"]),
            answer_after_ms=f["answer_after_ms"],
            ring_source=RingSource(f["ring_source"]),
            alert_info=f["alert_info"],
        )

    @property
    def cause(self) -> "EndCause | None":
        """Why the far end ended the call: the `Reason` (RFC 3326) of the BYE,
        the CANCEL or the refusal, on `SIPRAL_EVENT_KIND_CALL_ENDED`. ``None``
        on any other event, and on an end that carried no `Reason`."""
        if self.kind != lib.SIPRAL_EVENT_KIND_CALL_ENDED:
            return None
        f = self.fields
        if not f["cause_sip"] and not f["cause_q850"] and not f["cause_text"]:
            return None
        return EndCause(
            sip=int(f["cause_sip"]), q850=int(f["cause_q850"]), text=f["cause_text"]
        )

    @property
    def local_conference(self) -> "LocalConferenceNotice | None":
        """`SIPRAL_EVENT_KIND_LOCAL_CONFERENCE_CHANGED`, typed; ``None`` on
        any other event."""
        if self.kind != lib.SIPRAL_EVENT_KIND_LOCAL_CONFERENCE_CHANGED:
            return None
        f = self.fields
        return LocalConferenceNotice(
            conference=f["conference"],
            change=LocalConferenceChange(f["change"]),
            departure=Departure(f["departure"]),
            member=f["member"],
            members=f["members"],
            talkers=f["talkers"],
            loudest=f["loudest"],
        )

    @property
    def conference(self) -> "ConferenceNotice | None":
        """`SIPRAL_EVENT_KIND_CONFERENCE_CHANGED`, typed; ``None`` on any
        other event."""
        if self.kind != lib.SIPRAL_EVENT_KIND_CONFERENCE_CHANGED:
            return None
        f = self.fields
        return ConferenceNotice(
            subscription=int(f["subscription"]),
            update=ConferenceUpdate(f["update"]),
            version=int(f["version"]),
            users=int(f["users"]),
        )

    @property
    def text(self) -> "TypedText | None":
        """`SIPRAL_EVENT_KIND_TEXT_RECEIVED`, typed; ``None`` on any other
        event."""
        if self.kind != lib.SIPRAL_EVENT_KIND_TEXT_RECEIVED:
            return None
        return TypedText(text=self.fields["text"], missing=int(self.fields["missing"]))

    @property
    def presence(self) -> "Presence | None":
        """`SIPRAL_EVENT_KIND_PRESENCE_CHANGED`, typed; ``None`` on any
        other event."""
        if self.kind != lib.SIPRAL_EVENT_KIND_PRESENCE_CHANGED:
            return None
        f = self.fields
        return Presence(
            kind=PresenceKind(f["kind"]),
            subscription=int(f["subscription"]),
            basic=Basic(f["basic"]),
            activity=Activity(f["activity"]),
            entity=f["entity"],
            note=f["note"],
            publication_state=PublicationState(f["publication_state"]),
            failure=PublishFailure(f["failure"]),
            status_code=int(f["status_code"]),
            expires_ms=int(f["expires_ms"]),
            refresh_in_ms=int(f["refresh_in_ms"]),
        )

    @property
    def audio(self) -> "AudioNotice | None":
        """`SIPRAL_EVENT_KIND_AUDIO_DEVICES_CHANGED`, typed; ``None`` on any
        other event."""
        if self.kind != lib.SIPRAL_EVENT_KIND_AUDIO_DEVICES_CHANGED:
            return None
        f = self.fields
        return AudioNotice(
            change=AudioChange(f["change"]),
            origin=AudioOrigin(f["origin"]),
            role=AudioRole(f["role"]) if f["role"] else None,
            direction=AudioDirection(f["direction"]) if f["direction"] else None,
            device=int(f["device"]) or None,
        )


@dataclasses.dataclass(frozen=True)
class AudioNotice:
    """What changed among the audio devices, in device mode, and who changed
    it. An application notes ``AudioOrigin.SYSTEM`` changes (a headset
    plugged in, the default moved) and never answers an ``ENGINE`` one by
    selecting again: that is the engine doing what was asked, or falling back
    after a loss, and re-applying a choice on it loops. ``device`` is the id
    :meth:`sipral.audio.Audio.devices` lists, or ``None``."""

    change: "AudioChange"
    origin: "AudioOrigin"
    role: "AudioRole | None"
    direction: "AudioDirection | None"
    device: int | None


@dataclasses.dataclass(frozen=True)
class CallerIdentity:
    """What an incoming INVITE said about who is calling, beyond its `From`.

    ``asserted_uri``, ``asserted_display`` and ``verstat`` come only from a
    peer the account names in ``trusted_peers`` (RFC 3325 Section 8):
    ``trusted`` says whether this call came from one. ``privacy`` is what the
    caller's `Privacy` asked for. ``diverted_from`` and ``diversion_reason``
    are the top-most `Diversion` (RFC 5806); the full lists, and every
    `History-Info` entry (RFC 7044), are read with
    :meth:`sipral.call.Call.identity` or
    :meth:`sipral.stack.Stack.call_identity`.
    """

    trusted: bool
    asserted_uri: str | None
    asserted_display: str | None
    verstat: "Verstat"
    privacy: "Privacy"
    diverted_from: str | None
    diversion_reason: str | None
    diversion_count: int
    history_count: int
    #: This stack's own verdict on the caller (RFC 8224), for an account that
    #: verifies: unlike ``verstat``, what this end checked itself.
    verification: "VerificationOutcome" = VerificationOutcome.NONE
    attestation: "Attestation" = Attestation.NONE
    verification_failure: "VerificationFailure" = VerificationFailure.NONE


@dataclasses.dataclass(frozen=True)
class Verification:
    """One half of a caller's verification (RFC 8224 Section 6.2): the
    certificate wanted, or the verdict. ``refused`` says a strict account
    refused the call with ``response_code``, and it ends rather than
    rings."""

    stage: "VerificationStage"
    outcome: "VerificationOutcome"
    failure: "VerificationFailure"
    attestation: "Attestation"
    verstat: "Verstat"
    response_code: int
    refused: bool
    certificate_url: str | None
    orig: str | None
    origid: str | None
    detail: str | None


@dataclasses.dataclass(frozen=True)
class Protection:
    """How one stream is protected: the encryption report's entry, on a
    media event or from :meth:`sipral.media.Media.encryption`. ``suite`` is a
    :class:`sipral.enums.SrtpSuite` number, zero while none runs;
    ``authenticated`` is set for a DTLS-SRTP stream whose handshake checked
    the far end's certificate against its signalled fingerprint, and never
    for SDES."""

    key_exchange: "KeyExchange"
    encrypted: bool
    authenticated: bool
    suite: int
    awaiting_keys: bool = False


@dataclasses.dataclass(frozen=True)
class Answering:
    """How an incoming call asked to be answered (RFC 5373) and rung
    (`Alert-Info`, RFC 7462). ``answer_after_ms`` is not ``None`` when the
    call asked to be answered without the user -- whether to do so is the
    application's policy, never the stack's (RFC 5373 Section 4.2)."""

    answer_mode: "AnswerMode"
    answer_mode_required: bool
    priv_answer_mode: "AnswerMode"
    priv_answer_mode_required: bool
    answer_after_ms: int | None
    ring_source: "RingSource"
    alert_info: str | None


@dataclasses.dataclass(frozen=True)
class EndCause:
    """The `Reason` a call ended with. ``sip`` 200 on a CANCEL is a forking
    proxy saying another phone answered: not a missed call."""

    sip: int
    q850: int
    text: str | None


@dataclasses.dataclass(frozen=True)
class LocalConferenceNotice:
    """What a local conference did (`sipral.LocalConference`): who joined
    or left and why, who is talking, or a recording that stopped by itself.
    ``member`` and ``loudest`` are call handles, or the conference's own
    handle for this end; ``members`` and ``talkers`` how it stands now."""

    conference: int
    change: LocalConferenceChange
    departure: Departure
    member: int
    members: int
    talkers: int
    loudest: int


@dataclasses.dataclass(frozen=True)
class ConferenceNotice:
    """What a conference subscription learnt: a document merged into its
    picture (``ConferenceUpdate.APPLIED``) or the conference deleted by its
    focus (``ENDED``, after which the subscription is being given up), the
    version the picture is at and how many users it holds.
    :meth:`sipral.subscription.Subscription.conference` reads the picture."""

    subscription: int
    update: "ConferenceUpdate"
    version: int
    users: int


@dataclasses.dataclass(frozen=True)
class TypedText:
    """What the far end typed on the call's real-time text stream (RFC
    4103), in order: an erasure as BACKSPACE (U+0008), a new line as LINE
    SEPARATOR (U+2028), a REPLACEMENT CHARACTER (U+FFFD) where a block was
    lost for good, and ``missing`` counting those."""

    text: str
    missing: int


@dataclasses.dataclass(frozen=True)
class Presence:
    """Presence moved. ``PresenceKind.WATCHED``: the ``subscription`` that
    was told, and what the PIDF document said -- open or closed, the first
    RPID activity, the presentity and the first note. ``PUBLICATION``, about
    the event's ``account``: what became of its published presence, why it
    failed, the SIP status the compositor answered with, the lifetime granted
    and when the stack refreshes it."""

    kind: "PresenceKind"
    subscription: int
    basic: "Basic"
    activity: "Activity"
    entity: str | None
    note: str | None
    publication_state: "PublicationState"
    failure: "PublishFailure"
    status_code: int
    expires_ms: int
    refresh_in_ms: int


def _decode_payload(kind: int, payload) -> dict[str, object]:
    # Registration.
    if kind == lib.SIPRAL_EVENT_KIND_REGISTRATION_CHANGED:
        registration = payload.registration
        return {
            "state": int(registration.state),
            "failure": int(registration.failure),
            "status_code": int(registration.status_code),
            "expires_ms": int(registration.expires_ms),
            "refresh_in_ms": int(registration.refresh_in_ms),
            "retry_in_ms": int(registration.retry_in_ms),
        }

    # Every call kind shares `payload.call` (`sipral_call_event_t`).
    if kind in _CALL_KINDS:
        call = payload.call
        return {
            "state": int(call.state),
            "end_reason": int(call.end_reason),
            "status_code": int(call.status_code),
            "other": int(call.other),
            "held_here": bool(call.held_here),
            "held_there": bool(call.held_there),
            "local_sdp": _bytes(call.local_sdp, call.local_sdp_len),
            "remote_sdp": _bytes(call.remote_sdp, call.remote_sdp_len),
            "retry_in_ms": int(call.retry_in_ms),
            "from_uri": _text(call.from_uri, call.from_uri_len),
            "from_display": _text(call.from_display, call.from_display_len),
            "to_uri": _text(call.to_uri, call.to_uri_len),
            "call_id": _text(call.call_id, call.call_id_len),
            "digit": int(call.digit),
            "cause_sip": int(call.cause_sip),
            "cause_q850": int(call.cause_q850),
            "cause_text": _text(call.cause_text, call.cause_text_len),
            "identity_trusted": bool(call.identity_trusted),
            "asserted_uri": _text(call.asserted_uri, call.asserted_uri_len),
            "asserted_display": _text(call.asserted_display, call.asserted_display_len),
            "verstat": int(call.verstat),
            "privacy": int(call.privacy),
            "diverted_from": _text(call.diverted_from, call.diverted_from_len),
            "diversion_reason": _text(call.diversion_reason, call.diversion_reason_len),
            "diversion_count": int(call.diversion_count),
            "history_count": int(call.history_count),
            "answer_mode": int(call.answer_mode),
            "answer_mode_required": bool(call.answer_mode_required),
            "priv_answer_mode": int(call.priv_answer_mode),
            "priv_answer_mode_required": bool(call.priv_answer_mode_required),
            "answer_after_ms": int(call.answer_after_ms) if call.has_answer_after else None,
            "ring_source": int(call.ring_source),
            "alert_info": _text(call.alert_info, call.alert_info_len),
            "verification": int(call.verification),
            "attestation": int(call.attestation),
            "verification_failure": int(call.verification_failure),
        }

    # Who is calling, as a signature says: the certificate wanted, or the
    # verdict (`Stack.stir`, `Stack.stir_certificate`).
    if kind == lib.SIPRAL_EVENT_KIND_CALLER_VERIFICATION:
        verification = payload.verification
        return {
            "stage": int(verification.stage),
            "outcome": int(verification.outcome),
            "failure": int(verification.failure),
            "attestation": int(verification.attestation),
            "verstat": int(verification.verstat),
            "response_code": int(verification.response_code),
            "refused": bool(verification.refused),
            "certificate_url": _text(
                verification.certificate_url, verification.certificate_url_len
            ),
            "orig": _text(verification.orig, verification.orig_len),
            "origid": _text(verification.origid, verification.origid_len),
            "detail": _text(verification.detail, verification.detail_len),
        }

    # The audio engine's own news, in device mode: a device arrived or left,
    # a default moved, a role was put on a device or reopened elsewhere.
    if kind == lib.SIPRAL_EVENT_KIND_AUDIO_DEVICES_CHANGED:
        audio = payload.audio
        return {
            "change": int(audio.change),
            "origin": int(audio.origin),
            "role": int(audio.role),
            "direction": int(audio.direction),
            "device": int(audio.device),
        }

    # Every media kind shares `payload.media` (`sipral_media_event_t`).
    if kind in _MEDIA_KINDS:
        media = payload.media
        return {
            "codec": int(media.codec),
            "direction": int(media.direction),
            "silent_for_ms": int(media.silent_for_ms),
            "recorded_ms": int(media.recorded_ms),
            "fault": int(media.fault),
            "reason": _text(media.reason, media.reason_len),
            "statistics": _statistics(media.statistics),
            "digit": chr(media.digit) if media.digit else None,
            "event_code": int(media.event_code),
            "held_ms": int(media.held_ms),
            "suite": int(media.suite),
            "source": int(media.source),
            "key_exchange": int(media.key_exchange),
            "encrypted": bool(media.encrypted),
            "authenticated": bool(media.authenticated),
        }

    if kind == lib.SIPRAL_EVENT_KIND_RESOLVE_NEEDED:
        resolve = payload.resolve
        return {
            "dialog": int(resolve.dialog),
            "host": _text(resolve.host, resolve.host_len),
            "port": int(resolve.port),
            "protocol": int(resolve.protocol),
        }

    if kind in (
        lib.SIPRAL_EVENT_KIND_LOOKUP_WANTED,
        lib.SIPRAL_EVENT_KIND_LOCATED,
        lib.SIPRAL_EVENT_KIND_LOCATE_FAILED,
    ):
        locate = payload.locate
        return {
            "record": int(locate.record),
            "failure": int(locate.failure),
            "name": _text(locate.name, locate.name_len),
            "targets": _text(locate.targets, locate.targets_len),
            "retry_in_ms": int(locate.retry_in_ms),
        }

    if kind == lib.SIPRAL_EVENT_KIND_TRANSFER_REQUESTED or kind in (
        lib.SIPRAL_EVENT_KIND_TRANSFER_PROGRESS,
        lib.SIPRAL_EVENT_KIND_TRANSFER_DONE,
    ):
        transfer = payload.transfer
        return {
            "status_code": int(transfer.status_code),
            "attended": bool(transfer.attended),
            "target": _text(transfer.target, transfer.target_len),
        }

    if kind == lib.SIPRAL_EVENT_KIND_NAT_MAPPING:
        nat = payload.nat
        return {
            "mapping": int(nat.mapping),
            "signalling": bool(nat.signalling),
            "transport": int(nat.transport),
            "accounts": int(nat.accounts),
            "local": _text(nat.local, nat.local_len),
            "mapped": _text(nat.mapped, nat.mapped_len),
            "previous": _text(nat.previous, nat.previous_len),
        }

    if kind == lib.SIPRAL_EVENT_KIND_NAT_RELAY:
        relay = payload.relay
        return {
            "outcome": int(relay.outcome),
            "code": int(relay.code),
            "local": _text(relay.local, relay.local_len),
            "relayed": _text(relay.relayed, relay.relayed_len),
            "mapped": _text(relay.mapped, relay.mapped_len),
            "reason": _text(relay.reason, relay.reason_len),
        }

    # The STUN server in use moved to another in the list, or every one of
    # them failed (`Stack(stun_fallbacks=...)`).
    if kind == lib.SIPRAL_EVENT_KIND_STUN_SERVER:
        server = payload.stun_server
        return {
            "state": int(server.state),
            "server": _text(server.server, server.server_len),
            "previous": _text(server.previous, server.previous_len),
        }

    # A local conference changed: a member joined or left, who is talking
    # changed, or its recording stopped (`sipral.LocalConference`).
    if kind == lib.SIPRAL_EVENT_KIND_LOCAL_CONFERENCE_CHANGED:
        changed = payload.local_conference
        return {
            "conference": int(changed.conference),
            "change": int(changed.change),
            "departure": int(changed.departure),
            "member": int(changed.member),
            "members": int(changed.members),
            "talkers": int(changed.talkers),
            "loudest": int(changed.loudest),
        }

    # A request too large for a datagram (RFC 3261 Section 18.1.1), and the
    # stream it asks for; `Stack(stream_fallback=True)` opens it itself.
    if kind == lib.SIPRAL_EVENT_KIND_TRANSPORT_WANTED:
        wanted = payload.transport_wanted
        return {
            "protocol": int(wanted.protocol),
            "destination": _text(wanted.destination, wanted.destination_len),
            "request_bytes": int(wanted.request_bytes),
            "limit_bytes": int(wanted.limit_bytes),
        }

    # The signalling connection failed or closed, with the TLS library's
    # reason when TLS refused it (`Stack(signalling=Transport.TLS)`).
    if kind == lib.SIPRAL_EVENT_KIND_TRANSPORT_FAILED:
        lost = payload.transport_failed
        return {
            "transport": int(lost.transport),
            "protocol": int(lost.protocol),
            "error": int(lost.error),
            "tls": int(lost.tls),
            "detail": _text(lost.detail, lost.detail_len),
        }

    # A media socket's connection to a TURN server reached over TCP or TLS:
    # open it, or close it (`Stack` does both itself).
    if kind == lib.SIPRAL_EVENT_KIND_TURN_STREAM:
        stream = payload.turn_stream
        return {
            "state": int(stream.state),
            "protocol": int(stream.protocol),
            "local": _text(stream.local, stream.local_len),
            "server": _text(stream.server, stream.server_len),
        }

    # A REFER outside any dialog (`Stack.accept_referral`), or -- with
    # `status_code` set and nothing else -- the word that one lapsed.
    if kind == lib.SIPRAL_EVENT_KIND_REFERRAL:
        referral = payload.referral
        return {
            "status_code": int(referral.status_code),
            "attended": bool(referral.attended),
            "target": _text(referral.target, referral.target_len),
            "referred_by": _text(referral.referred_by, referral.referred_by_len),
        }

    # What a call told to listen heard: a network's tone, who answered, or
    # the beep (`Call.detect_progress`). `what` says which members mean
    # anything; the rest are zero.
    if kind == lib.SIPRAL_EVENT_KIND_PROGRESS_DETECTED:
        progress = payload.progress
        return {
            "what": int(progress.what),
            "tone": int(progress.tone),
            "verdict": int(progress.verdict),
            "reason": int(progress.reason),
            "at_ms": int(progress.at_ms),
            "initial_silence_ms": int(progress.initial_silence_ms),
            "greeting_ms": int(progress.greeting_ms),
            "words": int(progress.words),
            "frequency_hz": int(progress.frequency_hz),
            "length_ms": int(progress.length_ms),
            "sit_hz": (int(progress.sit_hz_1), int(progress.sit_hz_2), int(progress.sit_hz_3)),
            "sit_ms": (int(progress.sit_ms_1), int(progress.sit_ms_2), int(progress.sit_ms_3)),
        }

    # A conference subscription's picture changed, or the conference ended
    # (`Subscription.conference` reads the picture).
    if kind == lib.SIPRAL_EVENT_KIND_CONFERENCE_CHANGED:
        conference = payload.conference
        return {
            "subscription": int(conference.subscription),
            "update": int(conference.update),
            "version": int(conference.version),
            "users": int(conference.users),
        }

    # What the far end typed on the call's real-time text stream.
    if kind == lib.SIPRAL_EVENT_KIND_TEXT_RECEIVED:
        typed = payload.text
        return {
            "text": _text(typed.text, typed.text_len) or "",
            "missing": int(typed.missing),
        }

    # A watched presentity, or this account's own publication.
    if kind == lib.SIPRAL_EVENT_KIND_PRESENCE_CHANGED:
        presence = payload.presence
        return {
            "kind": int(presence.kind),
            "subscription": int(presence.subscription),
            "basic": int(presence.basic),
            "activity": int(presence.activity),
            "entity": _text(presence.entity, presence.entity_len),
            "note": _text(presence.note, presence.note_len),
            "publication_state": int(presence.publication_state),
            "failure": int(presence.failure),
            "status_code": int(presence.status_code),
            "expires_ms": int(presence.expires_ms),
            "refresh_in_ms": int(presence.refresh_in_ms),
        }

    # A subscription moved (`SIPRAL_EVENT_KIND_SUBSCRIPTION_CHANGED`), or a
    # NOTIFY arrived on it (`SIPRAL_EVENT_KIND_NOTIFIED`).
    if kind in (lib.SIPRAL_EVENT_KIND_SUBSCRIPTION_CHANGED, lib.SIPRAL_EVENT_KIND_NOTIFIED):
        subscription = payload.subscription
        return {
            "subscription": int(subscription.subscription),
            "state": int(subscription.state),
            "reason": int(subscription.reason),
            "status_code": int(subscription.status_code),
            "has_dialog_info": bool(subscription.has_dialog_info),
            "expires_ms": int(subscription.expires_ms),
            "refresh_in_ms": int(subscription.refresh_in_ms),
            "retry_in_ms": int(subscription.retry_in_ms),
            "forked_from": int(subscription.forked_from),
        }

    # The stack's own recovery after a network loss or a resume: which rung
    # of the ladder it reached, and how it settled.
    if kind == lib.SIPRAL_EVENT_KIND_RECOVERY:
        recovery = payload.recovery
        return {
            "state": int(recovery.state),
            "rung": int(recovery.rung),
            "reason": int(recovery.reason),
            "unverified": int(recovery.unverified),
        }

    # A call announced by a push, and one that never came.
    if kind in (lib.SIPRAL_EVENT_KIND_CALL_ANNOUNCED, lib.SIPRAL_EVENT_KIND_ANNOUNCED_CALL_MISSING):
        announce = payload.announce
        return {
            "announcement": int(announce.announcement),
            "waited_ms": int(announce.waited_ms),
        }

    # A MESSAGE received or answered, and a message-summary's counts.
    if kind in (
        lib.SIPRAL_EVENT_KIND_MESSAGE_RECEIVED,
        lib.SIPRAL_EVENT_KIND_MESSAGE_SENT,
        lib.SIPRAL_EVENT_KIND_MESSAGES_WAITING,
    ):
        message = payload.message
        return {
            "message": int(message.message),
            "subscription": int(message.subscription),
            "status_code": int(message.status_code),
            "content_type": _text(message.content_type, message.content_type_len),
            "body": _bytes(message.body, message.body_len),
            "waiting": bool(message.waiting),
            "new_messages": int(message.new_messages),
            "old_messages": int(message.old_messages),
            "urgent_new_messages": int(message.urgent_new_messages),
            "urgent_old_messages": int(message.urgent_old_messages),
            "message_account": _text(message.message_account, message.message_account_len),
        }

    # Unknown to this version of the layer: the caller still has `message`
    # and the raw `kind`/`kind_name`, which is what a generic event is for.
    return {}


_CALL_KINDS = frozenset(
    {
        lib.SIPRAL_EVENT_KIND_INCOMING_CALL,
        lib.SIPRAL_EVENT_KIND_CALL_PROGRESS,
        lib.SIPRAL_EVENT_KIND_CALL_FORKED,
        lib.SIPRAL_EVENT_KIND_CALL_CONFIRMED,
        lib.SIPRAL_EVENT_KIND_SESSION_CHANGED,
        lib.SIPRAL_EVENT_KIND_SESSION_OFFERED,
        lib.SIPRAL_EVENT_KIND_SESSION_CHANGE_FAILED,
        lib.SIPRAL_EVENT_KIND_CALL_REPLACED,
        lib.SIPRAL_EVENT_KIND_CALL_ENDED,
        lib.SIPRAL_EVENT_KIND_DTMF_SENT,
        lib.SIPRAL_EVENT_KIND_CALL_ADDRESS_WANTED,
    }
)

_PROTECTION_KINDS = frozenset(
    {
        lib.SIPRAL_EVENT_KIND_MEDIA_STARTED,
        lib.SIPRAL_EVENT_KIND_MEDIA_CHANGED,
        lib.SIPRAL_EVENT_KIND_MEDIA_SECURED,
    }
)

_MEDIA_KINDS = frozenset(
    {
        lib.SIPRAL_EVENT_KIND_MEDIA_STATISTICS,
        lib.SIPRAL_EVENT_KIND_MEDIA_STALLED,
        lib.SIPRAL_EVENT_KIND_MEDIA_STARTED,
        lib.SIPRAL_EVENT_KIND_MEDIA_CHANGED,
        lib.SIPRAL_EVENT_KIND_MEDIA_RESUMED,
        lib.SIPRAL_EVENT_KIND_MEDIA_FAILED,
        lib.SIPRAL_EVENT_KIND_RECORDING_STOPPED,
        lib.SIPRAL_EVENT_KIND_DIGIT_RECEIVED,
        lib.SIPRAL_EVENT_KIND_MEDIA_SECURED,
        lib.SIPRAL_EVENT_KIND_MEDIA_PATH_CHOSEN,
        lib.SIPRAL_EVENT_KIND_IN_BAND_DIGIT,
        lib.SIPRAL_EVENT_KIND_QUALITY_REPORT_SENT,
        lib.SIPRAL_EVENT_KIND_MEDIA_UNJOINED,
    }
)


def decode(raw) -> Event:
    """Copy one ``sipral_event_t*`` out into a standalone :class:`Event`.

    Called from inside the C callback, and nowhere else: ``raw`` points at
    memory the callback's caller owns, and every field this reads is read
    before this function returns.
    """
    return Event(
        kind=int(raw.kind),
        kind_name=ffi.string(lib.sipral_event_kind_name(raw.kind)).decode("utf-8"),
        stack=int(raw.stack),
        account=int(raw.account),
        call=int(raw.call),
        message=_bytes(raw.message, raw.message_len),
        fields=_decode_payload(int(raw.kind), raw.payload),
    )
