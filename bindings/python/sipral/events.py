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

__all__ = ["Event"]


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
        }

    if kind == lib.SIPRAL_EVENT_KIND_RESOLVE_NEEDED:
        resolve = payload.resolve
        return {
            "dialog": int(resolve.dialog),
            "host": _text(resolve.host, resolve.host_len),
            "port": int(resolve.port),
            "protocol": int(resolve.protocol),
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

    # Unknown or not yet decoded here: the caller still has `message` and
    # the raw `kind`/`kind_name`, which is what a generic event is for.
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
