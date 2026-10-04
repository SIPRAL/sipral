# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek

"""``Settings``: what a stack runs with, `sipral_stack_settings_t` as Python.

Read with :meth:`sipral.Stack.settings`: every default filled in, which is
what a settings screen or a support report shows rather than what was
passed.
"""

from __future__ import annotations

import dataclasses

from ._sipral_cffi import lib
from .enums import SrtpSuite, Transport

__all__ = ["Settings"]


@dataclasses.dataclass(frozen=True)
class Settings:
    """One reading of `sipral_stack_settings` and
    `sipral_stack_srtp_suite_order`."""

    #: The protocol the stack signals over.
    transport: Transport
    #: Whether it retransmits anything itself: only over UDP.
    retransmits: bool
    timer_t1_ms: int
    timer_t2_ms: int
    timer_t4_ms: int
    #: How many codecs the stack offers.
    codec_count: int
    frame_ms: int
    offer_dtmf: bool
    offer_rtcp_mux: bool
    silence_suppression: bool
    #: How long inbound audio may stop before it is reported; zero with the
    #: watchdog off.
    media_stall_ms: int
    g729_annex_b: bool
    referrals: bool
    #: How often an account behind a NAT sends to its registrar; zero when
    #: that keep-alive is off.
    registrar_keepalive_ms: int
    max_dialogs: int
    max_server_transactions: int
    diagnostic_decisions: int
    diagnostic_records: int
    #: The RTP port range as given, ``None`` for none.
    rtp_ports: tuple[int, int] | None
    #: The path MTU as given, zero for unknown.
    path_mtu: int
    #: ``datagram_without_stream_bytes`` as given, zero for never.
    datagram_without_stream_bytes: int
    #: The SRTP suites the stack's calls offer and accept unless their
    #: account names its own, in the order they are offered (ABI 0.35).
    srtp_suites: tuple[SrtpSuite, ...]
    #: Whether a ``pseudonym_salt`` was given; the salt itself is never
    #: read back (ABI 0.35).
    pseudonym_salted: bool
    #: Whether the trace writes whole messages now (ABI 0.35).
    diagnostic_trace: bool
    #: Whether the platform's echo cancellation is asked for, the default
    #: filled in (ABI 0.35); :meth:`sipral.audio.Audio.info` says what the
    #: platform did.
    system_echo_cancellation: bool

    @classmethod
    def read(cls, raw, suites: list[int]) -> "Settings":
        """From a filled `sipral_stack_settings_t` and the suite order."""

        def on(toggle: int) -> bool:
            return int(toggle) == lib.SIPRAL_TOGGLE_ON

        low, high = int(raw.rtp_port_min), int(raw.rtp_port_max)
        return cls(
            transport=Transport(int(raw.transport)),
            retransmits=bool(raw.retransmits),
            timer_t1_ms=int(raw.timer_t1_ms),
            timer_t2_ms=int(raw.timer_t2_ms),
            timer_t4_ms=int(raw.timer_t4_ms),
            codec_count=int(raw.codec_count),
            frame_ms=int(raw.frame_ms),
            offer_dtmf=on(raw.offer_dtmf),
            offer_rtcp_mux=on(raw.offer_rtcp_mux),
            silence_suppression=on(raw.silence_suppression),
            media_stall_ms=int(raw.media_stall_ms),
            g729_annex_b=on(raw.g729_annex_b),
            referrals=on(raw.referrals),
            registrar_keepalive_ms=int(raw.registrar_keepalive_ms),
            max_dialogs=int(raw.max_dialogs),
            max_server_transactions=int(raw.max_server_transactions),
            diagnostic_decisions=int(raw.diagnostic_decisions),
            diagnostic_records=int(raw.diagnostic_records),
            rtp_ports=None if low == 0 and high == 0 else (low, high),
            path_mtu=int(raw.path_mtu),
            datagram_without_stream_bytes=int(raw.datagram_without_stream_bytes),
            srtp_suites=tuple(SrtpSuite(suite) for suite in suites),
            pseudonym_salted=on(raw.pseudonym_salted),
            diagnostic_trace=on(raw.diagnostic_trace),
            system_echo_cancellation=on(raw.system_echo_cancellation),
        )
