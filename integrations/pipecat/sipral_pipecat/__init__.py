# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek

"""Sipral for Pipecat: a phone call as a Pipecat transport.

::

    transport = SipralTransport(call)
    pipeline = Pipeline([transport.input(), stt, llm, tts, transport.output()])

:class:`SipralTransport` carries one call whose media started in application
audio mode; :func:`serve` answers every call to an account and runs one
pipeline per call. See ``README.md`` and ``examples/phone_agent.py``.
"""

from __future__ import annotations

from .serve import PipelineFactory, serve
from .transport import (
    SipralInputTransport,
    SipralOutputTransport,
    SipralTransport,
    SipralTransportParams,
    wait_for_media,
)

__version__ = "1.1.0"

__all__ = [
    "PipelineFactory",
    "SipralInputTransport",
    "SipralOutputTransport",
    "SipralTransport",
    "SipralTransportParams",
    "__version__",
    "serve",
    "wait_for_media",
]
