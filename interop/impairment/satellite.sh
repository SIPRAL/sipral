# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek
#
# A geostationary hop each way: about 250 ms of pure distance, half a second of
# round trip, and very little jitter, because the delay is the speed of light
# and not a queue.
#
# The interesting failure here is not audio quality, it is arithmetic: a
# retransmission schedule tuned on a fast path gives up before a satellite
# answers, and a jitter buffer that reads a large but steady delay as
# instability will keep growing for nothing.

WHY="a geostationary carrier: half a second of round trip, and steady"
NETEM="delay 250ms 10ms distribution normal loss 0.5%"
REQUIRE="delay"
