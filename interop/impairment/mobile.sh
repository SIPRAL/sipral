# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek
#
# A phone on a cell that is not quite good enough. Two per cent loss sounds
# harmless averaged out; in bursts it takes whole syllables, which is what a
# concealer either hides or does not.
#
# The delay moves rather than sitting still, because a radio scheduler is what
# is moving it, and a buffer that has settled on a target has to give it back.

WHY="two per cent loss in bursts, on a link whose delay moves"
NETEM="delay 60ms 30ms distribution normal loss gemodel 2% 40% 60% 1%"
REQUIRE="delay"
