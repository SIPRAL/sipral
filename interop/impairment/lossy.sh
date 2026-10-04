# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek
#
# The general case: everything at once, at a level a call should survive.

WHY="bursty loss, jitter and reordering together"
NETEM="delay 40ms 15ms loss gemodel 4% 40% 60% 2% reorder 1% 30%"
REQUIRE="delay"
