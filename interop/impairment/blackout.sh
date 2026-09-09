# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Tiberiu Balasea
#
# The link goes away in the middle of the call and comes back.
#
# This is the shape of every report that says the call froze, and it is the one
# a simple profile cannot produce: loss and delay held constant for a call are
# a bad line, not an interruption. What is being asked is narrow and it is not
# "did audio survive" -- eight seconds of nothing cannot be concealed. It is
# whether the stack is still there afterwards: the dialog kept, the session
# not torn down by a timer that fired into the gap, and a buffer that goes
# back to the target it had rather than staying where the gap left it.
#
# The call is held up long enough to contain the outage with time either side
# of it, so that "before" and "after" are both measured.

WHY="the link disappears for eight seconds in the middle of the call"
NETEM=""
REQUIRE=""
DWELL_MS=20000
DURING='
    sleep 5
    tc qdisc change dev "$link" root netem loss 100%
    case "$(tc qdisc show dev "$link")" in
      *loss*) ;;
      *) echo "IMPAIRMENT-NOT-APPLIED" ;;
    esac
    sleep 8
    tc qdisc change dev "$link" root netem
'
