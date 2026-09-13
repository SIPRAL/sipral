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
#
# Two things have to be true for a run of this to prove anything, and the first
# version of it checked neither. The outage has to land in the call, and it has
# to actually eat the call's packets.
#
# It used to start five seconds after the container did. On a host where the
# call took longer than that to begin sending, the eight seconds fell on the
# REGISTER and the INVITE, whose own retransmissions outlasted them, and the
# call then ran clean from start to finish -- and passed, because the only thing
# looked at was whether the qdisc said `loss`. It did; the loss simply happened
# to nothing. So the outage now waits until audio is visibly going out through
# the qdisc, and afterwards netem's own drop counter has to show that it took
# the call's packets. A run where it did not is reported as proving nothing,
# never as a pass.

WHY="the link disappears for eight seconds in the middle of the call"
NETEM=""
REQUIRE=""
DWELL_MS=20000
DURING='
    # packets out through this qdisc, and packets it has thrown away
    sent() { tc -s qdisc show dev "$link" | sed -n "s/.*Sent [0-9]* bytes \([0-9]*\) pkt.*/\1/p"; }
    dropped() { tc -s qdisc show dev "$link" | sed -n "s/.*dropped \([0-9]*\).*/\1/p"; }
    missed() { echo "$1"; echo "IMPAIRMENT-NOT-APPLIED"; exit 0; }

    # A call that is up sends fifty packets a second; signalling is a handful.
    # A hundred and fifty out means audio has been flowing for a few seconds,
    # so the outage lands inside the call with time on both sides of it.
    tries=0
    while :; do
        out=$(sent)
        [ -n "$out" ] || missed "the qdisc counters could not be read, so nothing below could be checked"
        [ "$out" -ge 150 ] && break
        tries=$((tries + 1))
        [ "$tries" -lt 150 ] || missed "the call never started sending, so there was no call for the outage to land in"
        sleep 0.2
    done

    before=$(dropped)
    tc qdisc change dev "$link" root netem loss 100%
    case "$(tc qdisc show dev "$link")" in
      *loss*) ;;
      *) missed "this kernel did not take loss 100%" ;;
    esac
    sleep 8
    after=$(dropped)
    tc qdisc change dev "$link" root netem

    # eight seconds at fifty a second is four hundred; two hundred is four
    # seconds of a call gone, which is an outage by any reading and leaves room
    # for the pauses a cadenced sender takes
    [ -n "$before" ] && [ -n "$after" ] || missed "the drop counter could not be read"
    gone=$((after - before))
    echo "the outage took $gone of the call packets"
    [ "$gone" -ge 200 ] || missed "the outage took $gone packets, so it did not land in the call"
'
