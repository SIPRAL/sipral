#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek
"""What one client's samples from `scripts/soak.sh compare` say.

    endurance.py CSV

CSV is the file interop/compare/endurance.sh writes for one client, a row a
minute. Printed as `name=value` pairs on one line:

    hours            the span the rows cover
    offered, answered, done
                     calls Asterisk placed to the client, the ones it
                     answered, the ones it held to the end (the last row's)
    rss_kb, anon_kb, fds, threads
                     at the start of the settled part and at the end, as
                     `start/end`
    rss_kb_h, anon_kb_h, fds_h
                     growth over the settled part, per hour, by least squares
                     over every row in it
    anon_kb_call     the same growth per call held to the end
    cpu_pct          processor time over the whole span, percent of one core
    cpu_ms_call      processor time per call held to the end

The settled part is every row from the end of the first hour, as
scripts/soak.sh endurance judges its own run, or from the end of the first
third when the run is shorter than two hours. Standard library only.
"""

import csv
import sys


def slope(points):
    """Least-squares slope of (x, y) points; 0 for fewer than two."""
    if len(points) < 2:
        return 0.0
    n = len(points)
    mean_x = sum(x for x, _ in points) / n
    mean_y = sum(y for _, y in points) / n
    spread = sum((x - mean_x) ** 2 for x, _ in points)
    if spread == 0:
        return 0.0
    return sum((x - mean_x) * (y - mean_y) for x, y in points) / spread


def summary(rows):
    if not rows:
        return "hours=0"
    elapsed = [int(row["elapsed_s"]) for row in rows]
    span = elapsed[-1] - elapsed[0]
    settle = 3600 if span >= 7200 else span // 3
    settled = [row for row in rows if int(row["elapsed_s"]) - elapsed[0] >= settle] or rows[-1:]
    first, last = settled[0], rows[-1]

    def growth(column):
        return slope([(int(row["elapsed_s"]) / 3600, float(row[column])) for row in settled])

    def ends(column):
        return f"{first[column]}/{last[column]}"

    done = int(last["done"])
    settled_calls = int(settled[-1]["done"]) - int(settled[0]["done"])
    settled_hours = (int(settled[-1]["elapsed_s"]) - int(settled[0]["elapsed_s"])) / 3600
    anon_h = growth("anon_kb")
    per_call = "-"
    if settled_calls > 0 and settled_hours > 0:
        per_call = f"{anon_h * settled_hours / settled_calls:.2f}"
    cpu = float(last["cpu_s"]) - float(rows[0]["cpu_s"])
    cpu_pct = cpu / span * 100 if span else 0.0
    calls = done - int(rows[0]["done"])
    cpu_call = f"{cpu * 1000 / calls:.0f}" if calls > 0 else "-"
    return (f"hours={span / 3600:.2f} offered={last['offered']} answered={last['answered']} done={done} "
            f"rss_kb={ends('rss_kb')} anon_kb={ends('anon_kb')} fds={ends('fds')} threads={ends('threads')} "
            f"rss_kb_h={growth('rss_kb'):.1f} anon_kb_h={anon_h:.1f} fds_h={growth('fds'):.2f} "
            f"anon_kb_call={per_call} cpu_pct={cpu_pct:.2f} cpu_ms_call={cpu_call}")


def main(argv):
    if len(argv) != 2:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    try:
        with open(argv[1], encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))
    except OSError as error:
        print(f"cannot read: {error}", file=sys.stderr)
        return 1
    print(summary(rows))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
