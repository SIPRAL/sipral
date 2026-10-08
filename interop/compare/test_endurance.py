# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek
"""interop/compare/endurance.py against samples written here, so what it
says of a real run's rows is known to be arithmetic on them.

    python3 -m unittest discover -s interop/compare
"""

import csv
import os
import unittest

import endurance


def rows(minutes, rss, anon, fds=12, cpu_per_minute=0.6, calls_per_minute=1 / 3):
    """A row a minute, as endurance.sh writes them; rss and anon are
    functions of the minute."""
    out = []
    for minute in range(minutes + 1):
        done = int(minute * calls_per_minute)
        out.append({
            "utc": "-", "elapsed_s": str(minute * 60), "rss_kb": str(rss(minute)),
            "private_kb": "0", "anon_kb": str(anon(minute)), "cpu_s": f"{minute * cpu_per_minute:.2f}",
            "fds": str(fds), "threads": "3", "offered": str(done + 1), "answered": str(done + 1),
            "done": str(done),
        })
    return out


def parse(line):
    return dict(pair.split("=", 1) for pair in line.split())


class Summary(unittest.TestCase):
    def test_a_flat_client_grows_by_nothing(self):
        view = parse(endurance.summary(rows(180, lambda m: 6000, lambda m: 700)))
        self.assertEqual(view["hours"], "3.00")
        self.assertEqual((view["rss_kb_h"], view["anon_kb_h"], view["fds_h"]), ("0.0", "0.0", "0.00"))
        self.assertEqual(view["anon_kb_call"], "0.00")
        # 0.6 s a minute is 1 % of a core; 60 calls over the three hours
        self.assertEqual(view["cpu_pct"], "1.00")
        self.assertEqual(view["cpu_ms_call"], "1800")

    def test_growth_is_read_after_the_first_hour_only(self):
        # a start-up climb in the first hour, then 2 kB a minute
        def anon(minute):
            return 500 + 10 * minute if minute < 60 else 1100 + 2 * (minute - 60)

        view = parse(endurance.summary(rows(180, lambda m: 6000 + m, anon)))
        self.assertEqual(view["anon_kb_h"], "120.0")
        self.assertEqual(view["rss_kb_h"], "60.0")
        self.assertEqual(view["anon_kb"], "1100/1340")
        # 120 kB an hour at 20 calls an hour
        self.assertEqual(view["anon_kb_call"], "6.00")

    def test_the_row_after_the_run_counts_calls_but_not_memory(self):
        samples = rows(180, lambda m: 6000, lambda m: 700)
        samples.append(dict(samples[-1], elapsed_s=str(180 * 60 + 190), anon_kb="400", done="61"))
        view = parse(endurance.summary(samples))
        self.assertEqual((view["anon_kb"], view["anon_kb_h"], view["done"]), ("700/700", "0.0", "61"))

    def test_the_published_run_reads_as_published(self):
        # interop/fixtures/compare-endurance-2026-10-08, docs/23's table
        here = os.path.dirname(os.path.abspath(__file__))
        folder = os.path.join(here, "..", "fixtures", "compare-endurance-2026-10-08")
        published = {
            "sipral": ("59", "832/848", "8.6"),
            "pjsua": ("59", "3360/3424", "23.4"),
            "baresip": ("59", "2316/2380", "30.6"),
            "linphone": ("59", "11204/11572", "105.8"),
        }
        for client, expected in published.items():
            with open(os.path.join(folder, f"{client}.csv"), encoding="utf-8") as handle:
                view = parse(endurance.summary(list(csv.DictReader(handle))))
            self.assertEqual((view["done"], view["anon_kb"], view["anon_kb_h"]), expected, client)

    def test_a_short_run_settles_after_its_first_third(self):
        view = parse(endurance.summary(rows(60, lambda m: 6000, lambda m: 100 * min(m, 20))))
        self.assertEqual(view["anon_kb"], "2000/2000")
        self.assertEqual(view["anon_kb_h"], "0.0")


if __name__ == "__main__":
    unittest.main()
