#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek
#
# Holds what `scripts/check.sh --only numbers` measured to docs/numbers.toml.
#
#   scripts/numbers.py docs/numbers.toml MEASUREMENTS
#
# MEASUREMENTS is any text with `numbers: key=value key=value ...` lines in
# it, the lines the gate's measurements print. Every figure in the budget
# file has to have been measured and be within its limit; each verdict is
# one line, `ok<TAB>text`, `fail<TAB>text` or `detail<TAB>text` (said under
# the failure before it), which check.sh turns into its own ok and FAIL
# lines. Exits 1 when anything failed, 2 when it could not read its input.

import re
import sys

try:
    import tomllib
except ImportError:
    print("fail\tscripts/numbers.py needs Python 3.11 or later, for tomllib")
    sys.exit(2)


def measured(path):
    """Every key=value on the measurements' `numbers:` lines."""
    values = {}
    with open(path, encoding="utf-8") as text:
        for line in text:
            found = re.search(r"numbers: (.*)$", line)
            if not found:
                continue
            for pair in found.group(1).split():
                key, _, value = pair.partition("=")
                try:
                    values[key] = float(value)
                except ValueError:
                    continue
    return values


def shown(value, unit):
    """A value as the failure message says it: bytes whole, time to 2 places."""
    if unit == "B":
        return f"{round(value)} B"
    return f"{value:.2f} {unit}"


def judge(figure, values, yardstick_us):
    """One figure's verdict lines."""
    key, unit, what = figure["key"], figure["unit"], figure["what"]
    published = figure["published"]
    if "share" in figure:
        limit = published * figure["share"]
        budget = f"{shown(limit, unit)}, {figure['share']:.0%} of the published {shown(published, unit)}"
    else:
        limit = published + figure.get("margin", 0)
        budget = shown(limit, unit)
    lines = []
    ceiling = figure.get("ceiling")
    if ceiling is not None and limit > ceiling:
        return [("fail", f"{what}: its budget, {shown(limit, unit)}, is past the ceiling of {shown(ceiling, unit)} no published figure may pass")]
    if unit == "us":
        ratio = values.get(f"{key}.ratio")
        here = values.get(f"{key}.us")
        if ratio is None:
            return [("fail", f"{key}: not measured ({what})")]
        value = ratio * yardstick_us
        reading = f"{shown(value, unit)} ({ratio:.2f} yardsticks"
        reading += f"; {here:.2f} us on this machine)" if here is not None else ")"
    else:
        value = values.get(key)
        if value is None:
            return [("fail", f"{key}: not measured ({what})")]
        reading = shown(value, unit)
    if value <= limit:
        return [("ok", f"{what}: {reading}, within {budget}")]
    lines.append(("fail", f"{what}: published as {shown(published, unit)}, now {reading}, over the budget of {budget}"))
    for place in figure["where"]:
        lines.append(("detail", f"published in {place}"))
    lines.append(("detail", "a figure that changed on purpose: docs/11-testing.md, \"The published figures\""))
    return lines


def main(argv):
    if len(argv) != 3:
        print("fail\tusage: scripts/numbers.py docs/numbers.toml MEASUREMENTS")
        return 2
    try:
        with open(argv[1], "rb") as budget_file:
            budget = tomllib.load(budget_file)
        values = measured(argv[2])
    except (OSError, tomllib.TOMLDecodeError) as error:
        print(f"fail\tcannot read the budget or the measurements: {error}")
        return 2
    yardstick_us = budget.get("yardstick", {}).get("us")
    figures = budget.get("figure", [])
    if not figures:
        print(f"fail\t{argv[1]} lists no figure, so nothing was held to one")
        return 1
    failed = False
    for figure in figures:
        missing = [field for field in ("key", "what", "unit", "published", "where") if field not in figure]
        if missing:
            print(f"fail\t{figure.get('key', 'a figure')} in {argv[1]} has no {', '.join(missing)}")
            failed = True
            continue
        if figure["unit"] == "us" and yardstick_us is None:
            print(f"fail\t{figure['key']}: {argv[1]} gives no [yardstick] us to read it with")
            failed = True
            continue
        for verdict, text in judge(figure, values, yardstick_us):
            print(f"{verdict}\t{text}")
            failed = failed or verdict == "fail"
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
