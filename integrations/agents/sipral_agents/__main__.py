# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek

"""``python -m sipral_agents [--check] CONFIG.toml``: serve the accounts a
configuration file names, each call to its account's agent."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import logging
import sys

from .runner import Bridge, ConfigError, load_config


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="sipral-agents",
        description="Answer SIP calls and hand each to the voice agent configured for its account.",
    )
    parser.add_argument("config", help="the TOML configuration file")
    parser.add_argument(
        "--check",
        action="store_true",
        help="read the file and the environment it names, print the routes, and exit",
    )
    parser.add_argument("--quiet", action="store_true", help="log warnings and errors only")
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.WARNING if args.quiet else logging.INFO,
        format="%(asctime)s %(message)s",
    )
    try:
        settings = load_config(args.config)
    except ConfigError as error:
        print(f"sipral-agents: {error}", file=sys.stderr)
        return 2
    if args.check:
        for account in settings.accounts:
            agent = settings.agents[account.agent]
            target = agent.options["uri"] if agent.service == "sip" else agent.service
            print(f"{account.aor} -> {agent.name} ({target})")
        return 0
    try:
        with contextlib.suppress(KeyboardInterrupt):
            asyncio.run(Bridge(settings).serve())
    except ConfigError as error:
        print(f"sipral-agents: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
