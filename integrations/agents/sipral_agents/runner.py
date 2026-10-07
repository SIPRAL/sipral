# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek

"""The ready-to-run bridge: a TOML file names the SIP accounts to take
calls on and, for each, the agent that answers them -- one of the WebSocket
services or another SIP address -- and :class:`Bridge` serves them all from
one stack. ``python -m sipral_agents bridge.toml`` runs it, and
``--dial TARGET --from AOR`` places one call from an account to its agent
instead, deciding who answered as the account's ``[accounts.machine]``
table says (:class:`sipral_agents.outbound.MachinePolicy`).

The file holds no secret: an API key or a password is named by the
environment variable that holds it (``api_key_env``,
``auth_password_env``), and a literal one is refused.
"""

from __future__ import annotations

import asyncio
import logging
import os
import tomllib
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from sipral import Account, Call, InviteLimit, Stack, TlsTrust
from sipral.enums import AudioMode, EventKind, Transport
from sipral.errors import SipralError

from .core import Backoff, Provider
from .deepgram import DeepgramAgent
from .elevenlabs import ElevenLabsAgent
from .gemini_live import GeminiLive
from .openai_realtime import OpenAIRealtime
from .outbound import DETECTOR_KEYS, MachinePolicy, dial
from .serve import _run_call
from .sip_bridge import BridgeConfig, BridgedCall, agent_server, agent_target, domain_of
from .vapi import VapiAgent

__all__ = ["AccountSettings", "AgentSettings", "Bridge", "ConfigError", "Settings", "load_config"]

_log = logging.getLogger("sipral_agents.runner")

#: The services a configuration's ``service`` names, besides ``"sip"``.
SERVICES: dict[str, type[Provider]] = {
    "openai-realtime": OpenAIRealtime,
    "gemini-live": GeminiLive,
    "elevenlabs": ElevenLabsAgent,
    "vapi": VapiAgent,
    "deepgram": DeepgramAgent,
}

# what may never be written in the file itself
_SECRETS = ("api_key", "password", "auth_password", "secret", "token")

_SIP_AGENT_KEYS = {
    "uri",
    "address",
    "auth_user",
    "auth_password",
    "transfer",
    "outcomes",
    "outcome_uris",
    "max_seconds",
    "copy_headers",
}


class ConfigError(ValueError):
    """The configuration file, or the environment it names, is not usable."""


@dataclass
class AgentSettings:
    """One ``[agents.NAME]`` table: ``service`` and its settings, with every
    ``*_env`` key already read from the environment."""

    name: str
    service: str
    options: dict[str, Any]

    def provider(self) -> Provider:
        return SERVICES[self.service](**self.options)


@dataclass
class AccountSettings:
    """One ``[[accounts]]`` entry: a SIP account and the agent its calls go to."""

    aor: str
    agent: str
    registrar_address: str
    registrar: str | None = None
    auth_user: str | None = None
    auth_password: str | None = None
    display_name: str | None = None
    #: What a call this account places does when a machine answers.
    machine: MachinePolicy = field(default_factory=MachinePolicy)


@dataclass
class Settings:
    """A whole configuration file."""

    accounts: list[AccountSettings]
    agents: dict[str, AgentSettings]
    bind_host: str | None = None
    bind_port: int = 0
    media_host: str | None = None
    user_agent: str | None = None
    codecs: str | None = None
    invite_limit: str | None = None
    tls_ca: str | None = None
    backoff: Backoff = field(default_factory=Backoff)


def load_config(path: str, environ: dict[str, str] | None = None) -> Settings:
    """Read and check a configuration file; :class:`ConfigError` names the
    first thing wrong with it, the environment variables it needs among
    them."""
    try:
        with open(path, "rb") as handle:
            raw = tomllib.load(handle)
    except OSError as error:
        raise ConfigError(f"{path}: {error.strerror}") from None
    except tomllib.TOMLDecodeError as error:
        raise ConfigError(f"{path}: {error}") from None
    return parse_config(raw, os.environ if environ is None else environ)


def parse_config(raw: dict, environ: dict[str, str]) -> Settings:
    sip = _table(raw, "sip", "the [sip] table")
    agents = {
        name: _agent(name, table, environ)
        for name, table in _table(raw, "agents", "the [agents] table").items()
    }
    entries = raw.get("accounts")
    if not isinstance(entries, list) or not entries:
        raise ConfigError("no [[accounts]]: name at least one account to take calls on")
    accounts = [_account(i, entry, agents, environ) for i, entry in enumerate(entries)]
    seen: set[str] = set()
    for account in accounts:
        if account.aor in seen:
            raise ConfigError(f"the account {account.aor} is listed twice")
        seen.add(account.aor)
    limit = sip.get("invite_limit")
    if limit not in (None, "default", "voice-agent"):
        raise ConfigError('[sip] invite_limit is "default" or "voice-agent"')
    unknown = set(sip) - {
        "bind_host", "bind_port", "media_host", "user_agent", "codecs", "invite_limit", "tls_ca", "backoff"
    }
    if unknown:
        raise ConfigError(f"[sip] has unknown keys: {', '.join(sorted(unknown))}")
    backoff = Backoff()
    for key, value in _table(sip, "backoff", "[sip.backoff]").items():
        if key not in ("first", "longest", "jitter", "attempts"):
            raise ConfigError(f"[sip.backoff] has an unknown key: {key}")
        setattr(backoff, key, value)
    settings = Settings(
        accounts=accounts,
        agents=agents,
        bind_host=sip.get("bind_host"),
        bind_port=int(sip.get("bind_port", 0)),
        media_host=sip.get("media_host"),
        user_agent=sip.get("user_agent"),
        codecs=sip.get("codecs"),
        invite_limit=limit,
        tls_ca=sip.get("tls_ca"),
        backoff=backoff,
    )
    _tls_server_name(settings)
    return settings


def _table(raw: dict, key: str, what: str) -> dict:
    value = raw.get(key, {})
    if not isinstance(value, dict):
        raise ConfigError(f"{what} must be a table")
    return value


def _secrets_from(where: str, table: dict, environ: dict[str, str]) -> dict[str, Any]:
    """The table with every ``X_env`` key replaced by ``X`` read from the
    environment, refusing a secret written in the file."""
    options: dict[str, Any] = {}
    for key, value in table.items():
        if key.endswith("_env"):
            if not isinstance(value, str) or not value:
                raise ConfigError(f"{where}: {key} names an environment variable")
            if value not in environ:
                raise ConfigError(f"{where}: the environment variable {value} ({key}) is not set")
            options[key[: -len("_env")]] = environ[value]
        elif any(key == s or key.endswith("_" + s) for s in _SECRETS):
            raise ConfigError(
                f"{where}: {key} is a secret and does not go in the file; "
                f"set {key}_env to the environment variable that holds it"
            )
        else:
            options[key] = value
    return options


def _agent(name: str, table: Any, environ: dict[str, str]) -> AgentSettings:
    where = f"[agents.{name}]"
    if not isinstance(table, dict):
        raise ConfigError(f"{where} must be a table")
    options = _secrets_from(where, table, environ)
    service = options.pop("service", None)
    if service == "sip":
        if not options.get("uri"):
            raise ConfigError(f"{where}: a SIP agent needs uri, its SIP address")
        unknown = set(options) - _SIP_AGENT_KEYS
        if unknown:
            raise ConfigError(f"{where} has unknown keys: {', '.join(sorted(unknown))}")
        if options.get("transfer", "refer") not in ("refer", "bridge"):
            raise ConfigError(f'{where}: transfer is "refer" or "bridge"')
        if options.get("outcomes", "header") not in ("header", "refer"):
            raise ConfigError(f'{where}: outcomes is "header" or "refer"')
        return AgentSettings(name, service, options)
    if service not in SERVICES:
        known = ", ".join(['"sip"', *(f'"{s}"' for s in SERVICES)])
        raise ConfigError(f"{where}: service is one of {known}")
    agent = AgentSettings(name, service, options)
    try:
        agent.provider()
    except (TypeError, ValueError) as error:
        raise ConfigError(f"{where} ({service}): {error}") from None
    return agent


def _account(
    index: int, entry: Any, agents: dict[str, AgentSettings], environ: dict[str, str]
) -> AccountSettings:
    where = f"[[accounts]] #{index + 1}"
    if not isinstance(entry, dict):
        raise ConfigError(f"{where} must be a table")
    options = _secrets_from(where, entry, environ)
    for key in ("aor", "agent", "registrar_address"):
        if not options.get(key):
            raise ConfigError(f"{where}: {key} is required")
    if options["agent"] not in agents:
        raise ConfigError(f"{where}: no [agents.{options['agent']}] for {options['aor']}")
    options["machine"] = _machine(where, options.get("machine", {}))
    try:
        return AccountSettings(**options)
    except TypeError:
        known = set(AccountSettings.__dataclass_fields__)
        raise ConfigError(
            f"{where} has unknown keys: {', '.join(sorted(set(options) - known))}"
        ) from None


def _machine(where: str, table: Any) -> MachinePolicy:
    """An account's ``[accounts.machine]`` table: ``on_machine``,
    ``on_unknown``, ``beep_wait_s`` and any of the detector's limits."""
    if not isinstance(table, dict):
        raise ConfigError(f"{where}: machine must be a table")
    unknown = set(table) - {"on_machine", "on_unknown", "beep_wait_s", *DETECTOR_KEYS}
    if unknown:
        raise ConfigError(f"{where} machine has unknown keys: {', '.join(sorted(unknown))}")
    try:
        return MachinePolicy(
            on_machine=table.get("on_machine", "hangup"),
            on_unknown=table.get("on_unknown", "agent"),
            beep_wait_s=float(table.get("beep_wait_s", 20.0)),
            detector={key: table[key] for key in DETECTOR_KEYS if key in table},
        )
    except (TypeError, ValueError) as error:
        raise ConfigError(f"{where} machine: {error}") from None


def _tls_server_name(settings: Settings) -> str | None:
    """The one name the stack checks TLS certificates against: a stack has
    one, so every SIP agent reached over TLS must share it."""
    names = set()
    for agent in settings.agents.values():
        if agent.service == "sip":
            _, over, host = agent_target(agent.options["uri"], agent.options.get("address"))
            if over == Transport.TLS:
                names.add(host)
    if len(names) > 1:
        raise ConfigError(
            "SIP agents over TLS on different hosts need one bridge each: "
            + ", ".join(sorted(names))
        )
    return next(iter(names), None)


def _agent_route(agent: AgentSettings) -> tuple[str, int, str]:
    try:
        return agent_server(agent.options["uri"], agent.options.get("address"))
    except (OSError, ValueError) as error:
        raise ConfigError(f"[agents.{agent.name}]: cannot reach {agent.options['uri']}: {error}") from None


class Bridge:
    """Every account of a :class:`Settings` on one stack, each call to an
    account handed to that account's agent.

    ``await start()`` creates the stack and the accounts and registers those
    with a registrar; ``await serve()`` answers calls until cancelled and
    closes the stack after. ``on_event`` sees every stack event first.
    """

    def __init__(
        self, settings: Settings, *, on_event: Callable[[Any], object] | None = None
    ) -> None:
        self.settings = settings
        self.on_event = on_event
        self.stack: Stack | None = None
        #: account handle -> (its settings, what answers its calls)
        self.routes: dict[int, tuple[AccountSettings, Callable[[Call, Any], Any]]] = {}
        #: account handle -> the account itself, to place calls from
        self.lines: dict[int, Account] = {}
        self._calls: set[asyncio.Task] = set()

    async def start(self) -> Stack:
        s = self.settings
        tls_name = _tls_server_name(s)
        self.stack = stack = Stack(
            loop=asyncio.get_running_loop(),
            audio=AudioMode.APPLICATION,
            bind_host=s.bind_host,
            bind_port=s.bind_port,
            user_agent=s.user_agent,
            codecs=s.codecs,
            tls_server_name=tls_name,
            tls_trust=TlsTrust.only_authority(s.tls_ca) if s.tls_ca else None,
            invite_limit=InviteLimit.VOICE_AGENT if s.invite_limit == "voice-agent" else None,
        )
        for account in s.accounts:
            line = stack.add_account(
                account.aor,
                registrar=account.registrar,
                registrar_address=account.registrar_address,
                auth_user=account.auth_user,
                auth_password=account.auth_password,
                display_name=account.display_name,
            )
            agent = s.agents[account.agent]
            if agent.service == "sip":
                handler = self._sip_handler(account, line, agent)
            else:
                handler = self._service_handler(agent)
            self.routes[line.handle] = (account, handler)
            self.lines[line.handle] = line
            if account.registrar:
                line.register()
            _log.info("%s answers with %s (%s)", account.aor, agent.name, agent.service)
        _log.info("listening on %s", stack.bind_address)
        return stack

    def _service_handler(self, agent: AgentSettings):
        backoff = self.settings.backoff

        def handle(call: Call, _event) -> Any:
            return _run_call(call, lambda _call: agent.provider(), backoff, 10.0, None)

        return handle

    def _sip_handler(self, account: AccountSettings, line: Account, agent: AgentSettings):
        o = agent.options
        address, over, _host = _agent_route(agent)
        agent_account = self.stack.add_account(
            account.aor,
            registrar_address=address,
            stream_protocol=over,
            auth_user=o.get("auth_user"),
            auth_password=o.get("auth_password"),
        )
        cfg = BridgeConfig(
            pbx_domain=domain_of(account.registrar or account.aor),
            agent_uri=o["uri"],
            agent_account=agent_account,
            line=line,
            transfer=o.get("transfer", "refer"),
            outcomes=o.get("outcomes", "header"),
            outcome_uris=dict(o.get("outcome_uris", {})),
            max_seconds=float(o["max_seconds"]) if o.get("max_seconds") else None,
            copy=list(o.get("copy_headers", ["X-*"])),
        )
        stack = self.stack

        def handle(call: Call, event) -> Any:
            return BridgedCall(stack, cfg, call, event.message).run()

        return handle

    async def dial(self, aor: str, target: str) -> str:
        """Place one call from the account ``aor`` to ``target`` and join it
        to that account's agent once its ``machine`` policy says so; returns
        what :func:`sipral_agents.outbound.dial` says became of it. Only an
        agent that is a WebSocket service places calls."""
        if self.stack is None:
            await self.start()
        found = [
            (handle, account)
            for handle, (account, _handler) in self.routes.items()
            if account.aor == aor
        ]
        if not found:
            raise ConfigError(f"no account {aor} to call from")
        handle, account = found[0]
        agent = self.settings.agents[account.agent]
        if agent.service == "sip":
            raise ConfigError(f"{aor} hands its calls to a SIP agent, which places its own")
        return await dial(
            self.stack,
            self.lines[handle],
            target,
            lambda _call: agent.provider(),
            policy=account.machine,
            media_host=self.settings.media_host,
            backoff=self.settings.backoff,
        )

    async def serve(self) -> None:
        try:
            if self.stack is None:
                await self.start()
            stack = self.stack
            while True:
                event = await stack.events.get()
                if self.on_event is not None:
                    self.on_event(event)
                if event.kind == EventKind.REGISTRATION_CHANGED:
                    _log.info("registration %s", event.fields.get("state"))
                if event.kind != EventKind.INCOMING_CALL:
                    continue
                route = self.routes.get(event.account)
                if route is None:
                    _log.warning("a call to an account with no agent: refused")
                    stack.reject_call(event, 404)
                    continue
                account, handler = route
                try:
                    call = stack.answer_call(event, media_host=self.settings.media_host)
                except SipralError as refused:
                    _log.warning("could not answer a call to %s: %s", account.aor, refused)
                    continue
                _log.info("call %x to %s", call.handle, account.aor)
                task = asyncio.create_task(handler(call, event))
                self._calls.add(task)
                task.add_done_callback(self._calls.discard)
        finally:
            running = list(self._calls)
            for task in running:
                task.cancel()
            await asyncio.gather(*running, return_exceptions=True)
            if self.stack is not None:
                self.stack.close()
