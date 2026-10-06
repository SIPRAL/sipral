<!--
SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
Copyright (c) 2026 Sytek
-->

# Sipral for voice-agent APIs

`sipral-agents` joins a SIP phone call to a speech-to-speech service that
talks over a WebSocket, with no framework in between: OpenAI Realtime,
Gemini Live, ElevenLabs Agents, Vapi and Deepgram Voice Agent. Sipral does the SIP, the RTP and the codecs; the service
does the listening, the thinking and the speaking.

- `serve(account, factory)` answers every call to a Sipral account and joins
  it to the provider `factory(call)` returns, one session per call, so one
  process serves many calls at once.
- `AgentCall(call, provider)` is one call joined to one session, for an
  application that answers or places its calls itself: `await run()` until
  either side ends, `await close()` to end both.
- `OpenAIRealtime(model=..., api_key=...)` and `GeminiLive(model=...,
  api_key=...)` take `instructions`, `voice`, a `url` to use instead of the
  vendor's (a proxy, a test server), and a dictionary merged into the
  session's setup for anything else.
- `ElevenLabsAgent(agent_id=..., api_key=...)` talks to an agent configured
  at ElevenLabs, whose input and output formats must both be PCM at
  `sample_rate` (16000 by default); a conversation in another format is
  refused rather than played at the wrong speed. `overrides` and
  `dynamic_variables` go in the conversation's first message, and the
  service's pings are answered.
- `VapiAgent(api_key=..., assistant_id=...)` (or `assistant=` inline)
  creates one Vapi call per SIP call with `POST /call` and a WebSocket
  transport in `pcm_s16le` at 16 kHz, and sends `hangup` when the caller
  hangs up. `call` is merged into the request body.
- `DeepgramAgent(api_key=..., agent=...)` opens a Voice Agent session with
  `linear16` at 24 kHz both ways; `agent` is the `Settings` message's
  `agent` object -- the listen, think and speak providers and models are the
  application's to name -- and `settings` is merged into the message.

## What the core does for every service

- **Rate.** The call's frames are switched to the service's rate with
  `Media.set_app_rate`, so the library converts between the codec and the
  service both ways — G.711 at 8 kHz, G.722 at 16, Opus at 48 — and nothing
  is resampled in Python. Both services run at 24 kHz: OpenAI takes and
  returns PCM at 24 kHz, and Gemini returns 24 kHz and is told the caller's
  audio is 24 kHz in its MIME type.
- **Barge-in.** The agent's audio goes to the call a codec frame at a time,
  in real time, with never more than `send_ahead_ms` (40 ms) queued in the
  call's media. When the service says the caller started speaking (OpenAI's
  `input_audio_buffer.speech_started`) or that it cut its own turn short
  (Gemini's `interrupted`, ElevenLabs' `interruption`, Vapi's
  `user-interrupted`, Deepgram's `UserStartedSpeaking`), what is queued is
  dropped at once -- and ElevenLabs audio numbered before the interruption
  that still arrives after it is dropped too; OpenAI is
  then told how much of its turn the caller heard
  (`conversation.item.truncate`), so the conversation holds what was said
  and not what was generated.
- **Events.** Each `AgentCall` puts `AgentEvent`s on `events`: `CONNECTED`,
  `RECONNECTING`, `USER_SPEECH_STARTED`, `INTERRUPTED`, `TURN_COMPLETE`,
  `TRANSCRIPT` (role and text), `ERROR` and `ENDED` with its reason.
- **Reconnection.** A connection that drops while the call is up is opened
  again with exponential backoff (`Backoff`: 0.5 s doubling to 8 s, six
  tries, then the call is hung up). Gemini's `goAway` moves the session to
  a new connection at once, and Gemini sessions resume with the last
  resumption handle the service gave; an OpenAI reconnection is a new
  session, which `CONNECTED` reports with `resumed=False`, as are
  ElevenLabs' and Deepgram's; a Vapi reconnection goes back to the same
  call's WebSocket. A session the service turns down for good -- a format
  or a setting it rejects, a Vapi call it will not create -- ends the call
  at once with the reason `refused` instead of retrying.
- **Ending.** The caller hanging up closes the WebSocket with a normal
  closure; the service closing its side plays the last of its audio and
  hangs up the call.

## Another service

A service is a `Provider` subclass: `sample_rate`, `url()`, `headers()`,
`open(ws, resuming)` to set the session up, `audio_message(pcm)` for a frame
of the caller's audio, `parse(message)` returning `Audio`, `SpeechStarted`,
`Interrupted`, `TurnComplete`, `Transcript`, `ProviderError`, `GoAway` or
`Reply` (a message to send back at once) values, and optionally
`prepare(resuming)` (a request before each connection, such as creating the
call that hands out the WebSocket address), `barge_in(item, heard_ms)` and
`farewell()` (messages before a closure because the call ended). Raising
`SessionRefused` from `prepare` or `open` ends the call with no retry.
Rate, pacing, barge-in, events, reconnection and the end of the call stay
in the core.

## Install

```sh
pip install sipral-agents
```

Python 3.11 or later. The `sipral` wheel carries the native library; a
library built from this repository instead (`cargo build --release -p
sipral-ffi`) is found through `SIPRAL_LIBRARY=target/release`.

## Example

```python
import asyncio, os
from sipral import Stack
from sipral.enums import AudioMode
from sipral_agents import OpenAIRealtime, serve

async def main():
    stack = Stack(loop=asyncio.get_running_loop(), audio=AudioMode.APPLICATION)
    account = stack.add_account(
        os.environ["SIPRAL_AOR"], registrar=os.environ["SIPRAL_REGISTRAR"],
        registrar_address=os.environ["SIPRAL_REGISTRAR_ADDRESS"],
        auth_user=os.environ["SIPRAL_AUTH_USER"], auth_password=os.environ["SIPRAL_AUTH_PASSWORD"])
    account.register()
    await serve(account, lambda call: OpenAIRealtime(
        model="gpt-realtime", api_key=os.environ["OPENAI_API_KEY"],
        instructions="You answer the phone. Be brief."))

asyncio.run(main())
```

[`examples/phone_agent.py`](examples/phone_agent.py) is the same agent with
either service, the registration optional and the transcript printed.

## Environment variables of the example

| Variable | What it is |
|---|---|
| `SIPRAL_AOR` | the agent's address of record, `sip:agent@example.com` |
| `SIPRAL_REGISTRAR` | the registrar's URI, `sip:example.com`; unset, nothing registers |
| `SIPRAL_REGISTRAR_ADDRESS` | where requests go, `host:port`: the registrar or the outbound proxy |
| `SIPRAL_AUTH_USER`, `SIPRAL_AUTH_PASSWORD` | the digest credentials |
| `SIPRAL_PORT` | the port the example listens on, 5060 by default |
| `AGENT_SERVICE` | `openai` (the default) or `gemini` |
| `AGENT_MODEL` | the service's model name |
| `OPENAI_API_KEY`, `GEMINI_API_KEY` | the service's key |
| `AGENT_URL` | a WebSocket address to use instead of the service's |
| `AGENT_PROMPT` | the instructions, when the default will not do |
| `SIPRAL_LIBRARY` | the native library, or the directory holding it, when it is not the wheel's |

## Tests

```sh
SIPRAL_LIBRARY=target/release PYTHONPATH=integrations/agents:bindings/python \
    python3 -m unittest discover -s integrations/agents/tests -t integrations/agents
```

from the repository's root, in an environment with `websockets` and `cffi`
installed. Two stacks on loopback and, for each service, a local WebSocket
server that speaks its protocol as the vendor's public documentation
describes it (for Vapi, an HTTP server for `POST /call` as well); no network
and no key. They check the session's setup, that a tone the caller sends
comes back through the service at its rate, that a barge-in silences the
agent, that OpenAI's turn is truncated to what was heard, that ElevenLabs'
pings are answered and its stale audio dropped, that a dropped connection
and a `goAway` are recovered (Gemini's resumed, Vapi's back on the same
call), that a session the service refuses ends the call without retries,
and that either side ending ends the other. They have not been
run against the vendors' own services. `scripts/check.sh --only agents`
runs them in a virtual environment of its own.

## Licences

This package is under the same terms as Sipral: AGPL-3.0-only, or the
commercial licence. Its one dependency besides `sipral` is `websockets`,
BSD-3-Clause, which needs nothing else.
