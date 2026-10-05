<!--
SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
Copyright (c) 2026 Sytek
-->

# Sipral for Pipecat

`sipral-pipecat` puts a [Pipecat](https://github.com/pipecat-ai/pipecat)
pipeline on a SIP phone call: an AI voice agent answers a number on any SIP
registrar, trunk or PBX, with Sipral doing the SIP, the RTP and the codecs
and Pipecat the speech recognition, the model and the speech.

- `SipralTransport(call)` is one call whose media has started, as a Pipecat
  transport. `input()` turns the caller's audio into `InputAudioRawFrame` at
  the call's rate and each keypad digit into `InputDTMFFrame`; `output()`
  plays `OutputAudioRawFrame` on the call, resampled by Pipecat to the
  call's rate and paced in real time a codec frame at a time, and sends
  `OutputDTMFFrame` and `OutputDTMFUrgentFrame` as the call's own DTMF.
- An interruption (`InterruptionFrame`, when the caller starts speaking)
  drops the audio still queued at once: the call's media never holds more
  than `send_ahead_ms` (40 ms) of it.
- The caller hanging up cancels the pipeline; the pipeline ending, or being
  cancelled, hangs up the call. Every call event is reported as
  `on_call_event`, the end as `on_call_ended`.
- `serve(account, factory)` answers every call to a Sipral account and runs
  the `PipelineWorker` that `factory(transport)` builds for it, so one
  process serves many calls at once.

## Install

```sh
pip install sipral-pipecat "pipecat-ai[deepgram,openai,silero]"
```

Python 3.11 or later, as Pipecat needs. The `sipral` wheel carries the native
library; a library built from this repository instead (`cargo build
--release -p sipral-ffi`) is found through `SIPRAL_LIBRARY=target/release`.

## Example

```python
import asyncio, os
from pipecat.audio.vad.silero import SileroVADAnalyzer
from pipecat.pipeline.pipeline import Pipeline
from pipecat.pipeline.worker import PipelineParams, PipelineWorker
from pipecat.processors.aggregators.llm_context import LLMContext
from pipecat.processors.aggregators.llm_response_universal import (
    LLMContextAggregatorPair, LLMUserAggregatorParams)
from pipecat.services.deepgram.stt import DeepgramSTTService
from pipecat.services.openai.llm import OpenAILLMService
from pipecat.services.openai.tts import OpenAITTSService
from sipral import Stack
from sipral.enums import AudioMode
from sipral_pipecat import SipralTransport, serve

def agent(transport: SipralTransport) -> PipelineWorker:
    context = LLMContext([{"role": "system", "content": "You answer the phone. Be brief."}])
    turns = LLMContextAggregatorPair(
        context, user_params=LLMUserAggregatorParams(vad_analyzer=SileroVADAnalyzer()))
    pipeline = Pipeline([
        transport.input(), DeepgramSTTService(api_key=os.environ["DEEPGRAM_API_KEY"]),
        turns.user(), OpenAILLMService(api_key=os.environ["OPENAI_API_KEY"]),
        OpenAITTSService(api_key=os.environ["OPENAI_API_KEY"]),
        transport.output(), turns.assistant()])
    return PipelineWorker(pipeline, params=PipelineParams(audio_in_sample_rate=transport.sample_rate))

async def main():
    stack = Stack(loop=asyncio.get_running_loop(), audio=AudioMode.APPLICATION,
                  codecs="G722,PCMU,PCMA")
    account = stack.add_account(
        os.environ["SIPRAL_AOR"], registrar=os.environ["SIPRAL_REGISTRAR"],
        registrar_address=os.environ["SIPRAL_REGISTRAR_ADDRESS"],
        auth_user=os.environ["SIPRAL_AUTH_USER"], auth_password=os.environ["SIPRAL_AUTH_PASSWORD"])
    account.register()
    await serve(account, agent)

asyncio.run(main())
```

Two things in it are about rates. `audio_in_sample_rate` is the call's, so
speech recognition and the VAD are told the rate the caller's frames carry;
the output keeps Pipecat's default (24 kHz, what OpenAI speaks) and the
transport's output resamples to the call. And the codecs offered decode to
16 or 8 kHz, because Silero's VAD takes nothing else; a call on Opus runs at
48 kHz.

[`examples/phone_agent.py`](examples/phone_agent.py) is the same agent with a
greeting, a hang-up on "#" and the registration optional.

## Environment variables

| Variable | What it is |
|---|---|
| `SIPRAL_AOR` | the agent's address of record, `sip:agent@example.com` |
| `SIPRAL_REGISTRAR` | the registrar's URI, `sip:example.com`; unset, nothing registers |
| `SIPRAL_REGISTRAR_ADDRESS` | where requests go, `host:port`: the registrar or the outbound proxy |
| `SIPRAL_AUTH_USER`, `SIPRAL_AUTH_PASSWORD` | the digest credentials |
| `SIPRAL_PORT` | the port the example listens on, 5060 by default |
| `DEEPGRAM_API_KEY` | Deepgram's key, for speech to text |
| `OPENAI_API_KEY` | OpenAI's key, for the model and for text to speech |
| `AGENT_PROMPT` | the example's system prompt, when the default will not do |
| `SIPRAL_LIBRARY` | the native library, or the directory holding it, when it is not the wheel's |

## Tests

```sh
SIPRAL_LIBRARY=target/release PYTHONPATH=integrations/pipecat:bindings/python \
    python3 -m unittest discover -s integrations/pipecat/tests -t integrations/pipecat
```

from the repository's root, in an environment with `pipecat-ai` and `cffi`
installed; `integrations/pipecat` goes first, since `bindings/python` has a
`tests` package of its own. Two stacks on loopback, no network and no key: one serves its
calls through a pipeline that echoes what it hears, the other dials it and
checks that a tone comes back, that an interruption stops the agent's audio
within 100 ms, that DTMF crosses as Pipecat frames both ways, and that
hanging up on either side ends both. `scripts/check.sh --only pipecat` runs
them in a virtual environment of its own.

## Licences

This package is under the same terms as Sipral: AGPL-3.0-only, or the
commercial licence. Pipecat is BSD-2-Clause. Pipecat's own dependencies are
the application's, and two of them are LGPL: `soxr` (its resampler) and
`num2words`. [`THIRD-PARTY-NOTICES.md`](../../THIRD-PARTY-NOTICES.md) lists
them.
