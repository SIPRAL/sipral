<!--
SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
Copyright (c) 2026 Sytek
-->

# 24 — Connecting Sipral to AI voice-agent services

Sipral is a SIP client stack. It answers and places calls and hands their
audio to the application; it has no speech recognition, synthesis or
language model of its own (`07-headless.md`, "What it does not do"). A
voice agent is a service somebody else runs, and this page says, service by
service, how a call handled by Sipral reaches it and what the service
expects when it does.

**Where the vendor facts come from.** Each service's own documentation,
read on 5 October 2026: the published page, the repository the vendor
builds that page from, or the API specification or SDK the vendor
publishes. The URLs are under each section. Where a vendor's documentation
does not state something — a codec list, an address range — this page says
so rather than filling it in. Vendors change these details; check the page
before relying on a host name or an address range.

## The three paths

**1. SIP bridge.** Sipral registers on a PBX as an extension, or receives
calls on a trunk, answers the caller, places a second call to the
service's SIP address and joins the two calls. The caller hears the
service's agent and the agent hears the caller. This works with any
service that accepts a SIP call, and needs nothing from the service beyond
its address and its rules for admitting a caller.

The examples `bindings/python/examples/agent_bridge.py` and
`crates/sipral/examples/agent-bridge.rs` do this (`07-headless.md`,
"Bridging a call to a voice agent that speaks SIP"). Both read the
service's address from the environment variable `SIPRAL_AGENT_URI`, for
example
`SIPRAL_AGENT_URI='sip:proj_<project-id>@sip.api.openai.com;transport=tls'`.
When the agent ends its call, the bridge ends the PBX's with a named
outcome — human, callback, resolved, unresolved, expired — in a header on
the BYE or as a REFER to an address set per outcome, and a transfer the
agent asks for becomes a REFER of the caller's leg, so the PBX places it.

What the bridge uses from the stack:

- **Two calls, one stack.** The caller's call comes in on the account
  registered with the PBX; the agent's call goes out on an account whose
  transport is the one the service asks for. A service that takes only TLS
  needs an account on TLS (`22-tls.md`), and one that answers the INVITE
  with a digest challenge needs `auth_user` and `auth_password` on the
  account that places the call; that account does not have to register.
- **The join.** `sipral_call_join` pairs two calls whose sessions decode at
  the same rate and cut audio into frames of the same length; nothing in
  the pair resamples (`08-ffi.md`, "Two calls can be joined into a local
  conference of three"). When the two legs settle on different codecs — a
  G.711 PBX on one side and a G.722 agent on the other — a local conference
  of two members without this end mixes them instead, each call on its own
  codec and rate (`LocalConference` in the Python layer).
- **Codecs.** Sipral offers Opus, G.722, G.711 (PCMU, PCMA), L16 and G.729;
  the service picks from the offer. Most services below take G.711 and
  G.722, so a bridge call that both legs settle on G.722 keeps 16 kHz
  audio end to end.
- **Encryption.** SRTP with SDES, including AES_CM_128_HMAC_SHA1_80, which
  is the suite the services below that require SRTP name, and DTLS-SRTP
  (`05-media.md`).
- **Admission.** A service that admits callers by source address needs the
  public address of the host running Sipral in its allow-list. A service
  that admits callers through a webhook needs a web server of the
  application's that accepts the call; Sipral sees only the SIP side.

**2. Pipecat.** Pipecat is an open-source Python framework that runs a
pipeline of speech, language and speech-to-speech services. A Sipral
transport for Pipecat, the package `sipral-pipecat` (`integrations/pipecat/`,
and `07-headless.md`, "Pipecat"); with it
a call answered by Sipral becomes a Pipecat pipeline's input and output, and
every service Pipecat has an integration for is reachable without a
per-vendor adapter. Pipecat's pipelines default to 16 kHz in and 24 kHz out;
Sipral's PCM socket carries 8, 16, 24 or 48 kHz (`07-headless.md`), so the
two agree without a resampling step in between when the socket is opened at
the pipeline's rate. This is the path for every speech engine in the last
group below, and for a speech-to-speech API that does not take SIP.

**3. Headless PCM.** `07-headless.md`: the call's audio as signed 16-bit
little-endian mono PCM at 8, 16, 24 or 48 kHz, on a socket or in process,
for an application that talks to the service's WebSocket API itself. The
application converts between Sipral's frames and the service's messages —
base64 in JSON for most of the APIs below — and chooses the rate the
service asks for, so that only Sipral resamples: on the socket when the
session opens, and in process with `sipral_media_set_app_rate`
(`08-ffi.md`, "What ABI 1.1 added"). Direct adapters for
OpenAI Realtime, Gemini Live, ElevenLabs, Vapi and Deepgram, in a package
`sipral-agents`, are **planned, not available**.

## Summary

"SIP" is whether the service accepts a SIP call or a SIP trunk itself.
"Audio" is the codecs it takes on SIP, or the format and rate of its
streaming API where there is no SIP.

| Service | Kind | Path | SIP | Audio |
|---|---|---|---|---|
| [OpenAI Realtime](#openai-realtime) | speech-to-speech API | SIP bridge; Pipecat | yes | SIP: not listed; WebSocket: PCM 24 kHz, PCMU, PCMA |
| [Azure OpenAI Realtime](#azure-openai-realtime) | speech-to-speech API | SIP bridge | yes | SIP: not listed; WebSocket as OpenAI |
| [Azure Voice Live](#azure-voice-live) | speech-to-speech API | Pipecat; headless | no | PCM 16 or 24 kHz, G.711 in; PCM 8, 16 or 24 kHz, G.711 out |
| [Gemini Live](#gemini-live) | speech-to-speech API | Pipecat; headless | no | PCM in at any rate, PCM 24 kHz out |
| [Amazon Nova Sonic](#amazon-nova-sonic) | speech-to-speech API | Pipecat; headless | no | LPCM 8, 16 or 24 kHz both ways |
| [xAI Grok Voice Agent](#xai-grok-voice-agent) | speech-to-speech API | SIP bridge; Pipecat | yes | SIP: PCMU, PCMA, G.722 (Telnyx guide); WebSocket: PCMU 8 kHz, PCM |
| [Ultravox](#ultravox) | speech-to-speech API | SIP bridge; Pipecat | yes | G.722, Opus, PCMU, PCMA, iLBC and more |
| [Hume EVI](#hume-evi) | speech-to-speech API | headless | no | linear16 in at a declared rate; WAV out |
| [Inworld Realtime](#inworld-realtime) | speech-to-speech API | Pipecat; headless | no | G.711 μ-law, PCM |
| [Deepgram Voice Agent](#deepgram-voice-agent) | agent API | headless | no | linear16 24 kHz by default; μ-law, A-law and others |
| [Qwen-Omni Realtime](#qwen-omni-realtime) | speech-to-speech API | headless | no | PCM 16 kHz in, 24 kHz out |
| [Vapi](#vapi) | hosted platform | SIP bridge | yes | not listed |
| [Retell AI](#retell-ai) | hosted platform | SIP bridge | yes | PCMU, PCMA, G.722 |
| [Bland AI](#bland-ai) | hosted platform | SIP bridge | yes | PCMU, PCMA, Opus, G.722; SRTP required |
| [ElevenLabs Agents](#elevenlabs-agents) | hosted platform | SIP bridge | yes | PCMU, PCMA, G.722 |
| [Synthflow](#synthflow) | hosted platform | SIP bridge | yes | G.711 |
| [PolyAI](#polyai) | hosted platform | SIP bridge | yes | PCMU stated |
| [Cognigy Voice Gateway](#cognigy-voice-gateway) | hosted platform | SIP bridge | yes | G.711, Opus, G.722 |
| [Parloa](#parloa) | hosted platform | SIP bridge | yes | not listed |
| [Kore.ai](#koreai) | hosted platform | SIP bridge | yes | not listed |
| [IBM watsonx Assistant](#ibm-watsonx-assistant) | hosted platform | SIP bridge | yes | not listed |
| [SignalWire AI Agent](#signalwire-ai-agent) | hosted platform | SIP bridge | yes | Opus, G.722, PCMU, PCMA, G.729 |
| [Telnyx AI Assistants](#telnyx-ai-assistants) | hosted platform | SIP bridge, through the PBX | yes | not listed |
| [Pipecat](#pipecat) | framework | Pipecat | no | PCM, 16 kHz in and 24 kHz out by default |
| [LiveKit Agents](#livekit-agents) | framework | SIP bridge | yes | PCMU, PCMA, G.722; Opus and others on request |
| [jambonz](#jambonz) | framework | SIP bridge | yes | PCMU, PCMA, G.722, Opus |
| [OpenAI Agents SDK](#openai-agents-sdk) | framework | SIP bridge | yes, through OpenAI | as OpenAI Realtime |
| [Google ADK](#google-adk) | framework | SIP bridge, through LiveKit | yes, through LiveKit | as LiveKit |
| [Deepgram](#deepgram) | STT and TTS | Pipecat | no | linear16 at any rate in; 8 to 48 kHz out |
| [AssemblyAI](#assemblyai) | STT | Pipecat | no | pcm_s16le 8 to 96 kHz |
| [Speechmatics](#speechmatics) | STT and TTS | Pipecat | no | pcm_s16le 16 kHz (Agent API) |
| [Cartesia](#cartesia) | STT and TTS | Pipecat | no | pcm_s16le at any rate in; 8 to 48 kHz out |
| [Rime](#rime) | TTS | Pipecat | no | pcm or mulaw, 24 kHz by default |
| [ElevenLabs](#elevenlabs) | STT and TTS | Pipecat | no | PCM 8 to 48 kHz in; 16 to 44.1 kHz out |
| [Azure AI Speech](#azure-ai-speech) | STT and TTS | Pipecat | no | PCM 8 or 16 kHz in; 8 to 48 kHz out |
| [Google Cloud Speech](#google-cloud-speech) | STT and TTS | Pipecat | no | LINEAR16 8 to 48 kHz in; PCM out |
| [Amazon Transcribe and Polly](#amazon-transcribe-and-polly) | STT and TTS | Pipecat | no | PCM 8 to 48 kHz in; PCM 8 or 16 kHz out |
| [Gladia](#gladia) | STT | Pipecat | no | PCM 8, 16, 44.1 or 48 kHz |
| [Soniox](#soniox) | STT and TTS | Pipecat | no | pcm_s16le at any rate in; 8 to 48 kHz out |
| [Fish Audio](#fish-audio) | TTS | Pipecat | no | pcm, 44.1 kHz by default |
| [Neuphonic](#neuphonic) | TTS | Pipecat | no | pcm_linear or pcm_mulaw, 8 to 24 kHz |
| [Sarvam](#sarvam) | STT and TTS | Pipecat | no | PCM 8 or 16 kHz in |
| [Resemble AI](#resemble-ai) | TTS | Pipecat | no | PCM_16 or MULAW, 8 to 44.1 kHz |
| [NVIDIA Riva](#nvidia-riva) | STT and TTS | Pipecat | no | LINEAR_PCM, MULAW (gRPC) |

## Speech-to-speech model APIs

### OpenAI Realtime

A stateful API to a speech-in, speech-out model such as `gpt-realtime`,
used over WebRTC, WebSocket or SIP.

**Path: SIP bridge.** Also Pipecat (`OpenAIRealtimeLLMService`, and
`OpenAILiveLLMService` for the newer Live API).

- **Address:** `sip:proj_<project-id>@sip.api.openai.com;transport=tls`;
  for European data residency, `sip-eu.api.openai.com`. The project ID
  carries the `proj_` prefix. `sip.api.openai.com` routes by GeoIP to the
  nearest region.
- **Transport:** TLS is the only one the guide shows. It does not list
  codecs. The webhook below reports whether the call's media negotiated
  `rtp` or `srtp`.
- **Addresses to allow:** 13.79.45.80/28, 23.98.140.64/28, 40.67.149.176/28
  and 40.83.204.240/28.
- **Admission:** by webhook, not by address or digest. The project has a
  webhook (Settings, Project, Webhooks); an INVITE fires
  `realtime.call.incoming` with `data.call_id`, `data.sip_headers` (the
  INVITE's headers, without authorization headers) and
  `data.sip_media_security`. The application's server answers with
  `POST /v1/realtime/calls/{call_id}/accept` and a session configuration
  (`type`, `model`, `instructions`, voice, tools); that returns `200 OK`
  once OpenAI starts ringing the SIP leg. `.../reject` takes an optional
  `status_code` (603 if none), `.../refer` takes a `target_uri` that goes
  into `Refer-To`, and `.../hangup` ends the call. A WebSocket at
  `wss://api.openai.com/v1/realtime?call_id={call_id}` watches and steers
  the session while the call runs.
- **DTMF:** the server event `input_audio_buffer.dtmf_event_received` is
  sent for SIP calls only.
- **WebSocket (headless):** `audio/pcm` at 24 kHz only, `audio/pcmu` or
  `audio/pcma` (fields `audio.input.format` and `audio.output.format`);
  audio goes in with `input_audio_buffer.append` and comes back in
  `response.output_audio.delta`. Open Sipral's socket at 24000 Hz.

Sources: https://developers.openai.com/api/docs/guides/realtime-sip,
https://github.com/openai/openai-openapi/blob/main/openapi.yaml,
https://github.com/openai/openai-python/blob/main/src/openai/types/webhooks/realtime_call_incoming_webhook_event.py,
https://docs.pipecat.ai/api-reference/server/services/s2s/openai

### Azure OpenAI Realtime

The GPT Realtime models deployed in an Azure OpenAI resource, with the same
SIP interface as OpenAI's.

**Path: SIP bridge.**

- **Address:** `sip:proj_<internal-id>@<region>.sip.ai.azure.com;transport=tls`,
  where `<internal-id>` is the resource's internal ID shown in the portal's
  JSON view. SIP is available in `swedencentral` and `eastus2`.
- **Admission:** the `realtime.call.incoming` webhook, created with the Azure
  OpenAI webhook service, then
  `POST https://<resource>.openai.azure.com/openai/v1/realtime/calls/{call_id}/accept`
  (or `reject`, `refer`, `hangup`) with an `api-key` or bearer token; the
  `model` in the accept body is the deployment name. Monitoring is
  `wss://<resource>.openai.azure.com/openai/v1/realtime?call_id={call_id}`.
- The page does not list codecs or say whether SRTP is used.

Sources: https://learn.microsoft.com/en-us/azure/foundry/openai/how-to/realtime-audio-sip
(source: https://github.com/MicrosoftDocs/azure-ai-docs/blob/main/articles/foundry/openai/how-to/realtime-audio-sip.md)

### Azure Voice Live

A managed WebSocket speech-to-speech API in Azure AI Foundry that combines
speech recognition, a generative model and Azure's synthetic voices.

**Path: Pipecat** (`AzureVoiceLiveLLMService`), **or headless.** It has no SIP
address; Microsoft's telephony route to it is Azure Communication Services.

- **Endpoint:** `wss://<resource>.services.ai.azure.com/voice-live/realtime?api-version=2026-07-15&model=<model>`,
  authenticated with a bearer token or `api-key`.
- **In:** `input_audio_format` `pcm16`, `g711_ulaw` or `g711_alaw`;
  `input_audio_sampling_rate` 16000 or 24000 for `pcm16` (24000 if not set).
- **Out:** `output_audio_format` `pcm16` (24 kHz), `pcm16_16000hz`,
  `pcm16_8000hz`, `g711_ulaw` or `g711_alaw`.
- A headless application at 16 kHz asks for `pcm16` at 16000 in and
  `pcm16_16000hz` out and needs no resampling of its own.

Sources: https://learn.microsoft.com/en-us/azure/ai-services/speech-service/voice-live,
https://github.com/MicrosoftDocs/azure-ai-docs/blob/main/articles/ai-services/speech-service/voice-live-api-reference-2026-07-15.md,
https://github.com/MicrosoftDocs/azure-ai-docs/blob/main/articles/ai-services/speech-service/voice-live-how-to.md,
https://docs.pipecat.ai/api-reference/server/services/s2s/azure-voice-live

### Gemini Live

Google's bidirectional streaming API (`BidiGenerateContent`) for audio
sessions with Gemini models, on the Gemini Developer API and on Vertex AI.

**Path: Pipecat** (`GeminiLiveLLMService`, `GeminiLiveVertexLLMService`),
**or headless.** No SIP endpoint is documented.

- **Endpoints:** `wss://generativelanguage.googleapis.com/ws/google.ai.generativelanguage.{version}.GenerativeService.BidiGenerateContent`,
  and on Vertex AI
  `wss://{location}-aiplatform.googleapis.com/ws/google.cloud.aiplatform.{version}.LlmBidiService/BidiGenerateContent`.
- **Audio:** always raw 16-bit little-endian PCM, mono. Input is natively
  16 kHz, but the API resamples any rate, declared per blob as
  `audio/pcm;rate=<rate>`; 8 kHz PCM from a G.711 call can go in as it is.
  G.711 itself is not documented as an input. Output is always 24 kHz.

Sources: https://ai.google.dev/gemini-api/docs/live-api/capabilities,
https://github.com/googleapis/python-genai/blob/main/google/genai/live.py,
https://docs.pipecat.ai/api-reference/server/services/s2s/gemini-live

### Amazon Nova Sonic

A speech-to-speech model on Amazon Bedrock (`amazon.nova-2-sonic-v1:0`),
used through `InvokeModelWithBidirectionalStream`, an HTTP/2 event stream
rather than a WebSocket.

**Path: Pipecat** (`AWSNovaSonicLLMService`), **or headless** with an AWS SDK.
There is no SIP endpoint.

- **Audio:** `audioInputConfiguration` and `audioOutputConfiguration` take
  `mediaType` `audio/lpcm`, `sampleRateHertz` 8000, 16000 or 24000, 16-bit,
  mono, base64. AWS prefers 16 kHz for input.
- **Events:** `sessionStart`, `promptStart`, `contentStart`, `audioInput`,
  `contentEnd`, `promptEnd`, `sessionEnd`, nested in that order.

Sources: https://docs.aws.amazon.com/nova/latest/nova2-userguide/sonic-input-events.html,
https://github.com/aws-samples/amazon-nova-samples/blob/main/speech-to-speech/README.md,
https://docs.pipecat.ai/api-reference/server/services/s2s/aws

### xAI Grok Voice Agent

xAI's realtime voice-agent API, with OpenAI-Realtime-style events.

**Path: SIP bridge.** Also Pipecat (`GrokRealtimeLLMService`).

- **Address:** `sip:{phone_number}@sip.voice.x.ai;transport=tls`.
- **Setup:** register the number with `POST https://api.x.ai/v2/phone-numbers`,
  `origin` `byo_trunk`, with the webhook that receives incoming calls; the
  response carries the webhook's signing secret once.
- **Admission:** one method per number — `allowed_addresses`, the CIDR
  ranges the calls come from, or SIP digest credentials — and then the
  signed `realtime.call.incoming` webhook (`data.call_id`, `sip_headers`).
  The application connects to `wss://api.x.ai/v1/realtime?call_id={call_id}`
  and sends `session.update` and `response.create`.
- **Codecs:** stated only in the Telnyx section of the guide: G.711 μ-law,
  G.711 A-law or G.722, number in E.164.
- **Transfer and DTMF:** `POST /v1/realtime/calls/{call_id}/refer` with
  `target_uri` (custom headers are not carried on the REFER), and
  `input_audio_buffer.dtmf_event_received` for digits.
- **WebSocket (headless):** `wss://api.x.ai/v1/realtime`; xAI's phone
  example uses `audio/pcmu` at 8 kHz both ways, and its web example PCM at
  the client's own rate.

Sources: https://docs.x.ai/developers/model-capabilities/audio/voice-agent/sip,
https://github.com/xai-org/xai-cookbook/blob/main/examples/voice-agent-phone/README.md,
https://docs.pipecat.ai/api-reference/server/services/s2s/grok

### Ultravox

A hosted realtime voice platform on Ultravox's own speech model; its SIP
service is provided through Voximplant.

**Path: SIP bridge.** Also Pipecat (`UltravoxRealtimeLLMService`).

- **Address:** `agent_{agent_id}@{account-sip-domain}`; the account's SIP
  domain is in the SIP configuration (`GET /api/sip`). Agents can also be
  selected by a regular expression over the To user part (`allowedAgents`).
- **Transport:** UDP by default, `;transport=tcp` (port 5060) or
  `;transport=tls`.
- **Codecs:** G.722, G.722.1, G.722.2, Opus (48 kHz), PCMU, PCMA (8 kHz) and
  iLBC; a call offering none of them fails.
- **Admission, two ways:** an IP allow-list, `allowedCidrRanges` (IPv4 CIDR)
  in the SIP configuration API — for a host running Sipral with a fixed
  address; or SIP registration, where Ultravox registers as a user on the
  PBX with a username, password and proxy — then the Sipral bridge, on the
  same PBX, places its second call to that user.
- **Unmatched calls:** a fallback webhook, signed with HMAC-SHA256, receives
  `callerId`, `fromUri`, `toUri` and `sipHeaders` and answers with
  `startAgentCall`, `startCall` or `reject` (603 by default).
- **Headers:** an inbound header such as `X-Customer-Name` becomes the
  template variable `customer_name`.

Sources: https://docs.ultravox.ai/telephony/sip,
https://docs.pipecat.ai/api-reference/server/services/s2s/ultravox

### Hume EVI

Hume's Empathic Voice Interface, a speech-to-speech interface over a
WebSocket chat.

**Path: headless.** No SIP; Pipecat has Hume's text-to-speech service but not
EVI.

- **Endpoint:** `wss://api.hume.ai/v0/evi/chat`.
- **In:** `audio_input` messages, base64; `linear16` (16-bit signed
  little-endian PCM) at the rate and channel count declared in
  `session_settings`. μ-law is not accepted, so telephony audio is decoded
  first — Sipral's PCM already is.
- **Out:** `audio_output` messages whose `data` is a base64 WAV file; the
  rate is read from the WAV header.

Sources: https://dev.hume.ai/docs/speech-to-speech-evi/guides/audio,
https://github.com/HumeAI/hume-python-sdk/blob/main/src/hume/empathic_voice/types/audio_configuration.py

### Inworld Realtime

A WebSocket API that runs speech recognition, a selectable language model
and Inworld's speech synthesis on one connection, with an
OpenAI-Realtime-style protocol.

**Path: Pipecat** (`InworldRealtimeLLMService`), **or headless.** No SIP
address is documented.

- **Endpoint:** `wss://api.inworld.ai/api/v1/realtime/session?key=<id>&protocol=realtime`,
  `Authorization: Basic <key>`.
- **Audio:** Inworld's telephony example sets `g711_ulaw` for input and
  output; events are `input_audio_buffer.append` and
  `response.output_audio.delta`.

Sources: https://github.com/inworld-ai/inworld-api-examples/blob/main/integrations/telnyx/README.md,
https://docs.pipecat.ai/api-reference/server/services/s2s/inworld

### Deepgram Voice Agent

A WebSocket API that chains Deepgram speech recognition, a configurable
language model and Deepgram speech synthesis.

**Path: headless.** No SIP; Pipecat has Deepgram's speech-to-text and
text-to-speech services but not this API.

- **Endpoint:** `wss://agent.deepgram.com/v1/agent/converse`.
- **In** (`audio.input` in the settings message): `linear16` at 24000 Hz if
  not set; also `linear32`, `flac`, `alaw`, `mulaw`, `amr-nb`, `amr-wb`,
  `opus`, `ogg-opus`, `speex`, `g729`.
- **Out** (`audio.output`): `linear16`, `mulaw`, `alaw`, `mp3`, `opus`,
  `flac`, `aac`, with an optional `sample_rate`.
- Set both to `linear16` at the rate Sipral's socket uses.

Source: https://github.com/deepgram/deepgram-python-sdk (`src/deepgram/agent/v1/types/agent_v1settings_audio_input.py`
and the `audio_output` types beside it)

### Qwen-Omni Realtime

Alibaba Cloud's realtime WebSocket API for the Qwen3-Omni-Flash model.

**Path: headless.** No SIP; Pipecat lists Qwen only as a language model.

- **Endpoint:** `wss://dashscope.aliyuncs.com/api-ws/v1/realtime?model=<model>`.
- **Audio:** `pcm16` mono, 16 kHz in and 24 kHz out by default; events
  `input_audio_buffer.append` and `response.audio.delta`.

Sources: https://github.com/dashscope/dashscope-sdk-python/blob/main/dashscope/audio/qwen_omni/omni_realtime.py,
https://github.com/QwenLM/Qwen3-Omni/blob/main/README.md

## Hosted agent platforms

### Vapi

A hosted platform that runs voice assistants (speech recognition, language
model and synthesis) and connects them to phone numbers, SIP and WebSocket.

**Path: SIP bridge.** No Pipecat integration.

Two ways in:

- **A Vapi SIP number.** `POST /phone-number` with `provider` `vapi` and a
  `sipUri` of `sip:<any-username>@sip.vapi.ai` (US) or
  `sip:<any-username>@sip.eu.vapi.ai` (EU), matching the account's region.
  No registration is needed; optional digest credentials go in
  `authentication` (`username`, `password`, `realm`). Inbound only. A
  header such as `x-first_name` fills the assistant's template variable.
- **A bring-your-own trunk.** A credential with `provider` `byo-sip-trunk`
  and `gateways[]` listing the caller's IPv4 addresses (`inboundEnabled`,
  `netmask` 24 to 32), then a number with `provider` `byo-phone-number`.
  The caller sends to `{phoneNumber}@<credential_id>.sip.vapi.ai` (or
  `.sip.eu.vapi.ai`). Inbound calls are admitted by source address; an
  address missing from the gateways is answered 401.

Network: signalling from 44.229.228.186 and 44.238.177.138 (US) or
63.182.83.170 (EU); 5060 over UDP and TCP, 5061 over TLS; RTP on UDP
40000 to 60000, from dynamic addresses in the US. The SIP pages list no
codecs. For SRTP a trunk gateway takes the outbound protocol `tls/srtp`.

**WebSocket (headless):** a call created with transport `vapi.websocket`
and `audioFormat` `pcm_s16le` (16 kHz by default) or `mulaw` (8 kHz),
container `raw`; binary frames carry audio both ways.

Sources: https://docs.vapi.ai/advanced/sip, https://docs.vapi.ai/advanced/sip/sip-trunk,
https://docs.vapi.ai/advanced/sip/sip-networking,
https://docs.vapi.ai/calls/websocket-transport

### Retell AI

A hosted platform for language-model voice agents on phone and web calls.

**Path: SIP bridge.** No Pipecat integration.

- **Address:** `sip:sip.retellai.com`, with `;transport=tcp` (recommended),
  `;transport=udp` or `;transport=tls`; mTLS is enabled through support.
- **Codecs:** PCMU, PCMA and G.722. SRTP is supported with TLS. Re-INVITEs
  for session refresh, codec change, SDES re-keying and hold are accepted.
- **Admission:** by source address. Allow-list on Retell's side:
  18.98.16.120/30, 3.42.144.0/23 and 153.57.128.0/18 for all regions,
  143.223.88.0/21 and 161.115.160.0/19 for part of the US traffic.
- **Two ways to route a call:** import a number (E.164) bound to an agent
  and send the call for it; or call the Register Phone Call API with
  `agent_id`, `from_number`, `to_number` and `direction`, then dial
  `sip:{call_id}@sip.retellai.com` within 5 minutes. With the second,
  Retell's own transfer does not work.
- **Headers:** custom SIP headers carry metadata to the agent; transfer is
  by REFER.

Sources: https://docs.retellai.com/deploy/custom-telephony,
https://docs.retellai.com/api-references/register-phone-call

### Bland AI

A hosted platform for phone agents. SIP is an enterprise feature enabled
by Bland's support.

**Path: SIP bridge.** Pipecat has Bland's text-to-speech service, not its
agents.

- **Address:** regional hosts on TLS port 5061: `us2.sip.bland.ai`,
  `ca2.sip.bland.ai`, `asia2.sip.bland.ai`, `eu2.sip.bland.ai`, for example
  `us2.sip.bland.ai:5061;transport=tls`.
- **Transport:** TLS 1.2 or later over TCP 5061 only, no UDP and no
  plaintext 5060; the certificate chains to ISRG Root X1.
- **Media:** SRTP with AES_CM_128_HMAC_SHA1_80 is required; an offer of
  plain RTP is answered 488. RTP on UDP 16384 to 32768.
- **Codecs:** PCMU, PCMA, Opus and G.722; G.729 by advanced configuration.
- **Admission:** by source address (the default), or by registration —
  Bland registers with the PBX using digest — with optional credentials on
  the INVITE. US signalling addresses are 35.82.60.77 and 52.27.163.2; the
  media addresses, which also send Bland's SIP, are 52.13.231.129,
  35.160.144.213, 44.234.13.26 and 54.218.96.252. The other regions have
  their own lists on the page, and every address in a region's list must be
  accepted.
- **Methods:** INVITE, ACK, BYE, CANCEL, OPTIONS, REFER; DTMF by RFC 2833.

For Sipral this means an account on TLS and SRTP by SDES on the agent leg.

Source: https://docs.bland.ai/enterprise-features/SIP-integration

### ElevenLabs Agents

ElevenLabs' hosted conversational agent platform. SIP trunking is
available to enterprise accounts.

**Path: SIP bridge.** Pipecat has ElevenLabs' speech services, not its
agents.

- **Address:** `sip:<number>@sip.rtc.elevenlabs.io:5060;transport=tcp` or
  `sip:<number>@sip.rtc.elevenlabs.io:5061;transport=tls`; UDP on 5060 is
  experimental. The user part is the imported number, written with or
  without `+` exactly as it was imported.
- **Codecs:** PCMU or PCMA (8 kHz) and G.722 (16 kHz), independent of the
  agent's own audio format.
- **Admission, all optional:** digest credentials (the recommended one), a
  list of allowed source addresses in CIDR (TCP and TLS only), a list of
  allowed numbers, and remote domains for TLS certificate checks.
- **Addresses:** none are fixed. Enterprise accounts can have a static /24
  through `sip-static.rtc.elevenlabs.io`, or
  `sip-static.rtc.<region>.residency.elevenlabs.io` for `eu`, `in`, `sg`.
- **Media:** encryption disabled, allowed or required; RTP on UDP 10000 to
  60000 from dynamic addresses.
- **In-dialog requests:** the 200 OK's Contact names
  `<ip>.hosts.rtc.elevenlabs.io`, with a certificate for
  `*.hosts.rtc.elevenlabs.io`; a BYE sent to `sip.rtc.elevenlabs.io`
  instead of that remote target is answered 481.
- **Headers:** `X-CALL-ID` and `X-CALLER-ID` fill the agent's call
  variables; any other `X-` header becomes a dynamic variable
  (`X-Contact-ID` to `sip_contact_id`).
- **WebSocket (headless):** `wss://api.elevenlabs.io/v1/convai/conversation?agent_id=<id>`;
  input and output formats are set per agent: `pcm_8000`, `pcm_16000`,
  `pcm_22050`, `pcm_24000`, `pcm_44100`, `pcm_48000` or `ulaw_8000`.

Sources: https://elevenlabs.io/docs/eleven-agents/phone-numbers/sip-trunking,
https://elevenlabs.io/docs/eleven-agents/phone-numbers/sip-reference,
https://github.com/elevenlabs/elevenlabs-python (`src/elevenlabs/types/asr_input_format.py`, `tts_output_format.py`)

### Synthflow

A hosted voice-agent platform. SIP needs an enterprise plan; endpoints and
credentials appear in the console once access is granted.

**Path: SIP bridge.** No Pipecat integration.

- **Hosts:** `sip.synthflow.ai` (global, 34.138.86.8), `sip.us.synthflow.ai`
  (35.237.42.43, 34.139.4.161, 4.138.180.50) and `sip.eu.synthflow.ai`
  (34.185.212.150, 34.89.186.33, 35.242.217.198). The trunk points at the
  region of the workspace.
- **Ports:** 32681 over UDP and TCP, 32682 over TLS — not 5060 —
  for example `sip:sip.synthflow.ai:32682;transport=tls`. RTP on UDP 10000
  to 60000.
- **Codecs:** G.711 μ-law and A-law.
- **Admission:** a static trunk by source address, or SIP registration with
  digest. DTMF by RFC 2833 or SIP INFO. Transfers by REFER or a new INVITE.

Sources: https://docs.synthflow.ai/sip-trunking-acl,
https://docs.synthflow.ai/connect-your-phone-system

### PolyAI

PolyAI's Agent Studio, a hosted platform for voice agents, with a
self-service SIP trunking API.

**Path: SIP bridge.** No Pipecat integration.

- **Trunks:** created per account with
  `/v1/accounts/{account_id}/telephony/sip-trunks` on `api.us.poly.ai`,
  `api.eu.poly.ai` or `api.uk.poly.ai`. A trunk holds extensions; the user
  part of the Request-URI selects the agent, and `inbound.default_route`
  takes anything else.
- **Address:** each trunk has its own host, for example
  `tr-<trunk-id>.sbc.sip.eu.poly.ai`; the shared hosts
  `sbc.sip.us.poly.ai`, `sbc.sip.eu.poly.ai` and `sbc.sip.uk.poly.ai` need
  the trunk in an `X-PolyAI-SIP-Trunk-ID` header or an
  `x-polyai-sip-trunk-id` URI parameter.
- **Transport:** an encrypted trunk (the default) is SIP over TCP/TLS 1.2 on
  5061 with SRTP; an unencrypted one is UDP on 5060 with RTP. RTP ports
  9000 to 49000. PolyAI's certificate chains to DigiCert Global Root G2.
- **Admission:** source CIDR lists (`sip_cidr`, `rtp_cidr`) plus at most one
  of digest credentials or an `X-PolyAI-SIP-Trunk-Token` header.
- **Codecs:** the trunking pages do not list them; the Genesys guide states
  PCMU.
- **Headers and transfer:** the agent reads the INVITE's headers; handoff by
  INVITE (PolyAI stays in the call) or by REFER.

Sources: https://docs.poly.ai/api-reference/sip-trunking/introduction,
https://docs.poly.ai/api-reference/sip-trunking/connecting
(source: https://github.com/PolyAI-LDN/polyai-mintlify-doc)

### Cognigy Voice Gateway

The telephony component of NiCE Cognigy, which runs Cognigy voice agents
on phone calls; it is configured with a Cognigy representative.

**Path: SIP bridge.** No Pipecat integration.

- **Carriers:** a SIP trunk is a carrier with SIP gateways (address, port,
  netmask, inbound or outbound). Inbound calls are admitted by the gateway's
  source address. Phone numbers map to a Cognigy endpoint.
- **Signalling addresses (SaaS):** EU 3.68.22.26, 3.73.70.70, 3.74.34.237;
  US 18.210.218.95, 34.233.59.163; UK 13.43.21.62, 18.170.191.49; AU
  54.66.80.76, 52.65.113.43. Media addresses change with scaling and are
  not published.
- **Transports:** 5060 for UDP and TCP, 5061 for TLS and TLS with SRTP; SIP
  over WebSocket as well.
- **Codecs:** G.711 A-law and μ-law (preferred), Opus, G.722.
- **Other:** RFC 2833 and SIP INFO DTMF, session timers, UPDATE, custom
  headers both ways; it sends REFER but does not accept one.

Sources: https://docs.cognigy.com/voice-gateway/webapp/carriers,
https://docs.cognigy.com/voice-gateway/technical-capabilities,
https://docs.cognigy.com/ai/administer/installation/ip-ranges-shared-environments
(source: https://github.com/Cognigy/docs)

### Parloa

A hosted platform for contact-centre voice agents.

**Path: SIP bridge.** No Pipecat integration.

- **Address:** a customer-specific host under `voip.parloa.com`, for example
  `sip:<customer-id>@<customer>.voip.parloa.com`.
- **Transport:** UDP 5060 unencrypted, TLS 5061 encrypted (recommended).
- **Admission:** in Release Settings, Platform Settings: the external
  addresses of the calling system, digest credentials, or both.
- **Other:** INVITE and REFER; custom SIP headers for routing. The
  documentation does not list codecs. Parloa's own addresses, which the
  caller's firewall allows, are given on its Public IPs page.

Source: https://docs.parloa.com/rule-based-automation/phone-integrations/sip

### Kore.ai

Kore.ai's AI for Service, whose Voice Gateway takes calls for its
contact-centre agents.

**Path: SIP bridge.** No Pipecat integration.

- **Setup:** Configure SIP Trunk shows a pre-configured SIP URI; inbound
  callers are listed by address ("Incoming IP Address") or FQDN, with
  optional SIP credentials.
- **US-East:** `savg-sbc1.kore.ai` (3.224.189.218) and `savg-sbc2.kore.ai`
  (35.174.41.205); TCP and UDP 5060, TLS 5061; RTP from 44.215.230.111 and
  54.210.75.166 on ports 6000 to 65535. Other regions: `usw-savg-sbc1`,
  `eu-savg-sbc1`, `de-savg-sbc1`, `ind-savg-sbc1`, `au-prod-savg-sbc1`,
  `jp-savg-sbc1` (each with a `2`) under `kore.ai`.
- **Headers and transfer:** INVITE headers are readable as
  `{{SIPHEADER.<name>}}`; transfer by REFER.
- The pages do not list codecs; their example INVITE offers PCMU.

Sources: https://docs.kore.ai/ai-for-service/channels/voice-gateway/deployment-and-operations
(source: https://github.com/Koredotcom/docs-v2/blob/main/ai-for-service/channels/voice-gateway/deployment-and-operations.mdx),
https://github.com/Koredotcom/docs-v2/blob/main/ai-for-service/channels/voice-gateway/configure-voice-gateway.mdx

### IBM watsonx Assistant

The phone integration of watsonx Assistant on IBM Cloud, which answers
calls arriving on a SIP trunk with IBM's speech services.

**Path: SIP bridge.** No Pipecat integration.

- **Address:** the assistant's SIP URI, copied from its phone integration
  page. Each region has three SBCs, for example
  `public.0001.voip.us-south.assistant.watson.cloud.ibm.com` (Dallas:
  67.228.108.82, 169.63.5.162, 150.239.30.146) and the same pattern for
  `us-east`, `eu-de`, `eu-gb`, `au-syd`, `jp-tok`.
- **Admission:** the trunk provider's addresses are allow-listed by IBM —
  through a provider IBM works with, or a support case for one's own trunk.
  "Enable SIP authentication" adds digest and requires TLS.
- **Media:** "Force secure trunking" turns on SRTP.
- **Headers and transfer:** chosen INVITE headers arrive in
  `sip_custom_invite_headers`; transfer by REFER. On a setup failure it can
  answer 503 so that the caller tries another region.
- The page does not list codecs or say whether UDP or TCP is accepted.

Source: https://github.com/ibm-cloud-docs/watson-assistant/blob/master/phone-config.md

### SignalWire AI Agent

AI Agent resources on SignalWire's communications platform, reached by
phone number or SIP address.

**Path: SIP bridge.** No Pipecat integration.

- **Address:** `sip:<user>@<space>-<domain>.dapp.signalwire.com`, created as
  a SIP Address on the AI Agent resource; `user` defaults to `*`, any user
  part. Inbound only.
- **Codecs:** `OPUS`, `G722`, `PCMU`, `PCMA`, `G729` (default `PCMU`,
  `PCMA`), chosen per address.
- **Encryption:** `required`, `optional` (default) or `forbidden`, with the
  suites listed per address, AES_CM_128_HMAC_SHA1_80 among them.
- **Admission:** `ip_auth` (up to 256 addresses or CIDR ranges) and a
  password.
- **Network:** 5060, and 5061 for TLS. SignalWire publishes no fixed address
  list; the caller resolves `sip.signalwire.com` and the names beside it.

Sources: https://developer.signalwire.com/platform/addresses,
https://developer.signalwire.com/platform/voice/sip,
https://developer.signalwire.com/platform/allow-signalwire-ips-through-your-firewall
(source: https://github.com/signalwire/docs)

### Telnyx AI Assistants

Hosted voice agents on Telnyx's network.

**Path: SIP bridge, through the PBX.** SIP Attach turns the call around:
Telnyx registers on the PBX as an extension (a UAC connection), and the
AI Assistant is that extension. The Sipral bridge, registered on the same
PBX, places its second call to it. The connection needs the PBX's SIP
username and password, its proxy address and the transport (UDP, TCP or
TLS); Telnyx registers from 192.76.120.14 (US), 192.76.120.72 (Europe) and
regional addresses beside them, which the PBX allows.

Source: https://support.telnyx.com/en/articles/14805261-how-to-configure-sip-attach-using-a-uac-connection

## Frameworks

### Pipecat

An open-source Python framework that orchestrates speech, language and
speech-to-speech services into real-time pipelines.

**Path: Pipecat** (`sipral-pipecat`). Pipecat has no SIP
transport of its own; its telephony goes through Daily (WebRTC, with SIP
dial-in), LiveKit, or WebSocket serializers for Twilio, Telnyx, Plivo,
Exotel, Genesys and Vonage. A Sipral transport puts a SIP call straight into
the pipeline without one of those in between.

- **Audio:** `PipelineParams` defaults to 16000 Hz in and 24000 Hz out; most
  services take `sample_rate=None` to mean the pipeline's rate.
- **Speech-to-speech services listed:** AWS Nova Sonic, Azure Voice Live,
  Gemini Live, Gemini Live on Vertex AI, Grok Voice Agent, Inworld Realtime,
  OpenAI GPT-Live, OpenAI Realtime and Ultravox, and two community ones.
- **Speech engines:** the last group below, among others.

Sources: https://docs.pipecat.ai/api-reference/server/services/supported-services,
https://docs.pipecat.ai/pipecat/telephony/overview,
https://docs.pipecat.ai/pipecat/telephony/daily-sip
(source: https://github.com/pipecat-ai/docs)

### LiveKit Agents

A framework for agents that join LiveKit rooms as participants; LiveKit's
SIP service brings a SIP call into a room.

**Path: SIP bridge.**

- **Address (LiveKit Cloud):** `sip:<subdomain>.sip.livekit.cloud`, where the
  subdomain is the project ID without `p_`; regional endpoints restrict a
  call to one region.
- **Transport:** UDP by default, `;transport=tcp` or `;transport=tls`; media
  encryption on the inbound trunk can be disabled, allowed or required.
- **Codecs:** PCMU, PCMA and G.722 by default; Opus, AMR-WB and others are
  added per trunk or call (`codecs`, `only_listed_codecs`), the extras on
  TCP and TLS only. Only early offer: the SDP in the INVITE, which a call
  Sipral places with an offer carries (`04-ua.md`).
- **Admission:** an inbound trunk with its numbers and either
  `allowed_addresses` (IP or CIDR) or `auth_username` and `auth_password`;
  a dispatch rule maps the call into a room where the agent runs.
- **Agent audio:** room input and output default to 24000 Hz mono.

Sources: https://docs.livekit.io/sip/sip-trunk/,
https://docs.livekit.io/reference/telephony/codecs-negotiation/,
https://github.com/livekit/protocol/blob/main/protobufs/livekit_sip.proto,
https://github.com/livekit/agents

### jambonz

An open-source voice platform, hosted as jambonz.cloud or run by the user,
whose applications — voice agents among them — are driven by webhooks and
a WebSocket API.

**Path: SIP bridge.**

- **jambonz.cloud:** a SIP FQDN chosen at sign-up, `<subdomain>.sip.jambonz.cloud`;
  signalling at 54.236.168.131, UDP and TCP 5060, TLS 5061, SIP over
  WebSocket 8443; RTP from 54.144.249.44 and 3.218.246.146 on UDP 40000 to
  60000.
- **Codecs:** PCMU, PCMA, G.722, Opus.
- **Admission:** a carrier whose inbound gateway is the caller's address, or
  digest credentials; SIP clients can also register to the account's FQDN
  as realm.
- **Audio to an application:** the `listen` verb sends 16-bit PCM at 8000,
  16000, 24000, 48000 or 64000 Hz over a WebSocket.

Sources: https://docs.jambonz.org/guides/get-started/jambonz-cloud,
https://github.com/jambonz/jambonz-api-server/blob/main/lib/swagger/swagger.yaml

### OpenAI Agents SDK

OpenAI's framework for agent workflows, whose realtime agents can run on
a phone call.

**Path: SIP bridge, to OpenAI.** The SDK attaches to a call that OpenAI's SIP
endpoint already received: the `realtime.call.incoming` webhook fires, the
application accepts the call, and `RealtimeRunner` with
`OpenAIRealtimeSIPModel` joins it by `call_id`. The SIP side is the one in
[OpenAI Realtime](#openai-realtime).

Sources: https://openai.github.io/openai-agents-python/realtime/transport/,
https://github.com/openai/openai-agents-python/blob/main/examples/realtime/twilio_sip/README.md

### Google ADK

Google's Agent Development Kit, whose live agents take and give audio over
Gemini Live.

**Path: SIP bridge, to LiveKit.** ADK's `LiveKitRunner` puts an agent in a
LiveKit room, and "a SIP caller is an ordinary LiveKit participant": the
call reaches the agent once a LiveKit inbound trunk and dispatch rule point
at it, as in [LiveKit Agents](#livekit-agents). Audio inside is 16-bit PCM,
16 kHz in and 24 kHz out.

Sources: https://google.github.io/adk-docs/live/,
https://github.com/google/adk-docs/blob/main/docs/integrations/livekit.md

## Speech engines reached through Pipecat

Every engine here has a Pipecat service, which is the path; the streaming
formats are given for a headless application that talks to the engine
itself. Speech-to-text takes Sipral's PCM in; text-to-speech gives PCM back
at a rate Sipral's socket accepts.

### Deepgram

Streaming speech-to-text (Nova, Flux) and text-to-speech (Aura, Flux TTS)
over WebSocket.

- **STT:** `wss://api.deepgram.com/v1/listen?encoding=linear16&sample_rate=16000`;
  `encoding` also `mulaw`, `alaw`, `opus` and others. Flux is `/v2/listen`.
- **TTS:** `/v1/speak` with `encoding` `linear16` (default), `mulaw` or
  `alaw` and `sample_rate` 8000, 16000, 24000 (default), 32000 or 48000;
  `/v2/speak` adds 44100 for `linear16`.
- **Pipecat:** `DeepgramSTTService`, `DeepgramFluxSTTService`,
  `DeepgramTTSService`.

Sources: https://github.com/deepgram/deepgram-api-specs/blob/main/asyncapi.yml,
https://docs.pipecat.ai/api-reference/server/services/stt/deepgram,
https://docs.pipecat.ai/api-reference/server/services/tts/deepgram

### AssemblyAI

Streaming speech-to-text (Universal-Streaming and Universal-3 Pro models)
over WebSocket.

- **Endpoint:** `wss://streaming.assemblyai.com/v3/ws`; EU
  `streaming.eu.assemblyai.com`.
- **Audio:** `encoding` `pcm_s16le` (default) or `pcm_mulaw`, `sample_rate`
  any integer from 8000 to 96000, required for PCM.
- **Pipecat:** `AssemblyAISTTService`. AssemblyAI's reference and Pipecat's
  page disagree on the default model; set `model` explicitly.

Sources: https://github.com/AssemblyAI/assemblyai-python-sdk/blob/master/assemblyai/streaming/v3/models.py,
https://github.com/AssemblyAI/assemblyai-skill/blob/main/skills/assemblyai/references/streaming.md,
https://docs.pipecat.ai/api-reference/server/services/stt/assemblyai

### Speechmatics

Realtime speech-to-text over WebSocket; text-to-speech in preview over
HTTP.

- **STT, classic:** `wss://eu.rt.speechmatics.com/v2`, `audio_format` raw
  with `pcm_s16le`, `pcm_f32le` or `mulaw` at any rate.
- **STT, Agent API** (what Pipecat uses): `wss://<region>.rt.speechmatics.com/v2/agent`,
  `pcm_s16le` or `pcm_f32le` at 16000 Hz only.
- **TTS:** `output_format` `pcm_16000` or `wav_16000`.
- **Pipecat:** `SpeechmaticsSTTService`, `SpeechmaticsTTSService`. A call on
  G.711 is resampled to 16 kHz on the way in.

Sources: https://github.com/speechmatics/docs/blob/main/spec/agent-stt.yaml,
https://github.com/speechmatics/docs/blob/main/spec/realtime.yaml,
https://github.com/speechmatics/docs/blob/main/docs/text-to-speech/quickstart.mdx,
https://docs.pipecat.ai/api-reference/server/services/stt/speechmatics

### Cartesia

Streaming text-to-speech (Sonic) and speech-to-text (Ink) over WebSocket.

- **TTS:** `wss://api.cartesia.ai/tts/websocket`, `output_format`
  `{container: "raw", encoding, sample_rate}` with `pcm_s16le`, `pcm_f32le`,
  `pcm_mulaw` or `pcm_alaw` at 8000, 16000, 22050, 24000, 44100 or 48000.
- **STT:** `/stt/websocket` and `/stt/turns/websocket`, `encoding`
  `pcm_s16le`, `pcm_mulaw` and others, `sample_rate` required.
- **Pipecat:** `CartesiaTTSService`, `CartesiaSTTService`,
  `CartesiaTurnsSTTService`.

Sources: https://github.com/cartesia-ai/cartesia-python (`src/cartesia/types/raw_encoding.py`,
`raw_output_format_param.py`, `stt_encoding.py`),
https://docs.pipecat.ai/api-reference/server/services/tts/cartesia

### Rime

Streaming text-to-speech over WebSocket and HTTP.

- **Endpoint:** `wss://users-ws.rime.ai/ws3` (JSON, base64 chunks with word
  timestamps); `/ws` and `/ws2` are older.
- **Audio:** `audioFormat` `pcm`, `mulaw` or `mp3` among others;
  `samplingRate` 24000 by default, higher rates upsampled. For telephony
  Rime gives `mulaw` at 8000.
- **Pipecat:** `RimeTTSService`, `RimeHttpTTSService`.

Sources: https://docs.rime.ai/api-reference/endpoint/websockets,
https://docs.rime.ai/docs/streaming,
https://docs.pipecat.ai/api-reference/server/services/tts/rime

### ElevenLabs

Streaming text-to-speech and realtime speech-to-text (Scribe) over
WebSocket.

- **TTS:** `wss://api.elevenlabs.io/v1/text-to-speech/{voice_id}/stream-input`,
  `output_format` `pcm_16000`, `pcm_22050`, `pcm_24000`, `pcm_44100` or
  `ulaw_8000` (MP3 by default).
- **STT:** `/v1/speech-to-text/realtime`, `audio_format` `pcm_8000` to
  `pcm_48000` or `ulaw_8000`, model `scribe_v2_realtime`.
- **Pipecat:** `ElevenLabsTTSService`, `ElevenLabsRealtimeSTTService`.

Sources: https://github.com/elevenlabs/elevenlabs-python (`src/elevenlabs/types/output_format.py`,
`audio_format_enum.py`),
https://docs.pipecat.ai/api-reference/server/services/tts/elevenlabs,
https://docs.pipecat.ai/api-reference/server/services/stt/elevenlabs

### Azure AI Speech

Microsoft's speech-to-text and text-to-speech, used through the Speech
SDK.

- **STT:** 16-bit signed PCM, mono, 8000 or 16000 Hz in a push or pull
  stream; μ-law only inside a WAV container.
- **TTS:** raw formats `raw-8khz-16bit-mono-pcm`, `raw-16khz-16bit-mono-pcm`,
  `raw-24khz-16bit-mono-pcm`, `raw-48khz-16bit-mono-pcm`, the 22.05 and
  44.1 kHz ones, and `raw-8khz-8bit-mono-mulaw`.
- **Pipecat:** `AzureSTTService` (SDK-based), `AzureTTSService`.

Sources: https://github.com/MicrosoftDocs/azure-ai-docs/blob/main/articles/ai-services/speech-service/how-to-use-audio-input-streams.md,
https://github.com/MicrosoftDocs/azure-ai-docs/blob/main/articles/ai-services/speech-service/rest-text-to-speech.md,
https://docs.pipecat.ai/api-reference/server/services/tts/azure

### Google Cloud Speech

Google Cloud Speech-to-Text v2 and Text-to-Speech, streamed over gRPC, not
WebSocket.

- **STT:** `StreamingRecognize`, `LINEAR16` (headerless 16-bit LE), `MULAW`,
  `ALAW` and others, `sample_rate_hertz` 8000 to 48000, 16000 optimal.
- **TTS:** `StreamingSynthesize`, `PCM`, `ALAW`, `MULAW` or `OGG_OPUS`.
- **Pipecat:** `GoogleSTTService`, `GoogleTTSService`.

Sources: https://github.com/googleapis/googleapis/blob/master/google/cloud/speech/v2/cloud_speech.proto,
https://github.com/googleapis/googleapis/blob/master/google/cloud/texttospeech/v1/cloud_tts.proto,
https://docs.pipecat.ai/api-reference/server/services/stt/google

### Amazon Transcribe and Polly

Amazon's streaming speech-to-text and its text-to-speech.

- **Transcribe:** `StartStreamTranscription` over HTTP/2 or WebSocket,
  `media-encoding` `pcm` (16-bit signed LE) among others, `sample-rate`
  8000 to 48000. Pipecat's service takes 8000 or 16000 only.
- **Polly:** `OutputFormat` `pcm` (16-bit signed LE mono) at 8000 or 16000,
  or `mulaw` at 8000.
- **Pipecat:** `AWSTranscribeSTTService`, `AWSPollyTTSService`.

Sources: https://github.com/aws/api-models-aws/blob/main/models/transcribe-streaming/service/2017-10-26/transcribe-streaming-2017-10-26.json,
https://github.com/boto/botocore/blob/develop/botocore/data/polly/2016-06-10/service-2.json,
https://docs.pipecat.ai/api-reference/server/services/stt/aws

### Gladia

Streaming speech-to-text, set up by an HTTP request that returns a
WebSocket URL.

- **Session:** `POST https://api.gladia.io/v2/live`.
- **Audio:** `encoding` `wav/pcm`, `wav/alaw` or `wav/ulaw`, `bit_depth` 8
  or 16, `sample_rate` 8000, 16000, 44100 or 48000. 24000 is not among
  them; open Sipral's socket at 16 kHz or 48 kHz for it.
- **Pipecat:** `GladiaSTTService`.

Sources: https://github.com/gladiaio/docs/blob/main/chapters/live-stt/quickstart.mdx,
https://github.com/gladiaio/skills/blob/main/plugins/gladia/skills/gladia-live-transcription/references/session-config.md,
https://docs.pipecat.ai/api-reference/server/services/stt/gladia

### Soniox

Streaming speech-to-text and text-to-speech over WebSocket.

- **STT:** `wss://stt-rt.soniox.com/transcribe-websocket`, `audio_format`
  `pcm_s16le`, `mulaw`, `alaw` and others, with `sample_rate` and
  `num_channels` for raw audio.
- **TTS:** `wss://tts-rt.soniox.com/tts-websocket`, `pcm_s16le`,
  `pcm_mulaw` and others at 8000, 16000, 24000, 44100 or 48000.
- **Pipecat:** `SonioxSTTService`, `SonioxTTSService`.

Sources: https://github.com/soniox/soniox-python/blob/main/docs/types.md,
https://docs.pipecat.ai/api-reference/server/services/stt/soniox

### Fish Audio

Streaming text-to-speech over WebSocket.

- **Endpoint:** `wss://api.fish.audio/v1/tts/live`.
- **Audio:** `format` `pcm`, `wav`, `mp3` (default) or `opus`; `sample_rate`
  44100 when not set (48000 for Opus). No μ-law.
- **Pipecat:** `FishAudioTTSService`, `pcm` by default.

Sources: https://github.com/fishaudio/docs/blob/main/api-reference/asyncapi.yml,
https://docs.pipecat.ai/api-reference/server/services/tts/fish

### Neuphonic

Streaming text-to-speech over WebSocket and server-sent events.

- **Endpoint:** `wss://api.neuphonic.com`.
- **Audio:** `encoding` `pcm_linear` (default) or `pcm_mulaw`;
  `sampling_rate` 8000, 16000, 22050 or 24000 in the SDK's examples, 24000
  by default.
- **Pipecat:** `NeuphonicTTSService` (22050 Hz by default; set it to the
  socket's rate).

Sources: https://github.com/neuphonic/pyneuphonic/blob/main/pyneuphonic/models.py,
https://docs.pipecat.ai/api-reference/server/services/tts/neuphonic

### Sarvam

Speech-to-text and text-to-speech for Indian languages over WebSocket.

- **STT:** realtime `/speech-to-text-realtime/ws`, `pcm_s16le` or WAV,
  base64, at 8000 or 16000 Hz only; any other rate closes the connection
  with code 4000. Sarvam advises 8000 for telephony audio.
- **Pipecat:** `SarvamRealtimeSTTService`, `SarvamTTSService`.

Sources: https://github.com/sarvamai/skills/blob/main/speech-to-text/SKILL.md,
https://docs.pipecat.ai/api-reference/server/services/stt/sarvam

### Resemble AI

Streaming text-to-speech over WebSocket.

- **Endpoint:** `wss://websocket.cluster.resemble.ai/stream`.
- **Audio:** `precision` `PCM_16`, `PCM_24`, `PCM_32` or `MULAW`;
  `sample_rate` 8000, 16000, 22050, 32000 or 44100 — not 24000 or 48000.
- **Pipecat:** `ResembleAITTSService` (22050 Hz by default; set it to 8000 or
  16000 for a Sipral socket).

Sources: https://github.com/resemble-ai/resemble-mcp/blob/master/docs/pages/voice-generation/text-to-speech/streaming-websocket.mdx,
https://docs.pipecat.ai/api-reference/server/services/tts/resembleai

### NVIDIA Riva

Speech-to-text and text-to-speech over gRPC, hosted by NVIDIA or run
locally as a NIM.

- **Endpoint:** `grpc.nvcf.nvidia.com:443` hosted; a local NIM on its own
  port.
- **Audio:** `AudioEncoding` `LINEAR_PCM` (16-bit signed LE), `MULAW`,
  `ALAW`, `FLAC`, `OGGOPUS`.
- **Pipecat:** `NvidiaSTTService`, `NvidiaTTSService`.

Sources: https://github.com/nvidia-riva/common/blob/main/riva/proto/riva_audio.proto,
https://docs.pipecat.ai/api-reference/server/services/stt/nvidia

## Choosing a path

**SIP bridge** when the service takes SIP calls. Nothing runs between
Sipral and the service but the two calls, and the service keeps its own
features — transfers, headers, turn-taking — as it documents them. It
costs one hop of mixing: the caller's audio is decoded, mixed and encoded
again on its way to the agent, and the agent's on its way back, and the
second call is one more RTP leg across the network.

**Pipecat** when the speech services are to be chosen, or changed, without
changing the telephony: the recognition, language and synthesis services
are configuration of the pipeline, and one Sipral transport reaches all of
them. The pipeline adds its own processing between frames.

**Headless** for full control: one process holds the call and the
service's connection, chooses the rate, sees every frame and every
`VoiceActivity` message, and decides when to barge in (`07-headless.md`,
"Latency"). The application writes the protocol for each service itself,
until `sipral-agents` provides it for the five services it is planned for.
