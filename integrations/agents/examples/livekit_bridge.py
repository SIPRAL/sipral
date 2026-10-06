# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek

"""A SIP call as a participant in a LiveKit room.

Each call to the account joins a room of its own (``call-<n>``, or
``LIVEKIT_ROOM`` for every call) as the participant ``sip-<n>``: the
caller's voice is published as an audio track, and the first audio track
another participant publishes -- a LiveKit Agents worker, a person in a
browser -- is played to the caller. The call's frames run at 48 kHz, the
rate LiveKit's audio uses, so the library converts between the codec and
the room and nothing is resampled here. Either side leaving ends the other.

Uses LiveKit's Python SDK (``livekit`` and ``livekit-api``, Apache-2.0),
which this example needs and the package does not:

    pip install livekit livekit-api

    LIVEKIT_URL=ws://127.0.0.1:7880 LIVEKIT_API_KEY=devkey \\
    LIVEKIT_API_SECRET=secret \\
    SIPRAL_AOR=sip:agent@pbx.example SIPRAL_REGISTRAR=sip:pbx.example \\
    SIPRAL_REGISTRAR_ADDRESS=192.0.2.10:5060 \\
    SIPRAL_AUTH_USER=agent SIPRAL_AUTH_PASSWORD=... \\
    python3 livekit_bridge.py

``livekit-server --dev --bind 127.0.0.1 --node-ip 127.0.0.1`` runs a
server on this machine with the key ``devkey`` and the secret ``secret``;
without ``--node-ip`` it advertises the machine's LAN address for media
while listening on loopback only, and no audio flows.
"""

from __future__ import annotations

import asyncio
import os

from livekit import api, rtc

from sipral import Call, SipralError, Stack
from sipral.enums import AudioMode, EventKind

from sipral_agents import wait_for_media

RATE = 48000


def token(room: str, identity: str) -> str:
    """A token that lets ``identity`` join ``room``, publish and subscribe."""
    return (
        api.AccessToken(os.environ["LIVEKIT_API_KEY"], os.environ["LIVEKIT_API_SECRET"])
        .with_identity(identity)
        .with_grants(api.VideoGrants(room_join=True, room=room))
        .to_jwt()
    )


async def join_room(call: Call, url: str, room_name: str, identity: str) -> None:
    """Carry ``call`` into ``room_name`` as ``identity`` until either the
    call ends or the room drops this participant."""
    media = call.media
    media.set_app_rate(RATE)
    frame_bytes = media.frame_samples * 2
    room = rtc.Room()
    left = asyncio.Event()
    tasks: list[asyncio.Task] = []

    async def play(track: rtc.Track) -> None:
        # the room's audio, in the call's own frame length
        pending = bytearray()
        stream = rtc.AudioStream(track, sample_rate=RATE, num_channels=1)
        try:
            async for event in stream:
                pending += bytes(event.frame.data)
                while len(pending) >= frame_bytes:
                    media.send_audio(bytes(pending[:frame_bytes]))
                    del pending[:frame_bytes]
        except (RuntimeError, SipralError):
            left.set()
        finally:
            await stream.aclose()

    def subscribed(track: rtc.Track, _publication, _participant) -> None:
        if track.kind == rtc.TrackKind.KIND_AUDIO and not tasks:
            tasks.append(asyncio.create_task(play(track)))

    room.on("track_subscribed", subscribed)
    room.on("disconnected", lambda *_: left.set())
    await room.connect(url, token(room_name, identity))
    source = rtc.AudioSource(RATE, 1, queue_size_ms=100)
    track = rtc.LocalAudioTrack.create_audio_track("caller", source)
    await room.local_participant.publish_track(
        track, rtc.TrackPublishOptions(source=rtc.TrackSource.SOURCE_MICROPHONE)
    )

    async def publish() -> None:
        while True:
            pcm = await media.frames.get()
            samples = len(pcm) // 2
            await source.capture_frame(rtc.AudioFrame(pcm, RATE, 1, samples))

    async def watch() -> None:
        while not call.ended:
            event = await call.events.get()
            if event.kind == EventKind.CALL_ENDED:
                break
        left.set()

    tasks += [asyncio.create_task(publish()), asyncio.create_task(watch())]
    try:
        await left.wait()
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        await room.disconnect()
        await source.aclose()


async def bridge(call: Call, url: str, room_name: str, identity: str) -> None:
    try:
        if await wait_for_media(call, 10):
            await join_room(call, url, room_name, identity)
    finally:
        if not call.ended:
            try:
                call.hangup()
            except SipralError:
                pass
        await asyncio.sleep(0.2)
        call.close()


async def main() -> None:
    url = os.environ["LIVEKIT_URL"]
    stack = Stack(
        loop=asyncio.get_running_loop(),
        audio=AudioMode.APPLICATION,
        bind_port=int(os.environ.get("SIPRAL_PORT", "5060")),
    )
    account = stack.add_account(
        os.environ.get("SIPRAL_AOR", "sip:agent@example.invalid"),
        registrar=os.environ.get("SIPRAL_REGISTRAR"),
        registrar_address=os.environ["SIPRAL_REGISTRAR_ADDRESS"],
        auth_user=os.environ.get("SIPRAL_AUTH_USER"),
        auth_password=os.environ.get("SIPRAL_AUTH_PASSWORD"),
    )
    if os.environ.get("SIPRAL_REGISTRAR"):
        account.register()
    print(f"listening on {stack.bind_address}; calls join rooms on {url}")
    calls: set[asyncio.Task] = set()
    try:
        while True:
            event = await stack.events.get()
            if event.kind != EventKind.INCOMING_CALL:
                continue
            call = stack.answer_call(event)
            room_name = os.environ.get("LIVEKIT_ROOM") or f"call-{call.handle:x}"
            print(f"call {call.handle:x} joins {room_name}")
            task = asyncio.create_task(bridge(call, url, room_name, f"sip-{call.handle:x}"))
            calls.add(task)
            task.add_done_callback(calls.discard)
    finally:
        for task in calls:
            task.cancel()
        await asyncio.gather(*calls, return_exceptions=True)
        stack.close()


if __name__ == "__main__":
    asyncio.run(main())
