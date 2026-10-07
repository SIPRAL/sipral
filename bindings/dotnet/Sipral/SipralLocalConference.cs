// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Channels;
using Sipral.Interop;

namespace Sipral;

/// <summary>One member of a <see cref="SipralLocalConference"/>. The handle
/// is a call's, or <see cref="SipralLocalConference.Handle"/> for this end;
/// gains are in engine steps (256 is unity).</summary>
public sealed record SipralConferenceMember(
    ulong Member,
    bool Talking,
    bool MutedInput,
    bool MutedOutput,
    uint GainInput,
    uint GainOutput);

/// <summary>
/// A local conference: this stack's calls, each on its own codec, mixed so
/// every member hears everyone but itself (this end included, unless made
/// without).
///
/// An added call stops carrying its own frames (its <see cref="CallMedia"/>
/// still reads the socket and sends RTCP). In device mode the audio engine
/// mixes; in application mode this class ticks every 20 ms, with
/// <see cref="SendAudio"/> as this end's microphone and <see cref="Frames"/>
/// what it hears. Changes arrive as
/// <see cref="SipralEventKind.LocalConferenceChanged"/>.
/// </summary>
public sealed class SipralLocalConference : IDisposable
{
    private const int PacketBytes = 1500;
    private const int AddressBytes = 128;

    private readonly SipralStack _stack;
    private readonly ConcurrentDictionary<ulong, Call> _members = new();
    private readonly ConcurrentQueue<short[]> _toSend = new();
    private readonly Channel<short[]> _frames = Channel.CreateUnbounded<short[]>(new UnboundedChannelOptions { SingleWriter = true });
    private readonly ManualResetEventSlim _closed = new(false);
    private readonly Thread? _thread;
    private readonly IntPtr _packetData = Marshal.AllocHGlobal(PacketBytes);
    private readonly IntPtr _packetDestination = Marshal.AllocHGlobal(AddressBytes);
    private readonly List<short> _pending = new();
    private int _disposed;

    /// <summary>The conference's handle, also this end's member
    /// handle.</summary>
    public ulong Handle { get; }

    /// <summary>Whether this end takes part.</summary>
    public bool Local { get; }

    /// <summary>The rate of this end's frames, in hertz.</summary>
    public uint SampleRate { get; }

    /// <summary>Samples in one of this end's frames: twenty milliseconds.</summary>
    public int FrameSamples { get; }

    /// <summary>What this end hears, in application mode.</summary>
    public IAsyncEnumerable<short[]> Frames => _frames.Reader.ReadAllAsync();

    /// <summary><c>sipral_local_conference_create</c>.
    /// <paramref name="maxMembers"/> counts this end;
    /// <paramref name="sampleRate"/> (8000, 16000, 32000 or 48000) applies in
    /// application mode. Other rates throw with
    /// <see cref="SipralStatus.ConferenceRefused"/>.</summary>
    public SipralLocalConference(SipralStack stack, uint maxMembers = 16, bool local = true, uint sampleRate = 16000)
    {
        _stack = stack;
        var config = SipralLocalConferenceConfig.Sized();
        config.MaxMembers = maxMembers;
        config.Local = local ? 0u : (uint)SipralToggle.Off;
        config.SampleRate = sampleRate;
        ulong handle = 0;
        SipralErrors.Call(
            () => NativeMethods.sipral_local_conference_create(stack.Handle, in config, out handle),
            "sipral_local_conference_create");
        Handle = handle;
        var info = Info();
        Local = info.Local != 0;
        SampleRate = info.SampleRate;
        FrameSamples = (int)info.FrameSamples;
        if (stack.AudioMode != SipralAudio.Device)
        {
            _thread = new Thread(Run) { IsBackground = true, Name = "sipral-conference" };
            _thread.Start();
        }
    }

    /// <summary><c>sipral_local_conference_add</c>, from the next tick. A
    /// full conference, a call already in one, or an unmixable codec throws
    /// with <see cref="SipralStatus.ConferenceRefused"/>.</summary>
    public void Add(Call call)
    {
        // stop the call's own pump first, so no frame is taken twice
        var was = call.Media?.Pumped;
        if (call.Media is { } media)
        {
            media.Pumped = true;
        }
        try
        {
            SipralErrors.Call(
                () => NativeMethods.sipral_local_conference_add(Handle, call.Handle),
                "sipral_local_conference_add");
        }
        catch
        {
            if (call.Media is { } restored && was is { } pumped)
            {
                restored.Pumped = pumped;
            }
            throw;
        }
        _members[call.Handle] = call;
    }

    /// <summary><c>sipral_local_conference_remove</c>, from the next
    /// tick.</summary>
    public void Remove(Call call)
    {
        SipralErrors.Call(
            () => NativeMethods.sipral_local_conference_remove(Handle, call.Handle),
            "sipral_local_conference_remove");
        _members.TryRemove(call.Handle, out _);
        if (call.Media is { } media)
        {
            media.Pumped = _stack.AudioMode == SipralAudio.Device;
        }
    }

    private ulong MemberHandle(Call? member) => member?.Handle ?? Handle;

    /// <summary>Mutes one direction of a member (<see langword="null"/> for
    /// this end). Input is what it says, output what it hears.</summary>
    public void SetMuted(Call? member, SipralAudioDirection direction, bool muted = true)
    {
        var named = MemberHandle(member);
        SipralErrors.Call(
            () => NativeMethods.sipral_local_conference_set_muted(Handle, named, (uint)direction, muted ? 1u : 0u),
            "sipral_local_conference_set_muted");
    }

    /// <summary>Sets a member's gain in engine steps (256 is unity, 1024 the
    /// maximum).</summary>
    public void SetGain(Call? member, SipralAudioDirection direction, uint gain)
    {
        var named = MemberHandle(member);
        SipralErrors.Call(
            () => NativeMethods.sipral_local_conference_set_gain(Handle, named, (uint)direction, gain),
            "sipral_local_conference_set_gain");
    }

    /// <summary><c>sipral_local_conference_info</c>.</summary>
    public SipralLocalConferenceInfo Info()
    {
        var info = SipralLocalConferenceInfo.Sized();
        SipralErrors.Call(
            () => NativeMethods.sipral_local_conference_info(Handle, ref info),
            "sipral_local_conference_info");
        return info;
    }

    /// <summary>Every member, this end first.</summary>
    public IReadOnlyList<SipralConferenceMember> Members()
    {
        var found = new List<SipralConferenceMember>();
        var count = Info().Members;
        for (nuint index = 0; index < count; index++)
        {
            var member = SipralLocalConferenceMember.Sized();
            var at = index;
            SipralErrors.Call(
                () => NativeMethods.sipral_local_conference_member_at(Handle, at, ref member),
                "sipral_local_conference_member_at");
            found.Add(new SipralConferenceMember(
                member.Member, member.Talking != 0, member.MutedInput != 0, member.MutedOutput != 0,
                member.GainInput, member.GainOutput));
        }
        return found;
    }

    /// <summary>Handles talking in the last tick, loudest first.</summary>
    public IReadOnlyList<ulong> Talkers()
    {
        var found = new List<ulong>();
        var count = Info().Talkers;
        for (nuint index = 0; index < count; index++)
        {
            if (NativeMethods.sipral_local_conference_talker_at(Handle, index, out var talker) != SipralStatus.Ok)
            {
                break;
            }
            found.Add(talker);
        }
        return found;
    }

    /// <summary><c>sipral_local_conference_record_start</c>: record the mix,
    /// mono, at the conference's rate unless
    /// <paramref name="sampleRate"/> is given.</summary>
    public void Record(string path, SipralRecordingFormat format = SipralRecordingFormat.Wav, uint sampleRate = 0)
    {
        var options = SipralRecordingOptions.Sized();
        options.Format = (uint)format;
        options.SampleRate = sampleRate;
        global::Sipral.Sipral.LocalConferenceRecordStart(Handle, path, in options);
    }

    /// <summary><c>sipral_local_conference_record_stop</c>: stop, and finish
    /// the file.</summary>
    public void StopRecording() => global::Sipral.Sipral.LocalConferenceRecordStop(Handle);

    /// <summary>Queues this end's 16-bit mono PCM at
    /// <see cref="SampleRate"/>, any length. Thread-safe.</summary>
    public void SendAudio(ReadOnlySpan<short> samples) => _toSend.Enqueue(samples.ToArray());

    private short[] NextChunk()
    {
        while (_pending.Count < FrameSamples && _toSend.TryDequeue(out var more))
        {
            _pending.AddRange(more);
        }
        var chunk = new short[FrameSamples];
        var taken = Math.Min(FrameSamples, _pending.Count);
        _pending.CopyTo(0, chunk, 0, taken);
        _pending.RemoveRange(0, taken);
        return chunk;
    }

    private void Run()
    {
        var speaker = new short[FrameSamples];
        var next = DateTime.UtcNow;
        while (!_closed.IsSet)
        {
            var mic = NextChunk();
            var status = NativeMethods.sipral_local_conference_tick(
                Handle, _stack.NowMs, mic, (nuint)mic.Length, speaker, (nuint)speaker.Length, out var written);
            if (status != SipralStatus.Ok)
            {
                return;
            }
            if (Local)
            {
                _frames.Writer.TryWrite(speaker.AsSpan(0, (int)written).ToArray());
            }
            SendWaiting();
            next += TimeSpan.FromMilliseconds(20);
            var remaining = next - DateTime.UtcNow;
            if (remaining > TimeSpan.Zero)
            {
                _closed.Wait(remaining);
            }
            else
            {
                next = DateTime.UtcNow;
            }
        }
    }

    private void SendWaiting()
    {
        while (true)
        {
            var packet = SipralMediaPacket.Sized();
            packet.Data = _packetData;
            packet.Capacity = PacketBytes;
            packet.Destination = _packetDestination;
            packet.DestinationCapacity = AddressBytes;
            var status = NativeMethods.sipral_local_conference_poll_transmit(Handle, out var call, ref packet);
            if (status != SipralStatus.Ok || packet.Len == 0)
            {
                return;
            }
            if (!_members.TryGetValue(call, out var member) || member.Media is not { } media)
            {
                continue;
            }
            var payload = new byte[(int)packet.Len];
            Marshal.Copy(_packetData, payload, 0, payload.Length);
            var destination = Marshal.PtrToStringUTF8(_packetDestination, (int)packet.DestinationLen);
            if (destination is not null)
            {
                media.SendTo(payload, destination);
            }
        }
    }

    /// <summary><c>sipral_local_conference_destroy</c>: members carry their
    /// own frames again and any recording is finished.</summary>
    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }
        _closed.Set();
        _thread?.Join(TimeSpan.FromSeconds(5));
        foreach (var call in _members.Values)
        {
            if (call.Media is { } media)
            {
                media.Pumped = _stack.AudioMode == SipralAudio.Device;
            }
        }
        _members.Clear();
        _frames.Writer.TryComplete();
        try
        {
            SipralErrors.Call(
                () => NativeMethods.sipral_local_conference_destroy(Handle),
                "sipral_local_conference_destroy");
        }
        finally
        {
            Marshal.FreeHGlobal(_packetData);
            Marshal.FreeHGlobal(_packetDestination);
        }
    }
}
