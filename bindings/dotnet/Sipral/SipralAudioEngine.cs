// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

using System;
using System.Collections.Generic;
using System.Text;
using Sipral.Interop;

namespace Sipral;

/// <summary>One audio device. <see cref="Id"/> is stable across refreshes,
/// never reused and never zero. An unplugged device keeps its row with
/// <see cref="Present"/> false, so a saved selection still applies when it
/// returns.</summary>
public sealed record SipralDeviceInfo(
    uint Id,
    string Name,
    uint InputChannels,
    uint OutputChannels,
    bool DefaultInput,
    bool DefaultOutput,
    bool Present)
{
    /// <summary>Whether it captures.</summary>
    public bool IsMicrophone => InputChannels > 0;

    /// <summary>Whether it plays.</summary>
    public bool IsSpeaker => OutputChannels > 0;

    /// <summary>The name, for a list a person picks from.</summary>
    public override string ToString() => Name;
}

/// <summary>The engine's state (<c>sipral_audio_info</c>).
/// <see cref="SystemEchoCancellation"/>: whether the platform's processing
/// is active (on Windows only where the endpoint has its own; a virtual
/// cable has none). <see cref="RenderDelayMs"/>: the reported
/// speaker-to-microphone delay, passed to each call's canceller. Device ids
/// are <see langword="null"/> while a role is not open.</summary>
public sealed record SipralAudioSnapshot(
    bool Active,
    bool SystemEchoCancellation,
    ulong RenderDelayMs,
    uint MicrophoneRateHz,
    uint SpeakerRateHz,
    uint? Microphone,
    uint? Speaker,
    uint? Ringer);

/// <summary>
/// The library's audio engine in device mode: devices, gain, mute, meters,
/// activation and ringing. Every member is safe from any thread and never
/// waits on the poll. A platform call slower than <c>audioProbeMs</c> throws
/// with <see cref="SipralStatus.DeviceTimedOut"/>. In application mode every
/// member throws with <see cref="SipralStatus.WrongState"/>.
/// </summary>
public sealed class SipralAudioEngine
{
    // sipral_audio_set_gain's fixed-point unity
    private const double GainSteps = 256;

    private const double GainMost = 4;

    private readonly SipralStack _stack;

    internal SipralAudioEngine(SipralStack stack)
    {
        _stack = stack;
    }

    private ulong Handle => _stack.Handle;

    /// <summary>Asks the platform again and returns the list. The engine
    /// already refreshes on hot-plug (<see cref="SipralEventKind.AudioDevicesChanged"/>);
    /// this is for a settings screen opening, not for polling.</summary>
    public IReadOnlyList<SipralDeviceInfo> Refresh()
    {
        SipralErrors.Call(() => NativeMethods.sipral_audio_refresh(Handle, out _), "sipral_audio_refresh");
        return Devices();
    }

    /// <summary>Every device seen so far, present or not.</summary>
    public IReadOnlyList<SipralDeviceInfo> Devices()
    {
        nuint count = 0;
        SipralErrors.Call(() => NativeMethods.sipral_audio_device_count(Handle, out count), "sipral_audio_device_count");
        if (count == 0)
        {
            SipralErrors.Call(() => NativeMethods.sipral_audio_refresh(Handle, out count), "sipral_audio_refresh");
        }
        var devices = new List<SipralDeviceInfo>((int)count);
        for (nuint index = 0; index < count; index++)
        {
            devices.Add(DeviceAt(index));
        }
        return devices;
    }

    private SipralDeviceInfo DeviceAt(nuint index)
    {
        var device = SipralAudioDevice.Sized();
        var name = new sbyte[128];
        var status = NativeMethods.sipral_audio_device_at(Handle, index, ref device, name, (nuint)name.Length, out var needed);
        if (status == SipralStatus.BufferTooSmall)
        {
            name = new sbyte[(int)needed];
            device = SipralAudioDevice.Sized();
            status = NativeMethods.sipral_audio_device_at(Handle, index, ref device, name, (nuint)name.Length, out needed);
        }
        SipralErrors.Check(status, "sipral_audio_device_at");
        // `needed` counts the trailing NUL
        var bytes = new byte[(int)needed - 1];
        Buffer.BlockCopy(name, 0, bytes, 0, bytes.Length);
        return new SipralDeviceInfo(
            device.Id, Encoding.UTF8.GetString(bytes), device.InputChannels, device.OutputChannels,
            device.DefaultInput != 0, device.DefaultOutput != 0, device.Present != 0);
    }

    /// <summary>Puts <paramref name="role"/> on <paramref name="device"/>, or
    /// on the system route with <see langword="null"/>. Throws
    /// <see cref="SipralStatus.NoSuchDevice"/> for an unknown id,
    /// <see cref="SipralStatus.DeviceUnusable"/> for a device absent or
    /// lacking the role's direction, <see cref="SipralStatus.NotSupported"/>
    /// where the platform owns the route (iOS microphone and ringer). Open
    /// devices move at once, keeping gain and mute. An unplugged choice stays
    /// chosen: the system route stands in until it returns.</summary>
    public void Select(SipralAudioRole role, uint? device)
    {
        SipralErrors.Call(() => NativeMethods.sipral_audio_select(Handle, (uint)role, device ?? 0), "sipral_audio_select");
    }

    /// <summary>Same as <see cref="Select(SipralAudioRole, uint?)"/>.</summary>
    public void Select(SipralAudioRole role, SipralDeviceInfo? device) => Select(role, device?.Id);

    /// <summary>The selected and the running device of
    /// <paramref name="role"/> (<see langword="null"/>: system route, or not
    /// open). They differ while a chosen device is unplugged.</summary>
    public (uint? Selected, uint? Running) Selection(SipralAudioRole role)
    {
        uint selected = 0, running = 0;
        SipralErrors.Call(() => NativeMethods.sipral_audio_selection(Handle, (uint)role, out selected, out running), "sipral_audio_selection");
        return (selected == 0 ? null : selected, running == 0 ? null : running);
    }

    /// <summary>Sets <paramref name="direction"/>'s gain as a ratio (1 is
    /// unity, capped at 4). Applied to the audio, not the OS control, and
    /// kept across device changes.</summary>
    public void SetGain(SipralAudioDirection direction, double gain)
    {
        if (gain < 0 || double.IsNaN(gain))
        {
            throw new ArgumentOutOfRangeException(nameof(gain), gain, "a gain is a ratio of zero or more");
        }
        var steps = (uint)Math.Round(Math.Min(gain, GainMost) * GainSteps);
        SipralErrors.Call(() => NativeMethods.sipral_audio_set_gain(Handle, (uint)direction, steps), "sipral_audio_set_gain");
    }

    /// <summary><paramref name="direction"/>'s gain, as the ratio
    /// <see cref="SetGain(SipralAudioDirection, double)"/> takes.</summary>
    public double Gain(SipralAudioDirection direction)
    {
        uint steps = 0;
        SipralErrors.Call(() => NativeMethods.sipral_audio_gain(Handle, (uint)direction, out steps), "sipral_audio_gain");
        return steps / GainSteps;
    }

    /// <summary>The microphone gain: the input direction's.</summary>
    public double MicrophoneGain
    {
        get => Gain(SipralAudioDirection.Input);
        set => SetGain(SipralAudioDirection.Input, value);
    }

    /// <summary>The volume: the output direction's gain.</summary>
    public double Volume
    {
        get => Gain(SipralAudioDirection.Output);
        set => SetGain(SipralAudioDirection.Output, value);
    }

    /// <summary>Mutes or unmutes <paramref name="direction"/>, kept across
    /// device changes. A muted microphone still sends silence, not a
    /// gap.</summary>
    public void SetMuted(SipralAudioDirection direction, bool muted)
    {
        SipralErrors.Call(() => NativeMethods.sipral_audio_set_muted(Handle, (uint)direction, muted ? 1u : 0u), "sipral_audio_set_muted");
    }

    /// <summary>Whether <paramref name="direction"/> is muted.</summary>
    public bool Muted(SipralAudioDirection direction)
    {
        uint muted = 0;
        SipralErrors.Call(() => NativeMethods.sipral_audio_muted(Handle, (uint)direction, out muted), "sipral_audio_muted");
        return muted != 0;
    }

    /// <summary>Turns the platform's echo cancellation on or off at run
    /// time. Open devices are reopened at once, keeping gain and mute; calls
    /// keep their media through the short gap. <see cref="Info"/> says what
    /// the platform did.</summary>
    public void SetSystemEchoCancellation(bool on)
    {
        var toggle = (uint)(on ? SipralToggle.On : SipralToggle.Off);
        SipralErrors.Call(
            () => NativeMethods.sipral_audio_set_system_echo_cancellation(Handle, toggle),
            "sipral_audio_set_system_echo_cancellation");
    }

    /// <summary>Peak of the last 100 ms, 0 to 32767, smoothed for a meter
    /// bar. Cheap enough for a UI timer; zero while nothing is open.</summary>
    public uint Level(SipralAudioDirection direction)
    {
        uint peak = 0;
        SipralErrors.Call(() => NativeMethods.sipral_audio_level(Handle, (uint)direction, out peak), "sipral_audio_level");
        return peak;
    }

    /// <summary><see cref="Level(SipralAudioDirection)"/> in decibels below full scale:
    /// <see cref="double.NegativeInfinity"/> for silence.</summary>
    public double LevelDbfs(SipralAudioDirection direction)
    {
        var peak = Level(direction);
        return peak == 0 ? double.NegativeInfinity : 20 * Math.Log10(peak / 32767.0);
    }

    /// <summary>Sets one call's gain on top of the direction's. Kept through
    /// hold and local conferences. Throws with
    /// <see cref="SipralStatus.WrongState"/> outside the call's
    /// media.</summary>
    public void SetGain(Call call, SipralAudioDirection direction, double gain)
    {
        if (gain < 0 || double.IsNaN(gain))
        {
            throw new ArgumentOutOfRangeException(nameof(gain), gain, "a gain is a ratio of zero or more");
        }
        var steps = (uint)Math.Round(Math.Min(gain, GainMost) * GainSteps);
        SipralErrors.Call(
            () => NativeMethods.sipral_audio_call_set_gain(Handle, call.Handle, (uint)direction, steps),
            "sipral_audio_call_set_gain");
    }

    /// <summary><paramref name="call"/>'s own gain in
    /// <paramref name="direction"/>.</summary>
    public double Gain(Call call, SipralAudioDirection direction)
    {
        uint steps = 0;
        SipralErrors.Call(
            () => NativeMethods.sipral_audio_call_gain(Handle, call.Handle, (uint)direction, out steps),
            "sipral_audio_call_gain");
        return steps / GainSteps;
    }

    /// <summary>Mutes one call alone in <paramref name="direction"/>. Kept
    /// and refused as <see cref="SetGain(Call, SipralAudioDirection, double)"/>
    /// is.</summary>
    public void SetMuted(Call call, SipralAudioDirection direction, bool muted)
    {
        SipralErrors.Call(
            () => NativeMethods.sipral_audio_call_set_muted(Handle, call.Handle, (uint)direction, muted ? 1u : 0u),
            "sipral_audio_call_set_muted");
    }

    /// <summary>Whether <paramref name="call"/> is muted in
    /// <paramref name="direction"/>.</summary>
    public bool Muted(Call call, SipralAudioDirection direction)
    {
        uint muted = 0;
        SipralErrors.Call(
            () => NativeMethods.sipral_audio_call_muted(Handle, call.Handle, (uint)direction, out muted),
            "sipral_audio_call_muted");
        return muted != 0;
    }

    /// <summary><paramref name="call"/>'s own meter in
    /// <paramref name="direction"/>, 0 to 32767, after its own gain and
    /// mute.</summary>
    public uint Level(Call call, SipralAudioDirection direction)
    {
        uint peak = 0;
        SipralErrors.Call(
            () => NativeMethods.sipral_audio_call_level(Handle, call.Handle, (uint)direction, out peak),
            "sipral_audio_call_level");
        return peak;
    }

    /// <summary>Opens the devices now; the only way under
    /// <see cref="SipralAudioActivation.Manual"/>. If one direction fails it
    /// throws, but the engine stays active, silent in that direction.</summary>
    public void Activate()
    {
        SipralErrors.Call(() => NativeMethods.sipral_audio_activate(Handle), "sipral_audio_activate");
    }

    /// <summary>Closes the devices. Calls stay attached until the next
    /// <see cref="Activate"/>.</summary>
    public void Deactivate()
    {
        SipralErrors.Call(() => NativeMethods.sipral_audio_deactivate(Handle), "sipral_audio_deactivate");
    }

    /// <summary><c>sipral_audio_info</c>.</summary>
    public SipralAudioSnapshot Info()
    {
        var info = SipralAudioInfo.Sized();
        SipralErrors.Call(() => NativeMethods.sipral_audio_info(Handle, ref info), "sipral_audio_info");
        return new SipralAudioSnapshot(
            info.Active != 0, info.SystemEchoCancellation != 0, info.RenderDelayMs,
            info.MicrophoneRateHz, info.SpeakerRateHz,
            info.Microphone == 0 ? null : info.Microphone,
            info.Speaker == 0 ? null : info.Speaker,
            info.Ringer == 0 ? null : info.Ringer);
    }

    /// <summary>Plays 16-bit mono samples on the ringer (else the speaker)
    /// until <see cref="StopRinging"/>, or once when not
    /// <paramref name="looped"/>. Samples are copied. Under automatic
    /// activation this opens the devices.</summary>
    public void Ring(ReadOnlySpan<short> samples, uint sampleRateHz, bool looped = true)
    {
        var copy = samples.ToArray();
        SipralErrors.Call(
            () => NativeMethods.sipral_audio_ring(Handle, copy, (nuint)copy.Length, sampleRateHz, looped ? 1u : 0u),
            "sipral_audio_ring");
    }

    /// <summary>Stops the tone <see cref="Ring"/> started.</summary>
    public void StopRinging()
    {
        SipralErrors.Call(() => NativeMethods.sipral_audio_stop_ringing(Handle), "sipral_audio_stop_ringing");
    }
}
