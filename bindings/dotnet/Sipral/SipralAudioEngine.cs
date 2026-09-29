// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

using System;
using System.Collections.Generic;
using System.Text;
using Sipral.Interop;

namespace Sipral;

/// <summary>One audio device, as <c>sipral_audio_device_at</c> lists it.
/// <see cref="Id"/> is the engine's name for it: stable across refreshes,
/// never reused, never zero, and what
/// <see cref="SipralAudioEngine.Select(SipralAudioRole, uint?)"/> takes. A device that was unplugged keeps its row with
/// <see cref="Present"/> false, so a selection saved against it still names
/// something and comes back when it does.</summary>
public sealed record SipralDeviceInfo(
    uint Id,
    string Name,
    uint InputChannels,
    uint OutputChannels,
    bool DefaultInput,
    bool DefaultOutput,
    bool Present)
{
    /// <summary>Whether it captures: what the microphone role needs.</summary>
    public bool IsMicrophone => InputChannels > 0;

    /// <summary>Whether it plays: what the speaker and the ringer need.</summary>
    public bool IsSpeaker => OutputChannels > 0;

    /// <summary>The name, for a list a person picks from.</summary>
    public override string ToString() => Name;
}

/// <summary>What the engine is doing, as <c>sipral_audio_info</c> says.
/// <see cref="SystemEchoCancellation"/> is whether the platform's own
/// processing sits behind the microphone — the voice-processing unit on
/// Apple's platforms, a Windows communications stream (which cancels only
/// where the endpoint has processing of its own; a virtual cable has none) —
/// and <see cref="RenderDelayMs"/> the loudspeaker-to-microphone delay the
/// devices report, which the engine hands every call for a canceller
/// attached to it. The three device ids are <see langword="null"/> while
/// that role is not open.</summary>
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
/// <see cref="SipralStack.Audio"/>: the library's own audio engine, for a
/// stack in device mode — which device plays which role, how loud, what is
/// muted, the meter, when the devices are open, and what rings, over the
/// <c>sipral_audio_*</c> entry points (<c>docs/08-ffi.md</c>, "The built-in
/// audio engine"). Every member is safe from any thread, including a
/// window's own, and none waits on the stack's poll; a platform call that
/// does not answer within the stack's <c>audioProbeMs</c> throws with
/// <see cref="SipralStatus.DeviceTimedOut"/> instead of hanging the caller.
/// On a stack in application mode every member throws with
/// <see cref="SipralStatus.WrongState"/>.
/// </summary>
public sealed class SipralAudioEngine
{
    /// <summary><c>sipral_audio_set_gain</c>'s fixed-point unity: 256 steps
    /// is a ratio of one.</summary>
    private const double GainSteps = 256;

    /// <summary>The most a gain goes up to, four times unity.</summary>
    private const double GainMost = 4;

    private readonly SipralStack _stack;

    internal SipralAudioEngine(SipralStack stack)
    {
        _stack = stack;
    }

    private ulong Handle => _stack.Handle;

    // -- the list -----------------------------------------------------------

    /// <summary>Asks the platform again, and returns the list as it now is.
    /// The engine refreshes by itself when the platform announces a device
    /// arriving or leaving, and says so with
    /// <see cref="SipralEventKind.AudioDevicesChanged"/>; this is for a
    /// settings screen opening, not for polling.</summary>
    public IReadOnlyList<SipralDeviceInfo> Refresh()
    {
        SipralErrors.Call(() => NativeMethods.sipral_audio_refresh(Handle, out _), "sipral_audio_refresh");
        return Devices();
    }

    /// <summary>Every device the engine has seen, present or not, as last
    /// listed — asking the platform first when nothing has been listed
    /// yet.</summary>
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
        var bytes = new byte[(int)needed];
        Buffer.BlockCopy(name, 0, bytes, 0, bytes.Length);
        return new SipralDeviceInfo(
            device.Id, Encoding.UTF8.GetString(bytes), device.InputChannels, device.OutputChannels,
            device.DefaultInput != 0, device.DefaultOutput != 0, device.Present != 0);
    }

    // -- roles --------------------------------------------------------------

    /// <summary>Puts <paramref name="role"/> on <paramref name="device"/>, or
    /// back on the system's route with <see langword="null"/>.
    ///
    /// Refused before any platform call: <see cref="SipralStatus.NoSuchDevice"/>
    /// for an id the list never held, <see cref="SipralStatus.DeviceUnusable"/>
    /// for a device with no channels in the role's direction or one not
    /// plugged in, <see cref="SipralStatus.NotSupported"/> where the platform
    /// cannot put the role on a device of its own (macOS runs the microphone
    /// and the loudspeaker as one unit). While the devices are open the role
    /// moves at once, keeping its direction's gain and mute. A chosen device
    /// later unplugged stays the choice: the role runs on the system's route
    /// meanwhile and goes back when it returns.</summary>
    public void Select(SipralAudioRole role, uint? device)
    {
        SipralErrors.Call(() => NativeMethods.sipral_audio_select(Handle, (uint)role, device ?? 0), "sipral_audio_select");
    }

    /// <summary>Same as <see cref="Select(SipralAudioRole, uint?)"/>, for a
    /// device read off <see cref="Devices"/>.</summary>
    public void Select(SipralAudioRole role, SipralDeviceInfo? device) => Select(role, device?.Id);

    /// <summary>For <paramref name="role"/>: the id <see cref="Select(SipralAudioRole, uint?)"/>
    /// was given (<see langword="null"/> for the system's route) and the id
    /// of the device the role is open on (<see langword="null"/> while it is
    /// not open). They differ while a chosen device is unplugged.</summary>
    public (uint? Selected, uint? Running) Selection(SipralAudioRole role)
    {
        uint selected = 0, running = 0;
        SipralErrors.Call(() => NativeMethods.sipral_audio_selection(Handle, (uint)role, out selected, out running), "sipral_audio_selection");
        return (selected == 0 ? null : selected, running == 0 ? null : running);
    }

    // -- gain, mute and the meter ------------------------------------------

    /// <summary>Sets <paramref name="direction"/>'s gain as a ratio: 1 is
    /// unity, 0.5 halves, 2 doubles, anything above 4 is 4. The input gain
    /// is the microphone gain, the output gain the volume. Applied to the
    /// call's audio rather than to the operating system's control, and kept
    /// across every device change.</summary>
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
    /// <see cref="SetGain"/> takes.</summary>
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

    /// <summary>Mutes <paramref name="direction"/> or unmutes it, kept across
    /// every device change. A muted microphone still sends silence, so the
    /// far end hears a stream rather than a gap.</summary>
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

    /// <summary>The meter: the loudest sample of the last tenth of a second
    /// in <paramref name="direction"/>, 0 to 32767, held long enough that a
    /// bar drawn from it neither flickers nor sticks. Cheap enough for a
    /// window's timer; zero while nothing is open.</summary>
    public uint Level(SipralAudioDirection direction)
    {
        uint peak = 0;
        SipralErrors.Call(() => NativeMethods.sipral_audio_level(Handle, (uint)direction, out peak), "sipral_audio_level");
        return peak;
    }

    /// <summary><see cref="Level"/> in decibels below full scale:
    /// <see cref="double.NegativeInfinity"/> for silence.</summary>
    public double LevelDbfs(SipralAudioDirection direction)
    {
        var peak = Level(direction);
        return peak == 0 ? double.NegativeInfinity : 20 * Math.Log10(peak / 32767.0);
    }

    // -- activation ---------------------------------------------------------

    /// <summary>Opens the devices and starts the pump now, whatever the calls
    /// are doing. Under <see cref="SipralAudioActivation.Manual"/> this is the
    /// only thing that does; under automatic activation it opens them early.
    /// A direction that could not be opened throws, and the engine is active
    /// all the same, silent in that direction (<see cref="Info"/> says
    /// which).</summary>
    public void Activate()
    {
        SipralErrors.Call(() => NativeMethods.sipral_audio_activate(Handle), "sipral_audio_activate");
    }

    /// <summary>Closes the devices and stops the pump. The calls stay
    /// attached and get their audio back on the next
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

    // -- the ring -----------------------------------------------------------

    /// <summary>Plays a tone — 16-bit mono samples at
    /// <paramref name="sampleRateHz"/> — on the ringer's device (the
    /// loudspeaker when the ringer is on none of its own) until
    /// <see cref="StopRinging"/>, or once through when
    /// <paramref name="looped"/> is false. The samples are copied. Under
    /// automatic activation a ring opens the devices.</summary>
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
