// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

using System;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Sipral;
using Xunit;

namespace Sipral.Tests;

/// <summary>
/// The library's own audio engine through <c>new SipralStack(audio: …)</c>
/// and <see cref="SipralStack.Audio"/> — the .NET counterpart of
/// <c>bindings/python/tests/test_audio.py</c>. Everything that touches a
/// device stays on <see cref="SipralAudioActivation.Manual"/>, so no
/// microphone is ever opened on the machine the gate runs on; where the
/// build has no backend, the other half of the contract is checked instead.
/// <see cref="ACallOnRealDevicesCarriesAudioBothWays"/> is the one that opens
/// them, and runs only where <c>SIPRAL_AUDIO_DEVICES</c> says the machine has
/// devices a test may use (the Windows lab's virtual cable).
/// </summary>
public sealed class AudioEngineTests
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);
    private static readonly bool HasDevices = SipralStack.HasFeature(global::Sipral.Sipral.FeatureAudioDevice);

    /// <summary>The virtual loopback device a test that opens the devices
    /// plays and records on when the machine has one: it plays nowhere and
    /// hands back what it was given, so that a run never sounds through the
    /// machine's loudspeaker. Without it the test runs on the system's route,
    /// as it always did.</summary>
    internal const string QuietDeviceName = "BlackHole 2ch";

    /// <summary>The device <paramref name="role"/> goes on in a test that
    /// opens the devices: the quiet one when the machine has it and it serves
    /// the role, and null otherwise.</summary>
    internal static SipralDeviceInfo? QuietDevice(
        System.Collections.Generic.IEnumerable<SipralDeviceInfo> devices, SipralAudioRole role) =>
        devices.FirstOrDefault(device => device.Present && device.Name == QuietDeviceName
            && (role == SipralAudioRole.Microphone ? device.IsMicrophone : device.IsSpeaker));

    [Fact]
    public void TheQuietDeviceIsChosenWhereTheMachineHasItAndNothingNewOtherwise()
    {
        static SipralDeviceInfo Device(uint id, string name, uint inputs, uint outputs, bool present = true) =>
            new(id, name, inputs, outputs, false, id == 1, present);
        var laptop = new[] { Device(1, "MacBook Air Speakers", 0, 2), Device(2, "MacBook Air Microphone", 1, 0) };
        foreach (var role in new[] { SipralAudioRole.Speaker, SipralAudioRole.Microphone, SipralAudioRole.Ringer })
        {
            Assert.Null(QuietDevice(laptop, role));
            Assert.Equal(3u, QuietDevice(laptop.Append(Device(3, QuietDeviceName, 2, 2)), role)?.Id);
        }
        Assert.Null(QuietDevice(laptop.Append(Device(3, QuietDeviceName, 2, 2, present: false)), SipralAudioRole.Speaker));
        Assert.Null(QuietDevice(laptop.Append(Device(4, "BlackHole 16ch", 16, 16)), SipralAudioRole.Speaker));
    }

    [Fact]
    public void TheDefaultIsTheDevicesWhereverTheBuildCanOpenThem()
    {
        using var stack = new SipralStack();
        Assert.Equal(HasDevices ? SipralAudio.Device : SipralAudio.Application, stack.AudioMode);
    }

    [Fact]
    public void ApplicationModeIsKeptWhenAskedFor()
    {
        using var stack = new SipralStack(audio: SipralAudio.Application);
        Assert.Equal(SipralAudio.Application, stack.AudioMode);
        var refused = Assert.Throws<SipralException>(() => stack.Audio.Devices());
        Assert.Equal(SipralStatus.WrongState, refused.Status);
        // the library counts the trailing NUL in the length it reports; the
        // message is the text before it, and ends in the library's words
        Assert.DoesNotContain('\0', refused.Message);
        Assert.EndsWith("pumps its own frames", refused.Message);
    }

    [Fact]
    public void DeviceModeOnABuildWithoutABackendIsRefused()
    {
        if (HasDevices)
        {
            return;
        }
        var refused = Assert.Throws<SipralException>(() => new SipralStack(audio: SipralAudio.Device));
        Assert.Equal(SipralStatus.NotSupported, refused.Status);
    }

    private static SipralStack Manual() =>
        new(audio: SipralAudio.Device, audioActivation: SipralAudioActivation.Manual);

    /// <summary>ABI 1.1: the platform's echo cancellation switched on a
    /// running stack is refused in application mode, and in device mode, the
    /// devices closed, opens nothing and is read back from the
    /// settings.</summary>
    [Fact]
    public void TheEchoCancellationSwitchIsReadBackAndRefusedInApplicationMode()
    {
        using (var pumped = new SipralStack(audio: SipralAudio.Application))
        {
            var refused = Assert.Throws<SipralException>(() => pumped.Audio.SetSystemEchoCancellation(false));
            Assert.Equal(SipralStatus.WrongState, refused.Status);
            Assert.True(pumped.Settings().SystemEchoCancellation);
        }
        if (!HasDevices)
        {
            return;
        }
        using var stack = Manual();
        stack.Audio.SetSystemEchoCancellation(false);
        Assert.False(stack.Settings().SystemEchoCancellation);
        Assert.False(stack.Audio.Info().Active);
        stack.Audio.SetSystemEchoCancellation(true);
        Assert.True(stack.Settings().SystemEchoCancellation);
    }

    /// <summary>The switch on open devices reopens them where they were,
    /// with the gain and the mute, and <see cref="SipralAudioEngine.Info"/>
    /// says what the platform did. Opt-in, as it opens the machine's devices:
    /// <c>SIPRAL_AUDIO_DEVICES=1</c>.</summary>
    [Fact]
    public void TheEchoCancellationSwitchReopensTheOpenDevices()
    {
        if (!HasDevices || Environment.GetEnvironmentVariable("SIPRAL_AUDIO_DEVICES") != "1")
        {
            return;
        }
        using var stack = Manual();
        var devices = stack.Audio.Refresh();
        foreach (var role in new[] { SipralAudioRole.Speaker, SipralAudioRole.Microphone })
        {
            if (QuietDevice(devices, role) is { } quiet)
            {
                stack.Audio.Select(role, quiet);
            }
        }
        stack.Audio.SetMuted(SipralAudioDirection.Output, true);
        stack.Audio.SetGain(SipralAudioDirection.Input, 0.5);
        stack.Audio.Activate();
        var before = stack.Audio.Info();
        stack.Audio.SetSystemEchoCancellation(false);
        var off = stack.Audio.Info();
        Assert.True(off.Active);
        Assert.False(off.SystemEchoCancellation);
        Assert.Equal(before.Speaker, off.Speaker);
        Assert.Equal(before.Microphone, off.Microphone);
        Assert.True(stack.Audio.Muted(SipralAudioDirection.Output));
        Assert.Equal(0.5, stack.Audio.Gain(SipralAudioDirection.Input));
        stack.Audio.SetSystemEchoCancellation(true);
        Assert.True(stack.Settings().SystemEchoCancellation);
        stack.Audio.Deactivate();
    }

    [Fact]
    public void EveryDeviceIsListedWithAnIdThatSurvivesARefresh()
    {
        if (!HasDevices)
        {
            return;
        }
        using var stack = Manual();
        var listed = stack.Audio.Devices();
        Assert.NotEmpty(listed);
        Assert.All(listed, device =>
        {
            Assert.NotEqual(0u, device.Id);
            Assert.False(string.IsNullOrEmpty(device.Name));
            // the library counts the name's trailing NUL, which is not the name's
            Assert.DoesNotContain('\0', device.Name);
            Assert.True(device.IsMicrophone || device.IsSpeaker, device.Name);
        });
        // keyed by id: two devices may share a name (a dock's input and its
        // output are both called after the dock), never an id
        var again = stack.Audio.Refresh();
        Assert.Equal(
            listed.ToDictionary(d => d.Id, d => d.Name),
            again.Where(d => d.Present).ToDictionary(d => d.Id, d => d.Name));
    }

    [Fact]
    public void TheSpeakerIsChosenOnItsOwnAndReadBack()
    {
        if (!HasDevices)
        {
            return;
        }
        using var stack = Manual();
        var speaker = stack.Audio.Devices().First(d => d.IsSpeaker);
        stack.Audio.Select(SipralAudioRole.Speaker, speaker);
        Assert.Equal((speaker.Id, (uint?)null), stack.Audio.Selection(SipralAudioRole.Speaker));
        stack.Audio.Select(SipralAudioRole.Speaker, (uint?)null);
        Assert.Equal(((uint?)null, (uint?)null), stack.Audio.Selection(SipralAudioRole.Speaker));
    }

    [Fact]
    public void AChoiceTheDeviceCannotServeIsRefusedBeforeThePlatform()
    {
        if (!HasDevices)
        {
            return;
        }
        using var stack = Manual();
        var unknown = Assert.Throws<SipralException>(() => stack.Audio.Select(SipralAudioRole.Speaker, 0xFFFFu));
        Assert.Equal(SipralStatus.NoSuchDevice, unknown.Status);
        var microphoneOnly = stack.Audio.Devices().FirstOrDefault(d => d.IsMicrophone && !d.IsSpeaker);
        if (microphoneOnly is not null)
        {
            var unusable = Assert.Throws<SipralException>(() => stack.Audio.Select(SipralAudioRole.Speaker, microphoneOnly));
            Assert.Equal(SipralStatus.DeviceUnusable, unusable.Status);
        }
        Assert.Equal(((uint?)null, (uint?)null), stack.Audio.Selection(SipralAudioRole.Speaker));
    }

    [Fact]
    public void TheMicrophoneAndTheRingerAreRolesOfTheirOwn()
    {
        if (!HasDevices)
        {
            return;
        }
        using var stack = Manual();
        var microphone = stack.Audio.Devices().First(d => d.IsMicrophone);
        var speaker = stack.Audio.Devices().First(d => d.IsSpeaker);
        foreach (var (role, device) in new[] { (SipralAudioRole.Microphone, microphone), (SipralAudioRole.Ringer, speaker) })
        {
            try
            {
                stack.Audio.Select(role, device);
            }
            catch (SipralException refused)
            {
                // a platform whose route is the audio session's (iOS)
                Assert.Equal(SipralStatus.NotSupported, refused.Status);
                continue;
            }
            Assert.Equal((device.Id, (uint?)null), stack.Audio.Selection(role));
        }
    }

    [Fact]
    public void GainAndMuteBelongToTheDirection()
    {
        if (!HasDevices)
        {
            return;
        }
        using var stack = Manual();
        var audio = stack.Audio;
        Assert.Equal(1.0, audio.MicrophoneGain);
        audio.MicrophoneGain = 0.5;
        audio.Volume = 2.0;
        Assert.Equal(0.5, audio.Gain(SipralAudioDirection.Input));
        Assert.Equal(2.0, audio.Gain(SipralAudioDirection.Output));
        audio.SetGain(SipralAudioDirection.Output, 10.0);
        Assert.Equal(4.0, audio.Volume);
        Assert.Throws<ArgumentOutOfRangeException>(() => audio.SetGain(SipralAudioDirection.Input, -1));

        Assert.False(audio.Muted(SipralAudioDirection.Input));
        audio.SetMuted(SipralAudioDirection.Input, true);
        Assert.True(audio.Muted(SipralAudioDirection.Input));
        Assert.False(audio.Muted(SipralAudioDirection.Output));
    }

    [Fact]
    public void NothingIsOpenUntilActivated()
    {
        if (!HasDevices)
        {
            return;
        }
        using var stack = Manual();
        var info = stack.Audio.Info();
        Assert.False(info.Active);
        Assert.Null(info.Microphone);
        Assert.Null(info.Speaker);
        Assert.Equal(0u, stack.Audio.Level(SipralAudioDirection.Input));
        Assert.Equal(double.NegativeInfinity, stack.Audio.LevelDbfs(SipralAudioDirection.Output));
        stack.Audio.StopRinging();
        stack.Audio.Deactivate();
        Assert.False(stack.Audio.Info().Active);
    }

    /// <summary><c>audio_transmit_callback</c>, the way the engine calls it:
    /// a packet naming a call and a destination leaves from that call's own
    /// media socket. The record is built here, so this runs everywhere and
    /// opens nothing.</summary>
    [Fact]
    public async Task APacketTheEngineEncodedGoesOutOnTheCallsSocket()
    {
        using var alice = new SipralStack(audio: SipralAudio.Application);
        using var bob = new SipralStack(audio: SipralAudio.Application);
        using var far = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        far.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        far.ReceiveTimeout = 3000;
        var account = alice.AddAccount("sip:alice@sipral.invalid", registrarAddress: bob.BindAddress);
        bob.AddAccount("sip:bob@sipral.invalid", registrarAddress: alice.BindAddress);
        var call = alice.PlaceCall(account, $"sip:bob@{bob.BindAddress}");
        try
        {
            var payload = Encoding.ASCII.GetBytes("\u0080\0rtp-shaped");
            var destination = Encoding.UTF8.GetBytes(SipralStack.FormatAddress((IPEndPoint)far.LocalEndPoint!));
            var payloadMemory = Marshal.AllocHGlobal(payload.Length);
            var destinationMemory = Marshal.AllocHGlobal(destination.Length);
            var record = Marshal.AllocHGlobal(Marshal.SizeOf<SipralAudioTransmit>());
            try
            {
                Marshal.Copy(payload, 0, payloadMemory, payload.Length);
                Marshal.Copy(destination, 0, destinationMemory, destination.Length);
                var transmit = new SipralAudioTransmit
                {
                    Size = (nuint)Marshal.SizeOf<SipralAudioTransmit>(),
                    Call = call.Handle,
                    Protocol = (uint)SipralTransport.Udp,
                    Destination = destinationMemory,
                    DestinationLen = (nuint)destination.Length,
                    Payload = payloadMemory,
                    PayloadLen = (nuint)payload.Length,
                };
                Marshal.StructureToPtr(transmit, record, false);
                alice.OnAudioTransmit(record, IntPtr.Zero);

                var buffer = new byte[2048];
                EndPoint sender = new IPEndPoint(IPAddress.Any, 0);
                // a deadline, so that a packet that never comes fails the
                // test instead of hanging it
                far.ReceiveTimeout = 5_000;
                var read = await Task.Run(() => far.ReceiveFrom(buffer, ref sender));
                Assert.Equal(payload, buffer[..read]);
                Assert.Equal(call.MediaAddress, SipralStack.FormatAddress((IPEndPoint)sender));

                // a call this stack does not know is nobody's packet
                transmit.Call = call.Handle + 1000;
                Marshal.StructureToPtr(transmit, record, false);
                alice.OnAudioTransmit(record, IntPtr.Zero);
                far.ReceiveTimeout = 300;
                Assert.Throws<SocketException>(() => far.ReceiveFrom(buffer, ref sender));
            }
            finally
            {
                Marshal.FreeHGlobal(payloadMemory);
                Marshal.FreeHGlobal(destinationMemory);
                Marshal.FreeHGlobal(record);
            }
        }
        finally
        {
            call.Close();
        }
    }

    [Fact]
    public async Task ACallInDeviceModeIsTheEnginesToPump()
    {
        if (!HasDevices)
        {
            return;
        }
        using var alice = Manual();
        using var bob = new SipralStack(audio: SipralAudio.Application);
        var (call, answered) = await ConnectAsync(alice, bob);
        try
        {
            Assert.True(call.Media!.Pumped);
            Assert.False(answered.Media!.Pumped);
            Assert.Throws<InvalidOperationException>(() => call.Media.SendAudio(new short[160]));
            var frames = 0;
            call.Media.FrameDecoded += _ => Interlocked.Increment(ref frames);
            answered.Media.SendAudio(Enumerable.Repeat((short)4096, 1600).ToArray());
            await Task.Delay(300);
            Assert.Equal(0, frames);
            Assert.False(alice.Audio.Info().Active, "parked until activated: nothing is open");
        }
        finally
        {
            answered.Close();
            call.Close();
        }
    }

    /// <summary>A call's own gain and mute: held by the engine from the
    /// moment its media starts — the devices left closed under manual
    /// activation — to the moment it ends, beside the stack's own, and
    /// refused outside that and in application mode.</summary>
    [Fact]
    public async Task ACallsOwnGainAndMuteLastFromItsMediaToItsEnd()
    {
        if (!HasDevices)
        {
            return;
        }
        using var alice = Manual();
        using var bob = new SipralStack(audio: SipralAudio.Application);
        var account = alice.AddAccount("sip:alice@sipral.invalid", registrarAddress: bob.BindAddress);
        bob.AddAccount("sip:bob@sipral.invalid", registrarAddress: alice.BindAddress);
        var call = alice.PlaceCall(account, $"sip:bob@{bob.BindAddress}");
        var early = Assert.Throws<SipralException>(() => alice.Audio.SetGain(call, SipralAudioDirection.Output, 0.5));
        Assert.Equal(SipralStatus.WrongState, early.Status);
        using var cts = new CancellationTokenSource(Timeout);
        Call? answered = null;
        await foreach (var e in bob.Events.WithCancellation(cts.Token))
        {
            if (e.Kind == SipralEventKind.IncomingCall)
            {
                answered = bob.AnswerCall(e);
                break;
            }
        }
        Assert.NotNull(answered);
        try
        {
            Assert.NotNull(await call.WaitForMediaAsync(cts.Token));
            var audio = alice.Audio;
            audio.SetGain(call, SipralAudioDirection.Output, 0.5);
            audio.SetMuted(call, SipralAudioDirection.Input, true);
            Assert.Equal(0.5, audio.Gain(call, SipralAudioDirection.Output));
            Assert.Equal(1.0, audio.Gain(call, SipralAudioDirection.Input));
            Assert.True(audio.Muted(call, SipralAudioDirection.Input));
            Assert.False(audio.Muted(call, SipralAudioDirection.Output));
            Assert.False(audio.Muted(SipralAudioDirection.Input), "the stack's own mute is another");
            Assert.Equal(0u, audio.Level(call, SipralAudioDirection.Output));
            var application = Assert.Throws<SipralException>(
                () => bob.Audio.SetMuted(answered!, SipralAudioDirection.Input, true));
            Assert.Equal(SipralStatus.WrongState, application.Status);

            call.Hangup();
            var deadline = DateTime.UtcNow + Timeout;
            SipralException? after = null;
            while (after is null && DateTime.UtcNow < deadline)
            {
                try
                {
                    audio.Gain(call, SipralAudioDirection.Output);
                    await Task.Delay(20);
                }
                catch (SipralException ended)
                {
                    after = ended;
                }
            }
            Assert.Equal(SipralStatus.WrongState, after?.Status);
        }
        finally
        {
            answered!.Close();
            call.Close();
        }
    }

    /// <summary>A call whose one end runs on the machine's real devices:
    /// activated, the engine opens them, the far end's audio reaches the
    /// loudspeaker's meter and the microphone's packets reach the far end.
    /// Opt-in: <c>SIPRAL_AUDIO_DEVICES=1</c>, on a machine whose devices a
    /// test may open (the Windows lab's virtual cable).</summary>
    [Fact]
    public async Task ACallOnRealDevicesCarriesAudioBothWays()
    {
        if (!HasDevices || Environment.GetEnvironmentVariable("SIPRAL_AUDIO_DEVICES") != "1")
        {
            return;
        }
        using var alice = new SipralStack(audio: SipralAudio.Device);
        var devices = alice.Audio!.Refresh();
        foreach (var role in new[] { SipralAudioRole.Speaker, SipralAudioRole.Microphone, SipralAudioRole.Ringer })
        {
            if (QuietDevice(devices, role) is { } quiet)
            {
                alice.Audio.Select(role, quiet);
            }
        }
        using var bob = new SipralStack(audio: SipralAudio.Application);
        var (call, answered) = await ConnectAsync(alice, bob);
        try
        {
            var heard = 0;
            answered.Media!.FrameDecoded += _ => Interlocked.Increment(ref heard);
            var tone = Enumerable.Range(0, 8000).Select(i => (short)(8000 * Math.Sin(2 * Math.PI * 440 * i / 8000.0))).ToArray();
            uint loudest = 0;
            for (var round = 0; round < 30; round++)
            {
                answered.Media.SendAudio(tone.AsSpan(0, 1600));
                await Task.Delay(100);
                loudest = Math.Max(loudest, alice.Audio.Level(SipralAudioDirection.Output));
            }
            var info = alice.Audio.Info();
            Assert.True(info.Active);
            Assert.NotNull(info.Speaker);
            Assert.True(loudest > 1000, $"the loudspeaker's meter read {loudest}");
            Assert.True(heard > 50, $"the far end decoded {heard} frames from the microphone");
            var stats = call.Media!.Statistics();
            Assert.True(stats.PacketsSent > 50, $"{stats.PacketsSent} packets left through the transmit callback");
        }
        finally
        {
            answered.Close();
            call.Close();
        }
    }

    private static async Task<(Call Call, Call Answered)> ConnectAsync(SipralStack alice, SipralStack bob)
    {
        var account = alice.AddAccount("sip:alice@sipral.invalid", registrarAddress: bob.BindAddress);
        bob.AddAccount("sip:bob@sipral.invalid", registrarAddress: alice.BindAddress);
        var call = alice.PlaceCall(account, $"sip:bob@{bob.BindAddress}");
        using var cts = new CancellationTokenSource(Timeout);
        Call? answered = null;
        await foreach (var e in bob.Events.WithCancellation(cts.Token))
        {
            if (e.Kind == SipralEventKind.IncomingCall)
            {
                answered = bob.AnswerCall(e);
                break;
            }
        }
        Assert.NotNull(answered);
        Assert.NotNull(await call.WaitForMediaAsync(cts.Token));
        Assert.NotNull(await answered!.WaitForMediaAsync(cts.Token));
        return (call, answered);
    }
}
