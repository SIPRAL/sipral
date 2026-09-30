// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

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
