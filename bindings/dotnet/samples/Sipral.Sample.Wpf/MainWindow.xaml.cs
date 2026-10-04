// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using Sipral;

// A sibling of, not nested under, the `Sipral` namespace: that namespace
// also holds a type literally named `Sipral` (bindings/dotnet/Sipral's own
// static entry-point class), and an unqualified two-segment name starting
// with `Sipral.` written from inside a namespace nested under it resolves
// to that type before it resolves to further namespace nesting -- which is
// exactly what WPF's own generated code does, unqualified. Nesting under
// `Sipral` here would make every generated reference to this window fail
// with "the type name '...' does not exist in the type 'Sipral'".
namespace SipralSample.Wpf;

/// <summary>
/// A softphone window with no audio code of its own: the stack is created in
/// device mode (the default on Windows), so the library opens the machine's
/// microphone and loudspeaker and pumps every call through them. What is left
/// here is what a person decides — which device does what, how loud, what is
/// muted, whom to call — and what they are shown: the devices as Windows
/// lists them, the caller as the network asserted them, a meter per
/// direction, and the echo return loss those two meters read while the far
/// end is talking.
/// </summary>
public partial class MainWindow : Window
{
    /// <summary>A meter reading the loudspeaker has to reach before its
    /// echo is worth measuring: about 30 dB below full scale.</summary>
    private const uint Talking = 1000;

    private readonly SipralStack _stack;
    /// <summary>This machine's address on its default route: where the
    /// stack listens, and what goes in the Contact and the SDP.</summary>
    private readonly string _host;
    private readonly DispatcherTimer _meters;
    private Account? _account;
    private Call? _call;
    private SipralEventArgs? _ringing;
    private bool _filling;
    private double _echoSum;
    private int _echoReadings;

    public MainWindow()
    {
        InitializeComponent();
        // RFC 5737 TEST-NET-3: never dialled, only asked which route it takes
        _host = RouteTo("203.0.113.1:80");
        _stack = new SipralStack(bindHost: _host);
        // Fired on the stack's own poll thread (docs/08-ffi.md, "Events
        // arrive on one callback"); WPF controls may only be touched from
        // the dispatcher thread that owns them, so every event crosses back
        // onto it before touching a control.
        _stack.EventReceived += (_, e) => Dispatcher.BeginInvoke(() => OnEvent(e));
        AudioModeText.Text = _stack.AudioMode == SipralAudio.Device
            ? "The library runs the devices."
            : "This build cannot open devices here: calls carry silence.";
        FillDevices();
        _meters = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(100) };
        _meters.Tick += (_, _) => ReadMeters();
        _meters.Start();
    }

    private void Log(string line) => EventsList.Items.Insert(0, $"{DateTime.Now:HH:mm:ss} {line}");

    // -- devices ------------------------------------------------------------

    /// <summary>The device lists as the engine has them, each led by the
    /// system's own route, with the current choice selected.</summary>
    private void FillDevices()
    {
        if (_stack.AudioMode != SipralAudio.Device)
        {
            return;
        }
        _filling = true;
        try
        {
            var devices = _stack.Audio.Refresh().Where(d => d.Present).ToList();
            Fill(MicrophoneBox, devices.Where(d => d.IsMicrophone), SipralAudioRole.Microphone);
            Fill(SpeakerBox, devices.Where(d => d.IsSpeaker), SipralAudioRole.Speaker);
            Fill(RingerBox, devices.Where(d => d.IsSpeaker), SipralAudioRole.Ringer);
        }
        catch (SipralException ex)
        {
            Log($"devices: {ex.Message}");
        }
        finally
        {
            _filling = false;
        }
    }

    private void Fill(ComboBox box, IEnumerable<SipralDeviceInfo> devices, SipralAudioRole role)
    {
        box.Items.Clear();
        box.Items.Add("System default");
        foreach (var device in devices)
        {
            box.Items.Add(device);
        }
        var (selected, _) = _stack.Audio.Selection(role);
        box.SelectedItem = box.Items.OfType<SipralDeviceInfo>().FirstOrDefault(d => d.Id == selected)
            ?? box.Items[0];
    }

    private void OnDeviceChosen(object sender, SelectionChangedEventArgs e)
    {
        if (_filling || sender is not ComboBox box)
        {
            return;
        }
        var role = box == MicrophoneBox ? SipralAudioRole.Microphone
            : box == SpeakerBox ? SipralAudioRole.Speaker
            : SipralAudioRole.Ringer;
        try
        {
            _stack.Audio.Select(role, box.SelectedItem as SipralDeviceInfo);
            Log($"{role} on {box.SelectedItem}");
        }
        catch (SipralException ex)
        {
            Log($"{role}: {ex.Message}");
        }
    }

    private void OnGainChanged(object sender, RoutedPropertyChangedEventArgs<double> e)
    {
        if (_stack is null || _stack.AudioMode != SipralAudio.Device)
        {
            return;
        }
        if (sender == MicrophoneGainSlider)
        {
            _stack.Audio.MicrophoneGain = e.NewValue;
        }
        else
        {
            _stack.Audio.Volume = e.NewValue;
        }
    }

    private void OnMuteClick(object sender, RoutedEventArgs e)
    {
        if (_stack.AudioMode != SipralAudio.Device)
        {
            return;
        }
        _stack.Audio.SetMuted(SipralAudioDirection.Input, MicrophoneMutedBox.IsChecked == true);
        _stack.Audio.SetMuted(SipralAudioDirection.Output, SpeakerMutedBox.IsChecked == true);
    }

    /// <summary>The two meters, and — while the far end is loud enough to be
    /// heard — how far below the loudspeaker its echo in the microphone
    /// is.</summary>
    private void ReadMeters()
    {
        if (_stack.AudioMode != SipralAudio.Device)
        {
            return;
        }
        uint heard, said;
        try
        {
            heard = _stack.Audio.Level(SipralAudioDirection.Output);
            said = _stack.Audio.Level(SipralAudioDirection.Input);
        }
        catch (SipralException)
        {
            return;
        }
        SpeakerMeter.Value = heard;
        MicrophoneMeter.Value = said;
        if (_call is not { Ended: false, Media: { } media })
        {
            return;
        }
        if (heard >= Talking)
        {
            _echoSum += 20 * Math.Log10(heard / (double)Math.Max(said, 1u));
            _echoReadings++;
        }
        var info = _stack.Audio.Info();
        var sent = "";
        try
        {
            var stats = media.Statistics();
            sent = $"; {stats.PacketsSent} packets sent, {stats.PacketsReceived} received";
        }
        catch (SipralException)
        {
            // the call's media is going away under this tick
        }
        var echo = _echoReadings == 0
            ? "Echo return loss: waiting for the far end to talk"
            : $"Echo return loss: {_echoSum / _echoReadings:0.0} dB over {_echoReadings} readings";
        EchoText.Text =
            $"{echo} (system echo cancellation {(info.SystemEchoCancellation ? "on" : "off")}, " +
            $"render delay {info.RenderDelayMs} ms{sent})";
    }

    // -- events -------------------------------------------------------------

    private void OnEvent(SipralEventArgs e)
    {
        switch (e.Kind)
        {
            case SipralEventKind.AudioDevicesChanged when e.Audio is { } audio:
                Log($"audio: {audio.Change} ({audio.Origin})");
                // a device arriving or leaving; a change the engine made is
                // what was asked for, and choosing again on it would loop
                if (audio.Origin == SipralAudioOrigin.System)
                {
                    FillDevices();
                }
                return;
            case SipralEventKind.IncomingCall when e.CallInfo is { } info:
                _ringing = e;
                AnswerButton.IsEnabled = true;
                var who = info.Identity.AssertedDisplay ?? info.Identity.AssertedUri ?? info.FromUri;
                CallerText.Text = $"Call from {who}{(info.Identity.Trusted ? "" : " (not verified)")}";
                break;
            case SipralEventKind.CallEnded when e.CallInfo is { } ended:
                if (_ringing?.Call == e.Call)
                {
                    _ringing = null;
                    AnswerButton.IsEnabled = false;
                }
                CallerText.Text = ended.Cause is { } cause
                    ? $"Ended: {cause.Text ?? $"SIP {cause.Sip}, Q.850 {cause.Q850}"}"
                    : "Ended";
                break;
        }
        Log(e.KindName);
    }

    // -- signalling ---------------------------------------------------------

    private void OnRegisterClick(object sender, RoutedEventArgs e)
    {
        try
        {
            var registrarAddress = RegistrarAddressBox.Text;
            _account ??= _stack.AddAccount(
                AorBox.Text,
                registrarAddress: registrarAddress,
                registrar: string.IsNullOrWhiteSpace(RegistrarBox.Text) ? null : RegistrarBox.Text,
                authUser: string.IsNullOrWhiteSpace(AuthUserBox.Text) ? null : AuthUserBox.Text,
                authPassword: string.IsNullOrWhiteSpace(AuthPasswordBox.Password) ? null : AuthPasswordBox.Password,
                trustedPeers: new[] { SipralStack.ParseAddress(registrarAddress).Host });
            if (!string.IsNullOrWhiteSpace(RegistrarBox.Text))
            {
                _account.Register();
                Log("registering...");
            }
        }
        catch (SipralException ex)
        {
            Log($"register failed: {ex.Message}");
        }
    }

    private async void OnCallClick(object sender, RoutedEventArgs e)
    {
        if (_account is null)
        {
            Log("add the account first (Register)");
            return;
        }
        try
        {
            _call = _stack.PlaceCall(_account, TargetBox.Text, mediaHost: _host);
            await Connected(_call);
        }
        catch (SipralException ex)
        {
            Log($"call failed: {ex.Message}");
        }
    }

    private async void OnAnswerClick(object sender, RoutedEventArgs e)
    {
        if (_ringing is not { } ringing)
        {
            return;
        }
        _ringing = null;
        AnswerButton.IsEnabled = false;
        try
        {
            _call = _stack.AnswerCall(ringing, mediaHost: _host);
            await Connected(_call);
        }
        catch (SipralException ex)
        {
            Log($"answer failed: {ex.Message}");
        }
    }

    private async Task Connected(Call call)
    {
        _echoSum = 0;
        _echoReadings = 0;
        EchoText.Text = "";
        Log("calling...");
        var media = await call.WaitForMediaAsync();
        Log(media is not null ? $"media up, {media.Info().Codec}" : "call ended before media");
    }

    private void OnHangupClick(object sender, RoutedEventArgs e) => Try("hangup", () => _call?.Hangup());

    private void OnHoldClick(object sender, RoutedEventArgs e) => Try("hold", () => _call?.Hold());

    private void OnResumeClick(object sender, RoutedEventArgs e) => Try("resume", () => _call?.Resume());

    private void OnDtmfClick(object sender, RoutedEventArgs e)
    {
        if (!string.IsNullOrWhiteSpace(DtmfBox.Text))
        {
            Try("DTMF", () => _call?.SendDtmf(DtmfBox.Text));
        }
    }

    private void Try(string what, Action act)
    {
        try
        {
            act();
        }
        catch (SipralException ex)
        {
            Log($"{what} failed: {ex.Message}");
        }
    }

    /// <summary>The address of this machine a datagram to
    /// <paramref name="address"/> leaves from. Connecting a datagram socket
    /// sends nothing.</summary>
    private static string RouteTo(string address)
    {
        var (host, port) = SipralStack.ParseAddress(address);
        using var probe = new System.Net.Sockets.Socket(
            System.Net.Sockets.AddressFamily.InterNetwork, System.Net.Sockets.SocketType.Dgram,
            System.Net.Sockets.ProtocolType.Udp);
        probe.Connect(System.Net.IPAddress.Parse(host), port);
        return ((System.Net.IPEndPoint)probe.LocalEndPoint!).Address.ToString();
    }

    protected override void OnClosed(EventArgs e)
    {
        _meters.Stop();
        _call?.Close();
        _stack.Dispose();
        base.OnClosed(e);
    }
}
