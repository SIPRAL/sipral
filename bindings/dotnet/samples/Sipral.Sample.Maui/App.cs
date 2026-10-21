// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

using System;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Maui;
using Microsoft.Maui.ApplicationModel;
using Microsoft.Maui.Controls;

namespace Sipral.Sample.Maui;

/// <summary>
/// One page: the account's address, its server and password, a number to
/// call, and the state of each. The stack runs in device mode, so the
/// microphone is asked for before it is made.
///
/// Every line the page shows is also written to standard output, prefixed
/// <c>sipral-sample:</c>, which is the simulator's console and Android's
/// logcat (tag <c>DOTNET</c>): a run leaves its evidence there. The fields
/// can be filled at launch, and the buttons pressed in order, from
/// <c>SIPRAL_SAMPLE_*</c> variables: the process environment on iOS
/// (<c>SIMCTL_CHILD_</c> on the simulator, <c>devicectl --environment-variables</c>
/// on a device), the launching intent's string extras on Android
/// (<c>am start -e</c>). <c>SIPRAL_SAMPLE_STEPS</c> lists the presses,
/// among <c>register</c>, <c>call</c> and <c>unregister</c>; a call is hung
/// up after <c>SIPRAL_SAMPLE_CALL_SECONDS</c> (20 by default) unless the far
/// end hangs up first.
/// </summary>
public sealed class App : Application
{
    private const string AccountKey = "sample";
    private static readonly TimeSpan Settle = TimeSpan.FromSeconds(15);

    private readonly SipralAppLifecycle _lifecycle;
    private readonly Entry _aor = new() { Placeholder = "sip:1001@pbx.example.com", Keyboard = Keyboard.Email };
    private readonly Entry _server = new() { Placeholder = "pbx.example.com:5060", Keyboard = Keyboard.Url };
    private readonly Entry _password = new() { Placeholder = "password", IsPassword = true };
    private readonly Entry _target = new() { Placeholder = "sip:*43@pbx.example.com", Keyboard = Keyboard.Email };
    private readonly Label _status = new();
    private SipralStack? _stack;
    private Account? _account;
    private Call? _call;
    private int _registrationAnswers;

    public App(SipralAppLifecycle lifecycle)
    {
        _lifecycle = lifecycle;
        _lifecycle.Frozen += key => Show($"registration written down as {key}");
        _lifecycle.Suspended += report => Show($"in the background: suspending, {report.Unverified} binding(s) unverified, {report.Calls} call(s) standing");
        _lifecycle.Resumed += () => Show($"back in the foreground: resumed, registration {_account?.RegistrationState()}");
        _lifecycle.StorageFailed += failed => Show($"registration not kept: {failed.Message}");
        // the first call into the native library, before anything is asked
        // for: a library the application did not link fails here, at start
        Show($"Sipral {SipralInfo.Version}, features 0x{SipralStack.Features():x}");
    }

    protected override Window CreateWindow(IActivationState? activationState)
    {
        // read here, not when the fields are made: on Android the
        // application exists before the activity that carries the launch
        _aor.Text = Setting("AOR");
        _server.Text = Setting("SERVER");
        _password.Text = Setting("PASSWORD");
        _target.Text = Setting("TARGET");
        var register = new Button { Text = "Register" };
        register.Clicked += async (_, _) => await RegisterAsync();
        var call = new Button { Text = "Call" };
        call.Clicked += (_, _) => Place();
        var hangup = new Button { Text = "Hang up" };
        hangup.Clicked += (_, _) => _call?.Hangup();
        var unregister = new Button { Text = "Unregister" };
        unregister.Clicked += (_, _) => Unregister();
        var page = new ContentPage
        {
            Title = "Sipral",
            Content = new ScrollView
            {
                Content = new VerticalStackLayout
                {
                    Padding = 16,
                    Spacing = 8,
                    Children = { _aor, _server, _password, register, _target, call, hangup, unregister, _status },
                },
            },
        };
        if (Setting("STEPS") is { Length: > 0 } steps)
        {
            page.Loaded += async (_, _) => await RunAsync(steps);
        }
        return new Window(page);
    }

    private static string? Setting(string name) => Environment.GetEnvironmentVariable("SIPRAL_SAMPLE_" + name);

    private async Task RunAsync(string steps)
    {
        var seconds = int.TryParse(Setting("CALL_SECONDS"), out var given) && given > 0 ? given : 20;
        foreach (var step in steps.Split([' ', ','], StringSplitOptions.RemoveEmptyEntries))
        {
            Show($"step {step}");
            switch (step)
            {
                case "register":
                    await RegisterAsync();
                    await UntilAsync(() => _account?.RegistrationState() is SipralRegistrationState.Registered or SipralRegistrationState.Restored, Settle);
                    break;
                case "call":
                    Place();
                    await UntilAsync(() => _call is null || _call.Ended, TimeSpan.FromSeconds(seconds));
                    if (_call is { Ended: false } standing)
                    {
                        if (standing.Media is { } media)
                        {
                            var live = media.Statistics();
                            Show($"before hanging up: {live.Codec}, {live.PacketsSent} packets sent, {live.PacketsReceived} received, {live.PacketsLost} lost");
                        }
                        standing.Hangup();
                        await UntilAsync(() => standing.Ended, Settle);
                    }
                    break;
                case "unregister":
                    var answers = Volatile.Read(ref _registrationAnswers);
                    Unregister();
                    await UntilAsync(() => Volatile.Read(ref _registrationAnswers) > answers, Settle);
                    break;
                default:
                    Show($"no such step: {step}");
                    return;
            }
        }
        Show("steps done");
    }

    private static async Task UntilAsync(Func<bool> done, TimeSpan limit)
    {
        var deadline = DateTime.UtcNow + limit;
        while (!done() && DateTime.UtcNow < deadline)
        {
            await Task.Delay(100);
        }
    }

    private async Task RegisterAsync()
    {
        if (_stack is not null)
        {
            return;
        }
        if (string.IsNullOrWhiteSpace(_aor.Text) || string.IsNullOrWhiteSpace(_server.Text))
        {
            Show("an address of record and a server are needed");
            return;
        }
        Show(await SipralMicrophone.IsGrantedAsync() ? "microphone already granted" : "asking for the microphone");
        if (!await SipralMicrophone.RequestAsync())
        {
            Show("the microphone was refused; calls need it");
            return;
        }
        Show("microphone granted");
        try
        {
#if IOS
            // on iOS the audio session is the application's to set up
            SipralAudioSession.Activate();
#endif
            _stack = new SipralStack(audio: SipralAudio.Device);
            _lifecycle.Stack = _stack;
            // the server is the registrar as well, an address taken as it is
            // and a name looked up (RFC 3263); the password is the address
            // of record's user's
            var literal = IPEndPoint.TryParse(_server.Text ?? "", out _);
            var password = string.IsNullOrEmpty(_password.Text) ? null : _password.Text;
            _account = _stack.AddAccount(
                _aor.Text,
                registrarAddress: literal ? _server.Text : null,
                serverUri: literal ? null : $"sip:{_server.Text}",
                registrar: $"sip:{_server.Text}",
                authUser: password is null ? null : UserOf(_aor.Text),
                authPassword: password);
            _ = Task.Run(WatchAsync);
            if (await _lifecycle.RestoreAsync(_account, AccountKey))
            {
                Show($"registration restored from the last run: {_account.RegistrationState()}");
            }
            else
            {
                _account.Register();
                Show("registering");
            }
        }
        catch (SipralException refused)
        {
            Show(refused.Message);
        }
    }

    private static string UserOf(string aor)
    {
        var colon = aor.IndexOf(':');
        var at = aor.IndexOf('@');
        return at > colon ? aor[(colon + 1)..at] : aor[(colon + 1)..];
    }

    private void Place()
    {
        if (_stack is null || _account is null || string.IsNullOrWhiteSpace(_target.Text))
        {
            return;
        }
        try
        {
            _call = _stack.PlaceCall(_account, _target.Text);
            Show($"calling {_target.Text}");
        }
        catch (SipralException refused)
        {
            Show(refused.Message);
        }
    }

    private void Unregister()
    {
        if (_account is null)
        {
            return;
        }
        // nothing to carry into the next run once the binding is withdrawn
        _lifecycle.Forget(AccountKey);
        try
        {
            _account.Unregister();
            Show("unregistering");
        }
        catch (SipralException refused)
        {
            Show(refused.Message);
        }
    }

    private async Task WatchAsync()
    {
        var stack = _stack;
        if (stack is null)
        {
            return;
        }
        await foreach (var e in stack.Events)
        {
            switch (e.Kind)
            {
                case SipralEventKind.RegistrationChanged when e.Registration is { } registration:
                    Interlocked.Increment(ref _registrationAnswers);
                    Show($"registration {registration.State}, status {registration.StatusCode}, {registration.Failure}");
                    break;
                case SipralEventKind.CallEnded when e.CallInfo is { } ended:
                    Show($"call ended, {ended.EndReason}, status {ended.StatusCode}");
                    break;
                case SipralEventKind.MediaStatistics when e.Media?.Statistics is { } final:
                    Show($"media: {final.Codec}, {final.PacketsSent} packets sent, {final.PacketsReceived} received, {final.PacketsLost} lost");
                    break;
                default:
                    Show(e.Kind.ToString());
                    break;
            }
        }
    }

    private void Show(string text)
    {
        Console.WriteLine("sipral-sample: " + text);
        MainThread.BeginInvokeOnMainThread(() => _status.Text = text);
    }
}
