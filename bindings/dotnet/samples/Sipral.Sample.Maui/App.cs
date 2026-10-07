// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

using System;
using System.Threading.Tasks;
using Microsoft.Maui;
using Microsoft.Maui.ApplicationModel;
using Microsoft.Maui.Controls;

namespace Sipral.Sample.Maui;

/// <summary>
/// One page: the account's address, its server and password, a number to
/// call, and the state of each. The stack runs in device mode, so the
/// microphone is asked for before it is made.
/// </summary>
public sealed class App : Application
{
    private const string AccountKey = "sample";

    private readonly SipralAppLifecycle _lifecycle;
    private readonly Entry _aor = new() { Placeholder = "sip:1001@pbx.example.com", Keyboard = Keyboard.Email };
    private readonly Entry _server = new() { Placeholder = "pbx.example.com:5060", Keyboard = Keyboard.Url };
    private readonly Entry _password = new() { Placeholder = "password", IsPassword = true };
    private readonly Entry _target = new() { Placeholder = "sip:*43@pbx.example.com", Keyboard = Keyboard.Email };
    // the first call into the native library, before anything is asked for:
    // a library the application did not link fails here, at start
    private readonly Label _status = new() { Text = $"Sipral {SipralInfo.Version}, features 0x{SipralStack.Features():x}" };
    private SipralStack? _stack;
    private Account? _account;
    private Call? _call;

    public App(SipralAppLifecycle lifecycle)
    {
        _lifecycle = lifecycle;
        _lifecycle.Suspended += report => Show($"in the background, {report.Calls} call(s) standing");
        _lifecycle.StorageFailed += failed => Show($"registration not kept: {failed.Message}");
    }

    protected override Window CreateWindow(IActivationState? activationState)
    {
        var register = new Button { Text = "Register" };
        register.Clicked += async (_, _) => await RegisterAsync();
        var call = new Button { Text = "Call" };
        call.Clicked += (_, _) => Place();
        var hangup = new Button { Text = "Hang up" };
        hangup.Clicked += (_, _) => _call?.Hangup();
        var page = new ContentPage
        {
            Title = "Sipral",
            Content = new ScrollView
            {
                Content = new VerticalStackLayout
                {
                    Padding = 16,
                    Spacing = 8,
                    Children = { _aor, _server, _password, register, _target, call, hangup, _status },
                },
            },
        };
        return new Window(page);
    }

    private async Task RegisterAsync()
    {
        if (_stack is not null)
        {
            return;
        }
        if (!await SipralMicrophone.RequestAsync())
        {
            Show("the microphone was refused; calls need it");
            return;
        }
        try
        {
#if IOS
            // on iOS the audio session is the application's to set up
            SipralAudioSession.Activate();
#endif
            _stack = new SipralStack(audio: SipralAudio.Device);
            _lifecycle.Stack = _stack;
            _account = _stack.AddAccount(_aor.Text, registrarAddress: _server.Text, authPassword: _password.Text);
            _ = Task.Run(WatchAsync);
            if (await _lifecycle.RestoreAsync(_account, AccountKey))
            {
                Show("registration restored from the last run");
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

    private async Task WatchAsync()
    {
        var stack = _stack;
        if (stack is null)
        {
            return;
        }
        await foreach (var e in stack.Events)
        {
            Show(e.Kind.ToString());
        }
    }

    private void Show(string text) => MainThread.BeginInvokeOnMainThread(() => _status.Text = text);
}
