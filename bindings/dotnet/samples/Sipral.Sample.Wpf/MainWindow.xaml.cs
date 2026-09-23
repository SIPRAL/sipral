// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

using System.Windows;
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
/// A skeleton, not a product: registration, a call, hold/resume and DTMF
/// over <c>bindings/dotnet/Sipral</c> directly, the same public surface
/// <c>bindings/dotnet/samples/Sipral.Sample.Agent</c> drives headless. A
/// real application replaces the placeholder device list with whatever
/// local audio API it already uses, feeding <see cref="CallMedia.Frames"/>
/// to the earpiece and <see cref="CallMedia.SendAudio"/> from the
/// microphone; nothing else here changes.
/// </summary>
public partial class MainWindow : Window
{
    private SipralStack? _stack;
    private Account? _account;
    private Call? _call;

    public MainWindow()
    {
        InitializeComponent();
        DevicesList.Items.Add("(placeholder) default microphone");
        DevicesList.Items.Add("(placeholder) default speaker");
    }

    private void Log(string line) => EventsList.Items.Insert(0, line);

    private SipralStack EnsureStack()
    {
        if (_stack is not null)
        {
            return _stack;
        }
        _stack = new SipralStack();
        // Fired on the stack's own poll thread (docs/08-ffi.md, "Events
        // arrive on one callback"); WPF controls may only be touched from
        // the dispatcher thread that owns them, so every handler here
        // crosses back onto it before touching a control.
        _stack.EventReceived += (_, e) => Dispatcher.BeginInvoke(() => Log($"{e.Kind}"));
        return _stack;
    }

    private void OnRegisterClick(object sender, RoutedEventArgs e)
    {
        try
        {
            var stack = EnsureStack();
            _account ??= stack.AddAccount(
                AorBox.Text,
                registrarAddress: RegistrarAddressBox.Text,
                registrar: string.IsNullOrWhiteSpace(RegistrarBox.Text) ? null : RegistrarBox.Text,
                authUser: string.IsNullOrWhiteSpace(AuthUserBox.Text) ? null : AuthUserBox.Text,
                authPassword: string.IsNullOrWhiteSpace(AuthPasswordBox.Password) ? null : AuthPasswordBox.Password);
            _account.Register();
            Log("registering...");
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
            Log("register an account first");
            return;
        }
        try
        {
            var stack = EnsureStack();
            _call = stack.PlaceCall(_account, TargetBox.Text);
            Log("calling...");
            var media = await _call.WaitForMediaAsync();
            Log(media is not null ? "media up" : "call ended before media");
        }
        catch (SipralException ex)
        {
            Log($"call failed: {ex.Message}");
        }
    }

    private void OnHangupClick(object sender, RoutedEventArgs e)
    {
        try
        {
            _call?.Hangup();
        }
        catch (SipralException ex)
        {
            Log($"hangup failed: {ex.Message}");
        }
    }

    private void OnHoldClick(object sender, RoutedEventArgs e)
    {
        try
        {
            _call?.Hold();
        }
        catch (SipralException ex)
        {
            Log($"hold failed: {ex.Message}");
        }
    }

    private void OnResumeClick(object sender, RoutedEventArgs e)
    {
        try
        {
            _call?.Resume();
        }
        catch (SipralException ex)
        {
            Log($"resume failed: {ex.Message}");
        }
    }

    private void OnDtmfClick(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrWhiteSpace(DtmfBox.Text))
        {
            return;
        }
        try
        {
            _call?.SendDtmf(DtmfBox.Text);
            Log($"sent DTMF {DtmfBox.Text}");
        }
        catch (SipralException ex)
        {
            Log($"DTMF failed: {ex.Message}");
        }
    }

    protected override void OnClosed(System.EventArgs e)
    {
        _call?.Close();
        _stack?.Dispose();
        base.OnClosed(e);
    }
}
