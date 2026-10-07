// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Maui.Hosting;
using Microsoft.Maui.LifecycleEvents;
using Microsoft.Maui.Storage;

namespace Sipral;

/// <summary>
/// Ties a stack to the application's own lifecycle on iOS and Android.
/// Moving to the background calls <see cref="SipralStack.Suspending"/> and
/// writes down every kept account's registration (<see cref="Account.Freeze"/>)
/// in the platform's secure storage (the Keychain, the Android Keystore);
/// coming back calls <see cref="SipralStack.Resumed"/>. When the operating
/// system ended the process meanwhile, <see cref="RestoreAsync"/> carries the
/// registration into the new one with <see cref="Account.Thaw"/>, without a
/// full handshake (<c>docs/16-lifecycle.md</c>).
/// </summary>
public sealed class SipralAppLifecycle
{
    private const string KeyPrefix = "sipral.registration.";
    private readonly object _gate = new();
    private readonly Dictionary<string, Account> _kept = new(StringComparer.Ordinal);
    private SipralStack? _stack;

    /// <summary>Raised on the way into the background, with what was
    /// standing when the stack was told.</summary>
    public event Action<SipralSuspending>? Suspended;

    /// <summary>Raised when a registration could not be written down or
    /// read back; the stack itself carries on either way.</summary>
    public event Action<Exception>? StorageFailed;

    /// <summary>The stack the lifecycle is applied to; <see langword="null"/>
    /// until the application has made one, and again after disposing it.</summary>
    public SipralStack? Stack
    {
        get { lock (_gate) { return _stack; } }
        set { lock (_gate) { _stack = value; } }
    }

    /// <summary>Writes <paramref name="account"/>'s registration down under
    /// <paramref name="key"/> on every move to the background. The key names
    /// the account across processes, so it must not change between runs.</summary>
    public void Keep(Account account, string key)
    {
        ArgumentNullException.ThrowIfNull(account);
        ArgumentException.ThrowIfNullOrEmpty(key);
        lock (_gate)
        {
            _kept[key] = account;
        }
    }

    /// <summary>Stops writing the account under <paramref name="key"/> down
    /// and removes what was written: call it when the account is removed.</summary>
    public void Forget(string key)
    {
        ArgumentException.ThrowIfNullOrEmpty(key);
        lock (_gate)
        {
            _kept.Remove(key);
        }
        SecureStorage.Default.Remove(KeyPrefix + key);
    }

    /// <summary>Reads back what was written under <paramref name="key"/> onto
    /// <paramref name="account"/>, just added and not yet registered, and
    /// keeps it from then on. <see langword="false"/> when nothing usable was
    /// there: the application then calls <see cref="Account.Register"/>.</summary>
    public async Task<bool> RestoreAsync(Account account, string key)
    {
        ArgumentNullException.ThrowIfNull(account);
        ArgumentException.ThrowIfNullOrEmpty(key);
        Keep(account, key);
        string? stored;
        try
        {
            stored = await SecureStorage.Default.GetAsync(KeyPrefix + key).ConfigureAwait(false);
        }
        catch (Exception failed)
        {
            StorageFailed?.Invoke(failed);
            return false;
        }
        if (!SnapshotRecord.TryRead(stored, out var writtenAtMs, out var snapshot))
        {
            return false;
        }
        var nowMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var asleepMs = nowMs > writtenAtMs ? (ulong)(nowMs - writtenAtMs) : 0;
        try
        {
            account.Thaw(snapshot, asleepMs);
            return true;
        }
        catch (SipralException refused)
        {
            StorageFailed?.Invoke(refused);
            SecureStorage.Default.Remove(KeyPrefix + key);
            return false;
        }
    }

    internal void EnteredBackground()
    {
        SipralStack? stack;
        List<KeyValuePair<string, Account>> kept;
        lock (_gate)
        {
            stack = _stack;
            kept = new List<KeyValuePair<string, Account>>(_kept);
        }
        if (stack is null)
        {
            return;
        }
        // written down first: once told it is suspending, the stack no longer
        // counts a registration as bound, and there would be nothing to keep
        var nowMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        foreach (var (key, account) in kept)
        {
            Write(key, account, nowMs);
        }
        Suspended?.Invoke(stack.Suspending());
    }

    internal void EnteredForeground() => Stack?.Resumed();

    private void Write(string key, Account account, long nowMs)
    {
        byte[] snapshot;
        try
        {
            snapshot = account.Freeze();
        }
        catch (SipralException refused) when (refused.Status == SipralStatus.WrongState)
        {
            SecureStorage.Default.Remove(KeyPrefix + key);
            return;
        }
        catch (SipralException refused)
        {
            StorageFailed?.Invoke(refused);
            return;
        }
        // secure storage is asynchronous; the platform grants a moment on
        // the way into the background, and a write it cuts short leaves the
        // previous snapshot, which RestoreAsync then reads as older
        _ = SecureStorage.Default.SetAsync(KeyPrefix + key, SnapshotRecord.Write(nowMs, snapshot))
            .ContinueWith(
                written => StorageFailed?.Invoke(written.Exception!.GetBaseException()),
                TaskContinuationOptions.OnlyOnFaulted);
    }
}

/// <summary>Registers <see cref="SipralAppLifecycle"/> with a MAUI application.</summary>
public static class SipralMauiAppBuilderExtensions
{
    /// <summary>
    /// Adds one <see cref="SipralAppLifecycle"/> to the services and wires it
    /// to the platform: on iOS to entering the background and the
    /// foreground, on Android to the activity stopping and starting. Assign
    /// its <see cref="SipralAppLifecycle.Stack"/> once a stack exists.
    /// </summary>
    public static MauiAppBuilder UseSipral(this MauiAppBuilder builder, out SipralAppLifecycle lifecycle)
    {
        ArgumentNullException.ThrowIfNull(builder);
        var wired = new SipralAppLifecycle();
        lifecycle = wired;
        builder.Services.AddSingleton(wired);
        builder.ConfigureLifecycleEvents(events =>
        {
#if IOS
            events.AddiOS(ios => ios
                .DidEnterBackground(_ => wired.EnteredBackground())
                .WillEnterForeground(_ => wired.EnteredForeground()));
#elif ANDROID
            events.AddAndroid(android => android
                .OnStop(_ => wired.EnteredBackground())
                .OnRestart(_ => wired.EnteredForeground()));
#endif
        });
        return builder;
    }
}

/// <summary>What is stored per account: when it was written, in Unix
/// milliseconds, and the opaque snapshot, as one Base64 text.</summary>
internal static class SnapshotRecord
{
    internal static string Write(long writtenAtMs, byte[] snapshot)
    {
        var record = new byte[8 + snapshot.Length];
        BitConverter.TryWriteBytes(record.AsSpan(0, 8), writtenAtMs);
        snapshot.CopyTo(record, 8);
        return Convert.ToBase64String(record);
    }

    internal static bool TryRead(string? stored, out long writtenAtMs, out byte[] snapshot)
    {
        writtenAtMs = 0;
        snapshot = Array.Empty<byte>();
        if (string.IsNullOrEmpty(stored))
        {
            return false;
        }
        byte[] record;
        try
        {
            record = Convert.FromBase64String(stored);
        }
        catch (FormatException)
        {
            return false;
        }
        if (record.Length <= 8)
        {
            return false;
        }
        writtenAtMs = BitConverter.ToInt64(record, 0);
        snapshot = record[8..];
        return true;
    }
}
