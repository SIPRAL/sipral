// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

using System;
using System.Threading.Tasks;
using Sipral;
using Xunit;

namespace Sipral.Tests;

/// <summary>
/// What a mobile application calls as it goes to the background and comes
/// back, and the registration it writes down to carry into a later process.
/// </summary>
public sealed class LifecycleTests
{
    private static SipralStack Stack() => new(audio: SipralAudio.Application, bindHost: "127.0.0.1");

    private static async Task<bool> Until(Func<bool> condition, double seconds = 10)
    {
        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(seconds);
        while (!condition())
        {
            if (DateTime.UtcNow >= deadline)
            {
                return false;
            }
            await Task.Delay(20);
        }
        return true;
    }

    [Fact]
    public async Task ARegistrationWrittenDownComesBackRestoredInAnotherStack()
    {
        using var registrar = new ReachabilityTests.Registrar();
        byte[] snapshot;
        using (var first = Stack())
        {
            var account = first.AddAccount("sip:alice@example.com", registrar.Address, registrar: "sip:example.com");
            account.Register();
            Assert.True(await Until(() => account.RegistrationState() == SipralRegistrationState.Registered),
                "the account never registered");
            snapshot = account.Freeze();
            Assert.NotEmpty(snapshot);
            var report = first.Suspending();
            Assert.Equal((nuint)0, report.Calls);
            first.Resumed();
        }

        using var second = Stack();
        var restored = second.AddAccount("sip:alice@example.com", registrar.Address, registrar: "sip:example.com");
        restored.Thaw(snapshot, asleepMs: 1_000);
        Assert.Equal(SipralRegistrationState.Restored, restored.RegistrationState());
        Assert.True(restored.WantsRegistration);
    }

    [Fact]
    public void AnAccountThatNeverRegisteredHasNothingToWriteDown()
    {
        using var stack = Stack();
        var account = stack.AddAccount("sip:bob@example.com", "127.0.0.1:9", registrar: "sip:example.com");
        var refused = Assert.Throws<SipralException>(() => account.Freeze());
        Assert.Equal(SipralStatus.WrongState, refused.Status);
    }

    [Fact]
    public void BytesThatAreNotASnapshotAreRefused()
    {
        using var stack = Stack();
        var account = stack.AddAccount("sip:bob@example.com", "127.0.0.1:9", registrar: "sip:example.com");
        var refused = Assert.Throws<SipralException>(() => account.Thaw(new byte[] { 1, 2, 3 }, 0));
        Assert.Equal(SipralStatus.InvalidArgument, refused.Status);
        Assert.False(account.WantsRegistration);
    }

    [Fact]
    public void ResumingWithoutSuspendingIsSafe()
    {
        using var stack = Stack();
        stack.Resumed();
        stack.Suspending();
        stack.Resumed();
    }
}
