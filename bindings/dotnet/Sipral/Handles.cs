// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Sipral;

/// <summary>
/// A <c>sipral_handle_t</c> (a 64-bit id, never a pointer) as a
/// <see cref="SafeHandle"/>: released exactly once, by a finalizer if never
/// disposed. The value rides bit for bit in the <c>IntPtr</c> and is never
/// dereferenced.
/// </summary>
public abstract class SipralSafeHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    /// <summary>For derived types in this assembly only.</summary>
    private protected SipralSafeHandle()
        : base(ownsHandle: true)
    {
    }

    /// <summary>The raw <c>sipral_handle_t</c>.</summary>
    public ulong Value => unchecked((ulong)handle);

    internal void SetValue(ulong value)
    {
        SetHandle(unchecked((IntPtr)value));
    }
}

/// <summary>One <c>sipral_stack_create</c> handle. Released with
/// <c>sipral_stack_destroy</c>.</summary>
public sealed class StackSafeHandle : SipralSafeHandle
{
    /// <summary><c>sipral_stack_destroy</c>.</summary>
    protected override bool ReleaseHandle()
    {
        NativeMethods.sipral_stack_destroy(Value);
        return true;
    }
}

/// <summary>One <c>sipral_account_add</c> handle. Released with
/// <c>sipral_account_remove</c>, which also needs the stack handle kept
/// here.</summary>
public sealed class AccountSafeHandle : SipralSafeHandle
{
    private ulong _stack;

    internal void Attach(ulong stack, ulong account)
    {
        _stack = stack;
        SetValue(account);
    }

    /// <summary><c>sipral_account_remove</c>.</summary>
    protected override bool ReleaseHandle()
    {
        NativeMethods.sipral_account_remove(_stack, Value);
        return true;
    }
}

/// <summary>One <c>sipral_call_media</c> handle. Released with
/// <c>sipral_media_release</c>; it outlives its call, so needs no other
/// handle.</summary>
public sealed class MediaSafeHandle : SipralSafeHandle
{
    /// <summary><c>sipral_media_release</c>.</summary>
    protected override bool ReleaseHandle()
    {
        NativeMethods.sipral_media_release(Value);
        return true;
    }
}

/// <summary>
/// One call handle. The ABI has no release for it: it goes stale once
/// <c>CALL_ENDED</c> is delivered. It is a safe handle anyway, with a no-op
/// release, so <see cref="Call"/> disposes like every other handle.
/// </summary>
public sealed class CallSafeHandle : SipralSafeHandle
{
    /// <summary>Nothing to release; see the class summary.</summary>
    protected override bool ReleaseHandle() => true;
}
