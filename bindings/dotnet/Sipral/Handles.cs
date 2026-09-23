// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Sipral;

/// <summary>
/// A <c>sipral_handle_t</c> — a 64-bit number naming one thing the
/// library owns, never a pointer — wrapped as a <see cref="SafeHandle"/>
/// so that every handle this binding hands out gets the same
/// finalizer-backed disposal safety net .NET gives a file or a socket:
/// released once, from a finalizer if an application never calls
/// <c>Dispose</c>, and never twice even under a race between an explicit
/// close and the finalizer, which <see cref="SafeHandle"/>'s own
/// reference count already serialises.
///
/// The 64-bit value is carried in the <see cref="SafeHandle"/>'s own
/// <c>IntPtr</c> field bit for bit — never dereferenced, never read by
/// anything but the entry point that minted it, exactly as
/// <c>docs/08-ffi.md</c>'s "Handles" section describes it on the C side.
/// </summary>
public abstract class SipralSafeHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    /// <summary>For a derived handle type in this assembly only — an
    /// application never constructs one directly, it gets one back from
    /// <see cref="SipralStack"/>, <see cref="Account"/>, <see cref="Call"/>
    /// or <see cref="CallMedia"/>.</summary>
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
/// <c>sipral_account_remove</c>, which needs the stack handle too — kept
/// alongside it here since an account never outlives the stack that
/// minted it (<c>docs/08-ffi.md</c>, "A handle names something only on
/// the stack that minted it").</summary>
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
/// <c>sipral_media_release</c>. A media handle outlives its call
/// (<c>docs/08-ffi.md</c>, "A media handle outlives its call, and says
/// so"), so it needs no stack or call handle to release itself.</summary>
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
/// One call handle. There is no <c>sipral_call_release</c> in the C ABI
/// — a call's handle simply goes stale the moment
/// <c>SIPRAL_EVENT_KIND_CALL_ENDED</c> is delivered for it
/// (<c>docs/08-ffi.md</c>, "The call is over, and its handle is stale
/// from here on"), and nothing here frees it a second way. This is still
/// a <see cref="SipralSafeHandle"/>, with a <see cref="ReleaseHandle"/>
/// that does nothing but return success, so that <see cref="Call"/> gets
/// the exact same disposal shape — <c>IsClosed</c>, double-dispose
/// safety, a finalizer that cannot double-free — as every handle that
/// does have unmanaged state to give back, rather than a special case an
/// application has to remember.
/// </summary>
public sealed class CallSafeHandle : SipralSafeHandle
{
    /// <summary>Nothing to release; see the class summary.</summary>
    protected override bool ReleaseHandle() => true;
}
