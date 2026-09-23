// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

using System.Runtime.InteropServices;
using System.Text;

namespace Sipral;

/// <summary>
/// One <c>sipral_account_add</c> handle, and the entry points that take
/// it.
///
/// Built through <see cref="SipralStack.AddAccount"/>, never directly: a
/// handle only means something on the stack that minted it
/// (<c>docs/08-ffi.md</c>, "A handle names something only on the stack
/// that minted it"), so keeping the two together is what makes every
/// method here safe to call with nothing further to pass.
/// </summary>
public sealed class Account
{
    private readonly SipralStack _stack;
    private readonly AccountSafeHandle _handle;

    /// <summary>The address of record this account was added with.</summary>
    public string Aor { get; }

    internal ulong Handle => _handle.Value;

    private Account(SipralStack stack, ulong handle, string aor)
    {
        _stack = stack;
        _handle = new AccountSafeHandle();
        _handle.Attach(stack.Handle, handle);
        Aor = aor;
    }

    internal static Account Add(
        SipralStack stack,
        string aor,
        string registrarAddress,
        string? registrar,
        string? contact,
        string? displayName,
        string? authUser,
        string? authPassword,
        ulong expiresSeconds)
    {
        var aorBytes = Encoding.UTF8.GetBytes(aor);
        var registrarAddressBytes = Encoding.UTF8.GetBytes(registrarAddress);
        var registrarBytes = registrar is null ? null : Encoding.UTF8.GetBytes(registrar);
        var contactBytes = Encoding.UTF8.GetBytes(contact ?? DefaultContact(aor, stack.BindAddress));
        var displayNameBytes = displayName is null ? null : Encoding.UTF8.GetBytes(displayName);
        var authUserBytes = authUser is null ? null : Encoding.UTF8.GetBytes(authUser);
        var authPasswordBytes = authPassword is null ? null : Encoding.UTF8.GetBytes(authPassword);

        ulong accountHandle = 0;
        using (var aorPin = Pin(aorBytes))
        using (var registrarAddressPin = Pin(registrarAddressBytes))
        using (var registrarPin = Pin(registrarBytes))
        using (var contactPin = Pin(contactBytes))
        using (var displayNamePin = Pin(displayNameBytes))
        using (var authUserPin = Pin(authUserBytes))
        using (var authPasswordPin = Pin(authPasswordBytes))
        {
            var config = SipralAccountConfig.Sized();
            config.Aor = aorPin.Pointer;
            config.AorLen = (nuint)aorBytes.Length;
            if (registrarBytes is not null)
            {
                config.Registrar = registrarPin.Pointer;
                config.RegistrarLen = (nuint)registrarBytes.Length;
            }
            config.RegistrarAddress = registrarAddressPin.Pointer;
            config.RegistrarAddressLen = (nuint)registrarAddressBytes.Length;
            config.Contact = contactPin.Pointer;
            config.ContactLen = (nuint)contactBytes.Length;
            if (displayNameBytes is not null)
            {
                config.DisplayName = displayNamePin.Pointer;
                config.DisplayNameLen = (nuint)displayNameBytes.Length;
            }
            if (authUserBytes is not null)
            {
                config.AuthUser = authUserPin.Pointer;
                config.AuthUserLen = (nuint)authUserBytes.Length;
            }
            if (authPasswordBytes is not null)
            {
                config.AuthPassword = authPasswordPin.Pointer;
                config.AuthPasswordLen = (nuint)authPasswordBytes.Length;
            }
            config.ExpiresSeconds = expiresSeconds;

            SipralErrors.Call(() => NativeMethods.sipral_account_add(stack.Handle, config, out accountHandle), "sipral_account_add");
        }

        return new Account(stack, accountHandle, aor);
    }

    /// <summary>Where this account can actually be reached, for a caller
    /// who gave no <c>Contact</c> of its own — the user part of the AOR,
    /// kept, with the host replaced by the address this stack is
    /// listening on. The AOR itself is never a usable default: it names
    /// who this is, not a socket anything can write to.</summary>
    private static string DefaultContact(string aor, string bindAddress)
    {
        var colon = aor.IndexOf(':');
        if (colon < 0)
        {
            return $"sip:{bindAddress}";
        }
        var scheme = aor[..colon];
        var rest = aor[(colon + 1)..];
        var at = rest.IndexOf('@');
        return at < 0 ? $"{scheme}:{bindAddress}" : $"{scheme}:{rest[..at]}@{bindAddress}";
    }

    /// <summary><c>sipral_account_register</c>. A no-op account refuses
    /// this.</summary>
    public void Register()
    {
        SipralErrors.Call(() => NativeMethods.sipral_account_register(_stack.Handle, Handle, _stack.NowMs), "sipral_account_register");
    }

    /// <summary><c>sipral_account_unregister</c>.</summary>
    public void Unregister()
    {
        SipralErrors.Call(() => NativeMethods.sipral_account_unregister(_stack.Handle, Handle, _stack.NowMs), "sipral_account_unregister");
    }

    /// <summary><c>sipral_account_registration_state</c>.</summary>
    public SipralRegistrationState RegistrationState()
    {
        uint state = 0;
        SipralErrors.Call(() => NativeMethods.sipral_account_registration_state(_stack.Handle, Handle, out state), "sipral_account_registration_state");
        return (SipralRegistrationState)state;
    }

    /// <summary><c>sipral_account_remove</c>. Every call this account
    /// placed ends.</summary>
    public void Remove() => _handle.Dispose();

    private static Interop.PinnedBytes Pin(byte[]? bytes) => new(bytes);
}
