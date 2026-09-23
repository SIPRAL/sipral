// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

import CSipral

/// `sipral_account_add`, and the entry points that take its handle.
///
/// Built through `SipralStack.addAccount`, never directly: a handle names
/// something only on the stack that minted it (`docs/08-ffi.md`, "A handle
/// names something only on the stack that minted it"), so keeping the two
/// together is what makes every method here safe to call with nothing
/// further to pass.
public final class Account: @unchecked Sendable {
    public unowned let stack: SipralStack
    public let handle: SipralHandle
    public let aor: String

    init(stack: SipralStack, handle: SipralHandle, aor: String) {
        self.stack = stack
        self.handle = handle
        self.aor = aor
    }

    /// Where this account can actually be reached, for a caller who gave no
    /// `Contact` of its own. The AOR itself is never a usable default: a
    /// `sip:` address of record names who this is, not a socket anything can
    /// write to (`bindings/python/sipral/account.py`'s `_default_contact`
    /// explains the same choice).
    private static func defaultContact(aor: String, bindAddress: String) -> String {
        guard let colon = aor.firstIndex(of: ":") else { return aor }
        let scheme = aor[aor.startIndex..<colon]
        let rest = aor[aor.index(after: colon)...]
        guard let at = rest.firstIndex(of: "@") else { return "\(scheme):\(bindAddress)" }
        let user = rest[rest.startIndex..<at]
        return "\(scheme):\(user)@\(bindAddress)"
    }

    static func add(
        stack: SipralStack,
        aor: String,
        registrarAddress: String,
        registrar: String?,
        contact: String?,
        displayName: String?,
        authUser: String?,
        authPassword: String?,
        expiresSeconds: UInt64
    ) throws -> Account {
        let contact = contact ?? defaultContact(aor: aor, bindAddress: stack.bindAddress)
        let handle: SipralHandle = try CStrings.with(
            [aor, registrar, contact, registrarAddress, displayName, authUser, authPassword]
        ) { parts in
            var config = sipral_account_config_t.sized()
            config.aor = parts[0].pointer
            config.aor_len = parts[0].count
            if let registrarPointer = parts[1].pointer {
                config.registrar = registrarPointer
                config.registrar_len = parts[1].count
            }
            config.contact = parts[2].pointer
            config.contact_len = parts[2].count
            config.registrar_address = parts[3].pointer
            config.registrar_address_len = parts[3].count
            if let displayNamePointer = parts[4].pointer {
                config.display_name = displayNamePointer
                config.display_name_len = parts[4].count
            }
            if let authUserPointer = parts[5].pointer {
                config.auth_user = authUserPointer
                config.auth_user_len = parts[5].count
            }
            if let authPasswordPointer = parts[6].pointer {
                config.auth_password = authPasswordPointer
                config.auth_password_len = parts[6].count
            }
            config.expires_seconds = expiresSeconds
            return try retryingBusy {
                try Sipral.accountAdd(stack: stack.handle, config: config, configHeaders: [])
            }
        }
        return Account(stack: stack, handle: handle, aor: aor)
    }

    /// `sipral_account_register`. A no-op account (no registrar) refuses this.
    public func register() throws {
        try retryingBusy {
            try Sipral.accountRegister(stack: stack.handle, account: handle, nowMs: stack.nowMs())
        }
    }

    public func unregister() throws {
        try retryingBusy {
            try Sipral.accountUnregister(stack: stack.handle, account: handle, nowMs: stack.nowMs())
        }
    }

    public var registrationState: SipralRegistrationState? {
        get throws {
            let raw = try retryingBusy {
                try Sipral.accountRegistrationState(stack: stack.handle, account: handle)
            }
            return SipralRegistrationState(rawValue: raw)
        }
    }

    /// `sipral_account_remove`. Every call this account placed ends.
    public func remove() throws {
        try Sipral.accountRemove(stack: stack.handle, account: handle)
    }

    /// `sipral_account_announce` (`docs/15-mobile.md`, "C2"): what a
    /// `PushKitBridge` calls the instant a VoIP push arrives, before the
    /// INVITE it is about has necessarily reached the transport. Returns
    /// either an announcement waiting for that INVITE, or the call itself
    /// when it arrived first.
    public func announce(caller: String) throws -> (announcement: SipralHandle?, call: SipralHandle?) {
        let result = try retryingBusy {
            try Sipral.accountAnnounce(stack: stack.handle, account: handle, caller: caller, nowMs: stack.nowMs())
        }
        if result.call != Sipral.handleNone {
            return (nil, result.call)
        }
        return (result.announcement, nil)
    }

    /// `sipral_account_refresh_binding` (RFC 8599 §4.1.3): refreshed at once
    /// on a wake-up, ahead of the scheduled refresh and any back-off an
    /// earlier outage earned.
    public func refreshBinding() throws {
        try retryingBusy {
            try Sipral.accountRefreshBinding(stack: stack.handle, account: handle, nowMs: stack.nowMs())
        }
    }
}
