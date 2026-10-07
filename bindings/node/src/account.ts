// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// One `sipral_account_add` handle.

import { EventEmitter } from 'node:events';

import type { StackEvent } from './events.js';
import { SipralError, check, checkNow, config, plain, record, text, within } from './internal.js';
import { SIPRAL_TRANSPORT_MAIN, SipralActivity, SipralRegistrationState, SipralStatus, SipralTransport } from './sipral_abi.js';
import type { Stack } from './stack.js';
import { Subscription } from './subscription.js';

/** What an account emits. */
export interface AccountEvents {
  /** Every `RegistrationChanged` for this account: its new `SipralRegistrationState`. */
  registration: [number, StackEvent];
  /** Every event about this account, in order. */
  event: [StackEvent];
}

/**
 * What `sipral_account_check_certificate` found in a certificate the
 * account pins: its dates in seconds since 1970, and whether the clock is
 * past or before them. Accepted either way; an expired one is worth a
 * warning.
 */
export interface PinnedCertificate {
  readonly notBefore: number;
  readonly notAfter: number;
  readonly expired: boolean;
  readonly notYetValid: boolean;
}

/** What a push echo said: whether the push server took the binding, and how early to refresh it. */
export interface PushEcho {
  readonly accepted: boolean;
  readonly refreshLeadMs: number | null;
}

/** How a subscription is made. */
export interface SubscribeOptions {
  /** The body type wanted, when not the package's default. */
  accept?: string;
  /** How long to ask for, in seconds; an hour by default. */
  expiresSeconds?: number;
  /** Where the SUBSCRIBE goes, `host:port`, rather than where the account sends. */
  destination?: string;
}

/** @internal What the stack knows of an account when it adds one. */
export interface AccountFacts {
  registrarAddress: string;
  contactGiven: boolean;
  serverUri: string | null;
  advertised: string | null;
  streamProtocol: number;
  tlsPin: string | null;
  contactParameters: string;
}

/** An account added with {@link Stack.addAccount}. */
export class Account extends EventEmitter<AccountEvents> {
  /** The stack it belongs to. */
  readonly stack: Stack;
  /** The account's handle. */
  readonly handle: bigint;
  /** Its address of record. */
  readonly aor: string;
  /**
   * Where its requests go, `host:port`: the registrar or outbound proxy it
   * was added with, or -- added with `serverUri` -- the address it was last
   * located at, empty until then.
   */
  registrarAddress: string;
  /** The server URI RFC 3263 locates, or null. */
  readonly serverUri: string | null;
  /** Whether it was added with a `Contact` of its own, which a network move leaves to the application. */
  readonly contactGiven: boolean;
  /** The protocol of the connection of its own its requests go over, or 0 for the stack's transport. */
  readonly streamProtocol: number;
  /** The certificate pin it was added with. */
  readonly tlsPin: string | null;
  /** @internal What follows the address in the `Contact` this package derives for it. */
  readonly contactParameters: string;
  /** @internal The `host:port` its `Contact` names, when the stack chose it. */
  advertised: string | null;
  /** @internal Whether it was asked to register and not to unregister since. */
  wantsRegistration = false;

  /** @internal Built by the stack. */
  constructor(stack: Stack, accountHandle: bigint, aor: string, facts: AccountFacts) {
    super();
    this.stack = stack;
    this.handle = accountHandle;
    this.aor = aor;
    this.registrarAddress = facts.registrarAddress;
    this.serverUri = facts.serverUri;
    this.contactGiven = facts.contactGiven;
    this.streamProtocol = facts.streamProtocol;
    this.tlsPin = facts.tlsPin;
    this.contactParameters = facts.contactParameters;
    this.advertised = facts.advertised;
  }

  /** Where its registration is, a `SipralRegistrationState` value. */
  get registrationState(): number {
    const sipral = this.stack.sipral;
    const out = new Uint32Array(1);
    checkNow(sipral, 'sipral_account_registration_state', () =>
      sipral.sipral_account_registration_state(this.stack.handle, this.handle, out),
    );
    return out[0] ?? SipralRegistrationState.Unknown;
  }

  /**
   * Send a REGISTER now (`sipral_account_register`); refreshes follow by
   * themselves. On a stack signalling over TCP or TLS whose connection is
   * down this is kept, and the REGISTER goes the moment it is made again.
   */
  register(): void {
    this.stack.ensureOpen();
    this.wantsRegistration = true;
    try {
      checkNow(this.stack.sipral, 'sipral_account_register', () =>
        this.stack.sipral.sipral_account_register(this.stack.handle, this.handle, this.stack.nowMs()),
      );
    } catch (error) {
      if (!(error instanceof SipralError) || error.status !== SipralStatus.TransportDown) {
        throw error;
      }
    }
    this.stack.poll();
  }

  /**
   * Register and resolve once the registrar has taken it; reject when the
   * registration failed, with a `TimeoutError` after `timeoutMs`.
   */
  registered(timeoutMs = 10000): Promise<void> {
    const settled = within(
      new Promise<void>((resolve, reject) => {
        const listener = (state: number): void => {
          if (state === SipralRegistrationState.Registered) {
            this.off('registration', listener);
            resolve();
          } else if (state === SipralRegistrationState.Failed) {
            this.off('registration', listener);
            reject(new Error(`sipral: ${this.aor} did not register`));
          }
        };
        this.on('registration', listener);
      }),
      timeoutMs,
      `${this.aor} registering`,
    );
    this.register();
    return settled;
  }

  /** Remove the binding (`sipral_account_unregister`): a REGISTER with `Expires: 0`. */
  unregister(): void {
    this.stack.ensureOpen();
    this.wantsRegistration = false;
    checkNow(this.stack.sipral, 'sipral_account_unregister', () =>
      this.stack.sipral.sipral_account_unregister(this.stack.handle, this.handle, this.stack.nowMs()),
    );
    this.stack.poll();
  }

  /**
   * `sipral_account_refresh_binding`: register again now rather than at the
   * refresh, keeping everything else -- what a push that woke the
   * application asks for.
   */
  refreshBinding(): void {
    this.stack.ensureOpen();
    checkNow(this.stack.sipral, 'sipral_account_refresh_binding', () =>
      this.stack.sipral.sipral_account_refresh_binding(this.stack.handle, this.handle, this.stack.nowMs()),
    );
    this.stack.poll();
  }

  /**
   * `sipral_account_set_access_token`: the OAuth 2.0 access token the
   * account's server asked for (RFC 8898), in place of any it had; null
   * takes it away. The answer to `TokenRequired`, whose fields name the
   * `authzServer` to fetch one from and the `scope` it must carry -- check
   * the server against the ones the application trusts first. From the next
   * request on, the server's `Bearer` challenge is answered with it; a
   * registration that failed for want of one starts again with
   * {@link register}. `SipralStatus.InvalidArgument` for a token that is not
   * RFC 6750's `b64token`, with nothing changed.
   */
  setAccessToken(token: string | null): void {
    const [bytes, length] = text(token ?? '');
    check(
      this.stack.sipral,
      'sipral_account_set_access_token',
      this.stack.sipral.sipral_account_set_access_token(this.stack.handle, this.handle, bytes, length),
    );
  }

  /**
   * `sipral_account_check_certificate`: the verdict of this account's
   * `tlsPin` on `certificate` (the DER of the leaf a server presented), from
   * the application's own certificate check. A {@link PinnedCertificate} when
   * it is the pinned one; null when the account pins nothing; a
   * `SipralError` with `CertificateRefused` when it pins another.
   */
  checkCertificate(certificate: Buffer, unixSeconds = Math.floor(Date.now() / 1000)): PinnedCertificate | null {
    const out = record('sipral_pinned_certificate_t');
    checkNow(this.stack.sipral, 'sipral_account_check_certificate', () =>
      this.stack.sipral.sipral_account_check_certificate(
        this.stack.handle,
        this.handle,
        certificate,
        certificate.length,
        unixSeconds,
        out,
      ),
    );
    const read = plain(out, 'sipral_pinned_certificate_t');
    if (read.pinned === 0) {
      return null;
    }
    return {
      notBefore: read.notBefore as number,
      notAfter: read.notAfter as number,
      expired: read.expired !== 0,
      notYetValid: read.notYetValid !== 0,
    };
  }

  /**
   * `sipral_account_rebind`: point this account at `remote` (the address it
   * has when left out) and be reachable at `contact` (its user at the
   * stack's current address when left out). The next REGISTER uses both.
   */
  rebind(options: { remote?: string; contact?: string } = {}): void {
    const [remote, remoteLength] = text(options.remote ?? this.registrarAddress);
    const [contact, contactLength] = text(options.contact ?? this.stack.defaultContact(this.aor, null, this.contactParameters));
    checkNow(this.stack.sipral, 'sipral_account_rebind', () =>
      this.stack.sipral.sipral_account_rebind(
        this.stack.handle,
        this.handle,
        SIPRAL_TRANSPORT_MAIN,
        remote,
        remoteLength,
        contact,
        contactLength,
        this.stack.nowMs(),
      ),
    );
    if (options.remote !== undefined) {
      this.registrarAddress = options.remote;
    }
    this.stack.poll();
  }

  /** `sipral_account_retarget`: send this account's requests to `registrarAddress` from now on. */
  retarget(registrarAddress: string): void {
    const [address, length] = text(registrarAddress);
    checkNow(this.stack.sipral, 'sipral_account_retarget', () =>
      this.stack.sipral.sipral_account_retarget(this.stack.handle, this.handle, address, length, this.stack.nowMs()),
    );
    this.registrarAddress = registrarAddress;
    this.stack.poll();
  }

  /**
   * `sipral_account_subscribe`: watch `target` (a SIP URI) through the event
   * package `eventPackage` -- `presence`, `conference`, `dialog`,
   * `message-summary`... What the notifier says arrives on the stack's
   * events naming the subscription's handle.
   */
  subscribe(target: string, eventPackage: string, options: SubscribeOptions = {}): Subscription {
    this.stack.ensureOpen();
    const made = config('sipral_subscribe_config_t', { ...options, target, package: eventPackage });
    const out = new BigUint64Array(1);
    checkNow(this.stack.sipral, 'sipral_account_subscribe', () =>
      this.stack.sipral.sipral_account_subscribe(this.stack.handle, this.handle, made, out, this.stack.nowMs()),
    );
    this.stack.poll();
    return new Subscription(this.stack, out[0] ?? 0n, eventPackage);
  }

  /**
   * Watch a presentity's presence (RFC 3856): {@link subscribe} to the
   * `presence` package. Each document arrives as `PresenceChanged`.
   */
  watchPresence(target: string, options: Omit<SubscribeOptions, 'accept'> = {}): Subscription {
    return this.subscribe(target, 'presence', options);
  }

  /**
   * `sipral_account_publish_presence`: publish this account's presence (RFC
   * 3903) -- `basic` a `SipralBasic` value, an RPID `activity`
   * (`SipralActivity.None` publishes no person) and a one-line `note`. The
   * first call publishes and every later one modifies the same publication,
   * which the stack keeps refreshed until {@link unpublishPresence};
   * `PresenceChanged` says what the compositor did with it.
   */
  publishPresence(basic: number, activity: number = SipralActivity.None, note?: string): void {
    this.stack.ensureOpen();
    const made = config('sipral_presence_t', { basic, activity, note });
    checkNow(this.stack.sipral, 'sipral_account_publish_presence', () =>
      this.stack.sipral.sipral_account_publish_presence(this.stack.handle, this.handle, made, this.stack.nowMs()),
    );
    this.stack.poll();
  }

  /** Take the published presence away (RFC 3903 §4.5); `WrongState` when nothing was published. */
  unpublishPresence(): void {
    this.stack.ensureOpen();
    checkNow(this.stack.sipral, 'sipral_account_unpublish_presence', () =>
      this.stack.sipral.sipral_account_unpublish_presence(this.stack.handle, this.handle, this.stack.nowMs()),
    );
    this.stack.poll();
  }

  /**
   * `sipral_account_message`: send a MESSAGE (RFC 3428) to `target`, its body
   * of `contentType` (`text/plain` by default). The answer arrives as
   * `MessageSent` naming the handle returned in its `message` field.
   */
  sendMessage(target: string, body: string | Buffer, contentType = 'text/plain'): bigint {
    this.stack.ensureOpen();
    const [to, toLength] = text(target);
    const [type, typeLength] = text(contentType);
    const bytes = Buffer.from(body);
    const out = new BigUint64Array(1);
    checkNow(this.stack.sipral, 'sipral_account_message', () =>
      this.stack.sipral.sipral_account_message(
        this.stack.handle,
        this.handle,
        to,
        toLength,
        type,
        typeLength,
        bytes,
        bytes.length,
        out,
        this.stack.nowMs(),
      ),
    );
    this.stack.poll();
    return out[0] ?? 0n;
  }

  /**
   * `sipral_account_announce`: a push said a call from `caller` is on its
   * way; the stack waits for its INVITE (`CallAnnounced`, or
   * `AnnouncedCallMissing` when none comes). Returns the announcement's
   * handle and the call handle the INVITE will carry.
   */
  announce(caller: string): { announcement: bigint; call: bigint } {
    this.stack.ensureOpen();
    const [who, length] = text(caller);
    const announcement = new BigUint64Array(1);
    const call = new BigUint64Array(1);
    checkNow(this.stack.sipral, 'sipral_account_announce', () =>
      this.stack.sipral.sipral_account_announce(this.stack.handle, this.handle, who, length, announcement, call, this.stack.nowMs()),
    );
    this.stack.poll();
    return { announcement: announcement[0] ?? 0n, call: call[0] ?? 0n };
  }

  /** `sipral_account_push_echo`: what the registrar said about the push binding. */
  pushEcho(): PushEcho {
    const out = record('sipral_push_echo_t');
    checkNow(this.stack.sipral, 'sipral_account_push_echo', () =>
      this.stack.sipral.sipral_account_push_echo(this.stack.handle, this.handle, out),
    );
    const read = plain(out, 'sipral_push_echo_t');
    return {
      accepted: read.accepted !== 0,
      refreshLeadMs: read.hasRefreshLead !== 0 ? (read.refreshLeadMs as number) : null,
    };
  }

  /**
   * `sipral_account_freeze`: the account's registration as a snapshot, for a
   * process about to be suspended; {@link thaw} takes it back in the next.
   */
  freeze(): Buffer {
    const sipral = this.stack.sipral;
    const length = new BigUint64Array(1);
    let room = 4096;
    for (;;) {
      const buffer = Buffer.alloc(room);
      const status = sipral.sipral_account_freeze(this.stack.handle, this.handle, buffer, room, length, this.stack.nowMs());
      if (status === SipralStatus.BufferTooSmall && Number(length[0]) > room) {
        room = Number(length[0]);
        continue;
      }
      check(sipral, 'sipral_account_freeze', status);
      return Buffer.from(buffer.subarray(0, Number(length[0])));
    }
  }

  /** `sipral_account_thaw`: take back a {@link freeze} snapshot, after `asleepMs` asleep. */
  thaw(snapshot: Buffer, asleepMs: number): void {
    checkNow(this.stack.sipral, 'sipral_account_thaw', () =>
      this.stack.sipral.sipral_account_thaw(this.stack.handle, this.handle, snapshot, snapshot.length, asleepMs, this.stack.nowMs()),
    );
    this.stack.poll();
  }

  /** `sipral_account_time_to_ready`: how long until the account can take a call, or null when it cannot say. */
  timeToReady(): number | null {
    const has = new Uint32Array(1);
    const ms = new BigUint64Array(1);
    checkNow(this.stack.sipral, 'sipral_account_time_to_ready', () =>
      this.stack.sipral.sipral_account_time_to_ready(this.stack.handle, this.handle, has, ms),
    );
    return has[0] !== 0 ? Number(ms[0]) : null;
  }

  /** Forget the account (`sipral_account_remove`); every call it placed ends. */
  remove(): void {
    this.stack.ensureOpen();
    check(this.stack.sipral, 'sipral_account_remove', this.stack.sipral.sipral_account_remove(this.stack.handle, this.handle));
    this.stack.forgetAccount(this);
    this.removeAllListeners();
  }

  /** @internal Whether its connection of its own speaks TLS. */
  get overTls(): boolean {
    return this.streamProtocol === SipralTransport.Tls || this.streamProtocol === SipralTransport.Wss;
  }

  /** @internal What the stack hands each event about this account to. */
  deliver(event: StackEvent): void {
    if (event.registrationState !== null) {
      this.emit('registration', event.registrationState, event);
    }
    this.emit('event', event);
  }
}
