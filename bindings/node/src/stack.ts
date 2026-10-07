// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// One `sipral_stack_create` handle, its signalling socket and its poll.

import { randomBytes } from 'node:crypto';
import { type Socket, createSocket } from 'node:dgram';
import { EventEmitter, on } from 'node:events';
import { isIP } from 'node:net';
import { performance } from 'node:perf_hooks';

import koffi from 'koffi';

import { Account } from './account.js';
import { Call } from './call.js';
import { StackEvent } from './events.js';
import {
  ADDRESS_BYTES,
  PACKET_BYTES,
  SipralError,
  check,
  checkNow,
  formatAddress,
  handle,
  library,
  parseAddress,
  read,
  record,
  retryingClockBehind,
  text,
  toggle,
  within,
} from './internal.js';
import { MediaPacket } from './media.js';
import {
  SIPRAL_TRANSPORT_MAIN,
  type Pointer,
  Sipral,
  SipralAudio,
  SipralEventKind,
  SipralHeldAudio,
  SipralStatus,
  type SipralTransmit,
  SipralTransport,
  sipral_event_callback_t,
} from './sipral_abi.js';

/** How a stack is opened: every field may be left out. */
export interface StackOptions {
  /**
   * The address the signalling socket binds. Left out, it listens on every
   * interface and the stack advertises the route toward its first
   * account's server (`sipral_advertised_address`).
   */
  bindHost?: string;
  /** The port, 0 for any. */
  bindPort?: number;
  /** What `User-Agent` and `Server` say. */
  userAgent?: string;
  /** The library to use; `Sipral.open()`'s by default. */
  library?: Sipral;
  /** A `SipralSrtp` value: whether calls offer and take SRTP. */
  srtp?: number;
  /** Whether a REFER outside any dialog is taken to the application (`Referral`) rather than refused 403. */
  referrals?: boolean;
  /** A `SipralHeldAudio` value: what a party this end holds is sent. */
  heldAudio?: number;
  /** The most calls the stack holds at once, either way (0 for 128). */
  maxDialogs?: number;
  /** The most requests from other ends it works on at once (0 for 256). */
  maxServerTransactions?: number;
  /** The codecs every call offers, most preferred first: `'PCMA,PCMU'`. */
  codecs?: string;
}

/** How an account is added. */
export interface AccountOptions {
  /** Where its requests go, `host:port`. */
  registrarAddress: string;
  /** The registrar's URI; without one the account never registers. */
  registrar?: string;
  /** Where the account is reached; by default its user at this stack's address. */
  contact?: string;
  /** Who it answers a challenge as. */
  authUser?: string;
  /** The password it answers a challenge with. */
  authPassword?: string;
  /** The name `From` carries. */
  displayName?: string;
  /** The realms the password answers (RFC 3261 §22.1); empty for the server's own. */
  realms?: string[];
}

/** How a call is placed or answered. */
export interface CallOptions {
  /** Where the call's media socket binds; by default the route toward the far end. */
  mediaHost?: string;
  /** Send the INVITE here rather than to the account's registrar address. */
  destination?: string;
  /** What this call offers or takes, in place of the stack's: `'PCMA,PCMU'`. */
  codecs?: string;
}

/** What a stack emits. */
export interface StackEvents {
  /** Every event the stack raises, in order. */
  event: [StackEvent];
  /** An error thrown by a listener, or met on a socket. */
  error: [Error];
}

/** Bind `socket` and resolve with its port. */
function bind(socket: Socket, host: string, port: number): Promise<number> {
  return new Promise((resolve, reject) => {
    const failed = (error: Error): void => reject(error);
    socket.once('error', failed);
    socket.bind(port, host, () => {
      socket.off('error', failed);
      resolve(socket.address().port);
    });
  });
}

/** A UDP socket of the family `host` is in. */
function udp(host: string): Socket {
  return createSocket(isIP(host) === 6 ? 'udp6' : 'udp4');
}

/**
 * The address of this machine's route toward `peer` -- what a server at
 * `peer` reaches it at (`sipral_advertised_address`) -- or `127.0.0.1` for
 * a peer that is not an address literal.
 */
export function routeHost(peer: string | null | undefined, sipral: Sipral = library()): string {
  if (!peer || parseAddress(peer) === null) {
    return '127.0.0.1';
  }
  const [bound, boundLength] = text(peer.startsWith('[') ? '[::]:0' : '0.0.0.0:0');
  const [far, farLength] = text(peer);
  const buffer = Buffer.alloc(ADDRESS_BYTES);
  const needed = new BigUint64Array(1);
  const status = sipral.sipral_advertised_address(bound, boundLength, far, farLength, buffer, buffer.length, needed);
  if (status !== SipralStatus.Ok) {
    return '127.0.0.1';
  }
  const advertised = buffer.toString('utf8', 0, Math.max(0, Number(needed[0]) - 1));
  const colon = advertised.lastIndexOf(':');
  const host = advertised.slice(0, colon);
  return host.startsWith('[') ? host.slice(1, -1) : host;
}

/**
 * A SIP stack on one UDP socket: the class an application opens first.
 *
 * {@link Stack.open} binds the socket and creates the stack in application
 * mode, where this package carries each call's PCM; {@link close} hangs up
 * what is still up, destroys the stack exactly once and closes every socket
 * this package opened. Everything runs on the thread that opened it: the
 * library calls the event callback from inside `sipral_stack_poll`, the
 * callback only copies the event out, and the copies are delivered once the
 * poll has returned.
 */
export class Stack extends EventEmitter<StackEvents> {
  /** The library. */
  readonly sipral: Sipral;

  private stackHandle = 0n;
  private address: string;
  private readonly socket: Socket;
  private readonly routes: boolean;
  private routeChosen = false;
  private readonly started = performance.now();
  private readonly calls = new Map<bigint, Call>();
  private readonly accounts = new Map<bigint, Account>();
  private readonly pending: StackEvent[] = [];
  private delivering = false;
  private closed = false;
  private callback: bigint | null = null;
  private ticker: NodeJS.Timeout | undefined;
  private readonly result = record('sipral_poll_result_t');
  private readonly transmitData = Buffer.alloc(PACKET_BYTES);
  private readonly transmitTo = Buffer.alloc(ADDRESS_BYTES);
  private readonly transmit = record('sipral_transmit_t');
  private readonly farewell = new MediaPacket();
  private readonly farewellCall = new BigUint64Array(1);

  private constructor(sipral: Sipral, socket: Socket, address: string, routes: boolean) {
    super();
    this.sipral = sipral;
    this.socket = socket;
    this.address = address;
    this.routes = routes;
  }

  /**
   * Bind a socket and create a stack on it, in application mode: this
   * package carries each call's PCM.
   */
  static async open(options: StackOptions = {}): Promise<Stack> {
    for (const [name, value] of [
      ['maxDialogs', options.maxDialogs ?? 0],
      ['maxServerTransactions', options.maxServerTransactions ?? 0],
    ] as const) {
      if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) {
        throw new RangeError(`${name} is 0 to 4294967295`);
      }
    }
    const sipral = options.library ?? library();
    const host = options.bindHost ?? '0.0.0.0';
    const socket = udp(host);
    let port: number;
    try {
      port = await bind(socket, host, options.bindPort ?? 0);
    } catch (error) {
      socket.close();
      throw error;
    }
    const routes = options.bindHost === undefined;
    const stack = new Stack(sipral, socket, formatAddress(routes ? '127.0.0.1' : host, port), routes);
    try {
      stack.create(options);
    } catch (error) {
      stack.release();
      socket.close();
      throw error;
    }
    stack.start();
    return stack;
  }

  /** The stack's handle. */
  get handle(): bigint {
    return this.stackHandle;
  }

  /**
   * Where the signalling socket is reached, `host:port`: what every `Via`
   * this stack writes carries, and where another stack reaches it.
   */
  get bindAddress(): string {
    return this.address;
  }

  /** Milliseconds since the stack was created: what every `now_ms` is measured in. */
  nowMs(): number {
    return Math.floor(performance.now() - this.started);
  }

  /** Every event the stack raises from now on, as an async iterator. */
  events(options: { signal?: AbortSignal } = {}): AsyncIterableIterator<StackEvent> {
    const iterator = on(this, 'event', options) as AsyncIterableIterator<[StackEvent]>;
    return (async function* () {
      for await (const [event] of iterator) {
        yield event;
      }
    })();
  }

  /**
   * The next event that `matches`, or a `TimeoutError` after `timeoutMs`.
   * Listening starts at once, so nothing raised after this returns is
   * missed.
   */
  next(matches: (event: StackEvent) => boolean, timeoutMs = 15000): Promise<StackEvent> {
    return within(
      new Promise<StackEvent>((resolve) => {
        const listener = (event: StackEvent): void => {
          if (matches(event)) {
            this.off('event', listener);
            resolve(event);
          }
        };
        this.on('event', listener);
      }),
      timeoutMs,
      'the event waited for on the stack',
    );
  }

  /**
   * Add an account whose requests go to `registrarAddress`, `host:port`.
   * With `registrar` it can register there ({@link Account.register}), as
   * `authUser` with `authPassword` when challenged; without one it never
   * registers, and `registrarAddress` is only its outbound proxy.
   */
  addAccount(aor: string, options: AccountOptions): Account {
    this.ensureOpen();
    const advertised =
      options.contact === undefined && this.routes ? this.advertiseToward(options.registrarAddress) : null;
    const [aorText, aorLength] = text(aor);
    const [proxy, proxyLength] = text(options.registrarAddress);
    const [registrar, registrarLength] = text(options.registrar);
    const [contact, contactLength] = text(options.contact ?? defaultContact(aor, advertised ?? this.address));
    const [user, userLength] = text(options.authUser);
    const [password, passwordLength] = text(options.authPassword);
    const [display, displayLength] = text(options.displayName);
    const [realms, realmsLength] = text(
      options.realms === undefined || options.realms.length === 0 ? null : options.realms.join('\n'),
    );
    const config = record('sipral_account_config_t', {
      aor: aorText,
      aor_len: aorLength,
      registrar_address: proxy,
      registrar_address_len: proxyLength,
      registrar,
      registrar_len: registrarLength,
      contact,
      contact_len: contactLength,
      auth_user: user,
      auth_user_len: userLength,
      auth_password: password,
      auth_password_len: passwordLength,
      display_name: display,
      display_name_len: displayLength,
      realms,
      realms_len: realmsLength,
    });
    const out = new BigUint64Array(1);
    check(this.sipral, 'sipral_account_add', this.sipral.sipral_account_add(this.stackHandle, config, out));
    password?.fill(0);
    const account = new Account(this, handle(out[0] ?? 0n), aor, options.registrarAddress);
    this.accounts.set(account.handle, account);
    return account;
  }

  /**
   * Place a call from `account` to `target`, its media socket bound and its
   * address offered before the INVITE goes out.
   */
  async placeCall(account: Account, target: string, options: CallOptions = {}): Promise<Call> {
    this.ensureOpen();
    const media = udp(this.mediaHost(options.mediaHost, account, options.destination));
    const mediaAddress = await this.bindMedia(media, options.mediaHost, account, options.destination);
    const [targetText, targetLength] = text(target);
    const [mediaText, mediaLength] = text(mediaAddress);
    const [destination, destinationLength] = text(options.destination);
    const [codecs, codecsLength] = text(options.codecs);
    const config = record('sipral_call_config_t', {
      target: targetText,
      target_len: targetLength,
      media_address: mediaText,
      media_address_len: mediaLength,
      destination,
      destination_len: destinationLength,
      codecs,
      codecs_len: codecsLength,
    });
    const out = new BigUint64Array(1);
    try {
      checkNow(this.sipral, 'sipral_call_place', () =>
        this.sipral.sipral_call_place(this.stackHandle, account.handle, config, out, this.nowMs()),
      );
    } catch (error) {
      media.close();
      throw error;
    }
    const call = new Call(this, handle(out[0] ?? 0n), media, mediaAddress, false);
    this.calls.set(call.handle, call);
    this.poll();
    return call;
  }

  /**
   * Answer the `IncomingCall` event `incoming`, with a media socket bound by
   * default on the route toward the account's server. `codecs` is what
   * this call takes, in place of the stack's.
   */
  async answerCall(incoming: StackEvent, options: Omit<CallOptions, 'destination'> = {}): Promise<Call> {
    this.ensureOpen();
    if (incoming.kind !== SipralEventKind.IncomingCall) {
      throw new TypeError('sipral: answerCall takes an IncomingCall event');
    }
    const account = this.accounts.get(incoming.account);
    const media = udp(this.mediaHost(options.mediaHost, account, undefined));
    const mediaAddress = await this.bindMedia(media, options.mediaHost, account, undefined);
    const call = new Call(this, incoming.call, media, mediaAddress, true);
    this.calls.set(call.handle, call);
    const [mediaText, mediaLength] = text(mediaAddress);
    try {
      if (options.codecs !== undefined) {
        const [codecs, codecsLength] = text(options.codecs);
        const config = record('sipral_call_config_t', {
          media_address: mediaText,
          media_address_len: mediaLength,
          codecs,
          codecs_len: codecsLength,
        });
        checkNow(this.sipral, 'sipral_call_answer_with', () =>
          this.sipral.sipral_call_answer_with(this.stackHandle, incoming.call, config, this.nowMs()),
        );
      } else {
        checkNow(this.sipral, 'sipral_call_answer_media', () =>
          this.sipral.sipral_call_answer_media(this.stackHandle, incoming.call, mediaText, mediaLength, this.nowMs()),
        );
      }
    } catch (error) {
      this.calls.delete(call.handle);
      media.close();
      throw error;
    }
    this.poll();
    return call;
  }

  /** Refuse the `IncomingCall` event `incoming` with `code`. */
  rejectCall(incoming: StackEvent, code = 486): void {
    this.ensureOpen();
    checkNow(this.sipral, 'sipral_call_reject', () =>
      this.sipral.sipral_call_reject(this.stackHandle, incoming.call, code, this.nowMs()),
    );
    this.poll();
  }

  /**
   * Take the REFER of a `TransferRequested` (inside a call) or a `Referral`
   * (outside any) and place the call it asks for (`sipral_call_accept_transfer`):
   * the stack answers 202, reports on the new call to whoever asked, and
   * places it from the account the event names -- to `destination` when
   * given, else to the account's registrar address. A media socket is opened
   * for it here, and the {@link Call} returned is that placed call. Taking
   * one is a decision with a bill attached -- whoever sent it can make this
   * line dial anything -- so it is never made on the application's behalf.
   */
  async acceptTransfer(event: StackEvent, options: Pick<CallOptions, 'mediaHost' | 'destination'> = {}): Promise<Call> {
    this.ensureOpen();
    if (event.kind !== SipralEventKind.TransferRequested && event.kind !== SipralEventKind.Referral) {
      throw new TypeError('sipral: acceptTransfer takes a TransferRequested or a Referral event');
    }
    const account = this.accounts.get(event.account);
    const media = udp(this.mediaHost(options.mediaHost, account, options.destination));
    const mediaAddress = await this.bindMedia(media, options.mediaHost, account, options.destination);
    const [mediaText, mediaLength] = text(mediaAddress);
    const [destination, destinationLength] = text(options.destination);
    const config = record('sipral_call_config_t', {
      media_address: mediaText,
      media_address_len: mediaLength,
      destination,
      destination_len: destinationLength,
    });
    const out = new BigUint64Array(1);
    try {
      checkNow(this.sipral, 'sipral_call_accept_transfer', () =>
        this.sipral.sipral_call_accept_transfer(this.stackHandle, event.call, config, out, this.nowMs()),
      );
    } catch (error) {
      media.close();
      throw error;
    }
    const call = new Call(this, handle(out[0] ?? 0n), media, mediaAddress, false);
    this.calls.set(call.handle, call);
    this.poll();
    return call;
  }

  /** Refuse the REFER of a `TransferRequested` or a `Referral` with `code`, 300 to 699. */
  rejectTransfer(event: StackEvent, code = 603): void {
    this.ensureOpen();
    checkNow(this.sipral, 'sipral_call_reject_transfer', () =>
      this.sipral.sipral_call_reject_transfer(this.stackHandle, event.call, code, this.nowMs()),
    );
    this.poll();
  }

  /**
   * Hang up every call still up, give the goodbyes a moment to go out, then
   * destroy the stack and close every socket. Calling it again does nothing.
   */
  async close(): Promise<void> {
    if (this.closed) {
      return;
    }
    const open = [...this.calls.values()];
    let hungUp = false;
    for (const call of open) {
      if (!call.ended) {
        try {
          call.hangup();
          hungUp = true;
        } catch (error) {
          if (!(error instanceof SipralError)) {
            throw error;
          }
        }
      }
    }
    if (hungUp) {
      await new Promise((resolve) => setTimeout(resolve, 200));
    }
    for (const call of open) {
      call.close();
    }
    this.closed = true;
    clearInterval(this.ticker);
    this.sipral.sipral_stack_destroy(this.stackHandle);
    this.release();
    await new Promise<void>((resolve) => this.socket.close(() => resolve()));
    this.removeAllListeners('event');
  }

  /** @internal Throw unless the stack is open. */
  ensureOpen(): void {
    if (this.closed) {
      throw new Error('sipral: the stack is closed');
    }
  }

  /** @internal Run the stack: its timers, what it sends, what it raised. */
  poll(): void {
    if (this.closed) {
      return;
    }
    this.result.set(record('sipral_poll_result_t'));
    if (this.sipral.sipral_stack_poll(this.stackHandle, this.nowMs(), this.result) === SipralStatus.Ok) {
      this.drainTransmit();
      this.drainFarewells();
    }
    this.deliver();
  }

  /** @internal Hand an error to `error` listeners, or let it go uncaught. */
  report(error: unknown): void {
    const failure = error instanceof Error ? error : new Error(String(error));
    if (this.listenerCount('error') > 0) {
      this.emit('error', failure);
    } else {
      queueMicrotask(() => {
        throw failure;
      });
    }
  }

  /** @internal A call closed: forgotten. */
  forget(call: Call): void {
    this.calls.delete(call.handle);
  }

  /** @internal An account removed: forgotten. */
  forgetAccount(account: Account): void {
    this.accounts.delete(account.handle);
  }

  private create(options: StackOptions): void {
    this.callback = koffi.register(
      (event: Pointer) => this.onEvent(event),
      koffi.pointer(sipral_event_callback_t),
    );
    const entropy = randomBytes(32);
    const mediaSeed = randomBytes(32);
    const [bindText, bindLength] = text(this.address);
    const [agent, agentLength] = text(options.userAgent);
    const [codecs, codecsLength] = text(options.codecs);
    const config = record('sipral_stack_config_t', {
      event_callback: this.callback,
      transport: SipralTransport.Udp,
      bind_address: bindText,
      bind_address_len: bindLength,
      user_agent: agent,
      user_agent_len: agentLength,
      entropy,
      entropy_len: entropy.length,
      media_seed: mediaSeed,
      media_seed_len: mediaSeed.length,
      // the wall clock the RTCP sender reports carry (RFC 3550 §6.4.1)
      media_clock_unix_seconds: Math.floor(Date.now() / 1000),
      audio: SipralAudio.Application,
      srtp: options.srtp ?? 0,
      referrals: toggle(options.referrals),
      held_audio: options.heldAudio ?? SipralHeldAudio.Default,
      max_dialogs: options.maxDialogs ?? 0,
      max_server_transactions: options.maxServerTransactions ?? 0,
      codecs,
      codecs_len: codecsLength,
    });
    const out = new BigUint64Array(1);
    check(this.sipral, 'sipral_stack_create', this.sipral.sipral_stack_create(config, out));
    entropy.fill(0);
    mediaSeed.fill(0);
    this.stackHandle = handle(out[0] ?? 0n);
  }

  private start(): void {
    this.socket.on('message', (data: Buffer, from: { address: string; port: number }) =>
      this.receiveSignalling(data, from),
    );
    this.socket.on('error', (error) => this.report(error));
    this.ticker = setInterval(() => {
      try {
        this.poll();
      } catch (error) {
        this.report(error);
      }
    }, 10);
  }

  private release(): void {
    if (this.callback !== null) {
      koffi.unregister(this.callback);
      this.callback = null;
    }
  }

  private receiveSignalling(data: Buffer, from: { address: string; port: number }): void {
    if (this.closed) {
      return;
    }
    const [source, sourceLength] = text(formatAddress(from.address, from.port));
    retryingClockBehind(() =>
      this.sipral.sipral_stack_receive_datagram(
        this.stackHandle,
        SIPRAL_TRANSPORT_MAIN,
        data,
        data.length,
        source,
        sourceLength,
        null,
        0,
        this.nowMs(),
      ),
    );
    this.poll();
  }

  private drainTransmit(): void {
    while (!this.closed) {
      this.transmit.set(
        record('sipral_transmit_t', {
          data: this.transmitData,
          capacity: this.transmitData.length,
          destination: this.transmitTo,
          destination_capacity: this.transmitTo.length,
        }),
      );
      if (this.sipral.sipral_stack_poll_transmit(this.stackHandle, this.transmit) !== SipralStatus.Ok) {
        return;
      }
      const sent = read<SipralTransmit>(this.transmit, 'sipral_transmit_t');
      const length = Number(sent.len);
      if (length === 0) {
        return;
      }
      const to = parseAddress(this.transmitTo.toString('utf8', 0, Number(sent.destination_len)));
      if (to !== null) {
        this.socket.send(Buffer.from(this.transmitData.subarray(0, length)), to.port, to.host);
      }
    }
  }

  /** What a call that ended still owes its far end -- its RTCP BYE -- sent from its own socket. */
  private drainFarewells(): void {
    while (!this.closed) {
      this.farewell.prepare();
      if (
        this.sipral.sipral_stack_poll_farewell(this.stackHandle, this.farewellCall, this.farewell.packet) !==
        SipralStatus.Ok
      ) {
        return;
      }
      const out = this.farewell.written();
      if (out === null) {
        return;
      }
      this.calls.get(handle(this.farewellCall[0] ?? 0n))?.sendPacket(out.payload, out.destination);
    }
  }

  /** Copy the event out; it is delivered once the poll has returned. */
  private onEvent(address: Pointer): void {
    try {
      this.pending.push(StackEvent.read(address));
    } catch (error) {
      queueMicrotask(() => this.report(error));
    }
  }

  private deliver(): void {
    if (this.delivering) {
      return;
    }
    this.delivering = true;
    try {
      let event = this.pending.shift();
      while (event !== undefined) {
        try {
          this.calls.get(event.call)?.deliver(event);
          this.accounts.get(event.account)?.deliver(event);
          this.emit('event', event);
        } catch (error) {
          this.report(error);
        }
        event = this.pending.shift();
      }
    } finally {
      this.delivering = false;
    }
  }

  /**
   * The `host:port` an account whose server is `peer` is reached at, on a
   * stack that picks its own address: the route toward the server, on this
   * stack's port. The first server named also becomes the address the
   * stack's `Via` carries.
   */
  private advertiseToward(peer: string): string {
    const port = this.address.slice(this.address.lastIndexOf(':') + 1);
    const address = formatAddress(routeHost(peer, this.sipral), Number(port));
    if (!this.routeChosen) {
      this.routeChosen = true;
      if (address !== this.address) {
        const [local, localLength] = text(address);
        checkNow(this.sipral, 'sipral_stack_transport_bind', () =>
          this.sipral.sipral_stack_transport_bind(
            this.stackHandle,
            SIPRAL_TRANSPORT_MAIN,
            SipralTransport.Udp,
            local,
            localLength,
            null,
            0,
            this.nowMs(),
            null,
          ),
        );
        this.address = address;
      }
    }
    return address;
  }

  /** Where a call's media socket binds: the host given, else the route toward the far end. */
  private mediaHost(given: string | undefined, account: Account | undefined, destination: string | undefined): string {
    if (given !== undefined) {
      return given;
    }
    for (const peer of [destination, account?.registrarAddress]) {
      if (peer !== undefined && parseAddress(peer) !== null) {
        return routeHost(peer, this.sipral);
      }
    }
    return this.address.slice(0, this.address.lastIndexOf(':')).replace(/^\[|\]$/g, '');
  }

  private async bindMedia(
    socket: Socket,
    given: string | undefined,
    account: Account | undefined,
    destination: string | undefined,
  ): Promise<string> {
    const host = this.mediaHost(given, account, destination);
    try {
      const port = await bind(socket, host, 0);
      return formatAddress(host, port);
    } catch (error) {
      socket.close();
      throw error;
    }
  }
}

/** `scheme:user@at` for `aor`, or `scheme:at` for an address of record with no user part. */
function defaultContact(aor: string, at: string): string {
  const colon = aor.indexOf(':');
  const scheme = colon < 0 ? 'sip' : aor.slice(0, colon);
  const rest = colon < 0 ? aor : aor.slice(colon + 1);
  const user = rest.indexOf('@');
  return user < 0 ? `${scheme}:${at}` : `${scheme}:${rest.slice(0, user)}@${at}`;
}
