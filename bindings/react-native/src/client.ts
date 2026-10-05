// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// The API an application writes against: a client, its accounts and its
// calls, each with the state the native events last reported and a typed
// emitter. What a call cannot do in the state it is in is refused here,
// before anything crosses to native code, with the same `wrongState` the
// library would answer -- so a button pressed twice, or after the far end
// hung up, is one rejected promise and not a request sent into a call that
// is gone.

import type {EventSubscription} from 'react-native';
import type {NativeEvent, Spec} from './NativeSipral';
import {SipralError, fromNative} from './errors';
import {TypedEmitter} from './emitter';
import type {Subscription} from './emitter';
import {pinDigest} from './pin';
import type {
  AccountOptions,
  AppRate,
  AudioDirection,
  CallAudio,
  CallDirection,
  CallState,
  ChallengeRefusal,
  EndReason,
  LocateFailure,
  OpenOptions,
  PlaceCallOptions,
  RegistrationFailure,
  RegistrationState,
  Settings,
  Signalling,
} from './types';

export interface RegistrationChangedEvent {
  account: SipralAccount;
  state: RegistrationState;
  /** The registrar's final answer, or zero. */
  statusCode: number;
  /** When the next attempt goes, for "retrying"; zero otherwise. */
  retryInMs: number;
  /** Why it failed -- "unreachableContact" for a Contact the registrar cannot reach -- or "none". */
  failure: RegistrationFailure;
}

export interface LocatedEvent {
  account: SipralAccount;
  /** Every address the server was located at, the one in use first. */
  targets: string[];
}

export interface LocateFailedEvent {
  account: SipralAccount;
  failure: LocateFailure;
  /** When the name is looked up again. */
  retryInMs: number;
}

export interface ChallengeDeclinedEvent {
  account: SipralAccount;
  /** Why the password was not given. */
  refusal: ChallengeRefusal;
  /** Where the challenged request went, host:port. */
  server: string;
  /** The realms it was challenged for. */
  realms: string[];
}

export interface IncomingCallEvent {
  call: SipralCall;
  from: string;
  fromDisplay: string;
  to: string;
}

export interface CallStateEvent {
  call: SipralCall;
  state: CallState;
  /** A provisional or final response, where the event carries one; zero otherwise. */
  statusCode: number;
}

export interface CallEndedEvent {
  call: SipralCall;
  reason: EndReason;
  statusCode: number;
}

export interface HoldChangedEvent {
  call: SipralCall;
  /** This end put the call on hold. */
  heldHere: boolean;
  /** The far end put the call on hold. */
  heldThere: boolean;
}

export interface TransferRequestedEvent {
  call: SipralCall;
  /** Who the far end asks this end to call. */
  target: string;
  /** Whether it names a call to replace, which makes it attended rather than blind. */
  attended: boolean;
}

export interface TransferReportEvent {
  call: SipralCall;
  /** What the call placed to the transfer's target is doing. */
  statusCode: number;
}

export interface DigitEvent {
  call: SipralCall;
  digit: string;
}

/** Everything a client's emitter carries. */
export interface ClientEvents {
  registrationChanged: RegistrationChangedEvent;
  incomingCall: IncomingCallEvent;
  callProgress: CallStateEvent;
  callConfirmed: CallStateEvent;
  holdChanged: HoldChangedEvent;
  callEnded: CallEndedEvent;
  transferRequested: TransferRequestedEvent;
  transferProgress: TransferReportEvent;
  transferDone: TransferReportEvent;
  digitReceived: DigitEvent;
  located: LocatedEvent;
  locateFailed: LocateFailedEvent;
  challengeDeclined: ChallengeDeclinedEvent;
  /** Every event, typed or not, as the native half handed it over. */
  event: NativeEvent;
}

/** What one call's own emitter carries: the client's, for this call only. */
export interface CallEvents {
  progress: CallStateEvent;
  confirmed: CallStateEvent;
  holdChanged: HoldChangedEvent;
  ended: CallEndedEvent;
  transferRequested: TransferRequestedEvent;
  transferProgress: TransferReportEvent;
  transferDone: TransferReportEvent;
  digit: DigitEvent;
}

/** What one account's own emitter carries. */
export interface AccountEvents {
  registrationChanged: RegistrationChangedEvent;
  located: LocatedEvent;
  locateFailed: LocateFailedEvent;
  challengeDeclined: ChallengeDeclinedEvent;
}

const DTMF = /^[0-9A-Da-d*#]+$/;

/** The SRTP suites by their `SipralSrtpSuite` numbers, as RFC 4568 and RFC 7714 name them. */
const SUITES = [
  'unknown',
  'AES_CM_128_HMAC_SHA1_80',
  'AES_CM_128_HMAC_SHA1_32',
  'F8_128_HMAC_SHA1_80',
  'AES_256_CM_HMAC_SHA1_80',
  'AES_256_CM_HMAC_SHA1_32',
  'AEAD_AES_128_GCM',
  'AEAD_AES_256_GCM',
];

function suiteName(number: number): string {
  return SUITES[number] ?? `suite ${number}`;
}

function audioDirection(direction: string): void {
  if (direction !== 'input' && direction !== 'output') {
    throw new SipralError('invalidArgument', 'a direction is "input" or "output"');
  }
}

async function crossing<T>(action: () => Promise<T>): Promise<T> {
  try {
    return await action();
  } catch (failure) {
    throw fromNative(failure);
  }
}

export class SipralAccount {
  private readonly emitter = new TypedEmitter<AccountEvents>();
  private removed = false;
  private state: RegistrationState = 'idle';

  /** @internal Made by `SipralClient.addAccount`. */
  constructor(
    private readonly client: SipralClient,
    /** The library's handle, as the native half named it. */
    readonly id: string,
    readonly aor: string,
  ) {}

  /** What the last registration event said. */
  get registrationState(): RegistrationState {
    return this.state;
  }

  on<K extends keyof AccountEvents>(name: K, listener: (payload: AccountEvents[K]) => void): Subscription {
    return this.emitter.on(name, listener);
  }

  register(): Promise<void> {
    return this.client.run(() => this.usable(), (native) => native.register(this.id));
  }

  unregister(): Promise<void> {
    return this.client.run(() => this.usable(), (native) => native.unregister(this.id));
  }

  /**
   * Resolve once the account is registered, reject with the event that
   * said it will not be. Registering is asked for here too.
   */
  registerAndWait(timeoutMs = 30_000): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => {
        subscription.remove();
        reject(new SipralError('wrongState', `${this.aor} was not registered within ${timeoutMs} ms`));
      }, timeoutMs);
      const subscription = this.on('registrationChanged', (event) => {
        if (event.state === 'registered' || event.state === 'restored') {
          clearTimeout(timer);
          subscription.remove();
          resolve();
        } else if (event.state === 'failed' || event.state === 'unverified') {
          clearTimeout(timer);
          subscription.remove();
          reject(new SipralError('wrongState', `${this.aor} registration ${event.state}, ${event.statusCode}`));
        }
      });
      this.register().catch((failure: unknown) => {
        clearTimeout(timer);
        subscription.remove();
        reject(failure);
      });
    });
  }

  async remove(): Promise<void> {
    await this.client.run(() => this.usable(), (native) => native.removeAccount(this.id));
    this.removed = true;
    this.client.forgetAccount(this.id);
    this.emitter.removeAllListeners();
  }

  /** @internal */
  deliver(event: RegistrationChangedEvent): void {
    this.state = event.state;
    this.emitter.emit('registrationChanged', event);
  }

  /** @internal */
  located(event: LocatedEvent): void {
    this.emitter.emit('located', event);
  }

  /** @internal */
  locateFailed(event: LocateFailedEvent): void {
    this.emitter.emit('locateFailed', event);
  }

  /** @internal */
  challengeDeclined(event: ChallengeDeclinedEvent): void {
    this.emitter.emit('challengeDeclined', event);
  }

  private usable(): void {
    if (this.removed) {
      throw new SipralError('wrongState', `${this.aor} was removed`);
    }
  }
}

export class SipralCall {
  private readonly emitter = new TypedEmitter<CallEvents>();
  private current: CallState;
  private answered = false;
  private finished = false;
  private held = {here: false, there: false};
  private reason: EndReason | undefined;

  /** @internal Made by the client, for a call placed or one that arrived. */
  constructor(
    private readonly client: SipralClient,
    /** The library's handle, as the native half named it. */
    readonly id: string,
    readonly direction: CallDirection,
    /** Who the call is with: the target dialled, or the caller's URI. */
    public remote: string,
  ) {
    this.current = direction === 'incoming' ? 'incoming' : 'calling';
  }

  get state(): CallState {
    return this.current;
  }

  /** Whether the call has ended; nothing more can be done with it. */
  get ended(): boolean {
    return this.finished;
  }

  /** Why it ended, once it has. */
  get endReason(): EndReason | undefined {
    return this.reason;
  }

  /** Whether this end has the call on hold. */
  get heldHere(): boolean {
    return this.held.here;
  }

  /** Whether the far end has the call on hold. */
  get heldThere(): boolean {
    return this.held.there;
  }

  on<K extends keyof CallEvents>(name: K, listener: (payload: CallEvents[K]) => void): Subscription {
    return this.emitter.on(name, listener);
  }

  /**
   * The call's own audio on top of the client's: `input` is what the
   * microphone sends this call alone, `output` how loud it is in the speaker
   * beside the other calls. Mute the call being spoken about in a
   * consultation, turn one down. They last from the moment the call's audio
   * starts to its end, through a hold and back; before and after, the native
   * half refuses them as `wrongState`.
   */
  readonly audio = {
    setGain: (direction: AudioDirection, gain: number): Promise<void> =>
      this.client.run(
        () => {
          this.alive();
          audioDirection(direction);
          if (!(gain >= 0)) {
            throw new SipralError('invalidArgument', 'a gain is a factor of zero or more');
          }
        },
        (native) => native.setCallGain(this.id, direction, gain),
      ),
    setMuted: (direction: AudioDirection, muted: boolean): Promise<void> =>
      this.client.run(
        () => {
          this.alive();
          audioDirection(direction);
        },
        (native) => native.setCallMuted(this.id, direction, muted),
      ),
    read: (direction: AudioDirection): Promise<CallAudio> =>
      this.client.run(
        () => {
          this.alive();
          audioDirection(direction);
        },
        (native) => native.callAudio(this.id, direction),
      ),
    /**
     * The rate the call's frames cross the native layer at, whatever rate
     * the codec runs at: 8000, 16000, 24000 or 48000, or 0 for the codec's
     * own. Resolves with the rate and the length of one frame there, which
     * keeps the call's duration. It is for a call whose frames the
     * application carries; on the phone's own devices the native half
     * refuses it as `wrongState`.
     */
    setAppRate: (hz: number): Promise<AppRate> =>
      this.client.run(
        () => {
          this.alive();
          if (![0, 8000, 16000, 24000, 48000].includes(hz)) {
            throw new SipralError('invalidArgument', 'an application rate is 8000, 16000, 24000 or 48000, or 0');
          }
        },
        (native) => native.setAppRate(this.id, hz),
      ),
  };

  /** Answer a call that arrived. The audio runs on the phone's own devices. */
  async answer(): Promise<void> {
    await this.client.run(
      () => {
        this.alive();
        if (this.direction !== 'incoming' || this.answered) {
          throw new SipralError('wrongState', `call ${this.id} is not waiting to be answered`);
        }
      },
      (native) => native.answer(this.id),
    );
    this.answered = true;
  }

  /** Turn away a call that arrived, with a final response: 486 Busy Here unless said otherwise. */
  async reject(code = 486): Promise<void> {
    await this.client.run(
      () => {
        this.alive();
        if (this.direction !== 'incoming' || this.answered) {
          throw new SipralError('wrongState', `call ${this.id} is not waiting to be answered`);
        }
        if (!Number.isInteger(code) || code < 300 || code > 699) {
          throw new SipralError('invalidArgument', `${code} is not a final refusal, 300 to 699`);
        }
      },
      (native) => native.reject(this.id, code),
    );
    this.answered = true;
  }

  /** End the call, in whatever state it is: cancelled, refused or hung up. */
  hangup(): Promise<void> {
    return this.client.run(() => this.alive(), (native) => native.hangup(this.id));
  }

  hold(): Promise<void> {
    return this.client.run(() => this.established(), (native) => native.hold(this.id));
  }

  resume(): Promise<void> {
    return this.client.run(() => this.established(), (native) => native.resume(this.id));
  }

  /**
   * A blind transfer: ask the far end to call `target` instead. This end
   * stays in the call until "transferDone" says how it went.
   */
  transfer(target: string): Promise<void> {
    return this.client.run(
      () => {
        this.established();
        if (target.trim() === '') {
          throw new SipralError('invalidArgument', 'a transfer needs a target');
        }
      },
      (native) => native.transfer(this.id, target),
    );
  }

  /**
   * Take a transfer the far end asked for ("transferRequested"): the call it
   * asks for is placed, and is what this resolves with.
   */
  async acceptTransfer(): Promise<SipralCall> {
    const placed = await this.client.run(() => this.alive(), (native) => native.acceptTransfer(this.id));
    return this.client.callFor(placed, 'outgoing', '');
  }

  /** Refuse a transfer the far end asked for, 603 Decline unless said otherwise. */
  rejectTransfer(code = 603): Promise<void> {
    return this.client.run(
      () => {
        this.alive();
        if (!Number.isInteger(code) || code < 300 || code > 699) {
          throw new SipralError('invalidArgument', `${code} is not a final refusal, 300 to 699`);
        }
      },
      (native) => native.rejectTransfer(this.id, code),
    );
  }

  /** Send DTMF: 0-9, A-D, * and #, in the audio's own events (RFC 4733). */
  sendDtmf(digits: string): Promise<void> {
    return this.client.run(
      () => {
        this.established();
        if (!DTMF.test(digits)) {
          throw new SipralError('invalidArgument', `"${digits}" has a character no keypad has`);
        }
      },
      (native) => native.sendDtmf(this.id, digits),
    );
  }

  /** @internal */
  deliver(event: NativeEvent): void {
    switch (event.kind) {
      case 'callProgress':
      case 'callConfirmed': {
        const state = (event.callState as CallState | undefined) ?? (event.kind === 'callConfirmed' ? 'confirmed' : this.current);
        this.current = state;
        const payload = {call: this, state, statusCode: event.statusCode ?? 0};
        this.emitter.emit(event.kind === 'callConfirmed' ? 'confirmed' : 'progress', payload);
        this.client.emit(event.kind, payload);
        break;
      }
      case 'sessionChanged': {
        const here = event.heldHere ?? this.held.here;
        const there = event.heldThere ?? this.held.there;
        if (event.callState !== undefined) {
          this.current = event.callState as CallState;
        }
        if (here !== this.held.here || there !== this.held.there) {
          this.held = {here, there};
          const payload = {call: this, heldHere: here, heldThere: there};
          this.emitter.emit('holdChanged', payload);
          this.client.emit('holdChanged', payload);
        }
        break;
      }
      case 'callEnded': {
        this.finished = true;
        this.current = 'terminated';
        this.reason = (event.endReason as EndReason | undefined) ?? 'none';
        const payload = {call: this, reason: this.reason, statusCode: event.statusCode ?? 0};
        this.emitter.emit('ended', payload);
        this.client.emit('callEnded', payload);
        this.emitter.removeAllListeners();
        break;
      }
      case 'transferRequested': {
        const payload = {call: this, target: event.target ?? '', attended: event.attended ?? false};
        this.emitter.emit('transferRequested', payload);
        this.client.emit('transferRequested', payload);
        break;
      }
      case 'transferProgress':
      case 'transferDone': {
        const payload = {call: this, statusCode: event.statusCode ?? 0};
        this.emitter.emit(event.kind, payload);
        this.client.emit(event.kind, payload);
        break;
      }
      case 'digitReceived': {
        if (event.digit !== undefined && event.digit !== '') {
          const payload = {call: this, digit: event.digit};
          this.emitter.emit('digit', payload);
          this.client.emit('digitReceived', payload);
        }
        break;
      }
      default:
        break;
    }
  }

  private alive(): void {
    if (this.finished) {
      throw new SipralError('wrongState', `call ${this.id} has ended`);
    }
  }

  private established(): void {
    this.alive();
    if (this.current !== 'confirmed') {
      throw new SipralError('wrongState', `call ${this.id} is ${this.current}, not confirmed`);
    }
  }
}

/**
 * One Sipral stack on the phone. There is one per application: the native
 * module holds it, and a second `open` while one is open is refused.
 */
export class SipralClient {
  private static opened: SipralClient | undefined;

  private readonly emitter = new TypedEmitter<ClientEvents>();
  private readonly accounts = new Map<string, SipralAccount>();
  private readonly calls = new Map<string, SipralCall>();
  private subscription: EventSubscription | undefined;
  private closed = false;
  private address = '';
  private signalling: Signalling = 'udp';

  private constructor(private readonly native: Spec) {}

  /**
   * Open the stack. Events are listened for before the native half is asked
   * to open, so that nothing it raises while opening is missed.
   */
  static async open(options: OpenOptions, native: Spec): Promise<SipralClient> {
    if (SipralClient.opened !== undefined) {
      throw new SipralError('wrongState', 'a client is already open; close it first');
    }
    if (options.bindHost !== undefined && (typeof options.bindHost !== 'string' || options.bindHost.trim() === '')) {
      throw new SipralError('invalidArgument', 'bindHost is the address of this phone the server can reach, or left out');
    }
    const signalling = options.signalling ?? 'udp';
    if (signalling !== 'udp' && options.signallingServer === undefined) {
      throw new SipralError('invalidArgument', `SIP over ${signalling} needs signallingServer, host:port`);
    }
    if (options.tlsPin !== undefined && signalling !== 'tls') {
      throw new SipralError('invalidArgument', 'tlsPin is the certificate a TLS connection trusts: it needs signalling "tls"');
    }
    const tlsPin = options.tlsPin === undefined ? undefined : pinDigest(options.tlsPin);
    if (options.pseudonymSalt !== undefined && !/^([0-9a-fA-F]{2}){16,}$/.test(options.pseudonymSalt)) {
      throw new SipralError('invalidArgument', 'pseudonymSalt is at least 16 bytes, as hexadecimal');
    }
    if (options.heldAudio !== undefined && options.heldAudio !== 'silence' && options.heldAudio !== 'application') {
      throw new SipralError('invalidArgument', 'heldAudio is "silence" or "application"');
    }
    for (const [name, value] of [['maxDialogs', options.maxDialogs], ['maxServerTransactions', options.maxServerTransactions]] as const) {
      if (value !== undefined && !(Number.isInteger(value) && value >= 0 && value <= 0xffffffff)) {
        throw new SipralError('invalidArgument', `${name} is a whole number from 0 to 4294967295`);
      }
    }
    const client = new SipralClient(native);
    client.signalling = signalling;
    SipralClient.opened = client;
    client.subscription = native.onEvent((event) => client.dispatch(event));
    try {
      client.address = await native.open({
        bindHost: options.bindHost,
        bindPort: options.bindPort,
        userAgent: options.userAgent,
        codecs: options.codecs,
        signalling,
        signallingServer: options.signallingServer,
        stunServer: options.stunServer,
        manualAudio: options.audioActivation === 'manual',
        srtp: options.srtp,
        srtpSuites: options.srtpSuites === undefined ? undefined : options.srtpSuites.join(','),
        pathMtu: options.pathMtu,
        datagramWithoutStreamBytes: options.datagramWithoutStreamBytes,
        pseudonymSalt: options.pseudonymSalt,
        diagnosticTrace: options.diagnosticTrace,
        tlsPin,
        systemEchoCancellation: options.systemEchoCancellation,
        heldAudio: options.heldAudio,
        maxDialogs: options.maxDialogs,
        maxServerTransactions: options.maxServerTransactions,
      });
    } catch (failure) {
      client.release();
      throw fromNative(failure);
    }
    return client;
  }

  /** The address the stack signals from, as the native half bound it. */
  get bindAddress(): string {
    return this.address;
  }

  get isClosed(): boolean {
    return this.closed;
  }

  on<K extends keyof ClientEvents>(name: K, listener: (payload: ClientEvents[K]) => void): Subscription {
    return this.emitter.on(name, listener);
  }

  once<K extends keyof ClientEvents>(name: K, listener: (payload: ClientEvents[K]) => void): Subscription {
    return this.emitter.once(name, listener);
  }

  async addAccount(options: AccountOptions): Promise<SipralAccount> {
    let tlsPin: string | undefined;
    const id = await this.run(
      () => {
        if (options.aor.trim() === '') {
          throw new SipralError('invalidArgument', 'an account needs its aor');
        }
        const named = [options.registrarAddress, options.serverUri].filter((one) => one !== undefined && one.trim() !== '');
        if (named.length !== 1) {
          throw new SipralError('invalidArgument', 'an account names its server by registrarAddress or by serverUri, one of the two');
        }
        if (options.streamProtocol !== undefined && options.streamProtocol !== 'tcp' && options.streamProtocol !== 'tls') {
          throw new SipralError('invalidArgument', 'streamProtocol is "tcp" or "tls"');
        }
        if (options.streamProtocol !== undefined && this.signalling !== 'udp') {
          throw new SipralError('invalidArgument', 'an account on a connection of its own sits beside a client signalling over "udp"');
        }
        if (options.tlsPin !== undefined && options.streamProtocol !== 'tls') {
          throw new SipralError('invalidArgument', 'tlsPin is the certificate the account\'s own TLS connection trusts: it needs streamProtocol "tls"');
        }
        tlsPin = options.tlsPin === undefined ? undefined : pinDigest(options.tlsPin);
        if (options.realms !== undefined && options.realms.some((realm) => realm === '' || realm.includes('\n'))) {
          throw new SipralError('invalidArgument', 'a realm is a line of text, not empty');
        }
      },
      (native) =>
        native.addAccount({
          ...options,
          tlsPin,
          realms: options.realms === undefined || options.realms.length === 0 ? undefined : options.realms.join('\n'),
        }),
    );
    const account = new SipralAccount(this, id, options.aor);
    this.accounts.set(id, account);
    return account;
  }

  /** The accounts added and not removed. */
  get accountList(): SipralAccount[] {
    return [...this.accounts.values()];
  }

  /** The calls that have not ended. */
  get callList(): SipralCall[] {
    return [...this.calls.values()];
  }

  async placeCall(account: SipralAccount, target: string, options: PlaceCallOptions = {}): Promise<SipralCall> {
    const id = await this.run(
      () => {
        if (!this.accounts.has(account.id)) {
          throw new SipralError('wrongState', `${account.aor} is not an account of this client`);
        }
        if (target.trim() === '') {
          throw new SipralError('invalidArgument', 'a call needs a target');
        }
      },
      (native) => native.placeCall(account.id, target, {...options}),
    );
    return this.callFor(id, 'outgoing', target);
  }

  /**
   * Whether the trace writes every SIP message whole, with its peer, from now
   * on -- credentials and keys taken out either way -- or pseudonymised, as
   * by default. For a diagnosis.
   */
  setDiagnosticTrace(on: boolean): Promise<void> {
    return this.run(() => undefined, (native) => native.setDiagnosticTrace(on));
  }

  /**
   * What the stack runs with, every default filled in: the transport, the
   * codecs' count and frame, the SRTP suites the calls offer in order,
   * whether a pseudonym salt was given, whether the diagnostic trace is whole
   * now, and whether the platform's echo cancellation is asked for.
   */
  async settings(): Promise<Settings> {
    const read = await this.run(() => undefined, (native) => native.settings());
    return {
      transport: read.transport as Signalling,
      codecCount: read.codecCount,
      frameMs: read.frameMs,
      srtpSuites: read.srtpSuites === '' ? [] : read.srtpSuites.split(',').map((one) => suiteName(Number(one))),
      pseudonymSalted: read.pseudonymSalted,
      diagnosticTrace: read.diagnosticTrace,
      systemEchoCancellation: read.systemEchoCancellation,
    };
  }

  /** The audio devices: the library runs them, this only says when and whether the microphone is heard. */
  readonly audio = {
    activate: (): Promise<void> => this.run(() => undefined, (native) => native.activateAudio()),
    deactivate: (): Promise<void> => this.run(() => undefined, (native) => native.deactivateAudio()),
    setMuted: (muted: boolean): Promise<void> => this.run(() => undefined, (native) => native.setMuted(muted)),
  };

  /** Close the stack. Every call and account of it is gone afterwards. */
  async close(): Promise<void> {
    if (this.closed) {
      return;
    }
    this.release();
    await crossing(() => this.native.close());
  }

  /** @internal Check `guard` here, then cross; a closed client refuses before either. */
  async run<T>(guard: () => void, action: (native: Spec) => Promise<T>): Promise<T> {
    if (this.closed) {
      throw new SipralError('closed', 'this client is closed');
    }
    guard();
    return crossing(() => action(this.native));
  }

  /** @internal */
  emit<K extends keyof ClientEvents>(name: K, payload: ClientEvents[K]): void {
    this.emitter.emit(name, payload);
  }

  /** @internal */
  forgetAccount(id: string): void {
    this.accounts.delete(id);
  }

  /**
   * @internal The call a handle names. An event can name a call before the
   * promise that made it has resolved -- the far end answers a placed call
   * that fast on a quiet network -- so the first to arrive makes it and the
   * other finds it.
   */
  callFor(id: string, direction: CallDirection, remote: string): SipralCall {
    let call = this.calls.get(id);
    if (call === undefined) {
      call = new SipralCall(this, id, direction, remote);
      this.calls.set(id, call);
    } else if (call.remote === '' && remote !== '') {
      call.remote = remote;
    }
    return call;
  }

  private dispatch(event: NativeEvent): void {
    if (this.closed) {
      return;
    }
    this.emitter.emit('event', event);
    if (event.kind === 'registrationChanged') {
      const account = this.accounts.get(event.account);
      if (account !== undefined) {
        const payload = {
          account,
          state: (event.registrationState as RegistrationState | undefined) ?? 'unknown',
          statusCode: event.statusCode ?? 0,
          retryInMs: event.retryInMs ?? 0,
          failure: (event.registrationFailure as RegistrationFailure | undefined) ?? 'none',
        };
        account.deliver(payload);
        this.emitter.emit('registrationChanged', payload);
      }
      return;
    }
    if (event.kind === 'located' || event.kind === 'locateFailed') {
      const account = this.accounts.get(event.account);
      if (account === undefined) {
        return;
      }
      if (event.kind === 'located') {
        const payload = {account, targets: (event.targets ?? '').split(',').filter((one) => one !== '')};
        account.located(payload);
        this.emitter.emit('located', payload);
      } else {
        const payload = {
          account,
          failure: (event.locateFailure as LocateFailure | undefined) ?? 'none',
          retryInMs: event.retryInMs ?? 0,
        };
        account.locateFailed(payload);
        this.emitter.emit('locateFailed', payload);
      }
      return;
    }
    if (event.kind === 'challengeDeclined') {
      const account = this.accounts.get(event.account);
      if (account === undefined) {
        return;
      }
      const payload = {
        account,
        refusal: (event.challengeRefusal as ChallengeRefusal | undefined) ?? 'unknown',
        server: event.challengeServer ?? '',
        realms: (event.challengeRealms ?? '').split('\n').filter((one) => one !== ''),
      };
      account.challengeDeclined(payload);
      this.emitter.emit('challengeDeclined', payload);
      return;
    }
    if (event.call === '') {
      return;
    }
    if (event.kind === 'incomingCall') {
      const call = this.callFor(event.call, 'incoming', event.fromUri ?? '');
      this.emitter.emit('incomingCall', {
        call,
        from: event.fromUri ?? '',
        fromDisplay: event.fromDisplay ?? '',
        to: event.toUri ?? '',
      });
      return;
    }
    const call = this.calls.get(event.call) ?? (event.kind === 'callEnded' ? undefined : this.callFor(event.call, 'outgoing', ''));
    if (call === undefined) {
      return;
    }
    call.deliver(event);
    if (event.kind === 'callEnded') {
      this.calls.delete(event.call);
    }
  }

  private release(): void {
    this.closed = true;
    this.subscription?.remove();
    this.subscription = undefined;
    this.accounts.clear();
    this.calls.clear();
    this.emitter.removeAllListeners();
    if (SipralClient.opened === this) {
      SipralClient.opened = undefined;
    }
  }
}
