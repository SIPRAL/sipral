// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// The application-facing API: a client, its accounts and calls, each with
// its last reported state and a typed emitter. An action the call's state
// does not allow is refused here with `wrongState` before crossing to
// native code, so a button pressed twice is one rejected promise rather than
// a request into a call that is gone.

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
  AnswerOptions,
  PlaceCallOptions,
  RegistrationFailure,
  RegistrationState,
  Settings,
  Signalling,
  TokenError,
  NatKind,
  NetworkProbe,
  NetworkVerdict,
  ServerReach,
} from './types';

export interface RegistrationChangedEvent {
  account: SipralAccount;
  state: RegistrationState;
  /** The registrar's final answer, or zero. */
  statusCode: number;
  /** When the next attempt goes, for "retrying"; zero otherwise. */
  retryInMs: number;
  /** Why it failed ("unreachableContact": the registrar cannot reach the Contact), or "none". */
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

/**
 * The server wants an OAuth 2.0 access token (RFC 8898). Check `authzServer`
 * against the trusted ones, fetch a token for `scope`, and pass it to
 * `account.setAccessToken`.
 */
export interface TokenRequiredEvent {
  account: SipralAccount;
  /** What was wrong with the last token: 'invalidToken' for one expired or revoked. */
  error: TokenError;
  /** The `error` code as the server wrote it, '' for none. */
  errorCode: string;
  /** Whether a proxy asked (407) rather than the registrar (401). */
  proxy: boolean;
  /** Where the challenged request went, host:port. */
  server: string;
  /** The realm, '' when the challenge named none. */
  realm: string;
  /** The scope the token has to carry, '' for none named. */
  scope: string;
  /** The authorization server, an https URI, '' for none named. */
  authzServer: string;
}

/** A network test's result; `verdict` is the worst of the parts tested. */
export interface NetworkTestEvent {
  /** The number `client.networkTest` resolved with. */
  test: number;
  verdict: NetworkVerdict;
  stun: NetworkProbe;
  nat: NatKind;
  turn: NetworkProbe;
  server: ServerReach;
  /** The status the account's server answered with, 0 for none. */
  serverStatus: number;
  /** From the OPTIONS to its answer, in milliseconds. */
  serverRoundTripMs: number;
  echo: NetworkProbe;
  echoVerdict: NetworkVerdict;
  /** Lost or late on the echo call, as a percentage. */
  lossPercent: number;
  /** Interarrival jitter on the echo call, in milliseconds. */
  jitterMs: number;
  /** The round trip RTCP measured on the echo call, null when it brought none back. */
  roundTripMs: number | null;
  /** G.107's R for the echo call, for concealed G.711. */
  rFactor: number;
  /** The conversational MOS estimated from it. */
  mos: number;
  /** The socket the STUN answer was about, '' for none. */
  local: string;
  /** Where the STUN server saw it, '' for no answer. */
  mapped: string;
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
  tokenRequired: TokenRequiredEvent;
  networkTest: NetworkTestEvent;
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
  tokenRequired: TokenRequiredEvent;
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

  /**
   * Gives the binding up (REGISTER with Expires: 0). The state reads
   * unregistered at once; the registrar's answer comes as a later
   * registration event. Wait for it before closing, or a challenge to the
   * un-REGISTER goes unanswered.
   */
  unregister(): Promise<void> {
    return this.client.run(() => this.usable(), (native) => native.unregister(this.id));
  }

  /**
   * Sets the OAuth 2.0 access token (RFC 8898), replacing any previous one;
   * null removes it. Answers 'tokenRequired' and renews a token; the next
   * Bearer challenge is answered with it. A registration that failed for
   * want of a token restarts with `register()`. Rejects with
   * 'invalidArgument' for a token that is not an RFC 6750 b64token.
   */
  setAccessToken(token: string | null): Promise<void> {
    return this.client.run(
      () => this.usable(),
      (native) => native.setAccessToken(this.id, token ?? ''),
    );
  }

  /** Registers, resolving once registered or rejecting with the failing event. */
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

  /** @internal */
  tokenRequired(event: TokenRequiredEvent): void {
    this.emitter.emit('tokenRequired', event);
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
   * Per-call audio on top of the client's: `input` is what the microphone
   * sends this call alone, `output` its loudness beside other calls. Valid
   * from the start of the call's audio to its end, holds included; outside
   * that the native half refuses with `wrongState`.
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
     * The PCM rate of the call's frames, independent of the codec: 8000,
     * 16000, 24000 or 48000, or 0 for the codec's own. Resolves with the rate
     * and frame length. Only for application-carried audio; on the phone's
     * devices it is refused as `wrongState`.
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
  async answer(options: AnswerOptions = {}): Promise<void> {
    await this.client.run(
      () => {
        this.alive();
        if (this.direction !== 'incoming' || this.answered) {
          throw new SipralError('wrongState', `call ${this.id} is not waiting to be answered`);
        }
      },
      (native) => native.answer(this.id, {...options}),
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

  /** Open the stack. Listening starts first so no event raised while opening is missed. */
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
   * Start a network test and resolve with its number; the result arrives as
   * 'networkTest'. `account`'s server gets an OPTIONS. `echoCall`, a call to
   * an echo service, is measured for `echoMs` (8000 by default) and then
   * hung up by the test. Parts silent after `timeoutMs` (30000 by default)
   * count as failed.
   */
  networkTest(
    options: {account?: SipralAccount; echoCall?: SipralCall; echoMs?: number; timeoutMs?: number} = {},
  ): Promise<number> {
    return this.run(
      () => undefined,
      (native) =>
        native.networkTest(
          options.account?.id ?? '',
          options.echoCall?.id ?? '',
          options.echoMs ?? 0,
          options.timeoutMs ?? 0,
        ),
    );
  }

  /** Switch the trace between whole SIP messages and pseudonymised ones; credentials are removed either way. */
  setDiagnosticTrace(on: boolean): Promise<void> {
    return this.run(() => undefined, (native) => native.setDiagnosticTrace(on));
  }

  /** The settings in effect, defaults filled in. */
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

  /**
   * The audio devices, which the library runs. `setSystemEchoCancellation`
   * reopens open devices at once with or without the platform's canceller;
   * calls keep their media across the reopen.
   */
  readonly audio = {
    activate: (): Promise<void> => this.run(() => undefined, (native) => native.activateAudio()),
    deactivate: (): Promise<void> => this.run(() => undefined, (native) => native.deactivateAudio()),
    setMuted: (muted: boolean): Promise<void> => this.run(() => undefined, (native) => native.setMuted(muted)),
    setSystemEchoCancellation: (on: boolean): Promise<void> =>
      this.run(() => undefined, (native) => native.setSystemEchoCancellation(on)),
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
   * @internal An event can name a call before the promise that made it
   * resolves, so whichever arrives first creates it.
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
    if (event.kind === 'networkTest') {
      this.emitter.emit('networkTest', {
        test: event.test ?? 0,
        verdict: (event.verdict as NetworkVerdict | undefined) ?? 'unknown',
        stun: (event.stun as NetworkProbe | undefined) ?? 'notTested',
        nat: (event.nat as NatKind | undefined) ?? 'unknown',
        turn: (event.turn as NetworkProbe | undefined) ?? 'notTested',
        server: (event.server as ServerReach | undefined) ?? 'notTested',
        serverStatus: event.serverStatus ?? 0,
        serverRoundTripMs: event.serverRoundTripMs ?? 0,
        echo: (event.echo as NetworkProbe | undefined) ?? 'notTested',
        echoVerdict: (event.echoVerdict as NetworkVerdict | undefined) ?? 'unknown',
        lossPercent: event.lossPercent ?? 0,
        jitterMs: event.jitterMs ?? 0,
        roundTripMs: event.roundTripMs ?? null,
        rFactor: event.rFactor ?? 0,
        mos: event.mos ?? 0,
        local: event.local ?? '',
        mapped: event.mapped ?? '',
      });
      return;
    }
    if (event.kind === 'tokenRequired') {
      const account = this.accounts.get(event.account);
      if (account === undefined) {
        return;
      }
      const payload: TokenRequiredEvent = {
        account,
        error: (event.tokenError as TokenError | undefined) ?? 'none',
        errorCode: event.tokenErrorCode ?? '',
        proxy: event.tokenProxy ?? false,
        server: event.tokenServer ?? '',
        realm: event.tokenRealm ?? '',
        scope: event.tokenScope ?? '',
        authzServer: event.tokenAuthzServer ?? '',
      };
      account.tokenRequired(payload);
      this.emitter.emit('tokenRequired', payload);
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
