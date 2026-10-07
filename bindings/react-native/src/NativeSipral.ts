// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// The codegen spec for the two native halves, so only codegen's types
// (strings, numbers, booleans, plain objects); `src/index.ts` types them.
//
// Handles cross as strings: a Sipral handle is 64 bits, and a JavaScript
// number holds only 53 exactly.

import type {CodegenTypes, TurboModule} from 'react-native';
import {TurboModuleRegistry} from 'react-native';

export type NativeOpenOptions = {
  /** The address the stack and every call's media bind to; left out, the
   * route toward the server. */
  bindHost?: string;
  bindPort?: CodegenTypes.Int32;
  userAgent?: string;
  /** Codec names in order of preference, comma-separated. */
  codecs?: string;
  /** "udp", "tcp" or "tls". */
  signalling?: string;
  /** host:port, for "tcp" and "tls". */
  signallingServer?: string;
  stunServer?: string;
  /** Open the audio devices only between activateAudio and deactivateAudio. */
  manualAudio?: boolean;
  /** A SIPRAL_SRTP value in lower camel case: "offered", "bestEffort"... */
  srtp?: string;
  /** SRTP suite names, comma-separated, most preferred first. */
  srtpSuites?: string;
  pathMtu?: CodegenTypes.Int32;
  datagramWithoutStreamBytes?: CodegenTypes.Int32;
  /** The pseudonym salt, as hexadecimal. */
  pseudonymSalt?: string;
  diagnosticTrace?: boolean;
  /** The SHA-256 fingerprint of the one certificate a TLS connection trusts. */
  tlsPin?: string;
  /** False opens the devices past the platform's echo cancellation. */
  systemEchoCancellation?: boolean;
  /** What a party this end holds is sent: "silence" or "application"; left out, silence. */
  heldAudio?: string;
  /** The most calls held at once, 0 to 4 294 967 295; left out or 0, 128. */
  maxDialogs?: CodegenTypes.Double;
  /** The most requests from other ends worked on at once; left out or 0, 256. */
  maxServerTransactions?: CodegenTypes.Double;
};

export type NativeAccountOptions = {
  aor: string;
  registrarAddress?: string;
  /** A server named by a URI RFC 3263 locates, in place of registrarAddress. */
  serverUri?: string;
  serverNaptr?: boolean;
  keepaliveMs?: CodegenTypes.Double;
  registrar?: string;
  contact?: string;
  displayName?: string;
  authUser?: string;
  authPassword?: string;
  expiresSeconds?: CodegenTypes.Double;
  /** "tcp", "tls", "ws" or "wss": a connection of the account's own to its server. */
  streamProtocol?: string;
  /** The SHA-256 fingerprint, as bare hexadecimal, of the one certificate the account's own TLS connection trusts. */
  tlsPin?: string;
  /** The realms the password answers, one per line. */
  realms?: string;
  /** The `Host` of a WebSocket account's handshake. */
  websocketHost?: string;
  /** The resource a WebSocket account's handshake asks for. */
  websocketResource?: string;
};

/** One call's own controls in one direction, read back. */
export type NativeCallAudio = {
  gain: CodegenTypes.Double;
  muted: boolean;
  /** The meter, 0 to 1. */
  level: CodegenTypes.Double;
};

/** The rate a call's frames cross at, and how long one frame is there. */
export type NativeAppRate = {
  sampleRate: CodegenTypes.Int32;
  frameSamples: CodegenTypes.Int32;
};

/** What the stack runs with, every default filled in. */
export type NativeSettings = {
  /** "udp", "tcp" or "tls". */
  transport: string;
  codecCount: CodegenTypes.Int32;
  frameMs: CodegenTypes.Int32;
  /** The SRTP suites the calls offer, in order, as `SipralSrtpSuite` numbers, comma-separated. */
  srtpSuites: string;
  pseudonymSalted: boolean;
  diagnosticTrace: boolean;
  systemEchoCancellation: boolean;
};

export type NativeCallOptions = {
  destination?: string;
  codecs?: string;
  followRedirects?: boolean;
};

export type NativeAnswerOptions = {
  codecs?: string;
};

/** One event, flattened: the members an event's kind does not use are left out. */
export type NativeEvent = {
  /** The kind, in lower camel case: "registrationChanged", "callEnded". */
  kind: string;
  /** The library's own name for the kind, for one this package has no type for. */
  kindName: string;
  /** The account's handle, or "" when the event is about none. */
  account: string;
  /** The call's handle, or "" when the event is about none. */
  call: string;
  registrationState?: string;
  callState?: string;
  endReason?: string;
  statusCode?: CodegenTypes.Int32;
  retryInMs?: CodegenTypes.Double;
  heldHere?: boolean;
  heldThere?: boolean;
  fromUri?: string;
  fromDisplay?: string;
  toUri?: string;
  digit?: string;
  target?: string;
  attended?: boolean;
  /** A registration's failure in lower camel case: "unreachableContact". */
  registrationFailure?: string;
  /** Where an account's server was located: host:port, comma-separated, the one in use first. */
  targets?: string;
  /** Why it was not, in lower camel case: "notFound", "unanswered", "unsupported". */
  locateFailure?: string;
  /** Why a challenge was declined, in lower camel case: "notTheAccountsServer", "notTheAccountsRealm". */
  challengeRefusal?: string;
  /** Where the declined challenge's request went, host:port. */
  challengeServer?: string;
  /** The realms it was challenged for, one per line. */
  challengeRealms?: string;
  /** What was wrong with the last access token, in lower camel case: "none", "invalidToken". */
  tokenError?: string;
  /** The `error` code as the server wrote it. */
  tokenErrorCode?: string;
  /** Whether a proxy asked for the token (407) rather than the registrar (401). */
  tokenProxy?: boolean;
  /** Where the request asking for a token went, host:port. */
  tokenServer?: string;
  /** The realm the token is asked for, empty for none. */
  tokenRealm?: string;
  /** The scope the token has to carry. */
  tokenScope?: string;
  /** The authorization server a token comes from, an https URI. */
  tokenAuthzServer?: string;
  /** The number of the network test this event is about. */
  test?: CodegenTypes.Int32;
  /** A network test's verdict, in lower camel case: "unknown", "good", "acceptable", "poor". */
  verdict?: string;
  /** Whether a STUN server answered: "notTested", "succeeded", "failed". */
  stun?: string;
  /** What the STUN answer says about the NAT: "unknown", "open", "portPreserved", "portChanged". */
  nat?: string;
  /** Whether the TURN server allocated a relay: "notTested", "succeeded", "failed". */
  turn?: string;
  /** What the account's server did: "notTested", "answered", "timedOut", "transportFailed". */
  server?: string;
  /** The status the server answered with. */
  serverStatus?: CodegenTypes.Int32;
  /** From the OPTIONS to its answer, in milliseconds. */
  serverRoundTripMs?: CodegenTypes.Int32;
  /** Whether audio came back on the echo call. */
  echo?: string;
  /** The echo's own verdict. */
  echoVerdict?: string;
  /** Lost or late on the echo call, as a percentage. */
  lossPercent?: CodegenTypes.Double;
  /** Interarrival jitter on the echo call, in milliseconds. */
  jitterMs?: CodegenTypes.Double;
  /** The round trip RTCP measured on the echo call, when it did. */
  roundTripMs?: CodegenTypes.Int32;
  /** G.107's R for the echo call, for concealed G.711. */
  rFactor?: CodegenTypes.Int32;
  /** The conversational MOS estimated from it. */
  mos?: CodegenTypes.Double;
  /** The socket the STUN answer was about. */
  local?: string;
  /** Where the STUN server saw it. */
  mapped?: string;
};

export interface Spec extends TurboModule {
  /** Resolves with the address the stack signals from. */
  open(options: NativeOpenOptions): Promise<string>;
  close(): Promise<void>;

  /** Resolves with the account's handle. */
  addAccount(options: NativeAccountOptions): Promise<string>;
  register(account: string): Promise<void>;
  unregister(account: string): Promise<void>;
  /** The OAuth 2.0 access token the account's server asked for; "" takes it away. */
  setAccessToken(account: string, token: string): Promise<void>;
  removeAccount(account: string): Promise<void>;

  /** Resolves with the call's handle. */
  placeCall(account: string, target: string, options: NativeCallOptions): Promise<string>;
  answer(call: string, options: NativeAnswerOptions): Promise<void>;
  reject(call: string, code: CodegenTypes.Int32): Promise<void>;
  hangup(call: string): Promise<void>;
  hold(call: string): Promise<void>;
  resume(call: string): Promise<void>;
  transfer(call: string, target: string): Promise<void>;
  /** Resolves with the handle of the call placed to the transfer's target. */
  acceptTransfer(call: string): Promise<string>;
  rejectTransfer(call: string, code: CodegenTypes.Int32): Promise<void>;
  sendDtmf(call: string, digits: string): Promise<void>;

  activateAudio(): Promise<void>;
  deactivateAudio(): Promise<void>;
  setMuted(muted: boolean): Promise<void>;
  /** `sipral_audio_set_system_echo_cancellation`; open devices are reopened at once. */
  setSystemEchoCancellation(on: boolean): Promise<void>;
  setDiagnosticTrace(on: boolean): Promise<void>;
  /** A network test before a call; "" leaves the account or the echo call out. Resolves with the test's number. */
  networkTest(
    account: string,
    echoCall: string,
    echoMs: CodegenTypes.Double,
    timeoutMs: CodegenTypes.Double,
  ): Promise<CodegenTypes.Int32>;
  /** One call's own gain in one direction, "input" or "output", 1 for unity. */
  setCallGain(call: string, direction: string, gain: CodegenTypes.Double): Promise<void>;
  setCallMuted(call: string, direction: string, muted: boolean): Promise<void>;
  callAudio(call: string, direction: string): Promise<NativeCallAudio>;
  /** `sipral_media_set_app_rate` on the call's media: 8000, 16000, 24000 or 48000, 0 for the codec's own. */
  setAppRate(call: string, hz: CodegenTypes.Int32): Promise<NativeAppRate>;
  settings(): Promise<NativeSettings>;

  readonly onEvent: CodegenTypes.EventEmitter<NativeEvent>;
}

export default TurboModuleRegistry.getEnforcing<Spec>('Sipral');
