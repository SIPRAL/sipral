// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// The codegen spec: what crosses between JavaScript and the two native
// halves. React Native's codegen reads this file and writes the Java and
// Objective-C++ interfaces those halves implement, so everything here is in
// the few types codegen understands -- strings, numbers, booleans, plain
// objects -- and `src/index.ts` is where they become a typed API.
//
// Handles cross as strings: a Sipral handle is 64 bits, and a JavaScript
// number holds 53 of them exactly.

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
  /** "tcp" or "tls": a connection of the account's own to its server. */
  streamProtocol?: string;
  /** The SHA-256 fingerprint, as bare hexadecimal, of the one certificate the account's own TLS connection trusts. */
  tlsPin?: string;
  /** The realms the password answers, one per line. */
  realms?: string;
};

/** One call's own controls in one direction, read back. */
export type NativeCallAudio = {
  gain: CodegenTypes.Double;
  muted: boolean;
  /** The meter, 0 to 1. */
  level: CodegenTypes.Double;
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
};

export interface Spec extends TurboModule {
  /** Resolves with the address the stack signals from. */
  open(options: NativeOpenOptions): Promise<string>;
  close(): Promise<void>;

  /** Resolves with the account's handle. */
  addAccount(options: NativeAccountOptions): Promise<string>;
  register(account: string): Promise<void>;
  unregister(account: string): Promise<void>;
  removeAccount(account: string): Promise<void>;

  /** Resolves with the call's handle. */
  placeCall(account: string, target: string, options: NativeCallOptions): Promise<string>;
  answer(call: string): Promise<void>;
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
  setDiagnosticTrace(on: boolean): Promise<void>;
  /** One call's own gain in one direction, "input" or "output", 1 for unity. */
  setCallGain(call: string, direction: string, gain: CodegenTypes.Double): Promise<void>;
  setCallMuted(call: string, direction: string, muted: boolean): Promise<void>;
  callAudio(call: string, direction: string): Promise<NativeCallAudio>;
  settings(): Promise<NativeSettings>;

  readonly onEvent: CodegenTypes.EventEmitter<NativeEvent>;
}

export default TurboModuleRegistry.getEnforcing<Spec>('Sipral');
