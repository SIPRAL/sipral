// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea
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
  /** The address the stack and every call's media bind to. */
  bindHost: string;
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
};

export type NativeAccountOptions = {
  aor: string;
  registrarAddress: string;
  registrar?: string;
  contact?: string;
  displayName?: string;
  authUser?: string;
  authPassword?: string;
  expiresSeconds?: CodegenTypes.Double;
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

  readonly onEvent: CodegenTypes.EventEmitter<NativeEvent>;
}

export default TurboModuleRegistry.getEnforcing<Spec>('Sipral');
