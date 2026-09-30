// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea
//
// The Sipral SIP stack for React Native. `Sipral.open` is where an
// application starts; everything else hangs off the client it resolves with.

import NativeSipral from './NativeSipral';
import type {Spec} from './NativeSipral';
import {SipralClient} from './client';
import type {OpenOptions} from './types';

export {SipralAccount, SipralCall, SipralClient} from './client';
export type {
  AccountEvents,
  CallEndedEvent,
  CallEvents,
  CallStateEvent,
  ClientEvents,
  DigitEvent,
  HoldChangedEvent,
  IncomingCallEvent,
  RegistrationChangedEvent,
  TransferReportEvent,
  TransferRequestedEvent,
} from './client';
export {SipralError} from './errors';
export type {SipralErrorCode} from './errors';
export {TypedEmitter} from './emitter';
export type {Subscription} from './emitter';
export type {NativeEvent, Spec as NativeSipralSpec} from './NativeSipral';
export type {
  AccountOptions,
  CallDirection,
  CallState,
  EndReason,
  OpenOptions,
  PlaceCallOptions,
  RegistrationState,
  Signalling,
} from './types';

export const Sipral = {
  /**
   * Open the stack over the native module this package links. `native` is
   * for a test, or for an application that wraps the module itself.
   */
  open(options: OpenOptions, native: Spec = NativeSipral): Promise<SipralClient> {
    return SipralClient.open(options, native);
  },
};

export default Sipral;
