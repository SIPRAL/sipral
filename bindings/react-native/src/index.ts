// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
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
  ChallengeDeclinedEvent,
  ClientEvents,
  DigitEvent,
  HoldChangedEvent,
  IncomingCallEvent,
  LocatedEvent,
  LocateFailedEvent,
  RegistrationChangedEvent,
  TransferReportEvent,
  TransferRequestedEvent,
} from './client';
export {SipralError} from './errors';
export type {SipralErrorCode} from './errors';
export {pinDigest} from './pin';
export {TypedEmitter} from './emitter';
export type {Subscription} from './emitter';
export type {NativeEvent, Spec as NativeSipralSpec} from './NativeSipral';
export type {
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
  Srtp,
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
