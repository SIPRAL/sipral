// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// Sipral for Node.js: the idiomatic layer over the generated `sipral_abi.ts`.
// The application runs each call's audio through `Media`; silence goes out
// when it gave none.

export { Account, type AccountEvents } from './account.js';
export { Call, type CallEvents } from './call.js';
export { type MediaStatistics, StackEvent } from './events.js';
export { SipralError } from './internal.js';
export { Media } from './media.js';
export {
  SipralCallEndReason,
  SipralCallState,
  SipralCodec,
  SipralDtmf,
  SipralEventKind,
  SipralHeldAudio,
  SipralLoadError,
  SipralRegistrationFailure,
  SipralRegistrationState,
  SipralSrtp,
  SipralStatus,
  Sipral,
} from './sipral_abi.js';
export {
  type AccountOptions,
  type CallOptions,
  Stack,
  type StackEvents,
  type StackOptions,
  routeHost,
} from './stack.js';
