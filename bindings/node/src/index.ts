// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// Sipral for Node.js: the idiomatic layer over `sipral_abi.ts`, which
// tools/abi-gen prints and nothing here edits. A stack with its signalling
// socket, an account, a call with its media, and the stack's events as an
// EventEmitter and an async iterator. The application runs each call's
// audio: `Media` emits the far end's PCM a frame at a time and takes this
// end's with `sendAudio`, and silence goes out when nothing was given.

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
