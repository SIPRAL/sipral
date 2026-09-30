// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea
//
// The names the native halves hand over, as types. Each is the library's own
// enumeration in lower camel case -- SIPRAL_CALL_STATE_EARLY_MEDIA is
// "earlyMedia" -- which is what the Swift layer's cases are called already
// and what the Kotlin half turns its constants into.

/** `sipral_registration_state_t`. */
export type RegistrationState =
  | 'unknown'
  | 'idle'
  | 'registering'
  | 'registered'
  | 'refreshing'
  | 'retrying'
  | 'unregistered'
  | 'failed'
  | 'unverified'
  | 'restored'
  | 'notRegistering';

/** `sipral_call_state_t`. */
export type CallState =
  | 'unknown'
  | 'calling'
  | 'incoming'
  | 'ringing'
  | 'earlyMedia'
  | 'confirmed'
  | 'consulting'
  | 'terminating'
  | 'terminated';

/** `sipral_call_end_reason_t`. */
export type EndReason =
  | 'none'
  | 'localHangup'
  | 'remoteHangup'
  | 'refused'
  | 'cancelled'
  | 'unreachable'
  | 'forkLost'
  | 'abandoned'
  | 'expired';

/** How SIP travels between this phone and the server. */
export type Signalling = 'udp' | 'tcp' | 'tls';

export interface OpenOptions {
  /**
   * The phone's own address on the network the server is reached over: the
   * stack signals from it and every call's audio is sent from it. Required,
   * because a phone has several and only the application knows which one
   * the account lives on.
   */
  bindHost: string;
  /** Zero, or left out, for any free port. */
  bindPort?: number;
  userAgent?: string;
  /** Codec names in order of preference, comma-separated: "opus/48000,PCMA/8000". */
  codecs?: string;
  /** "udp" unless said otherwise. */
  signalling?: Signalling;
  /** host:port of the server, required for "tcp" and "tls". */
  signallingServer?: string;
  /** host:port of a STUN server, for the address the phone is seen from. */
  stunServer?: string;
  /**
   * "automatic" (the default) opens the microphone and the speaker with the
   * first call's audio and closes them with the last; "manual" opens them
   * only between `audio.activate()` and `audio.deactivate()`, which is what
   * CallKit's audio session callbacks and Android's audio focus are for.
   */
  audioActivation?: 'automatic' | 'manual';
}

export interface AccountOptions {
  /** The account's address of record: "sip:alice@example.com". */
  aor: string;
  /** host:port that requests go to: the registrar, or the outbound proxy. */
  registrarAddress: string;
  /** The registrar's URI. Without it the account never registers. */
  registrar?: string;
  contact?: string;
  displayName?: string;
  authUser?: string;
  authPassword?: string;
  /** Zero, or left out, for the library's own default. */
  expiresSeconds?: number;
}

export interface PlaceCallOptions {
  /** host:port the INVITE goes to, when it is not the account's registrar address. */
  destination?: string;
  /** This call's codecs, in place of the client's. */
  codecs?: string;
}

/** Whether a call was placed here or arrived here. */
export type CallDirection = 'outgoing' | 'incoming';
