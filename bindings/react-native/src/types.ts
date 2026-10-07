// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// The names the native halves hand over: the library's enumerations in lower
// camel case (SIPRAL_CALL_STATE_EARLY_MEDIA is "earlyMedia").

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

/** `sipral_srtp_t`: what calls do about SRTP. */
export type Srtp =
  | 'notOffered'
  | 'offered'
  | 'required'
  | 'dtls'
  | 'dtlsRequired'
  | 'dtlsOrSdes'
  | 'bestEffort';

/** `sipral_registration_failure_t`. */
export type RegistrationFailure =
  | 'none'
  | 'rejected'
  | 'badCredentials'
  | 'unreachable'
  | 'redirected'
  | 'unreachableContact';

/** `sipral_locate_failure_t`: why a server named by a URI was not located. */
export type LocateFailure = 'none' | 'notFound' | 'unanswered' | 'unsupported';

/** `sipral_challenge_refusal_t`: why an account's password was not given to a challenge. */
export type ChallengeRefusal = 'unknown' | 'notTheAccountsServer' | 'notTheAccountsRealm';

/** `sipral_token_error_t`: what an account's server said was wrong with its access token (RFC 6750 section 3.1). */
export type TokenError =
  | 'none'
  | 'invalidRequest'
  | 'invalidToken'
  | 'insufficientScope'
  | 'invalidScope'
  | 'other';

/** `sipral_network_verdict_t`: what a network test, or one part of it, came to. */
export type NetworkVerdict = 'unknown' | 'good' | 'acceptable' | 'poor';

/** `sipral_network_probe_t`: whether one part of a network test was tried, and how it went. */
export type NetworkProbe = 'notTested' | 'succeeded' | 'failed';

/** `sipral_nat_kind_t`: what a STUN answer says about the NAT in front of this end. */
export type NatKind = 'unknown' | 'open' | 'portPreserved' | 'portChanged';

/** `sipral_server_reach_t`: what the account's server did with a network test's OPTIONS. */
export type ServerReach = 'notTested' | 'answered' | 'timedOut' | 'transportFailed';

export interface OpenOptions {
  /**
   * The local address for signalling and audio. Left out, the stack listens
   * on every interface and advertises the route toward each server. A
   * loopback address is never advertised to a remote server: the library
   * refuses it as `unreachableAddress`.
   */
  bindHost?: string;
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
   * "automatic" (the default) opens the audio devices with the first call and
   * closes them with the last; "manual" opens them only between
   * `audio.activate()` and `audio.deactivate()`, for CallKit's audio session
   * callbacks and Android's audio focus.
   */
  audioActivation?: 'automatic' | 'manual';
  /**
   * "bestEffort" offers SDES on plain RTP/AVP and encrypts only if the answer
   * takes a key, for a PBX that answers an RTP/SAVP offer with 488.
   */
  srtp?: Srtp;
  /** SRTP suites, most preferred first, by their RFC 4568 and RFC 7714 names. */
  srtpSuites?: string[];
  /** The path MTU toward the server when the deployment knows it; RFC 3261 §18.1.1 moves a request to a stream within 200 bytes of it. */
  pathMtu?: number;
  /**
   * A deliberate deviation from RFC 3261 §18.1.1 for UDP-only servers: when
   * no stream can be had, requests up to this size go over UDP anyway. Zero
   * for never.
   */
  datagramWithoutStreamBytes?: number;
  /** At least 16 bytes, as hex, keying the log's pseudonyms so runs compare. A secret. */
  pseudonymSalt?: string;
  /** The trace writes whole SIP messages, credentials removed. */
  diagnosticTrace?: boolean;
  /**
   * The SHA-256 fingerprint of the one certificate `signallingServer` may
   * present, in any form `pinDigest` reads, for a self-signed PBX. No
   * authority or name is consulted.
   */
  tlsPin?: string;
  /**
   * False bypasses the platform's echo cancellation (voice processing on
   * iOS, the voice-recognition preset on Android), for a headset or an
   * application that cancels echo itself. On by default.
   */
  systemEchoCancellation?: boolean;
  /**
   * What a held party receives: silence by default; "application" sends what
   * the client sends (hold music, an announcement).
   */
  heldAudio?: 'silence' | 'application';
  /**
   * Maximum concurrent calls (0 for 128). Past it an incoming call gets 503
   * with `Retry-After: 2` and `placeCall` rejects with `limitReached`.
   */
  maxDialogs?: number;
  /**
   * Maximum concurrent incoming requests (0 for 256). Raise it with
   * `maxDialogs`, to three per call plus 256 (`docs/08-ffi.md`).
   */
  maxServerTransactions?: number;
}

/** Which way one call's audio goes: what the microphone sends it, or what it plays. */
export type AudioDirection = 'input' | 'output';

/** One call's own controls in one direction. */
export interface CallAudio {
  /** 1 is unity, 0.5 halves, 2 doubles. */
  gain: number;
  muted: boolean;
  /** The meter after the call's own gain and mute, 0 to 1. */
  level: number;
}

/** The rate a call's frames cross at, and how many samples one frame is there. */
export interface AppRate {
  sampleRate: number;
  frameSamples: number;
}

/** What the stack runs with, every default filled in. */
export interface Settings {
  transport: Signalling;
  codecCount: number;
  frameMs: number;
  /** The SRTP suites the calls offer and accept, in order, by their RFC 4568 and RFC 7714 names. */
  srtpSuites: string[];
  /** Whether a pseudonym salt was given; the salt itself is never read back. */
  pseudonymSalted: boolean;
  /** Whether the trace writes whole messages now. */
  diagnosticTrace: boolean;
  /** Whether the platform's echo cancellation is asked for. */
  systemEchoCancellation: boolean;
}

export interface AccountOptions {
  /** The account's address of record: "sip:alice@example.com". */
  aor: string;
  /** host:port that requests go to: the registrar, or the outbound proxy. One of this and `serverUri`. */
  registrarAddress?: string;
  /**
   * A server URI ("sip:pbx.example.com") located by RFC 3263 instead of
   * `registrarAddress`; `located` and `locateFailed` report the outcome.
   */
  serverUri?: string;
  /** Ask the domain for NAPTR records before SRV (RFC 3263 §4.1). */
  serverNaptr?: boolean;
  /** Keep the flow to the server open at this interval, 1 000 to 120 000 ms, whatever STUN found; zero for never. */
  keepaliveMs?: number;
  /** The registrar's URI. Without it the account never registers. */
  registrar?: string;
  contact?: string;
  displayName?: string;
  authUser?: string;
  authPassword?: string;
  /** Zero, or left out, for the library's own default. */
  expiresSeconds?: number;
  /**
   * "tcp", "tls", "ws" or "wss": the account gets its own connection to its
   * server, so one client can mix UDP and stream accounts. The REGISTER and
   * every call go over it; "ws"/"wss" run a WebSocket on it (RFC 7118). Only
   * on a client signalling over "udp".
   */
  streamProtocol?: 'tcp' | 'tls' | 'ws' | 'wss';
  /**
   * The SHA-256 fingerprint of the one certificate the account's own TLS
   * connection trusts, in any form `pinDigest` reads; it needs
   * `streamProtocol` "tls".
   */
  tlsPin?: string;
  /**
   * The realms the password answers (RFC 3261 §22.1). Left out: the first
   * challenge's realm plus every realm REGISTER is challenged with; an SBC
   * challenging calls under its own realm needs both named. Other challenges
   * are not answered and raise `challengeDeclined`.
   */
  realms?: string[];
  /**
   * The `Host` the WebSocket handshake of a "ws" or "wss" account names
   * (RFC 6455 §4.1), `host[:port]`; left out, the server's address.
   */
  websocketHost?: string;
  /**
   * The resource that handshake asks for, a path from "/" with any query;
   * left out, "/ws".
   */
  websocketResource?: string;
}

export interface PlaceCallOptions {
  /** host:port the INVITE goes to, when it is not the account's registrar address. */
  destination?: string;
  /** This call's codecs, in place of the client's. */
  codecs?: string;
  /**
   * Follow a 3xx's targets (RFC 3261 §8.1.3.4). Off by default: a 3xx ends
   * the call with its status.
   */
  followRedirects?: boolean;
}

export interface AnswerOptions {
  /**
   * The codecs this call takes ("PCMA,PCMU"). It chooses which, not their
   * order: an answer keeps the offer's order (RFC 3264 §6.1).
   */
  codecs?: string;
}

/** Whether a call was placed here or arrived here. */
export type CallDirection = 'outgoing' | 'incoming';
