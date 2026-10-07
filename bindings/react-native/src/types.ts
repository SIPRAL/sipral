// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
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
   * The phone's own address on the network the server is reached over: the
   * stack signals from it and every call's audio is sent from it. Left out,
   * the stack listens on every interface and advertises the address of the
   * route toward its first account's server -- the address a PBX on the
   * network reaches the phone at -- and each call's audio goes from the
   * route toward the far end. A loopback address is never advertised to a
   * server elsewhere: the library refuses that as `unreachableAddress`.
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
   * "automatic" (the default) opens the microphone and the speaker with the
   * first call's audio and closes them with the last; "manual" opens them
   * only between `audio.activate()` and `audio.deactivate()`, which is what
   * CallKit's audio session callbacks and Android's audio focus are for.
   */
  audioActivation?: 'automatic' | 'manual';
  /**
   * What every call does about SRTP. "bestEffort" offers SDES on plain
   * RTP/AVP: encrypted when the server's answer takes a key, plain when it
   * takes none, for a PBX that answers an RTP/SAVP offer with 488.
   */
  srtp?: Srtp;
  /** SRTP suites, most preferred first, by their RFC 4568 and RFC 7714 names. */
  srtpSuites?: string[];
  /** The path MTU toward the server when the deployment knows it; RFC 3261 §18.1.1 moves a request to a stream within 200 bytes of it. */
  pathMtu?: number;
  /**
   * A deliberate deviation from RFC 3261 §18.1.1, for a server that takes
   * SIP over UDP alone: once no stream to it can be had, a request up to this
   * many bytes goes over UDP anyway. Zero, or left out, for never.
   */
  datagramWithoutStreamBytes?: number;
  /** At least 16 bytes the installation keeps, as hexadecimal, keying the log's pseudonyms so that two runs compare; a secret, like a key. */
  pseudonymSalt?: string;
  /** The trace writes whole SIP messages, credentials and keys taken out; `client.setDiagnosticTrace` turns it on and off later. */
  diagnosticTrace?: boolean;
  /**
   * The SHA-256 fingerprint of the one certificate the TLS connection to
   * `signallingServer` trusts -- "SHA256 Fingerprint=AB:CD:..." as openssl
   * prints it, or any other form `pinDigest` reads -- for a PBX that signed
   * its own: the whole verdict, no authority or name consulted. Read before
   * the native half is asked, and handed to it as bare digits.
   */
  tlsPin?: string;
  /**
   * False opens the microphone and the speaker past the platform's echo
   * cancellation -- the voice-processing unit's processing bypassed on iOS,
   * the voice-recognition preset rather than the voice-communication one on
   * Android -- for a headset, which has no echo to cancel, or an application
   * that cancels it on each call itself. On unless said otherwise.
   */
  systemEchoCancellation?: boolean;
  /**
   * What a party this end holds is sent while the hold lasts. Left out,
   * silence, in either mode. "application" sends what the client sends --
   * for a client in application mode playing hold music or an announcement
   * itself.
   */
  heldAudio?: 'silence' | 'application';
  /**
   * The most calls the client holds at once, either way; left out or 0,
   * 128. Past it a call that arrives is answered 503 with `Retry-After: 2`
   * and `placeCall` rejects with `limitReached`.
   */
  maxDialogs?: number;
  /**
   * The most requests from other ends the client works on at once; left out
   * or 0, 256. Raised beside `maxDialogs` past a few hundred calls, to three
   * a call and 256 more (`docs/08-ffi.md`, "Limits, and what went out twice").
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
   * The server named by a URI whose host RFC 3263 locates --
   * "sip:pbx.example.com" -- in place of `registrarAddress`. The native half
   * asks the platform's resolver; `located` and `locateFailed` say how it went.
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
   * "tcp" or "tls": a connection of the account's own to its server, beside
   * accounts on the client's UDP socket to other servers, so that one client
   * holds an account on UDP with one PBX and another on TCP or TLS with a
   * second. The native half opens it when the stack asks, and the REGISTER
   * and every call of the account go over it. Only on a client signalling
   * over "udp".
   */
  streamProtocol?: 'tcp' | 'tls';
  /**
   * The SHA-256 fingerprint of the one certificate the account's own TLS
   * connection trusts, in any form `pinDigest` reads; it needs
   * `streamProtocol` "tls".
   */
  tlsPin?: string;
  /**
   * The realms the password answers (RFC 3261 §22.1). Left out, the account
   * answers the realm its server first challenges it with and every realm
   * its REGISTERs are challenged with, and no other; an SBC or outbound
   * proxy at the server's address that challenges calls under a realm of its
   * own needs both named. A challenge the password is not for is not
   * answered, and `challengeDeclined` says who asked and why.
   */
  realms?: string[];
}

export interface PlaceCallOptions {
  /** host:port the INVITE goes to, when it is not the account's registrar address. */
  destination?: string;
  /** This call's codecs, in place of the client's. */
  codecs?: string;
  /**
   * Send the call on to the targets a 3xx names (RFC 3261 §8.1.3.4). Off by
   * default: a 3xx then ends the call with its status, and where it pointed
   * is the application's to act on.
   */
  followRedirects?: boolean;
}

export interface AnswerOptions {
  /**
   * The codecs this call takes, in place of the client's: "PCMA,PCMU". An
   * answer keeps the offer's order (RFC 3264 §6.1), so this chooses which
   * codecs rather than which comes first.
   */
  codecs?: string;
}

/** Whether a call was placed here or arrived here. */
export type CallDirection = 'outgoing' | 'incoming';
