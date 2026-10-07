// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// One `sipral_stack_create` handle, the sockets and connections it is
// carried on, and its poll.

import { randomBytes } from 'node:crypto';
import { type Socket as DatagramSocket, createSocket } from 'node:dgram';
import { lookup as lookUpAddress, resolveNaptr, resolveSrv } from 'node:dns/promises';
import { EventEmitter, on } from 'node:events';
import { type Socket as StreamSocket, isIP } from 'node:net';
import { performance } from 'node:perf_hooks';
import { Worker } from 'node:worker_threads';

import koffi from 'koffi';

import { Account } from './account.js';
import { Audio } from './audio.js';
import { Call, type HeaderFields, headerArray } from './call.js';
import { LocalConference, type LocalConferenceOptions } from './conference.js';
import { StackEvent } from './events.js';
import {
  ADDRESS_BYTES,
  PACKET_BYTES,
  SipralError,
  check,
  checkNow,
  config,
  copyText,
  formatAddress,
  handle,
  library,
  parseAddress,
  passing,
  plain,
  read,
  readBytes,
  readText,
  record,
  retryingClockBehind,
  text,
  toggle,
  within,
} from './internal.js';
import { MediaPacket } from './media.js';
import {
  SIPRAL_INVITE_LIMIT_BURST,
  SIPRAL_INVITE_LIMIT_EVERY_MS,
  SIPRAL_INVITE_LIMIT_VOICE_AGENT_BURST,
  SIPRAL_INVITE_LIMIT_VOICE_AGENT_EVERY_MS,
  SIPRAL_STATE_TEXT_MAX,
  SIPRAL_TRANSPORT_MAIN,
  type Pointer,
  type Wide,
  Sipral,
  SipralAudio,
  SipralDnsAnswer,
  SipralDnsRecordType,
  SipralEventKind,
  SipralLink,
  SipralLogLevel,
  SipralNat,
  SipralStatus,
  SipralTlsFailure,
  type SipralTransmit,
  SipralTransport,
  SipralTransportError,
  SipralTurnStream,
  sipral_event_callback_t,
  sipral_log_callback_t,
  sipral_screen_callback_t,
} from './sipral_abi.js';
import { type Refusal, TlsTrust, classify, oneLine, openStream } from './tls.js';
import type { EnginePacket } from './transmit-worker.js';

/** How one connection attempt, the TLS handshake included, may take. */
const STREAM_PATIENCE_MS = 5000;
/** The first wait before connecting again after the signalling connection was lost, doubled each failure... */
const RECONNECT_FIRST_MS = 1000;
/** ...up to this. */
const RECONNECT_MOST_MS = 30000;
/** The first number a connection this class opens for `TransportWanted` is bound at, one more for each after it. */
const FIRST_STREAM = 1024;
/** How long a media socket waits for its NAT mapping and its relay. */
const NAT_PATIENCE_MS = 7000;

/**
 * Answers a lookup the stack asks for (`LookupWanted`): given the name and
 * the `SipralDnsRecordType`, a `SipralDnsAnswer` and, with `Records`, the
 * records -- each its time-to-live in seconds and then its data as a zone
 * file writes it: `300 192.0.2.40`, `300 10 60 5060 sip1.example.com`, or
 * NAPTR without the regexp, `300 10 50 S SIP+D2U _sip._udp.example.com`.
 */
export type Resolver = (name: string, record: number) => Promise<{ answer: number; records: string[] }>;

/** How fast one address may ring this stack: `burst` INVITEs at once, then one every `everyMs`. */
export interface InviteLimit {
  readonly burst: number;
  readonly everyMs: number;
}

/** The floor every stack starts with: ten at once, then one every two seconds. */
export const INVITE_LIMIT_DEFAULT: InviteLimit = { burst: SIPRAL_INVITE_LIMIT_BURST, everyMs: SIPRAL_INVITE_LIMIT_EVERY_MS };

/** The preset for a headless service taking a trunk's calls. */
export const INVITE_LIMIT_VOICE_AGENT: InviteLimit = {
  burst: SIPRAL_INVITE_LIMIT_VOICE_AGENT_BURST,
  everyMs: SIPRAL_INVITE_LIMIT_VOICE_AGENT_EVERY_MS,
};

/** The time-to-live given an address the platform's lookup found, which does not say the zone's. */
const ADDRESS_TTL = 60;

/**
 * The resolver a stack uses when given none: the platform's own lookup
 * (`getaddrinfo`, so the hosts file counts) for A and AAAA, and the
 * system's DNS servers for SRV and NAPTR, whose records Node does not give
 * a time-to-live for and get a minute.
 */
export const systemResolver: Resolver = async (name, recordType) => {
  const nothing = { answer: SipralDnsAnswer.Nothing, records: [] };
  const missing = (error: unknown): boolean => {
    const code = (error as NodeJS.ErrnoException).code;
    return code === 'ENOTFOUND' || code === 'ENODATA' || code === 'EAI_NONAME' || code === 'EAI_NODATA';
  };
  try {
    switch (recordType) {
      case SipralDnsRecordType.A:
      case SipralDnsRecordType.Aaaa: {
        const family = recordType === SipralDnsRecordType.A ? 4 : 6;
        const found = await lookUpAddress(name, { family, all: true });
        const addresses = [...new Set(found.map((entry) => entry.address.split('%')[0] as string))];
        return addresses.length === 0
          ? nothing
          : { answer: SipralDnsAnswer.Records, records: addresses.map((address) => `${ADDRESS_TTL} ${address}`) };
      }
      case SipralDnsRecordType.Srv: {
        const found = await resolveSrv(name);
        return {
          answer: SipralDnsAnswer.Records,
          records: found.map((srv) => `${ADDRESS_TTL} ${srv.priority} ${srv.weight} ${srv.port} ${srv.name}`),
        };
      }
      case SipralDnsRecordType.Naptr: {
        const found = await resolveNaptr(name);
        return {
          answer: SipralDnsAnswer.Records,
          records: found.map(
            (naptr) => `${ADDRESS_TTL} ${naptr.order} ${naptr.preference} ${naptr.flags} ${naptr.service} ${naptr.replacement}`,
          ),
        };
      }
      default:
        return nothing;
    }
  } catch (error) {
    return missing(error) ? nothing : { answer: SipralDnsAnswer.Failed, records: [] };
  }
};

/**
 * How a stack is opened: every field may be left out. Beside what this
 * class acts on itself, every member of `sipral_stack_config_t` the
 * application may set is here in `camelCase` -- `docs/08-ffi.md` says what
 * each does -- and goes to the library as given.
 */
export interface StackOptions {
  /**
   * The address the signalling socket binds. Left out, it listens on every
   * interface and the stack advertises the route toward its first
   * account's server (`sipral_advertised_address`).
   */
  bindHost?: string;
  /** The port, 0 for any. */
  bindPort?: number;
  /** The library to use; `Sipral.open()`'s by default. */
  library?: Sipral;
  /**
   * What SIP travels over, a `SipralTransport` value: UDP (the default) on
   * a socket bound at `bindHost`, or TCP or TLS on one connection to
   * `signallingServer`, which every account and call shares. A connection
   * lost is made again -- one second later, twice as long after each
   * attempt that fails, up to thirty -- and the accounts registered again;
   * each failure is a `TransportFailed` naming why.
   */
  signalling?: number;
  /** The server the signalling connection goes to, `host:port`: the registrar or the outbound proxy. */
  signallingServer?: string;
  /** The name the server's certificate is checked against; the host of `signallingServer` by default. */
  tlsServerName?: string;
  /** Which authorities a TLS connection trusts; the platform's by default. */
  tlsTrust?: TlsTrust;
  /**
   * Over UDP, a request too large for a datagram (RFC 3261 §18.1.1) goes on
   * a TCP connection this class opens to where it was going (on by
   * default); off, the stack is told none is coming and what waited ends.
   */
  streamFallback?: boolean;
  /** Where that connection goes instead, `host:port`, for a server taking TCP on another port. */
  streamServer?: string;
  /** Answers the lookups of accounts added with `serverUri`; {@link systemResolver} by default. */
  resolver?: Resolver;
  /** How fast one address may ring this stack; {@link INVITE_LIMIT_DEFAULT} until set. */
  inviteLimit?: InviteLimit;
  /** The name a TLS TURN server's certificate is checked against; the host of `turnServer` by default. */
  turnServerName?: string;
  /** Which authorities a TLS TURN server is trusted by; the platform's by default. */
  turnTrust?: TlsTrust;
  /**
   * Who pumps the calls' audio, a `SipralAudio` value: `Application` (the
   * default here) leaves each call's frames to {@link Media}; `Device` has
   * the library open the platform's microphone and loudspeaker and run
   * every call through them, chosen through {@link Stack.audio}.
   * `SipralStatus.NotSupported` where {@link features} has no
   * `SIPRAL_FEATURE_AUDIO_DEVICE`.
   */
  audio?: number;
  /** What `User-Agent` and `Server` say. */
  userAgent?: string;
  /** The codecs every call offers, most preferred first: `'PCMA,PCMU'`. */
  codecs?: string;
  frameMs?: number;
  offerDtmf?: boolean;
  offerRtcpMux?: boolean;
  silenceSuppression?: boolean;
  mediaStallWatchdog?: boolean;
  mediaStallMs?: number;
  timerT1Ms?: number;
  timerT2Ms?: number;
  timerT4Ms?: number;
  /** A `SipralSrtp` value: whether calls offer and take SRTP. */
  srtp?: number;
  /** A `SipralIce` value. */
  ice?: number;
  /** A `SipralNat` value: `Stun` maps every media socket through `stunServer` first. */
  nat?: number;
  /** The STUN server, `host:port`. */
  stunServer?: string;
  /** The STUN servers to turn to, in order, when one fails. */
  stunFallbacks?: readonly string[];
  g729AnnexB?: boolean;
  /** The TURN server, `host:port`, riding on `nat: Stun`. */
  turnServer?: string;
  turnUsername?: string;
  turnPassword?: string;
  /** A `SipralTransport` value: the TURN server over TCP or TLS. */
  turnTransport?: number;
  /** Whether a REFER outside any dialog is taken to the application (`Referral`) rather than refused 403. */
  referrals?: boolean;
  registrarKeepalive?: boolean;
  registrarKeepaliveMs?: number;
  /** A `SipralAudioActivation` value, in device mode. */
  audioActivation?: number;
  audioProbeMs?: number;
  audioDeviceRateHz?: number;
  /** The most calls the stack holds at once, either way (0 for 128). */
  maxDialogs?: number;
  /** The most requests from other ends it works on at once (0 for 256). */
  maxServerTransactions?: number;
  diagnosticDecisions?: number;
  diagnosticRecords?: number;
  /** A `SipralDtmfDetection` value. */
  dtmfDetection?: number;
  /** The RTP port range a firewall was opened for: every media socket binds an even port from it. */
  rtpPortMin?: number;
  rtpPortMax?: number;
  /** The SRTP suites offered and accepted, by their RFC 4568 and 7714 names, most preferred first. */
  srtpSuites?: readonly string[];
  pathMtu?: number;
  datagramWithoutStreamBytes?: number;
  /** Keys the pseudonyms the log writes: 16 bytes or more, a secret like a key. */
  pseudonymSalt?: Buffer;
  diagnosticTrace?: boolean;
  systemEchoCancellation?: boolean;
  /** A `SipralHeldAudio` value: what a party this end holds is sent. */
  heldAudio?: number;
}

/**
 * How an account is added: by `registrarAddress` or by `serverUri`, one of
 * the two. Every member of `sipral_account_config_t` is here in
 * `camelCase` and goes to the library as given.
 */
export interface AccountOptions {
  /** Where its requests go, `host:port`. */
  registrarAddress?: string;
  /** The server named by a URI RFC 3263 locates -- `sip:pbx.example.com` -- in place of `registrarAddress`. */
  serverUri?: string;
  /** Ask the domain for NAPTR records before SRV. */
  serverNaptr?: boolean;
  /** The registrar's URI; without one the account never registers. */
  registrar?: string;
  /** Where the account is reached; by default its user at this stack's address. */
  contact?: string;
  /** Who it answers a challenge as. */
  authUser?: string;
  /** The password it answers a challenge with. */
  authPassword?: string;
  /** The name `From` carries. */
  displayName?: string;
  /** The realms the password answers (RFC 3261 §22.1); empty for the server's own. */
  realms?: readonly string[];
  /** Keep the flow to the server open at this interval, 1000 to 120000 ms. */
  keepaliveMs?: number;
  /** The SHA-256 fingerprint of the one TLS certificate it trusts, in the forms {@link TlsTrust.pinned} takes. */
  tlsPin?: string;
  /** `SipralTransport.Tcp`, `Tls`, `Ws` or `Wss`: a connection of its own to its server, on a stack signalling over UDP; WS/WSS run a WebSocket on TCP/TLS (RFC 7118). */
  streamProtocol?: number;
  /** The `Host` of a WS/WSS account's handshake; the server's address when left out. */
  websocketHost?: string;
  /** The resource that handshake asks for; `/ws` when left out. */
  websocketResource?: string;
  instanceId?: string;
  expiresSeconds?: number;
  /** Header fields on every REGISTER. */
  headers?: HeaderFields;
  pushProvider?: string;
  pushPrid?: string;
  pushParam?: string;
  pushWakesItself?: boolean;
  qualityReportUri?: string;
  /** A `SipralSessionTimer` value. */
  sessionTimer?: number;
  sessionIntervalSeconds?: number;
  /** `SipralPrivacy` bits every call it places asks for. */
  privacy?: number;
  /** The addresses whose `P-Asserted-Identity` it believes. */
  trustedPeers?: readonly string[];
  /** A `SipralSrtp` value its calls are held to. */
  srtp?: number;
  srtpSuites?: readonly string[];
  /** A `SipralStirVerification` value. */
  stirVerification?: number;
  stirKey?: Buffer;
  stirCertificateUrl?: string;
  stirOrig?: string;
  stirOrigid?: string;
  /** A `SipralAttestation` value. */
  stirAttestation?: number;
  recordingInClear?: boolean;
}

/** How a call is placed or answered. */
export interface CallOptions {
  /** Where the call's media socket binds; by default the route toward the far end. */
  mediaHost?: string;
  /** The port, 0 for any (or one from the stack's RTP range). */
  mediaPort?: number;
  /** Send the INVITE here rather than to the account's registrar address. */
  destination?: string;
  /** What this call offers or takes, in place of the stack's: `'PCMA,PCMU'`. */
  codecs?: string;
  /**
   * Placing a call, send it on to the targets a 3xx names (RFC 3261
   * §8.1.3.4). Off by default: a 3xx then ends the call with its status, and
   * the `Contact` it named is the application's to act on.
   */
  followRedirects?: boolean;
  /** A `SipralSrtp` value, over the stack's. */
  srtp?: number;
  /** A `SipralIce` value, over the stack's. */
  ice?: number;
  /** Offer, or take, a real-time text stream (RFC 4103) on a socket of its own. */
  text?: boolean;
  /** Offer RTP/AVPF with Generic NACKs and reduced-size RTCP. */
  feedback?: boolean;
  /** This end is a conference's focus (RFC 4579): `isfocus` on its `Contact`. */
  focus?: boolean;
  /** Header fields on the INVITE. */
  headers?: HeaderFields;
  /** Keep every fork that answers, rather than the first. */
  keepAllForks?: boolean;
}

/** What a stack emits. */
export interface StackEvents {
  /** Every event the stack raises, in order. */
  event: [StackEvent];
  /** An error thrown by a listener, or met on a socket. */
  error: [Error];
}

/** One line of the stack's log. */
export interface LogLine {
  /** A `SipralLogLevel` value. */
  readonly level: number;
  /** The part of the stack that wrote it: `sip`, `call`, `api`... */
  readonly target: string;
  /** The line, redacted. */
  readonly message: string;
  /** How many lines a flood turned away before this one. */
  readonly suppressed: number;
}

/** Bind `socket` and resolve with its port. */
function bind(socket: DatagramSocket, host: string, port: number): Promise<number> {
  return new Promise((resolve, reject) => {
    const failed = (error: Error): void => reject(error);
    socket.once('error', failed);
    socket.bind(port, host, () => {
      socket.off('error', failed);
      resolve(socket.address().port);
    });
  });
}

/** A UDP socket of the family `host` is in. */
function udp(host: string): DatagramSocket {
  return createSocket(isIP(host) === 6 ? 'udp6' : 'udp4');
}

/** Whether `peer` is `host:port` with an address for its host. */
function isAddress(peer: string | null | undefined): peer is string {
  return typeof peer === 'string' && parseAddress(peer) !== null;
}

/**
 * The address of this machine's route toward `peer` -- what a server at
 * `peer` reaches it at (`sipral_advertised_address`) -- or `127.0.0.1` for
 * a peer that is not an address literal.
 */
export function routeHost(peer: string | null | undefined, sipral: Sipral = library()): string {
  if (!isAddress(peer)) {
    return '127.0.0.1';
  }
  const [bound, boundLength] = text(peer.startsWith('[') ? '[::]:0' : '0.0.0.0:0');
  const [far, farLength] = text(peer);
  const buffer = Buffer.alloc(ADDRESS_BYTES);
  const needed = new BigUint64Array(1);
  const status = sipral.sipral_advertised_address(bound, boundLength, far, farLength, buffer, buffer.length, needed);
  if (status !== SipralStatus.Ok) {
    return '127.0.0.1';
  }
  const advertised = buffer.toString('utf8', 0, Math.max(0, Number(needed[0]) - 1));
  const colon = advertised.lastIndexOf(':');
  const host = advertised.slice(0, colon);
  return host.startsWith('[') ? host.slice(1, -1) : host;
}

/** `host` and `port` of a `host:port` that may name a host rather than an address. */
function split(address: string): { host: string; port: number } {
  const colon = address.lastIndexOf(':');
  return { host: address.slice(0, colon).replace(/^\[|\]$/g, ''), port: Number(address.slice(colon + 1)) };
}

/** An account's own connection: each protocol and its `transport=` name. */
const OWN_STREAMS: ReadonlyMap<number, string> = new Map([
  [SipralTransport.Tcp, 'tcp'],
  [SipralTransport.Tls, 'tls'],
  [SipralTransport.Ws, 'ws'],
  [SipralTransport.Wss, 'wss'],
]);

/** A connection this class opened for `TransportWanted`, bound at its own transport number. */
interface SipStream {
  readonly destination: string;
  readonly socket: StreamSocket;
}

/** A media socket named with `sipral_stack_nat_map`, until its media takes it. */
interface MappedSocket {
  readonly socket: DatagramSocket;
  readonly listener: (data: Buffer, from: { address: string; port: number }) => void;
  mapped: () => void;
  relayed: () => void;
}

/**
 * A SIP stack: the class an application opens first.
 *
 * {@link Stack.open} binds the signalling socket -- or connects to the
 * signalling server over TCP or TLS -- and creates the stack; {@link close}
 * hangs up what is still up, destroys the stack exactly once and closes
 * every socket and connection this package opened. Everything runs on the
 * thread that opened it: the library calls the event callback from inside
 * `sipral_stack_poll`, the callback only copies the event out, and the
 * copies are delivered once the poll has returned. In device mode the
 * engine's packets cross from a worker thread of their own, so that the
 * engine never waits on this one.
 */
export class Stack extends EventEmitter<StackEvents> {
  /** The library. */
  readonly sipral: Sipral;
  /** What SIP travels over, a `SipralTransport` value. */
  readonly signalling: number;
  /** Whether the library's engine carries the calls' audio. */
  readonly deviceMode: boolean;
  /** The library's audio engine, in device mode. */
  readonly audio: Audio;
  /** The RTP port range media sockets are bound in, or null. */
  readonly rtpPorts: readonly [number, number] | null;
  /**
   * Whether the last {@link moveTo} that bound the UDP socket again kept its
   * port; false when another socket held it there and the system chose
   * another, which {@link bindAddress} then names.
   */
  keptSignallingPort = true;

  private stackHandle = 0n;
  private address: string;
  private socket: DatagramSocket | null;
  private link: StreamSocket | null;
  private readonly routes: boolean;
  private routeChosen: boolean;
  private chosenPort: number;
  private bindHost: string | undefined;
  private readonly started = performance.now();
  private readonly calls = new Map<bigint, Call>();
  private readonly accounts = new Map<bigint, Account>();
  private readonly pending: StackEvent[] = [];
  private delivering = false;
  private closed = false;
  private callback: bigint | null = null;
  private logCallback: bigint | null = null;
  private screenCallback: bigint | null = null;
  private readonly retired: bigint[] = [];
  private ticker: NodeJS.Timeout | undefined;
  private reconnectTimer: NodeJS.Timeout | undefined;
  private reconnectDelay = RECONNECT_FIRST_MS;
  private readonly result = record('sipral_poll_result_t');
  private readonly transmitData = Buffer.alloc(PACKET_BYTES);
  private readonly transmitTo = Buffer.alloc(ADDRESS_BYTES);
  private readonly transmitFrom = Buffer.alloc(ADDRESS_BYTES);
  private readonly transmit = record('sipral_transmit_t');
  private readonly farewell = new MediaPacket();
  private readonly farewellCall = new BigUint64Array(1);
  private readonly server: { host: string; port: number } | null;
  private readonly serverName: string | undefined;
  private readonly tlsTrust: TlsTrust;
  private readonly givenServerName: string | undefined;
  private readonly streamFallback: boolean;
  private readonly streamServer: { host: string; port: number } | null;
  private readonly sipStreams = new Map<number, SipStream>();
  private readonly streamsOpening = new Set<string>();
  private nextStream = FIRST_STREAM;
  private readonly resolver: Resolver;
  private natStun: boolean;
  private readonly turn: boolean;
  private readonly turnServerName: string | undefined;
  private readonly turnTrust: TlsTrust;
  private readonly stunSockets = new Map<string, MappedSocket>();
  private readonly probes = new Map<number, { address: string; socket: DatagramSocket }>();
  private readonly turnStreams = new Map<string, StreamSocket>();
  private readonly turnSockets = new Map<bigint, string>();
  private worker: Worker | null = null;

  private constructor(
    sipral: Sipral,
    options: StackOptions,
    socket: DatagramSocket | null,
    link: StreamSocket | null,
    address: string,
  ) {
    super();
    this.sipral = sipral;
    this.signalling = options.signalling ?? SipralTransport.Udp;
    this.socket = socket;
    this.link = link;
    this.address = address;
    this.bindHost = options.bindHost;
    this.chosenPort = options.bindPort ?? 0;
    this.routes = options.bindHost === undefined;
    const streamed = this.signalling !== SipralTransport.Udp;
    this.routeChosen = !this.routes || streamed || options.streamServer !== undefined;
    this.deviceMode = options.audio === SipralAudio.Device;
    this.audio = new Audio(this);
    this.server = streamed && options.signallingServer !== undefined ? split(options.signallingServer) : null;
    this.serverName = options.tlsServerName ?? this.server?.host;
    this.givenServerName = options.tlsServerName;
    this.tlsTrust = options.tlsTrust ?? TlsTrust.platform();
    this.streamFallback = options.streamFallback ?? true;
    this.streamServer = options.streamServer === undefined ? null : split(options.streamServer);
    this.resolver = options.resolver ?? systemResolver;
    this.natStun = options.nat === SipralNat.Stun;
    this.turn = options.turnServer !== undefined;
    this.turnServerName = options.turnServerName ?? (options.turnServer === undefined ? undefined : split(options.turnServer).host);
    this.turnTrust = options.turnTrust ?? TlsTrust.platform();
    const low = options.rtpPortMin ?? 0;
    const high = options.rtpPortMax ?? 0;
    this.rtpPorts = low !== 0 || high !== 0 ? [low, high] : null;
  }

  /**
   * Bind the signalling socket -- or connect to `signallingServer` -- and
   * create a stack on it. A first connection that fails is reported as
   * `TransportFailed` and tried again; the stack is open either way.
   */
  static async open(options: StackOptions = {}): Promise<Stack> {
    for (const [name, value] of [
      ['maxDialogs', options.maxDialogs ?? 0],
      ['maxServerTransactions', options.maxServerTransactions ?? 0],
    ] as const) {
      if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) {
        throw new RangeError(`${name} is 0 to 4294967295`);
      }
    }
    const signalling = options.signalling ?? SipralTransport.Udp;
    if (signalling !== SipralTransport.Udp && signalling !== SipralTransport.Tcp && signalling !== SipralTransport.Tls) {
      throw new RangeError('signalling is SipralTransport.Udp, Tcp or Tls');
    }
    if (signalling !== SipralTransport.Udp && options.signallingServer === undefined) {
      throw new TypeError('sipral: SIP over TCP or TLS needs signallingServer, host:port');
    }
    const sipral = options.library ?? library();
    let socket: DatagramSocket | null = null;
    let link: StreamSocket | null = null;
    let address: string;
    let refused: Refusal | null = null;
    if (signalling === SipralTransport.Udp) {
      const host = options.bindHost ?? '0.0.0.0';
      socket = udp(host);
      let port: number;
      try {
        port = await bind(socket, host, options.bindPort ?? 0);
      } catch (error) {
        socket.close();
        throw error;
      }
      const advertised = options.bindHost ?? (options.streamServer === undefined ? '127.0.0.1' : routeHost(options.streamServer, sipral));
      address = formatAddress(advertised, port);
    } else {
      const server = split(options.signallingServer as string);
      try {
        link = await openStream(server.host, server.port, {
          bindHost: options.bindHost,
          trust: signalling === SipralTransport.Tls ? (options.tlsTrust ?? TlsTrust.platform()) : null,
          serverName: options.tlsServerName,
          timeoutMs: STREAM_PATIENCE_MS,
        });
        address = formatAddress(link.localAddress ?? '127.0.0.1', link.localPort ?? 0);
      } catch (error) {
        refused = classify(error);
        address = formatAddress(options.bindHost ?? routeHost(options.signallingServer, sipral), options.bindPort ?? 0);
      }
    }
    const stack = new Stack(sipral, options, socket, link, address);
    try {
      await stack.create(options);
    } catch (error) {
      stack.release();
      socket?.close();
      link?.destroy();
      throw error;
    }
    if (options.inviteLimit !== undefined) {
      stack.setInviteLimit(options.inviteLimit);
    }
    stack.start(refused);
    return stack;
  }

  /** The stack's handle. */
  get handle(): bigint {
    return this.stackHandle;
  }

  /**
   * Where the signalling socket is reached, `host:port`: what every `Via`
   * this stack writes carries, and where another stack reaches it.
   */
  get bindAddress(): string {
    return this.address;
  }

  /** Whether SIP can go out now: always over UDP, and over TCP or TLS while the connection stands. */
  get connected(): boolean {
    return this.socket !== null || this.link !== null;
  }

  /** What follows the address in a `Contact` this package writes: `;transport=tcp` or `;transport=tls` over a connection. */
  get contactParameters(): string {
    if (this.signalling === SipralTransport.Tls) {
      return ';transport=tls';
    }
    return this.signalling === SipralTransport.Tcp ? ';transport=tcp' : '';
  }

  /** Milliseconds since the stack was created: what every `now_ms` is measured in. */
  nowMs(): number {
    return Math.floor(performance.now() - this.started);
  }

  /** Every event the stack raises from now on, as an async iterator. */
  events(options: { signal?: AbortSignal } = {}): AsyncIterableIterator<StackEvent> {
    const iterator = on(this, 'event', options) as AsyncIterableIterator<[StackEvent]>;
    return (async function* () {
      for await (const [event] of iterator) {
        yield event;
      }
    })();
  }

  /**
   * The next event that `matches`, or a `TimeoutError` after `timeoutMs`.
   * Listening starts at once, so nothing raised after this returns is
   * missed.
   */
  next(matches: (event: StackEvent) => boolean, timeoutMs = 15000): Promise<StackEvent> {
    return within(
      new Promise<StackEvent>((resolve) => {
        const listener = (event: StackEvent): void => {
          if (matches(event)) {
            this.off('event', listener);
            resolve(event);
          }
        };
        this.on('event', listener);
      }),
      timeoutMs,
      'the event waited for on the stack',
    );
  }

  // -- accounts and calls -----------------------------------------------

  /**
   * Add an account (`sipral_account_add`) whose requests go to
   * `registrarAddress`, or to wherever `serverUri` is located. With
   * `registrar` it can register there ({@link Account.register}); without
   * one it never registers, and the server is only its outbound proxy.
   */
  addAccount(aor: string, options: AccountOptions): Account {
    this.ensureOpen();
    if ((options.registrarAddress === undefined) === (options.serverUri === undefined)) {
      throw new TypeError('sipral: an account names its server by registrarAddress or by serverUri, one of the two');
    }
    const streamProtocol = options.streamProtocol ?? 0;
    const named = OWN_STREAMS.get(streamProtocol);
    if (streamProtocol !== 0 && (named === undefined || this.signalling !== SipralTransport.Udp)) {
      throw new TypeError('sipral: streamProtocol is SipralTransport.Tcp, Tls, Ws or Wss, on a stack that signals over UDP');
    }
    const parameters = named === undefined ? this.contactParameters : `;transport=${named}`;
    const advertised =
      options.contact === undefined && this.routes && options.registrarAddress !== undefined && this.signalling === SipralTransport.Udp
        ? this.advertiseToward(options.registrarAddress)
        : null;
    const contact = options.contact ?? this.defaultContact(aor, advertised, parameters);
    const { headers, tlsPin, ...rest } = options;
    const fields = headers === undefined ? { array: null, count: 0 } : headerArray(headers);
    const [pin, pinLength] = text(tlsPin);
    const made = config(
      'sipral_account_config_t',
      { ...rest, aor, contact },
      {
        headers: fields.array,
        headers_len: fields.count,
        tls_pin_sha256: pin,
        tls_pin_sha256_len: pinLength,
      },
      { realms: '\n', trusted_peers: ', ' },
    );
    const out = new BigUint64Array(1);
    check(this.sipral, 'sipral_account_add', this.sipral.sipral_account_add(this.stackHandle, made, out));
    for (const kept of (made as unknown as { kept: Buffer[] }).kept) {
      kept.fill(0);
    }
    const account = new Account(this, handle(out[0] ?? 0n), aor, {
      registrarAddress: options.registrarAddress ?? '',
      contactGiven: options.contact !== undefined,
      serverUri: options.serverUri ?? null,
      advertised,
      streamProtocol,
      tlsPin: tlsPin ?? null,
      contactParameters: parameters,
    });
    this.accounts.set(account.handle, account);
    this.poll();
    return account;
  }

  /**
   * Place a call from `account` to `target`, its media socket bound -- and
   * mapped through STUN, on a stack with `nat: Stun` -- and its address
   * offered before the INVITE goes out.
   */
  async placeCall(account: Account, target: string, options: CallOptions = {}): Promise<Call> {
    return this.placeWith(account, options, target, (made, out) =>
      this.sipral.sipral_call_place(this.stackHandle, account.handle, made, out, this.nowMs()), 'sipral_call_place');
  }

  /**
   * Answer the `IncomingCall` event `incoming`, with a media socket bound by
   * default on the route toward the account's server -- or, for a call
   * already rung with {@link ringCall}, on the socket opened then.
   * `codecs` chooses which codecs this call takes; `text`, `feedback` and
   * `focus` are as {@link placeCall} takes them.
   */
  async answerCall(incoming: StackEvent, options: Omit<CallOptions, 'destination' | 'followRedirects'> = {}): Promise<Call> {
    this.ensureOpen();
    if (incoming.kind !== SipralEventKind.IncomingCall) {
      throw new TypeError('sipral: answerCall takes an IncomingCall event');
    }
    const rung = this.calls.get(incoming.call);
    if (rung !== undefined) {
      rung.answer(options);
      return rung;
    }
    const call = await this.incoming(incoming, options);
    try {
      call.answer(options);
    } catch (error) {
      call.close();
      throw error;
    }
    return call;
  }

  /**
   * Say an incoming call is ringing and build its {@link Call}, not yet
   * answered: a 180, or with `media` a 183 whose answer this stack writes,
   * so the caller hears what the application plays before
   * {@link Call.answer} or {@link answerCall}.
   */
  async ringCall(incoming: StackEvent, options: Pick<CallOptions, 'mediaHost' | 'mediaPort' | 'srtp' | 'codecs'> & { media?: boolean } = {}): Promise<Call> {
    this.ensureOpen();
    const call = await this.incoming(incoming, options);
    try {
      if (options.media === true) {
        call.ringMedia(options);
      } else {
        call.ring();
      }
    } catch (error) {
      call.close();
      throw error;
    }
    return call;
  }

  /** Refuse the `IncomingCall` event `incoming` with `code`. */
  rejectCall(incoming: StackEvent, code = 486): void {
    this.ensureOpen();
    checkNow(this.sipral, 'sipral_call_reject', () => this.sipral.sipral_call_reject(this.stackHandle, incoming.call, code, this.nowMs()));
    this.poll();
  }

  /**
   * Answer an incoming call nothing answered with a redirection
   * (`sipral_call_redirect`): `statusCode` 300 to 399 (302 by default) with
   * `targets` in `Contact`; with `reason` -- RFC 5806's `unconditional`,
   * `user-busy`, `no-answer` -- a `Diversion` names the address called.
   */
  redirectCall(incoming: StackEvent, targets: string | readonly string[], options: { statusCode?: number; reason?: string } = {}): void {
    this.ensureOpen();
    const [listed, listedLength] = text(typeof targets === 'string' ? targets : targets.join(', '));
    const [reason, reasonLength] = text(options.reason);
    checkNow(this.sipral, 'sipral_call_redirect', () =>
      this.sipral.sipral_call_redirect(
        this.stackHandle,
        incoming.call,
        options.statusCode ?? 302,
        listed,
        listedLength,
        reason,
        reasonLength,
        this.nowMs(),
      ),
    );
    this.poll();
  }

  /**
   * Take the REFER of a `TransferRequested` (inside a call) or a `Referral`
   * (outside any) and place the call it asks for (`sipral_call_accept_transfer`):
   * the stack answers 202, reports on the new call to whoever asked, and
   * places it from the account the event names. Taking one is a decision
   * with a bill attached, so it is never made on the application's behalf.
   */
  async acceptTransfer(event: StackEvent, options: Pick<CallOptions, 'mediaHost' | 'mediaPort' | 'destination' | 'srtp' | 'ice'> = {}): Promise<Call> {
    this.ensureOpen();
    if (event.kind !== SipralEventKind.TransferRequested && event.kind !== SipralEventKind.Referral) {
      throw new TypeError('sipral: acceptTransfer takes a TransferRequested or a Referral event');
    }
    const account = this.accounts.get(event.account);
    return this.placeWith(account, options, null, (made, out) =>
      this.sipral.sipral_call_accept_transfer(this.stackHandle, event.call, made, out, this.nowMs()), 'sipral_call_accept_transfer');
  }

  /** Refuse the REFER of a `TransferRequested` or a `Referral` with `code`, 300 to 699. */
  rejectTransfer(event: StackEvent, code = 603): void {
    this.ensureOpen();
    checkNow(this.sipral, 'sipral_call_reject_transfer', () =>
      this.sipral.sipral_call_reject_transfer(this.stackHandle, event.call, code, this.nowMs()),
    );
    this.poll();
  }

  /**
   * Take the REFER of a `TransferRequested` with a call the application
   * placed itself (`sipral_call_accept_transfer_placed`): answered 202, and
   * `placed`'s progress goes to the far end in NOTIFYs.
   */
  acceptTransferPlaced(event: StackEvent, placed: Call): void {
    this.ensureOpen();
    checkNow(this.sipral, 'sipral_call_accept_transfer_placed', () =>
      this.sipral.sipral_call_accept_transfer_placed(this.stackHandle, event.call, placed.handle, this.nowMs()),
    );
    this.poll();
  }

  /**
   * Every entry of one identity list a call's INVITE carried -- `which` a
   * `SipralIdentityText` value -- for a call that may have no {@link Call}
   * yet: its `IncomingCall` event, or its handle.
   */
  callIdentity(call: bigint | StackEvent, which: number): string[] {
    const callHandle = typeof call === 'bigint' ? call : call.call;
    const count = new BigUint64Array(1);
    checkNow(this.sipral, 'sipral_call_identity_count', () =>
      this.sipral.sipral_call_identity_count(this.stackHandle, callHandle, which, count),
    );
    const found: string[] = [];
    for (let index = 0; index < Number(count[0]); index++) {
      found.push(
        copyText(this.sipral, 'sipral_call_identity_text', (buffer, capacity, needed) =>
          this.sipral.sipral_call_identity_text(this.stackHandle, callHandle, index, which, buffer, capacity, needed),
        ),
      );
    }
    return found;
  }

  /** The {@link Call} already made for a call handle. */
  callFor(callHandle: bigint): Call | undefined {
    return this.calls.get(callHandle);
  }

  /** Make a local conference on this stack (`sipral_local_conference_create`). */
  createConference(options: LocalConferenceOptions = {}): LocalConference {
    this.ensureOpen();
    return new LocalConference(this, options);
  }

  /** `sipral_announcement_forget`: an announcement ({@link Account.announce}) no longer waited for. */
  forgetAnnouncement(announcement: bigint): void {
    check(this.sipral, 'sipral_announcement_forget', this.sipral.sipral_announcement_forget(this.stackHandle, announcement));
  }

  // -- what the stack runs with, and what it has done ---------------------

  /** What the stack runs with, every default filled in, with the SRTP suites its calls offer in order. */
  settings(): Record<string, unknown> & { srtpSuites: number[] } {
    const out = record('sipral_stack_settings_t');
    checkNow(this.sipral, 'sipral_stack_settings', () => this.sipral.sipral_stack_settings(this.stackHandle, out));
    const read = plain(out, 'sipral_stack_settings_t');
    const count = read.srtpSuiteCount as number;
    const suites = new Uint32Array(Math.max(count, 1));
    const written = new BigUint64Array(1);
    checkNow(this.sipral, 'sipral_stack_srtp_suite_order', () =>
      this.sipral.sipral_stack_srtp_suite_order(this.stackHandle, suites, count, written),
    );
    return { ...read, srtpSuites: [...suites.subarray(0, Number(written[0]))] };
  }

  /** The codecs every call offers, in order, as `SipralCodec` values (`sipral_stack_codec_order`). */
  codecOrder(): number[] {
    const out = new Uint32Array(64);
    const count = new BigUint64Array(1);
    checkNow(this.sipral, 'sipral_stack_codec_order', () =>
      this.sipral.sipral_stack_codec_order(this.stackHandle, out, out.length, count),
    );
    return [...out.subarray(0, Number(count[0]))];
  }

  /** The stack's health counters since it was created (`sipral_stack_counters`). */
  counters(): Record<string, number> {
    const out = record('sipral_counters_t');
    checkNow(this.sipral, 'sipral_stack_counters', () => this.sipral.sipral_stack_counters(this.stackHandle, out));
    return plain(out, 'sipral_counters_t') as Record<string, number>;
  }

  /**
   * Everything the stack holds, as the redacted text
   * `sipral_stack_state_text` writes for a crash report.
   */
  state(): string {
    return copyText(
      this.sipral,
      'sipral_stack_state_text',
      (buffer, capacity, needed) => this.sipral.sipral_stack_state_text(this.stackHandle, buffer, capacity, needed),
      SIPRAL_STATE_TEXT_MAX,
    );
  }

  /** The diagnostic record of every call the stack keeps, as JSON. */
  diagnosticsJson(): string {
    return copyText(
      this.sipral,
      'sipral_stack_diagnostics_json',
      (buffer, capacity, needed) => this.sipral.sipral_stack_diagnostics_json(this.stackHandle, buffer, capacity, needed),
      4096,
    );
  }

  /** Whether the trace level writes every SIP message whole from now on (`sipral_stack_diagnostic_trace`). */
  setDiagnosticTrace(on: boolean): void {
    checkNow(this.sipral, 'sipral_stack_diagnostic_trace', () => this.sipral.sipral_stack_diagnostic_trace(this.stackHandle, toggle(on)));
  }

  /**
   * Send the stack's log to `handler` at `level` (a `SipralLogLevel` value)
   * and louder; `Off` or no handler turns it off. Every line is already
   * redacted (`docs/17-observability.md`).
   */
  setLog(level: number, handler?: (line: LogLine) => void): void {
    if (handler === undefined || level === SipralLogLevel.Off) {
      checkNow(this.sipral, 'sipral_stack_log', () => this.sipral.sipral_stack_log(this.stackHandle, SipralLogLevel.Off, null, null));
      return;
    }
    const callback = koffi.register((address: Pointer) => {
      try {
        const line = plain(address, 'sipral_log_record_t');
        handler({
          level: line.level as number,
          target: (line.target as string | null) ?? '',
          message: (line.message as string | null) ?? '',
          suppressed: Number(line.suppressed),
        });
      } catch (error) {
        queueMicrotask(() => this.report(error));
      }
    }, koffi.pointer(sipral_log_callback_t));
    checkNow(this.sipral, 'sipral_stack_log', () => this.sipral.sipral_stack_log(this.stackHandle, level, callback, null));
    // the callback it replaced may still be delivering a batch: kept until the stack closes
    if (this.logCallback !== null) {
      this.retired.push(this.logCallback);
    }
    this.logCallback = callback;
  }

  /**
   * Screen every INVITE before it rings (`sipral_stack_screen`): `policy`
   * answers a SIP status, `SIPRAL_SCREEN_ACCEPT` (200) to let it through or
   * the refusal to answer it with. Null removes the policy.
   */
  setScreen(policy: ((request: { source: string; message: Buffer | null }) => number) | null): void {
    if (policy === null) {
      check(this.sipral, 'sipral_stack_screen', this.sipral.sipral_stack_screen(this.stackHandle, null, null));
    } else {
      const callback = koffi.register((address: Pointer) => {
        try {
          const request = read<{ source: Pointer; source_len: Wide; message: Pointer; message_len: Wide }>(
            address,
            'sipral_screen_request_t',
          );
          return policy({
            source: readText(request.source, request.source_len) ?? '',
            message: readBytes(request.message, request.message_len),
          });
        } catch (error) {
          queueMicrotask(() => this.report(error));
          return 500;
        }
      }, koffi.pointer(sipral_screen_callback_t));
      check(this.sipral, 'sipral_stack_screen', this.sipral.sipral_stack_screen(this.stackHandle, callback, null));
      if (this.screenCallback !== null) {
        this.retired.push(this.screenCallback);
      }
      this.screenCallback = callback;
      return;
    }
    if (this.screenCallback !== null) {
      this.retired.push(this.screenCallback);
      this.screenCallback = null;
    }
  }

  /** How fast one address may ring this stack (`sipral_stack_invite_limit`). */
  setInviteLimit(limit: InviteLimit): void {
    check(this.sipral, 'sipral_stack_invite_limit', this.sipral.sipral_stack_invite_limit(this.stackHandle, limit.everyMs, limit.burst));
  }

  /**
   * Ask these STUN servers from now on, in order, each `host:port`
   * (`sipral_stack_stun_servers`); an empty list asks nobody any more.
   */
  setStunServers(servers: readonly string[]): void {
    const [listed, length] = text(servers.length === 0 ? null : servers.join(','));
    checkNow(this.sipral, 'sipral_stack_stun_servers', () =>
      this.sipral.sipral_stack_stun_servers(this.stackHandle, listed, length, this.nowMs()),
    );
    this.natStun = servers.length > 0;
    this.poll();
  }

  /**
   * `sipral_stack_stir`: verify the callers of the calls this stack's
   * accounts receive against `anchors` (PEM or DER certificates) from now on
   * (RFC 8224); null for a stack whose accounts only sign. `unixSeconds` is
   * the wall clock, this machine's by default.
   */
  stir(
    anchors: string | Buffer | null,
    options: { freshnessSeconds?: number; certificateWaitMs?: number; unixSeconds?: number; acceptServiceProviderCodes?: boolean } = {},
  ): void {
    const made = config('sipral_stir_config_t', {
      ...options,
      anchors: anchors === null ? undefined : Buffer.from(anchors),
      unixSeconds: options.unixSeconds ?? Math.floor(Date.now() / 1000),
    });
    checkNow(this.sipral, 'sipral_stack_stir', () => this.sipral.sipral_stack_stir(this.stackHandle, made, this.nowMs()));
  }

  /**
   * `sipral_call_stir_certificate`: the chain a verification's certificate
   * URL yielded, PEM or DER, or null for one that could not be had. `call`
   * is the handle the `CallerVerification` event named.
   */
  stirCertificate(call: bigint, chain: Buffer | null): void {
    checkNow(this.sipral, 'sipral_call_stir_certificate', () =>
      this.sipral.sipral_call_stir_certificate(this.stackHandle, call, chain, chain?.length ?? 0, this.nowMs()),
    );
    this.poll();
  }

  /**
   * `sipral_stack_resolved`: where a dialog's next hop actually is, the
   * answer to `ResolveNeeded`: `addresses` in priority order, `protocol` a
   * `SipralTransport` value or 0 to keep the flow's.
   */
  resolved(dialog: bigint, addresses: readonly string[], protocol = 0): void {
    const [listed, length] = text(addresses.join(','));
    check(this.sipral, 'sipral_stack_resolved', this.sipral.sipral_stack_resolved(this.stackHandle, dialog, listed, length, protocol));
  }

  /** Start recording the signalling this stack is fed, for a replay (`docs/18-replay.md`). */
  startRecording(note?: string): void {
    const [said, length] = text(note);
    check(this.sipral, 'sipral_stack_recording_start', this.sipral.sipral_stack_recording_start(this.stackHandle, said, length));
  }

  /** Stop recording, and take the recording out as text. */
  stopRecording(): string {
    return copyText(
      this.sipral,
      'sipral_stack_recording_stop',
      (buffer, capacity, needed) => this.sipral.sipral_stack_recording_stop(this.stackHandle, buffer, capacity, needed),
      65536,
    );
  }

  // -- the process and the network around it ------------------------------

  /** The operating system says this process stops shortly: nothing is sent, nothing stays scheduled. */
  suspending(): { unverified: number; subscriptions: number; calls: number } {
    const out = record('sipral_suspending_t');
    checkNow(this.sipral, 'sipral_stack_suspending', () => this.sipral.sipral_stack_suspending(this.stackHandle, this.nowMs(), out));
    const read = plain(out, 'sipral_suspending_t');
    return { unverified: read.unverified as number, subscriptions: read.subscriptions as number, calls: read.calls as number };
  }

  /** The process runs again after {@link suspending}. */
  resumed(): void {
    checkNow(this.sipral, 'sipral_stack_resumed', () => this.sipral.sipral_stack_resumed(this.stackHandle, this.nowMs()));
    this.poll();
  }

  /** The interface the stack was on is gone, and no other came up yet. */
  interfaceLost(): void {
    checkNow(this.sipral, 'sipral_stack_interface_lost', () => this.sipral.sipral_stack_interface_lost(this.stackHandle, this.nowMs()));
    this.poll();
  }

  /** Names stopped resolving, the network otherwise up. */
  nameResolutionLost(): void {
    checkNow(this.sipral, 'sipral_stack_name_resolution_lost', () =>
      this.sipral.sipral_stack_name_resolution_lost(this.stackHandle, this.nowMs()),
    );
    this.poll();
  }

  /** Mark the moment the process started, the zero of {@link Account.timeToReady}. */
  coldStart(): void {
    check(this.sipral, 'sipral_stack_cold_start', this.sipral.sipral_stack_cold_start(this.stackHandle, this.nowMs()));
  }

  /**
   * The network under this stack changed and `host` is this machine's
   * address on the new one: the signalling socket bound there again (over
   * TCP or TLS, the connection made again from it), the change reported
   * (`sipral_stack_network_changed`, `link` a `SipralLink` value) and every
   * account added without a `Contact` of its own pointed at it. Returns the
   * `SipralRecovery` value the stack decided; on `Rebuild` each call whose
   * media was at the old address gets `CallAddressWanted`, which
   * {@link Call.readdress} answers.
   */
  async moveTo(host: string, options: { link?: number } = {}): Promise<number> {
    this.ensureOpen();
    const link = options.link ?? SipralLink.Wired;
    const previous = split(this.address).host;
    const picks = this.routes && this.signalling === SipralTransport.Udp;
    if (this.signalling !== SipralTransport.Udp) {
      await this.moveLink(host);
    } else if (picks) {
      await this.advertiseAgain(host);
    } else {
      await this.moveSocket(host);
    }
    const [before, beforeLength] = text(previous);
    const [after, afterLength] = text(host);
    const recovery = new Uint32Array(1);
    checkNow(this.sipral, 'sipral_stack_network_changed', () =>
      this.sipral.sipral_stack_network_changed(
        this.stackHandle,
        link,
        before,
        beforeLength,
        null,
        0,
        1,
        link,
        after,
        afterLength,
        null,
        0,
        1,
        this.nowMs(),
        recovery,
      ),
    );
    for (const account of [...this.accounts.values()]) {
      if (account.contactGiven) {
        continue;
      }
      if (picks && isAddress(account.registrarAddress)) {
        const advertised = this.advertiseToward(account.registrarAddress);
        account.rebind({ contact: this.defaultContact(account.aor, advertised, account.contactParameters) });
        account.advertised = advertised;
      } else {
        account.rebind();
      }
    }
    this.poll();
    return recovery[0] ?? 0;
  }

  /**
   * `sipral_stack_network_test`: test the network before a call. Returns the
   * test's number; what it found arrives as `NetworkTest`, whose `test`
   * field is that number and `verdict` a `SipralNetworkVerdict` value.
   * `account` has its server asked with an OPTIONS; with `probe` on a stack
   * with `nat: Stun` a socket is asked about as a call's would be;
   * `echoCall` is a call placed to an echo service, measured for `echoMs`
   * and hung up.
   */
  async networkTest(
    options: { account?: Account; probe?: boolean; mediaHost?: string; echoCall?: Call; echoMs?: number; timeoutMs?: number } = {},
  ): Promise<number> {
    this.ensureOpen();
    let probe: { address: string; socket: DatagramSocket } | null = null;
    if ((options.probe ?? true) && this.natStun) {
      const socket = await this.openMediaSocket(this.mediaHost(options.mediaHost, options.account, undefined));
      const address = formatAddress(socket.address().address, socket.address().port);
      this.watchStun(socket, address);
      probe = { address, socket };
    }
    const made = config(
      'sipral_network_test_config_t',
      { probeSocket: probe?.address, echoMs: options.echoMs, timeoutMs: options.timeoutMs },
      { account: options.account?.handle ?? 0n, echo_call: options.echoCall?.handle ?? 0n },
    );
    const out = new Uint32Array(1);
    try {
      checkNow(this.sipral, 'sipral_stack_network_test', () =>
        this.sipral.sipral_stack_network_test(this.stackHandle, made, this.nowMs(), out),
      );
    } catch (error) {
      if (probe !== null) {
        this.releaseStunSocket(probe.address);
        this.closeMediaSocket(probe.socket);
      }
      throw error;
    }
    const test = out[0] ?? 0;
    if (probe !== null) {
      this.probes.set(test, probe);
    }
    this.poll();
    return test;
  }

  /**
   * Hang up every call still up, give the goodbyes a moment to go out, then
   * destroy the stack and close every socket. Calling it again does nothing.
   */
  async close(): Promise<void> {
    if (this.closed) {
      return;
    }
    const open = [...this.calls.values()];
    let hungUp = false;
    for (const call of open) {
      if (!call.ended) {
        try {
          call.hangup();
          hungUp = true;
        } catch (error) {
          if (!(error instanceof SipralError)) {
            throw error;
          }
        }
      }
    }
    if (hungUp) {
      await new Promise((resolve) => setTimeout(resolve, 200));
    }
    for (const call of open) {
      call.close();
    }
    for (const address of [...this.stunSockets.keys()]) {
      this.forgetMediaSocket(address);
    }
    this.closed = true;
    clearInterval(this.ticker);
    clearTimeout(this.reconnectTimer);
    for (const local of [...this.turnStreams.keys()]) {
      this.loseTurnStream(local, false);
    }
    for (const transport of [...this.sipStreams.keys()]) {
      this.loseSipStream(transport, false);
    }
    this.sipral.sipral_stack_destroy(this.stackHandle);
    this.release();
    if (this.worker !== null) {
      this.worker.postMessage('close');
      await this.worker.terminate();
      this.worker = null;
    }
    this.link?.destroy();
    this.link = null;
    const socket = this.socket;
    this.socket = null;
    if (socket !== null) {
      await new Promise<void>((resolve) => socket.close(() => resolve()));
    }
    this.removeAllListeners('event');
  }

  // -- what the account, the call and the media ask of the stack ---------

  /** @internal Throw unless the stack is open. */
  ensureOpen(): void {
    if (this.closed) {
      throw new Error('sipral: the stack is closed');
    }
  }

  /** @internal Run the stack: its timers, what it sends, what it raised. */
  poll(): void {
    if (this.closed) {
      return;
    }
    this.result.set(record('sipral_poll_result_t'));
    if (this.sipral.sipral_stack_poll(this.stackHandle, this.nowMs(), this.result) === SipralStatus.Ok) {
      this.drainTransmit();
      this.drainStun();
      this.drainFarewells();
    }
    this.deliver();
  }

  /** @internal Hand an error to `error` listeners, or let it go uncaught. */
  report(error: unknown): void {
    const failure = error instanceof Error ? error : new Error(String(error));
    if (this.listenerCount('error') > 0) {
      this.emit('error', failure);
    } else {
      queueMicrotask(() => {
        throw failure;
      });
    }
  }

  /** @internal A call closed: forgotten. */
  forget(call: Call): void {
    this.calls.delete(call.handle);
  }

  /** @internal An account removed: forgotten. */
  forgetAccount(account: Account): void {
    this.accounts.delete(account.handle);
  }

  /**
   * @internal `scheme:user@at` for `aor` -- `at` the stack's own address
   * when null -- with `parameters` after it: where a caller that gave no
   * `Contact` is reached.
   */
  defaultContact(aor: string, at: string | null, parameters: string): string {
    const colon = aor.indexOf(':');
    const scheme = colon < 0 ? 'sip' : aor.slice(0, colon);
    const rest = colon < 0 ? aor : aor.slice(colon + 1);
    const user = rest.indexOf('@');
    const where = at ?? this.address;
    return user < 0 ? `${scheme}:${where}${parameters}` : `${scheme}:${rest.slice(0, user)}@${where}${parameters}`;
  }

  /**
   * @internal A UDP socket for a call's media at `host`: at `port` when one
   * is named, else at an even port of the stack's RTP range when it has one
   * (`sipral_stack_rtp_port_reserve`), else wherever the system puts it.
   */
  async openMediaSocket(host: string, port = 0): Promise<DatagramSocket> {
    if (port !== 0 || this.rtpPorts === null) {
      const socket = udp(host);
      try {
        await bind(socket, host, port);
      } catch (error) {
        socket.close();
        throw error;
      }
      return socket;
    }
    const [low, high] = this.rtpPorts;
    let failure: unknown = null;
    for (let attempt = 0; attempt < Math.max(1, Math.floor((high - low + 1) / 2)); attempt++) {
      const reserved = new Uint32Array(1);
      checkNow(this.sipral, 'sipral_stack_rtp_port_reserve', () => this.sipral.sipral_stack_rtp_port_reserve(this.stackHandle, reserved));
      const socket = udp(host);
      try {
        await bind(socket, host, reserved[0] ?? 0);
        return socket;
      } catch (error) {
        socket.close();
        this.giveBackPort(reserved[0] ?? 0);
        failure = error;
      }
    }
    throw failure;
  }

  /** @internal Close a socket {@link openMediaSocket} opened, and give its port back to the range. */
  closeMediaSocket(socket: DatagramSocket): void {
    let port = 0;
    try {
      port = socket.address().port;
      socket.close();
    } catch {
      return;
    }
    this.giveBackPort(port);
  }

  /**
   * @internal A media socket named with `sipral_stack_nat_map` that will
   * carry no call after all: `sipral_stack_nat_unmap`, and what it owes the
   * TURN server sent before it closes.
   */
  forgetMediaSocket(address: string): void {
    if (!this.stunSockets.has(address) || this.closed) {
      this.releaseStunSocket(address);
      return;
    }
    const [local, length] = text(address);
    if (retryingClockBehind(() => this.sipral.sipral_stack_nat_unmap(this.stackHandle, local, length, this.nowMs())) === SipralStatus.Ok) {
      this.drainStun();
    }
    this.releaseStunSocket(address);
  }

  /** @internal Stop handing what arrives on `address` to STUN: its media reads it from now on. */
  releaseStunSocket(address: string): void {
    const mapped = this.stunSockets.get(address);
    if (mapped !== undefined) {
      mapped.socket.off('message', mapped.listener);
      this.stunSockets.delete(address);
    }
  }

  /**
   * @internal Write `payload` on media socket `local`'s connection to the
   * TURN server, whole; a connection that fails here is closed and the stack
   * told, which loses the relay on it.
   */
  writeTurn(local: string, payload: Buffer | Uint8Array): void {
    const stream = this.turnStreams.get(local);
    if (stream === undefined) {
      return;
    }
    stream.write(payload, (error) => {
      if (error) {
        this.loseTurnStream(local, true);
      }
    });
  }

  // -- creating and running ------------------------------------------------

  private async create(options: StackOptions): Promise<void> {
    this.callback = koffi.register((event: Pointer) => this.onEvent(event), koffi.pointer(sipral_event_callback_t));
    let transmitCallback: bigint | null = null;
    if (this.deviceMode) {
      transmitCallback = await this.startWorker();
    }
    const entropy = randomBytes(32);
    const mediaSeed = randomBytes(32);
    const [bindText, bindLength] = text(this.address);
    const {
      bindHost: _bindHost,
      bindPort: _bindPort,
      library: _library,
      signalling: _signalling,
      signallingServer: _server,
      tlsServerName: _tlsName,
      tlsTrust: _tlsTrust,
      streamFallback: _fallback,
      streamServer: _streamServer,
      resolver: _resolver,
      inviteLimit: _limit,
      turnServerName: _turnName,
      turnTrust: _turnTrust,
      ...raw
    } = options;
    const made = config(
      'sipral_stack_config_t',
      raw,
      {
        event_callback: this.callback,
        transport: this.signalling,
        bind_address: bindText,
        bind_address_len: bindLength,
        entropy,
        entropy_len: entropy.length,
        media_seed: mediaSeed,
        media_seed_len: mediaSeed.length,
        // the wall clock the RTCP sender reports carry (RFC 3550 §6.4.1)
        media_clock_unix_seconds: Math.floor(Date.now() / 1000),
        audio: this.deviceMode ? SipralAudio.Device : SipralAudio.Application,
        audio_transmit_callback: transmitCallback,
      },
      { stun_fallbacks: ',', srtp_suites: ',' },
    );
    const out = new BigUint64Array(1);
    try {
      check(this.sipral, 'sipral_stack_create', this.sipral.sipral_stack_create(made, out));
    } finally {
      entropy.fill(0);
      mediaSeed.fill(0);
      for (const kept of (made as unknown as { kept: Buffer[] }).kept) {
        kept.fill(0);
      }
    }
    this.stackHandle = handle(out[0] ?? 0n);
  }

  /** Device mode's packets: the transmit callback, registered on a worker thread that never calls the library. */
  private startWorker(): Promise<bigint> {
    const worker = new Worker(new URL('./transmit-worker.js', import.meta.url));
    this.worker = worker;
    worker.unref();
    return new Promise<bigint>((resolve, reject) => {
      worker.once('error', reject);
      worker.once('message', (first: { callback: bigint }) => {
        worker.off('error', reject);
        worker.on('message', (packet: EnginePacket) => this.engineSent(packet));
        worker.on('error', (error) => this.report(error));
        resolve(first.callback);
      });
    });
  }

  /** One packet the engine encoded, sent from its call's socket or on its TURN connection. */
  private engineSent(packet: EnginePacket): void {
    if (this.closed) {
      return;
    }
    this.calls.get(packet.call)?.sendPacket(packet.payload, packet.destination, packet.protocol);
  }

  private start(refused: Refusal | null): void {
    if (this.socket !== null) {
      const socket = this.socket;
      socket.on('message', (data: Buffer, from: { address: string; port: number }) => this.receiveSignalling(data, from));
      socket.on('error', (error) => this.report(error));
    }
    if (this.link !== null) {
      const link = this.link;
      this.link = null;
      try {
        this.installLink(link);
      } catch (error) {
        refused = classify(error);
      }
    }
    if (this.link === null && this.signalling !== SipralTransport.Udp) {
      const failure = refused ?? { error: SipralTransportError.Other, tls: SipralTlsFailure.None, detail: 'no connection' };
      this.reportFailure(SIPRAL_TRANSPORT_MAIN, failure);
      this.reconnectLater();
    }
    // the first poll is the ticker's, after `open` has resolved: whoever
    // listens straight away hears what the stack raised while opening
    this.ticker = setInterval(() => {
      try {
        this.poll();
      } catch (error) {
        this.report(error);
      }
    }, 10);
  }

  private release(): void {
    for (const callback of [this.callback, this.logCallback, this.screenCallback, ...this.retired]) {
      if (callback !== null) {
        koffi.unregister(callback);
      }
    }
    this.callback = null;
    this.logCallback = null;
    this.screenCallback = null;
    this.retired.length = 0;
  }

  private receiveSignalling(data: Buffer, from: { address: string; port: number }): void {
    if (this.closed) {
      return;
    }
    const [source, sourceLength] = text(formatAddress(from.address, from.port));
    retryingClockBehind(() =>
      this.sipral.sipral_stack_receive_datagram(
        this.stackHandle,
        SIPRAL_TRANSPORT_MAIN,
        data,
        data.length,
        source,
        sourceLength,
        null,
        0,
        this.nowMs(),
      ),
    );
    this.poll();
  }

  private drainTransmit(): void {
    while (!this.closed) {
      this.transmit.set(
        record('sipral_transmit_t', {
          data: this.transmitData,
          capacity: this.transmitData.length,
          destination: this.transmitTo,
          destination_capacity: this.transmitTo.length,
        }),
      );
      if (this.sipral.sipral_stack_poll_transmit(this.stackHandle, this.transmit) !== SipralStatus.Ok) {
        return;
      }
      const sent = read<SipralTransmit>(this.transmit, 'sipral_transmit_t');
      const length = Number(sent.len);
      if (length === 0) {
        return;
      }
      const payload = Buffer.from(this.transmitData.subarray(0, length));
      if (sent.transport >= FIRST_STREAM) {
        this.writeSipStream(sent.transport, payload);
        continue;
      }
      if (this.socket === null) {
        // one connection carries everything, whatever it names: the server
        // it reaches is the outbound proxy
        this.link?.write(payload);
        continue;
      }
      const to = parseAddress(this.transmitTo.toString('utf8', 0, Number(sent.destination_len)));
      if (to !== null) {
        this.socket.send(payload, to.port, to.host);
      }
    }
  }

  /** What `sipral_stack_poll_stun` has to send, each from the media socket it names. */
  private drainStun(): void {
    while (!this.closed) {
      this.transmit.set(
        record('sipral_transmit_t', {
          data: this.transmitData,
          capacity: this.transmitData.length,
          destination: this.transmitTo,
          destination_capacity: this.transmitTo.length,
          source: this.transmitFrom,
          source_capacity: this.transmitFrom.length,
        }),
      );
      if (this.sipral.sipral_stack_poll_stun(this.stackHandle, this.transmit) !== SipralStatus.Ok) {
        return;
      }
      const sent = read<SipralTransmit>(this.transmit, 'sipral_transmit_t');
      const length = Number(sent.len);
      if (length === 0) {
        return;
      }
      const payload = Buffer.from(this.transmitData.subarray(0, length));
      const source = this.transmitFrom.toString('utf8', 0, Number(sent.source_len));
      if (sent.protocol === SipralTransport.Tcp || sent.protocol === SipralTransport.Tls) {
        // for the TURN server, on the socket's connection to it
        this.writeTurn(source, payload);
        continue;
      }
      const from = this.stunSockets.get(source)?.socket ?? this.probeSocket(source);
      const to = parseAddress(this.transmitTo.toString('utf8', 0, Number(sent.destination_len)));
      if (from !== undefined && to !== null) {
        from.send(payload, to.port, to.host);
      }
    }
  }

  private probeSocket(address: string): DatagramSocket | undefined {
    for (const probe of this.probes.values()) {
      if (probe.address === address) {
        return probe.socket;
      }
    }
    return undefined;
  }

  /**
   * What a call that ended still owes -- its RTCP BYE, and with a TURN
   * server the Refresh that gives its relay back -- sent from its own socket
   * or on its TURN connection.
   */
  private drainFarewells(): void {
    while (!this.closed) {
      this.farewell.prepare();
      if (this.sipral.sipral_stack_poll_farewell(this.stackHandle, this.farewellCall, this.farewell.packet) !== SipralStatus.Ok) {
        return;
      }
      const out = this.farewell.written();
      if (out === null) {
        return;
      }
      const owner = handle(this.farewellCall[0] ?? 0n);
      if (out.protocol === SipralTransport.Tcp || out.protocol === SipralTransport.Tls) {
        const local = this.turnSockets.get(owner);
        if (local !== undefined) {
          this.writeTurn(local, out.payload);
        }
        continue;
      }
      this.calls.get(owner)?.sendPacket(out.payload, out.destination, out.protocol);
    }
  }

  /** Copy the event out; it is delivered once the poll has returned. */
  private onEvent(address: Pointer): void {
    try {
      this.pending.push(StackEvent.read(address));
    } catch (error) {
      queueMicrotask(() => this.report(error));
    }
  }

  private deliver(): void {
    if (this.delivering) {
      return;
    }
    this.delivering = true;
    try {
      let event = this.pending.shift();
      while (event !== undefined) {
        try {
          this.actOn(event);
          this.calls.get(event.call)?.deliver(event);
          this.accounts.get(event.account)?.deliver(event);
          this.emit('event', event);
        } catch (error) {
          this.report(error);
        }
        event = this.pending.shift();
      }
    } finally {
      this.delivering = false;
    }
  }

  /** What this class does itself about an event, before anybody hears it. */
  private actOn(event: StackEvent): void {
    const fields = event.fields;
    switch (event.kind) {
      case SipralEventKind.TransportWanted:
        if (this.signalling === SipralTransport.Udp) {
          this.streamWanted(fields);
        }
        break;
      case SipralEventKind.TransportFailed:
        if (this.signalling === SipralTransport.Udp) {
          this.loseSipStream(fields.transport as number, false);
        } else if (fields.transport === SIPRAL_TRANSPORT_MAIN && this.link !== null) {
          // a connection the stack retired, its socket still open here
          this.loseLink(null, false);
        }
        break;
      case SipralEventKind.LookupWanted:
        void this.lookUp(event.account, fields.name as string, fields.record as number);
        break;
      case SipralEventKind.Located:
        if (typeof fields.targets === 'string' && fields.targets.length > 0) {
          this.located(event.account, fields.targets.split(',')[0] as string);
        }
        break;
      case SipralEventKind.TurnStream:
        this.turnStreamWanted(fields);
        break;
      case SipralEventKind.NetworkTest:
        this.networkTested(fields.test as number);
        break;
      case SipralEventKind.NatMapping:
      case SipralEventKind.NatRelay: {
        const mapped = this.stunSockets.get((fields.local as string | null) ?? '');
        if (mapped !== undefined) {
          (event.kind === SipralEventKind.NatMapping ? mapped.mapped : mapped.relayed)();
        }
        break;
      }
      default:
        break;
    }
  }

  // -- a call's sockets ------------------------------------------------------

  private async placeWith(
    account: Account | undefined,
    options: CallOptions,
    target: string | null,
    entryPoint: (made: Buffer, out: BigUint64Array) => number,
    operation: string,
  ): Promise<Call> {
    this.ensureOpen();
    const host = this.mediaHost(options.mediaHost, account, options.destination);
    const media = await this.openMediaSocket(host, options.mediaPort ?? 0);
    const mediaAddress = formatAddress(media.address().address, media.address().port);
    let textSocket: DatagramSocket | null = null;
    try {
      await this.mapMediaSocket(media, mediaAddress);
      textSocket = options.text === true ? await this.openMediaSocket(host) : null;
    } catch (error) {
      this.forgetMediaSocket(mediaAddress);
      this.closeMediaSocket(media);
      throw error;
    }
    const fields = options.headers === undefined ? { array: null, count: 0 } : headerArray(options.headers);
    const { headers: _headers, text: _text, mediaHost: _host, mediaPort: _port, ...rest } = options;
    const made = config(
      'sipral_call_config_t',
      {
        ...rest,
        target: target ?? undefined,
        mediaAddress,
        textAddress: textSocket === null ? undefined : formatAddress(textSocket.address().address, textSocket.address().port),
        feedback: options.feedback === true ? true : undefined,
      },
      { headers: fields.array, headers_len: fields.count },
    );
    const out = new BigUint64Array(1);
    try {
      checkNow(this.sipral, operation, () => entryPoint(made, out));
    } catch (error) {
      this.forgetMediaSocket(mediaAddress);
      this.closeMediaSocket(media);
      if (textSocket !== null) {
        this.closeMediaSocket(textSocket);
      }
      throw error;
    }
    const call = new Call(this, handle(out[0] ?? 0n), media, mediaAddress, false, textSocket);
    this.register(call);
    this.poll();
    return call;
  }

  /** The {@link Call} of an incoming one, its media socket open and mapped, not yet answered. */
  private async incoming(event: StackEvent, options: Pick<CallOptions, 'mediaHost' | 'mediaPort' | 'text'>): Promise<Call> {
    const account = this.accounts.get(event.account);
    const host = this.mediaHost(options.mediaHost, account, undefined);
    const media = await this.openMediaSocket(host, options.mediaPort ?? 0);
    const mediaAddress = formatAddress(media.address().address, media.address().port);
    let textSocket: DatagramSocket | null = null;
    try {
      await this.mapMediaSocket(media, mediaAddress);
      textSocket = options.text === true ? await this.openMediaSocket(host) : null;
    } catch (error) {
      this.forgetMediaSocket(mediaAddress);
      this.closeMediaSocket(media);
      throw error;
    }
    const call = new Call(this, event.call, media, mediaAddress, true, textSocket);
    this.register(call);
    return call;
  }

  private register(call: Call): void {
    this.calls.set(call.handle, call);
    if (this.turn) {
      this.turnSockets.set(call.handle, call.mediaAddress);
    }
  }

  /** Where a call's media socket binds: the host given, else the route toward the far end. */
  private mediaHost(given: string | undefined, account: Account | undefined, destination: string | undefined): string {
    if (given !== undefined) {
      return given;
    }
    for (const peer of [destination, account?.registrarAddress]) {
      if (isAddress(peer)) {
        return routeHost(peer, this.sipral);
      }
    }
    return split(this.address).host;
  }

  private giveBackPort(port: number): void {
    if (this.rtpPorts === null || this.closed) {
      return;
    }
    this.sipral.sipral_stack_rtp_port_release(this.stackHandle, port);
  }

  // -- STUN and TURN on a media socket --------------------------------------

  /** Hand what arrives on `socket` to `sipral_stack_receive_stun`, until its media takes it. */
  private watchStun(socket: DatagramSocket, address: string): MappedSocket {
    const [to, toLength] = text(address);
    const listener = (data: Buffer, from: { address: string; port: number }): void => {
      if (this.closed) {
        return;
      }
      const [source, sourceLength] = text(formatAddress(from.address, from.port));
      retryingClockBehind(() =>
        this.sipral.sipral_stack_receive_stun(this.stackHandle, data, data.length, source, sourceLength, to, toLength, this.nowMs()),
      );
      this.poll();
    };
    const mapped: MappedSocket = { socket, listener, mapped: () => undefined, relayed: () => undefined };
    socket.on('message', listener);
    this.stunSockets.set(address, mapped);
    return mapped;
  }

  /**
   * `sipral_stack_nat_map`, and the wait before a call may be described on
   * the socket: its `NatMapping`, and with a TURN server its `NatRelay`. A
   * no-op on a stack that asks no STUN server.
   */
  private async mapMediaSocket(socket: DatagramSocket, address: string): Promise<void> {
    if (!this.natStun) {
      return;
    }
    const mapped = this.watchStun(socket, address);
    const mapping = new Promise<void>((resolve) => {
      mapped.mapped = resolve;
    });
    const relay = new Promise<void>((resolve) => {
      mapped.relayed = resolve;
    });
    const [local, length] = text(address);
    try {
      checkNow(this.sipral, 'sipral_stack_nat_map', () => this.sipral.sipral_stack_nat_map(this.stackHandle, local, length, this.nowMs()));
      this.poll();
      await within(mapping, NAT_PATIENCE_MS, `the NAT mapping of ${address}`);
      if (this.turn) {
        await within(relay, NAT_PATIENCE_MS, `the TURN allocation of ${address}`);
      }
    } catch (error) {
      this.releaseStunSocket(address);
      throw error;
    }
  }

  /** A test is over: what its probe owes goes out before the probe closes. */
  private networkTested(test: number): void {
    const probe = this.probes.get(test);
    if (probe === undefined) {
      return;
    }
    this.probes.delete(test);
    this.drainStun();
    this.releaseStunSocket(probe.address);
    this.closeMediaSocket(probe.socket);
  }

  /** Open or close what `TurnStream` asked for. */
  private turnStreamWanted(fields: Readonly<Record<string, unknown>>): void {
    const local = (fields.local as string | null) ?? '';
    if (fields.state === SipralTurnStream.Open) {
      void this.openTurnStream(local, (fields.server as string | null) ?? '', fields.protocol as number);
    } else if (fields.state === SipralTurnStream.Close) {
      for (const [call, named] of [...this.turnSockets]) {
        if (named === local) {
          this.turnSockets.delete(call);
        }
      }
      this.loseTurnStream(local, false);
    }
  }

  private async openTurnStream(local: string, server: string, protocol: number): Promise<void> {
    const [name, length] = text(local);
    const { host, port } = split(server);
    let stream: StreamSocket;
    try {
      stream = await openStream(host, port, {
        trust: protocol === SipralTransport.Tls ? this.turnTrust : null,
        serverName: this.turnServerName ?? host,
        timeoutMs: STREAM_PATIENCE_MS,
      });
    } catch {
      if (!this.closed) {
        retryingClockBehind(() => this.sipral.sipral_stack_turn_closed(this.stackHandle, name, length, this.nowMs()));
        this.poll();
      }
      return;
    }
    if (this.closed) {
      stream.destroy();
      return;
    }
    this.turnStreams.set(local, stream);
    stream.on('data', (data: Buffer) => {
      if (this.closed) {
        return;
      }
      const status = retryingClockBehind(() =>
        this.sipral.sipral_stack_turn_receive(this.stackHandle, name, length, data, data.length, this.nowMs()),
      );
      if (status === SipralStatus.StreamBroken) {
        this.loseTurnStream(local, false);
      }
      this.poll();
    });
    stream.on('close', () => this.loseTurnStream(local, true));
    stream.on('error', () => this.loseTurnStream(local, true));
    retryingClockBehind(() => this.sipral.sipral_stack_turn_connected(this.stackHandle, name, length, this.nowMs()));
    this.poll();
  }

  /** Close media socket `local`'s TURN connection, and when `tell`, say so. */
  private loseTurnStream(local: string, tell: boolean): void {
    const stream = this.turnStreams.get(local);
    if (stream === undefined) {
      return;
    }
    this.turnStreams.delete(local);
    stream.removeAllListeners('close');
    stream.destroy();
    if (tell && !this.closed) {
      const [name, length] = text(local);
      retryingClockBehind(() => this.sipral.sipral_stack_turn_closed(this.stackHandle, name, length, this.nowMs()));
    }
  }

  // -- RFC 3263: a server named by a name --------------------------------------

  /** One lookup through the resolver, its answer handed back; a resolver that threw is an answer that failed. */
  private async lookUp(account: bigint, name: string, recordType: number): Promise<void> {
    let answer: { answer: number; records: string[] };
    try {
      answer = await this.resolver(name, recordType);
    } catch {
      answer = { answer: SipralDnsAnswer.Failed, records: [] };
    }
    if (this.closed) {
      return;
    }
    const [asked, askedLength] = text(name);
    const [records, recordsLength] = text(answer.records.length === 0 ? null : answer.records.join(','));
    retryingClockBehind(() =>
      this.sipral.sipral_account_looked_up(
        this.stackHandle,
        account,
        asked,
        askedLength,
        recordType,
        answer.answer,
        records,
        recordsLength,
        this.nowMs(),
      ),
    );
    this.poll();
  }

  /**
   * An account's server was located at `target`: the account goes there and,
   * on a stack that picks its own address, is reached at the route toward it.
   */
  private located(accountHandle: bigint, target: string): void {
    const account = this.accounts.get(accountHandle);
    if (account === undefined) {
      return;
    }
    account.registrarAddress = target;
    if (!this.routes || this.signalling !== SipralTransport.Udp || account.contactGiven) {
      return;
    }
    const advertised = this.advertiseToward(target);
    if (advertised === (account.advertised ?? this.address)) {
      return;
    }
    account.advertised = advertised;
    try {
      account.rebind({ remote: target, contact: this.defaultContact(account.aor, advertised, account.contactParameters) });
    } catch (error) {
      if (!(error instanceof SipralError)) {
        throw error;
      }
    }
  }

  // -- the address this stack is reached at ----------------------------------

  /**
   * The `host:port` an account whose server is `peer` is reached at, on a
   * stack that picks its own address: the route toward the server, on this
   * stack's port. The first server named also becomes the address the
   * stack's `Via` carries.
   */
  private advertiseToward(peer: string): string {
    const address = formatAddress(routeHost(peer, this.sipral), split(this.address).port);
    if (!this.routeChosen) {
      this.routeChosen = true;
      if (address !== this.address) {
        this.advertiseMain(address);
      }
    }
    return address;
  }

  /** The UDP transport the stack writes in its `Via` names `address` from now on. */
  private advertiseMain(address: string): void {
    const [local, localLength] = text(address);
    checkNow(this.sipral, 'sipral_stack_transport_bind', () =>
      this.sipral.sipral_stack_transport_bind(
        this.stackHandle,
        SIPRAL_TRANSPORT_MAIN,
        SipralTransport.Udp,
        local,
        localLength,
        null,
        0,
        this.nowMs(),
        null,
      ),
    );
    this.address = address;
  }

  /**
   * After a move, a stack on every interface chooses again what it
   * advertises: the route toward its first account's server, or `host`
   * itself on the same port when no account names one by address.
   */
  private async advertiseAgain(host: string): Promise<void> {
    const probe = udp(host);
    try {
      await bind(probe, host, 0);
    } finally {
      probe.close();
    }
    this.keptSignallingPort = true;
    this.routeChosen = false;
    const server = [...this.accounts.values()].map((account) => account.registrarAddress).find((one) => isAddress(one));
    if (server !== undefined) {
      this.advertiseToward(server);
      return;
    }
    const local = formatAddress(host, split(this.address).port);
    if (local !== this.address) {
      this.advertiseMain(local);
    }
  }

  /** The UDP signalling socket bound again at `host`, on the port it had when that is free there. */
  private async moveSocket(host: string): Promise<void> {
    const old = this.socket;
    const inUse = old?.address().port ?? 0;
    const wanted = this.chosenPort || inUse;
    const attempt = async (port: number): Promise<DatagramSocket | null> => {
      const socket = udp(host);
      try {
        await bind(socket, host, port);
        return socket;
      } catch {
        socket.close();
        return null;
      }
    };
    let made = wanted !== 0 ? await attempt(wanted) : null;
    if (made === null && wanted !== 0 && inUse === wanted && old !== null) {
      const usable = await attempt(0);
      if (usable !== null) {
        usable.close();
        old.removeAllListeners('message');
        old.close();
        this.socket = null;
        made = await attempt(wanted);
      }
    }
    this.keptSignallingPort = made !== null || wanted === 0;
    made ??= await attempt(0);
    if (made === null) {
      throw new Error(`sipral: no UDP socket could be bound at ${host}`);
    }
    const bound = formatAddress(host, made.address().port);
    const [local, localLength] = text(bound);
    try {
      checkNow(this.sipral, 'sipral_stack_transport_bind', () =>
        this.sipral.sipral_stack_transport_bind(
          this.stackHandle,
          SIPRAL_TRANSPORT_MAIN,
          SipralTransport.Udp,
          local,
          localLength,
          null,
          0,
          this.nowMs(),
          null,
        ),
      );
    } catch (error) {
      made.close();
      throw error;
    }
    made.on('message', (data: Buffer, from: { address: string; port: number }) => this.receiveSignalling(data, from));
    made.on('error', (error) => this.report(error));
    if (this.socket !== null) {
      this.socket.removeAllListeners('message');
      this.socket.close();
    }
    this.socket = made;
    this.address = bound;
  }

  // -- SIP over TCP or TLS: the one connection signalling travels on -------

  /** Tell the stack a connection is open, naming both ends, and start reading it. */
  private installLink(link: StreamSocket): void {
    const local = formatAddress(link.localAddress ?? '127.0.0.1', link.localPort ?? 0);
    const remote = formatAddress(link.remoteAddress ?? '127.0.0.1', link.remotePort ?? 0);
    const [near, nearLength] = text(local);
    const [far, farLength] = text(remote);
    try {
      checkNow(this.sipral, 'sipral_stack_transport_bind', () =>
        this.sipral.sipral_stack_transport_bind(
          this.stackHandle,
          SIPRAL_TRANSPORT_MAIN,
          this.signalling,
          near,
          nearLength,
          far,
          farLength,
          this.nowMs(),
          null,
        ),
      );
    } catch (error) {
      link.destroy();
      throw error;
    }
    this.address = local;
    this.link = link;
    link.on('data', (data: Buffer) => {
      if (this.closed || this.link !== link) {
        return;
      }
      const status = retryingClockBehind(() =>
        this.sipral.sipral_stack_receive_stream(this.stackHandle, SIPRAL_TRANSPORT_MAIN, data, data.length, this.nowMs()),
      );
      if (status !== SipralStatus.Ok && !passing(status)) {
        // the framing is lost: the stack retired the transport itself
        this.loseLink(null, false);
      }
      this.poll();
    });
    let failure: unknown = null;
    link.on('error', (error) => {
      failure = error;
    });
    link.on('close', () => {
      if (this.link === link) {
        this.loseLink(failure, true);
        this.poll();
      }
    });
  }

  /** `sipral_stack_transport_failed_with` for `transport`; never throwing on the way out. */
  private reportFailure(transport: number, failure: Refusal, protocol: number = this.signalling): void {
    if (this.closed) {
      return;
    }
    const [detail, length] = text(oneLine(failure.detail));
    const made = record('sipral_transport_failure_t', {
      transport,
      error: failure.error,
      tls: protocol === SipralTransport.Tls ? failure.tls : SipralTlsFailure.None,
      detail,
      detail_len: length,
    });
    retryingClockBehind(() => this.sipral.sipral_stack_transport_failed_with(this.stackHandle, made, this.nowMs()));
  }

  /**
   * Close the signalling connection, tell the stack how it ended -- closed
   * in order, or failed -- unless it retired the connection itself, and
   * connect again.
   */
  private loseLink(failure: unknown, tell: boolean): void {
    const link = this.link;
    if (link === null) {
      return;
    }
    this.link = null;
    link.removeAllListeners('close');
    link.destroy();
    if (tell && !this.closed) {
      if (failure === null) {
        retryingClockBehind(() => this.sipral.sipral_stack_stream_closed(this.stackHandle, SIPRAL_TRANSPORT_MAIN, this.nowMs()));
      } else {
        this.reportFailure(SIPRAL_TRANSPORT_MAIN, classify(failure));
      }
    }
    this.reconnectDelay = RECONNECT_FIRST_MS;
    this.reconnectLater();
  }

  /** Connect again after the wait, backing off, until it works or the stack closes. */
  private reconnectLater(): void {
    if (this.closed || this.reconnectTimer !== undefined || this.server === null) {
      return;
    }
    const server = this.server;
    this.reconnectTimer = setTimeout(() => {
      void (async () => {
        try {
          const link = await openStream(server.host, server.port, {
            bindHost: this.bindHost,
            trust: this.signalling === SipralTransport.Tls ? this.tlsTrust : null,
            serverName: this.serverName,
            timeoutMs: STREAM_PATIENCE_MS,
          });
          this.reconnectTimer = undefined;
          if (this.closed) {
            link.destroy();
            return;
          }
          this.installLink(link);
          this.reconnectDelay = RECONNECT_FIRST_MS;
          this.afterReconnect();
        } catch (error) {
          this.reconnectTimer = undefined;
          this.reportFailure(SIPRAL_TRANSPORT_MAIN, classify(error));
          this.reconnectDelay = Math.min(this.reconnectDelay * 2, RECONNECT_MOST_MS);
          this.reconnectLater();
        }
        this.poll();
      })();
    }, this.reconnectDelay);
    this.reconnectTimer.unref();
  }

  /** Every account moves to the new connection's address, and every one registering registers again now. */
  private afterReconnect(): void {
    for (const account of [...this.accounts.values()]) {
      try {
        if (!account.contactGiven) {
          account.rebind();
        }
        if (account.wantsRegistration) {
          account.register();
        }
      } catch (error) {
        if (!(error instanceof SipralError)) {
          throw error;
        }
      }
    }
  }

  /** The signalling connection made again from `host`. */
  private async moveLink(host: string): Promise<void> {
    this.bindHost = host;
    const old = this.link;
    this.link = null;
    if (old !== null) {
      old.removeAllListeners('close');
      old.destroy();
    }
    if (this.server === null) {
      return;
    }
    try {
      const link = await openStream(this.server.host, this.server.port, {
        bindHost: host,
        trust: this.signalling === SipralTransport.Tls ? this.tlsTrust : null,
        serverName: this.serverName,
        timeoutMs: STREAM_PATIENCE_MS,
      });
      this.installLink(link);
    } catch (error) {
      this.address = formatAddress(host, 0);
      this.reportFailure(SIPRAL_TRANSPORT_MAIN, classify(error));
      this.reconnectLater();
    }
  }

  // -- RFC 3261 §18.1.1: a request too large for a datagram -------------------

  /** Answer `TransportWanted`: a connection to its destination, or the word that none is coming. */
  private streamWanted(fields: Readonly<Record<string, unknown>>): void {
    const destination = (fields.destination as string | null) ?? '';
    // an account on a connection of its own asks with nothing outgrown;
    // that one is opened whatever streamFallback says
    const opens = this.streamFallback || (fields.requestBytes === 0 && fields.limitBytes === 0);
    // a WebSocket goes over TCP or TLS, bound as WS or WSS so the stack runs it
    const bound = OWN_STREAMS.has(fields.protocol as number) ? (fields.protocol as number) : SipralTransport.Tcp;
    const over = bound === SipralTransport.Tls || bound === SipralTransport.Wss ? SipralTransport.Tls : SipralTransport.Tcp;
    if (this.streamsOpening.has(destination) || [...this.sipStreams.values()].some((stream) => stream.destination === destination)) {
      return;
    }
    const transport = this.nextStream++;
    if (!opens) {
      this.sayNoStream(transport, SipralTransportError.ConnectionRefused, `to ${destination} not tried: streamFallback is off`, over);
      return;
    }
    this.streamsOpening.add(destination);
    void this.openSipStream(transport, destination, over, bound);
  }

  /** What a TLS connection to `destination` trusts: the pin of an account on it, else the stack's trust. */
  private streamTrust(destination: string): TlsTrust {
    for (const account of this.accounts.values()) {
      if (account.overTls && account.registrarAddress === destination && account.tlsPin !== null) {
        return TlsTrust.pinned(account.tlsPin);
      }
    }
    return this.tlsTrust;
  }

  private async openSipStream(transport: number, destination: string, over: number, bound: number = over): Promise<void> {
    const tls = over === SipralTransport.Tls;
    const target = tls || this.streamServer === null ? split(destination) : this.streamServer;
    let socket: StreamSocket;
    try {
      socket = await openStream(target.host, target.port, {
        trust: tls ? this.streamTrust(destination) : null,
        serverName: this.givenServerName ?? target.host,
        timeoutMs: STREAM_PATIENCE_MS,
      });
    } catch (error) {
      this.streamsOpening.delete(destination);
      const refusal = classify(error);
      const server = formatAddress(target.host, target.port);
      const named = server === destination ? destination : `${server} (for ${destination})`;
      const verdict =
        refusal.error === SipralTransportError.ConnectionRefused
          ? 'refused'
          : refusal.error === SipralTransportError.TimedOut
            ? 'timed out'
            : refusal.error === SipralTransportError.Unreachable
              ? 'unreachable'
              : refusal.error === SipralTransportError.ConnectionReset
                ? 'reset'
                : 'failed';
      this.sayNoStream(transport, refusal.error, `to ${named} ${verdict}${refusal.detail ? `: ${refusal.detail}` : ''}`, over, refusal.tls);
      this.poll();
      return;
    }
    this.streamsOpening.delete(destination);
    if (this.closed) {
      socket.destroy();
      return;
    }
    this.sipStreams.set(transport, { destination, socket });
    const [near, nearLength] = text(formatAddress(socket.localAddress ?? '127.0.0.1', socket.localPort ?? 0));
    const [far, farLength] = text(destination);
    try {
      checkNow(this.sipral, 'sipral_stack_transport_bind', () =>
        this.sipral.sipral_stack_transport_bind(this.stackHandle, transport, bound, near, nearLength, far, farLength, this.nowMs(), null),
      );
    } catch (error) {
      this.loseSipStream(transport, false);
      this.sayNoStream(transport, SipralTransportError.Other, `to ${destination} connected, and the stack would not bind it: ${String(error)}`, over);
      this.poll();
      return;
    }
    socket.on('data', (data: Buffer) => {
      if (this.closed) {
        return;
      }
      const status = retryingClockBehind(() =>
        this.sipral.sipral_stack_receive_stream(this.stackHandle, transport, data, data.length, this.nowMs()),
      );
      if (status !== SipralStatus.Ok && !passing(status)) {
        this.loseSipStream(transport, false);
      }
      this.poll();
    });
    socket.on('error', () => undefined);
    socket.on('close', () => {
      this.loseSipStream(transport, true);
      this.poll();
    });
    this.poll();
  }

  /** `sipral_stack_transport_failed_with` for a connection that was not made. */
  private sayNoStream(transport: number, error: number, what: string, over: number, tls: number = SipralTlsFailure.None): void {
    this.reportFailure(
      transport,
      { error, tls, detail: `${over === SipralTransport.Tls ? 'TLS' : 'TCP'} ${what}` },
      over,
    );
  }

  private writeSipStream(transport: number, payload: Buffer): void {
    const stream = this.sipStreams.get(transport);
    stream?.socket.write(payload, (error) => {
      if (error) {
        this.loseSipStream(transport, true);
      }
    });
  }

  /** Close the connection bound at `transport` and, when `tell`, say so with `sipral_stack_stream_closed`. */
  private loseSipStream(transport: number, tell: boolean): void {
    const stream = this.sipStreams.get(transport);
    if (stream === undefined) {
      return;
    }
    this.sipStreams.delete(transport);
    stream.socket.removeAllListeners('close');
    stream.socket.destroy();
    if (tell && !this.closed) {
      retryingClockBehind(() => this.sipral.sipral_stack_stream_closed(this.stackHandle, transport, this.nowMs()));
    }
  }
}
