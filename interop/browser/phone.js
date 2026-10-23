// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

// The browser's end of scripts/lab.sh's `browser` step: a phone in a page,
// JsSIP (MIT) for the SIP over WebSocket and Chromium's own RTCPeerConnection
// for the media, the same two any web softphone is made of. interop/browser/
// run.mjs opens the page in a headless Chromium and drives it through
// `window.lab`; this file holds what only the page can see.
//
// The microphone is Chromium's fake capture device playing run.mjs's tone,
// SENT_HZ, with every voice processing stage off, so what reaches the far end
// is the tone as written. What arrives is read off the received track a frame
// at a time and measured at HEARD_HZ, the harness's own tone
// (interop/harness/src/audio.rs), and at SENT_HZ: a window counts as heard
// only when the far end's tone is there and this end's is not the louder.
//
// Trickle ICE (RFC 8838) over the `trickle-ice` Info Package (RFC 8840),
// when the run asks for it: every description this phone sends goes without
// a candidate, port 9 and 0.0.0.0 as RFC 8840 section 4.1.1 has it, and the
// candidates follow in INFO requests, each repeating those before it, one in
// flight at a time (section 10.9), once the far end has listed the package in
// its Recv-Info and holds the dialog (section 4.3). The INFOs that arrive are
// read the same way back: candidates of the current generation handed to the
// peer connection, the end of candidates too.

import JsSIP from 'jssip';

const HEARD_HZ = 444;
const SENT_HZ = 1000;
const WINDOW_MS = 20;
const HEARD_LEVEL = 0.05;
const TRICKLE_TYPE = 'application/trickle-ice-sdpfrag';
const TRICKLE_HEADERS = ['Recv-Info: trickle-ice', 'Supported: trickle-ice'];
const INFO_HEADERS = ['Info-Package: trickle-ice', 'Content-Disposition: Info-Package'];

let ua = null;
let microphone = null;
let trickling = false;
let current = null;
let incoming = [];
let waiting = null;

function level(samples, rate, hz) {
  const coefficient = 2 * Math.cos((2 * Math.PI * hz) / rate);
  let before = 0;
  let last = 0;
  for (const sample of samples) {
    const next = sample + coefficient * last - before;
    before = last;
    last = next;
  }
  const power = before * before + last * last - coefficient * before * last;
  return (2 * Math.sqrt(Math.max(power, 0))) / Math.max(samples.length, 1);
}

async function measure(call, track) {
  const processor = new MediaStreamTrackProcessor({ track });
  const reader = processor.readable.getReader();
  let held = [];
  let rate = 48000;
  for (;;) {
    const { value: frame, done } = await reader.read();
    if (done || call.over) {
      if (frame) frame.close();
      break;
    }
    rate = frame.sampleRate;
    const plane = new Float32Array(frame.numberOfFrames);
    frame.copyTo(plane, { planeIndex: 0, format: 'f32-planar' });
    frame.close();
    held = held.concat(Array.from(plane));
    const window = Math.round((rate * WINDOW_MS) / 1000);
    while (held.length >= window) {
      const samples = held.slice(0, window);
      held = held.slice(window);
      call.windows += 1;
      const heard = level(samples, rate, HEARD_HZ);
      const own = level(samples, rate, SENT_HZ);
      if (heard >= HEARD_LEVEL && heard > own) call.heard += 1;
      if (own >= HEARD_LEVEL && own > heard) call.own += 1;
    }
  }
}

function credentials(sdp) {
  const ufrag = /^a=ice-ufrag:(\S+)/m.exec(sdp);
  const pwd = /^a=ice-pwd:(\S+)/m.exec(sdp);
  return ufrag && pwd ? { ufrag: ufrag[1], pwd: pwd[1] } : null;
}

function withoutCandidates(sdp) {
  const lines = sdp.split('\r\n').filter((line) => line !== '');
  const kept = lines
    .filter((line) => !line.startsWith('a=candidate:') && line !== 'a=end-of-candidates')
    .map((line) => {
      if (line.startsWith('c=IN IP4 ')) return 'c=IN IP4 0.0.0.0';
      if (line.startsWith('m=')) return line.replace(/^(m=\S+) \d+ /, '$1 9 ');
      return line;
    });
  return `${kept.join('\r\n')}\r\n`;
}

function candidateCount(sdp) {
  return sdp.split('\r\n').filter((line) => line.startsWith('a=candidate:')).length;
}

function fragment(call) {
  const local = call.pc.localDescription ? credentials(call.pc.localDescription.sdp) : null;
  if (!local) return null;
  const lines = [`a=ice-ufrag:${local.ufrag}`, `a=ice-pwd:${local.pwd}`];
  const mids = [...new Set(call.gathered.map((candidate) => candidate.mid))];
  if (mids.length === 0 && call.gatheringOver) mids.push(call.mid);
  for (const mid of mids) {
    lines.push('m=audio 9 RTP/AVP 0', `a=mid:${mid}`);
    for (const candidate of call.gathered.filter((one) => one.mid === mid)) {
      lines.push(`a=${candidate.line}`);
    }
    if (call.gatheringOver) lines.push('a=end-of-candidates');
  }
  return `${lines.join('\r\n')}\r\n`;
}

function sendTrickle(call) {
  if (!call.mayTrickle || call.infoInFlight || !call.trickleDirty || call.over) return;
  const body = fragment(call);
  if (!body) return;
  call.trickleDirty = false;
  call.infoInFlight = true;
  try {
    call.session.sendInfo(TRICKLE_TYPE, body, { extraHeaders: INFO_HEADERS });
    call.infosSent += 1;
    call.candidatesSent = call.gathered.length;
    call.endSent = call.gatheringOver;
  } catch (error) {
    call.infoInFlight = false;
    call.trickleDirty = true;
    call.story.push(`an INFO could not go: ${error.message}`);
  }
}

function addRemote(call, entry) {
  call.pc
    .addIceCandidate(entry)
    .then(() => {
      if (entry.candidate === '') call.endsAdded += 1;
      else call.candidatesAdded += 1;
    })
    .catch((error) => call.story.push(`a trickled candidate refused: ${error.message}`));
}

function takeTrickle(call, body) {
  call.infosReceived += 1;
  const lines = body.split(/\r?\n/).filter((line) => line !== '');
  let ufrag = null;
  let mid = null;
  let sessionEnded = false;
  const entries = [];
  for (const line of lines) {
    if (line.startsWith('a=ice-ufrag:')) ufrag = line.slice('a=ice-ufrag:'.length);
    else if (line.startsWith('m=')) mid = null;
    else if (line.startsWith('a=mid:')) mid = line.slice('a=mid:'.length);
    else if (line.startsWith('a=candidate:')) entries.push({ candidate: line.slice(2), sdpMid: mid ?? call.mid });
    else if (line === 'a=end-of-candidates') {
      if (mid === null && entries.length === 0) sessionEnded = true;
      entries.push({ candidate: '', sdpMid: mid ?? call.mid });
    }
  }
  if (sessionEnded && !entries.some((entry) => entry.candidate === '')) {
    entries.push({ candidate: '', sdpMid: call.mid });
  }
  call.pendingRemote.push({ ufrag, entries });
  applyTrickle(call);
}

function applyTrickle(call) {
  const remote = call.pc && call.pc.remoteDescription ? credentials(call.pc.remoteDescription.sdp) : null;
  if (!remote) return;
  const pending = call.pendingRemote;
  call.pendingRemote = [];
  for (const { ufrag, entries } of pending) {
    if (ufrag !== null && ufrag !== remote.ufrag) {
      call.story.push('an INFO of another generation, dropped');
      continue;
    }
    for (const entry of entries) {
      const key = `${entry.sdpMid} ${entry.candidate}`;
      if (call.seenRemote.has(key)) continue;
      call.seenRemote.add(key);
      addRemote(call, entry);
    }
  }
}

function watch(call, pc) {
  call.pc = pc;
  pc.addEventListener('track', (event) => {
    if (event.track.kind === 'audio' && !call.measuring) {
      call.measuring = true;
      // Chromium decodes a received track only while something plays it out,
      // as an ear would: an audio element, whose output headless Chromium
      // sends to no device
      const earpiece = new Audio();
      earpiece.srcObject = new MediaStream([event.track]);
      earpiece.play().catch((error) => call.story.push(`the earpiece did not play: ${error.message}`));
      measure(call, event.track).catch((error) => call.story.push(`the earpiece failed: ${error.message}`));
    }
  });
  pc.addEventListener('icecandidate', (event) => {
    if (event.candidate && event.candidate.candidate) {
      call.gathered.push({ line: event.candidate.candidate, mid: event.candidate.sdpMid ?? call.mid });
    } else {
      call.gatheringOver = true;
    }
    call.trickleDirty = true;
    sendTrickle(call);
  });
  pc.addEventListener('signalingstatechange', () => applyTrickle(call));
}

function farListsPackage(message) {
  if (!message || !message.getHeaders) return false;
  return message
    .getHeaders('Recv-Info')
    .some((value) => value.split(',').some((item) => item.split(';')[0].trim().toLowerCase() === 'trickle-ice'));
}

function newCall(session, direction) {
  const call = {
    session,
    direction,
    pc: null,
    mid: '0',
    over: false,
    ended: null,
    measuring: false,
    windows: 0,
    heard: 0,
    own: 0,
    gathered: [],
    gatheringOver: false,
    trickleDirty: false,
    mayTrickle: false,
    infoInFlight: false,
    infosSent: 0,
    candidatesSent: 0,
    endSent: false,
    infosReceived: 0,
    candidatesAdded: 0,
    endsAdded: 0,
    pendingRemote: [],
    seenRemote: new Set(),
    farListed: false,
    offeredCandidates: null,
    sentCandidates: null,
    confirmed: null,
    story: [],
  };
  call.ended = new Promise((resolve) => {
    const finish = (originator, cause) => {
      call.over = true;
      resolve({ originator, cause });
    };
    session.on('ended', (event) => finish(event.originator, event.cause));
    session.on('failed', (event) => finish(event.originator, event.cause));
  });
  call.confirmed = new Promise((resolve, reject) => {
    session.on('confirmed', () => resolve());
    session.on('failed', (event) => reject(new Error(`${event.originator} ${event.cause}`)));
  });
  // a call this phone places has its peer connection made inside ua.call(),
  // before anything here could listen for it; one it answers, in answer()
  if (session.connection) watch(call, session.connection);
  else session.on('peerconnection', (event) => watch(call, event.peerconnection));
  session.on('sdp', (event) => {
    if (event.originator === 'remote') {
      call.offeredCandidates = candidateCount(event.sdp);
      const mid = /^a=mid:(\S+)/m.exec(event.sdp);
      if (mid) call.mid = mid[1];
      return;
    }
    if (trickling) event.sdp = withoutCandidates(event.sdp);
    call.sentCandidates = candidateCount(event.sdp);
  });
  session.on('icecandidate', (event) => {
    if (trickling) event.ready();
  });
  session.on('accepted', (event) => {
    if (direction === 'out') call.farListed = farListsPackage(event.response);
  });
  session.on('confirmed', () => {
    call.mayTrickle = trickling && call.farListed;
    sendTrickle(call);
  });
  session.on('newInfo', (event) => {
    if (event.originator === 'local') {
      const done = () => {
        call.infoInFlight = false;
        sendTrickle(call);
      };
      event.info.on('succeeded', done);
      event.info.on('failed', (failure) => {
        call.story.push(`an INFO was answered ${failure.response ? failure.response.status_code : 'with nothing'}`);
        done();
      });
      return;
    }
    const type = (event.info.contentType || '').split(';')[0].trim();
    if (type === TRICKLE_TYPE) takeTrickle(call, event.info.body || '');
  });
  return call;
}

async function stats(call) {
  if (!call.pc) return { dtlsState: 'never started' };
  const report = await call.pc.getStats();
  const all = new Map();
  report.forEach((entry) => all.set(entry.id, entry));
  const said = {};
  for (const entry of all.values()) {
    if (entry.type === 'transport') {
      said.dtlsState = entry.dtlsState;
      said.dtlsRole = entry.dtlsRole;
      said.tlsVersion = entry.tlsVersion;
      said.dtlsCipher = entry.dtlsCipher;
      said.srtpCipher = entry.srtpCipher;
      const pair = all.get(entry.selectedCandidatePairId);
      if (pair) {
        const local = all.get(pair.localCandidateId);
        const remote = all.get(pair.remoteCandidateId);
        said.local = local ? `${local.candidateType} ${local.address}:${local.port}` : null;
        said.remote = remote ? `${remote.candidateType} ${remote.address}:${remote.port}` : null;
      }
    }
    if (entry.type === 'inbound-rtp' && entry.kind === 'audio') {
      said.packetsReceived = entry.packetsReceived;
      const codec = all.get(entry.codecId);
      said.codec = codec ? `${codec.mimeType}/${codec.clockRate}` : null;
    }
    if (entry.type === 'outbound-rtp' && entry.kind === 'audio') said.packetsSent = entry.packetsSent;
    if (entry.type === 'remote-candidate') {
      said.remoteCandidates = (said.remoteCandidates || 0) + 1;
    }
  }
  return said;
}

function summary(call, measured) {
  return {
    direction: call.direction,
    windows: call.windows,
    heard: call.heard,
    own: call.own,
    offeredCandidates: call.offeredCandidates,
    sentCandidates: call.sentCandidates,
    trickle: {
      infosSent: call.infosSent,
      candidatesSent: call.candidatesSent,
      endSent: call.endSent,
      infosReceived: call.infosReceived,
      candidatesAdded: call.candidatesAdded,
      endsAdded: call.endsAdded,
      farListed: call.farListed,
    },
    stats: measured,
    story: call.story,
  };
}

function within(promise, ms, what) {
  return Promise.race([
    promise,
    new Promise((resolve, reject) => {
      setTimeout(() => reject(new Error(`${what}: nothing after ${ms} ms`)), ms);
    }),
  ]);
}

window.lab = {
  async start({ socket, uri, user, password, trickle }) {
    trickling = trickle;
    microphone = await navigator.mediaDevices.getUserMedia({
      audio: { echoCancellation: false, noiseSuppression: false, autoGainControl: false },
    });
    ua = new JsSIP.UA({
      sockets: [new JsSIP.WebSocketInterface(socket)],
      uri,
      authorization_user: user,
      password,
      register: true,
      register_expires: 300,
    });
    ua.on('newRTCSession', (event) => {
      if (event.originator !== 'remote') return;
      const call = newCall(event.session, 'in');
      call.farListed = farListsPackage(event.request);
      if (waiting) {
        const take = waiting;
        waiting = null;
        take(call);
      } else {
        incoming.push(call);
      }
    });
    const registered = new Promise((resolve, reject) => {
      ua.on('registered', () => resolve('registered'));
      ua.on('registrationFailed', (event) => reject(new Error(`the registration failed: ${event.cause}`)));
    });
    ua.start();
    return within(registered, 20000, 'the registration');
  },

  async answerNext(ms) {
    const arrived = incoming.length > 0
      ? Promise.resolve(incoming.shift())
      : new Promise((resolve) => {
        waiting = resolve;
      });
    const call = await within(arrived, ms, 'the call to this phone');
    current = call;
    call.session.answer({
      mediaStream: microphone,
      extraHeaders: trickling ? TRICKLE_HEADERS : [],
    });
    await within(call.confirmed, ms, 'the ACK of this phone\'s answer');
    return call.session.remote_identity.uri.toString();
  },

  async dial(target, ms) {
    const session = ua.call(target, {
      mediaStream: microphone,
      extraHeaders: trickling ? TRICKLE_HEADERS : [],
    });
    const call = newCall(session, 'out');
    current = call;
    await within(call.confirmed, ms, 'the call from this phone');
    return 'confirmed';
  },

  async listen(ms) {
    const call = current;
    await new Promise((resolve) => {
      setTimeout(resolve, ms);
    });
    return summary(call, await stats(call));
  },

  async hangUp(ms) {
    const call = current;
    call.session.terminate();
    return within(call.ended, ms, 'the BYE from this phone');
  },

  async farEnd(ms) {
    return within(current.ended, ms, 'the far end\'s BYE');
  },

  async stop(ms) {
    const unregistered = new Promise((resolve) => {
      ua.on('unregistered', () => resolve('unregistered'));
    });
    ua.unregister();
    const said = await within(unregistered, ms, 'the unregistration');
    ua.stop();
    return said;
  },
};
