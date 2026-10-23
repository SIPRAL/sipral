// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

// The browser's half of scripts/lab.sh's `browser` step, run inside
// interop/browser/Dockerfile's image: a headless Chromium, driven by
// Playwright, opens interop/browser/phone.js's page and makes it a phone on
// one of the lab's two SIP over WebSocket servers, named by the argument.
//
//   asterisk   wss://, Asterisk's TLS listener on 8089 (interop/wss/), as
//              labuser-browser, a webrtc=yes endpoint: Asterisk carries the
//              media of each call itself, one WebRTC leg to this page and
//              one to the harness's WebRTC line
//   kamailio   ws://, Kamailio's WebSocket listener on 8080, as
//              webrtc-browser: the proxy carries the signalling only, and
//              the media goes from this page to the harness and back, with
//              trickle ICE both ways
//
// The far end is the Rust harness's `browser` flow
// (interop/harness/src/browser.rs), started beside this one. It calls this
// phone first and hangs up; then this phone calls it and hangs up. Each call
// is judged here on what Chromium itself reports: the harness's tone heard,
// DTLS connected and SRTP keyed, the pair ICE chose, and what was trickled.
// A line per call, `pass` or `FAIL`, in the harness's own form; the exit
// status says whether all of them passed.

import { writeFile, readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { chromium } from 'playwright';

const RATE = 48000;
const TONE_HZ = 1000;
const TONE_SECONDS = 2;
const TONE_PATH = '/tmp/tone.wav';
const LISTEN_MS = 4000;
const PATIENCE_MS = 20000;
const CALLED_PATIENCE_MS = 120000;
const DIAL_PATIENCE_MS = 30000;
const DIAL_RETRY_MS = 2000;
const HEARD_WANTED = 25;

const where = process.argv[2];
const lines = {
  asterisk: {
    socket: 'wss://asterisk:8089/ws',
    uri: 'sip:labuser-browser@asterisk',
    user: 'labuser-browser',
    password: 'labpass',
    target: 'sip:9062@asterisk',
    trickle: false,
  },
  kamailio: {
    socket: 'ws://kamailio:8080/ws',
    uri: 'sip:webrtc-browser@kamailio',
    user: 'webrtc-browser',
    password: 'webrtcpass',
    target: 'sip:webrtc-sipral@kamailio',
    trickle: true,
  },
};
const line = lines[where];
if (!line) {
  console.log(`usage: run.mjs asterisk|kamailio (not ${where})`);
  process.exit(2);
}

// 2 s of a sine at TONE_HZ, a whole number of periods so the fake capture
// device's loop has no seam, at a third of full scale, as 16-bit PCM.
function tone() {
  const samples = RATE * TONE_SECONDS;
  const data = Buffer.alloc(samples * 2);
  for (let index = 0; index < samples; index += 1) {
    const value = Math.round(0.33 * 32767 * Math.sin((2 * Math.PI * TONE_HZ * index) / RATE));
    data.writeInt16LE(value, index * 2);
  }
  const header = Buffer.alloc(44);
  header.write('RIFF', 0);
  header.writeUInt32LE(36 + data.length, 4);
  header.write('WAVE', 8);
  header.write('fmt ', 12);
  header.writeUInt32LE(16, 16);
  header.writeUInt16LE(1, 20);
  header.writeUInt16LE(1, 22);
  header.writeUInt32LE(RATE, 24);
  header.writeUInt32LE(RATE * 2, 28);
  header.writeUInt16LE(2, 32);
  header.writeUInt16LE(16, 34);
  header.write('data', 36);
  header.writeUInt32LE(data.length, 40);
  return Buffer.concat([header, data]);
}

let failed = false;
const pass = (what) => console.log(`  pass  ${what}`);
const fail = (what) => {
  failed = true;
  console.log(`  FAIL  ${what}`);
};

// What one call came to, from Chromium's side, or why it is not enough.
function judged(said, expect) {
  const { stats } = said;
  const trickle = said.trickle;
  const problems = [];
  if (said.heard < HEARD_WANTED) problems.push(`only ${said.heard} of ${said.windows} windows held the harness's tone`);
  if (stats.dtlsState !== 'connected') problems.push(`DTLS is ${stats.dtlsState}`);
  if (!stats.srtpCipher) problems.push('no SRTP suite');
  if (!stats.packetsReceived) problems.push('no RTP received');
  if (expect.trickle) {
    if (said.sentCandidates !== 0) problems.push(`its description carried ${said.sentCandidates} candidates`);
    if (trickle.infosSent === 0 || trickle.candidatesSent === 0) problems.push('nothing was trickled out');
    if (expect.trickledIn && trickle.infosReceived === 0) problems.push('nothing was trickled in');
  }
  const text = `${said.heard} of ${said.windows} windows heard the harness's 444 Hz, `
    + `${said.own} held this end's own tone; ${stats.codec}, ${stats.packetsSent} sent, `
    + `${stats.packetsReceived} received; DTLS ${stats.dtlsState} as ${stats.dtlsRole} `
    + `(${stats.tlsVersion}, ${stats.dtlsCipher}), SRTP ${stats.srtpCipher}; `
    + `pair ${stats.local} -> ${stats.remote}, ${stats.remoteCandidates} remote candidates; `
    + `the far end's description carried ${said.offeredCandidates} candidates, this end's `
    + `${said.sentCandidates}; trickled out ${trickle.infosSent} INFOs, ${trickle.candidatesSent} `
    + `candidates${trickle.endSent ? ' and their end' : ''}; trickled in ${trickle.infosReceived} INFOs, `
    + `${trickle.candidatesAdded} candidates and ${trickle.endsAdded} ends taken`
    + `${said.story.length > 0 ? `; ${said.story.join(', ')}` : ''}`;
  return { problems, text };
}

async function main() {
  await writeFile(TONE_PATH, tone());
  const bundle = await readFile(new URL('./phone.bundle.js', import.meta.url));
  const args = [
    '--use-fake-ui-for-media-stream',
    '--use-fake-device-for-media-stream',
    `--use-file-for-fake-audio-capture=${TONE_PATH}`,
    '--autoplay-policy=no-user-gesture-required',
    // Chromium names its host candidates by a random .local name (mDNS)
    // unless told not to. The stack drops a candidate it cannot read as an
    // address and finds the browser by the checks it sends (a peer-reflexive
    // candidate); Asterisk 22 tries to send to the name and never completes
    // ICE. With the addresses written, what is trickled is a candidate either
    // end can pair
    '--disable-features=WebRtcHideLocalIpsWithMdns',
  ];
  // Asterisk's certificate is made for the run, by the lab's own authority;
  // Chromium is told to take that certificate's key and no other
  if (process.env.SIPRAL_BROWSER_SPKI) {
    args.push(`--ignore-certificate-errors-spki-list=${process.env.SIPRAL_BROWSER_SPKI}`);
  }
  // the page from a server on loopback, a secure context Chromium may open a
  // microphone in, and the most private address space there is: what it
  // reaches on the lab's network is then no less private, and Chromium's
  // local network access checks let it through
  const server = createServer((request, response) => {
    if (request.url === '/phone.js') {
      response.writeHead(200, { 'Content-Type': 'text/javascript' });
      response.end(bundle);
      return;
    }
    response.writeHead(200, { 'Content-Type': 'text/html' });
    response.end('<!doctype html><meta charset="utf-8"><title>lab phone</title><script src="/phone.js"></script>');
  });
  await new Promise((resolve) => {
    server.listen(0, '127.0.0.1', resolve);
  });
  const browser = await chromium.launch({ headless: true, args });
  const said = [];
  try {
    const page = await browser.newPage();
    page.on('console', (message) => {
      if (message.type() === 'error' || message.type() === 'warning') said.push(message.text());
    });
    page.on('pageerror', (error) => said.push(`page error: ${error.message}`));
    await page.goto(`http://127.0.0.1:${server.address().port}/`);
    console.log(`browser: ${browser.version()}, ${line.socket} as ${line.user}`);

    await page.evaluate((options) => window.lab.start(options), line);
    pass(`registered over ${line.socket.split(':')[0]}`);

    // the harness calls first, and hangs up
    const caller = await page.evaluate((ms) => window.lab.answerNext(ms), CALLED_PATIENCE_MS);
    const first = await page.evaluate((ms) => window.lab.listen(ms), LISTEN_MS);
    const firstJudged = judged(first, { trickle: line.trickle, trickledIn: true });
    try {
      const firstEnd = await page.evaluate((ms) => window.lab.farEnd(ms), PATIENCE_MS);
      if (firstEnd.originator !== 'remote') firstJudged.problems.push(`it ended ${firstEnd.originator}: ${firstEnd.cause}`);
    } catch (error) {
      firstJudged.problems.push(error.message.split('\n')[0]);
    }
    if (firstJudged.problems.length === 0) {
      pass(`called by ${caller}, answered, hung up by the far end (${firstJudged.text})`);
    } else {
      fail(`called by ${caller}: ${firstJudged.problems.join('; ')} (${firstJudged.text})`);
    }

    // then this phone calls the harness, and hangs up
    const started = Date.now();
    for (;;) {
      try {
        await page.evaluate(({ target, ms }) => window.lab.dial(target, ms), { target: line.target, ms: PATIENCE_MS });
        break;
      } catch (error) {
        if (Date.now() - started > DIAL_PATIENCE_MS) throw error;
        await new Promise((resolve) => {
          setTimeout(resolve, DIAL_RETRY_MS);
        });
      }
    }
    const second = await page.evaluate((ms) => window.lab.listen(ms), LISTEN_MS);
    const secondEnd = await page.evaluate((ms) => window.lab.hangUp(ms), PATIENCE_MS);
    const secondJudged = judged(second, { trickle: line.trickle, trickledIn: false });
    if (secondEnd.originator !== 'local') secondJudged.problems.push(`it ended ${secondEnd.originator}: ${secondEnd.cause}`);
    if (secondJudged.problems.length === 0) {
      pass(`called ${line.target}, answered, hung up from here (${secondJudged.text})`);
    } else {
      fail(`called ${line.target}: ${secondJudged.problems.join('; ')} (${secondJudged.text})`);
    }

    await page.evaluate((ms) => window.lab.stop(ms), PATIENCE_MS);
    pass('the binding given back');
  } catch (error) {
    fail(`the browser's run stopped: ${error.message.split('\n')[0]}`);
  } finally {
    await browser.close();
    server.close();
  }
  if (failed) {
    for (const text of said) console.log(`  browser: ${text}`);
  }
  process.exit(failed ? 1 : 0);
}

main();
