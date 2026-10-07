// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// What an account carries beyond calls, against this test's own peer
// writing RFC text by hand on loopback, or a second stack: presence
// published and watched, a conference's picture, a MESSAGE, an OAuth 2.0
// token a registrar asked for, a network test, a server located by its
// name, and a media socket mapped through STUN.

import assert from 'node:assert/strict';
import { type AddressInfo, createServer } from 'node:net';
import { afterEach, beforeEach, describe, test } from 'node:test';

import {
  type Call,
  SipralActivity,
  SipralBasic,
  SipralConferenceUpdate,
  SipralDialogPhase,
  SipralDnsAnswer,
  SipralDnsRecordType,
  SipralEndpointStatus,
  SipralEventKind,
  SipralLocateFailure,
  SipralNat,
  SipralNatRelay,
  SipralNetworkProbe,
  SipralNetworkVerdict,
  SipralPresenceKind,
  SipralPublicationState,
  SipralRegistrationState,
  SipralServerReach,
  SipralStatus,
  SipralSubscriptionState,
  SipralTokenError,
  SipralTransport,
  Stack,
  type StackOptions,
} from '../index.js';
import { Peer, StunServer, answer, header, kind, notify, registered, udpRegistrar } from './helpers.js';

const ROOM =
  '<?xml version="1.0"?>\r\n' +
  '<conference-info xmlns="urn:ietf:params:xml:ns:conference-info" entity="sip:room@example.com" state="full" version="1">\r\n' +
  '  <conference-description><subject>Weekly</subject><display-text>Team room</display-text></conference-description>\r\n' +
  '  <conference-state><user-count>3</user-count><active>true</active><locked>false</locked></conference-state>\r\n' +
  '  <users>\r\n' +
  '    <user entity="sip:bob@example.com" state="full"><display-text>Bob</display-text>\r\n' +
  '      <endpoint entity="sip:bob@203.0.113.5"><status>connected</status><media id="1"><type>audio</type></media></endpoint>\r\n' +
  '    </user>\r\n' +
  '    <user entity="sip:carol@example.com" state="full">\r\n' +
  '      <endpoint entity="sip:carol@203.0.113.6"><status>alerting</status></endpoint>\r\n' +
  '    </user>\r\n' +
  '  </users>\r\n' +
  '</conference-info>';

const BUDDY =
  '<?xml version="1.0" encoding="UTF-8"?>\r\n' +
  '<presence xmlns="urn:ietf:params:xml:ns:pidf" xmlns:dm="urn:ietf:params:xml:ns:pidf:data-model" ' +
  'xmlns:rpid="urn:ietf:params:xml:ns:pidf:rpid" entity="sip:bob@example.com">\r\n' +
  '  <tuple id="t1"><status><basic>open</basic></status><note>Back at four</note></tuple>\r\n' +
  '  <dm:person id="p1"><rpid:activities><rpid:meeting/></rpid:activities></dm:person>\r\n' +
  '</presence>';

let stacks: Stack[] = [];
let peers: { close(): void }[] = [];
let calls: Call[] = [];

async function open(options: StackOptions = {}): Promise<Stack> {
  const made = await Stack.open({ bindHost: '127.0.0.1', codecs: 'PCMU', ...options });
  stacks.push(made);
  return made;
}

async function peer(): Promise<Peer> {
  const made = await Peer.open();
  peers.push(made);
  return made;
}

beforeEach(() => {
  stacks = [];
  peers = [];
  calls = [];
});

afterEach(async () => {
  for (const call of calls) {
    call.close();
  }
  for (const stack of stacks) {
    await stack.close();
  }
  for (const one of peers) {
    one.close();
  }
});

describe('presence', () => {
  test('is published, modified and taken away', async () => {
    const stack = await open();
    const compositor = await peer();
    const account = stack.addAccount('sip:alice@sipral.invalid', { registrarAddress: compositor.address });
    assert.throws(() => account.unpublishPresence(), (error: { status?: number }) => error.status === SipralStatus.WrongState);

    account.publishPresence(SipralBasic.Open, SipralActivity.OnThePhone, 'In a call');
    const publish = await compositor.request('PUBLISH');
    assert.equal(header('Event', publish), 'presence');
    for (const said of ['<basic>open</basic>', 'on-the-phone', 'In a call']) {
      assert.ok(publish.includes(said), said);
    }
    const published = kind(stack, SipralEventKind.PresenceChanged);
    compositor.send(answer(publish, '200 OK', 'compositor', 'SIP-ETag: tag-one\r\nExpires: 1800\r\n'), stack.bindAddress);
    const told = await published;
    assert.equal(told.account, account.handle);
    assert.equal(told.fields.kind, SipralPresenceKind.Publication);
    assert.equal(told.fields.publicationState, SipralPublicationState.Published);
    assert.equal(told.fields.expiresMs, 1800000);

    account.publishPresence(SipralBasic.Closed, SipralActivity.Away);
    const modified = await compositor.request('PUBLISH');
    assert.equal(header('SIP-If-Match', modified), 'tag-one');
    const again = kind(stack, SipralEventKind.PresenceChanged);
    compositor.send(answer(modified, '200 OK', 'compositor', 'SIP-ETag: tag-two\r\nExpires: 1800\r\n'), stack.bindAddress);
    await again;

    account.unpublishPresence();
    const removal = await compositor.request('PUBLISH');
    assert.equal(header('Expires', removal), '0');
    const removed = kind(stack, SipralEventKind.PresenceChanged);
    compositor.send(answer(removal, '200 OK', 'compositor', 'SIP-ETag: tag-two\r\nExpires: 0\r\n'), stack.bindAddress);
    assert.equal((await removed).fields.publicationState, SipralPublicationState.Removed);
  });

  test('of a watched presentity is told with its activity and note', async () => {
    const stack = await open();
    const notifier = await peer();
    const account = stack.addAccount('sip:alice@sipral.invalid', { registrarAddress: notifier.address });
    const watched = account.watchPresence('sip:bob@example.com');
    assert.equal(watched.package, 'presence');
    const subscribe = await notifier.request('SUBSCRIBE');
    assert.equal(header('Event', subscribe), 'presence');
    const changed = kind(stack, SipralEventKind.PresenceChanged);
    notifier.send(answer(subscribe, '200 OK', 'notifier', `Expires: 3600\r\nContact: <sip:bob@${notifier.address}>\r\n`), stack.bindAddress);
    notifier.send(notify(subscribe, notifier.address, 'presence', 'application/pidf+xml', BUDDY, 1), stack.bindAddress);
    const told = await changed;
    assert.equal(told.fields.kind, SipralPresenceKind.Watched);
    assert.equal(told.fields.subscription, watched.handle);
    assert.equal(told.fields.basic, SipralBasic.Open);
    assert.equal(told.fields.activity, SipralActivity.Meeting);
    assert.equal(told.fields.entity, 'sip:bob@example.com');
    assert.equal(told.fields.note, 'Back at four');
    assert.equal(watched.state, SipralSubscriptionState.Active);
    watched.end();
    const ending = await notifier.request('SUBSCRIBE');
    assert.equal(header('Expires', ending), '0');
  });
});

describe('a conference subscription', () => {
  test('reads the picture back whole, and hears its end', async () => {
    const stack = await open();
    const notifier = await peer();
    const account = stack.addAccount('sip:alice@sipral.invalid', { registrarAddress: notifier.address });
    const subscription = account.subscribe('sip:room@example.com', 'conference');
    assert.equal(subscription.conference(), null);
    const subscribe = await notifier.request('SUBSCRIBE');
    const changed = kind(stack, SipralEventKind.ConferenceChanged);
    notifier.send(answer(subscribe, '200 OK', 'notifier', `Expires: 3600\r\nContact: <sip:room@${notifier.address}>\r\n`), stack.bindAddress);
    notifier.send(notify(subscribe, notifier.address, 'conference', 'application/conference-info+xml', ROOM, 1), stack.bindAddress);
    const event = await changed;
    assert.equal(event.fields.subscription, subscription.handle);
    assert.equal(event.fields.update, SipralConferenceUpdate.Applied);
    assert.deepEqual(subscription.conference(), {
      version: 1,
      entity: 'sip:room@example.com',
      subject: 'Weekly',
      displayText: 'Team room',
      userCount: 3,
      active: true,
      locked: false,
      users: [
        { entity: 'sip:bob@example.com', displayText: 'Bob', endpoint: 'sip:bob@203.0.113.5', status: SipralEndpointStatus.Connected, endpoints: 1, media: 1 },
        { entity: 'sip:carol@example.com', displayText: null, endpoint: 'sip:carol@203.0.113.6', status: SipralEndpointStatus.Alerting, endpoints: 1, media: 0 },
      ],
    });
    const ended = kind(stack, SipralEventKind.ConferenceChanged);
    const deleted =
      '<conference-info xmlns="urn:ietf:params:xml:ns:conference-info" entity="sip:room@example.com" state="deleted" version="2"/>';
    notifier.send(notify(subscribe, notifier.address, 'conference', 'application/conference-info+xml', deleted, 2), stack.bindAddress);
    const over = await ended;
    assert.equal(over.fields.update, SipralConferenceUpdate.Ended);
    assert.equal(over.fields.users, 0);
  });
});

describe('a dialog subscription', () => {
  test("reads the line's dialogs and its lamp", async () => {
    const stack = await open();
    const notifier = await peer();
    const account = stack.addAccount('sip:alice@sipral.invalid', { registrarAddress: notifier.address });
    const line = account.subscribe('sip:bob@example.com', 'dialog');
    const subscribe = await notifier.request('SUBSCRIBE');
    assert.equal(header('Event', subscribe), 'dialog');
    const told = kind(stack, SipralEventKind.Notified);
    const info =
      '<?xml version="1.0"?>\r\n' +
      '<dialog-info xmlns="urn:ietf:params:xml:ns:dialog-info" version="0" state="full" entity="sip:bob@example.com">\r\n' +
      '  <dialog id="d1" call-id="c1" direction="recipient"><state>confirmed</state>' +
      '<remote><identity display="Carol">sip:carol@example.com</identity></remote></dialog>\r\n' +
      '</dialog-info>';
    notifier.send(answer(subscribe, '200 OK', 'notifier', `Expires: 3600\r\nContact: <sip:bob@${notifier.address}>\r\n`), stack.bindAddress);
    notifier.send(notify(subscribe, notifier.address, 'dialog', 'application/dialog-info+xml', info, 1), stack.bindAddress);
    await told;
    const [dialog] = line.dialogs();
    assert.equal(dialog?.id, 'd1');
    assert.equal(dialog?.callId, 'c1');
    assert.equal(dialog?.remoteIdentity, 'sip:carol@example.com');
    assert.equal(dialog?.remoteDisplay, 'Carol');
    assert.equal(line.lamp(), SipralDialogPhase.Confirmed);
  });
});

describe('a MESSAGE', () => {
  test('reaches the other stack with its body, and its answer comes back', async () => {
    const alice = await open();
    const bob = await open();
    const line = alice.addAccount('sip:alice@sipral.invalid', { registrarAddress: bob.bindAddress });
    bob.addAccount('sip:bob@sipral.invalid', { registrarAddress: alice.bindAddress });
    const received = kind(bob, SipralEventKind.MessageReceived);
    const sent = kind(alice, SipralEventKind.MessageSent);
    const message = line.sendMessage(`sip:bob@${bob.bindAddress}`, 'hello there');
    const arrived = await received;
    assert.equal(arrived.fields.contentType, 'text/plain');
    assert.equal((arrived.fields.body as Buffer).toString('utf8'), 'hello there');
    const answered = await sent;
    assert.equal(answered.fields.message, message);
    assert.equal(answered.fields.statusCode, 200);
  });
});

describe('an OAuth 2.0 token', () => {
  test('a registrar asks for is told where to get, and the REGISTER carries it', async () => {
    const stack = await open();
    const registrar = await peer();
    registrar.responder = (message) => {
      if (!message.startsWith('REGISTER ')) {
        return null;
      }
      const authorization = header('Authorization', message);
      if (authorization === 'Bearer eyJhbGciOiJub25lIn0.e30.') {
        return registered(message);
      }
      return answer(
        message,
        '401 Unauthorized',
        'registrar',
        'WWW-Authenticate: Bearer realm="sipral.test", scope="sip register", authz_server="https://as.sipral.test/token"\r\n',
      );
    };
    const account = stack.addAccount('sip:alice@sipral.test', { registrarAddress: registrar.address, registrar: 'sip:sipral.test' });
    const wanted = kind(stack, SipralEventKind.TokenRequired);
    account.register();
    const asked = await wanted;
    assert.equal(asked.account, account.handle);
    assert.equal(asked.fields.authzServer, 'https://as.sipral.test/token');
    assert.equal(asked.fields.scope, 'sip register');
    assert.equal(asked.fields.realm, 'sipral.test');
    assert.equal(asked.fields.error, SipralTokenError.None);
    assert.throws(() => account.setAccessToken('two words'), (error: { status?: number }) => error.status === SipralStatus.InvalidArgument);
    account.setAccessToken('eyJhbGciOiJub25lIn0.e30.');
    await account.registered();
    assert.equal(account.registrationState, SipralRegistrationState.Registered);
    account.setAccessToken(null);
  });
});

describe('a network test', () => {
  test("asks the account's server with an OPTIONS and says it answered", async () => {
    const alice = await open();
    const bob = await open();
    const line = alice.addAccount('sip:alice@sipral.invalid', { registrarAddress: bob.bindAddress });
    bob.addAccount('sip:bob@sipral.invalid', { registrarAddress: alice.bindAddress });
    const test = await alice.networkTest({ account: line });
    const done = await alice.next((event) => event.kind === SipralEventKind.NetworkTest && event.fields.test === test);
    assert.equal(done.fields.server, SipralServerReach.Answered);
    assert.equal(done.fields.serverStatus, 200);
    assert.equal(done.fields.stun, SipralNetworkProbe.NotTested);
    assert.equal(done.fields.verdict, SipralNetworkVerdict.Good);
  });

  test('measures an echo call and hangs it up', async () => {
    const alice = await open();
    const bob = await open();
    bob.on('event', (event) => {
      if (event.kind === SipralEventKind.IncomingCall) {
        void bob.answerCall(event).then((call) => {
          calls.push(call);
          call.on('media', (media) => media.on('frame', (frame) => media.sendAudio(frame)));
        });
      }
    });
    const line = alice.addAccount('sip:alice@sipral.invalid', { registrarAddress: bob.bindAddress });
    bob.addAccount('sip:bob@sipral.invalid', { registrarAddress: alice.bindAddress });
    const call = await alice.placeCall(line, `sip:bob@${bob.bindAddress}`);
    calls.push(call);
    const test = await alice.networkTest({ echoCall: call, echoMs: 1500 });
    const media = await call.mediaStarted();
    const speaking = setInterval(() => media.sendAudio(new Int16Array(media.frameSamples)), media.frameMs);
    try {
      const done = await alice.next((event) => event.kind === SipralEventKind.NetworkTest && event.fields.test === test);
      assert.equal(done.fields.echo, SipralNetworkProbe.Succeeded);
      assert.ok((done.fields.mos as number) > 4);
    } finally {
      clearInterval(speaking);
    }
    await call.whenEnded(5000);
  });
});

describe('a server named by its name', () => {
  test('a host with a port is looked up and registered with', async () => {
    const registrar = await udpRegistrar();
    peers.push(registrar);
    const stack = await open({ bindHost: undefined });
    const port = registrar.address.split(':')[1];
    const account = stack.addAccount('sip:alice@sipral.test', { serverUri: `sip:localhost:${port}`, registrar: 'sip:sipral.test' });
    const located = kind(stack, SipralEventKind.Located);
    await account.registered();
    assert.ok(((await located).fields.targets as string).split(',').includes(registrar.address));
    assert.equal(account.registrarAddress, registrar.address);
  });

  test("an SRV answer from the application's resolver names where the requests go", async () => {
    const registrar = await udpRegistrar();
    peers.push(registrar);
    const asked: [string, number][] = [];
    const port = registrar.address.split(':')[1];
    const stack = await open({
      resolver: async (name, record) => {
        asked.push([name, record]);
        if (record === SipralDnsRecordType.Srv && name === '_sip._udp.pbx.sipral.test') {
          return { answer: SipralDnsAnswer.Records, records: [`300 10 60 ${port} host.sipral.test`] };
        }
        if (record === SipralDnsRecordType.A && name === 'host.sipral.test') {
          return { answer: SipralDnsAnswer.Records, records: ['300 127.0.0.1'] };
        }
        return { answer: SipralDnsAnswer.Nothing, records: [] };
      },
    });
    const account = stack.addAccount('sip:alice@pbx.sipral.test', { serverUri: 'sip:pbx.sipral.test', registrar: 'sip:pbx.sipral.test' });
    await account.registered();
    assert.ok(asked.some(([name, record]) => name === '_sip._udp.pbx.sipral.test' && record === SipralDnsRecordType.Srv));
    assert.equal(account.registrarAddress, registrar.address);
  });

  test('a name with no address is a located failure that says why', async () => {
    const stack = await open({ resolver: async () => ({ answer: SipralDnsAnswer.Nothing, records: [] }) });
    const account = stack.addAccount('sip:alice@sipral.test', { serverUri: 'sip:nowhere.sipral.test', registrar: 'sip:sipral.test' });
    const failed = kind(stack, SipralEventKind.LocateFailed);
    account.register();
    const event = await failed;
    assert.equal(event.fields.failure, SipralLocateFailure.NotFound);
    assert.ok((event.fields.retryInMs as number) > 0);
    assert.throws(() => stack.addAccount('sip:bob@sipral.test', { registrarAddress: '127.0.0.1:5060', serverUri: 'sip:x.test' }), TypeError);
  });
});

describe('a stack behind a NAT', () => {
  test("maps its signalling and a call's media through STUN, and offers the mapped address", async () => {
    const stun = await StunServer.open('203.0.113.7', 40000);
    peers.push(stun);
    const alice = await open({ nat: SipralNat.Stun, stunServer: stun.address });
    const bob = await open();
    const signalling = await kind(alice, SipralEventKind.NatMapping);
    assert.equal(signalling.fields.signalling, 1);
    assert.equal(signalling.fields.mapped, '203.0.113.7:40000');
    const line = alice.addAccount('sip:alice@sipral.invalid', { registrarAddress: bob.bindAddress });
    bob.addAccount('sip:bob@sipral.invalid', { registrarAddress: alice.bindAddress });
    const ringing = kind(bob, SipralEventKind.IncomingCall);
    const call = await alice.placeCall(line, `sip:bob@${bob.bindAddress}`);
    calls.push(call);
    const invite = ((await ringing).message as Buffer).toString('utf8');
    assert.match(invite, /c=IN IP4 203\.0\.113\.7/);
    alice.setStunServers([]);
  });

  test('a TURN server over TCP that cannot be reached is no relay, and the call goes on', async () => {
    const stun = await StunServer.open('203.0.113.7', 40000);
    peers.push(stun);
    const closed = createServer();
    await new Promise<void>((resolve) => closed.listen(0, '127.0.0.1', resolve));
    const turnServer = `127.0.0.1:${(closed.address() as AddressInfo).port}`;
    await new Promise<void>((resolve) => closed.close(() => resolve()));
    const alice = await open({
      nat: SipralNat.Stun,
      stunServer: stun.address,
      turnServer,
      turnUsername: 'alice',
      turnPassword: 'secret',
      turnTransport: SipralTransport.Tcp,
    });
    const bob = await open();
    const line = alice.addAccount('sip:alice@sipral.invalid', { registrarAddress: bob.bindAddress });
    bob.addAccount('sip:bob@sipral.invalid', { registrarAddress: alice.bindAddress });
    const asked = kind(alice, SipralEventKind.TurnStream);
    const relay = alice.next((event) => event.kind === SipralEventKind.NatRelay && event.fields.local !== null);
    const ringing = kind(bob, SipralEventKind.IncomingCall);
    const placing = alice.placeCall(line, `sip:bob@${bob.bindAddress}`);
    assert.equal((await asked).fields.server, turnServer);
    assert.notEqual((await relay).fields.outcome, SipralNatRelay.Allocated);
    calls.push(await placing);
    await ringing;
  });
});
