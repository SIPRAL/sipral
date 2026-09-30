// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

import Sipral, {SipralCall, SipralClient, SipralError} from '../index';
import type {CallEndedEvent, IncomingCallEvent, RegistrationChangedEvent} from '../index';
import {FakeNative} from './support/fakeNative';
import {asked} from './support/reactNative';

let open: SipralClient[] = [];

async function opened(native = new FakeNative()): Promise<{client: SipralClient; native: FakeNative}> {
  const client = await Sipral.open({bindHost: '192.0.2.10'}, native);
  open.push(client);
  return {client, native};
}

afterEach(async () => {
  for (const client of open) {
    await client.close();
  }
  open = [];
});

async function refusal(promise: Promise<unknown>): Promise<SipralError> {
  try {
    await promise;
  } catch (failure) {
    expect(failure).toBeInstanceOf(SipralError);
    return failure as SipralError;
  }
  throw new Error('expected a rejection');
}

async function confirmedCall(): Promise<{client: SipralClient; native: FakeNative; call: SipralCall}> {
  const {client, native} = await opened();
  const account = await client.addAccount({aor: 'sip:alice@example.com', registrarAddress: '203.0.113.5:5060'});
  const call = await client.placeCall(account, 'sip:bob@example.com');
  native.emit({kind: 'callConfirmed', call: call.id, callState: 'confirmed', statusCode: 200});
  return {client, native, call};
}

describe('opening', () => {
  it('listens before it opens, so an event raised while opening arrives', async () => {
    const native = new FakeNative();
    const seen: string[] = [];
    native.during.open = () => native.emit({kind: 'incomingCall', call: '7', fromUri: 'sip:carol@example.com'});
    const client = await Sipral.open({bindHost: '192.0.2.10'}, native);
    open.push(client);
    expect(client.callList.map((call) => [call.id, call.direction, call.remote])).toEqual([
      ['7', 'incoming', 'sip:carol@example.com'],
    ]);
    client.on('event', (event) => seen.push(event.kind));
    expect(native.listeners).toBe(1);
    expect(client.bindAddress).toBe('192.0.2.10:5060');
    expect(native.calls[0]).toEqual({
      method: 'open',
      args: [
        {
          bindHost: '192.0.2.10',
          bindPort: undefined,
          userAgent: undefined,
          codecs: undefined,
          signalling: 'udp',
          signallingServer: undefined,
          stunServer: undefined,
          manualAudio: false,
        },
      ],
    });
    native.emit({kind: 'started'});
    expect(seen).toEqual(['started']);
  });

  it('passes manual activation through', async () => {
    const native = new FakeNative();
    const client = await Sipral.open({bindHost: '192.0.2.10', audioActivation: 'manual'}, native);
    open.push(client);
    expect((native.calls[0].args[0] as {manualAudio: boolean}).manualAudio).toBe(true);
  });

  it('refuses a missing address, and a stream with no server, before crossing', async () => {
    const native = new FakeNative();
    expect((await refusal(Sipral.open({bindHost: ' '}, native))).code).toBe('invalidArgument');
    expect((await refusal(Sipral.open({bindHost: '192.0.2.10', signalling: 'tls'}, native))).code).toBe(
      'invalidArgument',
    );
    expect(native.calls).toEqual([]);
  });

  it('holds one client at a time', async () => {
    const {client} = await opened();
    expect((await refusal(Sipral.open({bindHost: '192.0.2.10'}, new FakeNative()))).code).toBe('wrongState');
    await client.close();
    open = [];
    await opened();
  });

  it('turns a refused open into a SipralError and lets go of the slot', async () => {
    const native = new FakeNative();
    native.failNext('open', 'invalidArgument', 'no such address');
    const failure = await refusal(Sipral.open({bindHost: '198.51.100.1'}, native));
    expect(failure.code).toBe('invalidArgument');
    expect(failure.message).toBe('no such address');
    expect(native.listeners).toBe(0);
    await opened();
  });

  it('looks the native module up as Sipral', () => {
    expect(asked).toEqual(['Sipral']);
  });
});

describe('accounts', () => {
  it('follows registration events on the account and on the client', async () => {
    const {client, native} = await opened();
    const account = await client.addAccount({
      aor: 'sip:alice@example.com',
      registrarAddress: '203.0.113.5:5060',
      registrar: 'sip:example.com',
      authUser: 'alice',
      authPassword: 'secret',
    });
    expect(account.id).toBe('1');
    expect(account.registrationState).toBe('idle');
    const onAccount: RegistrationChangedEvent[] = [];
    const onClient: RegistrationChangedEvent[] = [];
    account.on('registrationChanged', (event) => onAccount.push(event));
    client.on('registrationChanged', (event) => onClient.push(event));

    await account.register();
    native.emit({kind: 'registrationChanged', account: '1', registrationState: 'registering'});
    native.emit({kind: 'registrationChanged', account: '1', registrationState: 'registered', statusCode: 200});
    native.emit({kind: 'registrationChanged', account: '99', registrationState: 'registered'});

    expect(account.registrationState).toBe('registered');
    expect(onAccount.map((event) => event.state)).toEqual(['registering', 'registered']);
    expect(onClient).toEqual(onAccount);
    expect(onClient[1]).toEqual({account, state: 'registered', statusCode: 200, retryInMs: 0});
    expect(native.methods()).toEqual(['open', 'addAccount', 'register']);

    await account.unregister();
    expect(native.calls.at(-1)).toEqual({method: 'unregister', args: [account.id]});
  });

  it('resolves registerAndWait on registered and rejects it on failed', async () => {
    const {client, native} = await opened();
    const account = await client.addAccount({aor: 'sip:alice@example.com', registrarAddress: '203.0.113.5:5060'});
    native.during.register = () => native.emit({kind: 'registrationChanged', account: account.id, registrationState: 'registered'});
    await account.registerAndWait();

    native.during.register = () =>
      native.emit({kind: 'registrationChanged', account: account.id, registrationState: 'failed', statusCode: 403});
    const failure = await refusal(account.registerAndWait());
    expect(failure.message).toContain('403');
  });

  it('rejects registerAndWait with what the native half refused', async () => {
    const {client, native} = await opened();
    const account = await client.addAccount({aor: 'sip:alice@example.com', registrarAddress: '203.0.113.5:5060'});
    native.failNext('register', 'wrongState', 'the account has no registrar');
    expect((await refusal(account.registerAndWait())).code).toBe('wrongState');
  });

  it('refuses everything on an account once it is removed', async () => {
    const {client, native} = await opened();
    const account = await client.addAccount({aor: 'sip:alice@example.com', registrarAddress: '203.0.113.5:5060'});
    await account.remove();
    expect(client.accountList).toEqual([]);
    expect((await refusal(account.register())).code).toBe('wrongState');
    expect((await refusal(client.placeCall(account, 'sip:bob@example.com'))).code).toBe('wrongState');
    expect(native.methods()).toEqual(['open', 'addAccount', 'removeAccount']);
  });

  it('refuses an account with no address before crossing', async () => {
    const {client, native} = await opened();
    expect((await refusal(client.addAccount({aor: '', registrarAddress: '203.0.113.5:5060'}))).code).toBe(
      'invalidArgument',
    );
    expect(native.methods()).toEqual(['open']);
  });
});

describe('a call placed', () => {
  it('moves through progress and confirmation, and only then holds, sends digits and transfers', async () => {
    const {client, native} = await opened();
    const account = await client.addAccount({aor: 'sip:alice@example.com', registrarAddress: '203.0.113.5:5060'});
    const call = await client.placeCall(account, 'sip:bob@example.com', {destination: '203.0.113.7:5060'});
    expect(native.calls[2]).toEqual({
      method: 'placeCall',
      args: ['1', 'sip:bob@example.com', {destination: '203.0.113.7:5060'}],
    });
    expect(call.direction).toBe('outgoing');
    expect(call.remote).toBe('sip:bob@example.com');
    expect(call.state).toBe('calling');

    expect((await refusal(call.hold())).code).toBe('wrongState');
    expect((await refusal(call.sendDtmf('1'))).code).toBe('wrongState');
    expect((await refusal(call.transfer('sip:carol@example.com'))).code).toBe('wrongState');
    expect((await refusal(call.answer())).code).toBe('wrongState');

    const progress: number[] = [];
    call.on('progress', (event) => progress.push(event.statusCode));
    native.emit({kind: 'callProgress', call: call.id, callState: 'ringing', statusCode: 180});
    expect(call.state).toBe('ringing');
    expect(progress).toEqual([180]);

    native.emit({kind: 'callConfirmed', call: call.id, callState: 'confirmed', statusCode: 200});
    expect(call.state).toBe('confirmed');

    await call.hold();
    native.emit({kind: 'sessionChanged', call: call.id, callState: 'confirmed', heldHere: true, heldThere: false});
    expect(call.heldHere).toBe(true);
    await call.resume();
    await call.sendDtmf('12#*A');
    await call.transfer('sip:carol@example.com');
    expect(native.calls.slice(3)).toEqual([
      {method: 'hold', args: [call.id]},
      {method: 'resume', args: [call.id]},
      {method: 'sendDtmf', args: [call.id, '12#*A']},
      {method: 'transfer', args: [call.id, 'sip:carol@example.com']},
    ]);
  });

  it('refuses digits no keypad has and a transfer with no target, before crossing', async () => {
    const {native, call} = await confirmedCall();
    const before = native.calls.length;
    expect((await refusal(call.sendDtmf('12x'))).code).toBe('invalidArgument');
    expect((await refusal(call.sendDtmf(''))).code).toBe('invalidArgument');
    expect((await refusal(call.transfer('  '))).code).toBe('invalidArgument');
    expect(native.calls.length).toBe(before);
  });

  it('is the same call when an event names it before the promise that made it resolves', async () => {
    const {client, native} = await opened();
    const account = await client.addAccount({aor: 'sip:alice@example.com', registrarAddress: '203.0.113.5:5060'});
    native.during.placeCall = () => native.emit({kind: 'callConfirmed', call: '2', callState: 'confirmed'});
    const call = await client.placeCall(account, 'sip:bob@example.com');
    expect(call.id).toBe('2');
    expect(call.state).toBe('confirmed');
    expect(call.remote).toBe('sip:bob@example.com');
    expect(client.callList).toEqual([call]);
  });

  it('reports hold changes once each, on the call and on the client', async () => {
    const {client, native, call} = await confirmedCall();
    const seen: Array<[boolean, boolean]> = [];
    client.on('holdChanged', (event) => seen.push([event.heldHere, event.heldThere]));
    native.emit({kind: 'sessionChanged', call: call.id, heldHere: false, heldThere: true});
    native.emit({kind: 'sessionChanged', call: call.id, heldHere: false, heldThere: true});
    native.emit({kind: 'sessionChanged', call: call.id, heldHere: false, heldThere: false});
    expect(seen).toEqual([
      [false, true],
      [false, false],
    ]);
    expect(call.heldThere).toBe(false);
  });

  it('reports a transfer it asked for, on the call and on the client', async () => {
    const {client, native, call} = await confirmedCall();
    const onCall: string[] = [];
    const onClient: number[] = [];
    call.on('transferProgress', (event) => onCall.push(`progress ${event.statusCode}`));
    call.on('transferDone', (event) => onCall.push(`done ${event.statusCode}`));
    client.on('transferDone', (event) => onClient.push(event.statusCode));
    native.emit({kind: 'transferProgress', call: call.id, statusCode: 100});
    native.emit({kind: 'transferDone', call: call.id, statusCode: 200});
    expect(onCall).toEqual(['progress 100', 'done 200']);
    expect(onClient).toEqual([200]);
  });

  it('turns a native refusal into its status, and anything else into platform', async () => {
    const {native, call} = await confirmedCall();
    native.failNext('hold', 'wrongState', 'no media yet');
    const refused = await refusal(call.hold());
    expect(refused.code).toBe('wrongState');
    expect(refused.message).toBe('no media yet');
    native.failNext('resume', 'EUNSPECIFIED', 'socket closed');
    expect((await refusal(call.resume())).code).toBe('platform');
  });
});

describe('a call that arrives', () => {
  async function ringing(): Promise<{client: SipralClient; native: FakeNative; incoming: IncomingCallEvent}> {
    const {client, native} = await opened();
    const arrivals: IncomingCallEvent[] = [];
    client.on('incomingCall', (event) => arrivals.push(event));
    native.emit({
      kind: 'incomingCall',
      call: '42',
      account: '1',
      fromUri: 'sip:carol@example.com',
      fromDisplay: 'Carol',
      toUri: 'sip:alice@example.com',
    });
    expect(arrivals).toHaveLength(1);
    return {client, native, incoming: arrivals[0]};
  }

  it('is handed over as a call, answered once', async () => {
    const {native, incoming} = await ringing();
    const call = incoming.call;
    expect(incoming.from).toBe('sip:carol@example.com');
    expect(incoming.fromDisplay).toBe('Carol');
    expect(incoming.to).toBe('sip:alice@example.com');
    expect(call.direction).toBe('incoming');
    expect(call.state).toBe('incoming');
    expect(call.remote).toBe('sip:carol@example.com');

    await call.answer();
    expect((await refusal(call.answer())).code).toBe('wrongState');
    expect((await refusal(call.reject())).code).toBe('wrongState');
    expect(native.methods().filter((method) => method === 'answer')).toHaveLength(1);
  });

  it('is rejected with a final response only', async () => {
    const {native, incoming} = await ringing();
    expect((await refusal(incoming.call.reject(180))).code).toBe('invalidArgument');
    await incoming.call.reject(603);
    expect(native.calls.at(-1)).toEqual({method: 'reject', args: ['42', 603]});
  });

  it('can be answered again if the answer was refused', async () => {
    const {native, incoming} = await ringing();
    native.failNext('answer', 'notSent', 'the socket would not bind');
    expect((await refusal(incoming.call.answer())).code).toBe('notSent');
    await incoming.call.answer();
  });
});

describe('the end of a call', () => {
  it('says why, forgets the call, and refuses everything after', async () => {
    const {client, native, call} = await confirmedCall();
    const ended: CallEndedEvent[] = [];
    call.on('ended', (event) => ended.push(event));
    client.on('callEnded', (event) => ended.push(event));
    native.emit({kind: 'callEnded', call: call.id, callState: 'terminated', endReason: 'remoteHangup', statusCode: 0});
    native.emit({kind: 'callEnded', call: call.id, endReason: 'remoteHangup'});

    expect(ended).toHaveLength(2);
    expect(ended[0]).toEqual({call, reason: 'remoteHangup', statusCode: 0});
    expect(call.ended).toBe(true);
    expect(call.state).toBe('terminated');
    expect(call.endReason).toBe('remoteHangup');
    expect(client.callList).toEqual([]);

    const before = native.calls.length;
    for (const attempt of [call.hangup(), call.hold(), call.sendDtmf('1'), call.transfer('sip:x@example.com')]) {
      expect((await refusal(attempt)).code).toBe('wrongState');
    }
    expect(native.calls.length).toBe(before);
  });

  it('hangs up in any state until then', async () => {
    const {client, native} = await opened();
    const account = await client.addAccount({aor: 'sip:alice@example.com', registrarAddress: '203.0.113.5:5060'});
    const call = await client.placeCall(account, 'sip:bob@example.com');
    await call.hangup();
    expect(native.calls.at(-1)).toEqual({method: 'hangup', args: [call.id]});
  });
});

describe('a transfer the far end asks for', () => {
  it('is handed over with its target, and taken as a new call', async () => {
    const {client, native, call} = await confirmedCall();
    const asked: string[] = [];
    client.on('transferRequested', (event) => asked.push(`${event.target} ${event.attended}`));
    native.emit({kind: 'transferRequested', call: call.id, target: 'sip:carol@example.com', attended: false});
    expect(asked).toEqual(['sip:carol@example.com false']);

    const placed = await call.acceptTransfer();
    expect(placed.direction).toBe('outgoing');
    expect(client.callList).toContain(placed);
    expect(native.calls.at(-1)).toEqual({method: 'acceptTransfer', args: [call.id]});
  });

  it('is refused with a final response only', async () => {
    const {native, call} = await confirmedCall();
    expect((await refusal(call.rejectTransfer(200))).code).toBe('invalidArgument');
    await call.rejectTransfer();
    expect(native.calls.at(-1)).toEqual({method: 'rejectTransfer', args: [call.id, 603]});
    await call.rejectTransfer(486);
    expect(native.calls.at(-1)).toEqual({method: 'rejectTransfer', args: [call.id, 486]});
  });
});

describe('digits and audio', () => {
  it('hands a received digit to the call and the client', async () => {
    const {client, native, call} = await confirmedCall();
    const onCall: string[] = [];
    const onClient: string[] = [];
    call.on('digit', (event) => onCall.push(event.digit));
    client.on('digitReceived', (event) => onClient.push(event.digit));
    native.emit({kind: 'digitReceived', call: call.id, digit: '5'});
    native.emit({kind: 'digitReceived', call: call.id, digit: '#'});
    expect(onCall).toEqual(['5', '#']);
    expect(onClient).toEqual(['5', '#']);
  });

  it('activates, deactivates and mutes through the native half', async () => {
    const {client, native} = await opened();
    await client.audio.activate();
    await client.audio.setMuted(true);
    await client.audio.deactivate();
    expect(native.calls.slice(1)).toEqual([
      {method: 'activateAudio', args: []},
      {method: 'setMuted', args: [true]},
      {method: 'deactivateAudio', args: []},
    ]);
  });
});

describe('closing', () => {
  it('stops listening, refuses what comes after, and ignores late events', async () => {
    const {client, native, call} = await confirmedCall();
    const seen: string[] = [];
    client.on('event', (event) => seen.push(event.kind));
    await client.close();
    expect(native.methods().at(-1)).toBe('close');
    expect(native.listeners).toBe(0);
    expect(client.isClosed).toBe(true);
    native.emit({kind: 'callEnded', call: call.id});
    expect(seen).toEqual([]);
    expect((await refusal(call.hangup())).code).toBe('closed');
    expect((await refusal(client.audio.activate())).code).toBe('closed');
    await client.close();
    expect(native.methods().filter((method) => method === 'close')).toHaveLength(1);
  });
});
