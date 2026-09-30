// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea
//
// Two stacks on 127.0.0.1, one calling the other directly with no
// registrar between them: placed, answered, confirmed, RTP both ways,
// digits over, hung up from one side and ended on both.

import 'dart:async';
import 'dart:typed_data';

import 'package:sipral/sipral.dart';
import 'package:test/test.dart';

/// Poll [probe] every 20 ms until it holds, or fail after [within].
Future<void> until(bool Function() probe,
    {Duration within = const Duration(seconds: 15)}) async {
  final deadline = DateTime.now().add(within);
  while (!probe()) {
    if (DateTime.now().isAfter(deadline)) {
      fail('nothing within $within');
    }
    await Future<void>.delayed(const Duration(milliseconds: 20));
  }
}

void main() {
  late SipralStack alice;
  late SipralStack bob;

  setUp(() async {
    alice = await SipralStack.open(userAgent: 'sipral-dart-test');
    bob = await SipralStack.open();
  });

  tearDown(() async {
    await alice.close();
    await bob.close();
  });

  test('a call between two stacks on loopback', () async {
    final fromAlice = alice.addAccount(
      'sip:alice@sipral.invalid',
      registrarAddress: bob.bindAddress,
    );
    bob.addAccount('sip:bob@sipral.invalid',
        registrarAddress: alice.bindAddress);

    // subscribed before the INVITE can arrive, so it cannot be missed
    final ringing = bob.events
        .firstWhere((event) => event.kind == SipralEventKind.incomingCall);
    final callA =
        await alice.placeCall(fromAlice, 'sip:bob@${bob.bindAddress}');
    final incoming = await ringing.timeout(const Duration(seconds: 15));
    expect(incoming.callState, isNotNull);
    final callB = await bob.answerCall(incoming);
    expect(callB.incoming, isTrue);

    await Future.wait([
      callA.confirmed(timeout: const Duration(seconds: 15)),
      callB.confirmed(timeout: const Duration(seconds: 15)),
    ]);
    expect(callA.state, SipralCallState.confirmed);
    expect(callB.state, SipralCallState.confirmed);

    await until(() => callA.media != null && callB.media != null);
    final mediaA = callA.media!;
    final mediaB = callB.media!;
    await until(
      () =>
          mediaA.statistics().packetsReceived > 0 &&
          mediaB.statistics().packetsReceived > 0,
    );
    expect(mediaA.statistics().packetsSent, greaterThan(0));
    expect(mediaB.statistics().packetsSent, greaterThan(0));

    // audio queued on one end is played out as frames on the other
    final heard = mediaB.frames.first.timeout(const Duration(seconds: 15));
    mediaA.sendAudio(
        Int16List.fromList(List.filled(mediaA.frameSamples * 5, 1000)));
    expect((await heard).length, mediaB.frameSamples);

    final digits = <String>[];
    final listening = callB.digits.listen(digits.add);
    callA.sendDtmf('42#');
    await until(() => digits.length >= 3);
    await listening.cancel();
    expect(digits, ['4', '2', '#']);

    final bobEnded = callB.whenEnded(timeout: const Duration(seconds: 15));
    callA.hangup();
    await callA.whenEnded(timeout: const Duration(seconds: 15));
    await bobEnded;
    expect(callA.ended && callB.ended, isTrue);
    expect(callA.state, SipralCallState.terminated);

    callA.close();
    callB.close();
    expect(callA.media, isNull);
  });

  test('a call that is refused ends without being confirmed', () async {
    final fromAlice = alice.addAccount(
      'sip:alice@sipral.invalid',
      registrarAddress: bob.bindAddress,
    );
    bob.addAccount('sip:bob@sipral.invalid',
        registrarAddress: alice.bindAddress);
    final ringing = bob.events
        .firstWhere((event) => event.kind == SipralEventKind.incomingCall);
    final call = await alice.placeCall(fromAlice, 'sip:bob@${bob.bindAddress}');
    bob.rejectCall(await ringing.timeout(const Duration(seconds: 15)),
        code: 486);
    await expectLater(
        call.confirmed(timeout: const Duration(seconds: 15)), throwsStateError);
    await call.whenEnded(timeout: const Duration(seconds: 15));
    call.close();
  });

  test('a library call that fails throws with the library\'s own words', () {
    expect(
      () => alice.addAccount('not a uri', registrarAddress: 'nowhere'),
      throwsA(
          isA<SipralException>().having((e) => e.detail, 'detail', isNotEmpty)),
    );
  });
}
