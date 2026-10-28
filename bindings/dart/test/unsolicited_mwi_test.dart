// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// A `message-summary` NOTIFY nobody subscribed to, the way a PBX that ties
// the mailbox to the extension sends it, from the account's registrar
// address: an account with `unsolicitedMwi` answers it 200 and reports the
// mailbox, one without answers it 481 (RFC 6665 §4.1.3) and reports nothing.

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:sipral/sipral.dart';
import 'package:test/test.dart';

final class Pbx {
  Pbx._(this._socket) {
    _socket.listen((event) {
      if (event != RawSocketEvent.read) {
        return;
      }
      final datagram = _socket.receive();
      if (datagram != null) {
        received.add(utf8.decode(datagram.data, allowMalformed: true));
      }
    });
  }

  static Future<Pbx> open() async =>
      Pbx._(await RawDatagramSocket.bind(InternetAddress.loopbackIPv4, 0));

  final RawDatagramSocket _socket;
  final List<String> received = [];

  String get address => '127.0.0.1:${_socket.port}';

  void notify(String stack, String callId) {
    const body = 'Messages-Waiting: yes\r\nVoice-Message: 2/5 (0/0)\r\n';
    final message =
        'NOTIFY sip:alice@$stack SIP/2.0\r\n'
        'Via: SIP/2.0/UDP $address;branch=z9hG4bK-$callId\r\n'
        'Max-Forwards: 70\r\n'
        'From: <sip:alice@example.invalid>;tag=pbx\r\n'
        'To: <sip:alice@example.invalid>\r\n'
        'Call-ID: $callId\r\n'
        'CSeq: 1 NOTIFY\r\n'
        'Event: message-summary\r\n'
        'Subscription-State: active\r\n'
        'Content-Type: application/simple-message-summary\r\n'
        'Content-Length: ${utf8.encode(body).length}\r\n'
        '\r\n'
        '$body';
    final colon = stack.lastIndexOf(':');
    _socket.send(
      utf8.encode(message),
      InternetAddress(stack.substring(0, colon)),
      int.parse(stack.substring(colon + 1)),
    );
  }

  Future<String?> answer(Duration within) async {
    final deadline = DateTime.now().add(within);
    while (DateTime.now().isBefore(deadline)) {
      for (final message in received) {
        if (message.startsWith('SIP/2.0 ')) {
          return message;
        }
      }
      await Future<void>.delayed(const Duration(milliseconds: 50));
    }
    return null;
  }

  void close() => _socket.close();
}

void main() {
  late Pbx pbx;
  late SipralStack stack;
  late List<SipralStackEvent> waiting;
  late StreamSubscription<SipralStackEvent> listening;

  setUp(() async {
    pbx = await Pbx.open();
    stack = await SipralStack.open(bindHost: '127.0.0.1');
    waiting = [];
    listening = stack.events
        .where((event) => event.kind == SipralEventKind.messagesWaiting)
        .listen(waiting.add);
  });

  tearDown(() async {
    await listening.cancel();
    await stack.close();
    pbx.close();
  });

  test('an account with unsolicitedMwi answers an unasked message-summary '
      'NOTIFY 200 and reports the mailbox', () async {
    final account = stack.addAccount(
      'sip:alice@example.invalid',
      registrarAddress: pbx.address,
      unsolicitedMwi: true,
    );
    final told = stack.events.firstWhere(
      (event) => event.kind == SipralEventKind.messagesWaiting,
    );
    pbx.notify(stack.bindAddress, 'unasked-1');
    final event = await told.timeout(const Duration(seconds: 10));
    expect(
      (await pbx.answer(const Duration(seconds: 10)))?.split('\r\n').first,
      startsWith('SIP/2.0 200'),
    );
    expect(event.account, account.handle);
    final summary = event.messageSummary;
    expect(summary, isNotNull);
    expect(summary!.subscription, isNull);
    expect(summary.waiting, isTrue);
    expect(summary.newMessages, 2);
    expect(summary.oldMessages, 5);
  });

  test('an account without it answers 481 and reports nothing', () async {
    stack.addAccount(
      'sip:alice@example.invalid',
      registrarAddress: pbx.address,
    );
    pbx.notify(stack.bindAddress, 'unasked-2');
    expect(
      (await pbx.answer(const Duration(seconds: 10)))?.split('\r\n').first,
      startsWith('SIP/2.0 481'),
    );
    // the answer is written in the same pass that would have raised it
    await Future<void>.delayed(const Duration(milliseconds: 200));
    expect(waiting, isEmpty);
  });
}
