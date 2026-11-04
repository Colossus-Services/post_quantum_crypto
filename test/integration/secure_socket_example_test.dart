@Tags(['platform'])
@TestOn('vm')
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:post_quantum_crypto/post_quantum_crypto.dart';
import 'package:test/test.dart';

import '../../example/secure_socket.dart';
import '../support/test_engine.dart';

/// Rewrites one frame on its way to the peer: returns the chunks to forward
/// instead (none to drop it, several to inject or split).
typedef FrameHook = List<List<int>> Function(int index, Uint8List frame);

/// An in-memory connection whose two directions pass through hooks, so a
/// test can act as a man-in-the-middle. Every `add` on a channel's output is
/// exactly one frame (`u32 length || type || ...`), so [FrameHook] indices
/// are frame numbers:
///
/// - client → server: 0 ClientHello, 1 KeyExchange, 2 Finished, 3+ records;
/// - server → client: 0 ServerHello, 1 Finished, 2+ records.
final class Wire {
  final toServer = StreamController<List<int>>();
  final toClient = StreamController<List<int>>();
  late final StreamController<List<int>> clientOut;
  late final StreamController<List<int>> serverOut;

  /// Frames each side wrote, before any hook.
  final clientFrames = <Uint8List>[];
  final serverFrames = <Uint8List>[];

  Wire({FrameHook? fromClient, FrameHook? fromServer}) {
    clientOut = _relay(toServer, clientFrames, fromClient);
    serverOut = _relay(toClient, serverFrames, fromServer);
  }

  static StreamController<List<int>> _relay(
    StreamController<List<int>> destination,
    List<Uint8List> log,
    FrameHook? hook,
  ) {
    final source = StreamController<List<int>>();
    var index = 0;
    source.stream.listen((chunk) {
      final frame = Uint8List.fromList(chunk);
      log.add(frame);
      for (final out in hook?.call(index++, frame) ?? [frame]) {
        destination.add(out);
      }
    }, onDone: destination.close);
    return source;
  }
}

const serverId = 'server-1';
const clientId = 'client-7';

late SigningKeyPair identity;

Future<PqSecureChannel> startServer(
  Wire w, {
  Duration timeout = const Duration(seconds: 30),
  int maxMessageLength = PqSecureChannel.defaultMaxMessageLength,
}) => PqSecureChannel.server(
  w.toServer.stream,
  w.serverOut,
  engine: engine,
  identity: identity,
  serverId: serverId,
  timeout: timeout,
  maxMessageLength: maxMessageLength,
);

Future<PqSecureChannel> startClient(
  Wire w, {
  SigningPublicKey? pinned,
  String expectedServerId = serverId,
  Duration timeout = const Duration(seconds: 30),
}) => PqSecureChannel.client(
  w.toClient.stream,
  w.clientOut,
  engine: engine,
  serverIdentity: pinned ?? identity.publicKey,
  serverId: expectedServerId,
  clientId: clientId,
  timeout: timeout,
);

/// Runs a successful handshake over [w].
Future<(PqSecureChannel, PqSecureChannel)> connect(
  Wire w, {
  int maxMessageLength = PqSecureChannel.defaultMaxMessageLength,
}) async {
  final server = startServer(w, maxMessageLength: maxMessageLength);
  final client = startClient(w);
  return (await client, await server);
}

Matcher channelError([String? message]) => throwsA(
  isA<SecureChannelException>().having(
    (e) => e.message,
    'message',
    message == null ? anything : contains(message),
  ),
);

/// Expects both sides of a handshake to fail; [client] / [server] narrow the
/// expected message.
Future<void> expectHandshakeFails(
  Wire w, {
  SigningPublicKey? pinned,
  String expectedServerId = serverId,
  String? client,
  String? server,
}) async {
  final s = startServer(w);
  final c = startClient(w, pinned: pinned, expectedServerId: expectedServerId);
  await Future.wait([
    expectLater(c, channelError(client)),
    expectLater(s, channelError(server)),
  ]);
}

/// Reframes [body] with a fresh length prefix.
Uint8List frame(List<int> body) => Uint8List.fromList([
  ...(Uint8List(4)..buffer.asByteData().setUint32(0, body.length)),
  ...body,
]);

/// Flips [bit] of byte [index] of a frame, counted from the frame start.
List<List<int>> flipAt(Uint8List f, int index, [int bit = 0]) => [
  flip(f, index, bit),
];

/// Offset of the first byte after the type in a frame.
const bodyStart = 5;

void main() {
  setUpAll(() {
    identity = engine.generateSigningKeyPair();
  });

  group('handshake', () {
    test('both sides agree and learn the peer ids', () async {
      final (client, server) = await connect(Wire());
      expect(client.peerId, serverId);
      expect(server.peerId, clientId);
      await client.close();
      await server.close();
    });

    test('every session uses fresh keys', () async {
      final w1 = Wire();
      final w2 = Wire();
      final (c1, s1) = await connect(w1);
      final (c2, s2) = await connect(w2);
      c1.send(utf8.encode('same'));
      c2.send(utf8.encode('same'));
      expect(utf8.decode((await s1.receive())!), 'same');
      expect(utf8.decode((await s2.receive())!), 'same');
      // A new ephemeral X-Wing key per connection (forward secrecy) ...
      expect(w1.serverFrames[0], isNot(w2.serverFrames[0]));
      // ... so the same plaintext in the same position encrypts differently.
      expect(w1.clientFrames[3], isNot(w2.clientFrames[3]));
      for (final c in [c1, s1, c2, s2]) {
        await c.close();
      }
    });

    test('an unpinned server identity is refused', () async {
      await expectHandshakeFails(
        Wire(),
        pinned: engine.generateSigningKeyPair().publicKey,
        client: 'Server identity could not be verified',
        server: 'Connection closed by peer',
      );
    });

    test('a different server id is refused', () async {
      await expectHandshakeFails(
        Wire(),
        expectedServerId: 'server-2',
        client: 'Server identity could not be verified',
      );
    });

    test('a substituted ephemeral key is refused (MITM)', () async {
      // 0x02 || serverNonce(32) || u16 length || ephemeral key ...
      const ephemeralStart = bodyStart + 32 + 2;
      await expectHandshakeFails(
        Wire(
          fromServer: (i, f) => i == 0 ? flipAt(f, ephemeralStart + 100) : [f],
        ),
        client: 'Server identity could not be verified',
      );
    });

    test('a modified ClientHello is detected by the client', () async {
      // The server signs the hello it received, not the one the client sent.
      await expectHandshakeFails(
        Wire(fromClient: (i, f) => i == 0 ? flipAt(f, bodyStart + 1) : [f]),
        client: 'Server identity could not be verified',
      );
    });

    test('a modified signature is refused', () async {
      await expectHandshakeFails(
        Wire(fromServer: (i, f) => i == 0 ? flipAt(f, f.length - 1) : [f]),
        client: 'Server identity could not be verified',
      );
    });

    test('a modified key exchange fails key confirmation', () async {
      await expectHandshakeFails(
        Wire(fromClient: (i, f) => i == 1 ? flipAt(f, f.length - 1) : [f]),
        server: 'Record failed authentication',
      );
    });

    test('an unknown protocol version is refused', () async {
      await expectHandshakeFails(
        Wire(fromClient: (i, f) => i == 0 ? flipAt(f, bodyStart, 1) : [f]),
        server: 'Unsupported protocol version',
        client: 'Connection closed by peer',
      );
    });

    test('trailing bytes in a handshake message are refused', () async {
      await expectHandshakeFails(
        Wire(
          fromServer: (i, f) => i == 0
              ? [
                  frame([...f.sublist(4), 0]),
                ]
              : [f],
        ),
        client: 'Malformed handshake message',
      );
    });

    test('a non-handshake first message is refused', () async {
      await expectHandshakeFails(
        Wire(
          fromClient: (i, f) => i == 0
              ? [
                  frame([0x17, 1, 2, 3]),
                ]
              : [f],
        ),
        server: 'Malformed handshake message',
      );
    });

    test('a silent peer times out', () async {
      final w = Wire();
      w.toServer.stream.listen((_) {}); // nobody answers
      await expectLater(
        startClient(w, timeout: const Duration(milliseconds: 200)),
        channelError('timed out'),
      );
    });
  });

  group('records', () {
    test('messages of every size round-trip in both directions', () async {
      final (client, server) = await connect(Wire());
      final sizes = [
        0,
        1,
        PqSecureChannel.maxRecordPayload - 1,
        PqSecureChannel.maxRecordPayload,
        PqSecureChannel.maxRecordPayload + 1,
        3 * PqSecureChannel.maxRecordPayload,
        100000,
      ];
      for (final n in sizes) {
        final m = Uint8List.fromList(List.generate(n, (i) => i * 7));
        client.send(m);
        expect(await server.receive(), m, reason: 'client → server, $n');
        server.send(m);
        expect(await client.receive(), m, reason: 'server → client, $n');
      }
      await client.close();
      expect(await server.receive(), isNull);
      expect(await server.receive(), isNull);
      await server.close();
      expect(await client.receive(), isNull);
    });

    test('frames split into single bytes are reassembled', () async {
      List<List<int>> bytewise(int _, Uint8List f) => [
        for (final b in f) [b],
      ];
      final (client, server) = await connect(
        Wire(fromClient: bytewise, fromServer: bytewise),
      );
      client.send(utf8.encode('one byte at a time'));
      expect(utf8.decode((await server.receive())!), 'one byte at a time');
      // A full-size record, one byte per chunk: buffering stays linear.
      final full = Uint8List(PqSecureChannel.maxRecordPayload);
      client.send(full);
      expect(await server.receive(), full);
      await client.close();
      expect(await server.receive(), isNull);
    });

    Future<void> expectReceiveFails(Wire w, String message) async {
      final (client, server) = await connect(w);
      client
        ..send(utf8.encode('first'))
        ..send(utf8.encode('second'));
      final results = <Object?>[];
      try {
        results
          ..add(utf8.decode((await server.receive())!))
          ..add(utf8.decode((await server.receive())!));
      } on SecureChannelException catch (e) {
        results.add(e);
      }
      expect(
        results.last,
        isA<SecureChannelException>().having(
          (e) => e.message,
          'message',
          contains(message),
        ),
      );
      // Only the message that arrived intact and in order was released.
      expect(results.whereType<String>(), ['first']);
      // A failed channel stays failed.
      expect(server.receive, throwsStateError);
      expect(() => server.send([1]), throwsStateError);
      await client.close();
    }

    test('a modified record is rejected', () async {
      await expectReceiveFails(
        Wire(fromClient: (i, f) => i == 4 ? flipAt(f, f.length - 1) : [f]),
        'Record failed authentication',
      );
    });

    test('a modified record type is rejected', () async {
      // Turning "last fragment" into "more follows" changes the AAD.
      await expectReceiveFails(
        Wire(fromClient: (i, f) => i == 4 ? flipAt(f, 4, 4) : [f]),
        'Record failed authentication',
      );
    });

    test('a record shorter than a tag is rejected', () async {
      final (client, server) = await connect(
        Wire(
          fromClient: (i, f) => i == 3
              ? [
                  frame([0x17, 1, 2]),
                ]
              : [f],
        ),
      );
      client.send([1]);
      await expectLater(server.receive(), channelError());
      await client.close();
    });

    test('a replayed record is rejected', () async {
      await expectReceiveFails(
        Wire(fromClient: (i, f) => i == 3 ? [f, f] : [f]),
        'Record failed authentication',
      );
    });

    test('a dropped record is detected', () async {
      final (client, server) = await connect(
        Wire(fromClient: (i, f) => i == 4 ? [] : [f]),
      );
      client
        ..send(utf8.encode('first'))
        ..send(utf8.encode('second'))
        ..send(utf8.encode('third'));
      expect(utf8.decode((await server.receive())!), 'first');
      // 'third' arrives under the record number 'second' should have had.
      await expectLater(
        server.receive(),
        channelError('Record failed authentication'),
      );
      await client.close();
    });

    test('reordered records are rejected', () async {
      Uint8List? held;
      final (client, server) = await connect(
        Wire(
          fromClient: (i, f) {
            if (i == 3) {
              held = f;
              return [];
            }
            return i == 4 ? [f, held!] : [f];
          },
        ),
      );
      client
        ..send(utf8.encode('first'))
        ..send(utf8.encode('second'));
      await expectLater(
        server.receive(),
        channelError('Record failed authentication'),
      );
      await client.close();
    });

    test("a record reflected back to its sender is rejected", () async {
      late Wire w;
      w = Wire(
        // Replace the server's first record with the client's first record.
        fromServer: (i, f) => i == 2 ? [w.clientFrames[3]] : [f],
      );
      final (client, server) = await connect(w);
      client.send(utf8.encode('ping'));
      expect(utf8.decode((await server.receive())!), 'ping');
      server.send(utf8.encode('pong'));
      await expectLater(
        client.receive(),
        channelError('Record failed authentication'),
      );
      await server.close();
    });

    test('truncation without a Close record is detected', () async {
      final (client, server) = await connect(
        Wire(
          // Drop the server's Close record; its connection still ends.
          fromServer: (i, f) => f[4] == 0x15 ? [] : [f],
        ),
      );
      server.send(utf8.encode('partial'));
      await server.close();
      expect(utf8.decode((await client.receive())!), 'partial');
      await expectLater(client.receive(), channelError('truncated'));
    });

    test('a connection ending mid-frame is detected', () async {
      final (client, server) = await connect(
        Wire(
          fromClient: (i, f) => switch (i) {
            < 3 => [f],
            3 => [f.sublist(0, 9)],
            _ => [],
          },
        ),
      );
      client.send(utf8.encode('cut short'));
      await client.close();
      await expectLater(server.receive(), channelError('mid-frame'));
    });

    for (final (name, length) in [
      ('oversized', PqSecureChannel.maxFrameLength + 1),
      ('empty', 0),
    ]) {
      test('an $name frame is rejected before it is buffered', () async {
        final header = Uint8List(4)..buffer.asByteData().setUint32(0, length);
        final (client, server) = await connect(
          Wire(fromClient: (i, f) => i == 3 ? [header] : [f]),
        );
        client.send([1]);
        await expectLater(server.receive(), channelError('frame length'));
        await client.close();
      });
    }

    test('messages over the receiver limit are rejected', () async {
      final (client, server) = await connect(Wire(), maxMessageLength: 40000);
      client.send(Uint8List(40000));
      expect(await server.receive(), hasLength(40000));
      client.send(Uint8List(40001));
      await expectLater(server.receive(), channelError('Message too long'));
      await client.close();
    });

    test('close is idempotent and ends sending', () async {
      final (client, server) = await connect(Wire());
      await client.close();
      await client.close();
      expect(() => client.send([1]), throwsStateError);
      expect(await server.receive(), isNull);
      await server.close();
    });

    test('close is a half-close: the closer still receives', () async {
      final (client, server) = await connect(Wire());
      await client.close();
      expect(await server.receive(), isNull);
      server.send(utf8.encode('late reply'));
      await server.close();
      expect(utf8.decode((await client.receive())!), 'late reply');
      expect(await client.receive(), isNull);
    });

    test('abort is seen by the peer as truncation', () async {
      final (client, server) = await connect(Wire());
      await client.abort();
      expect(() => client.send([1]), throwsStateError);
      await expectLater(server.receive(), channelError('truncated'));
    });

    test('concurrent receive calls are refused', () async {
      final (client, server) = await connect(Wire());
      final pending = server.receive();
      expect(server.receive, throwsStateError);
      client.send([42]);
      expect(await pending, [42]);
      await client.close();
      await server.close();
    });
  });

  test('works over a real TCP socket', () async {
    final listener = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    addTearDown(listener.close);
    final served = listener.first.then((socket) async {
      final channel = await PqSecureChannel.server(
        socket,
        socket,
        engine: engine,
        identity: identity,
        serverId: serverId,
      );
      for (Uint8List? m; (m = await channel.receive()) != null;) {
        channel.send(m!.reversed.toList());
      }
      await channel.close();
    });

    final socket = await Socket.connect(listener.address, listener.port);
    final client = await PqSecureChannel.client(
      socket,
      socket,
      engine: engine,
      serverIdentity: identity.publicKey,
      serverId: serverId,
      clientId: clientId,
    );
    final big = Uint8List.fromList(List.generate(200000, (i) => i % 251));
    for (final m in [utf8.encode('hello'), big]) {
      client.send(m);
      expect(await client.receive(), m.reversed.toList());
    }
    await client.close();
    await served;
  });
}
