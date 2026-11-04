import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:post_quantum_crypto/post_quantum_crypto.dart';
import 'package:test/test.dart';

import '../support/test_engine.dart';

/// Rewrites one frame on its way to the peer: returns the chunks to forward
/// instead (none to drop it, several to inject or split).
typedef FrameHook = List<List<int>> Function(int index, Uint8List frame);

/// An in-memory connection whose two directions pass through hooks, so a
/// test can act as a man-in-the-middle. Every `add` on a channel's output is
/// exactly one frame (`u32 length || type || ...`), so [FrameHook] indices
/// are frame numbers. Without client authentication:
///
/// - client → server: 0 ClientHello, 1 KeyExchange, 2 Finished, 3+ records;
/// - server → client: 0 ServerHello, 1 Finished, 2+ records.
///
/// With it, the client's ClientAuth record is frame 2 and Finished frame 3.
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
const options = PQSecureChannelOptions(protocol: 'test/v1');

late SigningKeyPair identity;
late SigningKeyPair clientKey;

Future<PQSecureChannel> startServer(
  Wire w, {
  PQSecureChannelOptions options = options,
  ClientAuthorizer? authorizeClient,
  PostQuantumCryptoEngine? serverEngine,
}) => PQSecureChannel.accept(
  w.toServer.stream,
  w.serverOut,
  identity: identity,
  serverId: serverId,
  authorizeClient: authorizeClient,
  engine: serverEngine ?? engine,
  options: options,
);

Future<PQSecureChannel> startClient(
  Wire w, {
  SigningPublicKey? pinned,
  String expectedServerId = serverId,
  SigningKeyPair? clientIdentity,
  PQSecureChannelOptions options = options,
}) => PQSecureChannel.connect(
  w.toClient.stream,
  w.clientOut,
  serverKey: pinned ?? identity.publicKey,
  serverId: expectedServerId,
  clientId: clientId,
  clientIdentity: clientIdentity,
  engine: engine,
  options: options,
);

/// Runs a successful handshake over [w].
Future<(PQSecureChannel, PQSecureChannel)> connect(
  Wire w, {
  PQSecureChannelOptions clientOptions = options,
  PQSecureChannelOptions serverOptions = options,
  ClientAuthorizer? authorizeClient,
  SigningKeyPair? clientIdentity,
}) async {
  final server = startServer(
    w,
    options: serverOptions,
    authorizeClient: authorizeClient,
  );
  final client = startClient(
    w,
    options: clientOptions,
    clientIdentity: clientIdentity,
  );
  return (await client, await server);
}

/// An error on an established channel: one of its secure streams failed.
Matcher channelError([String? message]) => throwsA(
  isA<PQSecureStreamException>().having(
    (e) => e.message,
    'message',
    message == null ? anything : contains(message),
  ),
);

/// A handshake error, always the more specific [PQSecureChannelException].
Matcher handshakeError([String? message]) => throwsA(
  isA<PQSecureChannelException>().having(
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
  SigningKeyPair? clientIdentity,
  ClientAuthorizer? authorizeClient,
  PQSecureChannelOptions clientOptions = options,
  PQSecureChannelOptions serverOptions = options,
  PostQuantumCryptoEngine? serverEngine,
  String? client,
  String? server,
}) async {
  final s = startServer(
    w,
    options: serverOptions,
    authorizeClient: authorizeClient,
    serverEngine: serverEngine,
  );
  final c = startClient(
    w,
    pinned: pinned,
    expectedServerId: expectedServerId,
    clientIdentity: clientIdentity,
    options: clientOptions,
  );
  await Future.wait([
    expectLater(c, handshakeError(client)),
    expectLater(s, handshakeError(server)),
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

/// Returns a copy of [f] with byte [index] set to [value].
List<List<int>> setAt(Uint8List f, int index, int value) => [
  Uint8List.fromList(f)..[index] = value,
];

// Offsets in a frame: u32 length, then the type byte.
const typeAt = 4;
const bodyStart = 5;

// ServerHello: type || flags || serverNonce(32) || u16 length || key ...
const serverFlagsAt = bodyStart;
const ephemeralStart = bodyStart + 1 + 32 + 2;

const recordData = 0x17;
const recordDataMore = 0x18;
const recordClose = 0x15;

void main() {
  setUpAll(() {
    identity = engine.generateSigningKeyPair();
    clientKey = engine.generateSigningKeyPair();
  });

  group('handshake', () {
    test('both sides agree and learn the peer', () async {
      final (client, server) = await connect(Wire());
      expect(client.peerId, serverId);
      expect(client.peerKey, identity.publicKey);
      expect(server.peerId, clientId);
      expect(server.peerKey, isNull); // the client did not authenticate
      expect(client.protocol, 'test/v1');
      expect(client.aead, AeadAlgorithm.aes256Gcm);
      await client.close();
      await server.close();
    });

    test('the default engine and options work', () async {
      final w = Wire();
      final s = PQSecureChannel.accept(
        w.toServer.stream,
        w.serverOut,
        identity: identity,
        serverId: serverId,
      );
      final c = PQSecureChannel.connect(
        w.toClient.stream,
        w.clientOut,
        serverKey: identity.publicKey,
        serverId: serverId,
      );
      final (client, server) = (await c, await s);
      expect(server.peerId, '');
      client.send([1, 2, 3]);
      expect(await server.receive(), [1, 2, 3]);
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

    test('ChaCha20-Poly1305 is negotiated by the client', () async {
      const chacha = PQSecureChannelOptions(
        protocol: 'test/v1',
        aead: AeadAlgorithm.chacha20Poly1305,
      );
      final (client, server) = await connect(Wire(), clientOptions: chacha);
      expect(client.aead, AeadAlgorithm.chacha20Poly1305);
      expect(server.aead, AeadAlgorithm.chacha20Poly1305);
      client.send(utf8.encode('chacha'));
      expect(utf8.decode((await server.receive())!), 'chacha');
      await client.close();
      await server.close();
    });

    test('an AEAD the server policy forbids is refused', () async {
      await expectHandshakeFails(
        Wire(),
        clientOptions: const PQSecureChannelOptions(
          protocol: 'test/v1',
          aead: AeadAlgorithm.chacha20Poly1305,
        ),
        serverEngine: engine.withPolicy(
          SecurityPolicy.standard.copyWith(
            allowedAeads: {AeadAlgorithm.aes256Gcm},
          ),
        ),
        server: 'Handshake failed',
        client: 'closed by peer',
      );
    });

    test('a different application protocol is refused', () async {
      await expectHandshakeFails(
        Wire(),
        clientOptions: const PQSecureChannelOptions(protocol: 'test/v2'),
        server: 'Application protocol mismatch',
        client: 'closed by peer',
      );
    });

    test('an unpinned server identity is refused', () async {
      await expectHandshakeFails(
        Wire(),
        pinned: engine.generateSigningKeyPair().publicKey,
        client: 'Server identity could not be verified',
        server: 'closed by peer',
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
        Wire(fromClient: (i, f) => i == 0 ? flipAt(f, bodyStart + 5) : [f]),
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
        client: 'closed by peer',
      );
    });

    test('an unknown AEAD id is refused', () async {
      await expectHandshakeFails(
        Wire(
          fromClient: (i, f) => i == 0 ? setAt(f, bodyStart + 2, 0x7f) : [f],
        ),
        server: 'Handshake failed',
      );
    });

    test('unknown ServerHello flags are refused', () async {
      await expectHandshakeFails(
        Wire(fromServer: (i, f) => i == 0 ? flipAt(f, serverFlagsAt, 7) : [f]),
        client: 'Malformed handshake message',
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
                  frame([recordData, 1, 2, 3]),
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
        startClient(
          w,
          options: const PQSecureChannelOptions(
            protocol: 'test/v1',
            handshakeTimeout: Duration(milliseconds: 200),
          ),
        ),
        handshakeError('timed out'),
      );
    });
  });

  group('client authentication', () {
    test('an authorized client is identified on the server', () async {
      final seen = <(SigningPublicKey, String)>[];
      final (client, server) = await connect(
        Wire(),
        clientIdentity: clientKey,
        authorizeClient: (key, id) {
          seen.add((key, id));
          return key == clientKey.publicKey;
        },
      );
      expect(seen, [(clientKey.publicKey, clientId)]);
      expect(server.peerKey, clientKey.publicKey);
      client.send([7]);
      expect(await server.receive(), [7]);
      await client.close();
      await server.close();
    });

    test('an asynchronous authorizer is awaited', () async {
      final (client, server) = await connect(
        Wire(),
        clientIdentity: clientKey,
        authorizeClient: (key, id) async {
          await Future<void>.delayed(const Duration(milliseconds: 10));
          return true;
        },
      );
      expect(server.peerKey, clientKey.publicKey);
      await client.close();
      await server.close();
    });

    test('the client key is not sent when not requested', () async {
      final w = Wire();
      final (client, server) = await connect(w, clientIdentity: clientKey);
      expect(server.peerKey, isNull);
      // ClientHello, KeyExchange, Finished: no ClientAuth record.
      expect(w.clientFrames, hasLength(3));
      await client.close();
      await server.close();
    });

    test('a client without an identity is refused', () async {
      await expectHandshakeFails(
        Wire(),
        authorizeClient: (_, _) => true,
        client: 'Server requires client authentication',
        server: 'closed by peer',
      );
    });

    test('an unauthorized key is refused', () async {
      await expectHandshakeFails(
        Wire(),
        clientIdentity: engine.generateSigningKeyPair(),
        authorizeClient: (key, _) => key == clientKey.publicKey,
        server: 'Client is not authorized',
      );
    });

    test('a throwing authorizer refuses the client', () async {
      await expectHandshakeFails(
        Wire(),
        clientIdentity: clientKey,
        authorizeClient: (_, _) => throw StateError('database down'),
        server: 'Client is not authorized',
      );
    });

    test('a stripped client-auth flag fails the server signature', () async {
      await expectHandshakeFails(
        Wire(fromServer: (i, f) => i == 0 ? flipAt(f, serverFlagsAt) : [f]),
        clientIdentity: clientKey,
        authorizeClient: (_, _) => true,
        client: 'Server identity could not be verified',
      );
    });

    test('a dropped ClientAuth record is refused', () async {
      await expectHandshakeFails(
        Wire(fromClient: (i, f) => i == 2 ? [] : [f]),
        clientIdentity: clientKey,
        authorizeClient: (_, _) => true,
        // Finished arrives under the record number ClientAuth had.
        server: 'Record failed authentication',
      );
    });
  });

  group('records', () {
    test('messages of every size round-trip in both directions', () async {
      final (client, server) = await connect(Wire());
      final sizes = [
        0,
        1,
        PQSecureStream.maxRecordPayload - 1,
        PQSecureStream.maxRecordPayload,
        PQSecureStream.maxRecordPayload + 1,
        3 * PQSecureStream.maxRecordPayload,
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

    test('messages streams until the peer closes', () async {
      final (client, server) = await connect(Wire());
      for (final m in ['a', 'b', 'c']) {
        client.send(utf8.encode(m));
      }
      await client.close();
      expect(await server.messages.map(utf8.decode).toList(), ['a', 'b', 'c']);
      await server.close();
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
      final full = Uint8List(PQSecureStream.maxRecordPayload);
      client.send(full);
      expect(await server.receive(), full);
      await client.close();
      expect(await server.receive(), isNull);
    });

    /// Sends 'first' and 'second' (records 3 and 4) through [w] and expects
    /// 'first' to arrive and the next receive to fail with [message].
    Future<void> expectSecondFails(Wire w, String message) async {
      final (client, server) = await connect(w);
      client
        ..send(utf8.encode('first'))
        ..send(utf8.encode('second'));
      expect(utf8.decode((await server.receive())!), 'first');
      await expectLater(server.receive(), channelError(message));
      // A failed channel stays failed.
      expect(server.receive, throwsStateError);
      expect(() => server.send([1]), throwsStateError);
      expect(server.canSend, isFalse);
      await client.close();
    }

    test('a modified record is rejected', () async {
      await expectSecondFails(
        Wire(fromClient: (i, f) => i == 4 ? flipAt(f, f.length - 1) : [f]),
        'Record failed authentication',
      );
    });

    test('a record retyped from "last" to "more follows" is rejected', () {
      // Both are valid types: only the AAD tells them apart.
      return expectSecondFails(
        Wire(
          fromClient: (i, f) {
            if (i == 4) {
              expect(f[typeAt], recordData);
              return setAt(f, typeAt, recordDataMore);
            }
            return [f];
          },
        ),
        'Record failed authentication',
      );
    });

    test('a record with an unknown type is rejected', () async {
      await expectSecondFails(
        Wire(fromClient: (i, f) => i == 4 ? setAt(f, typeAt, 0x07) : [f]),
        'Record failed authentication',
      );
    });

    test('a replayed record is rejected', () async {
      await expectSecondFails(
        Wire(fromClient: (i, f) => i == 3 ? [f, f] : [f]),
        'Record failed authentication',
      );
    });

    test('a record shorter than a tag is rejected', () async {
      await expectSecondFails(
        Wire(
          fromClient: (i, f) => i == 4
              ? [
                  frame([recordData, 1, 2]),
                ]
              : [f],
        ),
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

    test('a record reflected back to its sender is rejected', () async {
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
          fromServer: (i, f) => f[typeAt] == recordClose ? [] : [f],
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
      ('oversized', PQSecureStream.maxFrameLength + 1),
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
      final (client, server) = await connect(
        Wire(),
        serverOptions: const PQSecureChannelOptions(
          protocol: 'test/v1',
          maxMessageLength: 40000,
        ),
      );
      client.send(Uint8List(40000));
      expect(await server.receive(), hasLength(40000));
      client.send(Uint8List(40001));
      await expectLater(server.receive(), channelError('Message too long'));
      await client.close();
    });

    test('a peer stalling past receiveTimeout fails the channel', () async {
      final (client, server) = await connect(
        Wire(
          // The first record stops after its length prefix.
          fromClient: (i, f) => i == 3 ? [f.sublist(0, 4)] : [f],
        ),
        serverOptions: const PQSecureChannelOptions(
          protocol: 'test/v1',
          receiveTimeout: Duration(milliseconds: 200),
        ),
      );
      client.send([1]);
      await expectLater(server.receive(), channelError('Receive timed out'));
      expect(server.receive, throwsStateError);
      await client.close();
    });

    test('close is idempotent and ends sending', () async {
      final (client, server) = await connect(Wire());
      expect(client.canSend, isTrue);
      await client.close();
      await client.close();
      expect(client.canSend, isFalse);
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
      await client.abort();
      expect(() => client.send([1]), throwsStateError);
      await expectLater(server.receive(), channelError('truncated'));
    });

    test('abort during a receive reports a local abort', () async {
      final (client, server) = await connect(Wire());
      final pending = server.receive();
      await server.abort();
      await expectLater(pending, channelError('cancelled locally'));
      expect(server.receive, throwsStateError);
      await expectLater(client.receive(), channelError('truncated'));
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
}
