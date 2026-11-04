@Tags(['platform'])
@TestOn('vm')
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:post_quantum_crypto/post_quantum_crypto_io.dart';
import 'package:test/test.dart';

import '../support/test_engine.dart';

const serverId = 'echo.test';
const options = SecureChannelOptions(protocol: 'test/echo/v1');

void main() {
  late SigningKeyPair identity;
  late SigningKeyPair alice;

  setUpAll(() {
    identity = engine.generateSigningKeyPair();
    alice = engine.generateSigningKeyPair();
  });

  /// Binds an echo server (messages come back reversed) and closes it after
  /// the test. Handshake errors are collected in [errors].
  Future<PQSecureServer> echoServer({
    ClientAuthorizer? authorizeClient,
    List<SecureChannelException>? errors,
    int maxPendingHandshakes = 64,
  }) async {
    final server = await PQSecureServer.bind(
      InternetAddress.loopbackIPv4,
      0,
      identity: identity,
      serverId: serverId,
      authorizeClient: authorizeClient,
      engine: engine,
      options: options,
      onHandshakeError: errors?.add,
      maxPendingHandshakes: maxPendingHandshakes,
    );
    addTearDown(server.close);
    server.channels.listen((channel) async {
      try {
        await for (final m in channel.messages) {
          channel.send(m.reversed.toList());
        }
        await channel.close();
      } on SecureStreamException {
        await channel.abort();
      }
    });
    return server;
  }

  Future<SecureChannel> connect(
    PQSecureServer server, {
    SigningKeyPair? clientIdentity,
    SigningPublicKey? serverKey,
  }) => PQSecureSocket.connect(
    server.address,
    server.port,
    serverKey: serverKey ?? identity.publicKey,
    serverId: serverId,
    clientId: 'alice',
    clientIdentity: clientIdentity,
    engine: engine,
    options: options,
  );

  test('a client and server exchange messages over TCP', () async {
    final server = await echoServer();
    final channel = await connect(server);
    expect(channel.peerKey, identity.publicKey);
    final big = Uint8List.fromList(List.generate(200000, (i) => i % 251));
    for (final m in [utf8.encode('hello'), big]) {
      channel.send(m);
      expect(await channel.receive(), m.reversed.toList());
    }
    await channel.close();
    expect(await channel.receive(), isNull);
  });

  test('several clients are served at once', () async {
    final server = await echoServer();
    final channels = await Future.wait([
      for (var i = 0; i < 4; i++) connect(server),
    ]);
    for (final (i, c) in channels.indexed) {
      c.send([i, 1, 2]);
    }
    for (final (i, c) in channels.indexed) {
      expect(await c.receive(), [2, 1, i]);
      await c.close();
    }
  });

  test('client authentication with an authorizer', () async {
    final seen = <String>[];
    final errors = <SecureChannelException>[];
    final server = await echoServer(
      errors: errors,
      authorizeClient: (key, id) {
        seen.add(id);
        return key == alice.publicKey;
      },
    );
    final channel = await connect(server, clientIdentity: alice);
    channel.send([1]);
    expect(await channel.receive(), [1]);
    await channel.close();

    await expectLater(
      connect(server, clientIdentity: engine.generateSigningKeyPair()),
      throwsA(isA<SecureChannelException>()),
    );
    await expectLater(
      connect(server),
      throwsA(
        isA<SecureChannelException>().having(
          (e) => e.message,
          'message',
          contains('requires client authentication'),
        ),
      ),
    );
    expect(seen, ['alice', 'alice']);
    // The server reported both refusals.
    await Future<void>.delayed(const Duration(milliseconds: 100));
    expect(errors.map((e) => e.message), [
      contains('Client is not authorized'),
      contains('closed by peer'),
    ]);
  });

  test('a client refuses a server it has not pinned', () async {
    final server = await echoServer();
    await expectLater(
      connect(server, serverKey: engine.generateSigningKeyPair().publicKey),
      throwsA(
        isA<SecureChannelException>().having(
          (e) => e.message,
          'message',
          contains('Server identity could not be verified'),
        ),
      ),
    );
  });

  test('connections over maxPendingHandshakes are dropped', () async {
    final errors = <SecureChannelException>[];
    final server = await echoServer(errors: errors, maxPendingHandshakes: 1);
    // A raw socket that never sends a ClientHello holds the only slot.
    final idle = await Socket.connect(server.address, server.port);
    addTearDown(idle.destroy);
    await Future<void>.delayed(const Duration(milliseconds: 100));
    await expectLater(connect(server), throwsA(isA<SecureChannelException>()));
    idle.destroy();
    await Future<void>.delayed(const Duration(milliseconds: 100));
    // With the slot free again, a client gets through.
    final channel = await connect(server);
    await channel.close();
  });

  test('maxPendingHandshakes must be positive', () async {
    await expectLater(
      PQSecureServer.bind(
        InternetAddress.loopbackIPv4,
        0,
        identity: identity,
        serverId: serverId,
        maxPendingHandshakes: 0,
      ),
      throwsA(isA<InvalidInputException>()),
    );
  });

  test('closing the server stops accepting', () async {
    final server = await echoServer();
    final port = server.port;
    await server.close();
    await expectLater(
      PQSecureSocket.connect(
        InternetAddress.loopbackIPv4,
        port,
        serverKey: identity.publicKey,
        serverId: serverId,
        options: options,
      ),
      throwsA(isA<SocketException>()),
    );
  });

  group('SecureStream over files', () {
    late Directory dir;
    setUp(() async {
      dir = await Directory.systemTemp.createTemp('pqc_secure_stream');
      addTearDown(() => dir.delete(recursive: true));
    });

    test('a file written to a recipient reads back', () async {
      final recipient = engine.generateEncryptionKeyPair();
      final file = File('${dir.path}/log.pqs');
      final writer = SecureStream.encryptTo(
        file.openWrite(),
        recipient: recipient.publicKey,
        engine: engine,
      );
      for (var i = 0; i < 100; i++) {
        writer.add(utf8.encode('entry $i'));
      }
      writer.add(Uint8List(50000));
      await writer.close();

      final reader = await SecureStream.decryptFrom(
        file.openRead(),
        privateKey: recipient.privateKey,
        engine: engine,
      );
      final messages = await reader.messages.toList();
      expect(messages, hasLength(101));
      expect(utf8.decode(messages[42]), 'entry 42');
      expect(messages.last, Uint8List(50000));
    });

    test('a file cut short is reported as truncated', () async {
      final recipient = engine.generateEncryptionKeyPair();
      final file = File('${dir.path}/cut.pqs');
      final writer = SecureStream.encryptTo(
        file.openWrite(),
        recipient: recipient.publicKey,
        engine: engine,
      )..add(utf8.encode('kept'));
      await writer.close();
      final bytes = await file.readAsBytes();
      // Remove the End record (u32 length + type + 16-byte tag).
      await file.writeAsBytes(bytes.sublist(0, bytes.length - 21));

      final reader = await SecureStream.decryptFrom(
        file.openRead(),
        privateKey: recipient.privateKey,
        engine: engine,
      );
      expect(utf8.decode((await reader.read())!), 'kept');
      await expectLater(
        reader.read(),
        throwsA(
          isA<SecureStreamException>().having(
            (e) => e.message,
            'message',
            contains('truncated'),
          ),
        ),
      );
    });
  });
}
