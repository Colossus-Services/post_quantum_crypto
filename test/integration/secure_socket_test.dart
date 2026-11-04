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
const options = PQSecureChannelOptions(protocol: 'test/echo/v1');

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
    List<PQSecureChannelException>? errors,
    void Function(PQSecureChannelException)? onHandshakeError,
    int maxPendingHandshakes = 64,
    int maxIdleConnections = 1024,
    PQSecureChannelOptions serverOptions = options,
  }) async {
    final server = await PQSecureServer.bind(
      InternetAddress.loopbackIPv4,
      0,
      identity: identity,
      serverId: serverId,
      authorizeClient: authorizeClient,
      engine: engine,
      options: serverOptions,
      onHandshakeError: onHandshakeError ?? errors?.add,
      maxPendingHandshakes: maxPendingHandshakes,
      maxIdleConnections: maxIdleConnections,
    );
    addTearDown(server.close);
    server.channels.listen((channel) async {
      try {
        await for (final m in channel.messages) {
          channel.send(m.reversed.toList());
        }
        await channel.close();
      } on PQSecureStreamException {
        await channel.abort();
      }
    });
    return server;
  }

  Future<PQSecureChannel> connect(
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
    final errors = <PQSecureChannelException>[];
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
      throwsA(isA<PQSecureChannelException>()),
    );
    await expectLater(
      connect(server),
      throwsA(
        isA<PQSecureChannelException>().having(
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
        isA<PQSecureChannelException>().having(
          (e) => e.message,
          'message',
          contains('Server identity could not be verified'),
        ),
      ),
    );
  });

  test('idle connections do not take handshake slots', () async {
    final server = await echoServer(maxPendingHandshakes: 1);
    // Sockets that never send a ClientHello...
    final idle = [
      for (var i = 0; i < 3; i++)
        await Socket.connect(server.address, server.port),
    ];
    addTearDown(() {
      for (final s in idle) {
        s.destroy();
      }
    });
    await Future<void>.delayed(const Duration(milliseconds: 100));
    // ...leave the only handshake slot to a real client.
    final channel = await connect(server);
    channel.send([1]);
    expect(await channel.receive(), [1]);
    await channel.close();
  });

  test('handshakes over maxPendingHandshakes are refused as busy', () async {
    final errors = <PQSecureChannelException>[];
    final release = Completer<void>();
    final server = await echoServer(
      errors: errors,
      maxPendingHandshakes: 1,
      // The first client's authorization blocks, holding the only slot.
      authorizeClient: (_, _) async {
        await release.future;
        return true;
      },
    );
    final first = connect(server, clientIdentity: alice);
    await Future<void>.delayed(const Duration(milliseconds: 300));
    await expectLater(
      connect(server, clientIdentity: alice),
      throwsA(isA<PQSecureChannelException>()),
    );
    release.complete();
    await (await first).close();
    expect(errors.map((e) => e.message), contains('Server busy'));
  });

  test('connections over maxIdleConnections are closed at once', () async {
    final server = await echoServer(maxIdleConnections: 1);
    final idle = await Socket.connect(server.address, server.port);
    addTearDown(idle.destroy);
    await Future<void>.delayed(const Duration(milliseconds: 100));
    // The idle slot is taken, so this connection is dropped before any
    // handshake.
    await expectLater(
      connect(server),
      throwsA(isA<PQSecureChannelException>()),
    );
  });

  test('a connection that sends no ClientHello is dropped', () async {
    final errors = <PQSecureChannelException>[];
    final server = await echoServer(
      errors: errors,
      maxIdleConnections: 1,
      serverOptions: const PQSecureChannelOptions(
        protocol: 'test/echo/v1',
        stepTimeout: Duration(milliseconds: 200),
      ),
    );
    final idle = await Socket.connect(server.address, server.port);
    addTearDown(idle.destroy);
    // The server hangs up on the silent socket...
    await idle.drain<void>().timeout(const Duration(seconds: 5));
    expect(errors.single.message, contains('ClientHello timed out'));
    // ...which frees its idle slot for a real client.
    final channel = await connect(server);
    await channel.close();
  });

  test('a throwing onHandshakeError does not stop the server', () async {
    var calls = 0;
    final server = await echoServer(
      onHandshakeError: (_) {
        calls++;
        throw StateError('log sink closed');
      },
    );
    await expectLater(
      connect(server, serverKey: engine.generateSigningKeyPair().publicKey),
      throwsA(isA<PQSecureChannelException>()),
    );
    await Future<void>.delayed(const Duration(milliseconds: 100));
    expect(calls, 1);
    final channel = await connect(server);
    channel.send([2]);
    expect(await channel.receive(), [2]);
    await channel.close();
  });

  test('close completes when nobody listens to channels', () async {
    // Also binds with the default engine.
    final server = await PQSecureServer.bind(
      InternetAddress.loopbackIPv4,
      0,
      identity: identity,
      serverId: serverId,
    );
    await server.close().timeout(const Duration(seconds: 5));
  });

  test('a handshake completing after close is not delivered', () async {
    final entered = Completer<void>();
    final release = Completer<void>();
    final server = await PQSecureServer.bind(
      InternetAddress.loopbackIPv4,
      0,
      identity: identity,
      serverId: serverId,
      engine: engine,
      options: options,
      authorizeClient: (_, _) async {
        entered.complete();
        await release.future;
        return true;
      },
    );
    final delivered = <PQSecureChannel>[];
    server.channels.listen(delivered.add);
    final client = PQSecureSocket.connect(
      server.address,
      server.port,
      serverKey: identity.publicKey,
      serverId: serverId,
      clientIdentity: alice,
      engine: engine,
      options: options,
    );
    await entered.future;
    await server.close();
    release.complete();
    // The server drops the late channel instead of delivering it.
    final channel = await client;
    await expectLater(
      channel.receive(),
      throwsA(isA<PQSecureStreamException>()),
    );
    expect(delivered, isEmpty);
  });

  test('close completes while a channel is being handled', () async {
    final server = await PQSecureServer.bind(
      InternetAddress.loopbackIPv4,
      0,
      identity: identity,
      serverId: serverId,
      engine: engine,
      options: options,
    );
    final handling = Completer<void>();
    final done = Completer<void>();
    // `await for` pauses the subscription while a channel is handled.
    unawaited(() async {
      await for (final channel in server.channels) {
        handling.complete();
        await done.future;
        await channel.abort();
      }
    }());
    final client = await connect(server);
    await handling.future;
    await server.close().timeout(const Duration(seconds: 5));
    done.complete();
    await client.abort();
  });

  test('the connection limits must be positive', () async {
    for (final (pending, idle) in [(0, 1), (1, 0)]) {
      await expectLater(
        PQSecureServer.bind(
          InternetAddress.loopbackIPv4,
          0,
          identity: identity,
          serverId: serverId,
          maxPendingHandshakes: pending,
          maxIdleConnections: idle,
        ),
        throwsA(isA<InvalidInputException>()),
      );
    }
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

  group('PQSecureStream over files', () {
    late Directory dir;
    setUp(() async {
      dir = await Directory.systemTemp.createTemp('pqc_secure_stream');
      addTearDown(() => dir.delete(recursive: true));
    });

    test('a file written to a recipient reads back', () async {
      final recipient = engine.generateEncryptionKeyPair();
      final file = File('${dir.path}/log.pqs');
      final writer = PQSecureStream.encryptTo(
        file.openWrite(),
        recipient: recipient.publicKey,
        engine: engine,
      );
      for (var i = 0; i < 100; i++) {
        writer.add(utf8.encode('entry $i'));
      }
      writer.add(Uint8List(50000));
      await writer.close();

      final reader = await PQSecureStream.decryptFrom(
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
      final writer = PQSecureStream.encryptTo(
        file.openWrite(),
        recipient: recipient.publicKey,
        engine: engine,
      )..add(utf8.encode('kept'));
      await writer.close();
      final bytes = await file.readAsBytes();
      // Remove the End record (u32 length + type + 16-byte tag).
      await file.writeAsBytes(bytes.sublist(0, bytes.length - 21));

      final reader = await PQSecureStream.decryptFrom(
        file.openRead(),
        privateKey: recipient.privateKey,
        engine: engine,
      );
      expect(utf8.decode((await reader.read())!), 'kept');
      await expectLater(
        reader.read(),
        throwsA(
          isA<PQSecureStreamException>().having(
            (e) => e.message,
            'message',
            contains('truncated'),
          ),
        ),
      );
    });
  });
}
