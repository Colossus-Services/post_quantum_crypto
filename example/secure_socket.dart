// A post-quantum secure socket: an echo server and its clients over TCP.
//
// The server proves its identity with ML-DSA-65, each connection agrees on
// fresh session keys with X-Wing (ML-KEM-768 + X25519), and every message
// travels in an AES-256-GCM record. Here the server also requires clients to
// authenticate with their own keys.
//
// Run with: dart run example/secure_socket.dart
import 'dart:convert';
import 'dart:io';

import 'package:post_quantum_crypto/post_quantum_crypto_io.dart';

Future<void> main() async {
  final engine = PostQuantumCryptoEngine();
  const options = PQSecureChannelOptions(
    protocol: 'example/echo/v1',
    // A peer that goes silent mid-conversation is dropped.
    receiveTimeout: Duration(seconds: 30),
  );

  // Long-term identities. Each side receives the other's public key through
  // a trusted channel (shipped with the app, a pinned PEM, an enrollment).
  final serverIdentity = engine.generateSigningKeyPair();
  final alice = engine.generateSigningKeyPair();
  final allowedClients = {alice.publicKey};

  final server = await PQSecureServer.bind(
    InternetAddress.loopbackIPv4,
    0,
    identity: serverIdentity,
    serverId: 'echo.example',
    engine: engine,
    options: options,
    authorizeClient: (key, clientId) => allowedClients.contains(key),
    onHandshakeError: (e) => print('server: handshake refused: ${e.message}'),
  );
  server.channels.listen((channel) async {
    print('server: "${channel.peerId}" connected (${channel.aead.name})');
    try {
      // Echo every message back in upper case until the client closes.
      await for (final m in channel.messages) {
        channel.send(
          utf8.encode(utf8.decode(m, allowMalformed: true).toUpperCase()),
        );
      }
      await channel.close();
    } catch (e) {
      // One misbehaving client must not take the server down.
      print('server: connection dropped: $e');
      await channel.abort();
    }
  });

  // --- An authorized client ----------------------------------------------------
  final channel = await PQSecureSocket.connect(
    server.address,
    server.port,
    serverKey: serverIdentity.publicKey,
    serverId: 'echo.example',
    clientId: 'alice',
    clientIdentity: alice,
    engine: engine,
    options: options,
  );
  channel.send(utf8.encode('hello, post-quantum world'));
  print('alice: ${utf8.decode((await channel.receive())!)}');

  // Messages larger than one record are split and reassembled.
  final big = 'x' * 100000;
  channel.send(utf8.encode(big));
  final echoed = utf8.decode((await channel.receive())!);
  print(
    'alice: echoed ${echoed.length} characters intact: '
    '${echoed == big.toUpperCase()}',
  );
  // Close our direction, then read until the server closes its own: null
  // means the conversation ended intact, with nothing cut off.
  await channel.close();
  print('alice: server closed cleanly: ${await channel.receive() == null}');

  // --- A client that pinned a different server key ---------------------------
  try {
    await PQSecureSocket.connect(
      server.address,
      server.port,
      serverKey: engine.generateSigningKeyPair().publicKey,
      serverId: 'echo.example',
      clientId: 'alice',
      clientIdentity: alice,
      engine: engine,
      options: options,
    );
  } on PQSecureChannelException catch (e) {
    print('alice: refused: ${e.message}');
  }

  // --- A client the server does not know -------------------------------------
  try {
    await PQSecureSocket.connect(
      server.address,
      server.port,
      serverKey: serverIdentity.publicKey,
      serverId: 'echo.example',
      clientId: 'mallory',
      clientIdentity: engine.generateSigningKeyPair(),
      engine: engine,
      options: options,
    );
  } on PQSecureChannelException catch (e) {
    print('mallory: refused: ${e.message}');
  }

  await server.close();
}
