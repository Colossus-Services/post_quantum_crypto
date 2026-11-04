// Post-quantum secure streams: protected messages over any byte stream.
//
// A secure stream works over anything that moves bytes: here a file and an
// in-memory pipe; `example/secure_socket.dart` runs two of them (one per
// direction) over TCP.
//
// Run with: dart run example/secure_stream.dart
import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:post_quantum_crypto/post_quantum_crypto_io.dart';

Future<void> main() async {
  final engine = PostQuantumCryptoEngine();
  final dir = await Directory.systemTemp.createTemp('secure_stream_example');

  try {
    // --- A file to a recipient's key (no round trip) --------------------------
    // Records are written as they are added, so an append-style log needs no
    // buffering; only the recipient's private key can read it back.
    final auditor = engine.generateEncryptionKeyPair();
    final file = File('${dir.path}/audit.log.pqs');
    const options = SecureStreamOptions(protocol: 'example/audit-log/v1');

    final log = SecureStream.encryptTo(
      file.openWrite(),
      recipient: auditor.publicKey,
      engine: engine,
      options: options,
    );
    for (final event in ['login alice', 'export report', 'logout alice']) {
      log.add(utf8.encode('${DateTime.now().toUtc()} $event'));
    }
    await log.close(); // writes the authenticated End record
    print('wrote ${await file.length()} bytes to ${file.path}');

    final reader = await SecureStream.decryptFrom(
      file.openRead(),
      privateKey: auditor.privateKey,
      engine: engine,
      options: options,
    );
    await for (final entry in reader.messages) {
      print('  ${utf8.decode(entry)}');
    }

    // A file cut short (here: its last 21 bytes, the End record) is reported
    // instead of silently read as complete.
    final bytes = await file.readAsBytes();
    await file.writeAsBytes(bytes.sublist(0, bytes.length - 21));
    try {
      final cut = await SecureStream.decryptFrom(
        file.openRead(),
        privateKey: auditor.privateKey,
        engine: engine,
        options: options,
      );
      await cut.messages.drain<void>();
    } on SecureStreamException catch (e) {
      print('truncated file refused: ${e.message}');
    }

    // --- A live pipe with a shared key ---------------------------------------
    // Both ends already share a key (here from X-Wing key establishment).
    // Each stream draws a random salt, so the key can protect many streams.
    final bob = engine.generateEncryptionKeyPair(algorithm: KemAlgorithm.xWing);
    const t = HybridTranscript(
      protocol: 'example/pipe/v1',
      initiatorId: 'alice',
      responderId: 'bob',
    );
    final init = engine.establishHybridKey(bob.publicKey, transcript: t);
    final bobKey = engine.acceptHybridKey(
      init.message,
      privateKey: bob.privateKey,
      transcript: t,
    );

    final pipe = StreamController<List<int>>();
    final sender = SecureStream.encryptWithKey(
      pipe.sink,
      sharedKey: init.sessionKey,
      engine: engine,
    );
    final receiver = SecureStream.decryptWithKey(
      pipe.stream,
      sharedKey: bobKey,
      engine: engine,
    );
    sender.add(utf8.encode('tick 1'));
    final r = await receiver;
    print('pipe: ${utf8.decode((await r.read())!)}'); // delivered at once
    sender.add(utf8.encode('tick 2'));
    print('pipe: ${utf8.decode((await r.read())!)}');
    final closing = sender.close();
    print('pipe ended cleanly: ${await r.read() == null}');
    await closing;
  } finally {
    await dir.delete(recursive: true);
  }
}
