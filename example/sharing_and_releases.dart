// Sharing encrypted data with a changing group, password-based encryption,
// streaming with progress, and signing software releases.
//
// Run with: dart run example/sharing_and_releases.dart
import 'dart:convert';
import 'dart:typed_data';

import 'package:post_quantum_crypto/post_quantum_crypto.dart';

Future<void> main() async {
  final engine = PostQuantumCryptoEngine();

  // --- Sharing with a group ----------------------------------------------------
  final alice = engine.generateEncryptionKeyPair();
  final bob = engine.generateEncryptionKeyPair();
  final carol = engine.generateEncryptionKeyPair(algorithm: KemAlgorithm.xWing);

  final doc = engine.encrypt(
    utf8.encode('Board minutes, 2026-10-27'),
    recipients: [alice.publicKey, bob.publicKey],
    context: {'doc': 'minutes', 'team': 'board'},
  );
  print('shared with ${doc.recipients.length} recipients');

  // Carol joins. Any current recipient can re-encrypt the document under a
  // fresh data key for the new group.
  final withCarol = engine.addRecipients(
    doc,
    privateKey: alice.privateKey,
    currentRecipients: [alice.publicKey, bob.publicKey],
    newRecipients: [carol.publicKey],
  );
  print(
    'carol reads: '
    '${utf8.decode(engine.decrypt(withCarol, privateKey: carol.privateKey))}',
  );

  // Bob leaves. New copies exclude him (copies he already holds are
  // unaffected: removal is not revocation).
  final withoutBob = engine.removeRecipients(
    withCarol,
    privateKey: carol.privateKey,
    currentRecipients: [alice.publicKey, bob.publicKey, carol.publicKey],
    remove: {bob.keyId},
  );
  try {
    engine.decrypt(withoutBob, privateKey: bob.privateKey);
  } on PostQuantumCryptoException catch (e) {
    print('bob after removal: ${e.runtimeType}');
  }

  // The context is authenticated: a decryptor can insist on it.
  try {
    engine.decrypt(
      withoutBob,
      privateKey: alice.privateKey,
      requiredContext: {'team': 'finance'},
    );
  } on ContextMismatchException {
    print('wrong context rejected');
  }

  // --- Password-based encryption -----------------------------------------------
  // For data protected by a passphrase rather than a key pair.
  final sealed = engine.encryptWithPassword(
    utf8.encode('wifi: correct horse battery staple'),
    'a long passphrase',
    context: {'purpose': 'notes'},
  );
  final opened = engine.decryptWithPassword(
    sealed,
    'a long passphrase',
    requiredContext: {'purpose': 'notes'},
  );
  print('password data: ${utf8.decode(opened)}');

  // --- Streaming with progress ---------------------------------------------------
  // Large data in bounded memory; each chunk is authenticated in position.
  final big = Uint8List(1 << 20);
  final encrypted = await engine
      .encryptStream(
        Stream.fromIterable([big]),
        recipients: [alice.publicKey],
        chunkSize: 64 * 1024,
      )
      .fold<BytesBuilder>(BytesBuilder(), (b, chunk) => b..add(chunk));
  var lastProgress = 0;
  final decryptedLength = await engine
      .decryptStream(
        Stream.value(encrypted.takeBytes()),
        privateKey: alice.privateKey,
        onProgress: (n) => lastProgress = n,
      )
      .fold<int>(0, (n, chunk) => n + chunk.length);
  print('streamed $decryptedLength bytes, progress reached $lastProgress');

  // --- Signing a release -------------------------------------------------------
  final releaseKey = engine.generateSigningKeyPair();
  final context = utf8.encode('example.com/releases');

  // A manifest signs many files at once: paths, sizes and SHA-384 digests.
  final files = {
    'bin/app': utf8.encode('#!/bin/sh\necho hello\n'),
    'README.md': utf8.encode('# App 1.2.0\n'),
  };
  final manifest = engine.createSignedManifest(
    [for (final e in files.entries) engine.manifestEntry(e.key, e.value)],
    privateKey: releaseKey.privateKey,
    context: context,
    metadata: {'version': '1.2.0'},
  );
  final received = engine.parseSignedManifest(manifest.toBytes());
  final verified = engine.verifyManifest(
    received,
    publicKey: releaseKey.publicKey,
  );
  print(
    'manifest ${verified.metadata['version']}: ${received.entries.length} files',
  );
  // Each file is then checked against its entry. For files on disk,
  // `verifyManifestFiles` (post_quantum_crypto_io.dart) does all of this.
  for (final entry in received.entries) {
    final content = files[entry.path];
    if (content == null) {
      print('  ${entry.path}: MISSING');
      continue;
    }
    final actual = engine.manifestEntry(entry.path, content);
    final ok =
        actual.size == entry.size && _sameDigest(actual.digest, entry.digest);
    print('  ${entry.path}: ${ok ? 'ok' : 'MODIFIED'}');
  }

  // A signed artifact bundles one payload with its signature; the content is
  // returned only after the signature verifies.
  final artifact = engine.createSignedArtifact(
    utf8.encode('{"latest": "1.2.0"}'),
    privateKey: releaseKey.privateKey,
    context: context,
  );
  final opened2 = engine.openSignedArtifact(
    artifact.toBytes(),
    publicKey: releaseKey.publicKey,
  );
  print('update feed: ${utf8.decode(opened2.content)}');
}

/// Compares two digests in constant time.
bool _sameDigest(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  var diff = 0;
  for (var i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff == 0;
}
