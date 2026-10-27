// Key lifecycle: metadata, rotation, revocation, policies, backup and
// interoperable (PEM) export.
//
// Run with: dart run example/key_management.dart
import 'dart:convert';

import 'package:post_quantum_crypto/post_quantum_crypto.dart';

Future<void> main() async {
  final engine = PostQuantumCryptoEngine();

  // A store over any KeyStorage (in memory here; FileKeyStorage or a platform
  // keystore in an app). Private keys are Argon2id-encrypted at rest.
  final store = KeyStore(
    engine,
    InMemoryKeyStorage(),
    password: 'store passphrase',
  );

  // --- Keys with lifecycle metadata ------------------------------------------
  final billing = engine.generateEncryptionKeyPair(
    metadata: KeyMetadata(
      createdAt: DateTime.now().toUtc(),
      expiresAt: DateTime.now().toUtc().add(const Duration(days: 365)),
      usages: const {KeyUsage.encrypt, KeyUsage.decrypt},
      label: 'billing / prod',
    ),
  );
  final releases = engine.generateSigningKeyPair(
    metadata: const KeyMetadata(
      usages: {KeyUsage.sign, KeyUsage.verify},
      label: 'release signing',
    ),
  );
  await store.putPair(billing);
  await store.putPair(releases);
  for (final id in await store.list()) {
    final key = await store.get(id);
    print('stored ${key!.metadata.label}: ${id.fingerprint}');
  }

  // --- Rotation ----------------------------------------------------------------
  // Old data stays readable: the previous key becomes decrypt-only, and the
  // new key records which key it replaces.
  final old = engine.encrypt(
    utf8.encode('invoice #1'),
    recipients: [billing.publicKey],
  );
  final billing2 = await store.rotateEncryptionKey(billing.keyId);
  print(
    'billing rotated, replaces: '
    '${billing2.publicKey.metadata.replaces!.fingerprint}',
  );

  final retired = await store.get(billing.keyId, private: true);
  print(
    'old envelope still opens: '
    '${utf8.decode(engine.decrypt(old, privateKey: retired as EncryptionPrivateKey))}',
  );
  try {
    engine.encrypt(utf8.encode('invoice #2'), recipients: [retired.publicKey]);
  } on PolicyViolationException catch (e) {
    print('encrypting to the retired key: ${e.message}');
  }

  // --- Revocation and trust ----------------------------------------------------
  final artifact = engine.signDetached(
    utf8.encode('app-1.2.0.tar.gz'),
    privateKey: releases.privateKey,
  );
  // Verified while the key was still valid.
  final verified = engine.verifyDetached(
    utf8.encode('app-1.2.0.tar.gz'),
    signature: artifact,
    publicKey: releases.publicKey,
  );
  await store.revoke(releases.keyId, reason: 'laptop lost');
  final revoked = await store.get(releases.keyId) as SigningPublicKey;
  print('revoked: ${revoked.metadata.revocationReason}');

  // The policy rejects revoked keys outright...
  try {
    engine.verifyDetached(
      utf8.encode('app-1.2.0.tar.gz'),
      signature: artifact,
      publicKey: revoked,
    );
  } on PolicyViolationException catch (e) {
    print('verify with revoked key: ${e.message}');
  }
  // ...and a TrustStore holding the updated key re-evaluates the earlier
  // verification as revoked.
  final trust = TrustStore([revoked]);
  print('trust decision now: ${trust.evaluate(verified)}');

  // --- Policies ----------------------------------------------------------------
  // `strict` requires NIST security category 3 or higher.
  final strict = engine.withPolicy(SecurityPolicy.strict);
  try {
    strict.generateSigningKeyPair(algorithm: SignatureAlgorithm.mlDsa44);
  } on PolicyViolationException catch (e) {
    print('strict policy: ${e.message}');
  }
  // A custom policy: hybrid (X-Wing) recipients only.
  final hybridOnly = engine.withPolicy(
    const SecurityPolicy(requireHybridKem: true),
  );
  final xwing = hybridOnly.generateEncryptionKeyPair(
    algorithm: KemAlgorithm.xWing,
  );
  print('hybrid-only policy accepts ${xwing.publicKey.algorithm.standardName}');

  // --- Backup and restore ------------------------------------------------------
  final backup = await store.backup('backup passphrase');
  final restoredStore = KeyStore(engine, InMemoryKeyStorage());
  final restored = await restoredStore.restore(backup, 'backup passphrase');
  print('backup: ${backup.length} bytes, restored ${restored.length} keys');

  // --- Interoperable export ----------------------------------------------------
  // Standard SPKI / PKCS#8 for ML-KEM, ML-DSA and SLH-DSA, interoperable
  // with OpenSSL 3.5+ (X-Wing keys have no standard DER form).
  final pem = engine.exportPublicKeyPem(billing2.publicKey);
  print(pem.split('\n').first);
  final imported = engine.importPublicKeyPem(pem);
  print('PEM round trip: ${imported.keyId == billing2.keyId}');
}
