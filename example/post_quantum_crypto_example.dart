// Quick tour of post_quantum_crypto. Run with: dart run example/post_quantum_crypto_example.dart
import 'dart:convert';

import 'package:post_quantum_crypto/post_quantum_crypto.dart';

void main() {
  final engine = PostQuantumCryptoEngine();

  // --- Encryption (ML-KEM-768 + HPKE + AES-256-GCM) -------------------------
  final alice = engine.generateEncryptionKeyPair();
  final bob = engine.generateEncryptionKeyPair(algorithm: KemAlgorithm.xWing);

  final envelope = engine.encrypt(
    utf8.encode('Quarterly numbers: confidential'),
    recipients: [alice.publicKey, bob.publicKey],
    context: {'tenant': 'acme', 'record': 'report-2026-q3'},
  );
  final wire = envelope.toBytes(); // canonical binary form
  print('envelope: ${wire.length} bytes, recipients: ${envelope.recipients}');

  final plaintext = engine.decryptBytes(
    wire,
    privateKey: bob.privateKey,
    requiredContext: {'tenant': 'acme'},
  );
  print('bob reads: ${utf8.decode(plaintext)}');

  // --- Signatures (ML-DSA-65) ----------------------------------------------
  final signer = engine.generateSigningKeyPair();
  final message = utf8.encode('release 1.0.0');
  final signature = engine.sign(
    message,
    privateKey: signer.privateKey,
    context: utf8.encode('example/releases'),
  );
  final valid = engine.verify(
    message,
    signature: signature,
    publicKey: signer.publicKey,
    context: utf8.encode('example/releases'),
  );
  print('signature valid: $valid (${signature.length} bytes)');

  // A valid signature is not the same as a trusted signer.
  final trust = TrustStore([signer.publicKey]);
  final detached = engine.signDetached(
    message,
    privateKey: signer.privateKey,
    metadata: {'name': 'app.tar.gz'},
  );
  final verified = engine.verifyDetached(
    message,
    signature: detached,
    publicKey: trust.lookup(detached.signerKeyId)!,
  );
  print('trust decision: ${trust.evaluate(verified)}');

  // --- Key export -----------------------------------------------------------
  print(engine.exportPublicKeyPem(signer.publicKey).split('\n').first);
  print('key id: ${alice.keyId.fingerprint}');

  // --- Hybrid key establishment (X-Wing) -----------------------------------
  const transcript = HybridTranscript(
    protocol: 'example/v1',
    initiatorId: 'client',
    responderId: 'server',
  );
  final init = engine.establishHybridKey(bob.publicKey, transcript: transcript);
  final serverKey = engine.acceptHybridKey(
    init.message,
    privateKey: bob.privateKey,
    transcript: transcript,
  );
  print(
    'hybrid keys match: '
    '${TextEncoding.toHex(serverKey) == TextEncoding.toHex(init.sessionKey)}',
  );
}
