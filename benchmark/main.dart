// Micro-benchmarks for post_quantum_crypto.
//
//   dart run benchmark/main.dart                      (VM, JIT)
//   dart compile exe benchmark/main.dart -o /tmp/qcb && /tmp/qcb   (AOT)
//   dart compile js benchmark/main.dart -o /tmp/qcb.js && node /tmp/qcb.js
//   dart compile wasm benchmark/main.dart -o /tmp/qcb.wasm   (run in a host)
//
// Each line reports the mean time per operation over a fixed wall-clock
// budget. Numbers depend heavily on the platform and compiler.
import 'dart:typed_data';

import 'package:post_quantum_crypto/post_quantum_crypto.dart';

void _bench(String name, void Function() op, {int bytes = 0}) {
  op(); // warm-up
  final sw = Stopwatch()..start();
  var n = 0;
  while (sw.elapsedMilliseconds < 1500 || n < 3) {
    op();
    n++;
  }
  final us = sw.elapsedMicroseconds / n;
  final rate = bytes > 0
      ? '  ${(bytes / us * 1e6 / (1 << 20)).toStringAsFixed(1)} MiB/s'
      : '';
  print(
    '${name.padRight(36)} ${(us / 1000).toStringAsFixed(3).padLeft(10)} ms$rate',
  );
}

void main() {
  final engine = PostQuantumCryptoEngine();
  final sym = engine.backend.symmetric;
  const mib = 1 << 20;
  final data = Uint8List(mib);
  final key = Uint8List(32);
  final nonce = Uint8List(12);
  final aad = Uint8List(48);

  for (final a in AeadAlgorithm.values) {
    final aead = sym.aead(a);
    _bench('${a.standardName} seal 1 MiB', () {
      aead.seal(key, nonce, data, aad);
    }, bytes: mib);
  }
  _bench('SHA-384 1 MiB', () {
    sym.hash(HashAlgorithm.sha384).hash(data);
  }, bytes: mib);

  for (final kem in KemAlgorithm.values) {
    late EncryptionKeyPair kp;
    _bench('${kem.standardName} keygen', () {
      kp = engine.generateEncryptionKeyPair(algorithm: kem);
    });
    _bench('${kem.standardName} envelope (32 B)', () {
      engine.encrypt(Uint8List(32), recipients: [kp.publicKey]);
    });
    final env = engine.encrypt(Uint8List(32), recipients: [kp.publicKey]);
    _bench('${kem.standardName} decrypt (32 B)', () {
      engine.decrypt(env, privateKey: kp.privateKey);
    });
  }

  for (final sig in [
    SignatureAlgorithm.mlDsa44,
    SignatureAlgorithm.mlDsa65,
    SignatureAlgorithm.mlDsa87,
  ]) {
    late SigningKeyPair kp;
    _bench('${sig.standardName} keygen', () {
      kp = engine.generateSigningKeyPair(algorithm: sig);
    });
    late Uint8List s;
    _bench('${sig.standardName} sign', () {
      s = engine.sign(data.sublist(0, 1024), privateKey: kp.privateKey);
    });
    _bench('${sig.standardName} verify', () {
      engine.verify(
        data.sublist(0, 1024),
        signature: s,
        publicKey: kp.publicKey,
      );
    });
  }

  final kp = engine.generateEncryptionKeyPair();
  final big = Uint8List(8 * mib);
  _bench('envelope encrypt 8 MiB', () {
    engine.encrypt(big, recipients: [kp.publicKey]);
  }, bytes: 8 * mib);

  _bench('Argon2id 19 MiB t=2 (OWASP min)', () {
    sym.argon2id.derive(
      password: Uint8List(8),
      salt: Uint8List(16),
      memoryKiB: 19 * 1024,
      iterations: 2,
      parallelism: 1,
      length: 32,
    );
  });
}
