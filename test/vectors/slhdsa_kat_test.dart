@Tags(['vectors'])
library;

import 'package:post_quantum_crypto/post_quantum_crypto.dart';
import 'package:test/test.dart';

import '../support/test_engine.dart';
import '../support/vectors.dart';

SignatureAlgorithm _alg(Object? name) =>
    SignatureAlgorithm.values.firstWhere((a) => a.standardName == name);

void main() {
  final backend = standardCryptoBackend;

  group('SLH-DSA sigVer external/pure (NIST ACVP, FIPS 205)', () {
    for (final (g, t) in acvpTests('acvp_slhdsa_sigver.json')) {
      final alg = _alg(g['parameterSet']);
      test('${alg.standardName} tcId ${t['tcId']} (${t['reason']})', () {
        final ok = backend.postQuantum
            .signature(alg)
            .verify(
              hex(t['pk']),
              hex(t['message']),
              hex(t['signature']),
              hex(t['context']),
            );
        expect(ok, t['testPassed'] == true);
      });
    }
  });

  group('SLH-DSA sigGen hedged external/pure (NIST ACVP, FIPS 205)', () {
    for (final (g, t) in acvpTests('acvp_slhdsa_siggen.json')) {
      final alg = _alg(g['parameterSet']);
      test('${alg.standardName} tcId ${t['tcId']}', () {
        final sig = backend.postQuantum
            .signature(alg)
            .sign(
              hex(t['sk']),
              hex(t['message']),
              hex(t['context']),
              hex(t['additionalRandomness']),
            );
        expect(sig, hex(t['signature']));

        // The ACVP secret key imports as a package key with the right pk.
        final key = engine.importSigningPrivateKeySeed(
          hex(t['sk']),
          algorithm: alg,
        );
        expect(key.publicKey.bytes, hex(t['pk']));
        expect(
          engine.verify(
            hex(t['message']),
            signature: sig,
            publicKey: key.publicKey,
            context: hex(t['context']),
          ),
          isTrue,
        );
      });
    }
  });

  test('declared sizes match the implementation', () {
    for (final alg in SignatureAlgorithm.values) {
      final p = backend.postQuantum.signature(alg);
      expect(p.publicKeyLength, alg.publicKeyLength, reason: alg.name);
      expect(p.signatureLength, alg.signatureLength, reason: alg.name);
      if (alg.isSlhDsa) {
        expect(p.secretKeyLength, alg.privateKeyLength, reason: alg.name);
      }
    }
    for (final kem in KemAlgorithm.values.where((k) => !k.isHybrid)) {
      final p = backend.postQuantum.mlKem(kem);
      expect(p.publicKeyLength, kem.publicKeyLength, reason: kem.name);
      expect(p.ciphertextLength, kem.ciphertextLength, reason: kem.name);
    }
  });
}
