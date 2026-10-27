@Tags(['vectors'])
library;

import 'dart:typed_data';

import 'package:quantum_crypto/src/algorithms/algorithms.dart';
import 'package:quantum_crypto/src/errors.dart';
import 'package:quantum_crypto/src/kem/kem_scheme.dart';
import 'package:quantum_crypto/src/providers/default_backend.dart';
import 'package:test/test.dart';

import '../support/vectors.dart';

KemAlgorithm _kem(Object? name) =>
    KemAlgorithm.values.firstWhere((a) => a.standardName == name);

SignatureAlgorithm _sig(Object? name) =>
    SignatureAlgorithm.values.firstWhere((a) => a.standardName == name);

void main() {
  final backend = standardCryptoBackend;

  group('ML-KEM keyGen (NIST ACVP, FIPS 203)', () {
    for (final (g, t) in acvpTests('acvp_mlkem_keygen.json')) {
      test('${g['parameterSet']} tcId ${t['tcId']}', () {
        final scheme = kemSchemeFor(_kem(g['parameterSet']), backend);
        final seed = Uint8List.fromList([...hex(t['d']), ...hex(t['z'])]);
        final kp = scheme.deriveFromSeed(seed);
        expect(kp.publicKey, hex(t['ek']));
        expect(kp.secret.part(0), hex(t['dk']));
      });
    }
  });

  group('ML-KEM encapDecap (NIST ACVP, FIPS 203)', () {
    for (final (g, t) in acvpTests('acvp_mlkem_encapdecap.json')) {
      final alg = _kem(g['parameterSet']);
      final fn = g['function'] as String;
      test('${g['parameterSet']} $fn tcId ${t['tcId']}', () {
        final scheme = kemSchemeFor(alg, backend);
        switch (fn) {
          case 'encapsulation':
            final r = scheme.encapsulate(hex(t['ek']), hex(t['m']));
            expect(r.ciphertext, hex(t['c']));
            expect(r.sharedSecret, hex(t['k']));
          case 'decapsulation':
            // Includes "modified ciphertext" cases: implicit rejection must
            // return the FIPS 203 pseudorandom value K̄, not an error.
            final kp = scheme.fromExpandedSecretKey(hex(t['dk']));
            expect(scheme.decapsulate(kp.secret, hex(t['c'])), hex(t['k']));
          case 'encapsulationKeyCheck':
            void encaps() => scheme.encapsulate(hex(t['ek']), Uint8List(32));
            if (t['testPassed'] == true) {
              encaps();
            } else {
              expect(encaps, throwsA(isA<InvalidKeyException>()));
            }
          case 'decapsulationKeyCheck':
            void check() => scheme.fromExpandedSecretKey(hex(t['dk']));
            if (t['testPassed'] == true) {
              check();
            } else {
              expect(check, throwsA(isA<InvalidKeyException>()));
            }
          default:
            fail('unknown function $fn');
        }
      });
    }
  });

  group('ML-DSA keyGen (NIST ACVP, FIPS 204)', () {
    for (final (g, t) in acvpTests('acvp_mldsa_keygen.json')) {
      test('${g['parameterSet']} tcId ${t['tcId']}', () {
        final sig = backend.postQuantum.signature(_sig(g['parameterSet']));
        final kp = sig.generateFromSeed(hex(t['seed']));
        expect(kp.publicKey, hex(t['pk']));
        expect(kp.secretKey, hex(t['sk']));
      });
    }
  });

  group('ML-DSA sigGen external/pure (NIST ACVP, FIPS 204)', () {
    for (final (g, t) in acvpTests('acvp_mldsa_siggen.json')) {
      final det = g['deterministic'] == true;
      test('${g['parameterSet']} ${det ? 'det' : 'hedged'} '
          'tcId ${t['tcId']}', () {
        final sig = backend.postQuantum.signature(_sig(g['parameterSet']));
        final rnd = det ? Uint8List(32) : hex(t['rnd']);
        final s = sig.sign(
          hex(t['sk']),
          hex(t['message']),
          hex(t['context']),
          rnd,
        );
        expect(s, hex(t['signature']));
      });
    }
  });

  group('ML-DSA sigVer external/pure (NIST ACVP, FIPS 204)', () {
    for (final (g, t) in acvpTests('acvp_mldsa_sigver.json')) {
      test('${g['parameterSet']} tcId ${t['tcId']} (${t['reason']})', () {
        final sig = backend.postQuantum.signature(_sig(g['parameterSet']));
        final ok = sig.verify(
          hex(t['pk']),
          hex(t['message']),
          hex(t['signature']),
          hex(t['context']),
        );
        expect(ok, t['testPassed'] == true);
      });
    }
  });

  group('X-Wing (draft-connolly-cfrg-xwing-kem)', () {
    final vectors = (loadVectors('xwing_draft.json') as List)
        .cast<Map<String, dynamic>>();
    final scheme = kemSchemeFor(KemAlgorithm.xWing, backend);
    for (var i = 0; i < vectors.length; i++) {
      final v = vectors[i];
      test('vector $i', () {
        final kp = scheme.deriveFromSeed(hex(v['seed']));
        expect(kp.publicKey, hex(v['pk']));
        final enc = scheme.encapsulate(kp.publicKey, hex(v['eseed']));
        expect(enc.ciphertext, hex(v['ct']));
        expect(enc.sharedSecret, hex(v['ss']));
        expect(scheme.decapsulate(kp.secret, enc.ciphertext), hex(v['ss']));
      });
    }
  });
}
