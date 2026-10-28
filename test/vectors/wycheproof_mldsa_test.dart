/// Wycheproof ML-DSA vectors (C2SP; FIPS 204).
///
/// Signing is checked byte for byte: deterministic (rnd = 0^32) and
/// randomized with the given rnd. `valid` tests must reproduce the published
/// signature or verify; every other test must be rejected, by an exception
/// or by `verify` returning false. Keys go through the engine's import
/// functions, as an application's would.
@Tags(['vectors'])
library;

import 'dart:typed_data';

import 'package:post_quantum_crypto/post_quantum_crypto.dart';
import 'package:test/test.dart';

import '../support/test_engine.dart';
import '../support/vectors.dart';

/// Tests with this flag sign a precomputed μ through ML-DSA.Sign_internal /
/// Verify_internal, which this package deliberately does not expose.
const _internal = 'Internal';

void main() {
  for (final p in ['44', '65', '87']) {
    final alg = SignatureAlgorithm.values.firstWhere(
      (a) => a.standardName == 'ML-DSA-$p',
    );
    final primitive = standardCryptoBackend.postQuantum.signature(alg);
    var skipped = 0;

    String name(Map<String, dynamic> t) =>
        'tcId ${t['tcId']} ${t['result']}'
        '${(t['comment'] as String?)?.isNotEmpty == true ? ' (${t['comment']})' : ''}';

    bool isInternal(Map<String, dynamic> t) =>
        ((t['flags'] as List?) ?? const []).contains(_internal);

    /// Signs [t] with [key] and checks the result against the test.
    void checkSign(Map<String, dynamic> t, SigningPrivateKey Function() key) {
      void body() {
        final sk = key();
        final ctx = hex(t['ctx'] ?? '');
        final rnd = t['rnd'] == null ? Uint8List(32) : hex(t['rnd']);
        final sig = primitive.sign(sk.secretKey, hex(t['msg']), ctx, rnd);
        expect(sig, hex(t['sig']));
        // The engine's verify accepts what the primitive produced.
        expect(
          engine.verify(
            hex(t['msg']),
            signature: sig,
            publicKey: sk.publicKey,
            context: ctx,
          ),
          isTrue,
        );
      }

      if (t['result'] == 'valid') {
        body();
      } else {
        expect(body, throwsA(isA<PostQuantumCryptoException>()));
      }
    }

    group('ML-DSA-$p signing from a seed (Wycheproof)', () {
      for (final (g, t) in wycheproofTests(
        'wycheproof_mldsa_${p}_sign_seed_test.json',
      )) {
        if (isInternal(t)) {
          skipped++;
          continue;
        }
        test(name(t), () {
          SigningPrivateKey key() {
            final k = engine.importSigningPrivateKeySeed(
              hex(g['privateSeed']),
              algorithm: alg,
            );
            expect(k.publicKey.bytes, hex(g['publicKey']));
            // The group's RFC 9881 seed-form PKCS#8, when given, is the same
            // key, and our export reproduces it.
            if (g['privateKeyPkcs8'] != null) {
              final der = hex(g['privateKeyPkcs8']);
              expect(engine.importPrivateKeyDer(der).keyId, k.keyId);
              expect(engine.exportPrivateKeyDer(k), der);
            }
            return k;
          }

          checkSign(t, key);
        });
      }
    });

    group('ML-DSA-$p signing with an expanded key (Wycheproof)', () {
      for (final (g, t) in wycheproofTests(
        'wycheproof_mldsa_${p}_sign_noseed_test.json',
      )) {
        if (isInternal(t)) {
          skipped++;
          continue;
        }
        test(name(t), () {
          checkSign(
            t,
            () => engine.importSigningPrivateKeyExpanded(
              hex(g['privateKey']),
              // Absent for the wrong-length keys; import then fails.
              publicKey: hex(g['publicKey'] ?? ''),
              algorithm: alg,
            ),
          );
        });
      }
    });

    group('ML-DSA-$p verification (Wycheproof)', () {
      for (final (g, t) in wycheproofTests(
        'wycheproof_mldsa_${p}_verify_test.json',
      )) {
        if (isInternal(t)) {
          skipped++;
          continue;
        }
        test(name(t), () {
          bool verify() {
            final pk =
                engine.importPublicKeyDer(hex(g['publicKeyDer']))
                    as SigningPublicKey;
            expect(pk.bytes, hex(g['publicKey']));
            expect(engine.exportPublicKeyDer(pk), hex(g['publicKeyDer']));
            return engine.verify(
              hex(t['msg']),
              signature: hex(t['sig']),
              publicKey: pk,
              context: hex(t['ctx'] ?? ''),
            );
          }

          if (t['result'] == 'valid') {
            expect(verify(), isTrue);
          } else {
            // Rejected: verification fails or an input is refused.
            try {
              expect(verify(), isFalse);
            } on PostQuantumCryptoException {
              // expected
            }
          }
        });
      }
    });

    test('ML-DSA-$p: only Sign_internal/Verify_internal tests are skipped', () {
      final internal = [
        for (final f in [
          'wycheproof_mldsa_${p}_sign_seed_test.json',
          'wycheproof_mldsa_${p}_sign_noseed_test.json',
          'wycheproof_mldsa_${p}_verify_test.json',
        ])
          for (final (_, t) in wycheproofTests(f))
            if (isInternal(t)) t,
      ];
      expect(skipped, internal.length);
    });
  }
}
