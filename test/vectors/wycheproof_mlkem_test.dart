/// Wycheproof ML-KEM vectors (C2SP; FIPS 203), including the CCTV edge cases
/// they incorporate (strcmp, unreduced and overflowing public keys).
///
/// `valid` tests must reproduce the published values byte for byte; every
/// other test must be rejected with a [PostQuantumCryptoException]. Keys go
/// through the engine's import functions, as an application's would.
@Tags(['vectors'])
library;

import 'package:post_quantum_crypto/post_quantum_crypto.dart';
import 'package:post_quantum_crypto/src/kem/kem_scheme.dart';
import 'package:test/test.dart';

import '../support/test_engine.dart';
import '../support/vectors.dart';

void main() {
  for (final p in ['512', '768', '1024']) {
    final alg = KemAlgorithm.values.firstWhere(
      (a) => a.standardName == 'ML-KEM-$p',
    );
    final scheme = kemSchemeFor(alg, standardCryptoBackend);

    /// Runs [body] and checks it against the test's expected result.
    void expectResult(Map<String, dynamic> t, void Function() body) {
      if (t['result'] == 'valid') {
        body();
      } else {
        expect(body, throwsA(isA<PostQuantumCryptoException>()));
      }
    }

    String name(Map<String, dynamic> t) =>
        'tcId ${t['tcId']} ${t['result']}'
        '${(t['comment'] as String?)?.isNotEmpty == true ? ' (${t['comment']})' : ''}';

    group('ML-KEM-$p key generation from seed (Wycheproof)', () {
      for (final (_, t) in wycheproofTests(
        'wycheproof_mlkem_${p}_keygen_seed_test.json',
      )) {
        test(name(t), () {
          final kp = scheme.deriveFromSeed(hex(t['seed']));
          expect(kp.publicKey, hex(t['ek']));
          expect(kp.secret.part(0), hex(t['dk']));
          final imported = engine.importEncryptionPrivateKeySeed(
            hex(t['seed']),
            algorithm: alg,
          );
          expect(imported.publicKey.bytes, hex(t['ek']));
        });
      }
    });

    group('ML-KEM-$p decapsulation (Wycheproof, CCTV strcmp)', () {
      for (final (_, t) in wycheproofTests('wycheproof_mlkem_${p}_test.json')) {
        test(name(t), () {
          expectResult(t, () {
            final key = engine.importEncryptionPrivateKeySeed(
              hex(t['seed']),
              algorithm: alg,
            );
            if ((t['ek'] as String?)?.isNotEmpty == true) {
              expect(key.publicKey.bytes, hex(t['ek']));
            }
            expect(scheme.decapsulate(key.secret, hex(t['c'])), hex(t['K']));
          });
        });
      }
    });

    group('ML-KEM-$p encapsulation (Wycheproof)', () {
      for (final (_, t) in wycheproofTests(
        'wycheproof_mlkem_${p}_encaps_test.json',
      )) {
        test(name(t), () {
          if (t['result'] == 'valid') {
            final pk = engine.importEncryptionPublicKey(
              hex(t['ek']),
              algorithm: alg,
            );
            final r = scheme.encapsulate(pk.bytes, hex(t['m']));
            expect(r.ciphertext, hex(t['c']));
            expect(r.sharedSecret, hex(t['K']));
          } else {
            // Rejected both on import and by the raw primitive.
            expect(
              () => engine.importEncryptionPublicKey(
                hex(t['ek']),
                algorithm: alg,
              ),
              throwsA(isA<PostQuantumCryptoException>()),
            );
            expect(
              () => scheme.encapsulate(
                hex(t['ek']),
                hex(t['m'] ?? '00' * alg.encapsulationRandomLength),
              ),
              throwsA(isA<PostQuantumCryptoException>()),
            );
          }
        });
      }
    });

    group('ML-KEM-$p expanded decapsulation keys (Wycheproof)', () {
      for (final (_, t) in wycheproofTests(
        'wycheproof_mlkem_${p}_semi_expanded_decaps_test.json',
      )) {
        test(name(t), () {
          expectResult(t, () {
            final key = engine.importEncryptionPrivateKeyExpanded(
              hex(t['dk']),
              algorithm: alg,
            );
            expect(key.publicKey.bytes, hex(t['ek']));
            expect(scheme.decapsulate(key.secret, hex(t['c'])), hex(t['K']));
          });
        });
      }
    });
  }
}
