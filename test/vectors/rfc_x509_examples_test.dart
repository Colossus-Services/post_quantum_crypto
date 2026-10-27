/// The Appendix C example keys of RFC 9881 (ML-DSA in X.509) and RFC 9935
/// (ML-KEM in X.509): private keys in the seed, expanded and both forms,
/// public keys, and the deliberately inconsistent private keys of C.4.
///
/// Every example is imported, re-exported byte for byte, and tied to its
/// public key; every C.4 key must be rejected.
@Tags(['vectors'])
library;

import 'dart:typed_data';

import 'package:post_quantum_crypto/post_quantum_crypto.dart';
import 'package:post_quantum_crypto/src/encoding/der.dart';
import 'package:test/test.dart';

import '../support/test_engine.dart';
import '../support/vectors.dart';

typedef _Example = ({String section, int index, String label, Uint8List der});

List<_Example> _examples(int rfc) => [
  for (final e
      in ((loadVectors('rfc${rfc}_examples.json') as Map)['examples'] as List)
          .cast<Map<String, dynamic>>())
    (
      section: e['section'] as String,
      index: e['index'] as int,
      label: e['label'] as String,
      der: hex(e['der']),
    ),
];

_Example _one(List<_Example> all, String section, [int index = 0]) =>
    all.singleWhere((e) => e.section == section && e.index == index);

/// The contents of a PKCS#8 `privateKey` OCTET STRING whose CHOICE is the
/// expanded form (`OCTET STRING expandedKey`).
Uint8List _expandedKey(Uint8List pkcs8) {
  final seq = DerReader(DerReader(pkcs8).expect(DerTag.sequence))
    ..expect(DerTag.integer)
    ..expect(DerTag.sequence);
  final inner = DerReader(seq.expect(DerTag.octetString));
  return inner.expect(DerTag.octetString);
}

void main() {
  group('RFC 9935 (ML-KEM) Appendix C', () {
    final all = _examples(9935);
    const params = ['ML-KEM-512', 'ML-KEM-768', 'ML-KEM-1024'];

    for (final (i, name) in params.indexed) {
      final n = i + 1;
      test('$name: C.1.$n private keys and C.2 public key', () {
        final pub = engine.importPublicKeyDer(_one(all, 'C.2', i).der);
        expect((pub as EncryptionPublicKey).algorithm.standardName, name);
        expect(engine.exportPublicKeyDer(pub), _one(all, 'C.2', i).der);

        final forms = {
          PrivateKeyDerForm.seed: _one(all, 'C.1.$n.1').der,
          PrivateKeyDerForm.expanded: _one(all, 'C.1.$n.2').der,
          PrivateKeyDerForm.both: _one(all, 'C.1.$n.3').der,
        };
        for (final MapEntry(key: form, value: der) in forms.entries) {
          final key = engine.importPrivateKeyDer(der) as EncryptionPrivateKey;
          expect(key.publicKey, pub, reason: '$form');
          // Re-export in the same form is byte-identical.
          expect(engine.exportPrivateKeyDer(key, form: form), der);
          if (form != PrivateKeyDerForm.expanded) {
            // A key with its seed reproduces all three forms.
            for (final MapEntry(key: f, value: d) in forms.entries) {
              expect(engine.exportPrivateKeyDer(key, form: f), d);
            }
          }
        }
      });
    }

    test('C.4.1 inconsistent ML-KEM-512 private keys are rejected', () {
      final bad = all.where((e) => e.section == 'C.4.1').toList();
      expect(bad, hasLength(4));
      for (final e in bad) {
        expect(
          () => engine.importPrivateKeyDer(e.der),
          throwsA(isA<InvalidKeyException>()),
          reason: 'C.4.1 example ${e.index + 1}',
        );
      }
    });
  });

  group('RFC 9881 (ML-DSA) Appendix C', () {
    final all = _examples(9881);
    const params = ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87'];

    for (final (i, name) in params.indexed) {
      final n = i + 1;
      test('$name: C.1.$n private keys and C.2 public key', () {
        final pub =
            engine.importPublicKeyDer(_one(all, 'C.2', i).der)
                as SigningPublicKey;
        expect(pub.algorithm.standardName, name);
        expect(engine.exportPublicKeyDer(pub), _one(all, 'C.2', i).der);

        final seed = _one(all, 'C.1.$n.1').der;
        final expanded = _one(all, 'C.1.$n.2').der;
        final both = _one(all, 'C.1.$n.3').der;
        for (final der in [seed, both]) {
          final key = engine.importPrivateKeyDer(der) as SigningPrivateKey;
          expect(key.publicKey, pub);
          expect(engine.exportPrivateKeyDer(key), seed);
          expect(
            engine.exportPrivateKeyDer(key, form: PrivateKeyDerForm.expanded),
            expanded,
          );
          expect(
            engine.exportPrivateKeyDer(key, form: PrivateKeyDerForm.both),
            both,
          );
        }

        // The expanded example imports on its own (the public key is
        // recomputed from it) and re-exports byte for byte; supplying the
        // public key explicitly gives the same key.
        final key = engine.importPrivateKeyDer(expanded) as SigningPrivateKey;
        expect(key.publicKey, pub);
        expect(
          engine.exportPrivateKeyDer(key, form: PrivateKeyDerForm.expanded),
          expanded,
        );
        expect(
          engine
              .importSigningPrivateKeyExpanded(
                _expandedKey(expanded),
                publicKey: pub.bytes,
                algorithm: pub.algorithm,
              )
              .keyId,
          pub.keyId,
        );
      });
    }

    test('C.4 inconsistent ML-DSA-44 private keys are rejected', () {
      final bad = all.where((e) => e.section == 'C.4').toList();
      expect(bad, hasLength(3));
      final pub =
          engine.importPublicKeyDer(_one(all, 'C.2').der) as SigningPublicKey;
      for (final e in bad) {
        final reason = 'C.4 example ${e.index + 1}';
        expect(
          () => engine.importPrivateKeyDer(e.der),
          throwsA(isA<InvalidKeyException>()),
          reason: reason,
        );
      }
      // Examples 2 and 3 are expanded-only: even with the matching public
      // key supplied, the inconsistency (tr, then t0) must be detected.
      for (final e in bad.skip(1)) {
        expect(
          () => engine.importSigningPrivateKeyExpanded(
            _expandedKey(e.der),
            publicKey: pub.bytes,
            algorithm: SignatureAlgorithm.mlDsa44,
          ),
          throwsA(isA<InvalidKeyException>()),
          reason: 'C.4 example ${e.index + 1} with its public key',
        );
      }
    });
  });
}
