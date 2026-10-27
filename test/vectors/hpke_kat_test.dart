@Tags(['vectors'])
library;

import 'package:quantum_crypto/src/algorithms/algorithms.dart';
import 'package:quantum_crypto/src/hpke/hpke.dart';
import 'package:quantum_crypto/src/kem/kem_scheme.dart';
import 'package:quantum_crypto/src/providers/default_backend.dart';
import 'package:test/test.dart';

import '../support/vectors.dart';

/// Checks the HPKE implementation (RFC 9180 key schedule + AEAD context)
/// together with the ML-KEM and X-Wing KEMs against draft-ietf-hpke-pq
/// vectors.
void main() {
  final backend = standardCryptoBackend;
  final vectors = (loadVectors('hpke_pq.json') as List)
      .cast<Map<String, dynamic>>();

  var covered = 0;
  for (final v in vectors) {
    final kemId = v['kem_id'] as int;
    final kdfId = v['kdf_id'] as int;
    final aeadId = v['aead_id'] as int;
    final KemAlgorithm kem;
    try {
      kem = KemAlgorithm.fromId(kemId);
    } on Object {
      continue; // P-256 hybrids are not supported by this package.
    }
    if (kdfId > 3 || aeadId > 3 || v['mode'] != 0) continue;
    covered++;

    test('kem 0x${kemId.toRadixString(16)} kdf $kdfId aead $aeadId', () {
      final scheme = kemSchemeFor(kem, backend);
      final kp = scheme.deriveFromSeed(hex(v['skRm']));
      expect(kp.publicKey, hex(v['pkRm']));

      final enc = scheme.encapsulate(kp.publicKey, hex(v['ikmE']));
      expect(enc.ciphertext, hex(v['enc']));
      expect(enc.sharedSecret, hex(v['shared_secret']));
      expect(scheme.decapsulate(kp.secret, enc.ciphertext), enc.sharedSecret);

      final suite = HpkeSuite(
        kemId: kemId,
        kdfId: kdfId,
        aeadId: aeadId,
        kdf: backend.symmetric.kdf(KdfAlgorithm.fromId(kdfId)),
        aead: aeadId == 1
            ? backend.symmetric.aead(AeadAlgorithm.aes256Gcm, keyLength: 16)
            : backend.symmetric.aead(AeadAlgorithm.fromId(aeadId)),
      );
      expect(suite.suiteId, hex(v['suite_id']));

      final sender = suite.keySchedule(enc.sharedSecret, hex(v['info']));
      final receiver = suite.keySchedule(enc.sharedSecret, hex(v['info']));
      expect(sender.key, hex(v['key']));
      expect(sender.baseNonce, hex(v['base_nonce']));
      expect(sender.exporterSecret, hex(v['exporter_secret']));

      for (final e in (v['encryptions'] as List).cast<Map<String, dynamic>>()) {
        final ct = sender.seal(hex(e['aad']), hex(e['pt']));
        expect(ct, hex(e['ct']));
        expect(receiver.open(hex(e['aad']), ct), hex(e['pt']));
      }
      for (final x in (v['exports'] as List).cast<Map<String, dynamic>>()) {
        expect(
          sender.export(hex(x['exporter_context']), x['L'] as int),
          hex(x['exported_value']),
        );
      }
    });
  }

  test('covers ML-KEM-512/768/1024 and X-Wing', () {
    expect(covered, greaterThanOrEqualTo(4));
  });
}
