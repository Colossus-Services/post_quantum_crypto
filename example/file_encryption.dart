// Streaming file encryption, password-protected keys and a key store.
//
// Run with: dart run example/file_encryption.dart
import 'dart:io';

import 'package:quantum_crypto/quantum_crypto_io.dart';

Future<void> main() async {
  final engine = QuantumCryptoEngine();
  final dir = Directory.systemTemp.createTempSync('qc_example_');
  try {
    // A key store backed by a directory; private keys are Argon2id-encrypted.
    final store = KeyStore(
      engine,
      FileKeyStorage(Directory('${dir.path}/keys')),
      password: 'store passphrase',
    );
    final keys = engine.generateEncryptionKeyPair();
    await store.putPair(keys);

    final input = File('${dir.path}/report.csv')
      ..writeAsStringSync('id,amount\n' * 50000);

    await engine.encryptFile(
      input.path,
      '${input.path}.qc',
      recipients: [keys.publicKey],
      context: {'file': 'report.csv'},
      onProgress: (n) {},
    );

    // decryptFile publishes the output only after the whole file verified.
    final privateKey =
        await store.get(keys.keyId, private: true) as EncryptionPrivateKey;
    await engine.decryptFile(
      '${input.path}.qc',
      '${dir.path}/report.decrypted.csv',
      privateKey: privateKey,
      requiredContext: {'file': 'report.csv'},
    );
    print(
      'decrypted ${File('${dir.path}/report.decrypted.csv').lengthSync()} bytes',
    );

    // Portable, password-protected backup of one key.
    final exported = engine.exportPrivateKeyWithPassword(
      privateKey,
      'backup passphrase',
    );
    final restored = engine.importPrivateKeyWithPassword(
      exported,
      'backup passphrase',
    );
    print('restored key ${restored.keyId.fingerprint}');

    // Rotation: new key for new data, old key kept for decryption only.
    final next = await store.rotateEncryptionKey(keys.keyId);
    print('rotated to ${next.keyId.fingerprint}');
  } finally {
    dir.deleteSync(recursive: true);
  }
}
