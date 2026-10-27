import 'dart:typed_data';

import 'algorithms/algorithms.dart';
import 'encryption/envelope.dart';
import 'engine.dart';
import 'keys/keys.dart';

/// Shortcuts to a default [PostQuantumCryptoEngine] (pure-Dart backend,
/// [SecurityPolicy.standard]).
///
/// ```dart
/// final keys = PostQuantumCrypto.generateEncryptionKeyPair();
/// final env = PostQuantumCrypto.encrypt(data, recipients: [keys.publicKey]);
/// final pt = PostQuantumCrypto.decrypt(env, privateKey: keys.privateKey);
/// ```
///
/// These calls are synchronous and CPU-bound; see `runInBackground`.
abstract final class PostQuantumCrypto {
  /// The default engine.
  static final PostQuantumCryptoEngine engine = PostQuantumCryptoEngine();

  static EncryptionKeyPair generateEncryptionKeyPair({
    KemAlgorithm algorithm = KemAlgorithm.mlKem768,
  }) => engine.generateEncryptionKeyPair(algorithm: algorithm);

  static SigningKeyPair generateSigningKeyPair({
    SignatureAlgorithm algorithm = SignatureAlgorithm.mlDsa65,
  }) => engine.generateSigningKeyPair(algorithm: algorithm);

  static EncryptedEnvelope encrypt(
    List<int> plaintext, {
    required List<EncryptionPublicKey> recipients,
    Map<String, String> context = const {},
  }) => engine.encrypt(plaintext, recipients: recipients, context: context);

  static Uint8List decrypt(
    EncryptedEnvelope envelope, {
    required EncryptionPrivateKey privateKey,
    Map<String, String>? requiredContext,
  }) => engine.decrypt(
    envelope,
    privateKey: privateKey,
    requiredContext: requiredContext,
  );

  static Uint8List sign(
    List<int> message, {
    required SigningPrivateKey privateKey,
    List<int> context = const [],
  }) => engine.sign(message, privateKey: privateKey, context: context);

  static bool verify(
    List<int> message, {
    required List<int> signature,
    required SigningPublicKey publicKey,
    List<int> context = const [],
  }) => engine.verify(
    message,
    signature: signature,
    publicKey: publicKey,
    context: context,
  );
}
