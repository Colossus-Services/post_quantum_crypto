import 'dart:typed_data';

import 'package:meta/meta.dart';

import 'algorithms/algorithms.dart';
import 'context.dart';
import 'encryption/envelope.dart';
import 'encryption/streaming.dart';
import 'hybrid/hybrid_key_establishment.dart';
import 'errors.dart';
import 'encoding/bytes.dart';
import 'encoding/canonical.dart';
import 'encoding/der.dart';
import 'keys/key_factory.dart';
import 'keys/key_metadata.dart';
import 'keys/key_serialization.dart';
import 'keys/keys.dart';
import 'keys/password_protection.dart';
import 'policy.dart';
import 'providers/default_backend.dart';
import 'providers/primitives.dart';
import 'random/secure_random.dart';
import 'signatures/signed_objects.dart';

/// The configurable entry point of the library.
///
/// An engine bundles a [CryptoBackend] (the primitive implementations), a
/// [SecurityPolicy] and the platform CSPRNG. Engines are cheap, immutable and
/// safe to share.
///
/// All methods are **synchronous and CPU-bound**: pure-Dart ML-KEM, ML-DSA
/// and Argon2id take from microseconds to seconds depending on the platform
/// and parameters. In UI isolates, call them through `runInBackground` (an
/// `Isolate.run` on native platforms).
final class PostQuantumCryptoEngine {
  @internal
  final CryptoContext ctx;

  final KeyFactory _keys;
  late final KeyCodec _codec;
  late final PasswordProtection _password;
  late final EnvelopeService _envelopes;
  late final SignedObjectService _signed;
  late final StreamService _streams;
  late final HybridKeyService _hybrid;

  /// Creates an engine. [backend] defaults to the pure-Dart
  /// [standardCryptoBackend]; [policy] to [SecurityPolicy.standard].
  ///
  /// Randomness always comes from the platform CSPRNG
  /// ([SystemSecureRandom]); there is no public way to select another source.
  factory PostQuantumCryptoEngine({
    CryptoBackend backend = standardCryptoBackend,
    SecurityPolicy policy = SecurityPolicy.standard,
  }) => PostQuantumCryptoEngine._(
    CryptoContext(backend, policy, SystemSecureRandom.instance),
  );

  PostQuantumCryptoEngine._(this.ctx) : _keys = KeyFactory(ctx) {
    _codec = KeyCodec(_keys);
    _password = PasswordProtection(ctx);
    _envelopes = EnvelopeService(ctx);
    _signed = SignedObjectService(ctx);
    _streams = StreamService(ctx);
    _hybrid = HybridKeyService(ctx);
  }

  /// Internal constructor used by tests to inject a deterministic source.
  @internal
  @visibleForTesting
  factory PostQuantumCryptoEngine.withRandomSourceForTesting(
    SecureRandomSource random, {
    CryptoBackend backend = standardCryptoBackend,
    SecurityPolicy policy = SecurityPolicy.standard,
  }) => PostQuantumCryptoEngine._(CryptoContext(backend, policy, random));

  CryptoBackend get backend => ctx.backend;

  SecurityPolicy get policy => ctx.policy;

  /// Returns an engine with the same backend and a different [policy].
  PostQuantumCryptoEngine withPolicy(SecurityPolicy policy) =>
      PostQuantumCryptoEngine._(CryptoContext(backend, policy, ctx.random));

  // ---------------------------------------------------------------------------
  // Keys
  // ---------------------------------------------------------------------------

  /// Generates an encryption key pair. Defaults to ML-KEM-768.
  EncryptionKeyPair generateEncryptionKeyPair({
    KemAlgorithm algorithm = KemAlgorithm.mlKem768,
    KeyMetadata? metadata,
  }) => _keys.generateEncryptionKeyPair(
    algorithm,
    metadata ?? KeyMetadata(createdAt: ctx.policy.now()),
  );

  /// Generates a signing key pair. Defaults to ML-DSA-65.
  SigningKeyPair generateSigningKeyPair({
    SignatureAlgorithm algorithm = SignatureAlgorithm.mlDsa65,
    KeyMetadata? metadata,
  }) => _keys.generateSigningKeyPair(
    algorithm,
    metadata ?? KeyMetadata(createdAt: ctx.policy.now()),
  );

  /// Imports a raw encryption public key (FIPS 203 `ek`, or the X-Wing
  /// encapsulation key). The FIPS 203 encapsulation-key check is applied.
  EncryptionPublicKey importEncryptionPublicKey(
    List<int> bytes, {
    KemAlgorithm algorithm = KemAlgorithm.mlKem768,
    KeyMetadata metadata = const KeyMetadata(),
  }) => _keys.encryptionPublicKey(algorithm, bytes, metadata);

  /// Imports an encryption private key from its seed (64-byte `d || z` for
  /// ML-KEM, 32 bytes for X-Wing).
  EncryptionPrivateKey importEncryptionPrivateKeySeed(
    List<int> seed, {
    KemAlgorithm algorithm = KemAlgorithm.mlKem768,
    KeyMetadata metadata = const KeyMetadata(),
  }) => _keys.encryptionPrivateKeyFromSeed(
    algorithm,
    Uint8List.fromList(seed),
    metadata,
  );

  /// Imports an ML-KEM expanded decapsulation key (FIPS 203 `dk`). Keys
  /// imported this way cannot be exported in seed form.
  EncryptionPrivateKey importEncryptionPrivateKeyExpanded(
    List<int> expanded, {
    KemAlgorithm algorithm = KemAlgorithm.mlKem768,
    KeyMetadata metadata = const KeyMetadata(),
  }) => _keys.encryptionPrivateKeyFromExpanded(
    algorithm,
    Uint8List.fromList(expanded),
    metadata,
  );

  /// Imports a raw signing public key.
  SigningPublicKey importSigningPublicKey(
    List<int> bytes, {
    SignatureAlgorithm algorithm = SignatureAlgorithm.mlDsa65,
    KeyMetadata metadata = const KeyMetadata(),
  }) => _keys.signingPublicKey(algorithm, bytes, metadata);

  /// Imports a signing private key from its canonical private form (the
  /// 32-byte ML-DSA seed `ξ`, or the full SLH-DSA secret key).
  SigningPrivateKey importSigningPrivateKeySeed(
    List<int> seed, {
    SignatureAlgorithm algorithm = SignatureAlgorithm.mlDsa65,
    KeyMetadata metadata = const KeyMetadata(),
  }) => _keys.signingPrivateKeyFromSeed(
    algorithm,
    Uint8List.fromList(seed),
    metadata,
  );

  /// Imports an expanded ML-DSA secret key together with its public key,
  /// which is checked against the key's embedded `tr = H(pk)`.
  SigningPrivateKey importSigningPrivateKeyExpanded(
    List<int> secretKey, {
    required List<int> publicKey,
    SignatureAlgorithm algorithm = SignatureAlgorithm.mlDsa65,
    KeyMetadata metadata = const KeyMetadata(),
  }) => _keys.signingPrivateKeyFromExpanded(
    algorithm,
    Uint8List.fromList(secretKey),
    publicKey,
    metadata,
  );

  // ---------------------------------------------------------------------------
  // Envelope encryption
  // ---------------------------------------------------------------------------

  /// Encrypts [plaintext] once for every key in [recipients].
  ///
  /// A fresh random 256-bit data-encryption key encrypts the payload; for each
  /// recipient it is wrapped with HPKE (KEM → HKDF-SHA-384 → AEAD). [context]
  /// is authenticated application metadata (tenant, record id, purpose, ...);
  /// it is stored in clear and is not proof of who encrypted the data.
  EncryptedEnvelope encrypt(
    List<int> plaintext, {
    required List<EncryptionPublicKey> recipients,
    Map<String, String> context = const {},
    AeadAlgorithm aead = AeadAlgorithm.aes256Gcm,
  }) => _envelopes.encrypt(
    plaintext is Uint8List ? plaintext : Uint8List.fromList(plaintext),
    recipients,
    context,
    aead,
  );

  /// Parses a serialized envelope (structure only).
  EncryptedEnvelope parseEnvelope(List<int> bytes) =>
      EncryptedEnvelope.parse(ctx, Uint8List.fromList(bytes));

  /// Decrypts [envelope] with [privateKey].
  ///
  /// Plaintext is returned only after both the wrapped key and the payload
  /// authenticate. Every authentication failure raises the same
  /// [DecryptionFailedException]. When [requiredContext] is given, each of
  /// its entries must be present in the envelope's authenticated context
  /// ([ContextMismatchException] otherwise), which stops a valid ciphertext
  /// from being replayed into a different application context.
  Uint8List decrypt(
    EncryptedEnvelope envelope, {
    required EncryptionPrivateKey privateKey,
    Map<String, String>? requiredContext,
  }) => _envelopes.decrypt(envelope, privateKey, requiredContext);

  /// Parses and decrypts a serialized envelope.
  Uint8List decryptBytes(
    List<int> bytes, {
    required EncryptionPrivateKey privateKey,
    Map<String, String>? requiredContext,
  }) => decrypt(
    parseEnvelope(bytes),
    privateKey: privateKey,
    requiredContext: requiredContext,
  );

  /// Re-encrypts [envelope] for a new recipient set.
  ///
  /// Requires the private key of a current recipient. The payload is
  /// decrypted and encrypted again under a fresh data key, so the result
  /// shares no key material with the original. Removing a recipient this way
  /// does not revoke access to the original envelope or to anything the
  /// removed recipient already decrypted or copied.
  EncryptedEnvelope rewrapEnvelope(
    EncryptedEnvelope envelope, {
    required EncryptionPrivateKey privateKey,
    required List<EncryptionPublicKey> recipients,
    Map<String, String>? requiredContext,
  }) => _envelopes.rewrap(
    envelope,
    privateKey,
    recipients,
    requiredContext: requiredContext,
  );

  /// Adds recipients to an envelope (see [rewrapEnvelope]). The existing
  /// recipients must be supplied as public keys because the envelope only
  /// stores their identifiers.
  EncryptedEnvelope addRecipients(
    EncryptedEnvelope envelope, {
    required EncryptionPrivateKey privateKey,
    required List<EncryptionPublicKey> currentRecipients,
    required List<EncryptionPublicKey> newRecipients,
  }) {
    _checkCurrentRecipients(envelope, currentRecipients);
    return rewrapEnvelope(
      envelope,
      privateKey: privateKey,
      recipients: [...currentRecipients, ...newRecipients],
    );
  }

  /// Removes recipients from an envelope (see [rewrapEnvelope]).
  EncryptedEnvelope removeRecipients(
    EncryptedEnvelope envelope, {
    required EncryptionPrivateKey privateKey,
    required List<EncryptionPublicKey> currentRecipients,
    required Set<KeyId> remove,
  }) {
    _checkCurrentRecipients(envelope, currentRecipients);
    final remaining = [
      for (final r in currentRecipients)
        if (!remove.contains(r.keyId)) r,
    ];
    return rewrapEnvelope(
      envelope,
      privateKey: privateKey,
      recipients: remaining,
    );
  }

  void _checkCurrentRecipients(
    EncryptedEnvelope envelope,
    List<EncryptionPublicKey> current,
  ) {
    final have = {for (final r in envelope.recipients) r.keyId};
    final given = {for (final r in current) r.keyId};
    if (have.length != given.length || !have.containsAll(given)) {
      throw const InvalidInputException(
        'currentRecipients must match the envelope recipients exactly',
      );
    }
  }

  // ---------------------------------------------------------------------------
  // Streaming encryption
  // ---------------------------------------------------------------------------

  /// Encrypts [input] with bounded memory (about two chunks).
  ///
  /// The first event of the returned stream is the header, followed by one
  /// event per encrypted chunk; concatenated, they form the stream object.
  /// [chunkSize] is the plaintext bytes per chunk, within
  /// [ResourceLimits.minStreamChunkBytes]..[ResourceLimits.maxStreamChunkBytes].
  Stream<Uint8List> encryptStream(
    Stream<List<int>> input, {
    required List<EncryptionPublicKey> recipients,
    Map<String, String> context = const {},
    AeadAlgorithm aead = AeadAlgorithm.aes256Gcm,
    int chunkSize = defaultStreamChunkSize,
    ProgressCallback? onProgress,
    CancellationToken? cancel,
  }) => _streams.encrypt(
    input,
    recipients: recipients,
    context: context,
    aead: aead,
    chunkSize: chunkSize,
    onProgress: onProgress,
    cancel: cancel,
  );

  /// Decrypts a stream produced by [encryptStream].
  ///
  /// **Release semantics:** every emitted chunk has been authenticated in its
  /// position, but truncation of the whole stream is only detected at its
  /// end. Plaintext emitted before an error must be treated as unverified and
  /// discarded. For files, `decryptFile` in `post_quantum_crypto_io.dart` writes
  /// to a temporary file and publishes it only after full verification.
  Stream<Uint8List> decryptStream(
    Stream<List<int>> input, {
    required EncryptionPrivateKey privateKey,
    Map<String, String>? requiredContext,
    ProgressCallback? onProgress,
    CancellationToken? cancel,
  }) => _streams.decrypt(
    input,
    privateKey: privateKey,
    requiredContext: requiredContext,
    onProgress: onProgress,
    cancel: cancel,
  );

  // ---------------------------------------------------------------------------
  // Hybrid key establishment
  // ---------------------------------------------------------------------------

  /// Initiates X-Wing hybrid key establishment with [responder] (an X-Wing
  /// public key). Returns the message to send and the derived session key.
  ///
  /// Unauthenticated: see `HybridTranscript` and the library documentation
  /// for the exact guarantees.
  HybridKeyEstablishment establishHybridKey(
    EncryptionPublicKey responder, {
    required HybridTranscript transcript,
    int length = 32,
  }) => _hybrid.initiate(responder, transcript, length);

  /// Responder side of [establishHybridKey]. Any non-hybrid KEM identifier in
  /// [message] is rejected (downgrade protection).
  Uint8List acceptHybridKey(
    List<int> message, {
    required EncryptionPrivateKey privateKey,
    required HybridTranscript transcript,
    int length = 32,
  }) => _hybrid.accept(
    Uint8List.fromList(message),
    privateKey,
    transcript,
    length,
  );

  // ---------------------------------------------------------------------------
  // Key serialization
  // ---------------------------------------------------------------------------

  /// Serializes any key as a package-specific `PQCR` key record, including
  /// its [KeyMetadata]. Private keys are written in seed form when available.
  ///
  /// The result contains **unencrypted private key material** for private
  /// keys; prefer [exportPrivateKeyWithPassword] for storage or backup.
  Uint8List encodeKey(QuantumKey key) => _codec.encodeRecord(key);

  /// Parses a `PQCR` key record. Private keys are re-derived and must match
  /// the stored public key.
  QuantumKey decodeKey(List<int> bytes) =>
      _codec.decodeRecord(Uint8List.fromList(bytes));

  /// [decodeKey], requiring an [EncryptionPublicKey].
  EncryptionPublicKey decodeEncryptionPublicKey(List<int> bytes) =>
      _expect<EncryptionPublicKey>(decodeKey(bytes));

  /// [decodeKey], requiring an [EncryptionPrivateKey].
  EncryptionPrivateKey decodeEncryptionPrivateKey(List<int> bytes) =>
      _expect<EncryptionPrivateKey>(decodeKey(bytes));

  /// [decodeKey], requiring a [SigningPublicKey].
  SigningPublicKey decodeSigningPublicKey(List<int> bytes) =>
      _expect<SigningPublicKey>(decodeKey(bytes));

  /// [decodeKey], requiring a [SigningPrivateKey].
  SigningPrivateKey decodeSigningPrivateKey(List<int> bytes) =>
      _expect<SigningPrivateKey>(decodeKey(bytes));

  static T _expect<T extends QuantumKey>(QuantumKey key) {
    if (key is T) return key;
    throw InvalidKeyException('Expected a $T');
  }

  /// Encodes a public key as X.509 `SubjectPublicKeyInfo` DER (ML-KEM,
  /// ML-DSA and SLH-DSA; X-Wing has no standardized form).
  Uint8List exportPublicKeyDer(QuantumKey publicKey) =>
      _codec.encodeSpki(publicKey);

  /// PEM (`PUBLIC KEY`) form of [exportPublicKeyDer].
  String exportPublicKeyPem(QuantumKey publicKey) =>
      Pem.encode('PUBLIC KEY', exportPublicKeyDer(publicKey));

  /// Decodes `SubjectPublicKeyInfo` DER into an [EncryptionPublicKey] or
  /// [SigningPublicKey].
  QuantumKey importPublicKeyDer(List<int> der) =>
      _codec.decodeSpki(Uint8List.fromList(der));

  QuantumKey importPublicKeyPem(String pem) =>
      importPublicKeyDer(Pem.decode(pem, 'PUBLIC KEY'));

  /// Encodes a private key as unencrypted PKCS#8 `OneAsymmetricKey` DER.
  Uint8List exportPrivateKeyDer(
    QuantumKey privateKey, {
    PrivateKeyDerForm form = PrivateKeyDerForm.seed,
  }) => _codec.encodePkcs8(privateKey, form);

  String exportPrivateKeyPem(
    QuantumKey privateKey, {
    PrivateKeyDerForm form = PrivateKeyDerForm.seed,
  }) => Pem.encode('PRIVATE KEY', exportPrivateKeyDer(privateKey, form: form));

  /// Decodes unencrypted PKCS#8 DER (seed, expanded or both forms).
  QuantumKey importPrivateKeyDer(List<int> der) =>
      _codec.decodePkcs8(Uint8List.fromList(der));

  QuantumKey importPrivateKeyPem(String pem) =>
      importPrivateKeyDer(Pem.decode(pem, 'PRIVATE KEY'));

  // ---------------------------------------------------------------------------
  // Password protection
  // ---------------------------------------------------------------------------

  /// The Argon2id parameters used when none are given.
  Argon2idParameters get defaultArgon2idParameters => _password.defaults;

  /// Exports [privateKey] (with metadata) encrypted under [password] using
  /// Argon2id and AES-256-GCM. A fresh random salt and nonce are used each
  /// time. Parameters are checked against [PasswordPolicy] first.
  Uint8List exportPrivateKeyWithPassword(
    QuantumKey privateKey,
    String password, {
    Argon2idParameters? parameters,
  }) {
    if (!privateKey.isPrivate) {
      throw const InvalidInputException('Expected a private key');
    }
    final record = _codec.encodeRecord(privateKey);
    try {
      return _password.seal(
        ObjectType.passwordProtectedKey,
        record,
        password,
        parameters: parameters,
      );
    } finally {
      zeroize(record);
    }
  }

  /// Decrypts a password-protected key export. A wrong password or any
  /// tampering raises [DecryptionFailedException].
  QuantumKey importPrivateKeyWithPassword(List<int> bytes, String password) {
    final record = _password.open(
      ObjectType.passwordProtectedKey,
      Uint8List.fromList(bytes),
      password,
    );
    try {
      return _codec.decodeRecord(record);
    } finally {
      zeroize(record);
    }
  }

  /// Re-encrypts a password-protected key export under [newPassword], with a
  /// fresh salt and nonce and optionally new [parameters].
  Uint8List changeKeyPassword(
    List<int> bytes, {
    required String oldPassword,
    required String newPassword,
    Argon2idParameters? parameters,
  }) {
    final key = importPrivateKeyWithPassword(bytes, oldPassword);
    try {
      return exportPrivateKeyWithPassword(
        key,
        newPassword,
        parameters: parameters,
      );
    } finally {
      switch (key) {
        case EncryptionPrivateKey k:
          k.destroy();
        case SigningPrivateKey k:
          k.destroy();
        default:
      }
    }
  }

  /// Password-based (symmetric) encryption of application data. Distinct
  /// from public-key encryption: security rests entirely on the password.
  Uint8List encryptWithPassword(
    List<int> plaintext,
    String password, {
    Argon2idParameters? parameters,
    Map<String, String> context = const {},
    AeadAlgorithm aead = AeadAlgorithm.aes256Gcm,
  }) => _password.seal(
    ObjectType.passwordEncryptedData,
    Uint8List.fromList(plaintext),
    password,
    parameters: parameters,
    context: context,
    aead: aead,
  );

  Uint8List decryptWithPassword(
    List<int> bytes,
    String password, {
    Map<String, String>? requiredContext,
  }) => _password.open(
    ObjectType.passwordEncryptedData,
    Uint8List.fromList(bytes),
    password,
    requiredContext: requiredContext,
  );

  // ---------------------------------------------------------------------------
  // Raw signatures
  // ---------------------------------------------------------------------------

  /// Signs [message] with FIPS 204 / FIPS 205 pure signing (hedged) and the
  /// optional [context] string (≤ 255 bytes). The output is a standard
  /// signature verifiable by any conforming implementation.
  Uint8List sign(
    List<int> message, {
    required SigningPrivateKey privateKey,
    List<int> context = const [],
  }) {
    ctx.policy.checkSignature(privateKey.algorithm);
    ctx.policy.checkKeyMetadata(privateKey.metadata, KeyUsage.sign);
    final ctxBytes = checkSignatureContext(context);
    final prim = ctx.signature(privateKey.algorithm);
    final rnd = ctx.randomBytes(prim.randomnessLength);
    return prim.sign(
      privateKey.secretKey,
      message is Uint8List ? message : Uint8List.fromList(message),
      ctxBytes,
      rnd,
    );
  }

  /// Verifies a raw signature. Returns `false` for any invalid or malformed
  /// signature. A valid signature proves only that the holder of the
  /// matching private key signed [message]; whether that key is trusted is a
  /// separate decision.
  bool verify(
    List<int> message, {
    required List<int> signature,
    required SigningPublicKey publicKey,
    List<int> context = const [],
  }) {
    ctx.policy.checkSignature(publicKey.algorithm);
    ctx.policy.checkKeyMetadata(publicKey.metadata, KeyUsage.verify);
    final ctxBytes = checkSignatureContext(context);
    return ctx
        .signature(publicKey.algorithm)
        .verify(
          publicKey.bytes,
          message is Uint8List ? message : Uint8List.fromList(message),
          Uint8List.fromList(signature),
          ctxBytes,
        );
  }

  // ---------------------------------------------------------------------------
  // Signed objects
  // ---------------------------------------------------------------------------

  /// Creates a detached signature binding the SHA-384 digest and length of
  /// [content], the signer key id, [context] and [metadata].
  DetachedSignature signDetached(
    List<int> content, {
    required SigningPrivateKey privateKey,
    List<int> context = const [],
    Map<String, String> metadata = const {},
  }) => _signed.signDetached(
    privateKey,
    Uint8List.fromList(content),
    context,
    metadata,
  );

  /// Signs streamed content (for example a large file) with bounded memory.
  Future<DetachedSignature> signStream(
    Stream<List<int>> content, {
    required SigningPrivateKey privateKey,
    List<int> context = const [],
    Map<String, String> metadata = const {},
  }) => _signed.signStream(privateKey, content, context, metadata);

  DetachedSignature parseDetachedSignature(List<int> bytes) =>
      DetachedSignature.parse(ctx, Uint8List.fromList(bytes));

  /// Verifies [signature] over [content] with [publicKey]. Throws
  /// [SignatureVerificationException] if the signature, signer or content
  /// does not match.
  VerifiedSignature verifyDetached(
    List<int> content, {
    required DetachedSignature signature,
    required SigningPublicKey publicKey,
  }) =>
      _signed.verifyDetached(signature, Uint8List.fromList(content), publicKey);

  /// Streaming counterpart of [verifyDetached].
  Future<VerifiedSignature> verifyStream(
    Stream<List<int>> content, {
    required DetachedSignature signature,
    required SigningPublicKey publicKey,
  }) => _signed.verifyStream(signature, content, publicKey);

  /// Bundles [content] with its detached signature.
  SignedArtifact createSignedArtifact(
    List<int> content, {
    required SigningPrivateKey privateKey,
    List<int> context = const [],
    Map<String, String> metadata = const {},
  }) => _signed.createArtifact(
    privateKey,
    Uint8List.fromList(content),
    context,
    metadata,
  );

  SignedArtifact parseSignedArtifact(List<int> bytes) =>
      SignedArtifact.parse(ctx, Uint8List.fromList(bytes));

  /// Verifies a signed artifact and returns its content. Content is returned
  /// only after the signature verifies.
  ({Uint8List content, VerifiedSignature verified}) openSignedArtifact(
    List<int> bytes, {
    required SigningPublicKey publicKey,
  }) {
    final a = parseSignedArtifact(bytes);
    final v = _signed.verifyDetached(a.signature, a.content, publicKey);
    return (content: Uint8List.fromList(a.content), verified: v);
  }

  /// Computes a manifest entry for in-memory [content].
  ManifestEntry manifestEntry(String path, List<int> content) =>
      _signed.manifestEntry(path, Uint8List.fromList(content));

  /// Signs a manifest of files (paths, sizes, SHA-384 digests).
  SignedManifest createSignedManifest(
    List<ManifestEntry> entries, {
    required SigningPrivateKey privateKey,
    List<int> context = const [],
    Map<String, String> metadata = const {},
  }) => _signed.createManifest(privateKey, entries, context, metadata);

  SignedManifest parseSignedManifest(List<int> bytes) =>
      SignedManifest.parse(ctx, Uint8List.fromList(bytes));

  /// Verifies the manifest signature. Check each file against its entry
  /// separately (`verifyManifestFiles` in `post_quantum_crypto_io.dart`, or
  /// [manifestEntry] for in-memory content).
  VerifiedSignature verifyManifest(
    SignedManifest manifest, {
    required SigningPublicKey publicKey,
  }) => _signed.verifyManifest(manifest, publicKey);
}
