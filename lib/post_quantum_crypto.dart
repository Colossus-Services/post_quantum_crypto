/// High-level post-quantum cryptography for Dart.
///
/// - **Encryption**: ML-KEM-768 (FIPS 203) envelopes with HPKE key wrapping
///   (RFC 9180) and AES-256-GCM, for one or many recipients, one-shot or
///   streaming.
/// - **Signatures**: ML-DSA-65 (FIPS 204), optional SLH-DSA (FIPS 205),
///   detached signatures, signed artifacts and manifests.
/// - **Hybrid**: X-Wing (ML-KEM-768 + X25519) recipients and key
///   establishment.
/// - **Keys**: seed-form keys, fingerprints, metadata, SPKI/PKCS#8 DER,
///   Argon2id-protected exports, key stores.
///
/// Start with [PostQuantumCrypto] for defaults, or create a
/// [PostQuantumCryptoEngine] with a custom [SecurityPolicy] or [CryptoBackend].
/// File helpers live in `package:post_quantum_crypto/post_quantum_crypto_io.dart`.
library;

export 'src/algorithms/algorithms.dart';
export 'src/background/background.dart';
export 'src/encoding/text_encoding.dart';
export 'src/encryption/envelope.dart' show EncryptedEnvelope, EnvelopeRecipient;
export 'src/encryption/streaming.dart'
    show
        CancellationToken,
        ProgressCallback,
        StreamHeader,
        defaultStreamChunkSize;
export 'src/engine.dart';
export 'src/hybrid/hybrid_key_establishment.dart'
    show HybridKeyEstablishment, HybridTranscript;
export 'src/errors.dart';
export 'src/keys/key_metadata.dart';
export 'src/keys/key_serialization.dart' show PrivateKeyDerForm;
export 'src/keys/key_store.dart';
export 'src/keys/keys.dart';
export 'src/keys/password_protection.dart' show Argon2idParameters;
export 'src/policy.dart';
export 'src/providers/default_backend.dart';
export 'src/providers/primitives.dart';
export 'src/post_quantum_crypto_facade.dart';
export 'src/random/secure_random.dart'
    show SecureRandomSource, SystemSecureRandom;
export 'src/signatures/signed_objects.dart'
    show
        DetachedSignature,
        ManifestEntry,
        SignedArtifact,
        SignedManifest,
        TrustDecision,
        TrustStore,
        VerifiedSignature;
export 'src/version.dart';
