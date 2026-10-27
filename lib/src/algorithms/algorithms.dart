import '../errors.dart';

/// Key-encapsulation mechanisms usable for encryption keys.
///
/// The [id] is the IANA HPKE KEM identifier (RFC 9180 registry, values from
/// draft-ietf-hpke-pq), and is what appears on the wire.
enum KemAlgorithm {
  /// ML-KEM-512 (FIPS 203), NIST security category 1.
  mlKem512(0x0040, 'ML-KEM-512', 1, 800, 768, 64, false),

  /// ML-KEM-768 (FIPS 203), NIST security category 3. The default.
  mlKem768(0x0041, 'ML-KEM-768', 3, 1184, 1088, 64, false),

  /// ML-KEM-1024 (FIPS 203), NIST security category 5.
  mlKem1024(0x0042, 'ML-KEM-1024', 5, 1568, 1568, 64, false),

  /// X-Wing: ML-KEM-768 combined with X25519 (draft-connolly-cfrg-xwing-kem).
  /// Secure if either component is secure. Category 3 post-quantum.
  xWing(0x647a, 'X-Wing', 3, 1216, 1120, 32, true);

  /// Wire identifier (HPKE KEM id).
  final int id;

  /// Standard name.
  final String standardName;

  /// NIST post-quantum security category.
  final int securityCategory;

  /// Encapsulation (public) key length in bytes.
  final int publicKeyLength;

  /// Encapsulation ciphertext length in bytes.
  final int ciphertextLength;

  /// Length of the private key seed in bytes (the canonical private form).
  final int seedLength;

  /// Whether the KEM combines a classical and a post-quantum component.
  final bool isHybrid;

  const KemAlgorithm(
    this.id,
    this.standardName,
    this.securityCategory,
    this.publicKeyLength,
    this.ciphertextLength,
    this.seedLength,
    this.isHybrid,
  );

  /// Shared-secret length in bytes (32 for every supported KEM).
  int get sharedSecretLength => 32;

  /// Randomness consumed by one encapsulation.
  int get encapsulationRandomLength => isHybrid ? 64 : 32;

  static KemAlgorithm fromId(int id) {
    for (final a in values) {
      if (a.id == id) return a;
    }
    throw const UnsupportedAlgorithmException('Unknown KEM identifier');
  }
}

/// Digital-signature algorithms usable for signing keys.
enum SignatureAlgorithm {
  /// ML-DSA-44 (FIPS 204), NIST security category 2.
  mlDsa44(0x0101, 'ML-DSA-44', 2, 1312, 2420, 32),

  /// ML-DSA-65 (FIPS 204), NIST security category 3. The default.
  mlDsa65(0x0102, 'ML-DSA-65', 3, 1952, 3309, 32),

  /// ML-DSA-87 (FIPS 204), NIST security category 5.
  mlDsa87(0x0103, 'ML-DSA-87', 5, 2592, 4627, 32),

  /// SLH-DSA-SHAKE-128s (FIPS 205). Small signatures, very slow signing.
  slhDsaShake128s(0x0201, 'SLH-DSA-SHAKE-128s', 1, 32, 7856, 64),

  /// SLH-DSA-SHAKE-128f (FIPS 205). Faster signing, larger signatures.
  slhDsaShake128f(0x0202, 'SLH-DSA-SHAKE-128f', 1, 32, 17088, 64),

  /// SLH-DSA-SHAKE-192s (FIPS 205).
  slhDsaShake192s(0x0203, 'SLH-DSA-SHAKE-192s', 3, 48, 16224, 96),

  /// SLH-DSA-SHAKE-192f (FIPS 205).
  slhDsaShake192f(0x0204, 'SLH-DSA-SHAKE-192f', 3, 48, 35664, 96),

  /// SLH-DSA-SHAKE-256s (FIPS 205).
  slhDsaShake256s(0x0205, 'SLH-DSA-SHAKE-256s', 5, 64, 29792, 128),

  /// SLH-DSA-SHAKE-256f (FIPS 205).
  slhDsaShake256f(0x0206, 'SLH-DSA-SHAKE-256f', 5, 64, 49856, 128);

  /// Package wire identifier.
  final int id;

  /// Standard name.
  final String standardName;

  /// NIST post-quantum security category.
  final int securityCategory;

  /// Public key length in bytes.
  final int publicKeyLength;

  /// Signature length in bytes.
  final int signatureLength;

  /// Length of the canonical private form: the 32-byte seed for ML-DSA, the
  /// full secret key (`SK.seed || SK.prf || PK.seed || PK.root`) for SLH-DSA.
  final int privateKeyLength;

  const SignatureAlgorithm(
    this.id,
    this.standardName,
    this.securityCategory,
    this.publicKeyLength,
    this.signatureLength,
    this.privateKeyLength,
  );

  /// Whether this is an ML-DSA parameter set.
  bool get isMlDsa => id >> 8 == 0x01;

  /// Whether this is an SLH-DSA parameter set.
  bool get isSlhDsa => id >> 8 == 0x02;

  static SignatureAlgorithm fromId(int id) {
    for (final a in values) {
      if (a.id == id) return a;
    }
    throw const UnsupportedAlgorithmException('Unknown signature identifier');
  }
}

/// Authenticated-encryption algorithms. [id] is the HPKE AEAD identifier.
enum AeadAlgorithm {
  /// AES-256-GCM with a 96-bit nonce and 128-bit tag. The default.
  aes256Gcm(0x0002, 'AES-256-GCM', 32),

  /// ChaCha20-Poly1305 (RFC 8439).
  chacha20Poly1305(0x0003, 'ChaCha20-Poly1305', 32);

  final int id;
  final String standardName;
  final int keyLength;

  const AeadAlgorithm(this.id, this.standardName, this.keyLength);

  int get nonceLength => 12;

  int get tagLength => 16;

  static AeadAlgorithm fromId(int id) {
    for (final a in values) {
      if (a.id == id) return a;
    }
    throw const UnsupportedAlgorithmException('Unknown AEAD identifier');
  }
}

/// Key-derivation functions. [id] is the HPKE KDF identifier.
enum KdfAlgorithm {
  /// HKDF-SHA-256.
  hkdfSha256(0x0001, 'HKDF-SHA-256', 32),

  /// HKDF-SHA-384. The default.
  hkdfSha384(0x0002, 'HKDF-SHA-384', 48),

  /// HKDF-SHA-512.
  hkdfSha512(0x0003, 'HKDF-SHA-512', 64);

  final int id;
  final String standardName;
  final int hashLength;

  const KdfAlgorithm(this.id, this.standardName, this.hashLength);

  HashAlgorithm get hash => switch (this) {
    hkdfSha256 => HashAlgorithm.sha256,
    hkdfSha384 => HashAlgorithm.sha384,
    hkdfSha512 => HashAlgorithm.sha512,
  };

  static KdfAlgorithm fromId(int id) {
    for (final a in values) {
      if (a.id == id) return a;
    }
    throw const UnsupportedAlgorithmException('Unknown KDF identifier');
  }
}

/// Hash functions.
enum HashAlgorithm {
  sha256(0x01, 'SHA-256', 32, 64),
  sha384(0x02, 'SHA-384', 48, 128),
  sha512(0x03, 'SHA-512', 64, 128),
  sha3_256(0x11, 'SHA3-256', 32, 136);

  final int id;
  final String standardName;
  final int digestLength;
  final int blockLength;

  const HashAlgorithm(
    this.id,
    this.standardName,
    this.digestLength,
    this.blockLength,
  );

  static HashAlgorithm fromId(int id) {
    for (final a in values) {
      if (a.id == id) return a;
    }
    throw const UnsupportedAlgorithmException('Unknown hash identifier');
  }
}
