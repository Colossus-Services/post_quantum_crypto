import 'algorithms/algorithms.dart';
import 'errors.dart';
import 'keys/key_metadata.dart';

/// Size, count and allocation limits applied while encoding and parsing.
///
/// Parsers check every length field against these limits before slicing or
/// allocating, so hostile input cannot force a large allocation.
final class ResourceLimits {
  /// Maximum plaintext size of a one-shot envelope. Use streaming for
  /// larger payloads.
  final int maxEnvelopePayloadBytes;

  /// Maximum number of recipients in an envelope or stream header.
  final int maxRecipients;

  /// Maximum number of entries in an authenticated context or metadata map.
  final int maxContextEntries;

  /// Maximum UTF-8 length of a context/metadata key (≤ 255).
  final int maxContextKeyBytes;

  /// Maximum UTF-8 length of a context/metadata value.
  final int maxContextValueBytes;

  /// Smallest accepted stream chunk size.
  final int minStreamChunkBytes;

  /// Largest accepted stream chunk size.
  final int maxStreamChunkBytes;

  /// Maximum content size of an attached signed artifact.
  final int maxSignedContentBytes;

  /// Maximum number of entries in a signed manifest.
  final int maxManifestEntries;

  /// Maximum length of a manifest path in UTF-8 bytes.
  final int maxManifestPathBytes;

  const ResourceLimits({
    this.maxEnvelopePayloadBytes = 256 * 1024 * 1024,
    this.maxRecipients = 256,
    this.maxContextEntries = 64,
    this.maxContextKeyBytes = 255,
    this.maxContextValueBytes = 64 * 1024,
    this.minStreamChunkBytes = 256,
    this.maxStreamChunkBytes = 16 * 1024 * 1024,
    this.maxSignedContentBytes = 256 * 1024 * 1024,
    this.maxManifestEntries = 100000,
    this.maxManifestPathBytes = 4096,
  });
}

/// Bounds and defaults for Argon2id password protection (RFC 9106).
///
/// Bounds are checked on both export and import, before Argon2id allocates
/// its memory, so a hostile file cannot request gigabytes of RAM.
final class PasswordPolicy {
  final int minMemoryKiB;
  final int maxMemoryKiB;
  final int minIterations;
  final int maxIterations;
  final int maxParallelism;

  /// Minimum password length in UTF-8 bytes.
  final int minPasswordBytes;

  /// Parameters used when the caller does not supply any:
  /// 64 MiB, 3 passes, 1 lane (RFC 9106 §4 second recommended option scaled
  /// for constrained devices; OWASP's minimum is 19 MiB / 2 passes).
  final int defaultMemoryKiB;
  final int defaultIterations;
  final int defaultParallelism;

  const PasswordPolicy({
    this.minMemoryKiB = 8 * 1024,
    this.maxMemoryKiB = 1024 * 1024,
    this.minIterations = 1,
    this.maxIterations = 16,
    this.maxParallelism = 16,
    this.minPasswordBytes = 1,
    this.defaultMemoryKiB = 64 * 1024,
    this.defaultIterations = 3,
    this.defaultParallelism = 1,
  });
}

/// Application security policy.
///
/// Checked before expensive work: a prohibited algorithm is rejected before
/// any decapsulation, signature or Argon2id computation runs.
final class SecurityPolicy {
  /// KEMs that may be used. Defaults to every supported KEM.
  final Set<KemAlgorithm> allowedKems;

  /// Signature algorithms that may be used.
  final Set<SignatureAlgorithm> allowedSignatures;

  /// AEADs that may be used.
  final Set<AeadAlgorithm> allowedAeads;

  /// Minimum NIST security category for KEMs and signatures.
  final int minimumSecurityCategory;

  /// Require hybrid (X-Wing) KEMs for every recipient.
  final bool requireHybridKem;

  /// Reject keys whose `expiresAt` lies in the past.
  final bool rejectExpiredKeys;

  /// Reject keys that carry revocation metadata.
  final bool rejectRevokedKeys;

  /// Enforce [KeyMetadata.usages] restrictions.
  final bool enforceKeyUsage;

  /// Whether objects in an older, still-supported format version are read
  /// (see "Format evolution" in doc/FORMATS.md). Writers always produce the
  /// current version. No older version is supported by this release (format
  /// 1 from package 1.x is not read), so this has no effect yet; it is the
  /// opt-in through which a future format version can keep reading this one.
  final bool acceptLegacyFormats;

  final ResourceLimits limits;

  final PasswordPolicy password;

  final DateTime Function()? _clock;

  const SecurityPolicy({
    this.allowedKems = const {...KemAlgorithm.values},
    this.allowedSignatures = const {...SignatureAlgorithm.values},
    this.allowedAeads = const {...AeadAlgorithm.values},
    this.minimumSecurityCategory = 1,
    this.requireHybridKem = false,
    this.rejectExpiredKeys = true,
    this.rejectRevokedKeys = true,
    this.enforceKeyUsage = true,
    this.acceptLegacyFormats = false,
    this.limits = const ResourceLimits(),
    this.password = const PasswordPolicy(),
    DateTime Function()? clock,
  }) : _clock = clock;

  /// The default policy: every supported NIST parameter set, expired and
  /// revoked keys rejected, usage restrictions enforced.
  static const SecurityPolicy standard = SecurityPolicy();

  /// Category 3 or higher only (excludes ML-KEM-512, ML-DSA-44 and the
  /// 128-bit SLH-DSA sets).
  static const SecurityPolicy strict = SecurityPolicy(
    minimumSecurityCategory: 3,
  );

  DateTime now() => (_clock ?? DateTime.now)();

  void checkKem(KemAlgorithm a) {
    if (!allowedKems.contains(a)) {
      throw PolicyViolationException('${a.standardName} is not permitted');
    }
    if (a.securityCategory < minimumSecurityCategory) {
      throw PolicyViolationException(
        '${a.standardName} is below the minimum security category',
      );
    }
    if (requireHybridKem && !a.isHybrid) {
      throw const PolicyViolationException('A hybrid KEM is required');
    }
  }

  void checkSignature(SignatureAlgorithm a) {
    if (!allowedSignatures.contains(a)) {
      throw PolicyViolationException('${a.standardName} is not permitted');
    }
    if (a.securityCategory < minimumSecurityCategory) {
      throw PolicyViolationException(
        '${a.standardName} is below the minimum security category',
      );
    }
  }

  void checkAead(AeadAlgorithm a) {
    if (!allowedAeads.contains(a)) {
      throw PolicyViolationException('${a.standardName} is not permitted');
    }
  }

  /// Validates lifecycle metadata and usage of a key for [usage].
  void checkKeyMetadata(KeyMetadata m, KeyUsage usage) {
    if (rejectRevokedKeys && m.isRevoked) {
      throw const PolicyViolationException('Key has been revoked');
    }
    if (rejectExpiredKeys && m.isExpiredAt(now())) {
      throw const PolicyViolationException('Key has expired');
    }
    if (enforceKeyUsage && !m.allows(usage)) {
      throw PolicyViolationException('Key usage ${usage.name} not permitted');
    }
  }

  SecurityPolicy copyWith({
    Set<KemAlgorithm>? allowedKems,
    Set<SignatureAlgorithm>? allowedSignatures,
    Set<AeadAlgorithm>? allowedAeads,
    int? minimumSecurityCategory,
    bool? requireHybridKem,
    bool? rejectExpiredKeys,
    bool? rejectRevokedKeys,
    bool? enforceKeyUsage,
    bool? acceptLegacyFormats,
    ResourceLimits? limits,
    PasswordPolicy? password,
    DateTime Function()? clock,
  }) => SecurityPolicy(
    allowedKems: allowedKems ?? this.allowedKems,
    allowedSignatures: allowedSignatures ?? this.allowedSignatures,
    allowedAeads: allowedAeads ?? this.allowedAeads,
    minimumSecurityCategory:
        minimumSecurityCategory ?? this.minimumSecurityCategory,
    requireHybridKem: requireHybridKem ?? this.requireHybridKem,
    rejectExpiredKeys: rejectExpiredKeys ?? this.rejectExpiredKeys,
    rejectRevokedKeys: rejectRevokedKeys ?? this.rejectRevokedKeys,
    enforceKeyUsage: enforceKeyUsage ?? this.enforceKeyUsage,
    acceptLegacyFormats: acceptLegacyFormats ?? this.acceptLegacyFormats,
    limits: limits ?? this.limits,
    password: password ?? this.password,
    clock: clock ?? _clock,
  );
}
