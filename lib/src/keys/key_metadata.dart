import 'dart:convert';

import '../encoding/bytes.dart';
import '../encoding/text_encoding.dart';
import '../errors.dart';

/// Operations a key may be used for.
enum KeyUsage {
  /// Encrypt to an encryption public key.
  encrypt(0x01),

  /// Decrypt with an encryption private key.
  decrypt(0x02),

  /// Sign with a signing private key.
  sign(0x04),

  /// Verify with a signing public key.
  verify(0x08);

  final int bit;

  const KeyUsage(this.bit);

  static Set<KeyUsage> fromMask(int mask) => {
    for (final u in values)
      if (mask & u.bit != 0) u,
  };

  static int toMask(Set<KeyUsage> usages) =>
      usages.fold(0, (m, u) => m | u.bit);
}

/// A key identifier: a SHA-256 fingerprint of the algorithm and public key.
///
/// `KeyId = SHA-256("post_quantum_crypto/v1/key-id" || 0x00 || kind || u16 alg ||
/// publicKey)`, where `kind` is 1 for encryption and 2 for signing keys. The
/// identifier is public and is not a secret.
final class KeyId {
  /// Identifier length in bytes.
  static const int length = 32;

  final Bytes _bytes;

  KeyId(List<int> bytes) : _bytes = immutableCopy(bytes) {
    if (bytes.length != length) {
      throw const InvalidInputException('KeyId must be 32 bytes');
    }
  }

  Bytes get bytes => _bytes;

  /// Lower-case hex of all 32 bytes.
  String get hex => TextEncoding.toHex(_bytes);

  /// Short human-readable fingerprint: the first 16 bytes in colon-separated
  /// groups of two bytes. Suitable for display, not for comparisons.
  String get fingerprint {
    final h = TextEncoding.toHex(_bytes.sublist(0, 16));
    return [
      for (var i = 0; i < h.length; i += 4) h.substring(i, i + 4),
    ].join(':');
  }

  @override
  bool operator ==(Object other) =>
      other is KeyId && constantTimeEquals(other._bytes, _bytes);

  @override
  int get hashCode => Object.hashAll(_bytes.take(8));

  @override
  String toString() => 'KeyId($hex)';
}

/// Lifecycle metadata attached to a key.
final class KeyMetadata {
  /// When the key was created, if known.
  final DateTime? createdAt;

  /// After this instant the key is expired.
  final DateTime? expiresAt;

  /// When the key was revoked, if it was.
  final DateTime? revokedAt;

  /// A free-form revocation reason (not secret).
  final String? revocationReason;

  /// Operations the key may be used for. Empty means "unrestricted".
  final Set<KeyUsage> usages;

  /// A caller-chosen label.
  final String? label;

  /// The key this key replaces (rotation chain).
  final KeyId? replaces;

  const KeyMetadata({
    this.createdAt,
    this.expiresAt,
    this.revokedAt,
    this.revocationReason,
    this.usages = const {},
    this.label,
    this.replaces,
  });

  bool get isRevoked => revokedAt != null;

  bool isExpiredAt(DateTime now) =>
      expiresAt != null && !now.isBefore(expiresAt!);

  bool allows(KeyUsage usage) => usages.isEmpty || usages.contains(usage);

  /// Returns a copy with some fields replaced. Throws like [checkLimits].
  KeyMetadata copyWith({
    DateTime? createdAt,
    DateTime? expiresAt,
    DateTime? revokedAt,
    String? revocationReason,
    Set<KeyUsage>? usages,
    String? label,
    KeyId? replaces,
  }) => KeyMetadata(
    createdAt: createdAt ?? this.createdAt,
    expiresAt: expiresAt ?? this.expiresAt,
    revokedAt: revokedAt ?? this.revokedAt,
    revocationReason: revocationReason ?? this.revocationReason,
    usages: usages ?? this.usages,
    label: label ?? this.label,
    replaces: replaces ?? this.replaces,
  )..checkLimits();

  /// Checks that [label] and [revocationReason] can be stored: at most 4096
  /// UTF-8 bytes each ([ResourceLimitExceededException]) and no unpaired
  /// UTF-16 surrogates ([InvalidInputException]).
  ///
  /// The constructor is `const` and cannot check; every key checks its
  /// metadata when it is created (generation, import, `withMetadata`), so an
  /// invalid label fails where it is introduced rather than when the key is
  /// later saved.
  void checkLimits() {
    _text(label, 'Key label');
    _text(revocationReason, 'Revocation reason');
  }

  /// Canonical encoding (part of the key-record format).
  ///
  /// `u8 flags || [i64 created] || [i64 expires] || [i64 revoked ||
  /// u16 reason] || u8 usageMask || u16 label || [32 replaces]`; the flag bits
  /// mark which optional fields are present. Times are milliseconds since the
  /// Unix epoch, UTC.
  void write(ByteWriter w) {
    final flags =
        (createdAt != null ? 0x01 : 0) |
        (expiresAt != null ? 0x02 : 0) |
        (revokedAt != null ? 0x04 : 0) |
        (replaces != null ? 0x08 : 0);
    w.u8(flags);
    if (createdAt != null) w.u64(_ms(createdAt!));
    if (expiresAt != null) w.u64(_ms(expiresAt!));
    if (revokedAt != null) {
      w
        ..u64(_ms(revokedAt!))
        ..bytes16(_text(revocationReason, 'Revocation reason'));
    }
    w
      ..u8(KeyUsage.toMask(usages))
      ..bytes16(_text(label, 'Key label'));
    if (replaces != null) w.fixed(replaces!.bytes, KeyId.length);
  }

  static KeyMetadata read(ByteReader r) {
    final flags = r.u8();
    if (flags & ~0x0f != 0) {
      throw const MalformedDataException('Unknown key metadata flags');
    }
    final created = flags & 0x01 != 0 ? _date(r.u64()) : null;
    final expires = flags & 0x02 != 0 ? _date(r.u64()) : null;
    DateTime? revoked;
    String? reason;
    if (flags & 0x04 != 0) {
      revoked = _date(r.u64());
      reason = _utf8(r.bytes16(max: _maxTextBytes));
    }
    final mask = r.u8();
    if (mask & ~0x0f != 0) {
      throw const MalformedDataException('Unknown key usage bits');
    }
    final label = _utf8(r.bytes16(max: _maxTextBytes));
    final replaces = flags & 0x08 != 0 ? KeyId(r.fixed(KeyId.length)) : null;
    return KeyMetadata(
      createdAt: created,
      expiresAt: expires,
      revokedAt: revoked,
      revocationReason: (reason == null || reason.isEmpty) ? null : reason,
      usages: KeyUsage.fromMask(mask),
      label: label.isEmpty ? null : label,
      replaces: replaces,
    );
  }

  static int _ms(DateTime d) {
    final ms = d.toUtc().millisecondsSinceEpoch;
    if (ms < 0) {
      throw const InvalidInputException('Key dates before 1970 unsupported');
    }
    return ms;
  }

  /// Largest UTF-8 label or revocation reason, enforced on write and read so
  /// every record this package writes can be read back.
  static const int _maxTextBytes = 4096;

  static Bytes _text(String? s, String what) {
    final b = utf8Bytes(s ?? '');
    if (b.length > _maxTextBytes) {
      throw ResourceLimitExceededException(
        '$what exceeds $_maxTextBytes bytes',
      );
    }
    return b;
  }

  static DateTime _date(int ms) {
    // u64 values can exceed DateTime's range (±8.64e15 ms).
    try {
      return DateTime.fromMillisecondsSinceEpoch(ms, isUtc: true);
    } on ArgumentError {
      // RangeError on the VM; a plain ArgumentError on some web targets.
      throw const MalformedDataException('Key metadata date out of range');
    }
  }

  static String _utf8(Bytes b) {
    try {
      return utf8.decode(b);
    } on FormatException {
      throw const MalformedDataException('Invalid UTF-8 in key metadata');
    }
  }
}
