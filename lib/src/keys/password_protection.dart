/// Password-based protection with Argon2id (RFC 9106) and an AEAD.
///
/// Used for password-protected private-key exports (object type 0x08) and,
/// as a separate feature, password-based encryption of application data
/// (object type 0x09). Password-based encryption is symmetric: anyone who
/// knows or guesses the password can decrypt. It provides no post-quantum
/// public-key property and its strength is bounded by the password.
///
/// Layout:
///
/// ```text
/// "PQCR" u8 version=1 u8 type (0x08 key / 0x09 data)
/// u8  kdf = 0x01 (Argon2id, version 0x13)
/// u32 memoryKiB | u32 iterations | u8 parallelism
/// 16  salt
/// u16 aeadId
/// context (canonical map, authenticated)
/// 12  nonce
///   ── aad = all bytes so far
/// u32 ciphertextLength | ciphertext || tag
/// ```
library;

import 'dart:typed_data';

import 'package:meta/meta.dart';

import '../algorithms/algorithms.dart';
import '../context.dart';
import '../encoding/bytes.dart';
import '../encoding/canonical.dart';
import '../encryption/key_wrapping.dart' show checkRequiredContext;
import '../errors.dart';

/// Argon2id cost parameters.
final class Argon2idParameters {
  /// Memory in KiB.
  final int memoryKiB;

  /// Number of passes.
  final int iterations;

  /// Number of lanes.
  final int parallelism;

  const Argon2idParameters({
    required this.memoryKiB,
    required this.iterations,
    required this.parallelism,
  });

  @override
  String toString() =>
      'Argon2idParameters(m=${memoryKiB}KiB, t=$iterations, p=$parallelism)';
}

const int _kdfArgon2id = 0x01;
const int _saltLength = 16;

/// Upper bound for the protected payload of a password object.
const int _maxPasswordPayload = 256 * 1024 * 1024;

@internal
final class PasswordProtection {
  final CryptoContext _ctx;

  PasswordProtection(this._ctx);

  Argon2idParameters get defaults => Argon2idParameters(
    memoryKiB: _ctx.policy.password.defaultMemoryKiB,
    iterations: _ctx.policy.password.defaultIterations,
    parallelism: _ctx.policy.password.defaultParallelism,
  );

  /// Validates [p] against the policy. Called before Argon2id runs, on both
  /// encryption and decryption, so hostile parameters never allocate.
  void checkParameters(Argon2idParameters p) {
    final pol = _ctx.policy.password;
    if (p.parallelism < 1 || p.parallelism > pol.maxParallelism) {
      throw const ResourceLimitExceededException(
        'Argon2id parallelism out of range',
      );
    }
    if (p.iterations < pol.minIterations || p.iterations > pol.maxIterations) {
      throw const ResourceLimitExceededException(
        'Argon2id iterations out of range',
      );
    }
    if (p.memoryKiB < pol.minMemoryKiB ||
        p.memoryKiB > pol.maxMemoryKiB ||
        p.memoryKiB < 8 * p.parallelism) {
      throw const ResourceLimitExceededException(
        'Argon2id memory out of range',
      );
    }
  }

  Uint8List _deriveKey(
    String password,
    Uint8List salt,
    Argon2idParameters p,
    int length,
  ) {
    final pw = utf8Bytes(password);
    try {
      return _ctx.backend.symmetric.argon2id.derive(
        password: pw,
        salt: salt,
        memoryKiB: p.memoryKiB,
        iterations: p.iterations,
        parallelism: p.parallelism,
        length: length,
      );
    } finally {
      zeroize(pw);
    }
  }

  void _checkPassword(String password) {
    if (utf8Bytes(password).length < _ctx.policy.password.minPasswordBytes) {
      throw const InvalidInputException('Password is too short');
    }
  }

  Uint8List seal(
    int type,
    Uint8List plaintext,
    String password, {
    Argon2idParameters? parameters,
    AeadAlgorithm aead = AeadAlgorithm.aes256Gcm,
    Map<String, String> context = const {},
  }) {
    _checkPassword(password);
    final p = parameters ?? defaults;
    checkParameters(p);
    _ctx.policy.checkAead(aead);
    if (plaintext.length > _maxPasswordPayload) {
      throw const ResourceLimitExceededException('Payload too large');
    }
    final salt = _ctx.randomBytes(_saltLength);
    final nonce = _ctx.randomBytes(aead.nonceLength);
    final w = ByteWriter();
    writeHeader(w, type);
    w
      ..u8(_kdfArgon2id)
      ..u32(p.memoryKiB)
      ..u32(p.iterations)
      ..u8(p.parallelism)
      ..raw(salt)
      ..u16(aead.id);
    CanonicalMap.write(w, context, _ctx.mapLimits);
    w.raw(nonce);
    final aad = w.toBytes();
    final key = _deriveKey(password, salt, p, aead.keyLength);
    try {
      w.bytes32(_ctx.aead(aead).seal(key, nonce, plaintext, aad));
    } finally {
      zeroize(key);
    }
    return w.toBytes();
  }

  /// Parsed header of a password object.
  ({
    Argon2idParameters parameters,
    Uint8List salt,
    AeadAlgorithm aead,
    Map<String, String> context,
    Uint8List nonce,
    Uint8List aad,
    Uint8List ciphertext,
  })
  parse(int type, Uint8List bytes) => parseStrict(() {
    final r = ByteReader(bytes);
    readHeader(r, type);
    if (r.u8() != _kdfArgon2id) {
      throw const UnsupportedAlgorithmException('Unsupported password KDF');
    }
    final p = Argon2idParameters(
      memoryKiB: r.u32(),
      iterations: r.u32(),
      parallelism: r.u8(),
    );
    final salt = r.fixed(_saltLength);
    final aead = AeadAlgorithm.fromId(r.u16());
    final context = CanonicalMap.read(r, _ctx.mapLimits);
    final nonce = r.fixed(aead.nonceLength);
    final aad = Uint8List.fromList(Uint8List.sublistView(bytes, 0, r.offset));
    final ct = r.bytes32(max: _maxPasswordPayload + aead.tagLength);
    r.expectEnd();
    return (
      parameters: p,
      salt: salt,
      aead: aead,
      context: context,
      nonce: nonce,
      aad: aad,
      ciphertext: ct,
    );
  });

  Uint8List open(
    int type,
    Uint8List bytes,
    String password, {
    Map<String, String>? requiredContext,
  }) {
    final o = parse(type, bytes);
    // Policy and parameter bounds before the expensive derivation.
    _ctx.policy.checkAead(o.aead);
    checkParameters(o.parameters);
    checkRequiredContext(o.context, requiredContext);
    final key = _deriveKey(password, o.salt, o.parameters, o.aead.keyLength);
    try {
      final pt = _ctx.aead(o.aead).open(key, o.nonce, o.ciphertext, o.aad);
      if (pt == null) throw const DecryptionFailedException();
      return pt;
    } finally {
      zeroize(key);
    }
  }
}
