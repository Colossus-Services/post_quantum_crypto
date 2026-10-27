/// [SymmetricProvider] backed by PointyCastle.
///
/// This is the only file that imports PointyCastle.
library;

import 'dart:typed_data';

import 'package:pointycastle/export.dart' as pc;

import '../algorithms/algorithms.dart';
import '../errors.dart';
import 'primitives.dart';

/// PointyCastle implementation of the symmetric primitives.
final class PointyCastleSymmetricProvider implements SymmetricProvider {
  const PointyCastleSymmetricProvider();

  @override
  HashFunction hash(HashAlgorithm algorithm) => switch (algorithm) {
    HashAlgorithm.sha256 ||
    HashAlgorithm.sha384 ||
    HashAlgorithm.sha512 => _PcHash(algorithm),
    HashAlgorithm.sha3_256 => throw const UnsupportedAlgorithmException(
      'SHA3-256 is provided by the Keccak provider',
    ),
  };

  @override
  MacFunction hmac(HashAlgorithm algorithm) => _PcHmac(algorithm);

  @override
  Kdf kdf(KdfAlgorithm algorithm) => _Hkdf(algorithm, _PcHmac(algorithm.hash));

  @override
  AeadCipher aead(AeadAlgorithm algorithm, {int? keyLength}) =>
      switch (algorithm) {
        AeadAlgorithm.aes256Gcm => _AesGcm(keyLength ?? 32),
        AeadAlgorithm.chacha20Poly1305 => const _ChaCha20Poly1305(),
      };

  @override
  Argon2idPrimitive get argon2id => const _PcArgon2id();
}

pc.Digest _digest(HashAlgorithm algorithm) => switch (algorithm) {
  HashAlgorithm.sha256 => pc.SHA256Digest(),
  HashAlgorithm.sha384 => pc.SHA384Digest(),
  HashAlgorithm.sha512 => pc.SHA512Digest(),
  HashAlgorithm.sha3_256 => throw const UnsupportedAlgorithmException(
    'SHA3-256 is provided by the Keccak provider',
  ),
};

final class _PcHash implements HashFunction {
  @override
  final HashAlgorithm algorithm;

  const _PcHash(this.algorithm);

  @override
  Uint8List hash(List<int> data) {
    final d = _digest(algorithm);
    return d.process(data is Uint8List ? data : Uint8List.fromList(data));
  }

  @override
  HashSink start() => _PcHashSink(_digest(algorithm));
}

final class _PcHashSink implements HashSink {
  final pc.Digest _d;
  bool _closed = false;

  _PcHashSink(this._d);

  @override
  void add(List<int> data) {
    if (_closed) throw StateError('HashSink already closed');
    final bytes = data is Uint8List ? data : Uint8List.fromList(data);
    _d.update(bytes, 0, bytes.length);
  }

  @override
  Uint8List close() {
    if (_closed) throw StateError('HashSink already closed');
    _closed = true;
    final out = Uint8List(_d.digestSize);
    _d.doFinal(out, 0);
    return out;
  }
}

final class _PcHmac implements MacFunction {
  final HashAlgorithm _algorithm;

  const _PcHmac(this._algorithm);

  @override
  int get length => _algorithm.digestLength;

  @override
  Uint8List compute(Uint8List key, List<int> data) {
    final mac = pc.HMac(_digest(_algorithm), _algorithm.blockLength)
      ..init(pc.KeyParameter(key));
    return mac.process(data is Uint8List ? data : Uint8List.fromList(data));
  }
}

/// RFC 5869 HKDF over PointyCastle's HMAC. Implemented here (rather than via
/// `HKDFKeyDerivator`) because HPKE needs Extract and Expand separately.
final class _Hkdf implements Kdf {
  @override
  final KdfAlgorithm algorithm;
  final MacFunction _hmac;

  const _Hkdf(this.algorithm, this._hmac);

  @override
  Uint8List extract(Uint8List? salt, Uint8List ikm) {
    final s = (salt == null || salt.isEmpty)
        ? Uint8List(algorithm.hashLength)
        : salt;
    return _hmac.compute(s, ikm);
  }

  @override
  Uint8List expand(Uint8List prk, Uint8List info, int length) {
    final hashLen = algorithm.hashLength;
    if (length < 0 || length > 255 * hashLen) {
      throw const InvalidInputException('HKDF output length out of range');
    }
    if (prk.length < hashLen) {
      throw const InvalidInputException('HKDF PRK too short');
    }
    final out = Uint8List(length);
    var t = Uint8List(0);
    var offset = 0;
    for (var i = 1; offset < length; i++) {
      final input = Uint8List(t.length + info.length + 1)
        ..setAll(0, t)
        ..setAll(t.length, info)
        ..[t.length + info.length] = i;
      t = _hmac.compute(prk, input);
      final n = (length - offset) < hashLen ? length - offset : hashLen;
      out.setRange(offset, offset + n, t);
      offset += n;
    }
    return out;
  }
}

final class _AesGcm implements AeadCipher {
  @override
  final int keyLength;

  const _AesGcm(this.keyLength);

  @override
  int get nonceLength => 12;

  @override
  int get tagLength => 16;

  void _check(Uint8List key, Uint8List nonce) {
    if (key.length != keyLength) {
      throw const InvalidInputException('AES-GCM key has wrong length');
    }
    if (nonce.length != nonceLength) {
      throw const InvalidInputException('AES-GCM nonce has wrong length');
    }
  }

  pc.GCMBlockCipher _cipher(
    bool encrypt,
    Uint8List key,
    Uint8List nonce,
    Uint8List aad,
  ) => pc.GCMBlockCipher(pc.AESEngine())
    ..init(encrypt, pc.AEADParameters(pc.KeyParameter(key), 128, nonce, aad));

  @override
  Uint8List seal(
    Uint8List key,
    Uint8List nonce,
    Uint8List plaintext,
    Uint8List aad,
  ) {
    _check(key, nonce);
    return _cipher(true, key, nonce, aad).process(plaintext);
  }

  @override
  Uint8List? open(
    Uint8List key,
    Uint8List nonce,
    Uint8List ciphertextWithTag,
    Uint8List aad,
  ) {
    _check(key, nonce);
    if (ciphertextWithTag.length < tagLength) return null;
    try {
      return _cipher(false, key, nonce, aad).process(ciphertextWithTag);
    } on pc.InvalidCipherTextException {
      return null;
    } on ArgumentError {
      return null;
    }
  }
}

final class _ChaCha20Poly1305 implements AeadCipher {
  const _ChaCha20Poly1305();

  @override
  int get keyLength => 32;

  @override
  int get nonceLength => 12;

  @override
  int get tagLength => 16;

  Uint8List _run(
    bool encrypt,
    Uint8List key,
    Uint8List nonce,
    Uint8List input,
    Uint8List aad,
  ) {
    if (key.length != keyLength) {
      throw const InvalidInputException('ChaCha20 key has wrong length');
    }
    if (nonce.length != nonceLength) {
      throw const InvalidInputException('ChaCha20 nonce has wrong length');
    }
    final cipher = pc.ChaCha20Poly1305(pc.ChaCha7539Engine(), pc.Poly1305())
      ..init(encrypt, pc.AEADParameters(pc.KeyParameter(key), 128, nonce, aad));
    final out = Uint8List(cipher.getOutputSize(input.length));
    var len = cipher.processBytes(input, 0, input.length, out, 0);
    len += cipher.doFinal(out, len);
    return len == out.length ? out : Uint8List.sublistView(out, 0, len);
  }

  @override
  Uint8List seal(
    Uint8List key,
    Uint8List nonce,
    Uint8List plaintext,
    Uint8List aad,
  ) => _run(true, key, nonce, plaintext, aad);

  @override
  Uint8List? open(
    Uint8List key,
    Uint8List nonce,
    Uint8List ciphertextWithTag,
    Uint8List aad,
  ) {
    if (ciphertextWithTag.length < tagLength) return null;
    try {
      return _run(false, key, nonce, ciphertextWithTag, aad);
    } on pc.InvalidCipherTextException {
      return null;
    } on ArgumentError {
      return null;
    } on StateError {
      return null;
    }
  }
}

final class _PcArgon2id implements Argon2idPrimitive {
  const _PcArgon2id();

  @override
  Uint8List derive({
    required Uint8List password,
    required Uint8List salt,
    required int memoryKiB,
    required int iterations,
    required int parallelism,
    required int length,
    Uint8List? secret,
    Uint8List? associatedData,
  }) {
    final params = pc.Argon2Parameters(
      pc.Argon2Parameters.ARGON2_id,
      Uint8List.fromList(salt),
      desiredKeyLength: length,
      secret: secret == null ? null : Uint8List.fromList(secret),
      additional: associatedData == null
          ? null
          : Uint8List.fromList(associatedData),
      iterations: iterations,
      memory: memoryKiB,
      lanes: parallelism,
      version: pc.Argon2Parameters.ARGON2_VERSION_13,
    );
    final gen = pc.Argon2BytesGenerator()..init(params);
    final out = Uint8List(length);
    gen.deriveKey(password, 0, out, 0);
    return out;
  }
}
