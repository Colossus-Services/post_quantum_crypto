/// Primitives backed by the pure-Dart implementations of
/// `package:cryptography`: X25519, AES-GCM and SHA-2.
///
/// This is the only file that imports package:cryptography.
library;

import 'dart:typed_data';

import 'package:cryptography/cryptography.dart' as c;
import 'package:cryptography/dart.dart' as cd;

import '../algorithms/algorithms.dart';
import '../errors.dart';
import 'primitives.dart';

/// AES-GCM via `DartAesGcm` (table-based GHASH; roughly an order of
/// magnitude faster than PointyCastle's GCM in pure Dart). The tag is
/// compared in constant time by `Mac.==`.
final class CryptographyAesGcm implements AeadCipher {
  @override
  final int keyLength;
  final cd.DartAesGcm _impl;

  CryptographyAesGcm([this.keyLength = 32])
    : _impl = cd.DartAesGcm(secretKeyLength: keyLength);

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

  @override
  Uint8List seal(
    Uint8List key,
    Uint8List nonce,
    Uint8List plaintext,
    Uint8List aad,
  ) {
    _check(key, nonce);
    final box = _impl.encryptSync(
      plaintext,
      secretKeyData: c.SecretKeyData(key),
      nonce: nonce,
      aad: aad,
    );
    final ct = box.cipherText;
    final out = Uint8List(ct.length + tagLength)
      ..setAll(0, ct)
      ..setAll(ct.length, box.mac.bytes);
    return out;
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
    final split = ciphertextWithTag.length - tagLength;
    try {
      final pt = _impl.decryptSync(
        c.SecretBox(
          Uint8List.sublistView(ciphertextWithTag, 0, split),
          nonce: nonce,
          mac: c.Mac(Uint8List.sublistView(ciphertextWithTag, split)),
        ),
        secretKeyData: c.SecretKeyData(key),
        aad: aad,
      );
      return pt is Uint8List ? pt : Uint8List.fromList(pt);
    } on c.SecretBoxAuthenticationError {
      return null;
    }
  }
}

/// ChaCha20-Poly1305 (RFC 8439) via `DartChacha20.poly1305Aead`. Unlike
/// PointyCastle's Poly1305 it avoids 64-bit integers, so it also runs when
/// compiled to JavaScript.
final class CryptographyChaCha20Poly1305 implements AeadCipher {
  static const _impl = cd.DartChacha20.poly1305Aead();

  const CryptographyChaCha20Poly1305();

  @override
  int get keyLength => 32;

  @override
  int get nonceLength => 12;

  @override
  int get tagLength => 16;

  void _check(Uint8List key, Uint8List nonce) {
    if (key.length != keyLength) {
      throw const InvalidInputException('ChaCha20 key has wrong length');
    }
    if (nonce.length != nonceLength) {
      throw const InvalidInputException('ChaCha20 nonce has wrong length');
    }
  }

  @override
  Uint8List seal(
    Uint8List key,
    Uint8List nonce,
    Uint8List plaintext,
    Uint8List aad,
  ) {
    _check(key, nonce);
    final box = _impl.encryptSync(
      plaintext,
      secretKey: c.SecretKeyData(key),
      nonce: nonce,
      aad: aad,
    );
    return Uint8List(box.cipherText.length + tagLength)
      ..setAll(0, box.cipherText)
      ..setAll(box.cipherText.length, box.mac.bytes);
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
    final split = ciphertextWithTag.length - tagLength;
    try {
      final pt = _impl.decryptSync(
        c.SecretBox(
          Uint8List.sublistView(ciphertextWithTag, 0, split),
          nonce: nonce,
          mac: c.Mac(Uint8List.sublistView(ciphertextWithTag, split)),
        ),
        secretKey: c.SecretKeyData(key),
        aad: aad,
      );
      return pt is Uint8List ? pt : Uint8List.fromList(pt);
    } on c.SecretBoxAuthenticationError {
      return null;
    }
  }
}

/// SHA-256/384/512 via package:cryptography (backed by package:crypto).
final class CryptographySha2 implements HashFunction {
  @override
  final HashAlgorithm algorithm;

  const CryptographySha2(this.algorithm);

  cd.DartHashAlgorithmMixin get _impl => switch (algorithm) {
    HashAlgorithm.sha256 => const cd.DartSha256(),
    HashAlgorithm.sha384 => const cd.DartSha384(),
    HashAlgorithm.sha512 => const cd.DartSha512(),
    HashAlgorithm.sha3_256 => throw const UnsupportedAlgorithmException(
      'SHA3-256 is provided by the Keccak provider',
    ),
  };

  @override
  Uint8List hash(List<int> data) =>
      Uint8List.fromList(_impl.hashSync(data).bytes);

  @override
  HashSink start() => _Sha2Sink(_impl.newHashSink());
}

final class _Sha2Sink implements HashSink {
  final cd.DartHashSink _sink;
  bool _closed = false;

  _Sha2Sink(this._sink);

  @override
  void add(List<int> data) {
    if (_closed) throw StateError('HashSink already closed');
    _sink.add(data);
  }

  @override
  Uint8List close() {
    if (_closed) throw StateError('HashSink already closed');
    _closed = true;
    _sink.close();
    return Uint8List.fromList(_sink.hashSync().bytes);
  }
}

/// X25519 via `DartX25519` (pure Dart: VM, JavaScript and WebAssembly).
final class CryptographyX25519 implements X25519Primitive {
  const CryptographyX25519();

  static const _impl = cd.DartX25519();

  static final Uint8List _basePoint = Uint8List(32)..[0] = 9;

  @override
  Uint8List publicKey(Uint8List scalar) => sharedSecret(scalar, _basePoint);

  @override
  Uint8List sharedSecret(Uint8List scalar, Uint8List point) {
    if (scalar.length != 32 || point.length != 32) {
      throw const InvalidInputException('X25519 inputs must be 32 bytes');
    }
    // DartX25519 clamps the scalar itself (RFC 7748 decodeScalar25519).
    final keyPair = c.SimpleKeyPairData(
      Uint8List.fromList(scalar),
      publicKey: c.SimplePublicKey(_basePoint, type: c.KeyPairType.x25519),
      type: c.KeyPairType.x25519,
    );
    final secret = _impl.sharedSecretSync(
      keyPairData: keyPair,
      remotePublicKey: c.SimplePublicKey(
        Uint8List.fromList(point),
        type: c.KeyPairType.x25519,
      ),
    );
    final bytes = (secret as c.SecretKeyData).bytes;
    return Uint8List.fromList(bytes);
  }
}
