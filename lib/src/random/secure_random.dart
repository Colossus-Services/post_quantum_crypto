import 'dart:math';
import 'dart:typed_data';

import '../errors.dart';

/// A source of cryptographically secure random bytes.
abstract interface class SecureRandomSource {
  /// Returns [length] fresh random bytes.
  Uint8List nextBytes(int length);
}

/// The platform CSPRNG exposed by `Random.secure()`.
///
/// On the Dart VM this reads the operating system generator; in browsers it is
/// `crypto.getRandomValues`. When the platform has no secure generator,
/// `Random.secure()` throws, and this source raises
/// [SecureRandomUnavailableException]. There is no fallback to a weaker
/// generator.
final class SystemSecureRandom implements SecureRandomSource {
  static final SystemSecureRandom instance = SystemSecureRandom._();

  Random? _random;

  SystemSecureRandom._();

  Random _rng() {
    final r = _random;
    if (r != null) return r;
    try {
      return _random = Random.secure();
    } on UnsupportedError {
      throw const SecureRandomUnavailableException();
    }
  }

  @override
  Uint8List nextBytes(int length) {
    if (length < 0) {
      throw const InvalidInputException('Negative random length');
    }
    final rng = _rng();
    final out = Uint8List(length);
    try {
      // nextInt(1 << 32) is not supported on all platforms; draw 16 bits.
      var i = 0;
      for (; i + 1 < length; i += 2) {
        final v = rng.nextInt(0x10000);
        out[i] = v >> 8;
        out[i + 1] = v & 0xff;
      }
      if (i < length) out[i] = rng.nextInt(0x100);
    } on UnsupportedError {
      throw const SecureRandomUnavailableException();
    }
    return out;
  }
}
