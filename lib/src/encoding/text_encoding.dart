import 'dart:convert';
import 'dart:typed_data';

import '../errors.dart';

/// Textual transport encodings. Binary serialization stays the canonical
/// representation of every object; these are lossless wrappers around it.
abstract final class TextEncoding {
  static const _hexDigits = '0123456789abcdef';

  /// Lower-case hexadecimal.
  static String toHex(List<int> bytes) {
    final sb = StringBuffer();
    for (final b in bytes) {
      sb
        ..write(_hexDigits[(b >> 4) & 0xf])
        ..write(_hexDigits[b & 0xf]);
    }
    return sb.toString();
  }

  /// Decodes hexadecimal (either case). Whitespace is not accepted.
  static Uint8List fromHex(String hex) {
    if (hex.length.isOdd) {
      throw const MalformedDataException('Hex string has odd length');
    }
    final out = Uint8List(hex.length ~/ 2);
    for (var i = 0; i < out.length; i++) {
      final hi = _hexValue(hex.codeUnitAt(2 * i));
      final lo = _hexValue(hex.codeUnitAt(2 * i + 1));
      out[i] = (hi << 4) | lo;
    }
    return out;
  }

  static int _hexValue(int c) {
    if (c >= 0x30 && c <= 0x39) return c - 0x30;
    if (c >= 0x61 && c <= 0x66) return c - 0x61 + 10;
    if (c >= 0x41 && c <= 0x46) return c - 0x41 + 10;
    throw const MalformedDataException('Invalid hex character');
  }

  /// Unpadded Base64URL (RFC 4648 §5).
  static String toBase64Url(List<int> bytes) =>
      base64Url.encode(bytes).replaceAll('=', '');

  /// Decodes Base64URL with or without padding. Standard-alphabet input
  /// (`+`, `/`) is rejected.
  static Uint8List fromBase64Url(String text) {
    if (text.contains('+') || text.contains('/')) {
      throw const MalformedDataException('Not Base64URL');
    }
    try {
      return base64Url.decode(base64Url.normalize(text));
    } on FormatException {
      throw const MalformedDataException('Invalid Base64URL');
    }
  }
}
