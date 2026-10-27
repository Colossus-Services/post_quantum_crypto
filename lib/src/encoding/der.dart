/// Minimal strict DER (X.690) for the fixed SPKI / PKCS#8 structures used by
/// ML-KEM, ML-DSA and SLH-DSA keys. Only definite, minimally encoded lengths
/// are accepted.
library;

import 'dart:convert';
import 'dart:typed_data';

import '../errors.dart';
import 'bytes.dart';

abstract final class DerTag {
  static const int integer = 0x02;
  static const int bitString = 0x03;
  static const int octetString = 0x04;
  static const int oid = 0x06;
  static const int sequence = 0x30;

  /// `[0] IMPLICIT OCTET STRING` (the `seed` CHOICE of the private-key
  /// formats).
  static const int contextPrimitive0 = 0x80;

  /// `[0]` constructed (PKCS#8 `attributes`).
  static const int contextConstructed0 = 0xa0;

  /// `[1] IMPLICIT BIT STRING` (PKCS#8 v2 `publicKey`).
  static const int contextPrimitive1 = 0x81;
}

/// Encodes one TLV.
Uint8List derTlv(int tag, List<int> value) {
  final len = value.length;
  final List<int> lenBytes;
  if (len < 0x80) {
    lenBytes = [len];
  } else {
    final digits = <int>[];
    for (var v = len; v > 0; v >>= 8) {
      digits.insert(0, v & 0xff);
    }
    lenBytes = [0x80 | digits.length, ...digits];
  }
  return concatBytes([
    [tag],
    lenBytes,
    value,
  ]);
}

Uint8List derSequence(List<List<int>> items) =>
    derTlv(DerTag.sequence, concatBytes(items));

/// A decoded TLV.
typedef DerElement = ({int tag, Uint8List value});

/// Reads TLVs from a buffer.
final class DerReader {
  final Uint8List _data;
  int _offset = 0;

  DerReader(this._data);

  bool get isAtEnd => _offset == _data.length;

  DerElement read() {
    if (_data.length - _offset < 2) {
      throw const MalformedDataException('Truncated DER');
    }
    final tag = _data[_offset++];
    if (tag & 0x1f == 0x1f) {
      throw const MalformedDataException('Unsupported DER tag');
    }
    var len = _data[_offset++];
    if (len & 0x80 != 0) {
      final n = len & 0x7f;
      if (n == 0 || n > 3 || _data.length - _offset < n) {
        throw const MalformedDataException('Invalid DER length');
      }
      if (_data[_offset] == 0) {
        throw const MalformedDataException('Non-minimal DER length');
      }
      len = 0;
      for (var i = 0; i < n; i++) {
        len = (len << 8) | _data[_offset++];
      }
      if (len < 0x80) {
        throw const MalformedDataException('Non-minimal DER length');
      }
    }
    if (_data.length - _offset < len) {
      throw const MalformedDataException('Truncated DER');
    }
    final value = Uint8List.fromList(
      Uint8List.sublistView(_data, _offset, _offset + len),
    );
    _offset += len;
    return (tag: tag, value: value);
  }

  Uint8List expect(int tag) {
    final e = read();
    if (e.tag != tag) {
      throw const MalformedDataException('Unexpected DER tag');
    }
    return e.value;
  }

  void expectEnd() {
    if (!isAtEnd) {
      throw const MalformedDataException('Trailing DER data');
    }
  }
}

/// Encodes a dotted OID string as DER content bytes.
Uint8List encodeOid(String dotted) {
  final parts = dotted.split('.').map(int.parse).toList();
  final out = <int>[40 * parts[0] + parts[1]];
  for (final p in parts.skip(2)) {
    final stack = <int>[p & 0x7f];
    for (var v = p >> 7; v > 0; v >>= 7) {
      stack.insert(0, 0x80 | (v & 0x7f));
    }
    out.addAll(stack);
  }
  return Uint8List.fromList(out);
}

/// PEM armor (RFC 7468).
abstract final class Pem {
  static String encode(String label, List<int> der) {
    final b64 = base64.encode(der);
    final lines = [
      for (var i = 0; i < b64.length; i += 64)
        b64.substring(i, i + 64 > b64.length ? b64.length : i + 64),
    ];
    return '-----BEGIN $label-----\n${lines.join('\n')}\n-----END $label-----\n';
  }

  static Uint8List decode(String pem, String label) {
    final begin = '-----BEGIN $label-----';
    final end = '-----END $label-----';
    final s = pem.indexOf(begin);
    final e = pem.indexOf(end);
    if (s < 0 || e < s) {
      throw MalformedDataException('Missing PEM $label block');
    }
    final body = pem
        .substring(s + begin.length, e)
        .replaceAll(RegExp(r'\s'), '');
    try {
      return base64.decode(body);
    } on FormatException {
      throw const MalformedDataException('Invalid PEM base64');
    }
  }
}
