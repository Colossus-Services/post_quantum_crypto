import 'dart:convert';
import 'dart:typed_data';

import '../errors.dart';

/// A byte string. All cryptographic APIs in this package use [Uint8List].
typedef Bytes = Uint8List;

/// Concatenates [parts] into a new [Bytes].
Bytes concatBytes(List<List<int>> parts) {
  var length = 0;
  for (final p in parts) {
    length += p.length;
  }
  final out = Uint8List(length);
  var offset = 0;
  for (final p in parts) {
    out.setAll(offset, p);
    offset += p.length;
  }
  return out;
}

/// Compares [a] and [b] in time that depends only on their lengths.
///
/// Dart offers no hard constant-time guarantee (JIT, AOT, JavaScript and
/// WebAssembly all may optimise differently); this avoids the obvious
/// early-exit timing leak.
bool constantTimeEquals(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  var diff = 0;
  for (var i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff == 0;
}

/// Overwrites [bytes] with zeros (best-effort).
///
/// Clearing a Dart buffer does not guarantee that no other copy of the data
/// exists: the garbage collector, the JavaScript engine or the operating
/// system may have copied it.
void zeroize(Uint8List? bytes) {
  bytes?.fillRange(0, bytes.length, 0);
}

/// Returns an unmodifiable view of a private copy of [bytes].
Bytes immutableCopy(List<int> bytes) =>
    Uint8List.fromList(bytes).asUnmodifiableView();

/// UTF-8 encodes [s].
Bytes utf8Bytes(String s) => Uint8List.fromList(utf8.encode(s));

/// Writes the canonical big-endian binary encodings used by every format in
/// this package.
final class ByteWriter {
  final BytesBuilder _builder = BytesBuilder(copy: true);

  /// Number of bytes written so far.
  int get length => _builder.length;

  void u8(int v) {
    _checkRange(v, 0xff, 'u8');
    _builder.addByte(v);
  }

  void u16(int v) {
    _checkRange(v, 0xffff, 'u16');
    _builder.add([v >> 8, v & 0xff]);
  }

  void u32(int v) {
    _checkRange(v, 0xffffffff, 'u32');
    _builder.add([
      (v >> 24) & 0xff,
      (v >> 16) & 0xff,
      (v >> 8) & 0xff,
      v & 0xff,
    ]);
  }

  /// Writes a non-negative integer below 2^53 as 8 big-endian bytes.
  ///
  /// The 2^53 bound keeps the encoding identical on the VM and on JavaScript,
  /// where integers are IEEE-754 doubles.
  void u64(int v) {
    if (v < 0 || v > _maxSafeInteger) {
      throw const InvalidInputException('u64 value out of range');
    }
    final hi = v ~/ 0x100000000;
    final lo = v - hi * 0x100000000;
    u32(hi);
    u32(lo);
  }

  /// Writes [bytes] verbatim (fixed-length field).
  void raw(List<int> bytes) => _builder.add(bytes);

  /// Writes a fixed-length field, asserting its length.
  void fixed(List<int> bytes, int length) {
    if (bytes.length != length) {
      throw const InvalidInputException('Fixed-length field has wrong length');
    }
    _builder.add(bytes);
  }

  /// Writes a u8 length prefix followed by [bytes].
  void bytes8(List<int> bytes) {
    u8(bytes.length);
    _builder.add(bytes);
  }

  /// Writes a u16 length prefix followed by [bytes].
  void bytes16(List<int> bytes) {
    u16(bytes.length);
    _builder.add(bytes);
  }

  /// Writes a u32 length prefix followed by [bytes].
  void bytes32(List<int> bytes) {
    u32(bytes.length);
    _builder.add(bytes);
  }

  Bytes toBytes() => _builder.toBytes();

  static void _checkRange(int v, int max, String what) {
    if (v < 0 || v > max) {
      throw InvalidInputException('$what value out of range');
    }
  }
}

const int _maxSafeInteger = 9007199254740991;

/// Thrown internally by [ByteReader] when more input is needed. Incremental
/// parsers catch it; one-shot parsers translate it into
/// [MalformedDataException].
final class InsufficientDataError implements Exception {
  const InsufficientDataError();
}

/// Strict reader for the canonical encodings written by [ByteWriter].
///
/// Every length prefix is checked against both a caller-supplied maximum and
/// the bytes actually remaining before any data is sliced, so a hostile
/// length field can never trigger a large allocation.
final class ByteReader {
  final Uint8List _data;
  int _offset;

  ByteReader(Uint8List data, [int offset = 0]) : _data = data, _offset = offset;

  int get offset => _offset;

  int get remaining => _data.length - _offset;

  bool get isAtEnd => _offset == _data.length;

  void _need(int n) {
    if (n > remaining) throw const InsufficientDataError();
  }

  int u8() {
    _need(1);
    return _data[_offset++];
  }

  int u16() {
    _need(2);
    final v = (_data[_offset] << 8) | _data[_offset + 1];
    _offset += 2;
    return v;
  }

  int u32() {
    _need(4);
    final v =
        (_data[_offset] * 0x1000000) +
        ((_data[_offset + 1] << 16) |
            (_data[_offset + 2] << 8) |
            _data[_offset + 3]);
    _offset += 4;
    return v;
  }

  int u64() {
    final hi = u32();
    final lo = u32();
    if (hi > 0x1fffff) {
      throw const MalformedDataException('u64 value out of range');
    }
    return hi * 0x100000000 + lo;
  }

  /// Reads exactly [length] bytes. Returns a copy.
  Bytes fixed(int length) {
    _need(length);
    final out = Uint8List.fromList(
      Uint8List.sublistView(_data, _offset, _offset + length),
    );
    _offset += length;
    return out;
  }

  /// Reads exactly [length] bytes as a view into the input (no copy). Only
  /// for inputs the parser owns.
  Bytes view(int length) {
    _need(length);
    final out = Uint8List.sublistView(_data, _offset, _offset + length);
    _offset += length;
    return out;
  }

  /// A u32 length prefix followed by that many bytes, returned as a view.
  Bytes view32({required int max}) {
    final length = u32();
    if (length > max) {
      throw const ResourceLimitExceededException(
        'Encoded field exceeds its size limit',
      );
    }
    return view(length);
  }

  Bytes bytes8({int max = 0xff}) => _prefixed(u8(), max);

  Bytes bytes16({int max = 0xffff}) => _prefixed(u16(), max);

  Bytes bytes32({required int max}) => _prefixed(u32(), max);

  Bytes _prefixed(int length, int max) {
    if (length > max) {
      throw const ResourceLimitExceededException(
        'Encoded field exceeds its size limit',
      );
    }
    return fixed(length);
  }

  /// Fails unless every byte has been consumed. Trailing data is never
  /// silently ignored.
  void expectEnd() {
    if (!isAtEnd) {
      throw const MalformedDataException('Unexpected trailing bytes');
    }
  }
}

/// Runs a one-shot parser, translating premature end of input into
/// [MalformedDataException] and any non-package error into one too.
T parseStrict<T>(T Function() parse) {
  try {
    return parse();
  } on InsufficientDataError {
    throw const MalformedDataException('Truncated data');
  } on QuantumCryptoException {
    rethrow;
  } on FormatException {
    throw const MalformedDataException('Invalid encoding');
  }
}
