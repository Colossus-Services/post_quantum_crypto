import 'dart:convert';
import 'dart:typed_data';

import '../errors.dart';
import 'bytes.dart';

/// Magic bytes that open every serialized object: ASCII `PQCR`.
const List<int> formatMagic = [0x50, 0x51, 0x43, 0x52];

/// Format version 1, the version of every object type in 1.x.
const int formatVersion1 = 1;

/// Format version 2: key-committing envelopes, streams and password objects
/// (see doc/FORMAT_V2.md).
const int formatVersion2 = 2;

/// Object type codes (the byte following the version).
abstract final class ObjectType {
  static const int envelope = 0x01;
  static const int stream = 0x03;
  static const int signedArtifact = 0x04;
  static const int detachedSignature = 0x05;
  static const int manifest = 0x06;
  static const int keyRecord = 0x07;
  static const int passwordProtectedKey = 0x08;
  static const int passwordEncryptedData = 0x09;
  static const int hybridKeyMessage = 0x0a;
}

/// The format version written for objects of [type]. Versions are per type:
/// only the types whose layout changed moved to version 2, so objects of
/// the other types stay readable by 1.x.
int currentFormatVersion(int type) => switch (type) {
  ObjectType.envelope ||
  ObjectType.stream ||
  ObjectType.passwordProtectedKey ||
  ObjectType.passwordEncryptedData => formatVersion2,
  _ => formatVersion1,
};

/// Writes the common header `PQCR || version || type` with the current
/// version of [type].
void writeHeader(ByteWriter w, int type) {
  w
    ..raw(formatMagic)
    ..u8(currentFormatVersion(type))
    ..u8(type);
}

/// Reads and validates the common header and returns its version.
///
/// The current version of [expectedType] is always accepted. An older
/// version is accepted only with [acceptLegacy] (the policy's
/// `acceptLegacyFormats`); otherwise, and for unknown versions, it raises
/// [UnsupportedFormatException].
int readHeader(ByteReader r, int expectedType, {bool acceptLegacy = false}) {
  final magic = r.fixed(4);
  if (!constantTimeEquals(magic, formatMagic)) {
    throw const MalformedDataException('Not a post_quantum_crypto object');
  }
  final version = r.u8();
  final type = r.u8();
  if (type != expectedType) {
    throw const UnsupportedFormatException('Unexpected object type');
  }
  final current = currentFormatVersion(type);
  if (version == current) return version;
  if (version >= formatVersion1 && version < current) {
    if (acceptLegacy) return version;
    throw const UnsupportedFormatException(
      'Legacy format version; enable SecurityPolicy.acceptLegacyFormats '
      'to read it',
    );
  }
  throw const UnsupportedFormatException('Unsupported format version');
}

/// Limits applied when decoding a canonical string map.
typedef MapLimits = ({int maxEntries, int maxKeyBytes, int maxValueBytes});

/// Canonical encoding of a `Map<String, String>` (authenticated context,
/// signed metadata).
///
/// Layout: `u16 count`, then for each entry in strictly ascending order of the
/// UTF-8 key bytes: `u8 keyLen || key || u32 valueLen || value`. Keys must be
/// non-empty and unique. Because the order is fixed and duplicates are
/// impossible, every map has exactly one encoding, and the decoder rejects any
/// other byte sequence.
abstract final class CanonicalMap {
  static List<MapEntry<Uint8List, Uint8List>> _sortedEntries(
    Map<String, String> map,
  ) {
    final entries = [
      for (final e in map.entries)
        MapEntry(utf8BytesStrict(e.key), utf8BytesStrict(e.value)),
    ]..sort((a, b) => compareBytes(a.key, b.key));
    return entries;
  }

  static void write(ByteWriter w, Map<String, String> map, MapLimits limits) {
    if (map.length > limits.maxEntries) {
      throw const ResourceLimitExceededException('Too many map entries');
    }
    final entries = _sortedEntries(map);
    w.u16(entries.length);
    // Strict encoding is injective, so distinct keys stay distinct and
    // sorted strictly ascending, as the reader requires.
    for (final e in entries) {
      if (e.key.isEmpty) {
        throw const InvalidInputException('Map keys must not be empty');
      }
      if (e.key.length > limits.maxKeyBytes || e.key.length > 0xff) {
        throw const ResourceLimitExceededException('Map key too long');
      }
      if (e.value.length > limits.maxValueBytes) {
        throw const ResourceLimitExceededException('Map value too long');
      }
      w
        ..bytes8(e.key)
        ..bytes32(e.value);
    }
  }

  static Uint8List encode(Map<String, String> map, MapLimits limits) {
    final w = ByteWriter();
    write(w, map, limits);
    return w.toBytes();
  }

  static Map<String, String> read(ByteReader r, MapLimits limits) {
    final count = r.u16();
    if (count > limits.maxEntries) {
      throw const ResourceLimitExceededException('Too many map entries');
    }
    final out = <String, String>{};
    Uint8List? previous;
    for (var i = 0; i < count; i++) {
      final key = r.bytes8(max: limits.maxKeyBytes.clamp(0, 0xff));
      if (key.isEmpty) {
        throw const MalformedDataException('Empty map key');
      }
      if (previous != null && compareBytes(previous, key) >= 0) {
        throw const MalformedDataException('Map keys not in canonical order');
      }
      previous = key;
      final value = r.bytes32(max: limits.maxValueBytes);
      try {
        out[utf8.decode(key)] = utf8.decode(value);
      } on FormatException {
        throw const MalformedDataException('Map entry is not valid UTF-8');
      }
    }
    return Map.unmodifiable(out);
  }
}

/// Lexicographic comparison of byte strings.
int compareBytes(List<int> a, List<int> b) {
  final n = a.length < b.length ? a.length : b.length;
  for (var i = 0; i < n; i++) {
    final d = a[i] - b[i];
    if (d != 0) return d;
  }
  return a.length - b.length;
}
