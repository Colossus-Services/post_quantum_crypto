import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:post_quantum_crypto/src/encoding/text_encoding.dart';

/// Loads a JSON vector file from `test/vectors/`.
dynamic loadVectors(String name) =>
    jsonDecode(File('test/vectors/$name').readAsStringSync());

/// Decodes a hex JSON value (either case).
Uint8List hex(Object? s) => TextEncoding.fromHex(s! as String);

/// Iterates over the tests of a Wycheproof file, yielding (group, test).
Iterable<(Map<String, dynamic>, Map<String, dynamic>)> wycheproofTests(
  String name,
) sync* {
  final json = loadVectors(name) as Map<String, dynamic>;
  for (final g in (json['testGroups'] as List).cast<Map<String, dynamic>>()) {
    for (final t in (g['tests'] as List).cast<Map<String, dynamic>>()) {
      yield (g, t);
    }
  }
}

/// Iterates over the tests of an ACVP internal projection.
Iterable<(Map<String, dynamic>, Map<String, dynamic>)> acvpTests(
  String name,
) sync* {
  final json = loadVectors(name) as Map<String, dynamic>;
  for (final g in (json['testGroups'] as List).cast<Map<String, dynamic>>()) {
    for (final t in (g['tests'] as List).cast<Map<String, dynamic>>()) {
      yield (g, t);
    }
  }
}
