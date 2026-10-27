// Regenerates test/vectors/post_quantum_crypto_v2.json.
//
// Usage: dart run test/vectors/generate_format_vectors.dart
//
// Only regenerate deliberately: a change here means the wire format changed,
// which requires a new format version (and a new vector file).
import 'dart:convert';
import 'dart:io';

import 'format_vectors.dart';

Future<void> main() async {
  final vectors = await buildFormatVectors();
  File('test/vectors/post_quantum_crypto_v2.json').writeAsStringSync(
    '${const JsonEncoder.withIndent('  ').convert(vectors)}\n',
  );
  stdout.writeln('Wrote test/vectors/post_quantum_crypto_v2.json');
}
