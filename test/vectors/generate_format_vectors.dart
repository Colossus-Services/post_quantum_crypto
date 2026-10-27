// Regenerates test/vectors/quantum_crypto_v1.json.
//
// Usage: dart run test/vectors/generate_format_vectors.dart
//
// Only regenerate deliberately: a change here means the wire format changed,
// which requires a new format version.
import 'dart:convert';
import 'dart:io';

import 'format_vectors.dart';

Future<void> main() async {
  final vectors = await buildFormatVectors();
  File('test/vectors/quantum_crypto_v1.json').writeAsStringSync(
    '${const JsonEncoder.withIndent('  ').convert(vectors)}\n',
  );
  stdout.writeln('Wrote test/vectors/quantum_crypto_v1.json');
}
