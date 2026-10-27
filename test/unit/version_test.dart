@Tags(['version'])
@TestOn('vm')
library;

import 'dart:io';

import 'package:post_quantum_crypto/post_quantum_crypto.dart'
    show postQuantumCryptoVersion;
import 'package:test/test.dart';

void main() {
  group('postQuantumCryptoVersion', () {
    test('matches the version declared in pubspec.yaml', () {
      final pubspec = File('pubspec.yaml');
      expect(
        pubspec.existsSync(),
        isTrue,
        reason: 'test must run from the package root',
      );

      final match = RegExp(
        r'''^version:\s*['"]?([^'"\s]+)''',
        multiLine: true,
      ).firstMatch(pubspec.readAsStringSync());

      expect(
        match,
        isNotNull,
        reason: 'no version: line found in pubspec.yaml',
      );

      expect(
        postQuantumCryptoVersion,
        equals(match!.group(1)),
        reason:
            'postQuantumCryptoVersion (lib/src/version.dart) is out of sync '
            'with pubspec.yaml — update the constant when bumping the version',
      );
    });
  });
}
