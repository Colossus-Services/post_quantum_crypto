import 'dart:io';
import 'dart:typed_data';

import '../encoding/text_encoding.dart';
import '../encryption/streaming.dart';
import '../engine.dart';
import '../errors.dart';
import '../keys/key_store.dart';
import '../keys/keys.dart';
import '../signatures/signed_objects.dart';

/// File helpers (Dart VM / Flutter native only).
extension QuantumCryptoFiles on QuantumCryptoEngine {
  /// Encrypts [inputPath] into [outputPath] with bounded memory.
  ///
  /// Output is written to a temporary file in the destination directory and
  /// renamed into place on success; on failure or cancellation the temporary
  /// file is deleted and [outputPath] is left untouched.
  Future<void> encryptFile(
    String inputPath,
    String outputPath, {
    required List<EncryptionPublicKey> recipients,
    Map<String, String> context = const {},
    int chunkSize = defaultStreamChunkSize,
    ProgressCallback? onProgress,
    CancellationToken? cancel,
  }) => _writeAtomically(
    outputPath,
    encryptStream(
      File(inputPath).openRead(),
      recipients: recipients,
      context: context,
      chunkSize: chunkSize,
      onProgress: onProgress,
      cancel: cancel,
    ),
  );

  /// Decrypts [inputPath] into [outputPath].
  ///
  /// Plaintext goes to a temporary file in the destination directory and is
  /// published (renamed to [outputPath]) only after the final chunk has been
  /// authenticated. On any failure the temporary file is deleted, so a
  /// truncated or tampered input never produces an output file.
  Future<void> decryptFile(
    String inputPath,
    String outputPath, {
    required EncryptionPrivateKey privateKey,
    Map<String, String>? requiredContext,
    ProgressCallback? onProgress,
    CancellationToken? cancel,
  }) => _writeAtomically(
    outputPath,
    decryptStream(
      File(inputPath).openRead(),
      privateKey: privateKey,
      requiredContext: requiredContext,
      onProgress: onProgress,
      cancel: cancel,
    ),
  );

  Future<void> _writeAtomically(
    String outputPath,
    Stream<List<int>> data,
  ) async {
    final out = File(outputPath);
    final suffix = TextEncoding.toHex(ctx.randomBytes(8));
    final tmp = File(
      '${out.parent.path}${Platform.pathSeparator}'
      '.${out.uri.pathSegments.last}.$suffix.qc-tmp',
    );
    final sink = tmp.openWrite();
    try {
      await sink.addStream(data);
      await sink.flush();
      await sink.close();
      await tmp.rename(out.path);
    } catch (_) {
      try {
        await sink.close();
      } catch (_) {}
      if (await tmp.exists()) await tmp.delete();
      rethrow;
    }
  }

  /// Creates a detached signature for a file (streamed).
  Future<DetachedSignature> signFile(
    String path, {
    required SigningPrivateKey privateKey,
    List<int> context = const [],
    Map<String, String> metadata = const {},
  }) => signStream(
    File(path).openRead(),
    privateKey: privateKey,
    context: context,
    metadata: metadata,
  );

  /// Verifies a detached signature over a file (streamed).
  Future<VerifiedSignature> verifyFile(
    String path, {
    required DetachedSignature signature,
    required SigningPublicKey publicKey,
  }) => verifyStream(
    File(path).openRead(),
    signature: signature,
    publicKey: publicKey,
  );

  /// Computes a manifest entry for the file at [baseDir]/[relativePath].
  Future<ManifestEntry> manifestEntryForFile(
    String baseDir,
    String relativePath,
  ) async {
    validateManifestPath(relativePath);
    final d = ContentDigester(ctx);
    await File(_join(baseDir, relativePath)).openRead().forEach(d.add);
    return ManifestEntry(relativePath, d.length, d.close());
  }

  /// Verifies the manifest signature, then every listed file under
  /// [baseDir]. Throws [SignatureVerificationException] naming no content
  /// if a file is missing or differs.
  Future<VerifiedSignature> verifyManifestFiles(
    SignedManifest manifest,
    String baseDir, {
    required SigningPublicKey publicKey,
  }) async {
    final verified = verifyManifest(manifest, publicKey: publicKey);
    for (final e in manifest.entries) {
      final f = File(_join(baseDir, e.path));
      if (!await f.exists()) {
        throw SignatureVerificationException('Missing file: ${e.path}');
      }
      final actual = await manifestEntryForFile(baseDir, e.path);
      if (actual.size != e.size || !_eq(actual.digest, e.digest)) {
        throw SignatureVerificationException('File differs: ${e.path}');
      }
    }
    return verified;
  }

  static String _join(String base, String rel) =>
      '$base${Platform.pathSeparator}${rel.replaceAll('/', Platform.pathSeparator)}';

  static bool _eq(Uint8List a, Uint8List b) {
    if (a.length != b.length) return false;
    var d = 0;
    for (var i = 0; i < a.length; i++) {
      d |= a[i] ^ b[i];
    }
    return d == 0;
  }
}

/// [KeyStorage] in a directory, one file per key.
///
/// Files are created with owner-only permissions on POSIX systems
/// (best-effort `chmod 600`). This is ordinary file storage: it is not
/// hardware-backed and offers no protection against other code running as
/// the same user. Combine it with a [KeyStore] password for private keys.
final class FileKeyStorage implements KeyStorage {
  final Directory directory;

  FileKeyStorage(this.directory);

  File _file(String name) {
    if (!RegExp(r'^[0-9a-f]{64}\.(key|pub)$').hasMatch(name)) {
      throw const InvalidInputException('Invalid key file name');
    }
    return File('${directory.path}${Platform.pathSeparator}$name');
  }

  @override
  Future<Uint8List?> read(String name) async {
    final f = _file(name);
    return await f.exists() ? await f.readAsBytes() : null;
  }

  @override
  Future<void> write(String name, Uint8List data) async {
    await directory.create(recursive: true);
    final f = _file(name);
    final tmp = File('${f.path}.tmp');
    await tmp.writeAsBytes(data, flush: true);
    if (!Platform.isWindows) {
      await Process.run('chmod', ['600', tmp.path]);
    }
    await tmp.rename(f.path);
  }

  @override
  Future<void> delete(String name) async {
    final f = _file(name);
    if (await f.exists()) await f.delete();
  }

  @override
  Future<List<String>> list() async {
    if (!await directory.exists()) return [];
    return [
      await for (final e in directory.list())
        if (e is File) e.uri.pathSegments.last,
    ]..sort();
  }
}
