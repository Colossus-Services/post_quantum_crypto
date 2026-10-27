import 'dart:io';
import 'dart:typed_data';

import '../encoding/bytes.dart' show constantTimeEquals;
import '../encoding/text_encoding.dart';
import '../encryption/streaming.dart';
import '../engine.dart';
import '../errors.dart';
import '../keys/key_store.dart';
import '../keys/keys.dart';
import '../random/secure_random.dart';
import '../signatures/signed_objects.dart';

/// File helpers (Dart VM / Flutter native only).
extension PostQuantumCryptoFiles on PostQuantumCryptoEngine {
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
  ///
  /// The temporary and output files are created with the process's default
  /// permissions (umask). On a shared host, make the destination directory
  /// private if other local users must not read the plaintext.
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
      if (actual.size != e.size ||
          !constantTimeEquals(actual.digest, e.digest)) {
        throw SignatureVerificationException('File differs: ${e.path}');
      }
    }
    return verified;
  }

  static String _join(String base, String rel) =>
      '$base${Platform.pathSeparator}${rel.replaceAll('/', Platform.pathSeparator)}';
}

/// [KeyStorage] in a directory, one file per key.
///
/// Files are restricted to owner-only permissions on POSIX systems
/// (`chmod 600`, applied before any key bytes are written). Temporary
/// files are named `<key>.<random>.tmp` and are not listed as keys. Writes
/// through one instance are serialized per key; concurrent writers in
/// different processes are not coordinated (on Windows the losing rename
/// fails). This is ordinary file storage: it is not
/// hardware-backed and offers no protection against other code running as
/// the same user. Combine it with a [KeyStore] password for private keys.
final class FileKeyStorage implements KeyStorage {
  final Directory directory;

  FileKeyStorage(this.directory);

  static final _keyName = RegExp(r'^[0-9a-f]{64}\.(key|pub)$');

  File _file(String name) {
    if (!_keyName.hasMatch(name)) {
      throw const InvalidInputException('Invalid key file name');
    }
    return File('${directory.path}${Platform.pathSeparator}$name');
  }

  @override
  Future<Uint8List?> read(String name) async {
    final f = _file(name);
    return await f.exists() ? await f.readAsBytes() : null;
  }

  /// Pending write per key name. Writes of one name are serialized: on
  /// Windows, renaming onto a file that another rename is replacing fails
  /// with "access denied" (POSIX rename replaces atomically).
  final Map<String, Future<void>> _pending = {};

  @override
  Future<void> write(String name, Uint8List data) =>
      _enqueue(name, () => _write(name, data));

  /// Runs [op] after every earlier write or delete of [name] has settled.
  Future<void> _enqueue(String name, Future<void> Function() op) {
    // Validate before queueing; report an invalid name as a failed Future,
    // like the other KeyStorage methods.
    try {
      _file(name);
    } catch (e, s) {
      return Future.error(e, s);
    }
    final previous = _pending[name] ?? Future<void>.value();
    final next = previous.catchError((Object _) {}).then((_) => op());
    _pending[name] = next;
    return next.whenComplete(() {
      if (identical(_pending[name], next)) _pending.remove(name);
    });
  }

  Future<void> _write(String name, Uint8List data) async {
    await directory.create(recursive: true);
    final f = _file(name);
    // A unique temporary name: concurrent writes of the same key cannot
    // clobber each other's partial file.
    final suffix = TextEncoding.toHex(SystemSecureRandom.instance.nextBytes(8));
    final tmp = File('${f.path}.$suffix.tmp');
    try {
      // Restrict permissions before any key bytes are written.
      await tmp.writeAsBytes(const [], flush: true);
      await _restrictPermissions(tmp);
      await tmp.writeAsBytes(data, flush: true);
      await tmp.rename(f.path);
    } catch (_) {
      if (await tmp.exists()) await tmp.delete();
      rethrow;
    }
  }

  /// `chmod 600` on POSIX systems. Fails closed if chmod runs and reports an
  /// error. Skipped where there is no chmod (Windows; the iOS sandbox, where
  /// `Process` is unavailable and app containers are already private).
  static Future<void> _restrictPermissions(File file) async {
    if (Platform.isWindows || Platform.isIOS) return;
    final ProcessResult r;
    try {
      r = await Process.run('chmod', ['600', file.path]);
    } on ProcessException {
      // No chmod binary (some Android images): app storage is private.
      return;
    }
    if (r.exitCode != 0) {
      throw const UnsupportedPlatformException(
        'Could not restrict key file permissions',
      );
    }
  }

  /// Deletes [name] once its pending writes have landed, so a delete issued
  /// after a write is not undone by that write's rename.
  @override
  Future<void> delete(String name) => _enqueue(name, () async {
    final f = _file(name);
    if (await f.exists()) await f.delete();
  });

  @override
  Future<List<String>> list() async {
    if (!await directory.exists()) return [];
    return [
      await for (final e in directory.list())
        if (e is File && _keyName.hasMatch(e.uri.pathSegments.last))
          e.uri.pathSegments.last,
    ]..sort();
  }
}
