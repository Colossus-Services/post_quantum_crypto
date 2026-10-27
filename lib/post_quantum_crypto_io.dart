/// File-system helpers for `post_quantum_crypto` (requires `dart:io`; not
/// available on the web).
///
/// - `encryptFile` / `decryptFile`: bounded-memory streaming encryption with
///   publish-after-verify semantics.
/// - `signFile` / `verifyFile`, `manifestEntryForFile` /
///   `verifyManifestFiles`.
/// - [FileKeyStorage]: a directory-backed `KeyStorage`.
library;

export 'post_quantum_crypto.dart';
export 'src/io/file_crypto.dart';
