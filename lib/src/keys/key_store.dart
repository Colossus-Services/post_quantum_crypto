/// Key lifecycle management on top of a pluggable [KeyStorage].
library;

import 'dart:typed_data';

import '../encoding/bytes.dart';
import '../encoding/canonical.dart' show ObjectType;
import '../encoding/text_encoding.dart';
import '../engine.dart';
import '../errors.dart';
import 'key_metadata.dart';
import 'keys.dart';
import 'password_protection.dart';

/// Byte storage for serialized keys.
///
/// Implement this to back a [KeyStore] with platform secure storage (Android
/// Keystore-wrapped preferences, iOS/macOS Keychain, Windows DPAPI, a cloud
/// KMS, ...). The core package ships only [InMemoryKeyStorage] and, in
/// `post_quantum_crypto_io.dart`, `FileKeyStorage`; neither is hardware-backed.
abstract interface class KeyStorage {
  Future<Uint8List?> read(String name);

  Future<void> write(String name, Uint8List data);

  Future<void> delete(String name);

  Future<List<String>> list();
}

/// Process-memory storage (tests, caches). Contents are lost on exit.
final class InMemoryKeyStorage implements KeyStorage {
  final Map<String, Uint8List> _data = {};

  @override
  Future<Uint8List?> read(String name) async {
    final d = _data[name];
    return d == null ? null : Uint8List.fromList(d);
  }

  @override
  Future<void> write(String name, Uint8List data) async =>
      _data[name] = Uint8List.fromList(data);

  @override
  Future<void> delete(String name) async {
    zeroize(_data.remove(name));
  }

  @override
  Future<List<String>> list() async => _data.keys.toList()..sort();
}

QuantumKey _withMetadata(QuantumKey key, KeyMetadata m) => switch (key) {
  EncryptionPublicKey k => k.withMetadata(m),
  EncryptionPrivateKey k => k.withMetadata(m),
  SigningPublicKey k => k.withMetadata(m),
  SigningPrivateKey k => k.withMetadata(m),
};

/// Stores keys with their metadata and implements rotation, revocation and
/// encrypted backup.
///
/// Private keys are stored Argon2id-encrypted when a [password] is given;
/// otherwise they are stored as plain key records and the security of the
/// store is that of the [KeyStorage]. Public keys are stored in clear.
final class KeyStore {
  final PostQuantumCryptoEngine engine;
  final KeyStorage storage;
  final String? _password;
  final Argon2idParameters? _parameters;

  KeyStore(
    this.engine,
    this.storage, {
    String? password,
    Argon2idParameters? parameters,
  }) : _password = password,
       _parameters = parameters;

  static String _name(KeyId id, bool private) =>
      '${id.hex}.${private ? 'key' : 'pub'}';

  /// Stores [key], replacing any key of the same id and kind.
  Future<void> put(QuantumKey key) async {
    final Uint8List data;
    if (key.isPrivate && _password != null) {
      data = engine.exportPrivateKeyWithPassword(
        key,
        _password,
        parameters: _parameters,
      );
    } else {
      data = engine.encodeKey(key);
    }
    await storage.write(_name(key.keyId, key.isPrivate), data);
    zeroize(data);
  }

  /// Stores both halves of a key pair.
  Future<void> putPair(Object pair) async {
    switch (pair) {
      case EncryptionKeyPair p:
        await put(p.publicKey);
        await put(p.privateKey);
      case SigningKeyPair p:
        await put(p.publicKey);
        await put(p.privateKey);
      default:
        throw const InvalidInputException('Expected a key pair');
    }
  }

  /// Loads a key. Returns the private key when [private] is true.
  ///
  /// Throws [InvalidKeyException] when the stored entry holds a different
  /// key, or a private key where a public one belongs (or vice versa), e.g.
  /// after a file was copied over another.
  ///
  /// [verifySlhDsaKey] false skips the SLH-DSA private-key check, a key
  /// generation that takes 1–2 s for the "s" parameter sets (see
  /// [PostQuantumCryptoEngine.decodeKey]).
  Future<QuantumKey?> get(
    KeyId id, {
    bool private = false,
    bool verifySlhDsaKey = true,
  }) async {
    final data = await storage.read(_name(id, private));
    if (data == null) return null;
    final QuantumKey key;
    try {
      key = private && _password != null
          ? engine.importPrivateKeyWithPassword(
              data,
              _password,
              verifySlhDsaKey: verifySlhDsaKey,
            )
          : engine.decodeKey(data, verifySlhDsaKey: verifySlhDsaKey);
    } finally {
      zeroize(data);
    }
    if (key.keyId != id || key.isPrivate != private) {
      _destroy(key);
      throw const InvalidKeyException('Stored key does not match its entry');
    }
    return key;
  }

  /// The public half of a stored key, derived from the private half when
  /// only that one is stored.
  Future<QuantumKey> _requirePublic(KeyId id) async {
    final pub = await get(id);
    if (pub != null) return pub;
    return switch (await get(id, private: true)) {
      EncryptionPrivateKey k => k.publicKey,
      SigningPrivateKey k => k.publicKey,
      _ => throw const KeyNotFoundException('Key not in store'),
    };
  }

  static final _namePattern = RegExp(r'^([0-9a-f]{64})\.(key|pub)$');

  /// Ids of all stored keys. Storage entries that are not key files are
  /// ignored.
  Future<List<KeyId>> list() async {
    final ids = <String>{};
    for (final n in await storage.list()) {
      final m = _namePattern.firstMatch(n);
      if (m != null) ids.add(m.group(1)!);
    }
    return [for (final h in ids) KeyId(TextEncoding.fromHex(h))];
  }

  /// Deletes both halves of a key.
  Future<void> remove(KeyId id) async {
    await storage.delete(_name(id, false));
    await storage.delete(_name(id, true));
  }

  Future<void> _updateMetadata(
    KeyId id,
    KeyMetadata Function(KeyMetadata) update,
  ) async {
    for (final private in [false, true]) {
      final k = await get(id, private: private);
      if (k != null) await put(_withMetadata(k, update(k.metadata)));
    }
  }

  /// Marks a key as revoked. With the default policy, revoked keys are
  /// refused for every operation.
  Future<void> revoke(KeyId id, {String? reason, DateTime? at}) async {
    await _requirePublic(id);
    await _updateMetadata(
      id,
      (m) => m.copyWith(
        revokedAt: at ?? engine.policy.now(),
        revocationReason: reason,
      ),
    );
  }

  /// The usages of a replacement key: unrestricted if the old key was,
  /// otherwise the old restriction widened to the full role ([roles]), so
  /// rotating an already-retired key still yields a working key.
  static Set<KeyUsage> _rotatedUsages(Set<KeyUsage> old, Set<KeyUsage> roles) =>
      old.isEmpty ? const {} : {...old, ...roles};

  /// Rotates an encryption key: generates a replacement (same algorithm)
  /// whose metadata records `replaces`, and restricts the old key to
  /// decryption only so existing data stays readable.
  Future<EncryptionKeyPair> rotateEncryptionKey(KeyId oldId) async {
    final old = await _requirePublic(oldId);
    if (old is! EncryptionPublicKey) {
      throw const InvalidKeyException('Not an encryption key');
    }
    final next = engine.generateEncryptionKeyPair(
      algorithm: old.algorithm,
      metadata: KeyMetadata(
        createdAt: engine.policy.now(),
        replaces: oldId,
        usages: _rotatedUsages(old.metadata.usages, {
          KeyUsage.encrypt,
          KeyUsage.decrypt,
        }),
        label: old.metadata.label,
      ),
    );
    await putPair(next);
    await _updateMetadata(oldId, (m) => m.copyWith(usages: {KeyUsage.decrypt}));
    return next;
  }

  /// Rotates a signing key: the old key is restricted to verification.
  Future<SigningKeyPair> rotateSigningKey(KeyId oldId) async {
    final old = await _requirePublic(oldId);
    if (old is! SigningPublicKey) {
      throw const InvalidKeyException('Not a signing key');
    }
    final next = engine.generateSigningKeyPair(
      algorithm: old.algorithm,
      metadata: KeyMetadata(
        createdAt: engine.policy.now(),
        replaces: oldId,
        usages: _rotatedUsages(old.metadata.usages, {
          KeyUsage.sign,
          KeyUsage.verify,
        }),
        label: old.metadata.label,
      ),
    );
    await putPair(next);
    await _updateMetadata(oldId, (m) => m.copyWith(usages: {KeyUsage.verify}));
    return next;
  }

  static const _backupContext = {'type': 'post_quantum_crypto/key-backup'};

  /// Exports every stored key into one Argon2id-encrypted backup.
  ///
  /// Each storage entry is decoded on its own, and the key it holds is backed
  /// up under that key's own id, whatever entry it was found in: a file moved
  /// or copied over another key's name is still backed up (once), and
  /// [restore] files it under its real name.
  ///
  /// A wrong store password fails the backup ([DecryptionFailedException]).
  /// An entry that holds no valid key also fails it, unless [onSkipped] is
  /// given: the entry is then left out and reported there, so a partial
  /// backup is always an explicit choice.
  Future<Uint8List> backup(
    String backupPassword, {
    Argon2idParameters? parameters,
    void Function(String entry, PostQuantumCryptoException error)? onSkipped,
  }) async {
    final keys = <(KeyId, bool), QuantumKey>{};
    try {
      for (final name in await storage.list()) {
        if (!_namePattern.hasMatch(name)) continue;
        final data = await storage.read(name);
        if (data == null) continue;
        final QuantumKey key;
        try {
          key = _decodeEntry(data);
        } on DecryptionFailedException {
          rethrow; // wrong store password (or a tampered entry)
        } on PostQuantumCryptoException catch (e) {
          if (onSkipped == null) rethrow;
          onSkipped(name, e);
          continue;
        } finally {
          zeroize(data);
        }
        final slot = (key.keyId, key.isPrivate);
        if (keys.containsKey(slot)) {
          _destroy(key);
        } else {
          keys[slot] = key;
        }
      }
      final w = ByteWriter()..u32(keys.length);
      for (final k in keys.values) {
        final r = engine.encodeKey(k);
        w.bytes32(r);
        zeroize(r);
      }
      final plain = w.toBytes();
      try {
        return engine.encryptWithPassword(
          plain,
          backupPassword,
          parameters: parameters,
          context: _backupContext,
        );
      } finally {
        zeroize(plain);
      }
    } finally {
      keys.values.forEach(_destroy);
    }
  }

  /// Decodes one storage entry by its content, not its name: a
  /// password-protected key with the store password, anything else as a
  /// plain key record.
  QuantumKey _decodeEntry(Uint8List data) {
    final password = _password;
    final isProtected =
        data.length > 5 && data[5] == ObjectType.passwordProtectedKey;
    return password != null && isProtected
        ? engine.importPrivateKeyWithPassword(data, password)
        : engine.decodeKey(data);
  }

  static void _destroy(QuantumKey key) {
    if (key case EncryptionPrivateKey k) k.destroy();
    if (key case SigningPrivateKey k) k.destroy();
  }

  /// Restores keys from [backup] into this store. Returns the restored ids.
  Future<List<KeyId>> restore(Uint8List backup, String backupPassword) async {
    final plain = engine.decryptWithPassword(
      backup,
      backupPassword,
      requiredContext: _backupContext,
    );
    try {
      final keys = parseStrict(() {
        final r = ByteReader(plain);
        final n = r.u32();
        final out = <QuantumKey>[];
        for (var i = 0; i < n; i++) {
          out.add(engine.decodeKey(r.bytes32(max: 1024 * 1024)));
        }
        r.expectEnd();
        return out;
      });
      for (final k in keys) {
        await put(k);
      }
      return {for (final k in keys) k.keyId}.toList();
    } finally {
      zeroize(plain);
    }
  }
}
