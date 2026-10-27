/// Versioned signed objects: detached signatures, signed artifacts and signed
/// manifests.
///
/// Every signed object signs a domain-separated, canonical encoding of
/// everything that precedes the signature field: the algorithm, the signer's
/// key id, the FIPS 204/205 context string, canonical metadata, the content
/// digest (SHA-384) and the content length. The same context string is also
/// passed to ML-DSA / SLH-DSA as the FIPS context. Nothing security-relevant
/// sits outside the signed bytes.
///
/// Verification here is purely mathematical. Whether a signer is trusted,
/// authorized, or still valid is decided separately (see [TrustStore]).
library;

import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:meta/meta.dart';

import '../algorithms/algorithms.dart';
import '../context.dart';
import '../encoding/bytes.dart';
import '../encoding/canonical.dart';
import '../errors.dart';
import '../keys/key_metadata.dart';
import '../keys/keys.dart';
import '../providers/primitives.dart';

final Uint8List _detachedDomain = utf8Bytes(
  'post_quantum_crypto/v1/detached-signature\u0000',
);
final Uint8List _manifestDomain = utf8Bytes(
  'post_quantum_crypto/v1/manifest\u0000',
);

const HashAlgorithm _digestAlgorithm = HashAlgorithm.sha384;

/// A detached signature over some content (object type 0x05).
final class DetachedSignature {
  final SignatureAlgorithm algorithm;

  /// Key id of the claimed signer. Only meaningful once verified.
  final KeyId signerKeyId;

  /// FIPS 204/205 context string (≤ 255 bytes).
  final Bytes context;

  /// Signed metadata (content type, file name, version, ...).
  final Map<String, String> metadata;

  /// SHA-384 of the content.
  final Bytes digest;

  final int contentLength;

  final Bytes signature;

  final Bytes _signedBytes;
  final Bytes _bytes;

  DetachedSignature._(
    this.algorithm,
    this.signerKeyId,
    this.context,
    this.metadata,
    this.digest,
    this.contentLength,
    this.signature,
    this._signedBytes,
    this._bytes,
  );

  /// The canonical serialization (a copy).
  Bytes toBytes() => Uint8List.fromList(_bytes);

  @internal
  Bytes get signedBytes => _signedBytes;

  static Uint8List _body(
    CryptoContext ctx,
    SignatureAlgorithm alg,
    KeyId keyId,
    Uint8List context,
    Map<String, String> metadata,
    Uint8List digest,
    int length,
  ) {
    final w = ByteWriter();
    writeHeader(w, ObjectType.detachedSignature);
    w
      ..u16(alg.id)
      ..fixed(keyId.bytes, KeyId.length)
      ..bytes8(context);
    CanonicalMap.write(w, metadata, ctx.mapLimits);
    w
      ..u8(_digestAlgorithm.id)
      ..fixed(digest, _digestAlgorithm.digestLength)
      ..u64(length);
    return w.toBytes();
  }

  @internal
  static DetachedSignature parse(CryptoContext ctx, Uint8List bytes) =>
      parseStrict(() {
        final data = Uint8List.fromList(bytes);
        final r = ByteReader(data);
        readHeader(r, ObjectType.detachedSignature);
        final alg = SignatureAlgorithm.fromId(r.u16());
        final keyId = KeyId(r.fixed(KeyId.length));
        final context = r.bytes8();
        final metadata = CanonicalMap.read(r, ctx.mapLimits);
        if (r.u8() != _digestAlgorithm.id) {
          throw const UnsupportedAlgorithmException('Unsupported digest');
        }
        final digest = r.fixed(_digestAlgorithm.digestLength);
        final length = r.u64();
        final body = Uint8List.sublistView(data, 0, r.offset);
        final sig = r.bytes32(max: alg.signatureLength);
        if (sig.length != alg.signatureLength) {
          throw const MalformedDataException('Signature has wrong length');
        }
        r.expectEnd();
        return DetachedSignature._(
          alg,
          keyId,
          context,
          metadata,
          digest,
          length,
          sig,
          concatBytes([_detachedDomain, body]),
          data,
        );
      });
}

/// The largest detached signature any supported algorithm can produce under
/// [ctx]'s metadata limits, so every artifact the library creates also parses.
int _maxDetachedSignatureBytes(CryptoContext ctx) {
  final l = ctx.policy.limits;
  final keyBytes = l.maxContextKeyBytes.clamp(0, 0xff);
  final maxSig = SignatureAlgorithm.values
      .map((a) => a.signatureLength)
      .reduce((a, b) => a > b ? a : b);
  final map =
      2 + l.maxContextEntries * (1 + keyBytes + 4 + l.maxContextValueBytes);
  return 6 + 2 + KeyId.length + 1 + 255 + map + 1 + 48 + 8 + 4 + maxSig;
}

/// Content together with its detached signature (object type 0x04).
///
/// Layout: `header || bytes32 detachedSignature || u64 length || content`.
final class SignedArtifact {
  final DetachedSignature signature;
  final Bytes content;

  SignedArtifact._(this.signature, this.content);

  Bytes toBytes() {
    final w = ByteWriter();
    writeHeader(w, ObjectType.signedArtifact);
    w
      ..bytes32(signature.toBytes())
      ..u64(content.length)
      ..raw(content);
    return w.toBytes();
  }

  @internal
  static SignedArtifact parse(CryptoContext ctx, Uint8List bytes) =>
      parseStrict(() {
        final r = ByteReader(bytes);
        readHeader(r, ObjectType.signedArtifact);
        final sig = DetachedSignature.parse(
          ctx,
          r.bytes32(max: _maxDetachedSignatureBytes(ctx)),
        );
        final length = r.u64();
        if (length > ctx.policy.limits.maxSignedContentBytes) {
          throw const ResourceLimitExceededException('Content too large');
        }
        final content = r.fixed(length);
        r.expectEnd();
        return SignedArtifact._(sig, content);
      });
}

/// One entry of a [SignedManifest].
final class ManifestEntry {
  /// Relative, `/`-separated path. Must not be absolute or contain `..`,
  /// empty or `.` segments, backslashes or NUL.
  final String path;

  final int size;

  /// SHA-384 of the file content.
  final Bytes digest;

  ManifestEntry(this.path, this.size, List<int> digest)
    : digest = immutableCopy(digest) {
    validateManifestPath(path);
    if (digest.length != _digestAlgorithm.digestLength) {
      throw const InvalidInputException('Manifest digest must be SHA-384');
    }
    if (size < 0) throw const InvalidInputException('Negative size');
  }

  @override
  String toString() => 'ManifestEntry($path, $size)';
}

/// Rejects manifest paths that could escape a base directory or be
/// interpreted differently across platforms.
void validateManifestPath(String path) {
  if (path.isEmpty ||
      path.startsWith('/') ||
      path.contains('\\') ||
      path.contains('\u0000') ||
      RegExp(r'^[A-Za-z]:').hasMatch(path)) {
    throw const InvalidInputException('Invalid manifest path');
  }
  for (final seg in path.split('/')) {
    if (seg.isEmpty || seg == '.' || seg == '..') {
      throw const InvalidInputException('Invalid manifest path');
    }
  }
}

/// A signed list of files with sizes and SHA-384 digests (object type 0x06).
final class SignedManifest {
  final SignatureAlgorithm algorithm;
  final KeyId signerKeyId;
  final Bytes context;
  final Map<String, String> metadata;

  /// Entries in canonical (UTF-8 byte) order of path; paths are unique.
  final List<ManifestEntry> entries;

  final Bytes signature;
  final Bytes _signedBytes;
  final Bytes _bytes;

  SignedManifest._(
    this.algorithm,
    this.signerKeyId,
    this.context,
    this.metadata,
    this.entries,
    this.signature,
    this._signedBytes,
    this._bytes,
  );

  Bytes toBytes() => Uint8List.fromList(_bytes);

  @internal
  Bytes get signedBytes => _signedBytes;

  /// Looks up an entry by path.
  ManifestEntry? operator [](String path) {
    for (final e in entries) {
      if (e.path == path) return e;
    }
    return null;
  }

  static Uint8List _body(
    CryptoContext ctx,
    SignatureAlgorithm alg,
    KeyId keyId,
    Uint8List context,
    Map<String, String> metadata,
    List<ManifestEntry> entries,
  ) {
    final limits = ctx.policy.limits;
    if (entries.length > limits.maxManifestEntries) {
      throw const ResourceLimitExceededException('Too many manifest entries');
    }
    final sorted = [for (final e in entries) (utf8Bytes(e.path), e)]
      ..sort((a, b) => compareBytes(a.$1, b.$1));
    final w = ByteWriter();
    writeHeader(w, ObjectType.manifest);
    w
      ..u16(alg.id)
      ..fixed(keyId.bytes, KeyId.length)
      ..bytes8(context);
    CanonicalMap.write(w, metadata, ctx.mapLimits);
    w
      ..u8(_digestAlgorithm.id)
      ..u32(sorted.length);
    Uint8List? prev;
    for (final (path, e) in sorted) {
      if (prev != null && compareBytes(prev, path) == 0) {
        throw const InvalidInputException('Duplicate manifest path');
      }
      if (path.length > limits.maxManifestPathBytes) {
        throw const ResourceLimitExceededException('Manifest path too long');
      }
      prev = path;
      w
        ..bytes16(path)
        ..u64(e.size)
        ..raw(e.digest);
    }
    return w.toBytes();
  }

  @internal
  static SignedManifest parse(CryptoContext ctx, Uint8List bytes) =>
      parseStrict(() {
        final limits = ctx.policy.limits;
        final data = Uint8List.fromList(bytes);
        final r = ByteReader(data);
        readHeader(r, ObjectType.manifest);
        final alg = SignatureAlgorithm.fromId(r.u16());
        final keyId = KeyId(r.fixed(KeyId.length));
        final context = r.bytes8();
        final metadata = CanonicalMap.read(r, ctx.mapLimits);
        if (r.u8() != _digestAlgorithm.id) {
          throw const UnsupportedAlgorithmException('Unsupported digest');
        }
        final count = r.u32();
        if (count > limits.maxManifestEntries) {
          throw const ResourceLimitExceededException(
            'Too many manifest entries',
          );
        }
        final entries = <ManifestEntry>[];
        Uint8List? prev;
        for (var i = 0; i < count; i++) {
          final path = r.bytes16(max: limits.maxManifestPathBytes);
          if (prev != null && compareBytes(prev, path) >= 0) {
            throw const MalformedDataException(
              'Manifest paths not in canonical order',
            );
          }
          prev = path;
          final size = r.u64();
          final digest = r.fixed(_digestAlgorithm.digestLength);
          final String p;
          try {
            p = utf8.decode(path);
          } on FormatException {
            throw const MalformedDataException('Invalid UTF-8 path');
          }
          try {
            entries.add(ManifestEntry(p, size, digest));
          } on InvalidInputException {
            throw const MalformedDataException('Invalid manifest path');
          }
        }
        final body = Uint8List.sublistView(data, 0, r.offset);
        final sig = r.bytes32(max: alg.signatureLength);
        if (sig.length != alg.signatureLength) {
          throw const MalformedDataException('Signature has wrong length');
        }
        r.expectEnd();
        return SignedManifest._(
          alg,
          keyId,
          context,
          metadata,
          List.unmodifiable(entries),
          sig,
          concatBytes([_manifestDomain, body]),
          data,
        );
      });
}

/// The result of a successful signature verification.
final class VerifiedSignature {
  final SignatureAlgorithm algorithm;
  final KeyId signerKeyId;
  final Bytes context;
  final Map<String, String> metadata;

  VerifiedSignature._(
    this.algorithm,
    this.signerKeyId,
    this.context,
    this.metadata,
  );
}

/// Validates a FIPS 204/205 context string (≤ 255 bytes) and copies it.
@internal
Uint8List checkSignatureContext(List<int> context) {
  if (context.length > 255) {
    throw const InvalidInputException('Signature context exceeds 255 bytes');
  }
  return Uint8List.fromList(context);
}

/// Running SHA-384 + length over streamed content.
@internal
final class ContentDigester {
  final HashSink _sink;
  int length = 0;

  ContentDigester(CryptoContext ctx)
    : _sink = ctx.hash(_digestAlgorithm).start();

  void add(List<int> data) {
    _sink.add(data);
    length += data.length;
  }

  Uint8List close() => _sink.close();
}

/// Signing and verification of signed objects. Internal; via the engine.
@internal
final class SignedObjectService {
  final CryptoContext _ctx;

  SignedObjectService(this._ctx);

  Uint8List _sign(SigningPrivateKey key, Uint8List message, Uint8List context) {
    _ctx.policy.checkSignature(key.algorithm);
    _ctx.policy.checkKeyMetadata(key.metadata, KeyUsage.sign);
    final prim = _ctx.signature(key.algorithm);
    return prim.sign(
      key.secretKey,
      message,
      context,
      _ctx.randomBytes(prim.randomnessLength),
    );
  }

  void _verify(
    SigningPublicKey key,
    SignatureAlgorithm alg,
    KeyId signer,
    Uint8List message,
    Uint8List signature,
    Uint8List context,
  ) {
    _ctx.policy.checkSignature(alg);
    if (alg != key.algorithm || signer != key.keyId) {
      throw const SignatureVerificationException(
        'Signature was not made with this key',
      );
    }
    _ctx.policy.checkKeyMetadata(key.metadata, KeyUsage.verify);
    final ok = _ctx
        .signature(alg)
        .verify(key.bytes, message, signature, context);
    if (!ok) throw const SignatureVerificationException();
  }

  static Uint8List _checkContext(List<int> context) =>
      checkSignatureContext(context);

  DetachedSignature signDigest(
    SigningPrivateKey key,
    Uint8List digest,
    int length,
    List<int> context,
    Map<String, String> metadata,
  ) {
    final ctxBytes = _checkContext(context);
    final body = DetachedSignature._body(
      _ctx,
      key.algorithm,
      key.keyId,
      ctxBytes,
      metadata,
      digest,
      length,
    );
    final sig = _sign(key, concatBytes([_detachedDomain, body]), ctxBytes);
    final w = ByteWriter()
      ..raw(body)
      ..bytes32(sig);
    return DetachedSignature.parse(_ctx, w.toBytes());
  }

  DetachedSignature signDetached(
    SigningPrivateKey key,
    Uint8List content,
    List<int> context,
    Map<String, String> metadata,
  ) => signDigest(
    key,
    _ctx.hash(_digestAlgorithm).hash(content),
    content.length,
    context,
    metadata,
  );

  Future<DetachedSignature> signStream(
    SigningPrivateKey key,
    Stream<List<int>> content,
    List<int> context,
    Map<String, String> metadata,
  ) async {
    final d = ContentDigester(_ctx);
    await content.forEach(d.add);
    return signDigest(key, d.close(), d.length, context, metadata);
  }

  VerifiedSignature verifyDigest(
    DetachedSignature sig,
    Uint8List digest,
    int length,
    SigningPublicKey key,
  ) {
    _verify(
      key,
      sig.algorithm,
      sig.signerKeyId,
      sig.signedBytes,
      sig.signature,
      sig.context,
    );
    // The signature is valid for (digest, length); now bind the content.
    if (length != sig.contentLength ||
        !constantTimeEquals(digest, sig.digest)) {
      throw const SignatureVerificationException(
        'Content does not match the signature',
      );
    }
    return VerifiedSignature._(
      sig.algorithm,
      sig.signerKeyId,
      sig.context,
      sig.metadata,
    );
  }

  VerifiedSignature verifyDetached(
    DetachedSignature sig,
    Uint8List content,
    SigningPublicKey key,
  ) => verifyDigest(
    sig,
    _ctx.hash(_digestAlgorithm).hash(content),
    content.length,
    key,
  );

  Future<VerifiedSignature> verifyStream(
    DetachedSignature sig,
    Stream<List<int>> content,
    SigningPublicKey key,
  ) async {
    final d = ContentDigester(_ctx);
    await content.forEach(d.add);
    return verifyDigest(sig, d.close(), d.length, key);
  }

  SignedArtifact createArtifact(
    SigningPrivateKey key,
    Uint8List content,
    List<int> context,
    Map<String, String> metadata,
  ) {
    if (content.length > _ctx.policy.limits.maxSignedContentBytes) {
      throw const ResourceLimitExceededException('Content too large');
    }
    return SignedArtifact._(
      signDetached(key, content, context, metadata),
      Uint8List.fromList(content),
    );
  }

  SignedManifest createManifest(
    SigningPrivateKey key,
    List<ManifestEntry> entries,
    List<int> context,
    Map<String, String> metadata,
  ) {
    final ctxBytes = _checkContext(context);
    final body = SignedManifest._body(
      _ctx,
      key.algorithm,
      key.keyId,
      ctxBytes,
      metadata,
      entries,
    );
    final sig = _sign(key, concatBytes([_manifestDomain, body]), ctxBytes);
    final w = ByteWriter()
      ..raw(body)
      ..bytes32(sig);
    return SignedManifest.parse(_ctx, w.toBytes());
  }

  VerifiedSignature verifyManifest(SignedManifest m, SigningPublicKey key) {
    _verify(
      key,
      m.algorithm,
      m.signerKeyId,
      m.signedBytes,
      m.signature,
      m.context,
    );
    return VerifiedSignature._(
      m.algorithm,
      m.signerKeyId,
      m.context,
      m.metadata,
    );
  }

  ManifestEntry manifestEntry(String path, Uint8List content) => ManifestEntry(
    path,
    content.length,
    _ctx.hash(_digestAlgorithm).hash(content),
  );
}

/// The outcome of evaluating a verified signer against a [TrustStore].
enum TrustDecision {
  /// The signer is a trusted key, not expired, not revoked.
  trusted,

  /// The signer is not in the trust store.
  unknownSigner,

  /// The signer's key has expired.
  expired,

  /// The signer's key was revoked.
  revoked,
}

/// A set of signing keys the application trusts.
///
/// Mathematical verification answers "did the holder of this key sign this
/// content?". A trust store answers the separate question "do we accept
/// that key as a signer?".
final class TrustStore {
  final Map<KeyId, SigningPublicKey> _keys = {};

  TrustStore([Iterable<SigningPublicKey> trusted = const []]) {
    trusted.forEach(trust);
  }

  void trust(SigningPublicKey key) => _keys[key.keyId] = key;

  void distrust(KeyId keyId) => _keys.remove(keyId);

  /// The trusted key with [keyId], to verify a signature with.
  SigningPublicKey? lookup(KeyId keyId) => _keys[keyId];

  Iterable<SigningPublicKey> get keys => _keys.values;

  /// Whether [verified] was made by a trusted, unrevoked, unexpired key.
  ///
  /// Expiry is judged at [at], or the wall clock when omitted. With a
  /// `SecurityPolicy` clock, pass `at: policy.now()` so this agrees with the
  /// engine's own expiry checks.
  TrustDecision evaluate(VerifiedSignature verified, {DateTime? at}) {
    final key = _keys[verified.signerKeyId];
    if (key == null || key.algorithm != verified.algorithm) {
      return TrustDecision.unknownSigner;
    }
    if (key.metadata.isRevoked) return TrustDecision.revoked;
    if (key.metadata.isExpiredAt(at ?? DateTime.now())) {
      return TrustDecision.expired;
    }
    return TrustDecision.trusted;
  }
}
