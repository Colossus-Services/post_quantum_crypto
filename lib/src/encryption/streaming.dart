/// Authenticated streaming encryption (object type 0x03), a STREAM-style
/// construction (Hoang, Reyhanitabar, Rogaway, Vizár 2015; the same shape as
/// Tink's streaming AEAD).
///
/// Header:
///
/// ```text
/// "QCRY" u8 version=1 u8 type=0x03
/// u16 kdfId (HKDF-SHA-384) | u16 aeadId
/// u32 chunkSize                      plaintext bytes per chunk
/// 32  salt | 7 noncePrefix
/// context (canonical map)
///   ── wrapHash   = SHA-384(bytes so far)   (AAD of every DEK wrap)
/// u16 recipientCount, recipient records (as in envelopes)
///   ── headerHash = SHA-384(entire header)
/// chunk*                             ciphertext || tag, no framing
/// ```
///
/// - Stream key: `HKDF-SHA-384(salt, DEK, "quantum_crypto/v1/stream/key" ||
///   headerHash)`. The DEK is fresh for every stream, so every stream has a
///   fresh key and nonces can never repeat across streams.
/// - Chunk `i` nonce: `noncePrefix(7) || u32 i || u8 final`, AAD:
///   `headerHash`. The counter detects reordering, duplication and removal;
///   the final flag detects truncation and appended data; the header hash
///   binds every chunk to this stream's header, recipients and context.
/// - Every chunk except the last holds exactly `chunkSize` plaintext bytes;
///   the last holds 0..chunkSize. At most 2^32 chunks per stream.
library;

import 'dart:async';
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
import 'envelope.dart' show EnvelopeRecipient, checkRequiredContext;
import 'key_wrapping.dart';

/// Default plaintext bytes per chunk.
const int defaultStreamChunkSize = 64 * 1024;

const int _saltLength = 32;
const int _noncePrefixLength = 7;
const int _maxChunks = 0xffffffff;

/// Upper bound for the header of a stream being decrypted.
const int _maxStreamHeaderBytes = 4 * 1024 * 1024;

/// Receives the number of plaintext bytes processed so far.
typedef ProgressCallback = void Function(int bytesProcessed);

/// Cooperative cancellation for long-running stream and file operations.
final class CancellationToken {
  bool _cancelled = false;

  bool get isCancelled => _cancelled;

  void cancel() => _cancelled = true;

  void throwIfCancelled() {
    if (_cancelled) throw const OperationCancelledException();
  }
}

/// Parsed stream header.
final class StreamHeader {
  final AeadAlgorithm aead;
  final int chunkSize;
  final Map<String, String> context;

  @internal
  final Bytes salt;
  @internal
  final Bytes noncePrefix;
  @internal
  final List<RecipientRecord> records;
  @internal
  final Bytes wrapHash;
  @internal
  final Bytes headerHash;

  /// Encoded header length in bytes.
  final int length;

  StreamHeader._(
    this.aead,
    this.chunkSize,
    this.context,
    this.salt,
    this.noncePrefix,
    this.records,
    this.wrapHash,
    this.headerHash,
    this.length,
  );

  List<EnvelopeRecipient> get recipients => [
    for (final r in records) EnvelopeRecipient(r.kem, r.keyId),
  ];

  /// Parses a header from the start of [data]. Throws
  /// [InsufficientDataError] when more bytes are needed.
  @internal
  static StreamHeader read(CryptoContext ctx, Uint8List data) {
    final r = ByteReader(data);
    readHeader(r, ObjectType.stream);
    if (KdfAlgorithm.fromId(r.u16()) != KdfAlgorithm.hkdfSha384) {
      throw const UnsupportedAlgorithmException('Unsupported KDF');
    }
    final aead = AeadAlgorithm.fromId(r.u16());
    final chunkSize = r.u32();
    _checkChunkSize(ctx, chunkSize);
    final salt = r.fixed(_saltLength);
    final prefix = r.fixed(_noncePrefixLength);
    final context = CanonicalMap.read(r, ctx.mapLimits);
    final wrapHash = ctx.sha384(Uint8List.sublistView(data, 0, r.offset));
    final records = readRecipients(r, aead, ctx.policy.limits.maxRecipients);
    final headerHash = ctx.sha384(Uint8List.sublistView(data, 0, r.offset));
    return StreamHeader._(
      aead,
      chunkSize,
      context,
      salt,
      prefix,
      records,
      wrapHash,
      headerHash,
      r.offset,
    );
  }
}

void _checkChunkSize(CryptoContext ctx, int chunkSize) {
  final l = ctx.policy.limits;
  if (chunkSize < l.minStreamChunkBytes || chunkSize > l.maxStreamChunkBytes) {
    throw const ResourceLimitExceededException('Chunk size out of range');
  }
}

/// A growable FIFO byte buffer.
final class _ByteQueue {
  Uint8List _buf = Uint8List(0);
  int _start = 0;
  int _end = 0;

  int get length => _end - _start;

  void add(List<int> data) {
    if (_end + data.length > _buf.length) {
      final needed = length + data.length;
      final next = Uint8List(needed * 2 < 1024 ? 1024 : needed * 2)
        ..setRange(0, length, _buf, _start);
      _buf = next;
      _end = length;
      _start = 0;
    }
    _buf.setRange(_end, _end + data.length, data);
    _end += data.length;
  }

  Uint8List view() => Uint8List.sublistView(_buf, _start, _end);

  /// Removes and returns the first [n] bytes (a copy).
  Uint8List take(int n) {
    final out = Uint8List.fromList(
      Uint8List.sublistView(_buf, _start, _start + n),
    );
    _start += n;
    return out;
  }

  void clear() {
    zeroize(_buf);
    _start = _end = 0;
  }
}

@internal
final class StreamService {
  final CryptoContext _ctx;
  final KeyWrapper _wrapper;

  StreamService(this._ctx) : _wrapper = KeyWrapper(_ctx, 'stream');

  static final Uint8List _keyLabel = utf8Bytes('quantum_crypto/v1/stream/key');

  Uint8List _streamKey(Uint8List dek, StreamHeader h) {
    final kdf = _ctx.hkdfSha384;
    final prk = kdf.extract(h.salt, dek);
    try {
      return kdf.expand(
        prk,
        concatBytes([_keyLabel, h.headerHash]),
        h.aead.keyLength,
      );
    } finally {
      zeroize(prk);
    }
  }

  static Uint8List _nonce(Uint8List prefix, int counter, bool last) =>
      Uint8List(12)
        ..setAll(0, prefix)
        ..[7] = (counter >> 24) & 0xff
        ..[8] = (counter >> 16) & 0xff
        ..[9] = (counter >> 8) & 0xff
        ..[10] = counter & 0xff
        ..[11] = last ? 1 : 0;

  /// Encrypts [input]. The first event is the header; each following event
  /// is one encrypted chunk.
  Stream<Uint8List> encrypt(
    Stream<List<int>> input, {
    required List<EncryptionPublicKey> recipients,
    required Map<String, String> context,
    required AeadAlgorithm aead,
    required int chunkSize,
    ProgressCallback? onProgress,
    CancellationToken? cancel,
  }) async* {
    // Validate everything before consuming input.
    _ctx.policy.checkAead(aead);
    checkRecipientsForEncryption(_ctx, recipients);
    _checkChunkSize(_ctx, chunkSize);

    final w = ByteWriter();
    writeHeader(w, ObjectType.stream);
    w
      ..u16(KdfAlgorithm.hkdfSha384.id)
      ..u16(aead.id)
      ..u32(chunkSize)
      ..raw(_ctx.randomBytes(_saltLength))
      ..raw(_ctx.randomBytes(_noncePrefixLength));
    CanonicalMap.write(w, context, _ctx.mapLimits);
    final wrapHash = _ctx.sha384(w.toBytes());
    final dek = _ctx.randomBytes(dekLength);
    final Uint8List key;
    final StreamHeader header;
    try {
      writeRecipients(w, [
        for (final r in recipients) _wrapper.wrap(r, dek, wrapHash, aead),
      ]);
      final headerBytes = w.toBytes();
      header = StreamHeader.read(_ctx, headerBytes);
      key = _streamKey(dek, header);
      yield headerBytes;
    } finally {
      zeroize(dek);
    }

    final cipher = _ctx.aead(aead);
    final queue = _ByteQueue();
    var counter = 0;
    var processed = 0;
    try {
      await for (final data in input) {
        cancel?.throwIfCancelled();
        queue.add(data);
        // Emit a full chunk only once more data follows it: the last chunk
        // must carry the final flag.
        while (queue.length > chunkSize) {
          if (counter >= _maxChunks) {
            throw const ResourceLimitExceededException('Stream too long');
          }
          final pt = queue.take(chunkSize);
          yield cipher.seal(
            key,
            _nonce(header.noncePrefix, counter++, false),
            pt,
            header.headerHash,
          );
          zeroize(pt);
          processed += chunkSize;
          onProgress?.call(processed);
        }
      }
      cancel?.throwIfCancelled();
      final pt = queue.take(queue.length);
      yield cipher.seal(
        key,
        _nonce(header.noncePrefix, counter, true),
        pt,
        header.headerHash,
      );
      processed += pt.length;
      zeroize(pt);
      onProgress?.call(processed);
    } finally {
      queue.clear();
      zeroize(key);
    }
  }

  /// Decrypts [input].
  ///
  /// Each emitted event is one chunk that has been authenticated on its own
  /// and in its position. The stream as a whole is complete and untruncated
  /// only once the returned stream finishes without error. Consumers that
  /// act on plaintext before completion must be prepared to discard it; use
  /// `decryptFile` for publish-after-verify semantics.
  Stream<Uint8List> decrypt(
    Stream<List<int>> input, {
    required EncryptionPrivateKey privateKey,
    Map<String, String>? requiredContext,
    ProgressCallback? onProgress,
    CancellationToken? cancel,
    void Function(StreamHeader header)? onHeader,
  }) async* {
    final queue = _ByteQueue();
    StreamHeader? header;
    Uint8List? key;
    AeadCipher? cipher;
    var counter = 0;
    var processed = 0;
    try {
      await for (final data in input) {
        cancel?.throwIfCancelled();
        queue.add(data);
        if (header == null) {
          final StreamHeader parsed;
          try {
            parsed = parseStrictIncremental(
              () => StreamHeader.read(_ctx, queue.view()),
            );
          } on InsufficientDataError {
            if (queue.length > _maxStreamHeaderBytes) {
              throw const ResourceLimitExceededException(
                'Stream header too large',
              );
            }
            continue;
          }
          header = parsed;
          queue.take(parsed.length);
          onHeader?.call(parsed);
          key = _openHeader(parsed, privateKey, requiredContext);
          cipher = _ctx.aead(parsed.aead);
        }
        final h = header;
        final chunkLen = h.chunkSize + h.aead.tagLength;
        while (queue.length > chunkLen) {
          if (counter >= _maxChunks) throw const DecryptionFailedException();
          final pt = cipher!.open(
            key!,
            _nonce(h.noncePrefix, counter++, false),
            queue.take(chunkLen),
            h.headerHash,
          );
          if (pt == null) throw const DecryptionFailedException();
          processed += pt.length;
          onProgress?.call(processed);
          yield pt;
        }
      }
      cancel?.throwIfCancelled();
      final h = header;
      if (h == null) {
        throw const MalformedDataException('Truncated stream header');
      }
      if (queue.length < h.aead.tagLength) {
        throw const DecryptionFailedException();
      }
      final pt = cipher!.open(
        key!,
        _nonce(h.noncePrefix, counter, true),
        queue.take(queue.length),
        h.headerHash,
      );
      // Appended data would have been absorbed into this final chunk and
      // fails here, as does a stream cut at a chunk boundary (that chunk was
      // sealed as non-final).
      if (pt == null) throw const DecryptionFailedException();
      processed += pt.length;
      onProgress?.call(processed);
      yield pt;
    } finally {
      queue.clear();
      zeroize(key);
    }
  }

  Uint8List _openHeader(
    StreamHeader h,
    EncryptionPrivateKey key,
    Map<String, String>? requiredContext,
  ) {
    _ctx.policy.checkAead(h.aead);
    checkRequiredContext(h.context, requiredContext);
    RecipientRecord? record;
    for (final r in h.records) {
      if (r.keyId == key.keyId) record = r;
    }
    if (record == null) {
      throw const KeyNotFoundException('No recipient entry for this key');
    }
    if (record.kem != key.algorithm) throw const DecryptionFailedException();
    _ctx.policy.checkKem(record.kem);
    _ctx.policy.checkKeyMetadata(key.metadata, KeyUsage.decrypt);
    final dek = _wrapper.unwrap(record, key, h.wrapHash, h.aead);
    if (dek == null) throw const DecryptionFailedException();
    try {
      return _streamKey(dek, h);
    } finally {
      zeroize(dek);
    }
  }
}

/// Like [parseStrict] but lets [InsufficientDataError] through so the
/// caller can wait for more input.
@internal
T parseStrictIncremental<T>(T Function() parse) {
  try {
    return parse();
  } on InsufficientDataError {
    rethrow;
  } on QuantumCryptoException {
    rethrow;
  } on FormatException {
    throw const MalformedDataException('Invalid encoding');
  }
}
