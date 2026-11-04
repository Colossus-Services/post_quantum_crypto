/// A post-quantum secure stream: protected messages over any byte stream.
///
/// A secure stream carries one direction of messages as numbered AEAD
/// records. It works over anything that moves bytes: a file, a socket, a
/// pipe, a message queue, a pair of stream controllers.
///
/// ```text
/// stream  = [header] record* end
/// frame   = u32 length || body                (every header and record)
/// record  = type || AEAD(key, nonce = 0^4 || u64 seq,
///                        aad = label || type, payload)
/// ```
///
/// - Messages keep their boundaries; a message larger than
///   [SecureStream.maxRecordPayload] spans several records.
/// - The record number is the nonce, and the record type goes into the AAD.
///   A record that is modified, retyped, replayed, reordered or dropped
///   fails to decrypt.
/// - The stream ends with an authenticated End record followed by the end of
///   the input. A stream that stops early is reported as truncated; data
///   after the End record is rejected.
/// - Frame and message sizes are checked before buffering.
///
/// One-way streams start with a header that derives a fresh key:
///
/// ```text
/// header = 0x10 || version || mode || u16 aeadId || bytes16 protocol
///          || (mode 1) u16 kemId || recipientKeyId(32) || KEM ciphertext
///          || (mode 2) salt(32)
/// key    = HKDF-SHA-384(ikm = KEM shared secret | shared key,
///                       info = label || SHA-384(header), 32)
/// ```
///
/// - Mode 1 is to a recipient's public key (ML-KEM or X-Wing), with no round
///   trip. Use it for files and other store-and-forward data.
/// - Mode 2 is from a key both ends already share. The random salt gives
///   every stream a fresh key, so the shared key may be reused.
///
/// A `SecureChannel` uses two secure streams, one per direction, keyed by
/// its handshake instead of a header.
///
/// A one-way stream is confidential and tamper-evident, but does not say
/// who wrote it: anyone holding the recipient's public key (or the shared
/// key) can write one. Sign the content (`signDetached`, `signStream`) or
/// use a `SecureChannel` when the writer must be authenticated.
library;

import 'dart:async';
import 'dart:typed_data';

import 'package:meta/meta.dart';

import '../algorithms/algorithms.dart';
import '../context.dart';
import '../encoding/bytes.dart';
import '../engine.dart';
import '../errors.dart';
import '../keys/key_metadata.dart';
import '../keys/keys.dart';
import '../providers/primitives.dart';
import 'framing.dart';

/// Settings for a secure stream. Writer and reader must use the same
/// [protocol].
base class SecureStreamOptions {
  /// The application protocol, e.g. `"myapp/backup/v1"`. It is bound into
  /// the key, so a stream for one protocol cannot be read as another.
  final String protocol;

  /// The record cipher. The writer chooses it; a reader accepts any AEAD its
  /// policy allows.
  final AeadAlgorithm aead;

  /// If set, the longest a reader waits for each frame. A peer that stalls
  /// longer fails the stream. `null` waits forever.
  final Duration? receiveTimeout;

  /// The largest message a reader reassembles.
  final int maxMessageLength;

  const SecureStreamOptions({
    this.protocol = 'post_quantum_crypto/secure-stream',
    this.aead = AeadAlgorithm.aes256Gcm,
    this.receiveTimeout,
    this.maxMessageLength = 16 * 1024 * 1024,
  });
}

/// Creates secure streams. See the library documentation for the format.
abstract final class SecureStream {
  /// The format version.
  static const version = 1;

  /// The largest frame a reader accepts.
  static const maxFrameLength = frameLimit;

  /// The largest plaintext in one record; larger messages are split.
  static const maxRecordPayload = 16 * 1024;

  /// Records per stream before a new stream must be started. This is the
  /// AES-GCM limit of RFC 8446 §5.5 for full-size records (about 2^24.5).
  static const maxRecords = 1 << 24;

  static const _header = 0x10;
  static const _modeRecipient = 1;
  static const _modeSharedKey = 2;
  static const _saltLength = 32;
  static const _minSharedKeyLength = 32;
  static final _keyLabel = utf8Bytes('post_quantum_crypto/v1/secure-stream');

  /// Starts a stream to [recipient] (ML-KEM or X-Wing) on [output]. Only the
  /// holder of the matching private key can read it.
  ///
  /// [destroy], if given, tears the transport down at once on
  /// [SecureStreamWriter.abort]; otherwise [output] is closed without
  /// waiting for it to flush.
  static SecureStreamWriter encryptTo(
    StreamSink<List<int>> output, {
    required EncryptionPublicKey recipient,
    PostQuantumCryptoEngine? engine,
    SecureStreamOptions options = const SecureStreamOptions(),
    void Function()? destroy,
  }) {
    final ctx = (engine ?? PostQuantumCryptoEngine()).ctx;
    final kem = recipient.algorithm;
    ctx.policy
      ..checkKem(kem)
      ..checkAead(options.aead)
      ..checkKeyMetadata(recipient.metadata, KeyUsage.encrypt);
    final rnd = ctx.randomBytes(kem.encapsulationRandomLength);
    final encap = ctx.kem(kem).encapsulate(recipient.bytes, rnd);
    zeroize(rnd);
    try {
      final header = _headerStart(_modeRecipient, options)
        ..u16(kem.id)
        ..raw(recipient.keyId.bytes)
        ..raw(encap.ciphertext);
      return _startWriter(
        ctx,
        output,
        header.toBytes(),
        encap.sharedSecret,
        options,
        destroy,
      );
    } finally {
      zeroize(encap.sharedSecret);
    }
  }

  /// Opens a stream written by [encryptTo] for [privateKey]. Reads the
  /// header from [input] before returning.
  ///
  /// Throws [SecureStreamException] if the header is malformed, was written
  /// for another key or protocol, or uses an AEAD the policy forbids.
  static Future<SecureStreamReader> decryptFrom(
    Stream<List<int>> input, {
    required EncryptionPrivateKey privateKey,
    PostQuantumCryptoEngine? engine,
    SecureStreamOptions options = const SecureStreamOptions(),
    void Function()? destroy,
  }) {
    final ctx = (engine ?? PostQuantumCryptoEngine()).ctx;
    return _openReader(ctx, input, options, destroy, _modeRecipient, (r) {
      final kem = KemAlgorithm.fromId(r.u16());
      final keyId = KeyId(r.fixed(KeyId.length));
      final enc = r.fixed(kem.ciphertextLength);
      r.expectEnd();
      if (kem != privateKey.algorithm || keyId != privateKey.keyId) {
        throw const SecureStreamException('Stream is not for this key');
      }
      ctx.policy
        ..checkKem(kem)
        ..checkKeyMetadata(privateKey.metadata, KeyUsage.decrypt);
      return ctx.kem(kem).decapsulate(privateKey.secret, enc);
    });
  }

  /// Starts a stream keyed by [sharedKey] (at least 32 bytes, for example a
  /// session key from `establishHybridKey`). Each stream draws a random
  /// salt, so the same key can protect many streams.
  static SecureStreamWriter encryptWithKey(
    StreamSink<List<int>> output, {
    required List<int> sharedKey,
    PostQuantumCryptoEngine? engine,
    SecureStreamOptions options = const SecureStreamOptions(),
    void Function()? destroy,
  }) {
    _checkSharedKey(sharedKey);
    final ctx = (engine ?? PostQuantumCryptoEngine()).ctx;
    ctx.policy.checkAead(options.aead);
    final header = _headerStart(_modeSharedKey, options)
      ..raw(ctx.randomBytes(_saltLength));
    return _startWriter(
      ctx,
      output,
      header.toBytes(),
      Uint8List.fromList(sharedKey),
      options,
      destroy,
    );
  }

  /// Opens a stream written by [encryptWithKey] with the same [sharedKey].
  /// A wrong key shows as [SecureStreamException] on the first record.
  static Future<SecureStreamReader> decryptWithKey(
    Stream<List<int>> input, {
    required List<int> sharedKey,
    PostQuantumCryptoEngine? engine,
    SecureStreamOptions options = const SecureStreamOptions(),
    void Function()? destroy,
  }) {
    _checkSharedKey(sharedKey);
    final ctx = (engine ?? PostQuantumCryptoEngine()).ctx;
    return _openReader(ctx, input, options, destroy, _modeSharedKey, (r) {
      r.fixed(_saltLength);
      r.expectEnd();
      return Uint8List.fromList(sharedKey);
    });
  }

  static void _checkSharedKey(List<int> key) {
    if (key.length < _minSharedKeyLength) {
      throw const InvalidInputException('Shared key must be >= 32 bytes');
    }
  }

  static ByteWriter _headerStart(int mode, SecureStreamOptions options) =>
      ByteWriter()
        ..u8(_header)
        ..u8(version)
        ..u8(mode)
        ..u16(options.aead.id)
        ..bytes16(utf8Bytes(options.protocol));

  static SecureStreamWriter _startWriter(
    CryptoContext ctx,
    StreamSink<List<int>> output,
    Uint8List header,
    Uint8List ikm,
    SecureStreamOptions options,
    void Function()? destroy,
  ) {
    final key = _deriveKey(ctx, ikm, header);
    writeFrame(output, header);
    return SecureStreamWriter.internal(
      ctx.aead(options.aead),
      key,
      output,
      destroy,
    );
  }

  static Future<SecureStreamReader> _openReader(
    CryptoContext ctx,
    Stream<List<int>> input,
    SecureStreamOptions options,
    void Function()? destroy,
    int mode,
    Uint8List Function(ByteReader r) keyMaterial,
  ) async {
    final frames = FrameReader(input);
    try {
      final next = frames.require();
      final timeout = options.receiveTimeout;
      final header = await (timeout == null
          ? next
          : next.timeout(timeout, onTimeout: _timedOut));
      final (aead, ikm) = parseStreamMessage(header, (r) {
        if (r.u8() != _header) malformedStream();
        if (r.u8() != version) {
          throw const SecureStreamException('Unsupported stream version');
        }
        if (r.u8() != mode) {
          throw const SecureStreamException('Unexpected stream key mode');
        }
        final aead = AeadAlgorithm.fromId(r.u16());
        if (utf8String(r.bytes16()) != options.protocol) {
          throw const SecureStreamException('Application protocol mismatch');
        }
        ctx.policy.checkAead(aead);
        return (aead, keyMaterial(r));
      });
      final key = _deriveKey(ctx, ikm, header);
      return SecureStreamReader.internal(
        ctx.aead(aead),
        key,
        frames,
        options,
        destroy: destroy,
      );
    } catch (e) {
      await teardown(frames, null, destroy);
      throw asStreamError(e, 'Cannot open stream');
    }
  }

  static Never _timedOut() =>
      throw const SecureStreamException('Receive timed out');

  /// Derives the record key, and zeroes [ikm].
  static Uint8List _deriveKey(
    CryptoContext ctx,
    Uint8List ikm,
    Uint8List header,
  ) {
    final kdf = ctx.hkdfSha384;
    final prk = kdf.extract(null, ikm);
    zeroize(ikm);
    try {
      return kdf.expand(
        prk,
        (ByteWriter()
              ..raw(_keyLabel)
              ..raw(ctx.sha384(header)))
            .toBytes(),
        32,
      );
    } finally {
      zeroize(prk);
    }
  }
}

// -----------------------------------------------------------------------------
// Records
// -----------------------------------------------------------------------------

/// Record types.
@internal
abstract final class RecordType {
  static const finished = 0x14;
  static const end = 0x15;
  static const clientAuth = 0x16;

  /// The last (or only) fragment of a message.
  static const data = 0x17;

  /// A fragment with more of the same message to follow.
  static const dataMore = 0x18;

  static final _label = utf8Bytes('post_quantum_crypto/v1/secure-stream');
  static final Map<int, Uint8List> aads = {
    for (final t in [finished, end, clientAuth, data, dataMore])
      t:
          (ByteWriter()
                ..raw(_label)
                ..u8(t))
              .toBytes(),
  };
}

Uint8List _nonce(int seq) =>
    (ByteWriter()
          ..u32(0)
          ..u64(seq))
        .toBytes();

/// The writing end of a secure stream.
///
/// [add] queues each message on the output as one or more records; [close]
/// writes the End record and closes the output.
final class SecureStreamWriter {
  final AeadCipher _cipher;
  final Uint8List _key;
  final StreamSink<List<int>> _output;
  final void Function()? _destroy;
  int _seq = 0;
  bool _closed = false;
  bool _failed = false;

  @internal
  SecureStreamWriter.internal(
    this._cipher,
    this._key,
    this._output,
    this._destroy,
  );

  /// Whether [add] may still be called.
  bool get isOpen => !_closed && !_failed;

  /// Writes [message], split into records of at most
  /// [SecureStream.maxRecordPayload] bytes.
  ///
  /// Throws [StateError] after [close] or [abort], and once
  /// [SecureStream.maxRecords] records have been written.
  void add(List<int> message) {
    if (!isOpen) throw StateError('Stream is closed');
    final bytes = message is Uint8List ? message : Uint8List.fromList(message);
    var offset = 0;
    do {
      final end = bytes.length - offset > SecureStream.maxRecordPayload
          ? offset + SecureStream.maxRecordPayload
          : bytes.length;
      writeRecord(
        end == bytes.length ? RecordType.data : RecordType.dataMore,
        Uint8List.sublistView(bytes, offset, end),
      );
      offset = end;
    } while (offset < bytes.length);
  }

  /// Writes every message of [messages], then [close]s.
  Future<void> addStream(Stream<List<int>> messages) async {
    await for (final m in messages) {
      add(m);
    }
    await close();
  }

  /// Writes the End record and closes the output, waiting for it to flush.
  /// Safe to call more than once.
  Future<void> close() async {
    if (!isOpen) return;
    writeRecord(RecordType.end, Uint8List(0));
    _closed = true;
    zeroize(_key);
    try {
      await _output.close();
    } catch (_) {
      // The peer may already be gone.
    }
  }

  /// Drops the output at once, without an End record: the reader sees a
  /// truncated stream.
  Future<void> abort() async {
    if (_failed) return;
    _failed = true;
    zeroize(_key);
    if (!_closed) await teardown(null, _output, _destroy);
  }

  /// Writes one record of [type].
  @internal
  void writeRecord(int type, Uint8List payload) {
    if (_seq >= SecureStream.maxRecords) {
      throw StateError('Record limit reached; start a new stream');
    }
    final sealed = _cipher.seal(
      _key,
      _nonce(_seq++),
      payload,
      RecordType.aads[type]!,
    );
    final frame = Uint8List(5 + sealed.length)
      ..buffer.asByteData().setUint32(0, 1 + sealed.length)
      ..[4] = type
      ..setRange(5, 5 + sealed.length, sealed);
    _output.add(frame);
  }
}

/// The reading end of a secure stream.
final class SecureStreamReader {
  final AeadCipher _cipher;
  final Uint8List _key;
  final FrameReader _frames;
  final Duration? _receiveTimeout;
  final int _maxMessageLength;
  final void Function()? _destroy;
  final StreamSink<List<int>>? _output;
  int _seq = 0;
  bool _reading = false;
  bool _ended = false;
  bool _failed = false;
  bool _cancelled = false;

  @internal
  SecureStreamReader.internal(
    this._cipher,
    this._key,
    this._frames,
    SecureStreamOptions options, {
    void Function()? destroy,
    StreamSink<List<int>>? output,
  }) : _receiveTimeout = options.receiveTimeout,
       _maxMessageLength = options.maxMessageLength,
       _destroy = destroy,
       _output = output;

  /// Whether the End record has been read.
  bool get isDone => _ended;

  /// Returns the next message, or `null` at the authenticated end of the
  /// stream.
  ///
  /// Throws [SecureStreamException] if the stream was tampered with, ended
  /// without an End record, carried data after it, stalled past
  /// `receiveTimeout` or held a message over `maxMessageLength`; the input
  /// is closed in that case. Throws [StateError] once the stream has failed
  /// or been cancelled, or if another [read] is in progress.
  Future<Uint8List?> read() async {
    if (_failed) throw StateError('Stream has failed or was cancelled');
    if (_ended) return null;
    if (_reading) throw StateError('read() is already in progress');
    _reading = true;
    try {
      final message = BytesBuilder(copy: false);
      while (true) {
        final (type, payload) = await readRecord();
        switch (type) {
          case RecordType.data || RecordType.dataMore:
            if (message.length + payload.length > _maxMessageLength) {
              throw const SecureStreamException('Message too long');
            }
            message.add(payload);
            if (type == RecordType.data) return message.takeBytes();
          case RecordType.end when message.isEmpty && payload.isEmpty:
            if (await _nextFrame() != null) {
              throw const SecureStreamException('Data after end of stream');
            }
            _ended = true;
            zeroize(_key);
            return null;
          default:
            throw const SecureStreamException('Unexpected record');
        }
      }
    } catch (e) {
      throw await _failWith(e);
    } finally {
      _reading = false;
    }
  }

  /// The remaining messages, until the end of the stream. Errors are those
  /// of [read]. Listen at most once.
  Stream<Uint8List> get messages async* {
    for (Uint8List? m; (m = await read()) != null;) {
      yield m!;
    }
  }

  /// Stops reading and closes the input. A pending [read] fails with
  /// [SecureStreamException].
  Future<void> cancel() async {
    _cancelled = true;
    await _fail();
  }

  /// Reads and decrypts one record.
  @internal
  Future<(int, Uint8List)> readRecord() async {
    final frame = await _nextFrame();
    if (frame == null) {
      throw const SecureStreamException(
        'Stream ended without an End record (truncated)',
      );
    }
    final type = frame[0];
    final aad = RecordType.aads[type];
    final plaintext = aad == null
        ? null
        : _cipher.open(
            _key,
            _nonce(_seq),
            Uint8List.sublistView(frame, 1),
            aad,
          );
    if (plaintext == null) {
      throw const SecureStreamException('Record failed authentication');
    }
    _seq++;
    return (type, plaintext);
  }

  Future<SecureStreamException> _failWith(Object e) async {
    if (_cancelled) {
      return const SecureStreamException('Stream was cancelled locally');
    }
    // A stream with a gap in it must not be read further.
    await _fail();
    return asStreamError(e, 'Stream failed');
  }

  Future<Uint8List?> _nextFrame() {
    final next = _frames.next();
    final timeout = _receiveTimeout;
    return timeout == null
        ? next
        : next.timeout(timeout, onTimeout: SecureStream._timedOut);
  }

  Future<void> _fail() async {
    if (_failed) return;
    _failed = true;
    zeroize(_key);
    await teardown(_frames, _output, _destroy);
  }
}

// -----------------------------------------------------------------------------
// Shared helpers
// -----------------------------------------------------------------------------

/// Parses a header or handshake message strictly; any structural problem is
/// a [SecureStreamException] (or the more specific error thrown by [parse]).
@internal
T parseStreamMessage<T>(Uint8List data, T Function(ByteReader r) parse) {
  try {
    return parseStrict(() => parse(ByteReader(data)));
  } on MalformedDataException {
    malformedStream();
  }
}

@internal
Never malformedStream() =>
    throw const SecureStreamException('Malformed stream header');

/// [e] as a [SecureStreamException], prefixing library errors with [what].
@internal
SecureStreamException asStreamError(Object e, String what) => switch (e) {
  SecureStreamException() => e,
  PostQuantumCryptoException(:final message) => SecureStreamException(
    '$what: $message',
  ),
  _ => SecureStreamException('$what (${e.runtimeType})'),
};
