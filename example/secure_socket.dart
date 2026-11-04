// A post-quantum secure channel over a TCP socket: the server proves its
// identity with ML-DSA-65, both sides agree on fresh session keys with X-Wing
// (ML-KEM-768 + X25519), and every message is encrypted with AES-256-GCM.
//
// Run with: dart run example/secure_socket.dart
//
// This is an EXAMPLE protocol showing how the package's building blocks fit
// together. It is not TLS and has not been reviewed as a protocol; for
// production traffic prefer a TLS stack with post-quantum key exchange where
// one is available.
//
// Handshake (every message is a frame: u32 big-endian length || body):
//
//   Client                                              Server
//   ClientHello  = 0x01 || version || clientNonce || clientId   -->
//          <--  ServerHello = 0x02 || serverNonce || ephemeralPk || signature
//   KeyExchange  = 0x03 || X-Wing hybrid key message             -->
//   Finished     (encrypted, empty)                              -->
//          <--  Finished (encrypted, empty)
//   ...application records in both directions...
//   Close        (encrypted, empty)                         <-->
//
// - `signature` is ML-DSA over the hello transcript (protocol label, the
//   whole ClientHello, the server id, serverNonce and ephemeralPk) with the
//   server's long-term identity key, which the client has pinned. A
//   man-in-the-middle cannot substitute its own ephemeral key.
// - The server generates a new X-Wing key pair for every connection and
//   forgets it afterwards, so recorded traffic stays secret even if the
//   identity key later leaks (forward secrecy). The session keys stay secret
//   as long as either ML-KEM-768 or X25519 holds.
// - The X-Wing session key (64 bytes) is bound to both ids and a SHA-384 of
//   the hello transcript. Its halves are the client-to-server and
//   server-to-client AES-256-GCM keys; each direction numbers its records,
//   and the record number is the nonce. A record that is modified, replayed,
//   reordered, reflected back or dropped fails to decrypt.
// - A stream that ends without an authenticated Close record is reported as
//   truncated, so an attacker cannot cut a conversation short unnoticed.
// - Only the server is authenticated. `clientId` is a claimed name, like a
//   TLS client without a certificate; authenticate the client inside the
//   channel (a password, a token or a signature) when the server needs to
//   know who it is.
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:post_quantum_crypto/post_quantum_crypto.dart';

Future<void> main() async {
  final engine = PostQuantumCryptoEngine();

  // The server's long-term identity. The client receives the public half
  // through a trusted channel (shipped with the app, a pinned PEM, ...).
  final identity = engine.generateSigningKeyPair();
  const serverId = 'echo.example';

  final server = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
  server.listen((socket) async {
    try {
      final channel = await PqSecureChannel.server(
        socket,
        socket,
        engine: engine,
        identity: identity,
        serverId: serverId,
      );
      print('server: secure session with "${channel.peerId}"');
      // Echo every message back in upper case until the client closes.
      for (Uint8List? m; (m = await channel.receive()) != null;) {
        channel.send(utf8.encode(utf8.decode(m!).toUpperCase()));
      }
      await channel.close();
    } on SecureChannelException catch (e) {
      print('server: connection dropped: ${e.message}');
    }
  });

  // --- A client that pinned the right identity -------------------------------
  final socket = await Socket.connect(server.address, server.port);
  final channel = await PqSecureChannel.client(
    socket,
    socket,
    engine: engine,
    serverIdentity: identity.publicKey,
    serverId: serverId,
    clientId: 'client-1',
  );
  channel.send(utf8.encode('hello, post-quantum world'));
  print('client: ${utf8.decode((await channel.receive())!)}');

  // Messages larger than one record are split and reassembled.
  final big = 'x' * 100000;
  channel.send(utf8.encode(big));
  final echoed = utf8.decode((await channel.receive())!);
  print(
    'client: echoed ${echoed.length} characters intact: '
    '${echoed == big.toUpperCase()}',
  );
  // Close our direction, then read until the server closes its own: a null
  // here means the conversation ended intact, with nothing cut off.
  await channel.close();
  final last = await channel.receive();
  print('client: server closed cleanly: ${last == null}');

  // --- A client that expects a different server ------------------------------
  // The server signs with a key this client does not trust, so the handshake
  // fails before any application data is sent.
  final impostorCheck = await Socket.connect(server.address, server.port);
  try {
    await PqSecureChannel.client(
      impostorCheck,
      impostorCheck,
      engine: engine,
      serverIdentity: engine.generateSigningKeyPair().publicKey,
      serverId: serverId,
      clientId: 'client-2',
    );
  } on SecureChannelException catch (e) {
    print('client: refused: ${e.message}');
  }

  await server.close();
}

// =============================================================================
// The protocol
// =============================================================================

/// Thrown when the handshake fails or the channel is corrupted, truncated or
/// misused by the peer. The underlying connection is closed when it is
/// thrown, and the channel cannot be used afterwards.
final class SecureChannelException implements Exception {
  final String message;

  const SecureChannelException(this.message);

  @override
  String toString() => 'SecureChannelException: $message';
}

/// An encrypted, authenticated message channel over any byte stream (a
/// [Socket], or a pair of stream controllers in tests).
///
/// Messages keep their boundaries: each [send] is one [receive] on the other
/// side. [send] queues the data on the output; [receive] returns `null` once
/// the peer has closed the channel. Each side closes its own direction with
/// [close].
final class PqSecureChannel {
  /// The protocol label; also the HKDF / signature domain.
  static const protocol = 'post_quantum_crypto-example/secure-socket/v1';
  static const version = 1;
  static const nonceLength = 32;

  /// Largest frame accepted from the peer. Checked before buffering, so a
  /// peer cannot make the reader allocate more.
  static const maxFrameLength = 64 * 1024;

  /// Largest plaintext carried by one record; [send] splits larger messages.
  static const maxRecordPayload = 16 * 1024;

  /// Largest message [receive] reassembles.
  static const defaultMaxMessageLength = 16 * 1024 * 1024;

  /// Records per direction before the channel must be re-established. Far
  /// below any AES-GCM limit for 16 KiB records.
  static const maxRecords = 1 << 32;

  // Handshake message types.
  static const _clientHello = 0x01;
  static const _serverHello = 0x02;
  static const _keyExchange = 0x03;

  // Record types (encrypted frames).
  static const _finished = 0x14;
  static const _close = 0x15;
  static const _data = 0x17; // last (or only) fragment of a message
  static const _dataMore = 0x18; // more fragments of this message follow

  static final _signatureContext = utf8.encode('$protocol server-hello');
  final AeadCipher _aead;
  final _FrameReader _reader;
  final StreamSink<List<int>> _output;
  final Uint8List _sendKey;
  final Uint8List _receiveKey;
  final int maxMessageLength;

  /// The id the peer presented: the server id on the client, the client's
  /// claimed (unauthenticated) id on the server.
  final String peerId;

  int _sendSeq = 0;
  int _receiveSeq = 0;
  bool _receiving = false;
  bool _sentClose = false;
  bool _peerClosed = false;
  bool _failed = false;

  PqSecureChannel._(
    PostQuantumCryptoEngine engine,
    this._reader,
    this._output,
    this._sendKey,
    this._receiveKey,
    this.peerId,
    this.maxMessageLength,
  ) : _aead = engine.backend.symmetric.aead(AeadAlgorithm.aes256Gcm);

  /// Connects to a server whose identity key the caller has pinned
  /// ([serverIdentity]) and which calls itself [serverId].
  static Future<PqSecureChannel> client(
    Stream<List<int>> input,
    StreamSink<List<int>> output, {
    required PostQuantumCryptoEngine engine,
    required SigningPublicKey serverIdentity,
    required String serverId,
    required String clientId,
    Duration timeout = const Duration(seconds: 30),
    int maxMessageLength = defaultMaxMessageLength,
  }) {
    final reader = _FrameReader(input);
    return _handshake(reader, output, timeout, () async {
      final clientNonce = SystemSecureRandom.instance.nextBytes(nonceLength);
      final hello =
          (BytesBuilder()
                ..addByte(_clientHello)
                ..addByte(version)
                ..add(clientNonce)
                .._addVar(utf8.encode(clientId)))
              .toBytes();
      _writeFrame(output, hello);

      final r = _Reader(await reader.require());
      r.expectType(_serverHello);
      final serverNonce = r.take(nonceLength);
      final ephemeralBytes = r.variable();
      final signature = r.variable();
      r.end();

      final transcript = _helloTranscript(
        hello,
        serverId,
        serverNonce,
        ephemeralBytes,
      );
      if (!engine.verify(
        transcript,
        signature: signature,
        publicKey: serverIdentity,
        context: _signatureContext,
      )) {
        throw const SecureChannelException(
          'Server identity could not be verified',
        );
      }
      final ephemeral = engine.importEncryptionPublicKey(
        ephemeralBytes,
        algorithm: KemAlgorithm.xWing,
      );
      final established = engine.establishHybridKey(
        ephemeral,
        transcript: _hybridTranscript(engine, clientId, serverId, transcript),
        length: 64,
      );
      _writeFrame(output, [_keyExchange, ...established.message]);

      final key = established.sessionKey;
      final channel = PqSecureChannel._(
        engine,
        reader,
        output,
        Uint8List.fromList(key.sublist(0, 32)),
        Uint8List.fromList(key.sublist(32)),
        serverId,
        maxMessageLength,
      );
      key.fillRange(0, key.length, 0);
      channel._writeRecord(_finished, const []);
      await channel._expectFinished();
      return channel;
    });
  }

  /// Accepts one client on [input] / [output], proving the server's
  /// [identity] under the name [serverId].
  static Future<PqSecureChannel> server(
    Stream<List<int>> input,
    StreamSink<List<int>> output, {
    required PostQuantumCryptoEngine engine,
    required SigningKeyPair identity,
    required String serverId,
    Duration timeout = const Duration(seconds: 30),
    int maxMessageLength = defaultMaxMessageLength,
  }) {
    final reader = _FrameReader(input);
    return _handshake(reader, output, timeout, () async {
      final hello = await reader.require();
      final r = _Reader(hello);
      r.expectType(_clientHello);
      if (r.byte() != version) {
        throw const SecureChannelException('Unsupported protocol version');
      }
      r.take(nonceLength);
      final clientId = r.string();
      r.end();

      // A fresh key pair for this connection only: forward secrecy.
      final ephemeral = engine.generateEncryptionKeyPair(
        algorithm: KemAlgorithm.xWing,
      );
      try {
        final serverNonce = SystemSecureRandom.instance.nextBytes(nonceLength);
        final transcript = _helloTranscript(
          hello,
          serverId,
          serverNonce,
          ephemeral.publicKey.bytes,
        );
        final signature = engine.sign(
          transcript,
          privateKey: identity.privateKey,
          context: _signatureContext,
        );
        _writeFrame(
          output,
          (BytesBuilder()
                ..addByte(_serverHello)
                ..add(serverNonce)
                .._addVar(ephemeral.publicKey.bytes)
                .._addVar(signature))
              .toBytes(),
        );

        final kx = _Reader(await reader.require());
        kx.expectType(_keyExchange);
        final key = engine.acceptHybridKey(
          kx.rest(),
          privateKey: ephemeral.privateKey,
          transcript: _hybridTranscript(engine, clientId, serverId, transcript),
          length: 64,
        );
        final channel = PqSecureChannel._(
          engine,
          reader,
          output,
          Uint8List.fromList(key.sublist(32)),
          Uint8List.fromList(key.sublist(0, 32)),
          clientId,
          maxMessageLength,
        );
        key.fillRange(0, key.length, 0);
        await channel._expectFinished();
        channel._writeRecord(_finished, const []);
        return channel;
      } finally {
        ephemeral.privateKey.destroy();
      }
    });
  }

  /// Runs [body] with a [timeout]; on any failure closes the connection and
  /// rethrows as [SecureChannelException].
  static Future<PqSecureChannel> _handshake(
    _FrameReader reader,
    StreamSink<List<int>> output,
    Duration timeout,
    Future<PqSecureChannel> Function() body,
  ) async {
    try {
      return await body().timeout(timeout);
    } catch (e) {
      await _abort(reader, output);
      throw switch (e) {
        SecureChannelException() => e,
        TimeoutException() => const SecureChannelException(
          'Handshake timed out',
        ),
        PostQuantumCryptoException(:final message) => SecureChannelException(
          'Handshake failed: $message',
        ),
        _ => SecureChannelException('Handshake failed: $e'),
      };
    }
  }

  static Uint8List _helloTranscript(
    Uint8List clientHello,
    String serverId,
    Uint8List serverNonce,
    Uint8List ephemeralPublicKey,
  ) =>
      (BytesBuilder()
            .._addVar(utf8.encode(protocol))
            .._addVar(clientHello)
            .._addVar(utf8.encode(serverId))
            ..add(serverNonce)
            .._addVar(ephemeralPublicKey))
          .toBytes();

  static HybridTranscript _hybridTranscript(
    PostQuantumCryptoEngine engine,
    String clientId,
    String serverId,
    Uint8List helloTranscript,
  ) => HybridTranscript(
    protocol: protocol,
    initiatorId: clientId,
    responderId: serverId,
    extra: {
      'hello-sha384': TextEncoding.toHex(
        engine.backend.symmetric
            .hash(HashAlgorithm.sha384)
            .hash(helloTranscript),
      ),
    },
  );

  // ---------------------------------------------------------------------------
  // Records
  // ---------------------------------------------------------------------------

  /// Sends [message], split into records of at most [maxRecordPayload]
  /// bytes. Throws [StateError] after [close] or a failure.
  void send(List<int> message) {
    if (_sentClose || _failed) throw StateError('Channel is closed');
    var offset = 0;
    do {
      final end = offset + maxRecordPayload < message.length
          ? offset + maxRecordPayload
          : message.length;
      _writeRecord(
        end == message.length ? _data : _dataMore,
        message.sublist(offset, end),
      );
      offset = end;
    } while (offset < message.length);
  }

  /// Returns the next message, or `null` once the peer has closed the
  /// channel. Throws [SecureChannelException] (and closes the connection)
  /// if the stream was tampered with or ended without a Close record.
  Future<Uint8List?> receive() async {
    if (_failed) throw StateError('Channel has failed');
    if (_peerClosed) return null;
    if (_receiving) throw StateError('receive() is already in progress');
    _receiving = true;
    try {
      final message = BytesBuilder(copy: false);
      while (true) {
        final (type, payload) = await _readRecord();
        switch (type) {
          case _dataMore || _data:
            if (message.length + payload.length > maxMessageLength) {
              throw const SecureChannelException('Message too long');
            }
            message.add(payload);
            if (type == _data) return message.takeBytes();
          case _close when message.isEmpty:
            _peerClosed = true;
            _receiveKey.fillRange(0, _receiveKey.length, 0);
            if (_sentClose) await _reader.cancel();
            return null;
          default:
            throw const SecureChannelException('Unexpected record');
        }
      }
    } catch (e) {
      // Any failure (tampering, truncation, a socket error) ends the
      // channel: a stream with a gap in it must not be read further.
      await _fail();
      if (e is SecureChannelException) rethrow;
      throw SecureChannelException('Connection failed: $e');
    } finally {
      _receiving = false;
    }
  }

  /// Sends a Close record and closes the output. This is a half-close:
  /// [receive] keeps returning the peer's remaining messages until its own
  /// Close, and the connection is released once both sides have closed. Call
  /// [abort] instead to stop reading from a peer that does not close. Safe
  /// to call more than once.
  Future<void> close() async {
    if (_sentClose || _failed) return;
    _writeRecord(_close, const []);
    _sentClose = true;
    _sendKey.fillRange(0, _sendKey.length, 0);
    try {
      await _output.close();
    } catch (_) {}
    if (_peerClosed) await _reader.cancel();
  }

  /// Drops the connection at once, without a Close record: the peer sees a
  /// truncated stream.
  Future<void> abort() => _fail();

  Future<void> _expectFinished() async {
    final (type, payload) = await _readRecord();
    if (type != _finished || payload.isNotEmpty) {
      throw const SecureChannelException('Expected Finished');
    }
  }

  void _writeRecord(int type, List<int> payload) {
    if (_sendSeq >= maxRecords) {
      throw StateError('Record limit reached; open a new channel');
    }
    final sealed = _aead.seal(
      _sendKey,
      _nonce(_sendSeq++),
      Uint8List.fromList(payload),
      _aad(type),
    );
    _writeFrame(_output, [type, ...sealed]);
  }

  Future<(int, Uint8List)> _readRecord() async {
    final frame = await _reader.next();
    if (frame == null) {
      throw const SecureChannelException(
        'Connection ended without a Close record (truncated)',
      );
    }
    final type = frame[0];
    final plaintext = _aead.open(
      _receiveKey,
      _nonce(_receiveSeq),
      Uint8List.sublistView(frame, 1),
      _aad(type),
    );
    if (plaintext == null) {
      throw const SecureChannelException('Record failed authentication');
    }
    _receiveSeq++;
    return (type, plaintext);
  }

  Future<void> _fail() async {
    _failed = true;
    await _abort(_reader, _output);
    _wipe();
  }

  void _wipe() {
    _sendKey.fillRange(0, _sendKey.length, 0);
    _receiveKey.fillRange(0, _receiveKey.length, 0);
  }

  static Uint8List _nonce(int seq) =>
      Uint8List(12)..buffer.asByteData().setUint64(4, seq);

  static Uint8List _aad(int type) =>
      (BytesBuilder()
            ..add(utf8.encode(protocol))
            ..addByte(type))
          .toBytes();

  static void _writeFrame(StreamSink<List<int>> output, List<int> body) {
    output.add(
      (BytesBuilder()
            ..add(Uint8List(4)..buffer.asByteData().setUint32(0, body.length))
            ..add(body))
          .toBytes(),
    );
  }

  static Future<void> _abort(
    _FrameReader reader,
    StreamSink<List<int>> output,
  ) async {
    // The peer may already be gone; closing is best-effort.
    try {
      await output.close();
    } catch (_) {}
    await reader.cancel();
  }
}

extension on BytesBuilder {
  /// Appends [bytes] with a u16 length prefix.
  void _addVar(List<int> bytes) {
    if (bytes.length > 0xffff) throw ArgumentError('Field too long');
    addByte(bytes.length >> 8);
    addByte(bytes.length & 0xff);
    add(bytes);
  }
}

/// Strict parser for handshake messages: any mismatch is a protocol error.
final class _Reader {
  final Uint8List _data;
  int _offset = 0;

  _Reader(this._data);

  Never _malformed() =>
      throw const SecureChannelException('Malformed handshake message');

  int byte() => _offset < _data.length ? _data[_offset++] : _malformed();

  void expectType(int type) {
    if (byte() != type) _malformed();
  }

  Uint8List take(int n) {
    if (_data.length - _offset < n) _malformed();
    return Uint8List.sublistView(_data, _offset, _offset += n);
  }

  Uint8List variable() => take(byte() << 8 | byte());

  String string() {
    try {
      return utf8.decode(variable());
    } on FormatException {
      _malformed();
    }
  }

  Uint8List rest() => take(_data.length - _offset);

  void end() {
    if (_offset != _data.length) _malformed();
  }
}

/// Splits a byte stream into length-prefixed frames.
///
/// Incoming chunks are queued and joined once per frame, so the work stays
/// linear however finely a peer splits its bytes.
final class _FrameReader {
  final StreamIterator<List<int>> _input;
  final _pending = BytesBuilder(copy: false);

  _FrameReader(Stream<List<int>> input) : _input = StreamIterator(input);

  /// Buffers at least [n] bytes; `false` if the stream ends first.
  Future<bool> _fill(int n) async {
    while (_pending.length < n) {
      if (!await _input.moveNext()) return false;
      _pending.add(_input.current);
    }
    return true;
  }

  /// Removes and returns the first [n] buffered bytes (a view).
  Uint8List _take(int n) {
    final all = _pending.takeBytes();
    _pending.add(Uint8List.sublistView(all, n));
    return Uint8List.sublistView(all, 0, n);
  }

  /// The next frame, or `null` when the stream ends cleanly between frames.
  Future<Uint8List?> next() async {
    if (!await _fill(4)) {
      if (_pending.isEmpty) return null;
      throw const SecureChannelException('Connection ended mid-frame');
    }
    final length = ByteData.sublistView(_take(4)).getUint32(0);
    if (length == 0 || length > PqSecureChannel.maxFrameLength) {
      throw const SecureChannelException('Invalid frame length');
    }
    if (!await _fill(length)) {
      throw const SecureChannelException('Connection ended mid-frame');
    }
    return Uint8List.fromList(_take(length));
  }

  /// [next] for the handshake, where the stream must not end.
  Future<Uint8List> require() async =>
      await next() ??
      (throw const SecureChannelException('Connection closed by peer'));

  Future<void> cancel() async {
    try {
      await _input.cancel();
    } catch (_) {}
  }
}
