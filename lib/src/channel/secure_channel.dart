/// A post-quantum secure channel: an authenticated handshake over any byte
/// stream, then a secure stream in each direction.
///
/// ```text
/// Client                                                         Server
/// ClientHello = 0x01 || version || u16 aeadId || clientNonce(32)
///               || bytes16 protocol || bytes16 clientId            -->
///      <--  ServerHello = 0x02 || flags || serverNonce(32)
///                         || bytes16 ephemeralPk || bytes16 signature
/// KeyExchange = 0x03 || X-Wing hybrid key message                  -->
/// [ClientAuth] (record: u16 sigAlg || bytes16 pk || bytes16 sig)   -->
/// Finished     (record, empty)                                     -->
///      <--  Finished (record, empty)
/// messages and End, as a secure stream in each direction
/// ```
///
/// - **Server authentication.** The server signs the hello transcript with
///   its long-term identity key: the protocol label, the whole ClientHello,
///   the server id, the flags, the server nonce and the ephemeral key. The
///   client has pinned that key, so a man-in-the-middle cannot substitute its
///   own ephemeral key.
/// - **Forward secrecy.** The server generates a new X-Wing key pair for every
///   connection and destroys it after the handshake, so recorded traffic
///   stays secret even if the identity key later leaks.
/// - **Hybrid security.** The session keys are secret as long as either
///   ML-KEM-768 or X25519 holds.
/// - **Optional client authentication.** When the server asks for it (a
///   signed flag), the client signs the hello transcript and the key exchange
///   with its own identity key. It sends that signature inside an encrypted
///   record, so a passive observer does not learn who the client is.
/// - **Records.** `establishHybridKey` derives 64 bytes, bound to both ids
///   and a SHA-384 of the hello transcript. They key the two directions,
///   each a secure stream (see `SecureStream`) with numbered records and an
///   authenticated end.
///
/// This is a package-specific protocol, not TLS.
library;

import 'dart:async';
import 'dart:typed_data';

import '../algorithms/algorithms.dart';
import '../context.dart';
import '../encoding/bytes.dart';
import '../encoding/text_encoding.dart';
import '../engine.dart';
import '../errors.dart';
import '../hybrid/hybrid_key_establishment.dart';
import '../keys/keys.dart';
import 'framing.dart';
import 'secure_stream.dart';

/// Decides whether an authenticated client may use the channel. [key] has
/// already proven possession of its private key in this handshake;
/// [clientId] is the name the client presented. Returning `false` (or
/// throwing) rejects the client.
typedef ClientAuthorizer =
    FutureOr<bool> Function(SigningPublicKey key, String clientId);

/// Settings for a [SecureChannel]: those of its secure streams, plus the
/// handshake timeout. Both ends must use the same `protocol`.
final class SecureChannelOptions extends SecureStreamOptions {
  /// The longest a handshake may take.
  final Duration handshakeTimeout;

  const SecureChannelOptions({
    super.protocol = 'post_quantum_crypto/secure-channel',
    super.aead,
    super.receiveTimeout,
    super.maxMessageLength,
    this.handshakeTimeout = const Duration(seconds: 30),
  });
}

/// An authenticated, encrypted, two-way message channel over any byte
/// stream: a socket, a WebSocket, a pair of stream controllers.
///
/// Create one with [connect] (the client) or [accept] (the server). Each
/// direction is a secure stream: [output] for what this side sends, [input]
/// for what it receives. [send], [receive], [messages] and [close] are
/// shortcuts to them.
///
/// The handshake is CPU-bound (ML-DSA, X-Wing); in a UI isolate, run it in
/// the background.
final class SecureChannel {
  /// The wire-format version.
  static const wireVersion = 1;

  static const _nonceLength = 32;
  static const _sessionKeyLength = 64;

  // Handshake messages.
  static const _clientHello = 0x01;
  static const _serverHello = 0x02;
  static const _keyExchange = 0x03;

  static const _flagClientAuth = 0x01;

  static const _labelText = 'post_quantum_crypto/v1/secure-channel';
  static final _label = utf8Bytes(_labelText);
  static final _serverContext = utf8Bytes('$_labelText server');
  static final _clientContext = utf8Bytes('$_labelText client');

  /// What this side sends.
  final SecureStreamWriter output;

  /// What this side receives.
  final SecureStreamReader input;

  /// The record cipher.
  final AeadAlgorithm aead;

  /// The application protocol both sides agreed on.
  final String protocol;

  /// The peer's id: the server id on the client, and the id the client
  /// presented on the server. It is authenticated only together with
  /// [peerKey].
  final String peerId;

  SigningPublicKey? _peerKey;

  SecureChannel._(
    CryptoContext ctx,
    this.aead,
    SecureStreamOptions options,
    FrameReader frames,
    StreamSink<List<int>> sink,
    void Function()? destroy,
    Uint8List sessionKey, {
    required bool isClient,
    required this.peerId,
    SigningPublicKey? peerKey,
  }) : protocol = options.protocol,
       _peerKey = peerKey,
       output = SecureStreamWriter.internal(
         ctx.aead(aead),
         Uint8List.fromList(
           isClient ? sessionKey.sublist(0, 32) : sessionKey.sublist(32),
         ),
         sink,
         destroy,
       ),
       input = SecureStreamReader.internal(
         ctx.aead(aead),
         Uint8List.fromList(
           isClient ? sessionKey.sublist(32) : sessionKey.sublist(0, 32),
         ),
         frames,
         options,
         destroy: destroy,
         output: sink,
       ) {
    zeroize(sessionKey);
  }

  /// The peer's authenticated identity key: the server's key on the client,
  /// and the client's key on a server that asked for client authentication
  /// (otherwise `null`).
  SigningPublicKey? get peerKey => _peerKey;

  /// Whether this side may still [send].
  bool get canSend => output.isOpen;

  /// Connects as a client over [input] / [output] to a server that holds the
  /// private half of [serverKey] and calls itself [serverId].
  ///
  /// Pass [clientIdentity] if the server requires client authentication.
  /// [destroy], if given, tears the transport down at once on failure or
  /// [abort] (for a `Socket`, `socket.destroy`); otherwise [output] is
  /// closed without waiting for it to flush.
  ///
  /// Throws [SecureChannelException] if the handshake fails; the connection
  /// is closed in that case.
  static Future<SecureChannel> connect(
    Stream<List<int>> input,
    StreamSink<List<int>> output, {
    required SigningPublicKey serverKey,
    required String serverId,
    String clientId = '',
    SigningKeyPair? clientIdentity,
    PostQuantumCryptoEngine? engine,
    SecureChannelOptions options = const SecureChannelOptions(),
    void Function()? destroy,
  }) {
    final e = engine ?? PostQuantumCryptoEngine();
    final frames = FrameReader(input);
    return _handshake(frames, output, destroy, options, () async {
      final ctx = e.ctx;
      ctx.policy.checkAead(options.aead);
      final hello =
          (ByteWriter()
                ..u8(_clientHello)
                ..u8(wireVersion)
                ..u16(options.aead.id)
                ..raw(ctx.randomBytes(_nonceLength))
                ..bytes16(utf8Bytes(options.protocol))
                ..bytes16(utf8Bytes(clientId)))
              .toBytes();
      writeFrame(output, hello);

      final (flags, serverNonce, ephemeralBytes, signature) = _parse(
        await frames.require(),
        (r) {
          _expectType(r, _serverHello);
          final flags = r.u8();
          if (flags & ~_flagClientAuth != 0) _malformed();
          final out = (flags, r.fixed(_nonceLength), r.bytes16(), r.bytes16());
          r.expectEnd();
          return out;
        },
      );
      final transcript = _helloTranscript(
        hello,
        serverId,
        flags,
        serverNonce,
        ephemeralBytes,
      );
      if (!e.verify(
        transcript,
        signature: signature,
        publicKey: serverKey,
        context: _serverContext,
      )) {
        throw const SecureChannelException(
          'Server identity could not be verified',
        );
      }
      final authRequired = flags & _flagClientAuth != 0;
      if (authRequired && clientIdentity == null) {
        throw const SecureChannelException(
          'Server requires client authentication',
        );
      }

      final established = e.establishHybridKey(
        e.importEncryptionPublicKey(
          ephemeralBytes,
          algorithm: KemAlgorithm.xWing,
        ),
        transcript: _hybridTranscript(ctx, clientId, serverId, transcript),
        length: _sessionKeyLength,
      );
      final keyExchange =
          (ByteWriter()
                ..u8(_keyExchange)
                ..raw(established.message))
              .toBytes();
      writeFrame(output, keyExchange);

      final channel = SecureChannel._(
        ctx,
        options.aead,
        options,
        frames,
        output,
        destroy,
        established.sessionKey,
        isClient: true,
        peerId: serverId,
        peerKey: serverKey,
      );
      return channel._confirm(() async {
        if (authRequired) {
          final id = clientIdentity!;
          final proof = e.sign(
            _clientAuthMessage(transcript, keyExchange),
            privateKey: id.privateKey,
            context: _clientContext,
          );
          channel.output.writeRecord(
            RecordType.clientAuth,
            (ByteWriter()
                  ..u16(id.publicKey.algorithm.id)
                  ..bytes16(id.publicKey.bytes)
                  ..bytes16(proof))
                .toBytes(),
          );
        }
        channel.output.writeRecord(RecordType.finished, Uint8List(0));
        await channel._expectFinished();
      });
    });
  }

  /// Accepts one client over [input] / [output], proving the server's
  /// [identity] under the name [serverId].
  ///
  /// With [authorizeClient], the client must authenticate with its own
  /// signing key, and the callback decides whether that key may connect.
  /// [destroy] is as in [connect].
  ///
  /// Throws [SecureChannelException] if the handshake fails; the connection
  /// is closed in that case.
  static Future<SecureChannel> accept(
    Stream<List<int>> input,
    StreamSink<List<int>> output, {
    required SigningKeyPair identity,
    required String serverId,
    ClientAuthorizer? authorizeClient,
    PostQuantumCryptoEngine? engine,
    SecureChannelOptions options = const SecureChannelOptions(),
    void Function()? destroy,
  }) {
    final e = engine ?? PostQuantumCryptoEngine();
    final frames = FrameReader(input);
    return _handshake(frames, output, destroy, options, () async {
      final ctx = e.ctx;
      final hello = await frames.require();
      final (aead, protocol, clientId) = _parse(hello, (r) {
        _expectType(r, _clientHello);
        if (r.u8() != wireVersion) {
          throw const SecureChannelException('Unsupported protocol version');
        }
        final aead = AeadAlgorithm.fromId(r.u16());
        r.fixed(_nonceLength);
        final protocol = utf8String(r.bytes16());
        final clientId = utf8String(r.bytes16());
        r.expectEnd();
        return (aead, protocol, clientId);
      });
      if (protocol != options.protocol) {
        throw const SecureChannelException('Application protocol mismatch');
      }
      ctx.policy.checkAead(aead);
      final flags = authorizeClient == null ? 0 : _flagClientAuth;

      // A key pair for this connection only: forward secrecy.
      final ephemeral = e.generateEncryptionKeyPair(
        algorithm: KemAlgorithm.xWing,
      );
      try {
        final serverNonce = ctx.randomBytes(_nonceLength);
        final transcript = _helloTranscript(
          hello,
          serverId,
          flags,
          serverNonce,
          ephemeral.publicKey.bytes,
        );
        final signature = e.sign(
          transcript,
          privateKey: identity.privateKey,
          context: _serverContext,
        );
        writeFrame(
          output,
          (ByteWriter()
                ..u8(_serverHello)
                ..u8(flags)
                ..raw(serverNonce)
                ..bytes16(ephemeral.publicKey.bytes)
                ..bytes16(signature))
              .toBytes(),
        );

        final keyExchange = await frames.require();
        final message = _parse(keyExchange, (r) {
          _expectType(r, _keyExchange);
          return r.fixed(r.remaining);
        });
        final sessionKey = e.acceptHybridKey(
          message,
          privateKey: ephemeral.privateKey,
          transcript: _hybridTranscript(ctx, clientId, serverId, transcript),
          length: _sessionKeyLength,
        );
        final channel = SecureChannel._(
          ctx,
          aead,
          options,
          frames,
          output,
          destroy,
          sessionKey,
          isClient: false,
          peerId: clientId,
        );
        return await channel._confirm(() async {
          if (authorizeClient != null) {
            await channel._authenticateClient(
              e,
              authorizeClient,
              clientId,
              _clientAuthMessage(transcript, keyExchange),
            );
          }
          await channel._expectFinished();
          channel.output.writeRecord(RecordType.finished, Uint8List(0));
        });
      } finally {
        ephemeral.privateKey.destroy();
      }
    });
  }

  // ---------------------------------------------------------------------------
  // Messages
  // ---------------------------------------------------------------------------

  /// Sends [message] on [output]. Throws [StateError] after [close], [abort]
  /// or a failure.
  void send(List<int> message) => output.add(message);

  /// Returns the next message from [input], or `null` once the peer has
  /// closed its direction.
  ///
  /// Throws [SecureStreamException] if the stream was tampered with,
  /// truncated or stalled; both directions are closed in that case. Throws
  /// [StateError] once the channel has failed or been aborted, or if another
  /// [receive] is in progress.
  Future<Uint8List?> receive() async {
    try {
      return await input.read();
    } on SecureStreamException {
      await output.abort();
      rethrow;
    }
  }

  /// The remaining messages, until the peer closes. Errors are those of
  /// [receive]. Listen at most once.
  Stream<Uint8List> get messages async* {
    for (Uint8List? m; (m = await receive()) != null;) {
      yield m!;
    }
  }

  /// Closes this side's direction (see [SecureStreamWriter.close]): a
  /// half-close. [receive] still returns the peer's remaining messages until
  /// its own close, and the connection is released once both sides have
  /// closed. Call [abort] to stop reading from a peer that does not close.
  Future<void> close() async {
    try {
      await output.close();
    } on SecureStreamException {
      // The peer may already be gone; its side reports what it received.
    }
  }

  /// Drops the connection at once in both directions: the peer sees a
  /// truncated stream, and a pending [receive] fails with
  /// [SecureStreamException].
  Future<void> abort() async {
    await input.cancel();
    await output.abort();
  }

  // ---------------------------------------------------------------------------
  // Handshake helpers
  // ---------------------------------------------------------------------------

  /// Runs [body] within the handshake timeout. On any failure it tears the
  /// connection down and rethrows as [SecureChannelException].
  static Future<SecureChannel> _handshake(
    FrameReader frames,
    StreamSink<List<int>> output,
    void Function()? destroy,
    SecureChannelOptions options,
    Future<SecureChannel> Function() body,
  ) async {
    try {
      return await body().timeout(options.handshakeTimeout);
    } catch (e) {
      await teardown(frames, output, destroy);
      throw switch (e) {
        SecureChannelException() => e,
        TimeoutException() => const SecureChannelException(
          'Handshake timed out',
        ),
        // The peer hung up: most often it refused us.
        _ when identical(e, closedByPeer) || identical(e, truncatedStream) =>
          const SecureChannelException(
            'Connection closed by peer during the handshake',
          ),
        SecureStreamException(:final message) ||
        PostQuantumCryptoException(
          :final message,
        ) => SecureChannelException('Handshake failed: $message'),
        _ => SecureChannelException('Handshake failed (${e.runtimeType})'),
      };
    }
  }

  /// Finishes the handshake with [steps], wiping the keys if they fail.
  Future<SecureChannel> _confirm(Future<void> Function() steps) async {
    try {
      await steps();
      return this;
    } catch (_) {
      await abort();
      rethrow;
    }
  }

  Future<void> _authenticateClient(
    PostQuantumCryptoEngine engine,
    ClientAuthorizer authorize,
    String clientId,
    Uint8List signedMessage,
  ) async {
    final (type, payload) = await input.readRecord();
    if (type != RecordType.clientAuth) {
      throw const SecureChannelException('Client authentication required');
    }
    final (key, proof) = _parse(payload, (r) {
      final algorithm = SignatureAlgorithm.fromId(r.u16());
      final key = engine.importSigningPublicKey(
        r.bytes16(),
        algorithm: algorithm,
      );
      final proof = r.bytes16();
      r.expectEnd();
      return (key, proof);
    });
    if (!engine.verify(
      signedMessage,
      signature: proof,
      publicKey: key,
      context: _clientContext,
    )) {
      throw const SecureChannelException('Client authentication failed');
    }
    bool allowed;
    try {
      allowed = await authorize(key, clientId);
    } catch (_) {
      allowed = false;
    }
    if (!allowed) {
      throw const SecureChannelException('Client is not authorized');
    }
    _peerKey = key;
  }

  Future<void> _expectFinished() async {
    final (type, payload) = await input.readRecord();
    if (type != RecordType.finished || payload.isNotEmpty) {
      throw const SecureChannelException('Expected Finished');
    }
  }

  static Uint8List _helloTranscript(
    Uint8List clientHello,
    String serverId,
    int flags,
    Uint8List serverNonce,
    Uint8List ephemeralPublicKey,
  ) =>
      (ByteWriter()
            ..bytes16(_label)
            ..bytes16(clientHello)
            ..bytes16(utf8Bytes(serverId))
            ..u8(flags)
            ..raw(serverNonce)
            ..bytes16(ephemeralPublicKey))
          .toBytes();

  static Uint8List _clientAuthMessage(
    Uint8List helloTranscript,
    Uint8List keyExchange,
  ) =>
      (ByteWriter()
            ..bytes16(helloTranscript)
            ..bytes16(keyExchange))
          .toBytes();

  static HybridTranscript _hybridTranscript(
    CryptoContext ctx,
    String clientId,
    String serverId,
    Uint8List helloTranscript,
  ) => HybridTranscript(
    protocol: _labelText,
    initiatorId: clientId,
    responderId: serverId,
    extra: {'hello-sha384': TextEncoding.toHex(ctx.sha384(helloTranscript))},
  );

  static T _parse<T>(Uint8List data, T Function(ByteReader r) parse) {
    try {
      return parseStrict(() => parse(ByteReader(data)));
    } on MalformedDataException {
      _malformed();
    }
  }

  static void _expectType(ByteReader r, int type) {
    if (r.u8() != type) _malformed();
  }

  static Never _malformed() =>
      throw const SecureChannelException('Malformed handshake message');
}
