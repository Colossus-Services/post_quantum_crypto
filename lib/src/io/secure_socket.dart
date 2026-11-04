/// [SecureChannel] over TCP sockets.
library;

import 'dart:async';
import 'dart:io';

import '../channel/secure_channel.dart';
import '../engine.dart';
import '../errors.dart';
import '../keys/keys.dart';

/// Sends records without Nagle delay, and keeps write-side errors (a reset
/// by the peer) from escaping as uncaught errors: the read side reports
/// them as [SecureStreamException]s.
void _prepare(Socket socket) {
  socket.setOption(SocketOption.tcpNoDelay, true);
  socket.done.ignore();
}

/// Client side of a [SecureChannel] over TCP.
///
/// Named `PQSecureSocket` so it does not clash with `dart:io`'s TLS
/// `SecureSocket`.
abstract final class PQSecureSocket {
  /// Opens a TCP connection to [host]:[port] and runs the client handshake
  /// (see [SecureChannel.connect]). [connectTimeout] bounds the TCP connect;
  /// `options.handshakeTimeout` bounds the handshake.
  ///
  /// Throws [SecureChannelException] if the handshake fails, and the
  /// `dart:io` [SocketException] if the connection cannot be opened.
  static Future<SecureChannel> connect(
    Object host,
    int port, {
    required SigningPublicKey serverKey,
    required String serverId,
    String clientId = '',
    SigningKeyPair? clientIdentity,
    PostQuantumCryptoEngine? engine,
    SecureChannelOptions options = const SecureChannelOptions(),
    Duration? connectTimeout,
  }) async {
    final socket = await Socket.connect(host, port, timeout: connectTimeout);
    _prepare(socket);
    return SecureChannel.connect(
      socket,
      socket,
      serverKey: serverKey,
      serverId: serverId,
      clientId: clientId,
      clientIdentity: clientIdentity,
      engine: engine,
      options: options,
      destroy: socket.destroy,
    );
  }
}

/// A TCP server whose connections are [SecureChannel]s.
///
/// Every accepted socket runs the server handshake (see
/// [SecureChannel.accept]); the connections that complete it arrive on
/// [channels]. Failed handshakes are dropped and reported to
/// `onHandshakeError`.
final class PQSecureServer {
  final ServerSocket _socket;
  final StreamController<SecureChannel> _channels;
  final int _maxPendingHandshakes;
  int _pending = 0;

  PQSecureServer._(this._socket, this._channels, this._maxPendingHandshakes);

  /// Binds to [address]:[port] (port 0 picks a free port) and starts
  /// accepting connections.
  ///
  /// [maxPendingHandshakes] caps the handshakes in progress at once; more
  /// connections are closed immediately, so a flood of half-open connections
  /// cannot make the server sign without limit. The other parameters are
  /// those of [SecureChannel.accept].
  static Future<PQSecureServer> bind(
    Object address,
    int port, {
    required SigningKeyPair identity,
    required String serverId,
    ClientAuthorizer? authorizeClient,
    PostQuantumCryptoEngine? engine,
    SecureChannelOptions options = const SecureChannelOptions(),
    void Function(SecureChannelException error)? onHandshakeError,
    int maxPendingHandshakes = 64,
    int backlog = 0,
    bool shared = false,
  }) async {
    if (maxPendingHandshakes < 1) {
      throw const InvalidInputException('maxPendingHandshakes must be >= 1');
    }
    final e = engine ?? PostQuantumCryptoEngine();
    final socket = await ServerSocket.bind(
      address,
      port,
      backlog: backlog,
      shared: shared,
    );
    final channels = StreamController<SecureChannel>();
    final server = PQSecureServer._(socket, channels, maxPendingHandshakes);
    socket.listen(
      (client) => server._handshake(
        client,
        identity: identity,
        serverId: serverId,
        authorizeClient: authorizeClient,
        engine: e,
        options: options,
        onHandshakeError: onHandshakeError,
      ),
      onDone: () => unawaited(channels.close()),
    );
    channels.onCancel = server.close;
    return server;
  }

  /// The address the server listens on.
  InternetAddress get address => _socket.address;

  /// The port the server listens on.
  int get port => _socket.port;

  /// The established channels. Single subscription; cancelling it closes the
  /// server.
  Stream<SecureChannel> get channels => _channels.stream;

  /// Stops accepting connections. Channels already delivered stay open.
  Future<void> close() async {
    await _socket.close();
    if (!_channels.isClosed) await _channels.close();
  }

  void _handshake(
    Socket socket, {
    required SigningKeyPair identity,
    required String serverId,
    required ClientAuthorizer? authorizeClient,
    required PostQuantumCryptoEngine engine,
    required SecureChannelOptions options,
    required void Function(SecureChannelException)? onHandshakeError,
  }) {
    if (_pending >= _maxPendingHandshakes) {
      socket.destroy();
      return;
    }
    _pending++;
    _prepare(socket);
    SecureChannel.accept(
          socket,
          socket,
          identity: identity,
          serverId: serverId,
          authorizeClient: authorizeClient,
          engine: engine,
          options: options,
          destroy: socket.destroy,
        )
        .then(
          (channel) {
            if (_channels.isClosed) {
              unawaited(channel.abort());
            } else {
              _channels.add(channel);
            }
          },
          onError: (Object e) {
            if (e is SecureChannelException) onHandshakeError?.call(e);
          },
        )
        .whenComplete(() => _pending--);
  }
}
