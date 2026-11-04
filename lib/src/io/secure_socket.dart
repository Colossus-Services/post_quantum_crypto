/// [PQSecureChannel] over TCP sockets.
library;

import 'dart:async';
import 'dart:io';

import '../channel/secure_channel.dart';
import '../engine.dart';
import '../errors.dart';
import '../keys/keys.dart';

/// Sends records without Nagle delay, and keeps write-side errors (a reset
/// by the peer) from escaping as uncaught errors: the read side reports
/// them as [PQSecureStreamException]s.
///
/// Returns `false` (and destroys the socket) if the peer is already gone.
bool _prepare(Socket socket) {
  socket.done.ignore();
  try {
    socket.setOption(SocketOption.tcpNoDelay, true);
    return true;
  } on SocketException {
    socket.destroy();
    return false;
  }
}

/// Client side of a [PQSecureChannel] over TCP.
///
/// Named `PQSecureSocket` so it does not clash with `dart:io`'s TLS
/// `SecureSocket`.
abstract final class PQSecureSocket {
  /// Opens a TCP connection to [host]:[port] and runs the client handshake
  /// (see [PQSecureChannel.connect]). [connectTimeout] bounds the TCP
  /// connect; `options.handshakeTimeout` bounds the handshake.
  ///
  /// Throws [PQSecureChannelException] if the handshake fails, and the
  /// `dart:io` [SocketException] if the connection cannot be opened.
  static Future<PQSecureChannel> connect(
    Object host,
    int port, {
    required SigningPublicKey serverKey,
    required String serverId,
    String clientId = '',
    SigningKeyPair? clientIdentity,
    PostQuantumCryptoEngine? engine,
    PQSecureChannelOptions options = const PQSecureChannelOptions(),
    Duration? connectTimeout,
  }) async {
    final socket = await Socket.connect(host, port, timeout: connectTimeout);
    if (!_prepare(socket)) {
      throw const PQSecureChannelException(
        'Connection closed by peer during the handshake',
      );
    }
    return PQSecureChannel.connect(
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

/// A TCP server whose connections are [PQSecureChannel]s.
///
/// Every accepted socket runs the server handshake (see
/// [PQSecureChannel.accept]); the connections that complete it arrive on
/// [channels]. Failed handshakes are dropped and reported to
/// `onHandshakeError`.
final class PQSecureServer {
  final ServerSocket _socket;
  final StreamController<PQSecureChannel> _channels;
  final int _maxPendingHandshakes;
  final int _maxIdleConnections;

  /// Connections that have not sent a ClientHello yet.
  int _idle = 0;

  /// Handshakes past the ClientHello: the ones that cost signing work.
  int _pending = 0;

  PQSecureServer._(
    this._socket,
    this._channels,
    this._maxPendingHandshakes,
    this._maxIdleConnections,
  );

  /// Binds to [address]:[port] (port 0 picks a free port) and starts
  /// accepting connections.
  ///
  /// Two limits keep a flood of connections from exhausting the server:
  ///
  /// - [maxIdleConnections] caps connections that have not yet sent a
  ///   ClientHello. Each is dropped after `options.helloTimeout`, and
  ///   connections over the cap are closed at once. Idle connections cost
  ///   only a socket.
  /// - [maxPendingHandshakes] caps handshakes past the ClientHello, the
  ///   point where the server starts signing. A ClientHello over the cap is
  ///   refused as busy.
  ///
  /// [onHandshakeError] receives every refused handshake; an error it throws
  /// is ignored. The other parameters are those of [PQSecureChannel.accept].
  static Future<PQSecureServer> bind(
    Object address,
    int port, {
    required SigningKeyPair identity,
    required String serverId,
    ClientAuthorizer? authorizeClient,
    PostQuantumCryptoEngine? engine,
    PQSecureChannelOptions options = const PQSecureChannelOptions(),
    void Function(PQSecureChannelException error)? onHandshakeError,
    int maxPendingHandshakes = 64,
    int maxIdleConnections = 1024,
    int backlog = 0,
    bool shared = false,
  }) async {
    if (maxPendingHandshakes < 1 || maxIdleConnections < 1) {
      throw const InvalidInputException(
        'maxPendingHandshakes and maxIdleConnections must be >= 1',
      );
    }
    final e = engine ?? PostQuantumCryptoEngine();
    final socket = await ServerSocket.bind(
      address,
      port,
      backlog: backlog,
      shared: shared,
    );
    final channels = StreamController<PQSecureChannel>();
    final server = PQSecureServer._(
      socket,
      channels,
      maxPendingHandshakes,
      maxIdleConnections,
    );
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
  Stream<PQSecureChannel> get channels => _channels.stream;

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
    required PQSecureChannelOptions options,
    required void Function(PQSecureChannelException)? onHandshakeError,
  }) {
    if (_idle >= _maxIdleConnections) {
      socket.destroy();
      return;
    }
    if (!_prepare(socket)) return;
    _idle++;
    var helloSeen = false;
    PQSecureChannel.acceptInternal(
          socket,
          socket,
          identity: identity,
          serverId: serverId,
          authorizeClient: authorizeClient,
          engine: engine,
          options: options,
          destroy: socket.destroy,
          onHello: () {
            if (_pending >= _maxPendingHandshakes) return false;
            helloSeen = true;
            _idle--;
            _pending++;
            return true;
          },
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
            if (e is! PQSecureChannelException || onHandshakeError == null) {
              return;
            }
            try {
              onHandshakeError(e);
            } catch (_) {
              // A failing error callback must not take the server down.
            }
          },
        )
        .whenComplete(() {
          if (helloSeen) {
            _pending--;
          } else {
            _idle--;
          }
        });
  }
}
