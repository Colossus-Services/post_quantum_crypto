/// Length-prefixed frames over a byte stream: `u32 length || body`.
library;

import 'dart:async';
import 'dart:typed_data';

import 'package:meta/meta.dart';

import '../errors.dart';

/// The largest frame accepted. Checked before buffering, so a peer cannot
/// make the reader allocate more.
@internal
const int frameLimit = 64 * 1024;

/// The input ended where a header or handshake message was expected.
@internal
const closedByPeer = SecureStreamException('Stream closed by peer');

/// The input ended before the End record.
@internal
const truncatedStream = SecureStreamException(
  'Stream ended without an End record (truncated)',
);

/// Writes [body] as one frame (a single `add`).
@internal
void writeFrame(StreamSink<List<int>> output, Uint8List body) {
  final frame = Uint8List(4 + body.length)
    ..buffer.asByteData().setUint32(0, body.length)
    ..setRange(4, 4 + body.length, body);
  output.add(frame);
}

/// Splits a byte stream into frames.
///
/// Incoming chunks are queued and joined once per frame, so the work stays
/// linear however finely a peer splits its bytes.
@internal
final class FrameReader {
  final StreamIterator<List<int>> _input;
  final _pending = BytesBuilder(copy: false);

  FrameReader(Stream<List<int>> input) : _input = StreamIterator(input);

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
      throw const SecureStreamException('Stream ended mid-frame');
    }
    final length = ByteData.sublistView(_take(4)).getUint32(0);
    if (length == 0 || length > frameLimit) {
      throw const SecureStreamException('Invalid frame length');
    }
    if (!await _fill(length)) {
      throw const SecureStreamException('Stream ended mid-frame');
    }
    return Uint8List.fromList(_take(length));
  }

  /// [next], where the stream must not end.
  Future<Uint8List> require() async => await next() ?? (throw closedByPeer);

  /// Stops reading. Safe to call more than once.
  Future<void> cancel() async {
    try {
      await _input.cancel();
    } catch (_) {}
  }
}

/// Stops reading and drops the output without waiting for it to flush, so a
/// peer that does not read cannot stall a failure. [destroy] (for a socket,
/// `socket.destroy`) tears the transport down at once if given.
@internal
Future<void> teardown(
  FrameReader? reader,
  StreamSink<List<int>>? output,
  void Function()? destroy,
) async {
  if (destroy != null) {
    try {
      destroy();
    } catch (_) {}
  } else if (output != null) {
    unawaited(output.close().then((_) {}, onError: (_) {}));
  }
  await reader?.cancel();
}
