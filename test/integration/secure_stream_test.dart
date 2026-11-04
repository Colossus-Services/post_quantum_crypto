import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:post_quantum_crypto/post_quantum_crypto.dart';
import 'package:test/test.dart';

import '../support/test_engine.dart';

/// Collects everything a writer produces, frame by frame (each `add` is one
/// frame: the header first, then one per record).
final class Captured {
  final _controller = StreamController<List<int>>();
  final frames = <Uint8List>[];
  late final Future<void> done = _controller.stream.forEach(
    (f) => frames.add(Uint8List.fromList(f)),
  );

  StreamSink<List<int>> get sink => _controller.sink;

  /// The bytes as one stream, optionally rewritten frame by frame.
  Stream<List<int>> replay([
    List<List<int>> Function(int index, Uint8List frame)? hook,
  ]) => Stream.fromIterable([
    for (var i = 0; i < frames.length; i++)
      ...(hook?.call(i, frames[i]) ?? [frames[i]]),
  ]);

  Uint8List get bytes => Uint8List.fromList([for (final f in frames) ...f]);
}

Matcher streamError([String? message]) => throwsA(
  isA<SecureStreamException>().having(
    (e) => e.message,
    'message',
    message == null ? anything : contains(message),
  ),
);

const options = SecureStreamOptions(protocol: 'test/backup/v1');
final sharedKey = Uint8List.fromList(List.generate(32, (i) => i));

/// Writes [messages] to a [Captured] with [encrypt], then closes.
Future<Captured> write(
  SecureStreamWriter Function(StreamSink<List<int>> sink) encrypt,
  List<List<int>> messages,
) async {
  final out = Captured();
  final writer = encrypt(out.sink);
  for (final m in messages) {
    writer.add(m);
  }
  await writer.close();
  await out.done;
  return out;
}

Future<List<String>> readAll(SecureStreamReader reader) =>
    reader.messages.map(utf8.decode).toList();

void main() {
  late EncryptionKeyPair mlKem;
  late EncryptionKeyPair xWing;

  setUpAll(() {
    mlKem = engine.generateEncryptionKeyPair();
    xWing = engine.generateEncryptionKeyPair(algorithm: KemAlgorithm.xWing);
  });

  SecureStreamWriter toRecipient(
    StreamSink<List<int>> sink, [
    EncryptionKeyPair? to,
  ]) => SecureStream.encryptTo(
    sink,
    recipient: (to ?? mlKem).publicKey,
    engine: engine,
    options: options,
  );

  Future<SecureStreamReader> fromRecipient(
    Stream<List<int>> input, [
    EncryptionKeyPair? to,
    SecureStreamOptions opts = options,
  ]) => SecureStream.decryptFrom(
    input,
    privateKey: (to ?? mlKem).privateKey,
    engine: engine,
    options: opts,
  );

  group('to a recipient', () {
    for (final (name, pair) in [
      ('ML-KEM-768', () => mlKem),
      ('X-Wing', () => xWing),
    ]) {
      test('round-trips messages ($name)', () async {
        final out = await write((s) => toRecipient(s, pair()), [
          utf8.encode('one'),
          utf8.encode('two'),
          utf8.encode(''),
        ]);
        final reader = await fromRecipient(out.replay(), pair());
        expect(await readAll(reader), ['one', 'two', '']);
        expect(reader.isDone, isTrue);
        expect(await reader.read(), isNull);
      });
    }

    test('large messages span records and are reassembled', () async {
      final big = Uint8List.fromList(List.generate(100000, (i) => i % 256));
      final out = await write(toRecipient, [big]);
      // Header, ceil(100000 / 16 KiB) = 7 records, End.
      expect(out.frames, hasLength(1 + 7 + 1));
      final reader = await fromRecipient(out.replay());
      expect(await reader.read(), big);
      expect(await reader.read(), isNull);
    });

    test('bytes split arbitrarily are reassembled', () async {
      final out = await write(toRecipient, [utf8.encode('chunked')]);
      final bytes = out.bytes;
      final input = Stream.fromIterable([
        for (var i = 0; i < bytes.length; i += 7)
          bytes.sublist(i, i + 7 > bytes.length ? bytes.length : i + 7),
      ]);
      expect(await readAll(await fromRecipient(input)), ['chunked']);
    });

    test('every stream has a fresh key', () async {
      final a = await write(toRecipient, [utf8.encode('same')]);
      final b = await write(toRecipient, [utf8.encode('same')]);
      expect(a.frames[0], isNot(b.frames[0]));
      expect(a.frames[1], isNot(b.frames[1]));
    });

    test('another key cannot open it', () async {
      final out = await write(toRecipient, [utf8.encode('secret')]);
      await expectLater(
        fromRecipient(out.replay(), engine.generateEncryptionKeyPair()),
        streamError('not for this key'),
      );
    });

    test('another protocol cannot open it', () async {
      final out = await write(toRecipient, [utf8.encode('secret')]);
      await expectLater(
        fromRecipient(
          out.replay(),
          null,
          const SecureStreamOptions(protocol: 'test/other/v1'),
        ),
        streamError('Application protocol mismatch'),
      );
    });

    test('a shared-key stream is not read as a recipient stream', () async {
      final out = await write(
        (s) => SecureStream.encryptWithKey(
          s,
          sharedKey: sharedKey,
          engine: engine,
          options: options,
        ),
        [utf8.encode('x')],
      );
      await expectLater(
        fromRecipient(out.replay()),
        streamError('Unexpected stream key mode'),
      );
    });

    test('a modified header changes the key', () async {
      final out = await write(toRecipient, [utf8.encode('secret')]);
      // Flip a byte of the KEM ciphertext (the end of the header).
      final reader = await fromRecipient(
        out.replay((i, f) => i == 0 ? [flip(f, f.length - 1)] : [f]),
      );
      await expectLater(reader.read(), streamError('Record failed'));
    });

    test('a modified record is rejected', () async {
      final out = await write(toRecipient, [
        utf8.encode('a'),
        utf8.encode('b'),
      ]);
      final reader = await fromRecipient(
        out.replay((i, f) => i == 2 ? [flip(f, f.length - 1)] : [f]),
      );
      expect(utf8.decode((await reader.read())!), 'a');
      await expectLater(reader.read(), streamError('Record failed'));
      expect(reader.read, throwsStateError);
    });

    test('reordered records are rejected', () async {
      final out = await write(toRecipient, [
        utf8.encode('a'),
        utf8.encode('b'),
      ]);
      final reader = await fromRecipient(
        out.replay(
          (i, f) => switch (i) {
            1 => [out.frames[2]],
            2 => [out.frames[1]],
            _ => [f],
          },
        ),
      );
      await expectLater(reader.read(), streamError('Record failed'));
    });

    test('a truncated stream is detected', () async {
      final out = await write(toRecipient, [utf8.encode('a')]);
      // Drop the End record.
      final reader = await fromRecipient(
        out.replay((i, f) => i == out.frames.length - 1 ? [] : [f]),
      );
      expect(utf8.decode((await reader.read())!), 'a');
      await expectLater(reader.read(), streamError('truncated'));
    });

    test('data after the end is rejected', () async {
      final out = await write(toRecipient, [utf8.encode('a')]);
      final reader = await fromRecipient(
        out.replay(
          (i, f) => i == out.frames.length - 1 ? [f, out.frames[1]] : [f],
        ),
      );
      expect(utf8.decode((await reader.read())!), 'a');
      await expectLater(reader.read(), streamError('Data after end'));
    });

    test('an empty input is refused', () async {
      await expectLater(
        fromRecipient(const Stream.empty()),
        streamError('closed by peer'),
      );
    });

    test('garbage instead of a header is refused', () async {
      await expectLater(
        fromRecipient(Stream.value([0, 0, 0, 3, 0x10, 1, 1])),
        streamError('Malformed stream header'),
      );
    });

    test('an AEAD the reader policy forbids is refused', () async {
      final out = await write(
        (s) => SecureStream.encryptTo(
          s,
          recipient: mlKem.publicKey,
          engine: engine,
          options: const SecureStreamOptions(
            protocol: 'test/backup/v1',
            aead: AeadAlgorithm.chacha20Poly1305,
          ),
        ),
        [utf8.encode('x')],
      );
      await expectLater(
        SecureStream.decryptFrom(
          out.replay(),
          privateKey: mlKem.privateKey,
          engine: engine.withPolicy(
            SecurityPolicy.standard.copyWith(
              allowedAeads: {AeadAlgorithm.aes256Gcm},
            ),
          ),
          options: options,
        ),
        streamError('Cannot open stream'),
      );
    });

    test('ChaCha20-Poly1305 streams round-trip', () async {
      const chacha = SecureStreamOptions(
        protocol: 'test/backup/v1',
        aead: AeadAlgorithm.chacha20Poly1305,
      );
      final out = await write(
        (s) => SecureStream.encryptTo(
          s,
          recipient: mlKem.publicKey,
          engine: engine,
          options: chacha,
        ),
        [utf8.encode('chacha')],
      );
      // The reader takes the AEAD from the header.
      expect(await readAll(await fromRecipient(out.replay())), ['chacha']);
    });
  });

  group('with a shared key', () {
    SecureStreamWriter encrypt(StreamSink<List<int>> s) =>
        SecureStream.encryptWithKey(
          s,
          sharedKey: sharedKey,
          engine: engine,
          options: options,
        );

    test('round-trips messages', () async {
      final out = await write(encrypt, [utf8.encode('a'), utf8.encode('b')]);
      final reader = await SecureStream.decryptWithKey(
        out.replay(),
        sharedKey: sharedKey,
        engine: engine,
        options: options,
      );
      expect(await readAll(reader), ['a', 'b']);
    });

    test('reusing the key still gives every stream its own key', () async {
      final a = await write(encrypt, [utf8.encode('same')]);
      final b = await write(encrypt, [utf8.encode('same')]);
      expect(a.frames[1], isNot(b.frames[1]));
    });

    test('a wrong key fails on the first record', () async {
      final out = await write(encrypt, [utf8.encode('a')]);
      final reader = await SecureStream.decryptWithKey(
        out.replay(),
        sharedKey: Uint8List(32),
        engine: engine,
        options: options,
      );
      await expectLater(reader.read(), streamError('Record failed'));
    });

    test('a short key is refused', () {
      expect(
        () => SecureStream.encryptWithKey(
          StreamController<List<int>>(),
          sharedKey: Uint8List(31),
        ),
        throwsA(isA<InvalidInputException>()),
      );
      expect(
        () => SecureStream.decryptWithKey(
          const Stream.empty(),
          sharedKey: Uint8List(16),
        ),
        throwsA(isA<InvalidInputException>()),
      );
    });

    test('works with a key from establishHybridKey', () async {
      const t = HybridTranscript(
        protocol: 'test/stream',
        initiatorId: 'a',
        responderId: 'b',
      );
      final init = engine.establishHybridKey(xWing.publicKey, transcript: t);
      final key = engine.acceptHybridKey(
        init.message,
        privateKey: xWing.privateKey,
        transcript: t,
      );
      final out = await write(
        (s) => SecureStream.encryptWithKey(s, sharedKey: init.sessionKey),
        [utf8.encode('hybrid')],
      );
      final reader = await SecureStream.decryptWithKey(
        out.replay(),
        sharedKey: key,
      );
      expect(await readAll(reader), ['hybrid']);
    });
  });

  group('writer and reader', () {
    test('a live pipe delivers messages as they are written', () async {
      final pipe = StreamController<List<int>>();
      final writer = toRecipient(pipe.sink);
      final reader = fromRecipient(pipe.stream);
      writer.add(utf8.encode('first'));
      final r = await reader;
      expect(utf8.decode((await r.read())!), 'first');
      writer.add(utf8.encode('second'));
      expect(utf8.decode((await r.read())!), 'second');
      await writer.close();
      expect(await r.read(), isNull);
    });

    test('addStream writes every message and closes', () async {
      final out = Captured();
      await toRecipient(
        out.sink,
      ).addStream(Stream.fromIterable(['x', 'y'].map(utf8.encode)));
      await out.done;
      expect(await readAll(await fromRecipient(out.replay())), ['x', 'y']);
    });

    test('close is idempotent and ends writing', () async {
      final out = Captured();
      final writer = toRecipient(out.sink);
      expect(writer.isOpen, isTrue);
      await writer.close();
      await writer.close();
      expect(writer.isOpen, isFalse);
      expect(() => writer.add([1]), throwsStateError);
    });

    test('an aborted writer leaves a truncated stream', () async {
      final out = Captured();
      final writer = toRecipient(out.sink)..add(utf8.encode('partial'));
      await writer.abort();
      expect(() => writer.add([1]), throwsStateError);
      await out.done;
      final reader = await fromRecipient(out.replay());
      expect(utf8.decode((await reader.read())!), 'partial');
      await expectLater(reader.read(), streamError('truncated'));
    });

    test('messages over the reader limit are rejected', () async {
      final out = await write(toRecipient, [Uint8List(5000)]);
      final reader = await fromRecipient(
        out.replay(),
        null,
        const SecureStreamOptions(
          protocol: 'test/backup/v1',
          maxMessageLength: 4999,
        ),
      );
      await expectLater(reader.read(), streamError('Message too long'));
    });

    test('a stalled input fails after receiveTimeout', () async {
      final pipe = StreamController<List<int>>();
      toRecipient(pipe.sink).add([1]);
      final reader = await fromRecipient(
        pipe.stream,
        null,
        const SecureStreamOptions(
          protocol: 'test/backup/v1',
          receiveTimeout: Duration(milliseconds: 200),
        ),
      );
      expect(await reader.read(), [1]);
      await expectLater(reader.read(), streamError('Receive timed out'));
    });

    test('cancel fails a pending read', () async {
      final pipe = StreamController<List<int>>();
      toRecipient(pipe.sink);
      final reader = await fromRecipient(pipe.stream);
      final pending = reader.read();
      await reader.cancel();
      await expectLater(pending, streamError('cancelled locally'));
      expect(reader.read, throwsStateError);
    });

    test('concurrent reads are refused', () async {
      final pipe = StreamController<List<int>>();
      final writer = toRecipient(pipe.sink);
      final reader = await fromRecipient(pipe.stream);
      final pending = reader.read();
      expect(reader.read, throwsStateError);
      writer.add([9]);
      expect(await pending, [9]);
      await writer.close();
    });
  });
}
