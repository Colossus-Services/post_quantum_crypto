import 'dart:io';
import 'dart:typed_data';

import 'package:quantum_crypto/quantum_crypto_io.dart';
import 'package:test/test.dart';

import '../support/test_engine.dart';

void main() {
  late Directory dir;
  late EncryptionKeyPair kp;

  setUpAll(() => kp = engine.generateEncryptionKeyPair());
  setUp(() => dir = Directory.systemTemp.createTempSync('qc_files_'));
  tearDown(() => dir.deleteSync(recursive: true));

  String p(String name) => '${dir.path}/$name';

  File writeRandom(String name, int size) {
    final data = Uint8List(size);
    for (var i = 0; i < size; i++) {
      data[i] = (i * 2654435761) >> 13 & 0xff;
    }
    return File(p(name))..writeAsBytesSync(data);
  }

  test('file round trip', () async {
    final src = writeRandom('in.bin', 300 * 1024 + 17);
    await engine.encryptFile(
      src.path,
      p('in.bin.qc'),
      recipients: [kp.publicKey],
      chunkSize: 4096,
    );
    await engine.decryptFile(
      p('in.bin.qc'),
      p('out.bin'),
      privateKey: kp.privateKey,
    );
    expect(File(p('out.bin')).readAsBytesSync(), src.readAsBytesSync());
    // No temporary files are left behind.
    expect(dir.listSync().map((e) => e.uri.pathSegments.last).toSet(), {
      'in.bin',
      'in.bin.qc',
      'out.bin',
    });
  });

  test('truncated file publishes no output', () async {
    final src = writeRandom('in.bin', 50 * 1024);
    await engine.encryptFile(
      src.path,
      p('in.qc'),
      recipients: [kp.publicKey],
      chunkSize: 4096,
    );
    final ct = File(p('in.qc')).readAsBytesSync();
    File(p('cut.qc')).writeAsBytesSync(ct.sublist(0, ct.length - 4096 - 16));
    await expectLater(
      engine.decryptFile(p('cut.qc'), p('out.bin'), privateKey: kp.privateKey),
      throwsA(isA<DecryptionFailedException>()),
    );
    expect(File(p('out.bin')).existsSync(), isFalse);
    expect(dir.listSync().where((e) => e.path.endsWith('.qc-tmp')), isEmpty);
  });

  test('cancelled encryption leaves no output', () async {
    final src = writeRandom('in.bin', 200 * 1024);
    final token = CancellationToken();
    await expectLater(
      engine.encryptFile(
        src.path,
        p('in.qc'),
        recipients: [kp.publicKey],
        chunkSize: 1024,
        cancel: token,
        onProgress: (n) {
          if (n > 10 * 1024) token.cancel();
        },
      ),
      throwsA(isA<OperationCancelledException>()),
    );
    expect(File(p('in.qc')).existsSync(), isFalse);
  });

  test('sign and verify a file; manifest of a directory', () async {
    final signer = engine.generateSigningKeyPair();
    final a = writeRandom('a.bin', 10000);
    Directory(p('sub')).createSync();
    writeRandom('sub/b.bin', 2000);

    final sig = await engine.signFile(a.path, privateKey: signer.privateKey);
    await engine.verifyFile(
      a.path,
      signature: sig,
      publicKey: signer.publicKey,
    );

    final manifest = engine.createSignedManifest([
      await engine.manifestEntryForFile(dir.path, 'a.bin'),
      await engine.manifestEntryForFile(dir.path, 'sub/b.bin'),
    ], privateKey: signer.privateKey);
    await engine.verifyManifestFiles(
      manifest,
      dir.path,
      publicKey: signer.publicKey,
    );

    writeRandom('sub/b.bin', 2001);
    await expectLater(
      engine.verifyManifestFiles(
        manifest,
        dir.path,
        publicKey: signer.publicKey,
      ),
      throwsA(isA<SignatureVerificationException>()),
    );
    File(p('a.bin')).deleteSync();
    await expectLater(
      engine.verifyFile(a.path, signature: sig, publicKey: signer.publicKey),
      throwsA(isA<FileSystemException>()),
    );
  });

  test(
    'memory does not scale with file size',
    () async {
      const mib = 1024 * 1024;
      Future<int> roundTrip(int sizeMiB) async {
        final src = File(p('big.bin'));
        final sink = src.openWrite();
        final block = Uint8List(mib);
        for (var i = 0; i < sizeMiB; i++) {
          block[0] = i;
          sink.add(block);
          await sink.flush();
        }
        await sink.close();
        await engine.encryptFile(
          src.path,
          p('big.qc'),
          recipients: [kp.publicKey],
        );
        await engine.decryptFile(
          p('big.qc'),
          p('big.out'),
          privateKey: kp.privateKey,
        );
        expect(File(p('big.out')).lengthSync(), sizeMiB * mib);
        return ProcessInfo.maxRss;
      }

      // Warm up (JIT, GC heap sizing) with a small file, then process a file
      // 8x larger: peak RSS must not grow with the size (an in-memory
      // implementation would need ≥ 2 × 128 MiB more).
      final small = await roundTrip(16);
      final large = await roundTrip(128);
      expect(
        large - small,
        lessThan(48 * mib),
        reason: 'peak RSS grew from ${small ~/ mib} to ${large ~/ mib} MiB',
      );
    },
    tags: ['slow'],
    timeout: const Timeout(Duration(minutes: 10)),
  );
}
