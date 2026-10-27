// Measures peak RSS while streaming-encrypting and decrypting a large file.
//
// Usage: dart run tool/memory_probe.dart [sizeMiB]
import 'dart:io';
import 'dart:typed_data';

import 'package:post_quantum_crypto/post_quantum_crypto_io.dart';

Future<void> main(List<String> args) async {
  final mib = args.isEmpty ? 256 : int.parse(args.first);
  final dir = Directory.systemTemp.createTempSync('qc_mem_');
  try {
    final engine = PostQuantumCryptoEngine();
    final kp = engine.generateEncryptionKeyPair();
    final src = File('${dir.path}/big.bin');
    final sink = src.openWrite();
    final block = Uint8List(1024 * 1024);
    for (var i = 0; i < mib; i++) {
      block[0] = i;
      sink.add(block);
      await sink.flush();
    }
    await sink.close();

    final base = ProcessInfo.currentRss;
    final sw = Stopwatch()..start();
    await engine.encryptFile(
      src.path,
      '${dir.path}/big.qc',
      recipients: [kp.publicKey],
    );
    final encMs = sw.elapsedMilliseconds;
    sw.reset();
    await engine.decryptFile(
      '${dir.path}/big.qc',
      '${dir.path}/big.out',
      privateKey: kp.privateKey,
    );
    final decMs = sw.elapsedMilliseconds;
    stdout.writeln(
      'size=${mib}MiB peakRssBytes=${ProcessInfo.maxRss} '
      'baseRss=${base >> 20}MiB '
      'peakRss=${ProcessInfo.maxRss >> 20}MiB '
      'encrypt=${encMs}ms (${(mib * 1000 / encMs).toStringAsFixed(1)} MiB/s) '
      'decrypt=${decMs}ms (${(mib * 1000 / decMs).toStringAsFixed(1)} MiB/s)',
    );
  } finally {
    dir.deleteSync(recursive: true);
  }
}
