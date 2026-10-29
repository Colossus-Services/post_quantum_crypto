/// Key serialization.
///
/// Two families of formats:
///
/// - **Standardized** (interoperable): raw FIPS 203/204/205 key encodings,
///   X.509 `SubjectPublicKeyInfo` and PKCS#8 `OneAsymmetricKey` DER with the
///   NIST OIDs (RFC 9881 for ML-DSA, RFC 9909 for SLH-DSA,
///   draft-ietf-lamps-kyber-certificates for ML-KEM), and PEM.
/// - **Package-specific**: the `PQCR` key record, which also carries
///   [KeyMetadata]. X-Wing keys only have this form.
library;

import 'dart:typed_data';

import 'package:meta/meta.dart';

import '../algorithms/algorithms.dart';
import '../context.dart';
import '../encoding/bytes.dart';
import '../encoding/canonical.dart';
import '../encoding/der.dart';
import '../errors.dart';
import 'key_factory.dart';
import 'key_metadata.dart';
import 'keys.dart';

/// Which private-key representation to put into PKCS#8.
enum PrivateKeyDerForm {
  /// The seed only (smallest; recommended by the IETF LAMPS drafts).
  seed,

  /// The expanded FIPS secret key only.
  expanded,

  /// Both, as `SEQUENCE { seed, expandedKey }`.
  both,
}

const _kindEncPub = 1;
const _kindEncPriv = 2;
const _kindSigPub = 3;
const _kindSigPriv = 4;

const _formSeed = 1;
const _formExpanded = 2;

const int _maxKeyField = 64 * 1024;

String? _kemOid(KemAlgorithm a) => switch (a) {
  KemAlgorithm.mlKem512 => '2.16.840.1.101.3.4.4.1',
  KemAlgorithm.mlKem768 => '2.16.840.1.101.3.4.4.2',
  KemAlgorithm.mlKem1024 => '2.16.840.1.101.3.4.4.3',
  KemAlgorithm.xWing => null,
};

String _sigOid(SignatureAlgorithm a) => switch (a) {
  SignatureAlgorithm.mlDsa44 => '2.16.840.1.101.3.4.3.17',
  SignatureAlgorithm.mlDsa65 => '2.16.840.1.101.3.4.3.18',
  SignatureAlgorithm.mlDsa87 => '2.16.840.1.101.3.4.3.19',
  SignatureAlgorithm.slhDsaShake128s => '2.16.840.1.101.3.4.3.26',
  SignatureAlgorithm.slhDsaShake128f => '2.16.840.1.101.3.4.3.27',
  SignatureAlgorithm.slhDsaShake192s => '2.16.840.1.101.3.4.3.28',
  SignatureAlgorithm.slhDsaShake192f => '2.16.840.1.101.3.4.3.29',
  SignatureAlgorithm.slhDsaShake256s => '2.16.840.1.101.3.4.3.30',
  SignatureAlgorithm.slhDsaShake256f => '2.16.840.1.101.3.4.3.31',
};

Object _algorithmForOid(Uint8List oid) {
  for (final a in KemAlgorithm.values) {
    final o = _kemOid(a);
    if (o != null && constantTimeEquals(encodeOid(o), oid)) return a;
  }
  for (final a in SignatureAlgorithm.values) {
    if (constantTimeEquals(encodeOid(_sigOid(a)), oid)) return a;
  }
  throw const UnsupportedAlgorithmException('Unknown key algorithm OID');
}

/// Encodes and decodes keys. Internal; reached through the engine.
@internal
final class KeyCodec {
  final CryptoContext _ctx;
  final KeyFactory _factory;

  KeyCodec(this._ctx, this._factory);

  // ---------------------------------------------------------------------------
  // PQCR key record
  // ---------------------------------------------------------------------------

  /// `PQCR 01 07 || u8 kind || u16 alg || bytes32 publicKey ||
  /// [u8 form || bytes32 privateMaterial] || metadata`.
  Uint8List encodeRecord(QuantumKey key) {
    final w = ByteWriter();
    writeHeader(w, ObjectType.keyRecord);
    switch (key) {
      case EncryptionPublicKey k:
        w
          ..u8(_kindEncPub)
          ..u16(k.algorithm.id)
          ..bytes32(k.bytes);
      case EncryptionPrivateKey k:
        w
          ..u8(_kindEncPriv)
          ..u16(k.algorithm.id)
          ..bytes32(k.publicKey.bytes);
        if (k.hasSeed) {
          w
            ..u8(_formSeed)
            ..bytes32(k.seed);
        } else {
          w
            ..u8(_formExpanded)
            ..bytes32(k.secret.part(0));
        }
      case SigningPublicKey k:
        w
          ..u8(_kindSigPub)
          ..u16(k.algorithm.id)
          ..bytes32(k.bytes);
      case SigningPrivateKey k:
        w
          ..u8(_kindSigPriv)
          ..u16(k.algorithm.id)
          ..bytes32(k.publicKey.bytes);
        final seed = k.seedOrNull;
        if (seed != null) {
          w
            ..u8(_formSeed)
            ..bytes32(seed);
        } else {
          w
            ..u8(_formExpanded)
            ..bytes32(k.secretKey);
        }
    }
    key.metadata.write(w);
    return w.toBytes();
  }

  /// Decodes a key record. Private keys are re-derived from their private
  /// material and must reproduce the stored public key. [verifySlhDsaKey]
  /// false skips the SLH-DSA `PK.root` recomputation (see
  /// `KeyFactory.signingPrivateKeyFromExpanded`).
  QuantumKey decodeRecord(Uint8List bytes, {bool verifySlhDsaKey = true}) =>
      parseStrict(() {
        final r = ByteReader(bytes);
        _ctx.readObjectHeader(r, ObjectType.keyRecord);
        final kind = r.u8();
        final algId = r.u16();
        final pk = r.bytes32(max: _maxKeyField);
        int? form;
        Uint8List? material;
        if (kind == _kindEncPriv || kind == _kindSigPriv) {
          form = r.u8();
          if (form != _formSeed && form != _formExpanded) {
            throw const MalformedDataException('Unknown private key form');
          }
          material = r.bytes32(max: _maxKeyField);
        }
        final metadata = KeyMetadata.read(r);
        r.expectEnd();
        try {
          return _buildKey(
            kind,
            algId,
            pk,
            form,
            material,
            metadata,
            verifySlhDsaKey: verifySlhDsaKey,
          );
        } finally {
          zeroize(material);
        }
      });

  QuantumKey _buildKey(
    int kind,
    int algId,
    Uint8List pk,
    int? form,
    Uint8List? material,
    KeyMetadata metadata, {
    required bool verifySlhDsaKey,
  }) {
    switch (kind) {
      case _kindEncPub:
        return _factory.encryptionPublicKey(
          KemAlgorithm.fromId(algId),
          pk,
          metadata,
        );
      case _kindEncPriv:
        final alg = KemAlgorithm.fromId(algId);
        final key = form == _formSeed
            ? _factory.encryptionPrivateKeyFromSeed(alg, material!, metadata)
            : _factory.encryptionPrivateKeyFromExpanded(
                alg,
                material!,
                metadata,
              );
        if (!constantTimeEquals(key.publicKey.bytes, pk)) {
          key.destroy();
          throw const InvalidKeyException('Private and public key mismatch');
        }
        return key;
      case _kindSigPub:
        return _factory.signingPublicKey(
          SignatureAlgorithm.fromId(algId),
          pk,
          metadata,
        );
      case _kindSigPriv:
        final alg = SignatureAlgorithm.fromId(algId);
        if (form == _formExpanded) {
          // Checks the secret key against the stored public key itself.
          return _factory.signingPrivateKeyFromExpanded(
            alg,
            material!,
            pk,
            metadata,
            verifySlhDsaKey: verifySlhDsaKey,
          );
        }
        final key = _factory.signingPrivateKeyFromSeed(
          alg,
          material!,
          metadata,
        );
        if (!constantTimeEquals(key.publicKey.bytes, pk)) {
          key.destroy();
          throw const InvalidKeyException('Private and public key mismatch');
        }
        return key;
      default:
        throw const MalformedDataException('Unknown key kind');
    }
  }

  // ---------------------------------------------------------------------------
  // SubjectPublicKeyInfo / PKCS#8
  // ---------------------------------------------------------------------------

  Uint8List encodeSpki(QuantumKey key) {
    final (oid, pk) = switch (key) {
      EncryptionPublicKey k => (_requireKemOid(k.algorithm), k.bytes),
      SigningPublicKey k => (_sigOid(k.algorithm), k.bytes),
      _ => throw const InvalidInputException('SPKI requires a public key'),
    };
    return derSequence([
      derSequence([derTlv(DerTag.oid, encodeOid(oid))]),
      derTlv(DerTag.bitString, [0, ...pk]),
    ]);
  }

  QuantumKey decodeSpki(Uint8List der) {
    final outer = DerReader(der);
    final spki = DerReader(outer.expect(DerTag.sequence));
    outer.expectEnd();
    final algId = DerReader(spki.expect(DerTag.sequence));
    final oid = algId.expect(DerTag.oid);
    // RFC 9881/9909: parameters MUST be absent.
    algId.expectEnd();
    final bits = spki.expect(DerTag.bitString);
    spki.expectEnd();
    if (bits.isEmpty || bits[0] != 0) {
      throw const MalformedDataException('Invalid BIT STRING');
    }
    final pk = bits.sublist(1);
    return switch (_algorithmForOid(oid)) {
      KemAlgorithm a => _factory.encryptionPublicKey(
        a,
        pk,
        const KeyMetadata(),
      ),
      SignatureAlgorithm a => _factory.signingPublicKey(
        a,
        pk,
        const KeyMetadata(),
      ),
      _ => throw const UnsupportedAlgorithmException('Unsupported OID'),
    };
  }

  Uint8List encodePkcs8(QuantumKey key, PrivateKeyDerForm form) {
    final String oid;
    Uint8List? seed;
    Uint8List expanded;
    bool slh = false;
    switch (key) {
      case EncryptionPrivateKey k:
        oid = _requireKemOid(k.algorithm);
        seed = k.hasSeed ? k.seed : null;
        expanded = k.secret.part(0);
      case SigningPrivateKey k:
        oid = _sigOid(k.algorithm);
        slh = k.algorithm.isSlhDsa;
        seed = k.seedOrNull;
        expanded = k.secretKey;
      default:
        throw const InvalidInputException('PKCS#8 requires a private key');
    }
    final Uint8List privateKey;
    if (slh) {
      // RFC 9909: the privateKey OCTET STRING holds the raw secret key.
      privateKey = expanded;
    } else {
      if (form != PrivateKeyDerForm.expanded && seed == null) {
        throw const InvalidKeyException('Key has no seed form');
      }
      privateKey = switch (form) {
        PrivateKeyDerForm.seed => derTlv(DerTag.contextPrimitive0, seed!),
        PrivateKeyDerForm.expanded => derTlv(DerTag.octetString, expanded),
        PrivateKeyDerForm.both => derSequence([
          derTlv(DerTag.octetString, seed!),
          derTlv(DerTag.octetString, expanded),
        ]),
      };
    }
    return derSequence([
      derTlv(DerTag.integer, [0]),
      derSequence([derTlv(DerTag.oid, encodeOid(oid))]),
      derTlv(DerTag.octetString, privateKey),
    ]);
  }

  QuantumKey decodePkcs8(Uint8List der) {
    final outer = DerReader(der);
    final seq = DerReader(outer.expect(DerTag.sequence));
    outer.expectEnd();
    final version = seq.expect(DerTag.integer);
    if (version.length != 1 || (version[0] != 0 && version[0] != 1)) {
      throw const UnsupportedFormatException('Unsupported PKCS#8 version');
    }
    final algId = DerReader(seq.expect(DerTag.sequence));
    final oid = algId.expect(DerTag.oid);
    algId.expectEnd();
    final privateKey = seq.expect(DerTag.octetString);
    // RFC 5958: [0] attributes (ignored) and, in v2 only, [1] publicKey
    // (checked below). Nothing else may follow.
    Uint8List? embeddedPublicKey;
    if (!seq.isAtEnd) {
      DerElement? e = seq.read();
      if (e.tag == DerTag.contextConstructed0) {
        e = seq.isAtEnd ? null : seq.read();
      }
      if (e != null) {
        if (e.tag != DerTag.contextPrimitive1) {
          throw const MalformedDataException('Unexpected PKCS#8 element');
        }
        if (version[0] != 1) {
          throw const MalformedDataException('publicKey requires PKCS#8 v2');
        }
        if (e.value.isEmpty || e.value[0] != 0) {
          throw const MalformedDataException('Invalid BIT STRING');
        }
        embeddedPublicKey = e.value.sublist(1);
      }
      seq.expectEnd();
    }
    final alg = _algorithmForOid(oid);
    final key = _decodePrivateKey(alg, privateKey, embeddedPublicKey);
    final derived = switch (key) {
      EncryptionPrivateKey k => k.publicKey.bytes,
      SigningPrivateKey k => k.publicKey.bytes,
      _ => throw const InvalidKeyException('Not a private key'),
    };
    if (embeddedPublicKey != null &&
        !constantTimeEquals(derived, embeddedPublicKey)) {
      switch (key) {
        case EncryptionPrivateKey k:
          k.destroy();
        case SigningPrivateKey k:
          k.destroy();
        default:
      }
      throw const InvalidKeyException('Embedded public key does not match');
    }
    return key;
  }

  QuantumKey _decodePrivateKey(
    Object alg,
    Uint8List privateKey,
    Uint8List? embeddedPublicKey,
  ) {
    if (alg is SignatureAlgorithm && alg.isSlhDsa) {
      return _factory.signingPrivateKeyFromExpanded(
        alg,
        privateKey,
        null,
        const KeyMetadata(),
      );
    }

    Uint8List? seed;
    Uint8List? expanded;
    final inner = DerReader(privateKey);
    final e = inner.read();
    inner.expectEnd();
    switch (e.tag) {
      case DerTag.contextPrimitive0:
        seed = e.value;
      case DerTag.octetString:
        expanded = e.value;
      case DerTag.sequence:
        final both = DerReader(e.value);
        seed = both.expect(DerTag.octetString);
        expanded = both.expect(DerTag.octetString);
        both.expectEnd();
      default:
        throw const MalformedDataException('Unknown private key CHOICE');
    }

    switch (alg) {
      case KemAlgorithm a:
        final key = seed != null
            ? _factory.encryptionPrivateKeyFromSeed(
                a,
                seed,
                const KeyMetadata(),
              )
            : _factory.encryptionPrivateKeyFromExpanded(
                a,
                expanded!,
                const KeyMetadata(),
              );
        if (seed != null &&
            expanded != null &&
            !constantTimeEquals(key.secret.part(0), expanded)) {
          key.destroy();
          throw const InvalidKeyException('Seed and expanded key mismatch');
        }
        return key;
      case SignatureAlgorithm a:
        if (seed == null) {
          // The public key is recomputed from the expanded key; a v2
          // embedded public key must match it.
          return _factory.signingPrivateKeyFromExpanded(
            a,
            expanded!,
            embeddedPublicKey,
            const KeyMetadata(),
          );
        }
        final key = _factory.signingPrivateKeyFromSeed(
          a,
          seed,
          const KeyMetadata(),
        );
        if (expanded != null && !constantTimeEquals(key.secretKey, expanded)) {
          key.destroy();
          throw const InvalidKeyException('Seed and expanded key mismatch');
        }
        return key;
      default:
        throw const UnsupportedAlgorithmException('Unsupported OID');
    }
  }

  static String _requireKemOid(KemAlgorithm a) {
    final oid = _kemOid(a);
    if (oid == null) {
      throw UnsupportedAlgorithmException(
        '${a.standardName} has no standardized DER form',
      );
    }
    return oid;
  }
}
