/// Typed errors raised by `post_quantum_crypto`.
///
/// Every error is a [PostQuantumCryptoException]. Messages are fixed, descriptive
/// strings: they never contain key material, plaintext, shared secrets or any
/// other sensitive intermediate value.
library;

/// Base class of every error raised by this package.
sealed class PostQuantumCryptoException implements Exception {
  /// A human-readable description. Never contains secret material.
  final String message;

  const PostQuantumCryptoException(this.message);

  @override
  String toString() => '$runtimeType: $message';
}

/// An argument supplied by the caller is invalid (wrong length, out of range,
/// empty where a value is required, ...).
final class InvalidInputException extends PostQuantumCryptoException {
  const InvalidInputException(super.message);
}

/// Serialized data is structurally invalid: bad magic, truncated, trailing
/// bytes, impossible lengths or non-canonical encodings.
final class MalformedDataException extends PostQuantumCryptoException {
  const MalformedDataException(super.message);
}

/// An algorithm identifier is unknown or not implemented.
final class UnsupportedAlgorithmException extends PostQuantumCryptoException {
  const UnsupportedAlgorithmException(super.message);
}

/// A serialized object uses a format version or object type that this
/// release does not understand.
final class UnsupportedFormatException extends PostQuantumCryptoException {
  const UnsupportedFormatException(super.message);
}

/// A key is malformed, has the wrong algorithm, fails its consistency checks
/// or is not usable for the requested operation.
final class InvalidKeyException extends PostQuantumCryptoException {
  const InvalidKeyException(super.message);
}

/// Authenticated decryption failed.
///
/// Raised for every failure that happens after an encrypted object has been
/// parsed: wrong key, tampered ciphertext, tampered tag, tampered metadata,
/// truncated or reordered streams. The cause is deliberately not reported, so
/// the error cannot act as a decryption or decapsulation oracle.
final class DecryptionFailedException extends PostQuantumCryptoException {
  const DecryptionFailedException() : super('Authenticated decryption failed');
}

/// A signature did not verify.
final class SignatureVerificationException extends PostQuantumCryptoException {
  const SignatureVerificationException([
    super.message = 'Signature verification failed',
  ]);
}

/// The platform does not provide a cryptographically secure random source.
/// Operations fail closed instead of falling back to a weaker generator.
final class SecureRandomUnavailableException
    extends PostQuantumCryptoException {
  const SecureRandomUnavailableException([
    super.message = 'No cryptographically secure random source is available',
  ]);
}

/// The current platform lacks a capability required by the operation.
final class UnsupportedPlatformException extends PostQuantumCryptoException {
  const UnsupportedPlatformException(super.message);
}

/// An input exceeds a configured size, count or resource limit. Raised before
/// the oversized allocation or expensive computation happens.
final class ResourceLimitExceededException extends PostQuantumCryptoException {
  const ResourceLimitExceededException(super.message);
}

/// The configured `SecurityPolicy` forbids the operation (prohibited
/// algorithm, expired or revoked key, disallowed key usage, ...).
final class PolicyViolationException extends PostQuantumCryptoException {
  const PolicyViolationException(super.message);
}

/// No recipient entry, key or record matched the requested key.
final class KeyNotFoundException extends PostQuantumCryptoException {
  const KeyNotFoundException(super.message);
}

/// Authenticated context of an encrypted object does not match the values the
/// caller required.
final class ContextMismatchException extends PostQuantumCryptoException {
  const ContextMismatchException(super.message);
}

/// The operation was cancelled through a `CancellationToken`.
final class OperationCancelledException extends PostQuantumCryptoException {
  const OperationCancelledException([super.message = 'Operation cancelled']);
}
