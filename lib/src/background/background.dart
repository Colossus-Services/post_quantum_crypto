import 'background_inline.dart'
    if (dart.library.isolate) 'background_isolate.dart'
    as impl;

/// Runs a CPU-bound [computation] off the current isolate where possible.
///
/// On native platforms (Dart VM, Flutter mobile/desktop) this is
/// `Isolate.run`: the closure and its result are copied to and from a new
/// isolate, so key material passed in is copied as well. On the web there are
/// no isolates; the computation runs on the current thread, in a later
/// microtask, and still blocks the event loop while it runs.
///
/// ```dart
/// final kp = await runInBackground(engine.generateSigningKeyPair);
/// ```
Future<T> runInBackground<T>(T Function() computation) =>
    impl.runInBackground(computation);

/// Whether [runInBackground] really runs off the calling thread.
bool get backgroundIsolatesSupported => impl.isolatesSupported;
