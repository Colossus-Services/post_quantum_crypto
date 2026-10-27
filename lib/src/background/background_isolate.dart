import 'dart:isolate';

Future<T> runInBackground<T>(T Function() computation) =>
    Isolate.run(computation);

const bool isolatesSupported = true;
