Future<T> runInBackground<T>(T Function() computation) => Future(computation);

const bool isolatesSupported = false;
