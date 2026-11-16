`rfc9162-tiles`: `PosixStore::create_new` writes a temporary file and links it at the path, so a write cut short by an error or a crash leaves nothing there, as the store promises, instead of a partial file that every later `create_new` takes for one already stored.
The root must be on a file system with hard links.
