`rfc9162-sidecar`: A command line the binary does not take exits with status 2 and opens nothing: the command and its arguments are checked before `DIR/.sidecar/pack` is opened.
An unknown command or a missing argument created the pack, and a non-numeric tree `SIZE`, `include` without `--trusted`, or a `--trusted` line that is not a key exited 1.
