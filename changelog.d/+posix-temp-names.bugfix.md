`rfc9162-tiles`: `PosixStore` handles in one process draw temporary file names from one counter, so two handles on one root no longer write the same temporary file and rename each other's bytes into place.
A temporary name that is already taken is passed over rather than truncated, and a temporary file whose write fails is removed.
