`rfc9162-log` seals a caller-supplied record as one canonical JSON line, signs an Ed25519 head over those lines, and finds a record with its inclusion proof.
A signing key stored inside the log directory is refused.
