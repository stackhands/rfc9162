`rfc9162-log` seals a caller-supplied record as one canonical JSON line, signs an Ed25519 head over those lines, and finds a record with its inclusion proof.
A signing key stored inside the log directory, or reached through a symlink there, is refused.
Find answers for a signed head: a record that head covers still proves against it after later records are appended, and a record past the head is refused. Two heads are consistent only when each root is the log prefix it claims to cover.
