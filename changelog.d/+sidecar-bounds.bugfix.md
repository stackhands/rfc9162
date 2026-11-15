A sidecar whose pair count or key length does not fit in its u16 prefix is refused, instead of being written with the length truncated.
A bundle of more than 256 entries is refused, because the entry offset is one byte.
