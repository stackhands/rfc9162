The tile split no longer overflows when a tree is wider than 2^63.
A perfect subtree whose span does not fit in a u64 is refused instead of being accepted or panicking.
