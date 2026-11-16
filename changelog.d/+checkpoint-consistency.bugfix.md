`rfc9162-tiles`: `Writer::checkpoint` signs only a tree that extends the checkpoint already published under its origin: the same root at that size, or a larger tree the tiles prove consistent with it.
A tree of the published size with another root, or a larger one that does not extend it, is `Error::Corrupt`, where it was signed.
