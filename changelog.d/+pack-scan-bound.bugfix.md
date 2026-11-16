`rfc9162-tiles`: Opening or refreshing a `PackStore` stops at a record head that declares more bytes than the file holds before sizing a buffer for it.
A torn head after a crash cost an allocation of whatever length its bytes claimed, up to 4 GiB.
