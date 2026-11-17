// This module runs the C2SP/CCTV SequenceHash test vectors against the
// library. It is a separate module so that the library itself has no
// dependencies; golang.org/x/crypto is only needed here for BLAKE2.
module github.com/trailofbits/sequencehash-go/conformance

go 1.24.4

require (
	github.com/trailofbits/sequencehash-go v0.0.0
	golang.org/x/crypto v0.48.0
)

require golang.org/x/sys v0.41.0 // indirect

replace github.com/trailofbits/sequencehash-go => ../
