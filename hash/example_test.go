package hash_test

import (
	"crypto/sha256"
	"fmt"

	"github.com/trailofbits/sequencehash-go/hash"
)

// Each call to Add is one element of the sequence, so adding "ab" then "cd"
// is not the same as adding "abcd".
func ExampleNew() {
	h, err := hash.New(sha256.New)
	if err != nil {
		panic(err)
	}
	h.Add([]byte("ab"))
	h.Add([]byte("cd"))
	fmt.Printf("%x\n", h.Result())

	h, _ = hash.New(sha256.New)
	h.Add([]byte("abcd"))
	fmt.Printf("%x\n", h.Result())
	// Output:
	// db972883a869d94f6c9ded7513f83e1b5e8b6c57996859aaa61ccac8386d656c
	// 12714159e45e2865f914d1ba69437d271375dd8028cd510365c546f8f6d2d116
}

func ExampleSequenceHash_ResultWithCustomizer() {
	h1, _ := hash.New(sha256.New)
	h1.Add([]byte("abcd"))
	fmt.Printf("%x\n", h1.ResultWithCustomizer([]byte("customizer1")))

	h2, _ := hash.New(sha256.New)
	h2.Add([]byte("abcd"))
	fmt.Printf("%x\n", h2.ResultWithCustomizer([]byte("customizer2")))
	// Output:
	// d383645c5e97f9addde6dbb0f750f6029ad69f94398ee8f3e285278d40a89c73
	// e1b71fac279ffba3d82d17692142392567cf7984f10bbf7310543743211f6b85
}
