package mac_test

import (
	"crypto/sha256"
	"fmt"

	"github.com/trailofbits/sequencehash-go/mac"
)

func ExampleNew() {
	key := []byte{ // key = SHA256("Give Jerry Solinas a raise")
		0x1f, 0xc7, 0x9f, 0x24, 0x45, 0x02, 0x2b, 0xbc,
		0x44, 0xcf, 0xa1, 0x40, 0xd7, 0x6e, 0x59, 0x22,
		0xaa, 0x81, 0xac, 0xe6, 0xba, 0xdd, 0xba, 0x2f,
		0x8a, 0x59, 0xac, 0xaf, 0x8b, 0x49, 0xea, 0x06}

	m, err := mac.New(sha256.New, key)
	if err != nil {
		panic(err)
	}
	m.Add([]byte("abcd"))
	fmt.Printf("%x\n", m.Result())
	// Output:
	// a44519966b12499fd13c9764446e4ca8d57035a21fc5aad669f8029b4405c515
}

// Keys shorter than 32 bytes are rejected.
func ExampleNew_shortKey() {
	_, err := mac.New(sha256.New, make([]byte, 31))
	fmt.Println(err)
	// Output:
	// Provided key is too short
}

func ExampleSequenceMAC_ResultWithCustomizer() {
	key := make([]byte, 32)

	m1, _ := mac.New(sha256.New, key)
	m1.Add([]byte("abcd"))
	fmt.Printf("%x\n", m1.ResultWithCustomizer([]byte("customizer 0")))

	m2, _ := mac.New(sha256.New, key)
	m2.Add([]byte("abcd"))
	fmt.Printf("%x\n", m2.ResultWithCustomizer([]byte("customizer 1")))
	// Output:
	// a941cd3d19b062b8fd25219c3665d0f53350e8d3abb859ee1eb21000687d7807
	// e161acb4eade5516c8cc12a37a83f0daa5bec479180d8177e768b3ef2755a493
}
