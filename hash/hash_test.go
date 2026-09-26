package hash

import (
	"crypto/subtle"
	"crypto/sha256"
	"fmt"

	"encoding/hex"
	"testing"
)

// Spec-1.0.0 KAT for SequenceHash with SHA256
func TestKAT(t *testing.T) {
	customizer, _ := hex.DecodeString("") // Empty customizer
	input0, _ := hex.DecodeString("")
	input1, _ := hex.DecodeString("01")
	input2, _ := hex.DecodeString("0202")
	input3, _ := hex.DecodeString("030303")
	hasher, _ := New(sha256.New)
	hasher.Add(input0)
	hasher.Add(input1)
	hasher.Add(input2)
	hasher.Add(input3)
	output := hasher.ResultWithCustomizer(customizer)
	expected, _ := hex.DecodeString("fe550c163f7ce3e8f636ca8770333c4ce33a1d8424b4f383036d424929111144")
	if subtle.ConstantTimeCompare(expected, output) != 1 {
		fmt.Println("Expcted:  ", hex.EncodeToString(expected))
		fmt.Println("Computed: ", hex.EncodeToString(output))
		t.Errorf("KAT failed")
	}
}

func TestDoubleResult(t *testing.T) {
	defer func () {
		if r := recover(); r != nil {
			return
		}
	}()
	hasher, _ := New(sha256.New)
	_ = hasher.Result()
	_ = hasher.Result()
	fmt.Errorf("Second hash should have caused panic!")
}
