package mac

import (
	"crypto/subtle"
	"crypto/sha256"
	"fmt"

	"encoding/hex"
	"testing"
)

// Spec-1.0.0 KAT for SequenceMAC with SHA256
func TestKAT(t *testing.T) {
	key, _ := hex.DecodeString("27ece6764c77eb17e28a4031878198f37ce95207205fba8671390c8d7449dc91")
	customizer, _ := hex.DecodeString("00000000")
	input0, _ := hex.DecodeString("74aee83f30db3fd88d6e31ad41710cb8d9a5dd01aad1d1")
	input1, _ := hex.DecodeString("f1ed6e58d442903e34571544a8af4f49e86790417916f538746911edbbd34fb9")
	input2, _ := hex.DecodeString("bd121635c5c732")
	hasher, _ := New(sha256.New, key)
	hasher.Add(input0)
	hasher.Add(input1)
	hasher.Add(input2)
	output := hasher.ResultWithCustomizer(customizer)
	expected, _ := hex.DecodeString("484ad123ab6f1fea03ac9ae765a38bd34128367f408eada7ff8c21b3cd8515c3")
	//if expected != output {
	if subtle.ConstantTimeCompare(expected, output) != 1 {
		fmt.Println("Expcted:  ", hex.EncodeToString(expected))
		fmt.Println("Computed: ", hex.EncodeToString(output))
		t.Errorf("KAT failed")
	}
}

func TestShortKey(t *testing.T) {
	key, _ := hex.DecodeString("0000000000000000") // Invalid key-- only 64 bits
	hasher, err := New(sha256.New, key)
	if err == nil || hasher != nil {
		t.Errorf("Short key accepted; this should not happen!")
	}
}

func TestDoubleResult(t *testing.T) {
	defer func () {
		if r := recover(); r != nil {
			return
		}
	}()
	key, _ := hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000000")
	hasher, _ := New(sha256.New, key)
	_ = hasher.Result()
	_ = hasher.Result()
	fmt.Errorf("Second MAC should have caused panic!")
}
