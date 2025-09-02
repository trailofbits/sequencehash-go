package mac

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/sha3"
	"crypto/sha512"
	"fmt"
	"hash"
	"os"
	"path/filepath"

	"encoding/hex"
	"encoding/json"
	"testing"
)

type testCase struct {
	BaseHash      string   `json:"base_hash"`
	ExpectedOut   string   `json:"expected_out"`
	ExpectedInner string   `json:"expected_inner"`
	Key           string   `json:"key"`
	Separator     string   `json:"separator"`
	TestInputs    []string `json:"test_inputs"`
	RawInner      []string `json:"raw_inner"`
	RawOuter      []string `json:"raw_outer"`
}

type testCaseFile struct {
	Tests []testCase `json:"tests"`
}

func loadTestFile(path string) testCaseFile {
	testPath := filepath.Join("testVectors", path)
	testFile, err := os.ReadFile(testPath)
	if err != nil {
		fmt.Println(err)
	}

	var caseFile testCaseFile
	json.Unmarshal(testFile, &caseFile)

	return caseFile
}

func getHash(algo string) func() hash.Hash {
	// We create these SHA3 instances because the SHA3 modules for the Go
	// crypto library don't match the API elsewhere. `sha3.New256` will return
	// a pointer to a SHA3 object, and the `hash.Hash` impedance-matching
	// magic chokes on that. So we have to use `crypto.SHA3_256.New`, but THAT
	// only works if you've already loaded the SHA3 module. Unfortunately, you
	// can't just _import_ the module without USING it, because that creates
	// an unused value. So we have to make SHA3 objects, then do something
	// with THOSE objects to ensure they don't cause an unused value error.
	hash3_256 := sha3.New256()
	hash3_384 := sha3.New384()
	hash3_512 := sha3.New512()
	hash3_256.Write([]byte(nil))
	hash3_384.Write([]byte(nil))
	hash3_512.Write([]byte(nil))

	// Actually get the desired `New` functions
	switch algo {
	case "sha512":
		return sha512.New
	case "sha256":
		return sha256.New
	case "sha384":
		return sha512.New384
	case "sha3_256":
		return crypto.SHA3_256.New
	case "sha3_384":
		return crypto.SHA3_384.New
	case "sha3_512":
		return crypto.SHA3_512.New
	}
	return nil
}

// Returns true if `ElementMAC` produces the correct output for the given key,
// separator, and inputs. If not, returns false. If there is an issue decoding
// the test vector (e.g., an invalid hexadecimal string), calls `t.Fatalf`
func (c *testCase) ValidateOuter(t *testing.T) bool {
	hashFunc := getHash(c.BaseHash)
	if hashFunc == nil {
		t.Fatalf("Could not load hash function: \"%s\"", c.BaseHash)
	}

	// Convert our key and separator from hex to binary
	key, err := hex.DecodeString(c.Key)
	if err != nil {
		t.Fatalf("Could not decode key: \"%s\"", err)
	}
	sep, err := hex.DecodeString(c.Separator)
	if err != nil {
		t.Fatalf("Could not decode separator: \"%s\"", err)
	}

	// Create an ElementMAC object and check the output
	macObj := NewWithSeparator(hashFunc, key, sep)
	for i := 0; i < len(c.TestInputs); i++ {
		input, err := hex.DecodeString(c.TestInputs[i])
		if err != nil {
			t.Fatalf("Could not decode input: \"%s\"", err)
		}
		macObj.Write(input)
	}
	output := macObj.Sum([]byte(nil))
	testOutput, err := hex.DecodeString(c.ExpectedOut)
	if err != nil {
		t.Fatalf("Could not decode input: \"%s\"", err)
	}

	// No match? That's a failed test vector
	if !bytes.Equal(output, testOutput) {
		fmt.Println("Expected: ", testOutput)
		fmt.Println("Computed: ", output)
		return false
	}

	return true
}

// Returns true if the given raw input values produce the correct inner and
// outer hash values. This is intended to test the test vectors rather than the
// `ElementMAC` code. The `raw_inner` and `raw_outer` values are useful for
// debugging implementation problems; if they are out of sync with the rest of
// a given test vector, that needs to be flagged.
func (c *testCase) ValidateRaw(t *testing.T) bool {
	// Now: process the RAW inputs to make sure everything matches
	hashFunc := getHash(c.BaseHash)
	if hashFunc == nil {
		t.Fatalf("Could not load hash function: \"%s\"", c.BaseHash)
	}

	// Decode our expected values
	expected_inner, err := hex.DecodeString(c.ExpectedInner)
	if err != nil {
		t.Fatalf("Could not decode raw inner input: \"%s\"", err)
	}

	expected_outer, err := hex.DecodeString(c.ExpectedOut)
	if err != nil {
		t.Fatalf("Could not decode raw out input: \"%s\"", err)
	}

	inner_hash := hashFunc()
	outer_hash := hashFunc()

	// Inner hash values
	for i := 0; i < len(c.RawInner); i++ {
		raw_input, err := hex.DecodeString(c.RawInner[i])
		if err != nil {
			t.Fatalf("Could not decode raw inner input: \"%s\"", err)
		}
		inner_hash.Write(raw_input)
	}
	inner_result := inner_hash.Sum([]byte(nil))

	// Mismatch means test vector failure
	if !bytes.Equal(expected_inner, inner_result) {
		return false
	}

	// Outer hash values
	for i := 0; i < len(c.RawOuter); i++ {
		raw_input, err := hex.DecodeString(c.RawOuter[i])
		if err != nil {
			t.Fatalf("Could not decode raw outer input: \"%s\"", err)
		}
		outer_hash.Write(raw_input)
	}
	outer_hash.Write(inner_result)

	outer_result := outer_hash.Sum([]byte(nil))
	// Mismatch means test vector failure
	if !bytes.Equal(expected_outer, outer_result) {
		return false
	}

	return true
}

func TestAll(t *testing.T) {
	paths := []string{"vectors_mac_sha256.json", "vectors_mac_sha384.json", "vectors_mac_sha512.json",
		"vectors_mac_sha3_256.json", "vectors_mac_sha3_384.json", "vectors_mac_sha3_512.json"}

	for i := 0; i < len(paths); i++ {
		caseFile := loadTestFile(paths[i])
		for j := 0; j < len(caseFile.Tests); j++ {
			if !caseFile.Tests[j].ValidateOuter(t) {
				t.Fatalf("Outer validation failure in test %d", i)
			}
			if !caseFile.Tests[j].ValidateRaw(t) {
				t.Fatalf("Raw data validation failure in test %d", i)
			}
		}
		fmt.Printf("Tests for \"%s\" passed.\n", paths[i])
	}
}
