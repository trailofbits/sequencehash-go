// Package conformance checks this implementation against the C2SP/CCTV
// SequenceHash test vectors (https://github.com/C2SP/CCTV/tree/main/sequencehash).
//
// The vectors are not vendored. Point SEQUENCEHASH_CCTV_DIR at the
// "sequencehash" directory of a CCTV checkout to run them:
//
//	git clone https://github.com/C2SP/CCTV /tmp/cctv
//	git -C /tmp/cctv checkout 50a8ecf2a220f4c8bdc4f085789b8e85c26829e7
//	SEQUENCEHASH_CCTV_DIR=/tmp/cctv/sequencehash go test ./...
//
// Every file is checked against testdata/cctv.sha256 first, so the test cannot
// silently pass on a partial or modified copy.
package conformance

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha3"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	stdhash "hash"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/blake2s"

	"github.com/trailofbits/sequencehash-go/hash"
	"github.com/trailofbits/sequencehash-go/mac"
)

const (
	envDir         = "SEQUENCEHASH_CCTV_DIR"
	vectorsPerFile = 384
)

var hashes = map[string]func() stdhash.Hash{
	"sha1":     sha1.New,
	"sha256":   sha256.New,
	"sha512":   sha512.New,
	"sha3_256": func() stdhash.Hash { return sha3.New256() },
	"sha3_512": func() stdhash.Hash { return sha3.New512() },
	"blake2b":  func() stdhash.Hash { return must(blake2b.New512(nil)) },
	"blake2s":  func() stdhash.Hash { return must(blake2s.New256(nil)) },
}

func must(h stdhash.Hash, err error) stdhash.Hash {
	if err != nil {
		panic(err)
	}
	return h
}

// vector is one entry of a CCTV file. The intermediate values (inner_hash,
// inner_header, outer_header) are not exposed by the public API, so only the
// final output is compared.
type vector struct {
	HashName    string   `json:"hash_name"`
	FunctionID  int      `json:"function_id"`
	Key         string   `json:"key"`
	Customizer  string   `json:"customizer"`
	Inputs      []string `json:"inputs"`
	MustFail    bool     `json:"must_fail"`
	FinalOutput string   `json:"final_output"`
}

type sequence interface {
	Add([]byte)
	ResultWithCustomizer([]byte) []byte
}

func TestCCTV(t *testing.T) {
	dir := os.Getenv(envDir)
	if dir == "" {
		t.Skipf("%s is not set; see the package comment", envDir)
	}

	files := checkedFiles(t, dir)
	if len(files) != 13 {
		t.Fatalf("expected 13 vector files in testdata/cctv.sha256, got %d", len(files))
	}

	for _, file := range files {
		t.Run(file, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(dir, file))
			if err != nil {
				t.Fatal(err)
			}
			var vectors []vector
			if err := json.Unmarshal(raw, &vectors); err != nil {
				t.Fatal(err)
			}
			if len(vectors) != vectorsPerFile {
				t.Fatalf("expected %d vectors, got %d", vectorsPerFile, len(vectors))
			}
			for i, v := range vectors {
				check(t, i, v)
			}
		})
	}
}

// checkedFiles verifies every file listed in testdata/cctv.sha256 and returns
// their paths relative to dir.
func checkedFiles(t *testing.T, dir string) []string {
	t.Helper()
	sums, err := os.Open(filepath.Join("testdata", "cctv.sha256"))
	if err != nil {
		t.Fatal(err)
	}
	defer sums.Close()

	var files []string
	scanner := bufio.NewScanner(sums)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 2 {
			t.Fatalf("malformed checksum line %q", scanner.Text())
		}
		want, file := fields[0], fields[1]
		data, err := os.ReadFile(filepath.Join(dir, file))
		if err != nil {
			t.Fatal(err)
		}
		got := sha256.Sum256(data)
		if hex.EncodeToString(got[:]) != want {
			t.Fatalf("%s: checksum mismatch", file)
		}
		files = append(files, file)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	return files
}

func check(t *testing.T, i int, v vector) {
	t.Helper()
	h, ok := hashes[v.HashName]
	if !ok {
		t.Fatalf("#%d: unknown hash %q", i, v.HashName)
	}

	var seq sequence
	switch v.FunctionID {
	case 1:
		m, err := mac.New(h, unhex(t, v.Key))
		if v.MustFail {
			if err == nil {
				t.Errorf("#%d: key of %d bytes must be rejected", i, len(v.Key)/2)
			}
			return
		}
		if err != nil {
			t.Errorf("#%d: unexpected error: %v", i, err)
			return
		}
		seq = m
	case 2:
		s, err := hash.New(h)
		if err != nil {
			t.Errorf("#%d: unexpected error: %v", i, err)
			return
		}
		seq = s
	default:
		t.Fatalf("#%d: unknown function id %d", i, v.FunctionID)
	}

	if v.MustFail {
		t.Fatalf("#%d: must_fail vector for function id %d is not handled", i, v.FunctionID)
	}

	for _, input := range v.Inputs {
		seq.Add(unhex(t, input))
	}
	got := seq.ResultWithCustomizer(unhex(t, v.Customizer))
	if !bytes.Equal(got, unhex(t, v.FinalOutput)) {
		t.Errorf("#%d: got %x, want %s", i, got, v.FinalOutput)
	}
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
