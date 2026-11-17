package readme_test

// Runs every Go example in README.md and checks that it prints the output
// block that follows it, so the README cannot drift from the API.

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// fenceRE matches one fenced code block and captures its language and body.
var fenceRE = regexp.MustCompile("(?ms)^```([a-z]*)\n(.*?)^```")

// wantExamples is the number of runnable Go examples in README.md.
const wantExamples = 5

type example struct{ code, output string }

// readmeExamples returns every Go block in the README that is followed
// directly by a plain block holding its output. Go blocks that only show an
// import declaration are not examples and are skipped.
func readmeExamples(t *testing.T, readme string) []example {
	t.Helper()
	blocks := fenceRE.FindAllStringSubmatch(readme, -1)
	var examples []example
	for i, b := range blocks {
		lang, code := b[1], b[2]
		if lang != "go" || strings.HasPrefix(strings.TrimSpace(code), "import") {
			continue
		}
		if i+1 >= len(blocks) || blocks[i+1][1] != "" {
			t.Fatalf("Go example %d has no output block after it:\n%s", len(examples)+1, code)
		}
		examples = append(examples, example{code, blocks[i+1][2]})
	}
	return examples
}

func TestREADMEExamples(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs every README example")
	}
	goBin := filepath.Join(runtime.GOROOT(), "bin", "go")
	if _, err := os.Stat(goBin); err != nil {
		t.Skipf("go toolchain not found at %s", goBin)
	}

	readme, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatal(err)
	}
	examples := readmeExamples(t, string(readme))
	if len(examples) != wantExamples {
		t.Fatalf("expected %d Go examples in README.md, found %d", wantExamples, len(examples))
	}

	root, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	module := modulePath(t)

	dir := t.TempDir()
	goMod := "module example.com/readme\n\ngo 1.24\n\n" +
		"require " + module + " v0.0.0\n\n" +
		"replace " + module + " => " + root + "\n"
	write(t, filepath.Join(dir, "go.mod"), goMod)

	for i, ex := range examples {
		code, want := ex.code, ex.output
		name := fmt.Sprintf("example%d", i+1)
		t.Run(name, func(t *testing.T) {
			src := "package main\n\nimport (\n" +
				"\t\"crypto/sha256\"\n\t\"fmt\"\n\n" +
				"\t\"" + module + "/hash\"\n\t\"" + module + "/mac\"\n)\n\n" +
				"var _, _, _, _ = sha256.New, fmt.Println, hash.New, mac.New\n\n" +
				"func main() {\n" + code + "}\n"
			write(t, filepath.Join(dir, name, "main.go"), src)

			cmd := exec.Command(goBin, "run", "./"+name)
			cmd.Dir = dir
			cmd.Env = append(os.Environ(), "GOFLAGS=-mod=mod", "GOPROXY=off", "GOWORK=off")
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("README example %d failed: %v\n%s\nsource:\n%s", i+1, err, out, code)
			}
			if strings.TrimSpace(string(out)) != strings.TrimSpace(want) {
				t.Errorf("README example %d printed:\n%s\nREADME says:\n%s", i+1, out, want)
			}
		})
	}
}

func modulePath(t *testing.T) string {
	t.Helper()
	f, err := os.Open("go.mod")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if path, ok := strings.CutPrefix(strings.TrimSpace(scanner.Text()), "module "); ok {
			return strings.TrimSpace(path)
		}
	}
	t.Fatal("no module line in go.mod")
	return ""
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
