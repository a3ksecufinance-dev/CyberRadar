package e2echain

import (
	"errors"
	"io"
	"os"
	"strings"
	"testing"
)

// An annotation is a single line, and it must not carry a password.
func TestAnAnnotationIsOneLineWithNoPassword(t *testing.T) {
	t.Setenv("GITHUB_ACTIONS", "true")
	out := capture(t, func() {
		Annotate("cannot reach %s:\n  %v", "postgres://crp_user:s3cret@db:5432/crp?sslmode=disable",
			errors.New("refused\nand again"))
	})
	if strings.Contains(out, "s3cret") {
		t.Errorf("the password reached the annotation: %s", out)
	}
	if !strings.Contains(out, "crp_user:***@") {
		t.Errorf("the user should survive the redaction: %s", out)
	}
	if n := strings.Count(strings.TrimSuffix(out, "\n"), "\n"); n != 0 {
		t.Errorf("an annotation spanning %d extra lines is truncated by Actions: %q", n, out)
	}
	if !strings.Contains(out, "%0A") {
		t.Errorf("the newlines should be escaped, not dropped: %q", out)
	}

	// And nothing at all outside Actions: the test already prints everything.
	t.Setenv("GITHUB_ACTIONS", "")
	if out := capture(t, func() { Annotate("nothing") }); out != "" {
		t.Errorf("wrote %q outside Actions", out)
	}
}

// capture takes what fn writes to stdout.
func capture(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stdout
	os.Stdout = w
	fn()
	os.Stdout = saved
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}
