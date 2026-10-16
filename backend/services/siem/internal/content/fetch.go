package content

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Fetch brings a pack within reach, from a path or a URL, and returns where it
// landed along with a function to clean up after it.
//
// Deliberately small. The interesting part of publishing content separately is
// that a deployment can verify what it got, not how it got it — a release
// fetched over HTTPS and one copied by an operator onto a disconnected network
// are the same claim once the signature checks out, and the second is how a
// bank actually does this.
//
// Only https for a remote: http would mean an operator could be handed a
// different pack by anyone on the path, and while the signature would catch a
// tampered one, it would not catch being given an older genuine one.
func Fetch(ctx context.Context, from string) (local string, cleanup func(), err error) {
	noop := func() {}

	if !strings.Contains(from, "://") {
		if _, err := os.Stat(from); err != nil {
			return "", noop, fmt.Errorf("read %s: %w", from, err)
		}
		return from, noop, nil
	}

	u, err := url.Parse(from)
	if err != nil {
		return "", noop, fmt.Errorf("parse %s: %w", from, err)
	}
	switch u.Scheme {
	case "file":
		return u.Path, noop, nil
	case "https":
	default:
		return "", noop, fmt.Errorf("%s is not a scheme a pack may come from; use https, a file path, or copy it across", u.Scheme)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, from, nil)
	if err != nil {
		return "", noop, err
	}
	client := &http.Client{Timeout: 2 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return "", noop, fmt.Errorf("fetch %s: %w", from, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", noop, fmt.Errorf("fetch %s: %s", from, resp.Status)
	}

	tmp, err := os.CreateTemp("", "crp-pack-*.crpack")
	if err != nil {
		return "", noop, fmt.Errorf("stage the download: %w", err)
	}
	cleanup = func() { os.Remove(tmp.Name()) } //nolint:errcheck // best effort

	// Bounded: a response that never ends would otherwise fill the disk of
	// whatever ran the loader.
	if _, err := io.Copy(tmp, io.LimitReader(resp.Body, maxPackBytes)); err != nil {
		tmp.Close()
		cleanup()
		return "", noop, fmt.Errorf("download %s: %w", from, err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return "", noop, err
	}
	return tmp.Name(), cleanup, nil
}

// PackName is the conventional file name for a release, so a directory of them
// sorts and reads sensibly.
func PackName(pack *Pack) string {
	safe := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '-':
			return r
		case r >= 'A' && r <= 'Z':
			return r + 32
		case r == ' ' || r == '_':
			return '-'
		default:
			return -1
		}
	}, pack.Name)
	if safe == "" {
		safe = "pack"
	}
	return filepath.Clean(fmt.Sprintf("%s-%s.crpack", safe, pack.Version))
}
