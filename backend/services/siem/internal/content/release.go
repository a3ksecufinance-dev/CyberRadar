package content

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ─── A channel: what has been published, and which version is current ───────
//
// A signed pack proves nobody altered it. It does not prove it is the pack a
// deployment should be running — an attacker who cannot forge a signature can
// still hand over a genuine, older release, one published before a detection
// they care about existed. Nothing in a pack can rule that out, because the
// pack is exactly as true as it was the day it was signed.
//
// So the channel is signed too. index.json names every published version, each
// with the digest of its manifest, and says which is current; index.sig covers
// it. That turns three separate questions into things a deployment can check
// rather than assume:
//
//	what exists        — the index lists it
//	what is current    — the index says so, under a signature
//	is this that pack  — the digest in the index has to match the pack opened
//
// The channel itself is a directory of files. Whether it is served by S3, by
// nginx, or carried into an air-gapped site on a disk is an infrastructure
// decision and deliberately not one this code makes: everything below works
// the same against a local path and an https base, because the second of those
// is how a bank actually moves content into a regulated network.

const (
	// IndexName and IndexSigName are the two files that make a directory a
	// channel.
	IndexName    = "index.json"
	IndexSigName = "index.sig"

	// maxIndexBytes bounds the index. It is a list of versions; anything
	// approaching this is not one.
	maxIndexBytes = 1 << 20
)

// Release is one published version.
type Release struct {
	Version string `json:"version"`
	// File is the pack's name within the channel, relative by construction so
	// a channel can be copied or re-hosted without rewriting it.
	File string `json:"file"`
	// ManifestDigest is what the pack has to hash to. This is the binding that
	// makes the index worth signing.
	ManifestDigest string `json:"manifest_digest"`
	// SignedBy is the key that signed the pack, which need not be the key that
	// signed the index.
	SignedBy    string `json:"signed_by,omitempty"`
	Size        int64  `json:"size"`
	PublishedAt string `json:"published_at"`
}

// Index is the channel's contents.
type Index struct {
	Pack string `json:"pack"`
	// Current is the version a deployment gets when it asks for no version in
	// particular. Separate from "the highest version published" so a release
	// can be withdrawn by pointing current back without deleting anything.
	Current  string    `json:"current"`
	Releases []Release `json:"releases"`
	// KeyID names the key expected to have signed the index.
	KeyID string `json:"key_id,omitempty"`
}

// Bytes is the exact serialisation the index signature is taken over.
//
// Newest first, so the file reads the way an operator wants it to and, more to
// the point, so two publishers of the same set produce identical bytes.
func (i *Index) Bytes() ([]byte, error) {
	sorted := *i
	sorted.Releases = append([]Release(nil), i.Releases...)
	sort.Slice(sorted.Releases, func(a, b int) bool {
		return CompareVersions(sorted.Releases[a].Version, sorted.Releases[b].Version) > 0
	})
	return json.Marshal(sorted)
}

// Find resolves a version request against the index.
//
// An empty version, "current" or "latest" all mean what the index says is
// current — not the highest number present, which would make withdrawing a bad
// release impossible without deleting it.
func (i *Index) Find(version string) (*Release, error) {
	want := strings.TrimSpace(version)
	if want == "" || want == "current" || want == "latest" {
		if i.Current == "" {
			return nil, fmt.Errorf("the channel names no current version; ask for one by number")
		}
		want = i.Current
	}
	for n := range i.Releases {
		if i.Releases[n].Version == want {
			return &i.Releases[n], nil
		}
	}
	return nil, fmt.Errorf("the channel has no version %s (published: %s)", want, strings.Join(i.Versions(), ", "))
}

// Versions are the published version numbers, newest first.
func (i *Index) Versions() []string {
	out := make([]string, 0, len(i.Releases))
	for _, r := range i.Releases {
		out = append(out, r.Version)
	}
	sort.Slice(out, func(a, b int) bool { return CompareVersions(out[a], out[b]) > 0 })
	return out
}

// Publish copies a built pack into a channel directory and rewrites the signed
// index.
//
// Publishing is the only place a version number becomes a promise, so this is
// where the promise is enforced: a version already published under a different
// digest is refused. Letting 2026.10.1 mean two things would make every pin
// anybody wrote worthless, and the failure would show up as a detection that
// behaves differently on two deployments running "the same" version.
func Publish(channelDir, packPath string, priv ed25519.PrivateKey) (*Index, *Release, error) {
	// Opened without a trust store: the publisher is the one vouching, and
	// requiring it to trust its own key before it could publish would mean a
	// trust store on the build machine for no benefit. The manifest is still
	// read from the pack, so what is indexed is what the pack says it is.
	opened, err := Open(packPath, nil)
	if err != nil {
		return nil, nil, err
	}
	info, err := os.Stat(packPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read %s: %w", packPath, err)
	}

	if err := os.MkdirAll(channelDir, 0o750); err != nil {
		return nil, nil, fmt.Errorf("create %s: %w", channelDir, err)
	}

	index, err := readLocalIndex(channelDir)
	if err != nil {
		return nil, nil, err
	}
	if index.Pack != "" && index.Pack != opened.Pack.Name {
		return nil, nil, fmt.Errorf("%s publishes %q; this pack is %q. One channel carries one pack: "+
			"a deployment pinned to a version has no way to say which pack it meant",
			channelDir, index.Pack, opened.Pack.Name)
	}
	index.Pack = opened.Pack.Name

	release := Release{
		Version:        opened.Pack.Version,
		File:           PackName(opened.Pack),
		ManifestDigest: opened.Digest,
		SignedBy:       opened.SignedBy,
		Size:           info.Size(),
		PublishedAt:    time.Now().UTC().Format(time.RFC3339),
	}
	// SignedBy comes from the manifest here rather than from a verified
	// signature, because nothing verified it: say so by reading the key the
	// pack claims, which is what a deployment will check against its own trust.
	release.SignedBy = opened.Manifest.KeyID

	for n, existing := range index.Releases {
		if existing.Version != release.Version {
			continue
		}
		if existing.ManifestDigest != release.ManifestDigest {
			return nil, nil, fmt.Errorf(
				"%s is already published with digest %s and this pack is %s; "+
					"a version that changes is a version nobody can pin — publish it under a new number",
				release.Version, ShortDigest(existing.ManifestDigest), ShortDigest(release.ManifestDigest))
		}
		// Identical: keep the original publication time. Re-running a release
		// job should be a no-op, not a new timestamp on an old artefact.
		release.PublishedAt = existing.PublishedAt
		index.Releases[n] = release
		goto write
	}
	index.Releases = append(index.Releases, release)

write:
	// Current advances only forwards. Publishing an old version into a channel
	// is a legitimate thing to do — backfilling a gap, re-signing an archive —
	// and it must not quietly roll every deployment back.
	if index.Current == "" || CompareVersions(release.Version, index.Current) > 0 {
		index.Current = release.Version
	}

	body, err := os.ReadFile(packPath) //nolint:gosec // a pack path the operator named
	if err != nil {
		return nil, nil, fmt.Errorf("read %s: %w", packPath, err)
	}
	if err := os.WriteFile(filepath.Join(channelDir, release.File), body, 0o644); err != nil { //nolint:gosec // a published artefact is public
		return nil, nil, fmt.Errorf("write %s: %w", release.File, err)
	}

	if priv != nil {
		index.KeyID = KeyID(priv.Public().(ed25519.PublicKey))
	} else {
		index.KeyID = ""
	}
	raw, err := index.Bytes()
	if err != nil {
		return nil, nil, fmt.Errorf("index: %w", err)
	}
	if err := os.WriteFile(filepath.Join(channelDir, IndexName), raw, 0o644); err != nil { //nolint:gosec // a published index is public
		return nil, nil, fmt.Errorf("write %s: %w", IndexName, err)
	}

	sigPath := filepath.Join(channelDir, IndexSigName)
	if priv == nil {
		// An unsigned index must not sit next to a stale signature: it would
		// verify against the old contents and refuse the new ones, which reads
		// to an operator as tampering rather than as a step they skipped.
		if err := os.Remove(sigPath); err != nil && !os.IsNotExist(err) {
			return nil, nil, fmt.Errorf("remove the stale %s: %w", IndexSigName, err)
		}
	} else if err := os.WriteFile(sigPath, Sign(priv, raw), 0o644); err != nil { //nolint:gosec // a signature is public
		return nil, nil, fmt.Errorf("write %s: %w", IndexSigName, err)
	}

	return index, &release, nil
}

// readLocalIndex reads a channel's index from disk, returning an empty one when
// the channel is new. It does not verify: Publish is the writer, and a build
// machine checking its own previous signature proves nothing.
func readLocalIndex(channelDir string) (*Index, error) {
	raw, err := os.ReadFile(filepath.Join(channelDir, IndexName)) //nolint:gosec // a channel the operator named
	if os.IsNotExist(err) {
		return &Index{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", IndexName, err)
	}
	var index Index
	if err := json.Unmarshal(raw, &index); err != nil {
		return nil, fmt.Errorf("parse %s: %w", IndexName, err)
	}
	return &index, nil
}

// ReadIndex fetches a channel's index and verifies it against the trust store.
//
// A nil trust store accepts an unsigned index, which the caller has to ask for
// deliberately — same rule as a pack, for the same reason.
func ReadIndex(ctx context.Context, channel string, trust *TrustStore) (*Index, error) {
	raw, err := fetchBytes(ctx, join(channel, IndexName))
	if err != nil {
		return nil, err
	}
	var index Index
	if err := json.Unmarshal(raw, &index); err != nil {
		return nil, fmt.Errorf("parse the channel index: %w", err)
	}

	if trust == nil {
		return &index, nil
	}

	sig, err := fetchBytes(ctx, join(channel, IndexSigName))
	if err != nil {
		return nil, fmt.Errorf("the channel index is not signed, and this deployment only reads signed channels: %w", err)
	}
	// Verified over the bytes as fetched, not over a re-serialisation: a
	// round-trip through the struct would drop any field this version does not
	// know about and verify something the publisher never signed.
	if _, err := trust.Verify(raw, sig, index.KeyID); err != nil {
		return nil, fmt.Errorf("the channel index: %w", err)
	}
	return &index, nil
}

// FetchRelease resolves a version in a channel, fetches that pack, verifies it,
// and checks it against the digest the index promised.
//
// The last step is what the index buys. Without it a signed index would say
// which version is current and an attacker could still serve a different,
// genuinely-signed pack at that file name.
func FetchRelease(ctx context.Context, channel, version string, trust *TrustStore) (*Opened, string, error) {
	index, err := ReadIndex(ctx, channel, trust)
	if err != nil {
		return nil, "", err
	}
	release, err := index.Find(version)
	if err != nil {
		return nil, "", err
	}

	from := join(channel, release.File)
	local, cleanup, err := Fetch(ctx, from)
	if err != nil {
		return nil, "", err
	}
	defer cleanup()

	opened, err := Open(local, trust)
	if err != nil {
		return nil, "", err
	}
	if opened.Digest != release.ManifestDigest {
		return nil, "", fmt.Errorf(
			"%s says %s has digest %s; the pack served is %s. "+
				"Both are properly signed, so this is not a forgery — it is the wrong pack at that address",
			IndexName, release.Version, ShortDigest(release.ManifestDigest), ShortDigest(opened.Digest))
	}
	if opened.Pack.Version != release.Version {
		return nil, "", fmt.Errorf("%s says %s and the pack calls itself %s",
			IndexName, release.Version, opened.Pack.Version)
	}
	return opened, from, nil
}

// join addresses a file within a channel, whether the channel is a directory or
// an https base.
func join(channel, name string) string {
	if !strings.Contains(channel, "://") {
		return filepath.Join(channel, name)
	}
	return strings.TrimRight(channel, "/") + "/" + name
}

// fetchBytes reads a small file from a path or a URL.
func fetchBytes(ctx context.Context, from string) ([]byte, error) {
	if !strings.Contains(from, "://") {
		raw, err := os.ReadFile(from) //nolint:gosec // a channel path the operator named
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", from, err)
		}
		return raw, nil
	}

	u, err := url.Parse(from)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", from, err)
	}
	switch u.Scheme {
	case "file":
		raw, err := os.ReadFile(u.Path) //nolint:gosec // a channel path the operator named
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", u.Path, err)
		}
		return raw, nil
	case "https":
	default:
		return nil, fmt.Errorf("%s is not a scheme a channel may be served over; use https or a path", u.Scheme)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, from, nil)
	if err != nil {
		return nil, err
	}
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", from, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch %s: %s", from, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxIndexBytes))
}

// CompareVersions orders two version strings: negative when a precedes b, zero
// when they are equal, positive when a follows b.
//
// Dot-separated, numeric segments compared as numbers so 2026.10.1 follows
// 2026.9.4 — which a string comparison gets backwards, and which is exactly the
// comparison a downgrade check depends on. A non-numeric segment falls back to
// a string comparison of that segment, which is not a full semver precedence
// and is not pretending to be: the pack versions are calendar numbers.
func CompareVersions(a, b string) int {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for n := 0; n < len(as) || n < len(bs); n++ {
		var x, y string
		if n < len(as) {
			x = as[n]
		}
		if n < len(bs) {
			y = bs[n]
		}
		if x == y {
			continue
		}
		// A missing segment is lower: 2026.10 precedes 2026.10.1.
		if x == "" {
			return -1
		}
		if y == "" {
			return 1
		}
		xi, xerr := strconv.Atoi(x)
		yi, yerr := strconv.Atoi(y)
		if xerr == nil && yerr == nil {
			if xi != yi {
				if xi < yi {
					return -1
				}
				return 1
			}
			continue
		}
		return strings.Compare(x, y)
	}
	return 0
}

// ShortDigest is a digest cut to the length a person can compare by eye in a
// log line, which is the only place anybody ever compares one.
func ShortDigest(digest string) string {
	if len(digest) <= 16 {
		return digest
	}
	return digest[:16]
}
