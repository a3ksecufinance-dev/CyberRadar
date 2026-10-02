package content

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// ─── A pack as one file ──────────────────────────────────────────────────────
//
// A tar.gz holding:
//
//	manifest.json          the pack's identity and every file's digest
//	manifest.sig           a detached Ed25519 signature over manifest.json
//	detections/pack.yaml   the pack manifest, as authored
//	detections/CRP-*.yaml  one detection each
//
// Read entirely into memory and never extracted to disk: an archive that is
// never written out cannot be made to write outside where it was told to, which
// retires a whole family of mistakes rather than guarding against them.

const (
	manifestName  = "manifest.json"
	signatureName = "manifest.sig"
	contentPrefix = "detections/"

	// maxPackBytes bounds what a pack may expand to. A compressed archive can
	// be a great deal larger than it looks, and a loader that read until it ran
	// out of memory would be a denial of service with a polite file extension.
	maxPackBytes = 32 << 20
)

// Build writes a pack file from a content directory, signing it when given a
// key.
//
// Validation runs first, on purpose: a pack that cannot load is a pack nobody
// should be able to publish, and finding out at the deployment is finding out
// from a customer.
func Build(dir, out string, priv ed25519.PrivateKey) (*Manifest, error) {
	pack, _, err := Load(dir)
	if err != nil {
		return nil, err
	}

	files, err := collect(dir)
	if err != nil {
		return nil, err
	}

	manifest := &Manifest{Pack: *pack}
	for _, f := range files {
		manifest.Files = append(manifest.Files, FileDigest{Path: f.name, SHA256: hashOf(f.body)})
	}
	sort.Slice(manifest.Files, func(i, j int) bool { return manifest.Files[i].Path < manifest.Files[j].Path })

	var signature []byte
	if priv != nil {
		manifest.KeyID = KeyID(priv.Public().(ed25519.PublicKey))
	}
	raw, err := manifest.Bytes()
	if err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}
	if priv != nil {
		signature = Sign(priv, raw)
	}

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)

	add := func(name string, body []byte) error {
		if err := tw.WriteHeader(&tar.Header{
			Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg,
		}); err != nil {
			return err
		}
		_, err := tw.Write(body)
		return err
	}

	if err := add(manifestName, raw); err != nil {
		return nil, fmt.Errorf("write the manifest: %w", err)
	}
	if signature != nil {
		if err := add(signatureName, signature); err != nil {
			return nil, fmt.Errorf("write the signature: %w", err)
		}
	}
	for _, f := range files {
		if err := add(contentPrefix+f.name, f.body); err != nil {
			return nil, fmt.Errorf("write %s: %w", f.name, err)
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}

	if dirOf := filepath.Dir(out); dirOf != "." {
		if err := os.MkdirAll(dirOf, 0o750); err != nil {
			return nil, fmt.Errorf("create %s: %w", dirOf, err)
		}
	}
	if err := os.WriteFile(out, buf.Bytes(), 0o644); err != nil { //nolint:gosec // a published artefact is public
		return nil, fmt.Errorf("write %s: %w", out, err)
	}
	return manifest, nil
}

type packFile struct {
	name string
	body []byte
}

// collect reads the YAML files a pack carries, in a fixed order.
func collect(dir string) ([]packFile, error) {
	matches, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", dir, err)
	}
	sort.Strings(matches)

	var out []packFile
	for _, m := range matches {
		body, err := os.ReadFile(m) //nolint:gosec // a content directory the operator named
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", m, err)
		}
		out = append(out, packFile{name: filepath.Base(m), body: body})
	}
	return out, nil
}

// Opened is a pack file that has been read and, where a trust store was given,
// verified.
type Opened struct {
	Manifest *Manifest
	Pack     *Pack
	Entries  []*Entry

	// SignedBy is the key that vouched for it, empty when it was loaded
	// unsigned.
	SignedBy string
	// Digest is the manifest's fingerprint.
	Digest string
}

// Open reads a pack file, verifies it, and parses what it holds.
//
// The order matters and is the whole point: the signature is checked over the
// manifest bytes, then every file is checked against its digest, and only then
// is any of it parsed. Parsing first would mean running a YAML decoder over
// bytes nobody has vouched for, which is exactly the thing signing is for.
//
// A nil trust store means "accept unsigned", which the caller has to ask for
// explicitly. It is a legitimate thing to want while authoring and never a
// thing a deployment should reach by accident.
func Open(packPath string, trust TrustStore) (*Opened, error) {
	raw, err := os.ReadFile(packPath) //nolint:gosec // a pack path the operator named
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", packPath, err)
	}

	files, err := unpack(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", filepath.Base(packPath), err)
	}

	manifestRaw, ok := files[manifestName]
	if !ok {
		return nil, fmt.Errorf("%s carries no %s", filepath.Base(packPath), manifestName)
	}
	var manifest Manifest
	if err := json.Unmarshal(manifestRaw, &manifest); err != nil {
		return nil, fmt.Errorf("%s: parse the manifest: %w", filepath.Base(packPath), err)
	}

	opened := &Opened{Manifest: &manifest, Digest: hashOf(manifestRaw)}

	signature, signed := files[signatureName]
	switch {
	case trust != nil && !signed:
		return nil, fmt.Errorf("%s is not signed, and this deployment only loads signed packs",
			filepath.Base(packPath))
	case trust != nil:
		by, err := trust.Verify(manifestRaw, signature, manifest.KeyID)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", filepath.Base(packPath), err)
		}
		opened.SignedBy = by
	}

	// Every file the manifest names has to be present and unchanged, and every
	// file present has to be named. A file nobody vouched for riding along in
	// the archive is how an extra detection appears in a catalogue.
	named := map[string]bool{manifestName: true, signatureName: true}
	for _, want := range manifest.Files {
		name := contentPrefix + want.Path
		named[name] = true
		body, ok := files[name]
		if !ok {
			return nil, fmt.Errorf("%s: the manifest names %s and the pack does not carry it",
				filepath.Base(packPath), want.Path)
		}
		if got := hashOf(body); got != want.SHA256 {
			return nil, fmt.Errorf("%s: %s does not match its digest; it has been altered since the pack was signed",
				filepath.Base(packPath), want.Path)
		}
	}
	for name := range files {
		if !named[name] {
			return nil, fmt.Errorf("%s carries %s, which its manifest does not name",
				filepath.Base(packPath), name)
		}
	}

	// Verified. Now, and only now, parse.
	dir, err := os.MkdirTemp("", "crp-pack-")
	if err != nil {
		return nil, fmt.Errorf("stage the pack: %w", err)
	}
	defer os.RemoveAll(dir)

	for _, want := range manifest.Files {
		// The names came from the manifest the signature covers, and each is
		// checked to be a bare file name below, so nothing here can write
		// outside the directory just created.
		if err := os.WriteFile(filepath.Join(dir, want.Path), files[contentPrefix+want.Path], 0o600); err != nil {
			return nil, fmt.Errorf("stage %s: %w", want.Path, err)
		}
	}

	pack, entries, err := Load(dir)
	if err != nil {
		return nil, err
	}
	opened.Pack = pack
	opened.Entries = entries
	return opened, nil
}

// unpack reads the archive into memory, refusing anything that is not a plain
// file with a plain name.
//
// Nothing is written to disk here, so a path escaping the destination has no
// destination to escape — but the names are checked anyway, because the staging
// step later does write, and a check at the boundary is worth more than one
// beside the write.
func unpack(raw []byte) (map[string][]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("not a gzip archive: %w", err)
	}
	defer gz.Close()

	out := map[string][]byte{}
	tr := tar.NewReader(io.LimitReader(gz, maxPackBytes))
	total := 0

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read the archive: %w", err)
		}
		// A directory entry carries no content and nothing reads it: packs this
		// tool builds have none, and one built with tar does. Skipping them
		// keeps a legitimate pack loadable; everything else that is not a plain
		// file — a symlink above all — is refused, because that is the kind
		// that can make a reader fetch something it was not given.
		if header.Typeflag == tar.TypeDir {
			continue
		}
		if header.Typeflag != tar.TypeReg {
			return nil, fmt.Errorf("%s is a %c, not a plain file; a pack carries files and nothing else",
				header.Name, header.Typeflag)
		}
		if !safeName(header.Name) {
			return nil, fmt.Errorf("%q is not a name a pack may carry", header.Name)
		}
		body, err := io.ReadAll(io.LimitReader(tr, maxPackBytes))
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", header.Name, err)
		}
		total += len(body)
		if total > maxPackBytes {
			return nil, fmt.Errorf("the pack expands past %d bytes", maxPackBytes)
		}
		if _, exists := out[header.Name]; exists {
			return nil, fmt.Errorf("%s appears twice; which one is meant is not a question a loader should answer",
				header.Name)
		}
		out[header.Name] = body
	}
	return out, nil
}

// safeName accepts manifest.json, manifest.sig, and detections/<file>.yaml —
// and nothing with a directory traversal, an absolute path or a nested
// directory in it.
func safeName(name string) bool {
	if name == manifestName || name == signatureName {
		return true
	}
	if !strings.HasPrefix(name, contentPrefix) {
		return false
	}
	rest := strings.TrimPrefix(name, contentPrefix)
	if rest == "" || rest != path.Base(rest) || rest == "." || rest == ".." {
		return false
	}
	if strings.ContainsAny(rest, `/\`) || strings.HasPrefix(rest, ".") {
		return false
	}
	return strings.HasSuffix(rest, ".yaml")
}
