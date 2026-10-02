package content

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// authored builds a small but valid content directory.
func authored(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	write(t, dir, PackFile, "name: Test Pack\nversion: \"1.0.0\"\n")
	write(t, dir, "CRP-TST-0001.yaml", `
code: CRP-TST-0001
title: Essai
description: Une détection d'essai.
category: IAM
severity: HIGH
mitre: { tactic: TA0006, technique: T1110.004 }
conditions:
  field_matches:
    - { field: category, op: eq, value: IAM }
actions:
  - type: notify
dedup_window_s: 300
rationale: une raison assez longue pour passer la validation
frameworks: [DORA]
controls: [DORA-10.3]
requires: []
enabled_by_default: true
tags: [standard]
`)
	return dir
}

func signingKey(t *testing.T) (ed25519.PrivateKey, string) {
	t.Helper()
	prefix := filepath.Join(t.TempDir(), "signing")
	if _, err := GenerateKey(prefix); err != nil {
		t.Fatalf("keygen: %v", err)
	}
	priv, err := LoadPrivateKey(prefix + ".key")
	if err != nil {
		t.Fatalf("load key: %v", err)
	}
	return priv, prefix
}

func trustOf(t *testing.T, prefix string) *TrustStore {
	t.Helper()
	store, err := LoadTrust(prefix + ".pub")
	if err != nil {
		t.Fatalf("load trust: %v", err)
	}
	return store
}

// A pack built and signed has to open again, verified, with what went in.
func TestASignedPackRoundTrips(t *testing.T) {
	dir := authored(t)
	priv, prefix := signingKey(t)
	out := filepath.Join(t.TempDir(), "p.crpack")

	manifest, err := Build(dir, out, priv)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if manifest.KeyID == "" {
		t.Error("a signed build recorded no key identifier")
	}

	opened, err := Open(out, trustOf(t, prefix))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if opened.SignedBy != manifest.KeyID {
		t.Errorf("opened as signed by %q, built by %q", opened.SignedBy, manifest.KeyID)
	}
	if len(opened.Entries) != 1 || opened.Entries[0].Code != "CRP-TST-0001" {
		t.Errorf("the pack came back with %d entries", len(opened.Entries))
	}
	if opened.Digest == "" {
		t.Error("no manifest digest, so two deployments cannot compare what they are running")
	}
}

// Two builds of the same content must produce the same manifest digest, or two
// deployments claiming one version can never be shown to be running it.
func TestTheManifestDigestIsStable(t *testing.T) {
	dir := authored(t)
	priv, _ := signingKey(t)

	first, err := Build(dir, filepath.Join(t.TempDir(), "a.crpack"), priv)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	second, err := Build(dir, filepath.Join(t.TempDir(), "b.crpack"), priv)
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	a, _ := first.Digest()
	b, _ := second.Digest()
	if a != b {
		t.Errorf("two builds of one pack digest differently: %s and %s", a, b)
	}
}

// Changing a detection inside a signed pack has to be caught, and the message
// has to name the file — a failure an operator cannot localise is one they
// learn to ignore.
func TestAnAlteredDetectionIsRefused(t *testing.T) {
	priv, prefix := signingKey(t)
	out := filepath.Join(t.TempDir(), "p.crpack")
	if _, err := Build(authored(t), out, priv); err != nil {
		t.Fatalf("build: %v", err)
	}

	tampered := repack(t, out, func(files map[string][]byte) {
		files["detections/CRP-TST-0001.yaml"] = bytes.ReplaceAll(
			files["detections/CRP-TST-0001.yaml"], []byte("dedup_window_s: 300"), []byte("dedup_window_s: 1"))
	})

	_, err := Open(tampered, trustOf(t, prefix))
	if err == nil {
		t.Fatal("an altered detection opened")
	}
	if !strings.Contains(err.Error(), "CRP-TST-0001.yaml") || !strings.Contains(err.Error(), "digest") {
		t.Errorf("the error does not name the file and the reason: %v", err)
	}
}

// Somebody who alters a detection and recomputes the manifest to match still
// cannot sign it, which is the whole point of signing the manifest.
func TestAnAlteredManifestIsRefused(t *testing.T) {
	priv, prefix := signingKey(t)
	out := filepath.Join(t.TempDir(), "p.crpack")
	if _, err := Build(authored(t), out, priv); err != nil {
		t.Fatalf("build: %v", err)
	}

	tampered := repack(t, out, func(files map[string][]byte) {
		body := bytes.ReplaceAll(files["detections/CRP-TST-0001.yaml"],
			[]byte("severity: HIGH"), []byte("severity: LOW"))
		files["detections/CRP-TST-0001.yaml"] = body

		var m Manifest
		if err := json.Unmarshal(files[manifestName], &m); err != nil {
			t.Fatalf("manifest: %v", err)
		}
		for i := range m.Files {
			if m.Files[i].Path == "CRP-TST-0001.yaml" {
				m.Files[i].SHA256 = hashOf(body)
			}
		}
		raw, _ := m.Bytes()
		files[manifestName] = raw
	})

	_, err := Open(tampered, trustOf(t, prefix))
	if err == nil {
		t.Fatal("a pack whose manifest was recomputed opened")
	}
	if !strings.Contains(err.Error(), "signature") {
		t.Errorf("the error does not say the signature failed: %v", err)
	}
}

// A file nobody vouched for riding along in the archive is how an extra
// detection appears in a catalogue.
func TestAFileTheManifestDoesNotNameIsRefused(t *testing.T) {
	priv, prefix := signingKey(t)
	out := filepath.Join(t.TempDir(), "p.crpack")
	if _, err := Build(authored(t), out, priv); err != nil {
		t.Fatalf("build: %v", err)
	}

	tampered := repack(t, out, func(files map[string][]byte) {
		files["detections/CRP-ZZZ-9999.yaml"] = files["detections/CRP-TST-0001.yaml"]
	})

	if _, err := Open(tampered, trustOf(t, prefix)); err == nil {
		t.Fatal("a pack carrying an unnamed file opened")
	}
}

// And one the manifest names and the pack does not carry.
func TestAMissingFileIsRefused(t *testing.T) {
	priv, prefix := signingKey(t)
	out := filepath.Join(t.TempDir(), "p.crpack")
	if _, err := Build(authored(t), out, priv); err != nil {
		t.Fatalf("build: %v", err)
	}

	tampered := repack(t, out, func(files map[string][]byte) {
		delete(files, "detections/CRP-TST-0001.yaml")
	})

	if _, err := Open(tampered, trustOf(t, prefix)); err == nil {
		t.Fatal("a pack missing a file its manifest names opened")
	}
}

// A pack signed by a key this deployment does not trust is refused, and the
// message names both so an operator can tell a rotation from an attack.
func TestAPackSignedByAnUntrustedKeyIsRefused(t *testing.T) {
	priv, _ := signingKey(t)
	_, otherPrefix := signingKey(t)
	out := filepath.Join(t.TempDir(), "p.crpack")
	if _, err := Build(authored(t), out, priv); err != nil {
		t.Fatalf("build: %v", err)
	}

	_, err := Open(out, trustOf(t, otherPrefix))
	if err == nil {
		t.Fatal("a pack signed by an untrusted key opened")
	}
	if !strings.Contains(err.Error(), "does not trust") {
		t.Errorf("the error does not say the key is untrusted: %v", err)
	}
}

// A key has to be replaceable without a window in which nothing verifies:
// trust both, publish under the new one, then drop the old.
func TestTwoTrustedKeysBothVerify(t *testing.T) {
	oldKey, oldPrefix := signingKey(t)
	newKey, newPrefix := signingKey(t)

	both := filepath.Join(t.TempDir(), "trust")
	if err := os.MkdirAll(both, 0o750); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{oldPrefix, newPrefix} {
		raw, err := os.ReadFile(p + ".pub")
		if err != nil {
			t.Fatal(err)
		}
		write(t, both, filepath.Base(p)+"-"+hashOf(raw)[:8]+".pub", string(raw))
	}
	store, err := LoadTrust(both)
	if err != nil {
		t.Fatalf("load trust: %v", err)
	}
	if len(store.IDs()) != 2 {
		t.Fatalf("%d keys trusted, want 2", len(store.IDs()))
	}

	for name, key := range map[string]ed25519.PrivateKey{"old": oldKey, "new": newKey} {
		out := filepath.Join(t.TempDir(), name+".crpack")
		if _, err := Build(authored(t), out, key); err != nil {
			t.Fatalf("build %s: %v", name, err)
		}
		if _, err := Open(out, store); err != nil {
			t.Errorf("a pack signed by the %s key did not verify: %v", name, err)
		}
	}
}

// An unsigned pack is a legitimate thing to build while authoring, and a thing
// a deployment that asked for signatures must not accept.
func TestAnUnsignedPackIsRefusedWhereSignaturesAreRequired(t *testing.T) {
	out := filepath.Join(t.TempDir(), "p.crpack")
	if _, err := Build(authored(t), out, nil); err != nil {
		t.Fatalf("build: %v", err)
	}
	_, prefix := signingKey(t)

	if _, err := Open(out, trustOf(t, prefix)); err == nil {
		t.Fatal("an unsigned pack opened where a trust store was configured")
	}
	// And opens where the caller asked for no verification at all.
	if _, err := Open(out, nil); err != nil {
		t.Errorf("an unsigned pack did not open when verification was waived: %v", err)
	}
}

// A trust store of nothing would verify nothing and look exactly like one that
// had verified something.
func TestAnEmptyTrustStoreIsRefused(t *testing.T) {
	if _, err := LoadTrust(t.TempDir()); err == nil {
		t.Fatal("an empty trust directory loaded")
	}
}

// Regenerating over an existing key would orphan every pack signed with it.
func TestKeygenRefusesToOverwrite(t *testing.T) {
	prefix := filepath.Join(t.TempDir(), "signing")
	if _, err := GenerateKey(prefix); err != nil {
		t.Fatalf("keygen: %v", err)
	}
	if _, err := GenerateKey(prefix); err == nil {
		t.Fatal("a second keygen overwrote the first")
	}
}

// A symlink is the entry type that can make a reader fetch something it was
// never given.
func TestASymlinkInAPackIsRefused(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{
		Name: "detections/evil.yaml", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd", Mode: 0o777,
	}); err != nil {
		t.Fatal(err)
	}
	tw.Close()
	gz.Close()

	path := filepath.Join(t.TempDir(), "evil.crpack")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, nil); err == nil {
		t.Fatal("a pack carrying a symlink opened")
	}
}

// Verification has to happen before parsing. A pack whose signature is wrong
// AND whose content is unparseable must fail on the signature: reaching the
// parser at all would mean running a decoder over bytes nobody vouched for.
func TestNothingIsParsedBeforeItIsVerified(t *testing.T) {
	priv, prefix := signingKey(t)
	out := filepath.Join(t.TempDir(), "p.crpack")
	if _, err := Build(authored(t), out, priv); err != nil {
		t.Fatalf("build: %v", err)
	}

	tampered := repack(t, out, func(files map[string][]byte) {
		files["detections/CRP-TST-0001.yaml"] = []byte("{{{ this is not yaml at all")
	})

	_, err := Open(tampered, trustOf(t, prefix))
	if err == nil {
		t.Fatal("a tampered pack opened")
	}
	// It has to be the digest that refused it. Any parser complaint here would
	// mean a YAML decoder had already run over bytes nobody vouched for — and
	// matching on "yaml" alone would not say so, because the file is named
	// CRP-TST-0001.yaml.
	if !strings.Contains(err.Error(), "does not match its digest") {
		t.Errorf("the pack was not stopped by its digest, so something ran before verification: %v", err)
	}
	for _, parserish := range []string{"unmarshal", "cannot unmarshal", "did not find expected", "line 1"} {
		if strings.Contains(err.Error(), parserish) {
			t.Errorf("the pack was parsed before it was verified: %v", err)
		}
	}
}

// repack rewrites an archive's files, leaving the signature alone.
func repack(t *testing.T, path string, edit func(map[string][]byte)) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	files, err := unpack(raw)
	if err != nil {
		t.Fatalf("unpack: %v", err)
	}
	edit(files)

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{
			Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	tw.Close()
	gz.Close()

	out := filepath.Join(t.TempDir(), "tampered.crpack")
	if err := os.WriteFile(out, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return out
}
