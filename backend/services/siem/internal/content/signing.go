package content

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ─── Signing a content pack ──────────────────────────────────────────────────
//
// A pack that ships separately from the code is a pack a deployment did not
// build. Everything below exists so it can still tell where one came from.
//
// Three decisions are worth stating, because each has a tempting wrong answer:
//
//   · The signing key is not the token-signing key. The platform already has an
//     RSA pair for JWTs, and reusing it would make a content-key compromise a
//     token forgery — the blast radius of a detection author's laptop would be
//     every session on the platform.
//
//   · Trust is configured by the deployment and never carried by the pack. A
//     pack that shipped its own public key would prove only that whoever built
//     it had a key, which is not a fact anybody needs.
//
//   · The signature covers a manifest, and the manifest carries each file's
//     digest. Signing the archive bytes directly would work too, but it would
//     say nothing about which file changed when verification failed — and a
//     failure an operator cannot localise is a failure they ignore.
//
//   · Revocation is additive, not a deletion. Withdrawing a key by deleting its
//     file means the one host that missed the change keeps trusting it and says
//     nothing; a .revoked file that has to be distributed anyway fails the other
//     way — the host that got it refuses, loudly, and the host that did not is
//     at least no worse off than before.

// KeyPEMType is the PEM block the keys are written under.
const (
	privateKeyPEMType = "CRP CONTENT PRIVATE KEY"
	publicKeyPEMType  = "CRP CONTENT PUBLIC KEY"
)

// FileDigest is one file in a pack and the fingerprint of its bytes.
type FileDigest struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// Manifest is what the signature covers.
//
// Ordered by path and marshalled with Go's encoder, so the same pack produces
// the same bytes and therefore the same signature on any machine. A manifest
// whose serialisation varied would make two builds of one pack unverifiable
// against each other.
type Manifest struct {
	Pack  Pack         `json:"pack"`
	Files []FileDigest `json:"files"`
	// KeyID identifies the key expected to have signed this, so a deployment
	// trusting several keys knows which one to check without trying each.
	KeyID string `json:"key_id,omitempty"`
}

// Digest is the manifest's own fingerprint: what two deployments compare when
// both claim to run the same version.
func (m *Manifest) Digest() (string, error) {
	raw, err := m.Bytes()
	if err != nil {
		return "", err
	}
	return hashOf(raw), nil
}

// Bytes is the exact serialisation the signature is taken over.
func (m *Manifest) Bytes() ([]byte, error) {
	sorted := *m
	sorted.Files = append([]FileDigest(nil), m.Files...)
	sort.Slice(sorted.Files, func(i, j int) bool { return sorted.Files[i].Path < sorted.Files[j].Path })
	return json.Marshal(sorted)
}

// GenerateKey makes a signing key pair and writes it as two PEM files.
//
// Ed25519 rather than RSA: there are no parameter choices to get wrong, the
// signatures are small enough to carry anywhere, and the private key cannot be
// generated at an inadequate size by somebody in a hurry.
func GenerateKey(prefix string) (keyID string, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", fmt.Errorf("generate: %w", err)
	}

	privPath := prefix + ".key"
	pubPath := prefix + ".pub"
	for _, p := range []string{privPath, pubPath} {
		if _, err := os.Stat(p); err == nil {
			return "", fmt.Errorf("%s already exists; regenerating would orphan every pack signed with the old key", p)
		}
	}
	if err := os.MkdirAll(filepath.Dir(privPath), 0o700); err != nil {
		return "", fmt.Errorf("create %s: %w", filepath.Dir(privPath), err)
	}

	// 0600 on the private key: a signing key readable by the group is a signing
	// key anybody on the build machine can use.
	privPEM := pem.EncodeToMemory(&pem.Block{Type: privateKeyPEMType, Bytes: priv})
	if err := os.WriteFile(privPath, privPEM, 0o600); err != nil {
		return "", fmt.Errorf("write %s: %w", privPath, err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: publicKeyPEMType, Bytes: pub})
	if err := os.WriteFile(pubPath, pubPEM, 0o644); err != nil { //nolint:gosec // a public key is public
		return "", fmt.Errorf("write %s: %w", pubPath, err)
	}
	return KeyID(pub), nil
}

// KeyID names a public key, so a deployment trusting several can say which one
// signed what. The first sixteen bytes of its digest: long enough that two keys
// will not collide, short enough to appear in a log line.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:16])
}

// LoadPrivateKey reads a signing key.
func LoadPrivateKey(path string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // a key path the operator named
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != privateKeyPEMType {
		return nil, fmt.Errorf("%s is not a %s", path, privateKeyPEMType)
	}
	if len(block.Bytes) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%s is %d bytes, not an Ed25519 private key", path, len(block.Bytes))
	}
	return ed25519.PrivateKey(block.Bytes), nil
}

// TrustStore is what a deployment accepts, and what it has withdrawn.
//
// Two sets rather than one, because they answer different questions. Removing
// a key says "we no longer publish under this"; revoking one says "anything
// this signed is suspect", and the second has to survive the key file still
// being on disk somewhere.
type TrustStore struct {
	keys    map[string]ed25519.PublicKey
	revoked map[string]string // key id -> why
}

// RevokedFileSuffix is the extension of a revocation list in a trust directory.
const RevokedFileSuffix = ".revoked"

// LoadTrust reads trusted public keys, and any revocations, from a file or a
// directory of them.
//
// Given by the deployment, never by the pack. Several keys are allowed so one
// can be rotated without a window in which nothing verifies: publish under the
// new key while the old one is still trusted, then drop the old one.
func LoadTrust(path string) (*TrustStore, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("read the trust store %s: %w", path, err)
	}

	var keyFiles, revokedFiles []string
	if info.IsDir() {
		if keyFiles, err = filepath.Glob(filepath.Join(path, "*.pub")); err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
		if revokedFiles, err = filepath.Glob(filepath.Join(path, "*"+RevokedFileSuffix)); err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
	} else {
		keyFiles = []string{path}
	}

	store := &TrustStore{keys: map[string]ed25519.PublicKey{}, revoked: map[string]string{}}
	for _, f := range keyFiles {
		raw, err := os.ReadFile(f) //nolint:gosec // a trust path the operator named
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", f, err)
		}
		// A file may hold several keys, one PEM block each.
		for rest := raw; len(rest) > 0; {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			if block.Type != publicKeyPEMType {
				return nil, fmt.Errorf("%s holds a %q block; a trust store takes %s only",
					f, block.Type, publicKeyPEMType)
			}
			if len(block.Bytes) != ed25519.PublicKeySize {
				return nil, fmt.Errorf("%s holds a key of %d bytes, not an Ed25519 public key",
					f, len(block.Bytes))
			}
			pub := ed25519.PublicKey(block.Bytes)
			store.keys[KeyID(pub)] = pub
		}
	}

	for _, f := range revokedFiles {
		if err := store.readRevocations(f); err != nil {
			return nil, err
		}
	}

	if len(store.keys) == 0 {
		return nil, fmt.Errorf("%s holds no trusted key; a trust store of nothing would verify nothing and look like it had", path)
	}
	return store, nil
}

// readRevocations parses one revocation list: a key id per line, optionally
// followed by the reason, with # comments.
//
// A malformed identifier is an error rather than a line skipped. A revocation
// nobody noticed had failed is the one case where silence is worst: the
// operator believes the key is withdrawn and it is not.
func (t *TrustStore) readRevocations(path string) error {
	raw, err := os.ReadFile(path) //nolint:gosec // a trust path the operator named
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	for n, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		id, reason, _ := strings.Cut(line, " ")
		id = strings.ToLower(strings.TrimSpace(id))
		if !isKeyID(id) {
			return fmt.Errorf("%s line %d: %q is not a key identifier (32 hex characters); "+
				"a mistyped revocation withdraws nothing and looks like it did", path, n+1, id)
		}
		t.revoked[id] = strings.TrimSpace(reason)
	}
	return nil
}

func isKeyID(s string) bool {
	if len(s) != 32 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// Verify checks a signature over a manifest against the trusted keys, and
// reports which key vouched for it.
//
// The key id is a hint, not an authority: it says which key to try, and a
// signature naming a key the deployment does not trust is refused for that
// reason rather than silently tried against the others.
//
// The messages name no subject — "signed by key X, which…" — because the same
// check covers a pack's manifest and a channel's index, and a caller that has
// already said which it is reads better than one correcting the other.
func (t *TrustStore) Verify(manifest []byte, signature []byte, keyID string) (string, error) {
	if keyID != "" {
		if why, gone := t.revoked[keyID]; gone {
			return "", fmt.Errorf("signed by key %s, which this deployment has revoked%s",
				keyID, becauseOf(why))
		}
		pub, ok := t.keys[keyID]
		if !ok {
			return "", fmt.Errorf("signed by key %s, which this deployment does not trust (trusted: %s)",
				keyID, strings.Join(t.IDs(), ", "))
		}
		if !ed25519.Verify(pub, manifest, signature) {
			return "", fmt.Errorf("the signature by key %s does not match; it has been altered since it was signed", keyID)
		}
		return keyID, nil
	}

	// No key named. Try them all rather than refuse: an older pack format or a
	// hand-built one may carry a signature and no identifier.
	for id, pub := range t.keys {
		if _, gone := t.revoked[id]; gone {
			continue
		}
		if ed25519.Verify(pub, manifest, signature) {
			return id, nil
		}
	}
	// A revoked key that would have verified is reported as revoked rather than
	// as unknown: the two send an operator looking in different places.
	for id, pub := range t.keys {
		if why, gone := t.revoked[id]; gone && ed25519.Verify(pub, manifest, signature) {
			return "", fmt.Errorf("signed by key %s, which this deployment has revoked%s", id, becauseOf(why))
		}
	}
	return "", fmt.Errorf("no trusted key verifies this signature")
}

func becauseOf(why string) string {
	if why == "" {
		return ""
	}
	return " (" + why + ")"
}

// IDs are the trusted key identifiers that have not been revoked, for an error
// message that names them.
func (t *TrustStore) IDs() []string {
	out := make([]string, 0, len(t.keys))
	for id := range t.keys {
		if _, gone := t.revoked[id]; !gone {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

// RevokedIDs are the withdrawn key identifiers, whether or not the deployment
// still holds the key itself.
func (t *TrustStore) RevokedIDs() []string {
	out := make([]string, 0, len(t.revoked))
	for id := range t.revoked {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// RevocationReason is why a key was withdrawn, empty when none was recorded.
func (t *TrustStore) RevocationReason(id string) string { return t.revoked[id] }

// Holds reports whether the deployment has the key itself, revoked or not.
func (t *TrustStore) Holds(id string) bool { _, ok := t.keys[id]; return ok }

// Sign produces a detached signature over the manifest bytes.
func Sign(priv ed25519.PrivateKey, manifest []byte) []byte {
	return ed25519.Sign(priv, manifest)
}
