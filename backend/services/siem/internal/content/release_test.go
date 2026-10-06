package content

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// authoredAt is a valid content directory carrying a chosen version, so a test
// can publish more than one.
func authoredAt(t *testing.T, version, dedup string) string {
	t.Helper()
	dir := authored(t)
	write(t, dir, PackFile, "name: Test Pack\nversion: \""+version+"\"\n")
	if dedup != "" {
		raw, err := os.ReadFile(filepath.Join(dir, "CRP-TST-0001.yaml"))
		if err != nil {
			t.Fatalf("read the detection: %v", err)
		}
		write(t, dir, "CRP-TST-0001.yaml",
			strings.Replace(string(raw), "dedup_window_s: 300", "dedup_window_s: "+dedup, 1))
	}
	return dir
}

// A release published into a channel comes back out of it, verified, with the
// index vouching for which version is current.
func TestAChannelRoundTrips(t *testing.T) {
	priv, prefix := signingKey(t)
	channel := filepath.Join(t.TempDir(), "ch")

	first := filepath.Join(t.TempDir(), "1.crpack")
	if _, err := Build(authoredAt(t, "2026.9.4", ""), first, priv); err != nil {
		t.Fatalf("build: %v", err)
	}
	if _, _, err := Publish(channel, first, priv); err != nil {
		t.Fatalf("publish: %v", err)
	}

	second := filepath.Join(t.TempDir(), "2.crpack")
	if _, err := Build(authoredAt(t, "2026.10.1", "600"), second, priv); err != nil {
		t.Fatalf("build: %v", err)
	}
	index, _, err := Publish(channel, second, priv)
	if err != nil {
		t.Fatalf("publish: %v", err)
	}

	// 2026.10.1 follows 2026.9.4, which a string comparison gets backwards.
	if index.Current != "2026.10.1" {
		t.Fatalf("current is %s, want 2026.10.1", index.Current)
	}

	trust := trustOf(t, prefix)
	opened, _, err := FetchRelease(context.Background(), channel, "", trust)
	if err != nil {
		t.Fatalf("fetch current: %v", err)
	}
	if opened.Pack.Version != "2026.10.1" {
		t.Fatalf("fetched %s, want the current 2026.10.1", opened.Pack.Version)
	}

	pinned, _, err := FetchRelease(context.Background(), channel, "2026.9.4", trust)
	if err != nil {
		t.Fatalf("fetch pinned: %v", err)
	}
	if pinned.Pack.Version != "2026.9.4" {
		t.Fatalf("pinned fetch gave %s", pinned.Pack.Version)
	}
}

// Pointing the index at an older release without re-signing it is the attack
// the index exists to stop: a replay of genuine packs.
func TestARolledBackIndexIsRefused(t *testing.T) {
	priv, prefix := signingKey(t)
	channel := filepath.Join(t.TempDir(), "ch")
	for _, v := range []string{"2026.9.4", "2026.10.1"} {
		out := filepath.Join(t.TempDir(), v+".crpack")
		if _, err := Build(authoredAt(t, v, ""), out, priv); err != nil {
			t.Fatalf("build %s: %v", v, err)
		}
		if _, _, err := Publish(channel, out, priv); err != nil {
			t.Fatalf("publish %s: %v", v, err)
		}
	}

	path := filepath.Join(channel, IndexName)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var index Index
	if err := json.Unmarshal(raw, &index); err != nil {
		t.Fatal(err)
	}
	index.Current = "2026.9.4"
	edited, err := json.Marshal(index)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, edited, 0o644); err != nil {
		t.Fatal(err)
	}

	_, err = ReadIndex(context.Background(), channel, trustOf(t, prefix))
	if err == nil {
		t.Fatal("a rolled-back index was accepted")
	}
	if !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
}

// Both packs properly signed, one served at the other's address. Nothing in
// either signature can catch this; the digest in the index is what does.
func TestTheWrongPackAtTheRightAddressIsRefused(t *testing.T) {
	priv, prefix := signingKey(t)
	channel := filepath.Join(t.TempDir(), "ch")

	var names []string
	for _, v := range []string{"2026.9.4", "2026.10.1"} {
		out := filepath.Join(t.TempDir(), v+".crpack")
		if _, err := Build(authoredAt(t, v, ""), out, priv); err != nil {
			t.Fatalf("build %s: %v", v, err)
		}
		_, release, err := Publish(channel, out, priv)
		if err != nil {
			t.Fatalf("publish %s: %v", v, err)
		}
		names = append(names, release.File)
	}

	older, err := os.ReadFile(filepath.Join(channel, names[0]))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(channel, names[1]), older, 0o644); err != nil {
		t.Fatal(err)
	}

	_, _, err = FetchRelease(context.Background(), channel, "2026.10.1", trustOf(t, prefix))
	if err == nil {
		t.Fatal("a genuine pack served at another version's address was accepted")
	}
	if !strings.Contains(err.Error(), "digest") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
}

// A version number is a promise. Letting it mean two things would make every
// pin anybody wrote worthless.
func TestAVersionCannotBeRepublishedWithDifferentContent(t *testing.T) {
	priv, _ := signingKey(t)
	channel := filepath.Join(t.TempDir(), "ch")

	first := filepath.Join(t.TempDir(), "a.crpack")
	if _, err := Build(authoredAt(t, "2026.10.1", ""), first, priv); err != nil {
		t.Fatalf("build: %v", err)
	}
	if _, _, err := Publish(channel, first, priv); err != nil {
		t.Fatalf("publish: %v", err)
	}

	changed := filepath.Join(t.TempDir(), "b.crpack")
	if _, err := Build(authoredAt(t, "2026.10.1", "900"), changed, priv); err != nil {
		t.Fatalf("build: %v", err)
	}
	if _, _, err := Publish(channel, changed, priv); err == nil {
		t.Fatal("a version was republished with different content")
	} else if !strings.Contains(err.Error(), "already published") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
}

// Re-running a release job must be a no-op, not a new timestamp on an old
// artefact.
func TestRepublishingTheSamePackKeepsItsPublicationTime(t *testing.T) {
	priv, _ := signingKey(t)
	channel := filepath.Join(t.TempDir(), "ch")

	pack := filepath.Join(t.TempDir(), "a.crpack")
	if _, err := Build(authoredAt(t, "2026.10.1", ""), pack, priv); err != nil {
		t.Fatalf("build: %v", err)
	}
	_, first, err := Publish(channel, pack, priv)
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	index, second, err := Publish(channel, pack, priv)
	if err != nil {
		t.Fatalf("republish: %v", err)
	}
	if second.PublishedAt != first.PublishedAt {
		t.Fatalf("republishing moved the publication time from %s to %s", first.PublishedAt, second.PublishedAt)
	}
	if len(index.Releases) != 1 {
		t.Fatalf("%d releases after republishing one, want 1", len(index.Releases))
	}
}

// Backfilling an old release into a channel must not roll every deployment
// following it back.
func TestPublishingAnOlderVersionDoesNotMoveCurrent(t *testing.T) {
	priv, _ := signingKey(t)
	channel := filepath.Join(t.TempDir(), "ch")

	newer := filepath.Join(t.TempDir(), "n.crpack")
	if _, err := Build(authoredAt(t, "2026.10.1", ""), newer, priv); err != nil {
		t.Fatalf("build: %v", err)
	}
	if _, _, err := Publish(channel, newer, priv); err != nil {
		t.Fatalf("publish: %v", err)
	}

	older := filepath.Join(t.TempDir(), "o.crpack")
	if _, err := Build(authoredAt(t, "2026.9.4", ""), older, priv); err != nil {
		t.Fatalf("build: %v", err)
	}
	index, _, err := Publish(channel, older, priv)
	if err != nil {
		t.Fatalf("publish the older one: %v", err)
	}
	if index.Current != "2026.10.1" {
		t.Fatalf("current moved to %s", index.Current)
	}
}

// An unsigned index must not sit beside a stale signature: it would verify
// against the old contents and read to an operator as tampering.
func TestPublishingUnsignedClearsTheStaleSignature(t *testing.T) {
	priv, _ := signingKey(t)
	channel := filepath.Join(t.TempDir(), "ch")

	signed := filepath.Join(t.TempDir(), "a.crpack")
	if _, err := Build(authoredAt(t, "2026.9.4", ""), signed, priv); err != nil {
		t.Fatalf("build: %v", err)
	}
	if _, _, err := Publish(channel, signed, priv); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if _, err := os.Stat(filepath.Join(channel, IndexSigName)); err != nil {
		t.Fatalf("the signed publish wrote no %s", IndexSigName)
	}

	plain := filepath.Join(t.TempDir(), "b.crpack")
	if _, err := Build(authoredAt(t, "2026.10.1", ""), plain, nil); err != nil {
		t.Fatalf("build: %v", err)
	}
	if _, _, err := Publish(channel, plain, nil); err != nil {
		t.Fatalf("publish unsigned: %v", err)
	}
	if _, err := os.Stat(filepath.Join(channel, IndexSigName)); !os.IsNotExist(err) {
		t.Fatalf("%s survived an unsigned publish (%v)", IndexSigName, err)
	}
}

// A channel with no signature is refused where one is configured, the same way
// a pack is.
func TestAnUnsignedChannelIsRefusedWhereSignaturesAreRequired(t *testing.T) {
	_, prefix := signingKey(t)
	channel := filepath.Join(t.TempDir(), "ch")

	pack := filepath.Join(t.TempDir(), "a.crpack")
	if _, err := Build(authoredAt(t, "2026.10.1", ""), pack, nil); err != nil {
		t.Fatalf("build: %v", err)
	}
	if _, _, err := Publish(channel, pack, nil); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if _, err := ReadIndex(context.Background(), channel, trustOf(t, prefix)); err == nil {
		t.Fatal("an unsigned channel was accepted")
	}
}

// Asking for a version a channel never published says so, and says what it has.
func TestAnUnknownVersionNamesWhatThereIs(t *testing.T) {
	index := &Index{Current: "2026.10.1", Releases: []Release{
		{Version: "2026.9.4"}, {Version: "2026.10.1"},
	}}
	_, err := index.Find("2027.1.0")
	if err == nil {
		t.Fatal("an unpublished version resolved")
	}
	for _, want := range []string{"2027.1.0", "2026.10.1", "2026.9.4"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("%q does not name %s", err, want)
		}
	}
	for _, alias := range []string{"", "current", "latest"} {
		r, err := index.Find(alias)
		if err != nil {
			t.Fatalf("Find(%q): %v", alias, err)
		}
		if r.Version != "2026.10.1" {
			t.Fatalf("Find(%q) gave %s", alias, r.Version)
		}
	}
}

// The comparison a downgrade check rests on. Each pair here is one a string
// comparison would get wrong, or one the ordering has to leave alone.
func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"2026.10.1", "2026.9.4", 1},
		{"2026.9.4", "2026.10.1", -1},
		{"2026.10.1", "2026.10.1", 0},
		{"2026.10", "2026.10.1", -1},
		{"2027.1.0", "2026.12.9", 1},
		{"1.0.0", "1.0", 1},
		{"2026.10.1", "2026.10.1-rc1", -1},
	}
	for _, c := range cases {
		got := CompareVersions(c.a, c.b)
		if (got > 0) != (c.want > 0) || (got < 0) != (c.want < 0) {
			t.Errorf("CompareVersions(%q, %q) = %d, want sign %d", c.a, c.b, got, c.want)
		}
	}
}

// ─── Revocation ─────────────────────────────────────────────────────────────

// Revoking a key refuses what it signed, and says why.
func TestARevokedKeyIsRefused(t *testing.T) {
	priv, prefix := signingKey(t)
	store := filepath.Join(t.TempDir(), "trust")
	if err := os.MkdirAll(store, 0o750); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(prefix + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	write(t, store, "signing.pub", string(raw))

	pack := filepath.Join(t.TempDir(), "a.crpack")
	if _, err := Build(authored(t), pack, priv); err != nil {
		t.Fatalf("build: %v", err)
	}
	trust, err := LoadTrust(store)
	if err != nil {
		t.Fatalf("load trust: %v", err)
	}
	id := trust.IDs()[0]
	if _, err := Open(pack, trust); err != nil {
		t.Fatalf("the pack does not open before revocation: %v", err)
	}

	write(t, store, "incident.revoked", "# INC-4412\n"+id+" laptop stolen\n")
	trust, err = LoadTrust(store)
	if err != nil {
		t.Fatalf("load trust after revoking: %v", err)
	}
	if len(trust.IDs()) != 0 {
		t.Fatalf("a revoked key is still listed as trusted: %v", trust.IDs())
	}
	_, err = Open(pack, trust)
	if err == nil {
		t.Fatal("a pack signed by a revoked key was accepted")
	}
	if !strings.Contains(err.Error(), "revoked") || !strings.Contains(err.Error(), "laptop stolen") {
		t.Fatalf("the refusal does not say it was revoked, or why: %v", err)
	}
}

// Deleting the public key is not how a key is withdrawn: the one host that
// missed the deletion keeps trusting it. The revocation has to stand on its
// own, with no key file beside it.
func TestARevocationStandsWithoutTheKeyFile(t *testing.T) {
	priv, prefix := signingKey(t)
	store := filepath.Join(t.TempDir(), "trust")
	if err := os.MkdirAll(store, 0o750); err != nil {
		t.Fatal(err)
	}
	// Another key is kept so the store is not empty — the deployment has
	// rotated, and only the old key's revocation remains.
	otherPriv, otherPrefix := signingKey(t)
	otherRaw, err := os.ReadFile(otherPrefix + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	write(t, store, "current.pub", string(otherRaw))

	revokedRaw, err := os.ReadFile(prefix + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	// Derive the id from the key, then throw the key away.
	tmp := filepath.Join(t.TempDir(), "old.pub")
	if err := os.WriteFile(tmp, revokedRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	oldStore, err := LoadTrust(tmp)
	if err != nil {
		t.Fatal(err)
	}
	oldID := oldStore.IDs()[0]
	write(t, store, "old.revoked", oldID+"\n")

	trust, err := LoadTrust(store)
	if err != nil {
		t.Fatalf("load trust: %v", err)
	}
	if trust.Holds(oldID) {
		t.Fatal("the store holds a key it was never given")
	}
	if len(trust.RevokedIDs()) != 1 {
		t.Fatalf("%d revocations, want 1", len(trust.RevokedIDs()))
	}

	pack := filepath.Join(t.TempDir(), "a.crpack")
	if _, err := Build(authored(t), pack, priv); err != nil {
		t.Fatalf("build: %v", err)
	}
	if _, err := Open(pack, trust); err == nil {
		t.Fatal("a pack signed by a revoked key whose file is gone was accepted")
	} else if !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("refused as unknown rather than as revoked: %v", err)
	}

	// The surviving key still works.
	current := filepath.Join(t.TempDir(), "b.crpack")
	if _, err := Build(authored(t), current, otherPriv); err != nil {
		t.Fatalf("build: %v", err)
	}
	if _, err := Open(current, trust); err != nil {
		t.Fatalf("the current key stopped verifying: %v", err)
	}
}

// A mistyped key id would withdraw nothing and look like it had.
func TestAMistypedRevocationIsRefused(t *testing.T) {
	_, prefix := signingKey(t)
	store := filepath.Join(t.TempDir(), "trust")
	if err := os.MkdirAll(store, 0o750); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(prefix + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	write(t, store, "signing.pub", string(raw))
	write(t, store, "oops.revoked", "deadbeef not-a-key-id\n")

	if _, err := LoadTrust(store); err == nil {
		t.Fatal("a mistyped revocation loaded silently")
	} else if !strings.Contains(err.Error(), "key identifier") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
}

// The same version rebuilt with different content and dropped over the file in
// the channel, with the index left alone. The version matches, so only the
// digest can catch it — and this is the likely operational accident, not the
// clever attack.
func TestAPackOverwrittenInPlaceIsRefused(t *testing.T) {
	priv, prefix := signingKey(t)
	channel := filepath.Join(t.TempDir(), "ch")

	original := filepath.Join(t.TempDir(), "a.crpack")
	if _, err := Build(authoredAt(t, "2026.10.1", ""), original, priv); err != nil {
		t.Fatalf("build: %v", err)
	}
	_, release, err := Publish(channel, original, priv)
	if err != nil {
		t.Fatalf("publish: %v", err)
	}

	// Same version, different content, properly signed by the same key.
	rebuilt := filepath.Join(t.TempDir(), "b.crpack")
	if _, err := Build(authoredAt(t, "2026.10.1", "900"), rebuilt, priv); err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	raw, err := os.ReadFile(rebuilt)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(channel, release.File), raw, 0o644); err != nil {
		t.Fatal(err)
	}

	_, _, err = FetchRelease(context.Background(), channel, "2026.10.1", trustOf(t, prefix))
	if err == nil {
		t.Fatal("a pack overwritten in place was accepted")
	}
	if !strings.Contains(err.Error(), "digest") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
}
