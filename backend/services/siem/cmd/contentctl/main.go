// contentctl builds, verifies and loads detection content packs.
//
// The detections used to be INSERT statements in a migration, so improving one
// meant a schema change, a rebuild and a deployment window — for a sentence of
// rationale or a threshold somebody wanted tightened. This is what lets the
// content ship on its own cadence, and be told apart from content nobody
// published.
//
//	contentctl -keygen deployments/content/signing   make a signing key pair
//	contentctl -build dist/pack.crpack -sign-key ... package a release
//	contentctl -build dist/p.crpack -publish dist/ch -sign-key ...  and publish it
//	contentctl -channel https://… -verify-only       check what a channel serves
//	contentctl -channel https://… -trust … -apply    install the current version
//	contentctl -channel https://… -version 2026.10.1 install a named one
//	contentctl -pack dist/pack.crpack -verify-only   check one release, load nothing
//	contentctl -pack dist/pack.crpack -apply         install it
//	contentctl -check                                validate the working directory
//	contentctl -trust-list -trust /etc/crp/trust     what this deployment accepts
//	contentctl -affected <key id> -db …              what a key signed that we ran
//
// The release procedure, and what to do when a signing key is lost or
// compromised, is written down in plan/20-CONTENT-RELEASE.md.
package main

import (
	"context"
	"crypto/ed25519"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/cyberradar/platform/services/siem/internal/content"
)

func main() {
	var (
		dir   = flag.String("dir", envOr("CRP_CONTENT_DIR", "content/detections"), "a content directory to load, build or check")
		pack  = flag.String("pack", envOr("CRP_CONTENT_PACK", ""), "a packaged release to load, as a path or an https URL; overrides -dir")
		trust = flag.String("trust", envOr("CRP_CONTENT_TRUST", ""), "public key, or directory of them, this deployment accepts")

		channel = flag.String("channel", envOr("CRP_CONTENT_CHANNEL", ""), "a published channel to load from, as a path or an https base; overrides -pack")
		version = flag.String("version", envOr("CRP_CONTENT_VERSION", ""), "which version to take from the channel; empty means whatever it calls current")

		build   = flag.String("build", "", "package the content directory into this file")
		publish = flag.String("publish", "", "publish a pack into this channel directory and rewrite its signed index")
		signKey = flag.String("sign-key", envOr("CRP_CONTENT_SIGN_KEY", ""), "private key to sign a build or an index with")
		keygen  = flag.String("keygen", "", "generate a signing key pair under this prefix and exit")

		trustList = flag.Bool("trust-list", false, "print the keys this deployment trusts and the ones it has revoked, and exit")
		affected  = flag.String("affected", "", "list what a given key signed that this deployment loaded, and exit")

		dsn   = flag.String("db", envOr("DATABASE_URL", "postgres://crp_user:crp_password_dev@localhost:5432/crp_foundation?sslmode=disable"), "PostgreSQL DSN")
		apply = flag.Bool("apply", false, "write the changes; without it nothing is written")
		check = flag.Bool("check", false, "validate and exit, touching no database")

		verifyOnly     = flag.Bool("verify-only", false, "verify a pack's signature and contents, load nothing")
		allowUnsigned  = flag.Bool("allow-unsigned", false, "load a pack with no signature; needed while authoring, never on a deployment")
		allowDowngrade = flag.Bool("allow-downgrade", false, "install a version older than the one already loaded")
		quiet          = flag.Bool("quiet", false, "print only what changes")
	)
	flag.Parse()

	if *keygen != "" {
		id, err := content.GenerateKey(*keygen)
		if err != nil {
			fail("%v", err)
		}
		fmt.Printf("signing key %s written to %s.key (keep it) and %s.pub (publish it)\n", id, *keygen, *keygen)
		fmt.Printf("a deployment trusts it with:  -trust %s.pub\n", *keygen)
		return
	}

	if *trustList {
		doTrustList(*trust)
		return
	}

	if *affected != "" {
		doAffected(*dsn, *affected)
		return
	}

	if *build != "" {
		doBuild(*dir, *build, *signKey, *quiet)
		if *publish == "" {
			return
		}
		// Built and published in one command on purpose: the two steps that
		// have to agree are the signing of the pack and the signing of the
		// index that pins its digest, and a release job that can do one
		// without the other is a release job that eventually does.
		*pack = *build
	}

	if *publish != "" {
		if *pack == "" {
			fail("-publish needs a pack: give it -pack <file>, or -build one in the same command")
		}
		doPublish(*publish, *pack, *signKey, *quiet)
		return
	}

	loaded, err := open(*pack, *channel, *version, *dir, *trust, *allowUnsigned)
	if err != nil {
		fail("%v", err)
	}

	if !*quiet {
		fmt.Printf("%s %s — %d detection(s) from %s\n",
			loaded.pack.Name, loaded.pack.Version, len(loaded.entries), loaded.source)
		switch {
		case loaded.signedBy != "":
			fmt.Printf("  signed by %s · manifest %s\n", loaded.signedBy, content.ShortDigest(loaded.digest))
		case *pack != "" || *channel != "":
			fmt.Printf("  UNSIGNED — nothing vouches for where this came from\n")
		}
	}

	if *verifyOnly || *check {
		if !*quiet {
			fmt.Println("the pack is valid")
		}
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	db, err := pgxpool.New(ctx, *dsn)
	if err != nil {
		fail("connect: %v", err)
	}
	defer db.Close()
	if err := db.Ping(ctx); err != nil {
		fail("connect: %v", err)
	}

	// What is already installed, read before anything is decided. A pack six
	// months old is as properly signed as today's, so the signature cannot tell
	// an operator they are about to roll the catalogue back — only the record
	// of what came before can.
	last, err := content.LastLoad(ctx, db, loaded.pack.Name)
	if err != nil {
		fail("%v", err)
	}
	if last != nil && !*quiet {
		fmt.Printf("  currently %s, loaded %s\n", last.Version, last.LoadedAt.Format("2006-01-02 15:04"))
	}
	// The refusal is for a published release only. Replaying an old release is
	// an attack; pointing the loader at a directory is somebody saying "make
	// the catalogue match these files", which is a statement about content
	// they are holding, not a version claim made by anybody else. Refusing
	// that would block the ordinary case — editing a detection on a box that
	// once installed a newer release — to guard against nothing.
	if last != nil && content.CompareVersions(loaded.pack.Version, last.Version) < 0 {
		switch {
		case *allowDowngrade:
		case !loaded.published:
			warn("this directory is %s and %s is loaded; the catalogue will be rolled back to match it",
				loaded.pack.Version, last.Version)
		default:
			fail("this release is %s and %s is already loaded. Installing it would withdraw every detection "+
				"published since, and a correctly signed old release is exactly what someone replaying one "+
				"would hand you. Say -allow-downgrade if that is what you mean.",
				loaded.pack.Version, last.Version)
		}
	}

	plan, err := content.Reconcile(ctx, db, loaded.pack, loaded.entries, loaded.source)
	if err != nil {
		fail("%v", err)
	}
	plan.SignedBy = loaded.signedBy
	plan.Digest = loaded.digest

	for _, c := range plan.Changes {
		if c.Action == "unchanged" && *quiet {
			continue
		}
		switch c.Action {
		case "publish":
			if c.From == 0 {
				fmt.Printf("  + %-14s v1           %s\n", c.Code, c.Why)
			} else {
				fmt.Printf("  ^ %-14s v%d -> v%d     %s\n", c.Code, c.From, c.To, c.Why)
			}
		case "retire":
			fmt.Printf("  - %-14s v%d retired   %s\n", c.Code, c.From, c.Why)
		default:
			fmt.Printf("    %-14s v%d\n", c.Code, c.From)
		}
	}

	published, retired, unchanged := plan.Counts()
	summary := fmt.Sprintf("%d published, %d retired, %d unchanged", published, retired, unchanged)

	if !*apply {
		if plan.Moves() {
			fmt.Printf("would apply: %s   (re-run with -apply)\n", summary)
		} else if !*quiet {
			fmt.Println("nothing to do: the catalogue already matches this pack")
		}
		return
	}

	// Applied even when nothing moves: "we loaded 2026.10.1, signed by this key,
	// and it changed nothing" is a different claim from "we never loaded it",
	// and an operator asking why a detection is missing needs to tell them apart.
	if err := content.Apply(ctx, db, loaded.pack, loaded.entries, plan); err != nil {
		fail("%v", err)
	}
	if plan.Moves() {
		fmt.Printf("%s applied: %s\n", loaded.pack.Version, summary)
	} else if !*quiet {
		fmt.Printf("%s: nothing to change\n", loaded.pack.Version)
	}
}

// source is a pack ready to reconcile, however it was obtained.
type source struct {
	pack     *content.Pack
	entries  []*content.Entry
	source   string
	signedBy string
	digest   string
	// published is true when this came from a release — a pack or a channel —
	// rather than from a directory somebody is editing.
	published bool
}

// open resolves -channel, -pack or -dir into entries, verifying along the way.
//
// A published release and no trust store is refused unless the caller says
// -allow-unsigned. Defaulting to "accept anything" would make the signature
// decorative: a deployment that forgot to configure its trust would verify
// nothing and look exactly like one that had.
func open(packPath, channel, version, dir, trustPath string, allowUnsigned bool) (*source, error) {
	if packPath == "" && channel == "" {
		pack, entries, err := content.Load(dir)
		if err != nil {
			return nil, err
		}
		abs, _ := filepath.Abs(dir)
		return &source{pack: pack, entries: entries, source: abs}, nil
	}

	var trust *content.TrustStore
	switch {
	case trustPath != "":
		var err error
		if trust, err = content.LoadTrust(trustPath); err != nil {
			return nil, err
		}
	case !allowUnsigned:
		return nil, fmt.Errorf("loading a published release needs -trust, or -allow-unsigned said out loud; " +
			"without one of them a signature would be checked against nothing and look like it had been checked")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	if channel != "" {
		opened, from, err := content.FetchRelease(ctx, channel, version, trust)
		if err != nil {
			return nil, err
		}
		return &source{
			pack: opened.Pack, entries: opened.Entries, source: from,
			signedBy: opened.SignedBy, digest: opened.Digest, published: true,
		}, nil
	}

	local, cleanup, err := content.Fetch(ctx, packPath)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	opened, err := content.Open(local, trust)
	if err != nil {
		return nil, err
	}
	return &source{
		pack: opened.Pack, entries: opened.Entries, source: packPath,
		signedBy: opened.SignedBy, digest: opened.Digest, published: true,
	}, nil
}

func doBuild(dir, out, signKey string, quiet bool) {
	var priv []byte
	if signKey != "" {
		key, err := content.LoadPrivateKey(signKey)
		if err != nil {
			fail("%v", err)
		}
		priv = key
	}

	manifest, err := content.Build(dir, out, priv)
	if err != nil {
		fail("%v", err)
	}
	digest, err := manifest.Digest()
	if err != nil {
		fail("%v", err)
	}

	if quiet {
		return
	}
	fmt.Printf("%s %s packaged into %s\n", manifest.Pack.Name, manifest.Pack.Version, out)
	fmt.Printf("  %d file(s) · manifest %s\n", len(manifest.Files), content.ShortDigest(digest))
	if manifest.KeyID == "" {
		// Said plainly rather than as a warning nobody reads: an unsigned
		// release is a release a deployment cannot accept without being told to.
		fmt.Println("  UNSIGNED — pass -sign-key to sign it, or deployments will need -allow-unsigned")
	} else {
		fmt.Printf("  signed by %s\n", manifest.KeyID)
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func warn(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "contentctl: "+format+"\n", args...)
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "contentctl: "+format+"\n", args...)
	os.Exit(1)
}

// doPublish puts a built pack into a channel and rewrites the signed index.
//
// Publishing is separate from building because they happen under different
// authority: anybody may build a pack from the working directory, and putting
// one into the channel a deployment follows is the step that says "run this".
func doPublish(channelDir, packPath, signKey string, quiet bool) {
	var priv ed25519.PrivateKey
	if signKey != "" {
		key, err := content.LoadPrivateKey(signKey)
		if err != nil {
			fail("%v", err)
		}
		priv = key
	}

	index, release, err := content.Publish(channelDir, packPath, priv)
	if err != nil {
		fail("%v", err)
	}
	if quiet {
		return
	}

	fmt.Printf("%s %s published to %s\n", index.Pack, release.Version, channelDir)
	fmt.Printf("  %s · manifest %s · %d bytes\n", release.File, content.ShortDigest(release.ManifestDigest), release.Size)
	if release.SignedBy == "" {
		fmt.Println("  the pack itself is UNSIGNED")
	}
	if index.KeyID == "" {
		fmt.Printf("  %s is UNSIGNED — a deployment reading this channel cannot tell which version is really current\n", content.IndexName)
	} else {
		fmt.Printf("  %s signed by %s\n", content.IndexName, index.KeyID)
	}
	fmt.Printf("  current: %s   (published: %s)\n", index.Current, strings.Join(index.Versions(), ", "))
}

// doTrustList prints what a deployment accepts.
//
// Exists because a revocation is a line in a file, and a line in a file can be
// mistyped. Printing what the deployment actually resolved turns "we revoked
// it" from a belief into something an operator can read back.
func doTrustList(trustPath string) {
	if trustPath == "" {
		fail("-trust-list needs -trust <file or directory>")
	}
	store, err := content.LoadTrust(trustPath)
	if err != nil {
		fail("%v", err)
	}

	fmt.Printf("%s\n", trustPath)
	for _, id := range store.IDs() {
		fmt.Printf("  trusted  %s\n", id)
	}
	for _, id := range store.RevokedIDs() {
		held := "revoked, key not held"
		if store.Holds(id) {
			held = "revoked, key still on disk"
		}
		if why := store.RevocationReason(id); why != "" {
			fmt.Printf("  REVOKED  %s  (%s) — %s\n", id, held, why)
		} else {
			fmt.Printf("  REVOKED  %s  (%s)\n", id, held)
		}
	}
	if len(store.RevokedIDs()) == 0 {
		fmt.Println("  no revocations")
	}
}

// doAffected answers the question a revocation raises: what did that key sign
// that we installed?
//
// Withdrawing a key stops the next bad pack. It says nothing about the ones
// already in the catalogue, and an operator who has just learned a signing key
// leaked needs that list before they need anything else.
func doAffected(dsn, keyID string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	db, err := pgxpool.New(ctx, dsn)
	if err != nil {
		fail("connect: %v", err)
	}
	defer db.Close()

	loads, err := content.LoadsSignedBy(ctx, db, keyID)
	if err != nil {
		fail("%v", err)
	}
	if len(loads) == 0 {
		fmt.Printf("nothing this deployment loaded was signed by %s\n", keyID)
		return
	}

	fmt.Printf("%d load(s) signed by %s:\n", len(loads), keyID)
	for _, l := range loads {
		fmt.Printf("  %s  %-10s  manifest %s  +%d -%d =%d\n",
			l.LoadedAt.Format("2006-01-02 15:04"), l.Version,
			content.ShortDigest(l.Digest), l.Published, l.Retired, l.Unchanged)
		fmt.Printf("    from %s\n", l.Source)
	}
	fmt.Println("\nEvery detection published by these loads came in under that key. " +
		"Re-install the catalogue from a release signed by a key you still trust before " +
		"treating the catalogue as sound.")
}
