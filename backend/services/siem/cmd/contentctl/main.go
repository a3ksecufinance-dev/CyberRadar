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
//	contentctl -pack dist/pack.crpack -verify-only   check a release, load nothing
//	contentctl -pack dist/pack.crpack               what loading it would do
//	contentctl -pack dist/pack.crpack -apply        do it
//	contentctl -check                               validate the working directory
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/cyberradar/platform/services/siem/internal/content"
)

func main() {
	var (
		dir   = flag.String("dir", envOr("CRP_CONTENT_DIR", "content/detections"), "a content directory to load, build or check")
		pack  = flag.String("pack", envOr("CRP_CONTENT_PACK", ""), "a packaged release to load, as a path or an https URL; overrides -dir")
		trust = flag.String("trust", envOr("CRP_CONTENT_TRUST", ""), "public key, or directory of them, this deployment accepts")

		build   = flag.String("build", "", "package the content directory into this file and exit")
		signKey = flag.String("sign-key", envOr("CRP_CONTENT_SIGN_KEY", ""), "private key to sign a build with")
		keygen  = flag.String("keygen", "", "generate a signing key pair under this prefix and exit")

		dsn   = flag.String("db", envOr("DATABASE_URL", "postgres://crp_user:crp_password_dev@localhost:5432/crp_foundation?sslmode=disable"), "PostgreSQL DSN")
		apply = flag.Bool("apply", false, "write the changes; without it nothing is written")
		check = flag.Bool("check", false, "validate and exit, touching no database")

		verifyOnly    = flag.Bool("verify-only", false, "verify a pack's signature and contents, load nothing")
		allowUnsigned = flag.Bool("allow-unsigned", false, "load a pack with no signature; needed while authoring, never on a deployment")
		quiet         = flag.Bool("quiet", false, "print only what changes")
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

	if *build != "" {
		doBuild(*dir, *build, *signKey, *quiet)
		return
	}

	loaded, err := open(*pack, *dir, *trust, *allowUnsigned)
	if err != nil {
		fail("%v", err)
	}

	if !*quiet {
		fmt.Printf("%s %s — %d detection(s) from %s\n",
			loaded.pack.Name, loaded.pack.Version, len(loaded.entries), loaded.source)
		switch {
		case loaded.signedBy != "":
			fmt.Printf("  signed by %s · manifest %s\n", loaded.signedBy, short(loaded.digest))
		case *pack != "":
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
}

// open resolves -pack or -dir into entries, verifying a pack along the way.
//
// A pack and no trust store is refused unless the caller says -allow-unsigned.
// Defaulting to "accept anything" would make the signature decorative: a
// deployment that forgot to configure its trust would verify nothing and look
// exactly like one that had.
func open(packPath, dir, trustPath string, allowUnsigned bool) (*source, error) {
	if packPath == "" {
		pack, entries, err := content.Load(dir)
		if err != nil {
			return nil, err
		}
		abs, _ := filepath.Abs(dir)
		return &source{pack: pack, entries: entries, source: abs}, nil
	}

	var trust content.TrustStore
	switch {
	case trustPath != "":
		var err error
		if trust, err = content.LoadTrust(trustPath); err != nil {
			return nil, err
		}
	case !allowUnsigned:
		return nil, fmt.Errorf("loading a pack needs -trust, or -allow-unsigned said out loud; " +
			"without one of them a signature would be checked against nothing and look like it had been checked")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

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
		signedBy: opened.SignedBy, digest: opened.Digest,
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
	fmt.Printf("  %d file(s) · manifest %s\n", len(manifest.Files), short(digest))
	if manifest.KeyID == "" {
		// Said plainly rather than as a warning nobody reads: an unsigned
		// release is a release a deployment cannot accept without being told to.
		fmt.Println("  UNSIGNED — pass -sign-key to sign it, or deployments will need -allow-unsigned")
	} else {
		fmt.Printf("  signed by %s\n", manifest.KeyID)
	}
}

func short(digest string) string {
	if len(digest) <= 16 {
		return digest
	}
	return digest[:16]
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "contentctl: "+format+"\n", args...)
	os.Exit(1)
}
