// contentctl reconciles a detection content pack with the catalogue.
//
// The detections used to be INSERT statements in a migration, so improving one
// meant a schema change, a rebuild and a deployment window — for a sentence of
// rationale or a threshold somebody wanted tightened. This is what lets the
// content ship on its own cadence.
//
//	contentctl                      # show what a load would do, change nothing
//	contentctl -apply               # do it
//	contentctl -check               # validate the pack, touch no database
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
		dir   = flag.String("dir", envOr("CRP_CONTENT_DIR", "content/detections"), "the content pack to load")
		dsn   = flag.String("db", envOr("DATABASE_URL", "postgres://crp_user:crp_password_dev@localhost:5432/crp_foundation?sslmode=disable"), "PostgreSQL DSN")
		apply = flag.Bool("apply", false, "write the changes; without it nothing is written")
		check = flag.Bool("check", false, "validate the pack and exit, touching no database")
		quiet = flag.Bool("quiet", false, "print only what changes")
	)
	flag.Parse()

	pack, entries, err := content.Load(*dir)
	if err != nil {
		fail("%v", err)
	}

	abs, _ := filepath.Abs(*dir)
	if !*quiet {
		fmt.Printf("%s %s — %d detection(s) from %s\n", pack.Name, pack.Version, len(entries), abs)
	}

	// -check is what a pipeline runs on a content change: it proves the pack is
	// loadable and that every condition names a field the engine reads, without
	// needing a database to prove it against.
	if *check {
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

	plan, err := content.Reconcile(ctx, db, pack, entries, abs)
	if err != nil {
		fail("%v", err)
	}

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

	// Applied even when nothing moves: "we loaded 2026.10.1 and it changed
	// nothing" is a different claim from "we never loaded it", and an operator
	// asking why a detection is missing needs to tell them apart.
	if err := content.Apply(ctx, db, pack, entries, plan); err != nil {
		fail("%v", err)
	}
	if plan.Moves() {
		fmt.Printf("%s applied: %s\n", pack.Version, summary)
	} else if !*quiet {
		fmt.Printf("%s: nothing to change\n", pack.Version)
	}
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
