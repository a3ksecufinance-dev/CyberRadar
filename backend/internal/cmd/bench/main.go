// Command bench measures the three figures a CIO asks for first: how many
// events the platform ingests per second, how long its API takes at the 95th
// percentile, and how long it takes to turn an event into an alert.
//
// None of the three existed. They are the first three questions of every
// tender, and "we have not measured it" is a worse answer than a modest
// number with the machine beside it.
//
// The point is the method, not the figure. A number measured once is an
// anecdote; this is a command, so it can be re-run on the hardware a customer
// is actually buying, and the report always carries the machine that produced
// it — a figure taken on a shared four-core container says what that container
// does, and quoting it as a product specification would be a lie told with a
// true number.
//
//	bench                    the three measurements, against a running platform
//	bench -only throughput   one of them, to iterate
//	bench -ladder 200,500    offer these rates rather than the default ladder
//
// It needs a platform that is up and seeded: `./scripts/dev-local.sh up` then
// `./bin/demo-seed`, which is also what creates the connector credential this
// reads.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cyberradar/platform/internal/pkg/db"
	"github.com/cyberradar/platform/internal/pkg/devtoken"
)

// benchConnectorID is a correlation identifier the collector records against
// the events, not a foreign key. A constant of its own keeps the bench's
// events distinguishable from the demonstration's.
const benchConnectorID = "b3c40000-0000-4000-8000-000000000001"

type bench struct {
	admin     *client
	connector *client
	brokers   []string

	ladder         []int
	window         time.Duration
	settle         time.Duration
	concurrency    int
	latencyCount   int
	detectRounds   int
	detectDeadline time.Duration

	drainDeadline time.Duration

	// runSalt keeps one run's detection addresses clear of another's, which
	// matters inside the engine's deduplication window.
	runSalt int
}

func main() {
	var (
		email    = flag.String("as", "admin@cyberradar.io", "identity to read the platform as")
		keyPath  = flag.String("key", envOr("JWT_PRIVATE_KEY_PATH", "deployments/jwt/private.pem"), "RSA private key used to mint the access token")
		dsn      = flag.String("db", envOr("DATABASE_URL", "postgres://crp_user:crp_password_dev@localhost:5432/crp_foundation?sslmode=disable"), "PostgreSQL DSN, used only to resolve the identity")
		credFile = flag.String("connector-credential", envOr("CRP_DEMO_CONNECTOR_CREDENTIAL", filepath.Join(envOr("CRP_STATE_DIR", ".dev-local"), "demo-connector.json")), "the connector credential demo-seed wrote")
		brokers  = flag.String("brokers", envOr("KAFKA_BROKERS", "localhost:9092"), "Kafka brokers, read to see what the pipeline drained")
		ladder   = flag.String("ladder", "100,250,500,1000,2000", "offered ingestion rates, events per second")
		window   = flag.Duration("window", 10*time.Second, "how long each rung of the ladder offers its rate")
		settle   = flag.Duration("settle", 15*time.Second, "how long the pipeline is given to drain before the verdict")
		conc     = flag.Int("concurrency", 16, "requests in flight")
		lat      = flag.Int("latency-requests", 600, "requests used for the latency distribution")
		rounds   = flag.Int("detection-rounds", 10, "how many times the detection path is timed")
		deadline = flag.Duration("detection-deadline", 90*time.Second, "how long one detection round waits for its alert")
		drain    = flag.Duration("drain-deadline", 10*time.Minute, "how long to let the rule engine catch up before measuring detection")
		only     = flag.String("only", "", "run one of: throughput, latency, detection, lag")
		lagFill  = flag.Int("lag-backlog", 0, "with -only lag: events to put on the normalized topic first, instead of waiting for a backlog")
		shared   = flag.Bool("shared-machine", true, "the platform runs on this same machine, and the report must say so")
	)
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	rates, err := parseLadder(*ladder)
	if err != nil {
		fatal(err)
	}

	token, err := mintToken(ctx, *dsn, *keyPath, *email)
	if err != nil {
		fatal(err)
	}
	base := baseURLs()
	admin := newClient(token, base)

	connector, err := connectorClient(ctx, admin, *credFile)
	if err != nil {
		fatal(fmt.Errorf("%w\n\nThe bench ingests as a connector, which needs the credential "+
			"demo-seed writes. Run ./bin/demo-seed first", err))
	}

	b := &bench{
		admin: admin, connector: connector,
		brokers:      strings.Split(*brokers, ","),
		ladder:       rates,
		window:       *window,
		settle:       *settle,
		concurrency:  *conc,
		latencyCount: *lat,
		detectRounds: *rounds, detectDeadline: *deadline,
		drainDeadline: *drain,
		runSalt:       int(time.Now().UnixNano()/int64(time.Second)) % 60000,
	}

	m := describeMachine(*shared)
	fmt.Printf("\n\033[1mLa machine\033[0m\n%s\n", m)

	run := func(name string) bool { return *only == "" || *only == name }

	// A mode of its own, because the first thing to know about a platform
	// that has just been loaded is whether it is still digesting. It also
	// yields the figure the ladder cannot: watching a backlog drain measures
	// what the pipeline processes per second with no sender in the way.
	if *only == "lag" {
		if err := b.reportLag(ctx, *lagFill); err != nil {
			fatal(err)
		}
		return
	}
	var report strings.Builder

	if run("throughput") {
		fmt.Printf("\033[1m── Débit d'ingestion\033[0m  (%s par palier, %s de drainage)\n", *window, *settle)
		rungs, err := b.throughput(ctx)
		if err != nil {
			fatal(err)
		}
		report.WriteString(throughputLine(rungs))
	}

	if run("latency") {
		// Twice, because one figure would hide which of two very different
		// things it measures. One request at a time is what the handler
		// costs; the configured concurrency is what a user feels when
		// colleagues are using the platform too, and on a machine with few
		// cores the difference between them is queueing rather than work.
		// Reporting only the first flatters, only the second alarms.
		fmt.Printf("\n\033[1m── Latence API\033[0m  (%d requêtes, après échauffement)\n", *lat)
		b.warm(ctx, "/api/v1/assets")

		quiet := b.concurrency
		b.concurrency = 1
		alone, err := b.latency(ctx, "/api/v1/assets", *lat)
		if err != nil {
			fatal(err)
		}
		fmt.Printf("   une requête à la fois   %s\n", alone.summary())

		b.concurrency = quiet
		loaded, err := b.latency(ctx, "/api/v1/assets", *lat)
		if err != nil {
			fatal(err)
		}
		fmt.Printf("   %2d requêtes en vol      %s\n", quiet, loaded.summary())

		report.WriteString(fmt.Sprintf("  latence API p95        %s seule · %s à %d en vol  (p50 %s · %s)\n",
			ms(alone.quantile(0.95)), ms(loaded.quantile(0.95)), quiet,
			ms(alone.quantile(0.50)), ms(loaded.quantile(0.50))))
	}

	if run("detection") {
		fmt.Printf("\n\033[1m── Temps de détection\033[0m  (%d tours)\n", *rounds)
		s, err := b.detection(ctx, *rounds)
		if err != nil {
			fatal(err)
		}
		fmt.Printf("   %s\n", s.summary())
		report.WriteString(fmt.Sprintf("  temps de détection     p50 %s · p95 %s  (sur %d tours)\n",
			ms(s.quantile(0.50)), ms(s.quantile(0.95)), s.n()))
	}

	fmt.Printf("\n\033[1mLes trois chiffres\033[0m\n%s", report.String())
	fmt.Printf("\n%s\n", caveat(m))
}

// saturated says the ladder found the ceiling rather than merely running out
// of rungs: the last two held, the offered rate grew by at least half, and the
// achieved rate did not follow. Without this the report would call "no rung
// broke" and "it stopped going faster" the same thing, and only the second is
// a measured ceiling.
func saturated(rungs []rung) bool {
	var held []rung
	for _, r := range rungs {
		if r.OK {
			held = append(held, r)
		}
	}
	if len(held) < 2 {
		return false
	}
	a, b := held[len(held)-2], held[len(held)-1]
	offeredGrew := float64(b.Offered) >= float64(a.Offered)*1.5
	achievedStalled := b.Achieved < a.Achieved*1.25
	return offeredGrew && achievedStalled
}

// firstBroken is the rung that failed, if the ladder reached one.
func firstBroken(rungs []rung) *rung {
	for i := range rungs {
		if !rungs[i].OK {
			return &rungs[i]
		}
	}
	return nil
}

func throughputLine(rungs []rung) string {
	var best *rung
	for i := range rungs {
		if rungs[i].OK {
			best = &rungs[i]
		}
	}
	if best == nil {
		if len(rungs) == 0 {
			return "  débit d'ingestion      non mesuré\n"
		}
		return fmt.Sprintf("  débit d'ingestion      sous %d ev/s — %s\n", rungs[0].Offered, rungs[0].Note)
	}
	// The achieved rate, not the offered one. When the sender cannot deliver
	// what it offers it is because the collector is answering more slowly —
	// that is the platform applying backpressure, and the rate that actually
	// went through is the one that was sustained.
	// Which of three things the ladder actually established, in the order
	// that makes the figure mean something: a rung that broke gives the
	// ceiling and the reason, a plateau gives saturation, and a ladder that
	// ran out of rungs gives only a lower bound — and has to say so, or the
	// last figure reads as a limit when it is a floor.
	note := ""
	if broken := firstBroken(rungs); broken != nil {
		note = fmt.Sprintf("\n                         plafond trouvé : %d ev/s ont cédé — %s",
			broken.Offered, broken.Note)
	} else if saturated(rungs) {
		note = " — saturation : l'offre double, le débit ne suit plus"
	} else {
		note = " — aucun palier n'a cédé, le plafond est au-dessus"
	}
	return fmt.Sprintf("  débit d'ingestion      %.0f ev/s tenus%s\n"+
		"                         0 en rebut, %d événements drainés par le pipeline\n",
		best.Achieved, note, best.Drained)
}

// caveat is printed with every report, and is the sentence that keeps the
// figures honest when somebody copies them into a slide.
func caveat(m machine) string {
	if !m.Shared {
		return "Mesuré sur une machine dédiée à la plateforme."
	}
	return "Ces chiffres sont un plancher, pas une spécification produit. Le banc, les 29\n" +
		"services et toute l'infrastructure se partagent ces " +
		strconv.Itoa(m.CPUs) + " cœurs : ce qui est mesuré\n" +
		"est ce que fait cette machine-là, pas ce que fait le produit. Une mesure qui\n" +
		"engage se prend sur le matériel du client, avec la même commande."
}

func parseLadder(s string) ([]int, error) {
	var out []int
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		n, err := strconv.Atoi(part)
		if err != nil || n <= 0 {
			return nil, fmt.Errorf("%q is not a rate in events per second", part)
		}
		out = append(out, n)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("the ladder is empty")
	}
	return out, nil
}

func mintToken(ctx context.Context, dsn, keyPath, email string) (string, error) {
	pool, err := db.NewPostgresPool(ctx, db.DefaultPostgresConfig(dsn))
	if err != nil {
		return "", fmt.Errorf("connect to PostgreSQL: %w", err)
	}
	defer pool.Close()
	token, _, err := devtoken.Mint(ctx, pool, keyPath, email)
	return token, err
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "bench: %v\n", err)
	os.Exit(1)
}
