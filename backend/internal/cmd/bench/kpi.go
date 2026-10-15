package main

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// ─── The KPI the master plan names ───────────────────────────────────────────
//
// Three of the eight are the bench's own figures and have their own modes.
// This is the other five, and the first thing to say about them is that they
// are not all the same kind of thing. Two are properties of the platform that
// a measurement can establish. Two are numbers the product computes about a
// customer's own operations, where what can be checked here is that the
// computation runs and on how much evidence it rests. One cannot be measured
// at all without a corpus that does not exist, and saying so is the honest
// answer rather than producing a figure that would be invented.

func (b *bench) reportKPI(ctx context.Context, window time.Duration) error {
	if err := b.assetCoverage(ctx); err != nil {
		return err
	}
	if err := b.availability(ctx, window); err != nil {
		return err
	}
	if err := b.incidentTimes(ctx); err != nil {
		return err
	}
	falsePositives()
	return nil
}

// assetCoverage is the share of the inventory that the platform can show is
// alive.
//
// Inventory alone says nothing: an asset that is listed and silent is a blind
// spot, and counting it as covered is how a coverage figure becomes a
// reassurance instead of a measurement. The numbers come from the service's
// own stats endpoint, which is where the interface reads them too.
func (b *bench) assetCoverage(ctx context.Context) error {
	// Decoded flat: the client already unwraps the standard envelope, so a
	// struct declaring its own Data field finds no such key and reads zero
	// for every number. Which is what it did, and an inventory of a hundred
	// and twenty-five assets reported itself empty.
	var d struct {
		Total     int `json:"total"`
		NeverSeen int `json:"never_seen"`
		Stale     int `json:"stale"`
	}
	if err := b.admin.get(ctx, "asset", "/api/v1/assets/stats", nil, &d); err != nil {
		return fmt.Errorf("statistiques des actifs: %w", err)
	}
	if d.Total == 0 {
		fmt.Printf("   couverture d'actifs     inventaire vide — rien à couvrir\n\n")
		return nil
	}

	seen := d.Total - d.NeverSeen
	fmt.Printf("   couverture d'actifs     %d / %d actifs vus — %.0f %%\n",
		seen, d.Total, float64(seen)/float64(d.Total)*100)
	if d.Stale > 0 {
		fmt.Printf("     dont %d vus pour la dernière fois il y a plus de trente jours\n", d.Stale)
	}
	fmt.Printf("     un actif inventorié et muet est un angle mort : il compte au\n")
	fmt.Printf("     dénominateur, pas au numérateur\n\n")
	return nil
}

// availability probes the paths a user takes and reports the share of probes
// that answered.
//
// What this measures is bounded and the bound is printed with it: a window of
// seconds says nothing about an annual figure. What it establishes is that the
// number exists, is taken from the same entry points a customer uses, and
// comes back the same way on the next run.
func (b *bench) availability(ctx context.Context, window time.Duration) error {
	probed := []string{"identity", "collector", "asset", "siem", "ir"}
	const interval = 500 * time.Millisecond

	var mu sync.Mutex
	ok := make(map[string]int, len(probed))
	total := make(map[string]int, len(probed))

	deadline := time.Now().Add(window)
	var wg sync.WaitGroup
	for _, name := range probed {
		wg.Add(1)
		go func(svc string) {
			defer wg.Done()
			for time.Now().Before(deadline) {
				err := b.admin.get(ctx, svc, "/health", nil, nil)
				mu.Lock()
				total[svc]++
				if err == nil {
					ok[svc]++
				}
				mu.Unlock()
				select {
				case <-ctx.Done():
					return
				case <-time.After(interval):
				}
			}
		}(name)
	}
	wg.Wait()

	var sumOK, sumAll int
	var worst string
	worstPct := 101.0
	for _, svc := range probed {
		sumOK += ok[svc]
		sumAll += total[svc]
		if total[svc] == 0 {
			continue
		}
		pct := float64(ok[svc]) / float64(total[svc]) * 100
		if pct < worstPct {
			worstPct, worst = pct, svc
		}
	}
	if sumAll == 0 {
		fmt.Printf("   disponibilité           aucun relevé\n\n")
		return nil
	}
	fmt.Printf("   disponibilité           %.1f %%   %d relevés sur %d services en %s\n",
		float64(sumOK)/float64(sumAll)*100, sumAll, len(probed), window)
	if worstPct < 100 {
		fmt.Printf("     le moins disponible : %s à %.1f %%\n", worst, worstPct)
	}
	fmt.Printf("     mesurée sur les chemins qu'emprunte un utilisateur — identité,\n")
	fmt.Printf("     collecte, inventaire, détection, réponse. Une fenêtre de %s ne dit\n", window)
	fmt.Printf("     rien d'une disponibilité annuelle : ce qui est établi est que le\n")
	fmt.Printf("     chiffre existe, se prend sur les mêmes portes qu'un client, et se\n")
	fmt.Printf("     reproduit\n\n")
	return nil
}

// incidentTimes reads the MTTD and MTTR the product computes, and says how
// many incidents they rest on.
//
// The count is not decoration. An average over four incidents is not an
// average, and publishing it without its denominator is how a KPI becomes a
// claim. What this verifies is that the computation runs end to end on real
// records — the figure itself belongs to whoever's incidents they are.
func (b *bench) incidentTimes(ctx context.Context) error {
	var d struct {
		TotalIncidents int     `json:"total_incidents"`
		AvgMTTDMinutes float64 `json:"avg_mttd_minutes"`
		AvgMTTRMinutes float64 `json:"avg_mttr_minutes"`
	}
	if err := b.admin.get(ctx, "ir", "/api/v1/ir/stats", nil, &d); err != nil {
		return fmt.Errorf("statistiques des incidents: %w", err)
	}
	fmt.Printf("   MTTD                    %.0f min   MTTR %.0f min   sur %d incidents\n",
		d.AvgMTTDMinutes, d.AvgMTTRMinutes, d.TotalIncidents)
	if d.TotalIncidents < 30 {
		fmt.Printf("     ⚠ %d incidents : la moyenne n'a pas de sens statistique. Ce que\n", d.TotalIncidents)
		fmt.Printf("     cette ligne établit est que le calcul s'exécute de bout en bout\n")
		fmt.Printf("     sur des enregistrements réels, pas que le chiffre vaille quelque\n")
		fmt.Printf("     chose. Il vaudra celui du client, sur ses incidents à lui\n")
	}
	fmt.Println()
	return nil
}

// falsePositives says what the KPI would need, because no honest number can be
// produced for it here.
func falsePositives() {
	fmt.Printf("   réduction des faux positifs   \033[33mnon mesurable en l'état\033[0m\n")
	fmt.Printf("     elle compare un taux de faux positifs à un autre, et il manque les\n")
	fmt.Printf("     deux : un corpus d'alertes étiquetées vrai/faux par quelqu'un qui\n")
	fmt.Printf("     sait, et le taux de l'outil remplacé. Aucun des deux ne se fabrique\n")
	fmt.Printf("     depuis cette machine ; les deux se collectent sur un site, pendant\n")
	fmt.Printf("     une période de double exploitation. Publier un chiffre ici serait\n")
	fmt.Printf("     l'inventer\n\n")
	return
}
