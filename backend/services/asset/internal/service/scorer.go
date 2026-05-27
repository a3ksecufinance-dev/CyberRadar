package service

import "github.com/cyberradar/platform/services/asset/internal/model"

// ScoreAsset computes a 0–10 risk score for an asset based on multiple factors.
// Formula: weighted sum of 5 dimensions, capped at 10.
func ScoreAsset(a *model.Asset) (float64, *model.RiskBreakdown) {
	rb := &model.RiskBreakdown{AssetID: a.ID}

	// ── 1. Criticality (0–3) ──────────────────────────────────────────────────
	// Maps criticality 1-4 → 0, 1, 2, 3
	critScore := float64(a.Criticality-1) * 1.0
	rb.CriticalityScore = critScore

	if a.Criticality == model.CriticalityCritical {
		rb.Factors = append(rb.Factors, "critical asset")
	}

	// ── 2. Vulnerability score (0–4) ──────────────────────────────────────────
	vulnScore := float64(a.VulnCritical)*2.0 +
		float64(a.VulnHigh)*1.0 +
		float64(a.VulnMedium)*0.4 +
		float64(a.VulnLow)*0.1
	if vulnScore > 4.0 {
		vulnScore = 4.0
	}
	rb.VulnScore = vulnScore

	if a.VulnCritical > 0 {
		rb.Factors = append(rb.Factors, "critical vulnerabilities present")
	}
	if a.VulnHigh > 2 {
		rb.Factors = append(rb.Factors, "multiple high vulnerabilities")
	}

	// ── 3. Exposure score (0–2) ──────────────────────────────────────────────
	// Banking-native assets and PCI-scope assets face higher inherent exposure.
	var expScore float64
	if a.IsCBSConnected {
		expScore += 1.0
		rb.Factors = append(rb.Factors, "connected to CBS")
	}
	if a.IsSWIFTConnected {
		expScore += 1.0
		rb.Factors = append(rb.Factors, "connected to SWIFT")
	}
	if a.IsPCIScope {
		expScore += 0.5
		rb.Factors = append(rb.Factors, "in PCI scope")
	}
	if expScore > 2.0 {
		expScore = 2.0
	}
	rb.ExposureScore = expScore

	// ── 4. Staleness / visibility (0–1) ───────────────────────────────────────
	// Assets never seen by any sensor are unknown risk — add penalty.
	var behaviorScore float64
	if a.LastSeenAt == nil {
		behaviorScore = 0.5
		rb.Factors = append(rb.Factors, "asset never observed by sensor")
	}
	rb.BehaviorScore = behaviorScore

	// ── 5. Context (0–1): production + critical type ──────────────────────────
	var ctxScore float64
	if a.Environment == "production" && a.Criticality >= model.CriticalityHigh {
		ctxScore = 0.5
		rb.Factors = append(rb.Factors, "critical production asset")
	}
	if isBankingCriticalType(a.AssetType) {
		ctxScore += 0.5
		rb.Factors = append(rb.Factors, "banking-critical asset type")
	}
	if ctxScore > 1.0 {
		ctxScore = 1.0
	}
	rb.ContextScore = ctxScore

	// ── Total ─────────────────────────────────────────────────────────────────
	total := critScore + vulnScore + expScore + behaviorScore + ctxScore
	if total > 10.0 {
		total = 10.0
	}
	rb.TotalScore = total

	return total, rb
}

func isBankingCriticalType(t model.AssetType) bool {
	switch t {
	case model.AssetTypeCBSServer,
		model.AssetTypeATM,
		model.AssetTypeSWIFTGateway,
		model.AssetTypePaymentTerminal,
		model.AssetTypeMonetique,
		model.AssetTypeHSM:
		return true
	}
	return false
}
