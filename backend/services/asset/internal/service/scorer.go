package service

import (
	"math"

	"github.com/cyberradar/platform/services/asset/internal/model"
)

// ScoreAsset computes an asset's risk score under one institution's risk
// appetite, and the breakdown that explains it.
//
// The weights come from the profile because they are a judgement, not a fact:
// what a critical finding on a card-scope asset is worth is a decision a bank's
// risk function makes. The set of factors does not come from the profile, and
// that is the trade — full control over the weighting, none over the
// vocabulary, so the score stays explicable and comparable between tenants.
//
// The same arithmetic exists as an expression in the asset_risk view, which is
// what lets a hundred thousand assets be ordered and counted by risk in the
// database. asset_risk_test.go runs both over the same rows under several
// profiles and fails if they disagree.
func ScoreAsset(a *model.Asset, p *model.RiskProfile) (float64, *model.RiskBreakdown) {
	if p == nil {
		p = DefaultRiskProfile()
	}
	rb := &model.RiskBreakdown{AssetID: a.ID, Profile: p}

	// ── 1. Criticality ────────────────────────────────────────────────────────
	// The lowest tier scores nothing; each step above it is worth one step.
	critScore := math.Min(p.CriticalityCap, float64(a.Criticality-1)*p.CriticalityStep)
	rb.CriticalityScore = critScore

	if a.Criticality == model.CriticalityCritical {
		rb.Factors = append(rb.Factors, "critical asset")
	}

	// ── 2. Open findings, by severity ─────────────────────────────────────────
	vulnScore := math.Min(p.VulnCap,
		float64(a.VulnCritical)*p.VulnCritical+
			float64(a.VulnHigh)*p.VulnHigh+
			float64(a.VulnMedium)*p.VulnMedium+
			float64(a.VulnLow)*p.VulnLow)
	rb.VulnScore = vulnScore

	if a.VulnCritical > 0 {
		rb.Factors = append(rb.Factors, "critical vulnerabilities present")
	}
	if a.VulnHigh > 2 {
		rb.Factors = append(rb.Factors, "multiple high vulnerabilities")
	}

	// ── 3. Inherent exposure of a banking asset ──────────────────────────────
	var expScore float64
	if a.IsCBSConnected {
		expScore += p.CBSConnected
		rb.Factors = append(rb.Factors, "connected to CBS")
	}
	if a.IsSWIFTConnected {
		expScore += p.SWIFTConnected
		rb.Factors = append(rb.Factors, "connected to SWIFT")
	}
	if a.IsPCIScope {
		expScore += p.PCIScope
		rb.Factors = append(rb.Factors, "in PCI scope")
	}
	expScore = math.Min(p.ExposureCap, expScore)
	rb.ExposureScore = expScore

	// ── 4. Visibility ─────────────────────────────────────────────────────────
	// An asset no sensor has ever seen is unknown risk, not no risk.
	var behaviorScore float64
	if a.LastSeenAt == nil {
		behaviorScore = p.NeverSeen
		rb.Factors = append(rb.Factors, "asset never observed by sensor")
	}
	rb.BehaviorScore = behaviorScore

	// ── 5. Context ────────────────────────────────────────────────────────────
	var ctxScore float64
	if a.Environment == "production" && a.Criticality >= model.CriticalityHigh {
		ctxScore = p.CriticalProduction
		rb.Factors = append(rb.Factors, "critical production asset")
	}
	if isBankingCriticalType(a.AssetType) {
		ctxScore += p.BankingType
		rb.Factors = append(rb.Factors, "banking-critical asset type")
	}
	ctxScore = math.Min(p.ContextCap, ctxScore)
	rb.ContextScore = ctxScore

	// ── Total ─────────────────────────────────────────────────────────────────
	total := math.Min(p.TotalCap, critScore+vulnScore+expScore+behaviorScore+ctxScore)
	rb.TotalScore = total

	return total, rb
}

// DefaultRiskProfile is the standard balanced profile, in code.
//
// It exists so a caller with no database — a test, a tool — still scores, and
// so the values the platform ships are visible in one place next to the
// formula. migrations/postgres/000039 seeds the same numbers as the 'balanced'
// profile, and a test asserts the two agree: two sets of defaults that drift
// apart would mean a fresh install scoring differently from a documented one.
func DefaultRiskProfile() *model.RiskProfile {
	return &model.RiskProfile{
		Code: "balanced", Name: "Équilibré (par défaut)", Version: 1,

		CriticalityStep: 1.0, CriticalityCap: 3.0,

		VulnCritical: 2.0, VulnHigh: 1.0, VulnMedium: 0.4, VulnLow: 0.1, VulnCap: 4.0,

		CBSConnected: 1.0, SWIFTConnected: 1.0, PCIScope: 0.5, ExposureCap: 2.0,

		NeverSeen: 0.5,

		CriticalProduction: 0.5, BankingType: 0.5, ContextCap: 1.0,

		TotalCap: 10.0, HighRiskThreshold: 7.0,
	}
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
