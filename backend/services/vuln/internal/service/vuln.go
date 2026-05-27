package service

import (
	"context"

	apierrors "github.com/cyberradar/platform/internal/pkg/errors"
	"github.com/cyberradar/platform/services/vuln/internal/model"
	"github.com/cyberradar/platform/services/vuln/internal/repository"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

// VulnService orchestrates vulnerability and exposure management.
type VulnService struct {
	repo   *repository.VulnRepository
	logger zerolog.Logger
}

// NewVulnService creates a VulnService.
func NewVulnService(repo *repository.VulnRepository, logger zerolog.Logger) *VulnService {
	return &VulnService{repo: repo, logger: logger}
}

// ─── Vulnerabilities ──────────────────────────────────────────────────────────

func (s *VulnService) CreateVuln(ctx context.Context, tenantID uuid.UUID, req *model.CreateVulnRequest) (*model.Vulnerability, error) {
	v, err := s.repo.UpsertVuln(ctx, tenantID, req)
	if err != nil {
		return nil, apierrors.Internal("create vuln", err)
	}
	s.logger.Info().Str("vuln_id", v.ID.String()).Str("cve", v.CVEID).Str("severity", v.CVSSSeverity).Msg("vuln_created")
	return v, nil
}

func (s *VulnService) GetVuln(ctx context.Context, tenantID, vulnID uuid.UUID) (*model.Vulnerability, error) {
	v, err := s.repo.GetVuln(ctx, tenantID, vulnID)
	if err != nil {
		return nil, apierrors.Internal("get vuln", err)
	}
	if v == nil {
		return nil, apierrors.New(apierrors.KindNotFound, "vulnerability not found")
	}
	return v, nil
}

func (s *VulnService) ListVulns(ctx context.Context, f model.VulnFilter) ([]*model.Vulnerability, int, error) {
	vulns, total, err := s.repo.ListVulns(ctx, f)
	if err != nil {
		return nil, 0, apierrors.Internal("list vulns", err)
	}
	return vulns, total, nil
}

// ─── Findings ─────────────────────────────────────────────────────────────────

func (s *VulnService) CreateFinding(ctx context.Context, tenantID uuid.UUID, req *model.CreateFindingRequest) (*model.AssetVulnerability, error) {
	// Load CVSS from the vuln definition to compute exposure
	v, err := s.repo.GetVuln(ctx, tenantID, req.VulnID)
	if err != nil || v == nil {
		return nil, apierrors.Wrap(apierrors.KindNotFound, "vulnerability not found", err)
	}
	av, err := s.repo.UpsertFinding(ctx, tenantID, req, v.CVSSScore, v.CVSSSeverity)
	if err != nil {
		return nil, apierrors.Internal("create finding", err)
	}
	av.Vulnerability = v
	return av, nil
}

func (s *VulnService) BulkCreateFindings(ctx context.Context, tenantID uuid.UUID, req *model.BulkCreateFindingsRequest) (int, error) {
	count := 0
	for i := range req.Findings {
		item := &req.Findings[i]
		if req.ScanJobID != nil && item.ScanJobID == nil {
			item.ScanJobID = req.ScanJobID
		}
		v, err := s.repo.GetVuln(ctx, tenantID, item.VulnID)
		if err != nil || v == nil {
			s.logger.Warn().Str("vuln_id", item.VulnID.String()).Msg("bulk_finding_vuln_not_found")
			continue
		}
		if _, err := s.repo.UpsertFinding(ctx, tenantID, item, v.CVSSScore, v.CVSSSeverity); err != nil {
			s.logger.Error().Err(err).Str("asset_id", item.AssetID.String()).Msg("bulk_finding_error")
			continue
		}
		count++
	}
	return count, nil
}

func (s *VulnService) ListFindings(ctx context.Context, f model.FindingFilter) ([]*model.AssetVulnerability, int, error) {
	findings, total, err := s.repo.ListFindings(ctx, f)
	if err != nil {
		return nil, 0, apierrors.Internal("list findings", err)
	}
	return findings, total, nil
}

func (s *VulnService) UpdateFinding(ctx context.Context, tenantID, findingID uuid.UUID, req *model.UpdateFindingRequest) (*model.AssetVulnerability, error) {
	av, err := s.repo.UpdateFinding(ctx, tenantID, findingID, req)
	if err != nil {
		return nil, apierrors.Internal("update finding", err)
	}
	if av == nil {
		return nil, apierrors.New(apierrors.KindNotFound, "finding not found")
	}
	return av, nil
}

func (s *VulnService) GetAssetExposure(ctx context.Context, tenantID, assetID uuid.UUID) (*model.ExposureScore, error) {
	es, err := s.repo.AssetExposure(ctx, tenantID, assetID)
	if err != nil {
		return nil, apierrors.Internal("asset exposure", err)
	}
	return es, nil
}

// ─── Scan Jobs ────────────────────────────────────────────────────────────────

func (s *VulnService) CreateScanJob(ctx context.Context, tenantID uuid.UUID, callerID *uuid.UUID, req *model.CreateScanJobRequest) (*model.ScanJob, error) {
	job, err := s.repo.CreateScanJob(ctx, tenantID, callerID, req)
	if err != nil {
		return nil, apierrors.Internal("create scan job", err)
	}
	s.logger.Info().Str("job_id", job.ID.String()).Str("type", job.ScanType).Msg("scan_job_created")
	return job, nil
}

func (s *VulnService) ListScanJobs(ctx context.Context, tenantID uuid.UUID, status string, limit int) ([]*model.ScanJob, error) {
	jobs, err := s.repo.ListScanJobs(ctx, tenantID, status, limit)
	if err != nil {
		return nil, apierrors.Internal("list scan jobs", err)
	}
	return jobs, nil
}

// ─── Remediation Tickets ──────────────────────────────────────────────────────

func (s *VulnService) CreateTicket(ctx context.Context, tenantID uuid.UUID, callerID *uuid.UUID, req *model.CreateTicketRequest) (*model.RemediationTicket, error) {
	t, err := s.repo.CreateTicket(ctx, tenantID, callerID, req)
	if err != nil {
		return nil, apierrors.Internal("create ticket", err)
	}
	s.logger.Info().Str("ticket_id", t.ID.String()).Str("title", t.Title).Msg("remediation_ticket_created")
	return t, nil
}

func (s *VulnService) ListTickets(ctx context.Context, tenantID uuid.UUID, status string, limit, offset int) ([]*model.RemediationTicket, int, error) {
	tickets, total, err := s.repo.ListTickets(ctx, tenantID, status, limit, offset)
	if err != nil {
		return nil, 0, apierrors.Internal("list tickets", err)
	}
	return tickets, total, nil
}

func (s *VulnService) UpdateTicket(ctx context.Context, tenantID, ticketID uuid.UUID, req *model.UpdateTicketRequest) (*model.RemediationTicket, error) {
	t, err := s.repo.UpdateTicket(ctx, tenantID, ticketID, req)
	if err != nil {
		return nil, apierrors.Internal("update ticket", err)
	}
	if t == nil {
		return nil, apierrors.New(apierrors.KindNotFound, "ticket not found")
	}
	return t, nil
}

// ─── Stats ────────────────────────────────────────────────────────────────────

func (s *VulnService) GetStats(ctx context.Context, tenantID uuid.UUID) (*model.VulnStats, error) {
	stats, err := s.repo.Stats(ctx, tenantID)
	if err != nil {
		return nil, apierrors.Internal("vuln stats", err)
	}
	return stats, nil
}
