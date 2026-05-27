package service

import (
	"context"
	"strings"
	"time"
	"fmt"
	"unicode/utf8"

	apierrors "github.com/cyberradar/platform/internal/pkg/errors"
	"github.com/cyberradar/platform/services/copilot/internal/model"
	"github.com/cyberradar/platform/services/copilot/internal/repository"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

// CopilotService orchestrates sessions, chat, and hunt jobs.
type CopilotService struct {
	repo   *repository.CopilotRepository
	llm    *LLMClient
	logger zerolog.Logger
}

// NewCopilotService creates a CopilotService.
func NewCopilotService(repo *repository.CopilotRepository, llm *LLMClient, logger zerolog.Logger) *CopilotService {
	return &CopilotService{repo: repo, llm: llm, logger: logger}
}

// ─── Sessions ─────────────────────────────────────────────────────────────────

func (s *CopilotService) CreateSession(ctx context.Context, tenantID, userID uuid.UUID, req *model.CreateSessionRequest) (*model.Session, error) {
	session, err := s.repo.CreateSession(ctx, tenantID, userID, req)
	if err != nil {
		return nil, apierrors.Internal("create session", err)
	}
	return session, nil
}

func (s *CopilotService) GetSession(ctx context.Context, tenantID, sessionID uuid.UUID) (*model.Session, error) {
	session, err := s.repo.GetSession(ctx, tenantID, sessionID)
	if err != nil {
		return nil, apierrors.Internal("get session", err)
	}
	if session == nil {
		return nil, apierrors.New(apierrors.KindNotFound, "session not found")
	}
	return session, nil
}

func (s *CopilotService) CloseSession(ctx context.Context, tenantID, sessionID uuid.UUID) error {
	if err := s.repo.CloseSession(ctx, tenantID, sessionID); err != nil {
		return apierrors.Internal("close session", err)
	}
	return nil
}

func (s *CopilotService) ListSessions(ctx context.Context, f model.SessionFilter) ([]*model.Session, int, error) {
	sessions, total, err := s.repo.ListSessions(ctx, f)
	if err != nil {
		return nil, 0, apierrors.Internal("list sessions", err)
	}
	return sessions, total, nil
}

func (s *CopilotService) GetHistory(ctx context.Context, tenantID, sessionID uuid.UUID, limit int) ([]*model.Message, error) {
	msgs, err := s.repo.GetHistory(ctx, tenantID, sessionID, limit)
	if err != nil {
		return nil, apierrors.Internal("get history", err)
	}
	return msgs, nil
}

// ─── Chat ─────────────────────────────────────────────────────────────────────

// Chat sends a user message, calls Claude (with tool use), persists all turns,
// and returns the final assistant message.
func (s *CopilotService) Chat(ctx context.Context, tenantID, userID, sessionID uuid.UUID, req *model.SendMessageRequest) (*model.Message, error) {
	// Confirm session ownership
	session, err := s.GetSession(ctx, tenantID, sessionID)
	if err != nil {
		return nil, err
	}
	if !session.IsActive {
		return nil, apierrors.New(apierrors.KindBadInput, "session is closed")
	}

	// Load recent history for context (last 20 messages)
	history, err := s.repo.GetHistory(ctx, tenantID, sessionID, 20)
	if err != nil {
		s.logger.Warn().Err(err).Msg("chat_history_load_error")
		history = nil
	}

	// Persist user message
	userMsg := &model.Message{
		SessionID: sessionID,
		TenantID:  tenantID,
		Role:      model.RoleUser,
		Content:   req.Content,
	}
	if _, err := s.repo.SaveMessage(ctx, userMsg); err != nil {
		return nil, apierrors.Internal("save user message", err)
	}
	_ = s.repo.TouchSession(ctx, sessionID)

	// Auto-generate session title from first user message
	if session.MessageCount == 0 {
		title := truncate(req.Content, 60)
		_ = s.repo.UpdateSessionTitle(ctx, sessionID, title)
	}

	// Call LLM with agentic tool loop
	start := time.Now()
	resp, err := s.llm.Chat(ctx, tenantID, history, req.Content)
	if err != nil {
		s.logger.Error().Err(err).Str("session_id", sessionID.String()).Msg("llm_chat_error")
		return nil, apierrors.Internal("llm chat", err)
	}
	latencyMS := int(time.Since(start).Milliseconds())

	// Extract text content from response
	var textContent strings.Builder
	for _, block := range resp.Content {
		if block.Type == "text" {
			textContent.WriteString(block.Text)
		}
	}

	// Persist assistant message
	assistantMsg := &model.Message{
		SessionID:    sessionID,
		TenantID:     tenantID,
		Role:         model.RoleAssistant,
		Content:      textContent.String(),
		InputTokens:  resp.Usage.InputTokens,
		OutputTokens: resp.Usage.OutputTokens,
		LatencyMS:    latencyMS,
	}
	saved, err := s.repo.SaveMessage(ctx, assistantMsg)
	if err != nil {
		return nil, apierrors.Internal("save assistant message", err)
	}
	_ = s.repo.TouchSession(ctx, sessionID)

	s.logger.Info().
		Str("session_id", sessionID.String()).
		Int("input_tokens", resp.Usage.InputTokens).
		Int("output_tokens", resp.Usage.OutputTokens).
		Int("latency_ms", latencyMS).
		Msg("chat_completed")

	return saved, nil
}

// ─── Hunt Jobs ────────────────────────────────────────────────────────────────

// CreateHuntJob creates a job and fires it asynchronously.
func (s *CopilotService) CreateHuntJob(ctx context.Context, tenantID, userID uuid.UUID, req *model.CreateHuntJobRequest) (*model.HuntJob, error) {
	job, err := s.repo.CreateHuntJob(ctx, tenantID, userID, req)
	if err != nil {
		return nil, apierrors.Internal("create hunt job", err)
	}

	// Run asynchronously
	go s.runHuntJob(context.Background(), tenantID, job, req.Context)
	return job, nil
}

func (s *CopilotService) runHuntJob(ctx context.Context, tenantID uuid.UUID, job *model.HuntJob, extraCtx map[string]any) {
	_ = s.repo.UpdateHuntJob(ctx, job.ID, "running", "", "", nil, 0, 0)

	// Build a structured prompt for the hunt type
	prompt := buildHuntPrompt(job.HuntType, job.Query, extraCtx)

	start := time.Now()
	resp, err := s.llm.Analyze(ctx, tenantID, prompt)
	if err != nil {
		s.logger.Error().Err(err).Str("job_id", job.ID.String()).Msg("hunt_job_llm_error")
		_ = s.repo.UpdateHuntJob(ctx, job.ID, "failed", "", err.Error(), nil, 0, 0)
		return
	}

	// Extract text
	var sb strings.Builder
	for _, block := range resp.Content {
		if block.Type == "text" {
			sb.WriteString(block.Text)
		}
	}
	summary := sb.String()
	latencyMS := int(time.Since(start).Milliseconds())

	payload := map[string]any{
		"hunt_type":    job.HuntType,
		"query":        job.Query,
		"summary":      summary,
		"latency_ms":   latencyMS,
		"stop_reason":  resp.StopReason,
	}

	_ = s.repo.UpdateHuntJob(ctx, job.ID, "completed", truncate(summary, 500), "",
		payload, resp.Usage.InputTokens, resp.Usage.OutputTokens)

	s.logger.Info().
		Str("job_id", job.ID.String()).
		Str("hunt_type", job.HuntType).
		Int("input_tokens", resp.Usage.InputTokens).
		Int("output_tokens", resp.Usage.OutputTokens).
		Msg("hunt_job_completed")
}

func (s *CopilotService) GetHuntJob(ctx context.Context, tenantID, jobID uuid.UUID) (*model.HuntJob, error) {
	job, err := s.repo.GetHuntJob(ctx, tenantID, jobID)
	if err != nil {
		return nil, apierrors.Internal("get hunt job", err)
	}
	if job == nil {
		return nil, apierrors.New(apierrors.KindNotFound, "hunt job not found")
	}
	return job, nil
}

func (s *CopilotService) ListHuntJobs(ctx context.Context, tenantID, userID uuid.UUID, limit, offset int) ([]*model.HuntJob, int, error) {
	jobs, total, err := s.repo.ListHuntJobs(ctx, tenantID, userID, limit, offset)
	if err != nil {
		return nil, 0, apierrors.Internal("list hunt jobs", err)
	}
	return jobs, total, nil
}

// ─── Stats ────────────────────────────────────────────────────────────────────

func (s *CopilotService) GetStats(ctx context.Context, tenantID uuid.UUID) (*model.CopilotStats, error) {
	stats, err := s.repo.Stats(ctx, tenantID)
	if err != nil {
		return nil, apierrors.Internal("copilot stats", err)
	}
	return stats, nil
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func truncate(s string, maxRunes int) string {
	if utf8.RuneCountInString(s) <= maxRunes {
		return s
	}
	runes := []rune(s)
	return string(runes[:maxRunes]) + "…"
}

func buildHuntPrompt(huntType, query string, ctx map[string]any) string {
	base := map[string]string{
		model.HuntTypeThreatHunt:        "Conduct a comprehensive threat hunt based on the following hypothesis. Use available tools to query alerts, anomalies, and IOCs. Correlate findings and provide a structured report with: (1) Executive Summary, (2) Findings, (3) Risk Assessment, (4) Recommended Actions.",
		model.HuntTypeIncidentTriage:    "Perform AI-assisted incident triage. Query the incident details, related alerts, affected assets, and IOCs. Provide: (1) Incident Overview, (2) Attack Timeline, (3) Scope Assessment, (4) Immediate Actions, (5) Evidence Summary.",
		model.HuntTypeVulnPrioritization: "Analyze the vulnerability landscape and provide a prioritized remediation roadmap. Consider CVSS scores, EPSS, KEV status, and asset criticality. Output: (1) Critical Path, (2) Priority Matrix, (3) Quick Wins (patch within 24h), (4) Risk Acceptance Candidates.",
		model.HuntTypeAttackPathSummary: "Analyze attack path scenarios and identify the most critical lateral movement risks. Query choke points and provide: (1) Highest-Risk Paths, (2) Choke Point Recommendations, (3) Network Segmentation Gaps, (4) Remediation Priority.",
		model.HuntTypeIOCCorrelation:    "Perform IOC correlation and threat actor attribution. Look up the provided indicators and find related entities in the knowledge graph. Provide: (1) IOC Profile, (2) Related Indicators, (3) Threat Actor Attribution, (4) Exposure Assessment.",
		model.HuntTypeEntityProfiling:   "Build a comprehensive security profile for the specified entity. Query behavioral baselines, anomaly history, vulnerability exposure, and graph relationships. Output: (1) Entity Overview, (2) Risk Profile, (3) Anomaly History, (4) Recommendations.",
	}

	instruction := base[huntType]
	if instruction == "" {
		instruction = "Analyze the following security query and provide a structured assessment using available platform tools."
	}

	prompt := instruction + "\n\nQuery: " + query
	if len(ctx) > 0 {
		prompt += "\n\nAdditional context: "
		for k, v := range ctx {
			prompt += k + "=" + truncate(strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(fmt.Sprintf("%v", v), "\n", " "), "\r", "")), 200) + " "
		}
	}
	return prompt
}
