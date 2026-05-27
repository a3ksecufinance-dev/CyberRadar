package service

import (
	"context"
	"fmt"
	"time"

	"github.com/cyberradar/platform/services/soar/internal/model"
	"github.com/cyberradar/platform/services/soar/internal/repository"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

// Executor runs playbooks step-by-step.
type Executor struct {
	repo   *repository.SOARRepository
	logger zerolog.Logger
}

// NewExecutor creates an Executor.
func NewExecutor(repo *repository.SOARRepository, logger zerolog.Logger) *Executor {
	return &Executor{repo: repo, logger: logger}
}

// Run executes a playbook asynchronously.
func (e *Executor) Run(ctx context.Context, tenantID uuid.UUID, pb *model.Playbook, incidentID *uuid.UUID, triggerEvent map[string]any, triggeredBy *uuid.UUID) {
	go func() {
		bgCtx := context.Background()
		if err := e.run(bgCtx, tenantID, pb, incidentID, triggerEvent, triggeredBy); err != nil {
			e.logger.Error().Err(err).Str("playbook_id", pb.ID.String()).Msg("execution_error")
		}
	}()
}

func (e *Executor) run(ctx context.Context, tenantID uuid.UUID, pb *model.Playbook, incidentID *uuid.UUID, triggerEvent map[string]any, triggeredBy *uuid.UUID) error {
	exec, err := e.repo.CreateExecution(ctx, tenantID, pb.ID, incidentID, triggerEvent, triggeredBy, len(pb.Steps))
	if err != nil {
		return fmt.Errorf("create execution: %w", err)
	}

	completed := 0
	failed := 0
	summary := map[string]any{}
	var execErr string

	for _, step := range pb.Steps {
		execStep, err := e.repo.CreateExecutionStep(ctx, exec.ID, step.ID, step.StepOrder, step.ActionType)
		if err != nil {
			e.logger.Warn().Err(err).Msg("create_exec_step_error")
			continue
		}

		output, stepErr := e.executeAction(ctx, tenantID, step, triggerEvent)

		status := "completed"
		errMsg := ""
		if stepErr != nil {
			status = "failed"
			errMsg = stepErr.Error()
			failed++
			e.logger.Warn().Err(stepErr).
				Str("execution_id", exec.ID.String()).
				Str("action_type", step.ActionType).
				Msg("step_failed")
		} else {
			completed++
		}

		_ = e.repo.UpdateExecutionStep(ctx, execStep.ID, status, output, errMsg)
		summary[fmt.Sprintf("step_%d_%s", step.StepOrder, step.ActionType)] = map[string]any{
			"status": status,
			"output": output,
		}

		// Abort on failure unless step says continue
		if stepErr != nil && step.OnFailure == model.FailureAbort {
			execErr = fmt.Sprintf("aborted at step %d (%s): %s", step.StepOrder, step.ActionType, errMsg)
			break
		}

		// Respect timeout between steps
		if step.TimeoutSec > 0 && step.ActionType == model.ActionWait {
			waitSec, _ := step.ActionParams["seconds"].(float64)
			if waitSec <= 0 {
				waitSec = float64(step.TimeoutSec)
			}
			timer := time.NewTimer(time.Duration(waitSec) * time.Second)
			select {
			case <-timer.C:
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			}
		}
	}

	finalStatus := "completed"
	if failed > 0 && execErr != "" {
		finalStatus = "failed"
	}

	return e.repo.CompleteExecution(ctx, exec.ID, finalStatus, completed, failed, summary, execErr)
}

// executeAction dispatches the action and returns output + any error.
// In production each action calls the relevant microservice via HTTP.
// Here we implement the logic gate and return structured results.
func (e *Executor) executeAction(ctx context.Context, tenantID uuid.UUID, step model.PlaybookStep, ev map[string]any) (map[string]any, error) {
	e.logger.Info().
		Str("action", step.ActionType).
		Str("step", step.Name).
		Msg("executing_action")

	switch step.ActionType {
	case model.ActionBlockIP:
		ip := resolveParam(step.ActionParams, "ip", ev, "ip_source")
		if ip == "" {
			return nil, fmt.Errorf("block_ip: no IP address provided")
		}
		return map[string]any{"action": "block_ip", "ip": ip, "status": "blocked"}, nil

	case model.ActionUnblockIP:
		ip := resolveParam(step.ActionParams, "ip", ev, "ip_source")
		return map[string]any{"action": "unblock_ip", "ip": ip, "status": "unblocked"}, nil

	case model.ActionDisableUser:
		userID := resolveParam(step.ActionParams, "user_id", ev, "user_id")
		if userID == "" {
			return nil, fmt.Errorf("disable_user: no user_id provided")
		}
		return map[string]any{"action": "disable_user", "user_id": userID, "status": "disabled"}, nil

	case model.ActionEnableUser:
		userID := resolveParam(step.ActionParams, "user_id", ev, "user_id")
		return map[string]any{"action": "enable_user", "user_id": userID, "status": "enabled"}, nil

	case model.ActionIsolateHost:
		assetID := resolveParam(step.ActionParams, "asset_id", ev, "asset_id")
		if assetID == "" {
			return nil, fmt.Errorf("isolate_host: no asset_id provided")
		}
		return map[string]any{"action": "isolate_host", "asset_id": assetID, "status": "isolated"}, nil

	case model.ActionUnisolateHost:
		assetID := resolveParam(step.ActionParams, "asset_id", ev, "asset_id")
		return map[string]any{"action": "unisolate_host", "asset_id": assetID, "status": "unisolated"}, nil

	case model.ActionEnrichIOC:
		ioc := resolveParam(step.ActionParams, "ioc_value", ev, "ioc_value")
		return map[string]any{"action": "enrich_ioc", "ioc": ioc, "status": "enriched", "threat_score": 8.5}, nil

	case model.ActionAddToBlocklist:
		ioc := resolveParam(step.ActionParams, "ioc_value", ev, "ioc_value")
		return map[string]any{"action": "add_to_blocklist", "ioc": ioc, "status": "added"}, nil

	case model.ActionCreateTicket:
		title := resolveParam(step.ActionParams, "title", ev, "title")
		return map[string]any{"action": "create_ticket", "title": title, "ticket_id": "TKT-" + uuid.New().String()[:8], "status": "created"}, nil

	case model.ActionCloseTicket:
		ticketID := resolveParam(step.ActionParams, "ticket_id", ev, "ticket_id")
		return map[string]any{"action": "close_ticket", "ticket_id": ticketID, "status": "closed"}, nil

	case model.ActionSendNotification:
		channel := resolveParam(step.ActionParams, "channel", ev, "channel")
		message := resolveParam(step.ActionParams, "message", ev, "message")
		return map[string]any{"action": "send_notification", "channel": channel, "message": message, "status": "sent"}, nil

	case model.ActionRunSIEMQuery:
		query := resolveParam(step.ActionParams, "query", ev, "query")
		return map[string]any{"action": "run_siem_query", "query": query, "result_count": 0, "status": "executed"}, nil

	case model.ActionTagEntity:
		entityID := resolveParam(step.ActionParams, "entity_id", ev, "entity_id")
		tag := resolveParam(step.ActionParams, "tag", ev, "tag")
		return map[string]any{"action": "tag_entity", "entity_id": entityID, "tag": tag, "status": "tagged"}, nil

	case model.ActionMarkCompromised:
		nodeID := resolveParam(step.ActionParams, "node_id", ev, "node_id")
		return map[string]any{"action": "mark_compromised", "node_id": nodeID, "status": "marked"}, nil

	case model.ActionCreateIncident:
		title := resolveParam(step.ActionParams, "title", ev, "title")
		severity := resolveParam(step.ActionParams, "severity", ev, "severity")
		if severity == "" {
			severity = "HIGH"
		}
		return map[string]any{"action": "create_incident", "title": title, "severity": severity, "status": "created"}, nil

	case model.ActionWait:
		return map[string]any{"action": "wait", "status": "completed"}, nil

	default:
		return nil, fmt.Errorf("unknown action type: %s", step.ActionType)
	}
}

// resolveParam returns the param value, falling back to the event field.
func resolveParam(params map[string]any, paramKey string, event map[string]any, eventKey string) string {
	if v, ok := params[paramKey].(string); ok && v != "" {
		return v
	}
	if v, ok := event[eventKey].(string); ok {
		return v
	}
	return ""
}
