package service

import (
	"context"
	"fmt"
	"time"

	"github.com/cyberradar/platform/services/soar/internal/model"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

// ExecutionStore is the part of the repository the executor needs: the record
// of what a run did. Narrowing it to these four methods is what lets the
// abort-on-failure path be tested without a database.
type ExecutionStore interface {
	CreateExecution(ctx context.Context, tenantID, playbookID uuid.UUID, incidentID *uuid.UUID, triggerEvent map[string]any, triggeredBy *uuid.UUID, stepsTotal int) (*model.Execution, error)
	CreateExecutionStep(ctx context.Context, execID, stepID uuid.UUID, stepOrder int, actionType string) (*model.ExecutionStep, error)
	UpdateExecutionStep(ctx context.Context, stepID uuid.UUID, status string, output map[string]any, errMsg string) error
	CompleteExecution(ctx context.Context, execID uuid.UUID, status string, completed, failed int, summary map[string]any, errMsg string) error
}

// Executor runs playbooks step-by-step.
type Executor struct {
	repo ExecutionStore
	// dispatcher carries out each step. Sequencing, abort-on-failure and
	// persistence stay here; what an action *does* lives behind this.
	dispatcher Dispatcher
	logger     zerolog.Logger
}

// NewExecutor creates an Executor.
func NewExecutor(repo ExecutionStore, dispatcher Dispatcher, logger zerolog.Logger) *Executor {
	return &Executor{repo: repo, dispatcher: dispatcher, logger: logger}
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

// executeAction carries out one step through the dispatcher.
func (e *Executor) executeAction(ctx context.Context, tenantID uuid.UUID, step model.PlaybookStep, ev map[string]any) (map[string]any, error) {
	e.logger.Info().
		Str("action", step.ActionType).
		Str("step", step.Name).
		Str("tenant_id", tenantID.String()).
		Msg("executing_action")

	return e.dispatcher.Do(ctx, tenantID, step, ev)
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
