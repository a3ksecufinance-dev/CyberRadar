package service

import (
	"context"
	"errors"
	"testing"

	"github.com/cyberradar/platform/services/soar/internal/model"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

// recordingStore keeps a run's outcome in memory.
type recordingStore struct {
	steps      []string // "<action>:<status>"
	finalState string
	finalErr   string
	completed  int
	failed     int
}

func (s *recordingStore) CreateExecution(_ context.Context, tenantID, playbookID uuid.UUID, _ *uuid.UUID, _ map[string]any, _ *uuid.UUID, _ int) (*model.Execution, error) {
	return &model.Execution{ID: uuid.New(), TenantID: tenantID, PlaybookID: playbookID}, nil
}

func (s *recordingStore) CreateExecutionStep(_ context.Context, _, _ uuid.UUID, _ int, actionType string) (*model.ExecutionStep, error) {
	return &model.ExecutionStep{ID: uuid.New(), ActionType: actionType}, nil
}

func (s *recordingStore) UpdateExecutionStep(_ context.Context, _ uuid.UUID, status string, _ map[string]any, _ string) error {
	s.steps = append(s.steps, status)
	return nil
}

func (s *recordingStore) CompleteExecution(_ context.Context, _ uuid.UUID, status string, completed, failed int, _ map[string]any, errMsg string) error {
	s.finalState, s.completed, s.failed, s.finalErr = status, completed, failed, errMsg
	return nil
}

// scriptedDispatcher fails the actions named, and succeeds at the rest.
type scriptedDispatcher struct {
	failOn map[string]bool
	calls  []string
}

func (d *scriptedDispatcher) Do(_ context.Context, _ uuid.UUID, step model.PlaybookStep, _ map[string]any) (map[string]any, error) {
	d.calls = append(d.calls, step.ActionType)
	if d.failOn[step.ActionType] {
		return nil, errors.New("the target service refused")
	}
	return map[string]any{"service": "stub", "status": 200}, nil
}

func playbook(actions ...string) *model.Playbook {
	pb := &model.Playbook{ID: uuid.New()}
	for i, a := range actions {
		pb.Steps = append(pb.Steps, model.PlaybookStep{
			ID: uuid.New(), StepOrder: i + 1, Name: a, ActionType: a,
			OnFailure: model.FailureAbort,
		})
	}
	return pb
}

func runPlaybook(t *testing.T, pb *model.Playbook, d *scriptedDispatcher) *recordingStore {
	t.Helper()
	store := &recordingStore{}
	e := NewExecutor(store, d, zerolog.Nop())
	if err := e.run(context.Background(), uuid.New(), pb, nil, nil, nil); err != nil {
		t.Fatalf("run: %v", err)
	}
	return store
}

func TestAbortOnFailureStopsThePlaybook(t *testing.T) {
	// This was unreachable until now, not because the check was wrong but
	// because no step could fail: every action returned a fixed success map
	// without contacting anything. A containment playbook would report
	// "blocked, isolated, notified" having done none of it.
	d := &scriptedDispatcher{failOn: map[string]bool{model.ActionIsolateHost: true}}
	store := runPlaybook(t, playbook(
		model.ActionBlockIP, model.ActionIsolateHost, model.ActionSendNotification), d)

	if len(d.calls) != 2 {
		t.Errorf("dispatched %v, want the run to stop at the failing step", d.calls)
	}
	if store.finalState != "failed" {
		t.Errorf("execution status = %q, want failed", store.finalState)
	}
	if store.finalErr == "" {
		t.Error("the execution record carries no reason for the abort")
	}
	if store.completed != 1 || store.failed != 1 {
		t.Errorf("completed=%d failed=%d, want 1 and 1", store.completed, store.failed)
	}
}

func TestContinueOnFailureRunsTheRestOfThePlaybook(t *testing.T) {
	// Notifying the SOC should still happen when containment failed — that is
	// exactly when someone needs to hear about it.
	pb := playbook(model.ActionBlockIP, model.ActionSendNotification)
	pb.Steps[0].OnFailure = model.FailureContinue

	d := &scriptedDispatcher{failOn: map[string]bool{model.ActionBlockIP: true}}
	store := runPlaybook(t, pb, d)

	if len(d.calls) != 2 {
		t.Errorf("dispatched %v, want both steps", d.calls)
	}
	if store.completed != 1 || store.failed != 1 {
		t.Errorf("completed=%d failed=%d, want 1 and 1", store.completed, store.failed)
	}
}

func TestAPlaybookThatSucceedsIsRecordedAsCompleted(t *testing.T) {
	d := &scriptedDispatcher{failOn: map[string]bool{}}
	store := runPlaybook(t, playbook(model.ActionBlockIP, model.ActionSendNotification), d)

	if store.finalState != "completed" {
		t.Errorf("execution status = %q, want completed", store.finalState)
	}
	if store.failed != 0 {
		t.Errorf("failed = %d, want 0", store.failed)
	}
}
