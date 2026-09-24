package labelsyncmapping

import (
	"context"
	"errors"

	"github.com/flightctl/flightctl/internal/store/labelsyncmapping"
	"github.com/google/uuid"
)

type Reconciler struct {
	store     labelsyncmapping.ReconciliationStore
	evaluator Evaluator
}

func NewReconciler(store labelsyncmapping.ReconciliationStore, evaluator Evaluator) *Reconciler {
	return &Reconciler{store: store, evaluator: evaluator}
}

func (r *Reconciler) ReconcileDeviceLabels(ctx context.Context, orgID uuid.UUID, deviceName string) (ReconciliationResult, error) {
	if r == nil || r.store == nil || r.evaluator == nil {
		return ReconciliationResult{}, errors.New("label-sync reconciler is not configured")
	}

	snapshot, err := r.store.LoadDeviceLabelReconciliationSnapshot(ctx, orgID, deviceName)
	if err != nil {
		return ReconciliationResult{}, err
	}
	desired, outcomes, err := desiredDeviceLabels(snapshot, r.evaluator)
	if err != nil {
		return ReconciliationResult{}, err
	}
	writeResult, err := r.store.ApplyDeviceLabelReconciliation(ctx, orgID, deviceName, snapshot, desired)
	if err != nil {
		return ReconciliationResult{}, err
	}
	return ReconciliationResult{LabelsChanged: writeResult.LabelsChanged, MappingOutcomes: outcomes}, nil
}

type MappingOutcome struct {
	MappingID uuid.UUID
	Err       error
}

type ReconciliationResult struct {
	LabelsChanged   bool
	MappingOutcomes []MappingOutcome
}
