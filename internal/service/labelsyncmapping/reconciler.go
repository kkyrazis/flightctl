package labelsyncmapping

import (
	"context"
	"errors"

	"github.com/flightctl/flightctl/internal/domain"
	"github.com/flightctl/flightctl/internal/service/common"
	eventservice "github.com/flightctl/flightctl/internal/service/events"
	"github.com/flightctl/flightctl/internal/store"
	"github.com/flightctl/flightctl/internal/store/labelsyncmapping"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

const maxReconciliationAttempts = 5

type Reconciler struct {
	store     labelsyncmapping.ReconciliationStore
	evaluator Evaluator
	events    eventservice.Service
	log       logrus.FieldLogger
}

func NewReconciler(store labelsyncmapping.ReconciliationStore, evaluator Evaluator, events eventservice.Service, log logrus.FieldLogger) (*Reconciler, error) {
	if store == nil || evaluator == nil || events == nil {
		return nil, errors.New("label-sync reconciler requires a store, evaluator, and event service")
	}
	if log == nil {
		log = logrus.New()
	}
	return &Reconciler{store: store, evaluator: evaluator, events: events, log: log}, nil
}

func (r *Reconciler) ReconcileDeviceLabels(ctx context.Context, orgID uuid.UUID, deviceName string) (ReconciliationResult, error) {
	if r == nil || r.store == nil || r.evaluator == nil || r.events == nil {
		return ReconciliationResult{}, errors.New("label-sync reconciler is not configured")
	}
	// The event store does not join caller-owned transactions. Reject nested
	// reconciliation to avoid publishing an update for a label write that may
	// still be rolled back by the caller.
	if store.InTransaction(ctx) {
		return ReconciliationResult{}, errors.New("label-sync reconciliation cannot run inside an existing store transaction")
	}

	for attempt := 0; attempt < maxReconciliationAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return ReconciliationResult{}, err
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
		if err == nil {
			if writeResult.LabelsChanged {
				r.emitLabelsUpdated(ctx, orgID, deviceName)
			}
			return ReconciliationResult{LabelsChanged: writeResult.LabelsChanged, MappingOutcomes: outcomes}, nil
		}
		if !errors.Is(err, labelsyncmapping.ErrDeviceLabelReconciliationConflict) {
			return ReconciliationResult{}, err
		}
		if attempt+1 == maxReconciliationAttempts {
			return ReconciliationResult{}, err
		}
		if err := ctx.Err(); err != nil {
			return ReconciliationResult{}, err
		}
	}
	return ReconciliationResult{}, labelsyncmapping.ErrDeviceLabelReconciliationConflict
}

func (r *Reconciler) emitLabelsUpdated(ctx context.Context, orgID uuid.UUID, deviceName string) {
	updates := &domain.ResourceUpdatedDetails{
		UpdatedFields: []domain.ResourceUpdatedDetailsUpdatedFields{domain.Labels},
	}
	event := common.GetResourceCreatedOrUpdatedSuccessEvent(ctx, false, domain.DeviceKind, deviceName, updates, r.log, nil)
	if event != nil {
		r.events.CreateEvent(ctx, orgID, event)
	}
}

type MappingOutcome struct {
	MappingID uuid.UUID
	Err       error
}

type ReconciliationResult struct {
	LabelsChanged   bool
	MappingOutcomes []MappingOutcome
}
