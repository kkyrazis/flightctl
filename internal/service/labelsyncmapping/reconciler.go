package labelsyncmapping

import (
	"context"
	"errors"
	"fmt"

	"github.com/flightctl/flightctl/internal/domain"
	"github.com/flightctl/flightctl/internal/service/common"
	eventservice "github.com/flightctl/flightctl/internal/service/events"
	"github.com/flightctl/flightctl/internal/store"
	"github.com/flightctl/flightctl/internal/store/labelsyncmapping"
	"github.com/google/uuid"
	"github.com/samber/lo"
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

	for attempt := range maxReconciliationAttempts {
		if err := ctx.Err(); err != nil {
			return ReconciliationResult{}, err
		}

		snapshot, err := r.store.LoadDeviceLabelReconciliationSnapshot(ctx, orgID, deviceName)
		if err != nil {
			return ReconciliationResult{}, err
		}
		desired, outcomes, err := desiredDeviceLabels(snapshot, r.evaluator)
		if err != nil {
			return ReconciliationResult{MappingOutcomes: failedDeviceOutcomes(snapshot.Mappings, nil, err)}, err
		}

		writeResult, err := r.store.ApplyDeviceLabelReconciliation(ctx, orgID, deviceName, snapshot, desired)
		if err == nil {
			if writeResult.LabelsChanged {
				r.emitLabelsUpdated(ctx, orgID, deviceName)
			}
			return ReconciliationResult{LabelsChanged: writeResult.LabelsChanged, MappingOutcomes: outcomes}, nil
		}
		if !errors.Is(err, labelsyncmapping.ErrDeviceLabelReconciliationConflict) {
			return ReconciliationResult{MappingOutcomes: failedDeviceOutcomes(snapshot.Mappings, outcomes, err)}, err
		}
		if attempt+1 == maxReconciliationAttempts {
			return ReconciliationResult{MappingOutcomes: failedDeviceOutcomes(snapshot.Mappings, outcomes, err)}, err
		}
		if err := ctx.Err(); err != nil {
			return ReconciliationResult{}, err
		}
	}
	return ReconciliationResult{}, labelsyncmapping.ErrDeviceLabelReconciliationConflict
}

func failedDeviceOutcomes(mappings []labelsyncmapping.ReconciliationMapping, current []MappingOutcome, err error) []MappingOutcome {
	byID := make(map[uuid.UUID]MappingOutcome, len(current))
	for _, outcome := range current {
		byID[outcome.MappingID] = outcome
	}
	outcomes := make([]MappingOutcome, 0, len(mappings))
	for _, mapping := range mappings {
		if mapping.Mapping.Spec.ResourceType != domain.LabelSyncMappingDevice {
			continue
		}
		outcome := byID[mapping.ID]
		outcome.MappingID = mapping.ID
		outcome.Generation = lo.FromPtr(mapping.Mapping.Metadata.Generation)
		outcome.DeletionRevision = mapping.DeletionRevision
		outcome.Err = errors.Join(outcome.Err, err)
		outcomes = append(outcomes, outcome)
	}
	return outcomes
}

func (r *Reconciler) RecordFailures(ctx context.Context, orgID uuid.UUID, outcomes []MappingOutcome) error {
	if r == nil || r.store == nil {
		return errors.New("label-sync reconciler is not configured")
	}
	var recordErrors []error
	for _, outcome := range outcomes {
		if outcome.Err == nil {
			continue
		}
		if err := ctx.Err(); err != nil {
			recordErrors = append(recordErrors, err)
			break
		}
		_, err := r.store.RecordReconciliationFailure(ctx, orgID, labelsyncmapping.ReconciliationFailure{
			MappingID:        outcome.MappingID,
			Generation:       outcome.Generation,
			DeletionRevision: outcome.DeletionRevision,
			Message:          outcome.Err.Error(),
		})
		if err != nil {
			recordErrors = append(recordErrors, fmt.Errorf("record reconciliation failure for mapping %s: %w", outcome.MappingID, err))
		}
	}
	return errors.Join(recordErrors...)
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
	MappingID        uuid.UUID
	Generation       int64
	DeletionRevision *int64
	Err              error
}

type ReconciliationResult struct {
	LabelsChanged   bool
	MappingOutcomes []MappingOutcome
}
