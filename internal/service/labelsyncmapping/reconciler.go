package labelsyncmapping

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"strconv"

	"github.com/flightctl/flightctl/internal/domain"
	"github.com/flightctl/flightctl/internal/flterrors"
	"github.com/flightctl/flightctl/internal/store"
	labelsyncmappingstore "github.com/flightctl/flightctl/internal/store/labelsyncmapping"
	"github.com/google/uuid"
	"github.com/samber/lo"
)

// Reconciler derives the labels managed by LabelSyncMappings for one device.
// It intentionally owns only label reconciliation; deciding when each device is
// reconciled is left to the caller that consumes device and mapping changes.
type Reconciler struct {
	store     labelsyncmappingstore.Store
	evaluator Evaluator
}

func NewReconciler(store labelsyncmappingstore.Store, evaluator Evaluator) *Reconciler {
	return &Reconciler{store: store, evaluator: evaluator}
}

// Reconcile evaluates every device mapping and writes the resulting complete
// managed-label set. It returns updated=false when labels already match or when
// either compare-and-swap precondition changed while evaluating the mappings.
// Evaluation failures do not prevent independent mappings from converging: the
// prior value for the failed managed label is retained, and the failures are
// returned after the write.
func (r *Reconciler) Reconcile(ctx context.Context, orgID uuid.UUID, deviceName string) (updated bool, err error) {
	if r == nil || r.store == nil || r.evaluator == nil {
		return false, errors.New("label-sync reconciler is not configured")
	}

	device, err := r.store.GetDevice(ctx, orgID, deviceName)
	if err != nil {
		return false, err
	}
	if device == nil {
		return false, flterrors.ErrResourceNotFound
	}

	mappings, revision, stable, err := r.mappingSnapshot(ctx, orgID)
	if err != nil {
		return false, err
	}
	if !stable {
		// A mapping changed while it was being read. Do not publish a label set
		// against the newer revision when it was derived from the older mapping
		// list; the next reconciliation will obtain a consistent snapshot.
		return false, nil
	}

	labels, evaluationErr := r.labelsForDevice(device, mappings)
	if maps.Equal(lo.FromPtr(device.Metadata.Labels), labels) {
		return false, evaluationErr
	}

	resourceVersion, err := strconv.ParseInt(lo.FromPtr(device.Metadata.ResourceVersion), 10, 64)
	if err != nil {
		return false, flterrors.ErrIllegalResourceVersionFormat
	}
	updated, err = r.store.UpdateDeviceLabels(ctx, orgID, deviceName, resourceVersion, revision, labels)
	if err != nil {
		return false, err
	}
	return updated, evaluationErr
}

// mappingSnapshot verifies that the revision did not change while the mapping
// list was read. A later mapping change is still protected by the revision CAS
// in UpdateDeviceLabels.
func (r *Reconciler) mappingSnapshot(ctx context.Context, orgID uuid.UUID) (*domain.LabelSyncMappingList, int64, bool, error) {
	before, err := r.store.Revision(ctx, orgID, domain.LabelSyncMappingDevice)
	if err != nil {
		return nil, 0, false, err
	}
	mappings, err := r.store.List(ctx, orgID, store.ListParams{})
	if err != nil {
		return nil, 0, false, err
	}
	after, err := r.store.Revision(ctx, orgID, domain.LabelSyncMappingDevice)
	if err != nil {
		return nil, 0, false, err
	}
	return mappings, after, before == after, nil
}

func (r *Reconciler) labelsForDevice(device *domain.Device, mappings *domain.LabelSyncMappingList) (map[string]string, error) {
	managedKeys := make(map[string]struct{})
	derived := make(map[string]string)
	var evaluationErrs []error

	for _, mapping := range lo.FromPtr(mappings).Items {
		if mapping.Spec.ResourceType != domain.LabelSyncMappingDevice {
			continue
		}
		managedKeys[mapping.Spec.Key] = struct{}{}
		result, err := r.evaluator.Evaluate(mapping.Spec.Expression, *device)
		if err != nil {
			evaluationErrs = append(evaluationErrs, fmt.Errorf("evaluating label %q: %w", mapping.Spec.Key, err))
			if value, found := lo.FromPtr(device.Metadata.Labels)[mapping.Spec.Key]; found {
				derived[mapping.Spec.Key] = value
			}
			continue
		}
		if result.Present {
			derived[mapping.Spec.Key] = result.Value
		}
	}

	labels := make(map[string]string, len(lo.FromPtr(device.Metadata.Labels))+len(derived))
	for key, value := range lo.FromPtr(device.Metadata.Labels) {
		if _, managed := managedKeys[key]; !managed {
			labels[key] = value
		}
	}
	for key, value := range derived {
		labels[key] = value
	}
	return labels, errors.Join(evaluationErrs...)
}
