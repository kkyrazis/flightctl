package labelsyncmapping

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"testing"

	"github.com/flightctl/flightctl/api/core/v1beta1"
	"github.com/flightctl/flightctl/internal/domain"
	"github.com/flightctl/flightctl/internal/flterrors"
	"github.com/flightctl/flightctl/internal/store"
	labelsyncmappingstore "github.com/flightctl/flightctl/internal/store/labelsyncmapping"
	"github.com/google/uuid"
	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type reconcilerStore struct {
	labelsyncmappingstore.Store
	device          *domain.Device
	mappings        domain.LabelSyncMappingList
	revision        int64
	revisions       []int64
	revisionCalls   int
	updateCalls     int
	updatedLabels   map[string]string
	resourceVersion int64
	updatedRevision int64
	conflict        bool
}

func (s *reconcilerStore) GetDevice(_ context.Context, _ uuid.UUID, _ string) (*domain.Device, error) {
	if s.device == nil {
		return nil, flterrors.ErrResourceNotFound
	}
	return s.device, nil
}

func (s *reconcilerStore) List(context.Context, uuid.UUID, store.ListParams) (*domain.LabelSyncMappingList, error) {
	return &s.mappings, nil
}

func (s *reconcilerStore) Revision(context.Context, uuid.UUID, domain.LabelSyncMappingResourceType) (int64, error) {
	if len(s.revisions) > 0 {
		index := min(s.revisionCalls, len(s.revisions)-1)
		s.revisionCalls++
		return s.revisions[index], nil
	}
	return s.revision, nil
}

func (s *reconcilerStore) UpdateDeviceLabels(_ context.Context, _ uuid.UUID, _ string, resourceVersion, revision int64, labels map[string]string) (bool, error) {
	s.updateCalls++
	s.resourceVersion = resourceVersion
	s.updatedRevision = revision
	s.updatedLabels = maps.Clone(labels)
	if s.conflict {
		return false, nil
	}
	s.device.Metadata.Labels = lo.ToPtr(maps.Clone(labels))
	s.device.Metadata.ResourceVersion = lo.ToPtr(fmt.Sprintf("%d", resourceVersion+1))
	return true, nil
}

type evaluatorResult struct {
	result Result
	err    error
}

type fakeEvaluator map[string]evaluatorResult

func (e fakeEvaluator) Evaluate(expression string, _ v1beta1.Device) (Result, error) {
	result := e[expression]
	return result.result, result.err
}

func labelMapping(key, expression string) domain.LabelSyncMapping {
	return domain.LabelSyncMapping{
		Spec: domain.LabelSyncMappingSpec{
			ResourceType: domain.LabelSyncMappingDevice,
			Key:          key,
			Expression:   expression,
		},
	}
}

func TestReconcilerReconcile(t *testing.T) {
	orgID := uuid.New()
	deviceName := "edge-0"

	t.Run("When mappings return values, nulls, and failures it should write the complete managed-label set", func(t *testing.T) {
		labels := map[string]string{
			"manual":       "preserved",
			"architecture": "stale",
			"model":        "stale",
			"serial":       "stale",
		}
		device := &domain.Device{Metadata: domain.ObjectMeta{
			Name:            lo.ToPtr(deviceName),
			Labels:          &labels,
			ResourceVersion: lo.ToPtr("12"),
		}}
		state := &reconcilerStore{
			device: device,
			mappings: domain.LabelSyncMappingList{Items: []domain.LabelSyncMapping{
				labelMapping("architecture", "architecture"),
				labelMapping("model", "model"),
				labelMapping("serial", "serial"),
			}},
			revision: 9,
		}
		reconciler := NewReconciler(state, fakeEvaluator{
			"architecture": {result: Result{Present: true, Value: "x86_64"}},
			"model":        {}, // CEL null and missing values remove their managed label.
			"serial":       {err: errors.New("source unavailable")},
		})

		updated, err := reconciler.Reconcile(context.Background(), orgID, deviceName)

		assert.True(t, updated)
		require.ErrorContains(t, err, `evaluating label "serial"`)
		assert.Equal(t, 1, state.updateCalls)
		assert.EqualValues(t, 12, state.resourceVersion)
		assert.EqualValues(t, 9, state.updatedRevision)
		assert.Equal(t, map[string]string{"manual": "preserved", "architecture": "x86_64", "serial": "stale"}, state.updatedLabels)

		updated, err = reconciler.Reconcile(context.Background(), orgID, deviceName)

		assert.False(t, updated)
		require.ErrorContains(t, err, `evaluating label "serial"`)
		assert.Equal(t, 1, state.updateCalls, "a repeated reconciliation must not write unchanged labels")
	})

	t.Run("When a device or mapping changes during evaluation it should leave the stale result unwritten", func(t *testing.T) {
		labels := map[string]string{"architecture": "stale"}
		state := &reconcilerStore{
			device: &domain.Device{Metadata: domain.ObjectMeta{
				Name:            lo.ToPtr(deviceName),
				Labels:          &labels,
				ResourceVersion: lo.ToPtr("4"),
			}},
			mappings: domain.LabelSyncMappingList{Items: []domain.LabelSyncMapping{labelMapping("architecture", "architecture")}},
			revision: 3,
			conflict: true,
		}
		reconciler := NewReconciler(state, fakeEvaluator{
			"architecture": {result: Result{Present: true, Value: "aarch64"}},
		})

		updated, err := reconciler.Reconcile(context.Background(), orgID, deviceName)

		require.NoError(t, err)
		assert.False(t, updated)
		assert.Equal(t, 1, state.updateCalls)
		assert.EqualValues(t, 4, state.resourceVersion)
		assert.EqualValues(t, 3, state.updatedRevision)
		assert.Equal(t, map[string]string{"architecture": "stale"}, lo.FromPtr(state.device.Metadata.Labels))
	})

	t.Run("When mappings change while they are loading it should not evaluate a mixed snapshot", func(t *testing.T) {
		labels := map[string]string{"architecture": "stale"}
		state := &reconcilerStore{
			device: &domain.Device{Metadata: domain.ObjectMeta{
				Name:            lo.ToPtr(deviceName),
				Labels:          &labels,
				ResourceVersion: lo.ToPtr("4"),
			}},
			mappings:  domain.LabelSyncMappingList{Items: []domain.LabelSyncMapping{labelMapping("architecture", "architecture")}},
			revisions: []int64{3, 4},
		}

		updated, err := NewReconciler(state, fakeEvaluator{
			"architecture": {result: Result{Present: true, Value: "aarch64"}},
		}).Reconcile(context.Background(), orgID, deviceName)

		require.NoError(t, err)
		assert.False(t, updated)
		assert.Equal(t, 0, state.updateCalls)
	})
}
