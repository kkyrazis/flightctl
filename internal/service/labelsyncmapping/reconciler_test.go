package labelsyncmapping

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/flightctl/flightctl/internal/domain"
	transactionstore "github.com/flightctl/flightctl/internal/store"
	labelsyncmappingstore "github.com/flightctl/flightctl/internal/store/labelsyncmapping"
	"github.com/google/uuid"
	"github.com/samber/lo"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type reconciliationResponse struct {
	result Result
	err    error
}

type fakeEvaluator struct {
	responses   map[string]reconciliationResponse
	activations []Activation
}

func (e *fakeEvaluator) Evaluate(expression string, activation Activation) (Result, error) {
	e.activations = append(e.activations, activation)
	response := e.responses[expression]
	return response.result, response.err
}

func (*fakeEvaluator) ValidateExpressionIs(string, ResultKind) error { return nil }

type reconcilerStore struct {
	labelsyncmappingstore.Store
	snapshot         labelsyncmappingstore.DeviceLabelReconciliationSnapshot
	loadErr          error
	loadCalls        int
	applyCalls       int
	applyErrors      []error
	writeResult      labelsyncmappingstore.DeviceLabelWriteResult
	appliedLabels    []map[string]labelsyncmappingstore.DesiredDeviceLabel
	recordedFailures []labelsyncmappingstore.ReconciliationFailure
	recordFailureErr error
	scanTargets      []labelsyncmappingstore.MappingScanRecord
	scanTargetsErr   error
	scanFailure      labelsyncmappingstore.MappingScanRecord
	scanFailureSaved bool
	scanFailureErr   error
	scanCompletion   map[uuid.UUID]bool
	scanCompleteErr  error
	onApply          func()
}

type reconciliationEventService struct {
	created []*domain.Event
}

func (s *reconciliationEventService) CreateEvent(_ context.Context, _ uuid.UUID, event *domain.Event) {
	s.created = append(s.created, event)
}

func (*reconciliationEventService) HandleGenericResourceDeletedEvents(context.Context, domain.ResourceKind, uuid.UUID, string, interface{}, interface{}, bool, error) {
}

func newTestReconciler(t *testing.T, store *reconcilerStore, evaluator Evaluator, eventServices ...*reconciliationEventService) *Reconciler {
	t.Helper()
	var events *reconciliationEventService
	if len(eventServices) > 0 {
		events = eventServices[0]
	} else {
		events = &reconciliationEventService{}
	}
	reconciler, err := NewReconciler(store, evaluator, events, logrus.New())
	require.NoError(t, err)
	return reconciler
}

func (s *reconcilerStore) LoadDeviceLabelReconciliationSnapshot(context.Context, uuid.UUID, string) (labelsyncmappingstore.DeviceLabelReconciliationSnapshot, error) {
	s.loadCalls++
	return s.snapshot, s.loadErr
}

func (s *reconcilerStore) ApplyDeviceLabelReconciliation(_ context.Context, _ uuid.UUID, _ string, _ labelsyncmappingstore.DeviceLabelReconciliationSnapshot, desired map[string]labelsyncmappingstore.DesiredDeviceLabel) (labelsyncmappingstore.DeviceLabelWriteResult, error) {
	call := s.applyCalls
	s.applyCalls++
	s.appliedLabels = append(s.appliedLabels, cloneDesiredLabels(desired))
	if s.onApply != nil {
		s.onApply()
	}
	if call < len(s.applyErrors) && s.applyErrors[call] != nil {
		return labelsyncmappingstore.DeviceLabelWriteResult{}, s.applyErrors[call]
	}
	return s.writeResult, nil
}

func (s *reconcilerStore) RecordReconciliationFailure(_ context.Context, _ uuid.UUID, failure labelsyncmappingstore.ReconciliationFailure) (bool, error) {
	s.recordedFailures = append(s.recordedFailures, failure)
	return true, s.recordFailureErr
}

func (s *reconcilerStore) ListMappingScanTargets(context.Context, uuid.UUID) ([]labelsyncmappingstore.MappingScanRecord, error) {
	return s.scanTargets, s.scanTargetsErr
}

func (s *reconcilerStore) RecordMappingScanFailure(_ context.Context, _ uuid.UUID, failure labelsyncmappingstore.ReconciliationFailure) (labelsyncmappingstore.MappingScanRecord, bool, error) {
	s.recordedFailures = append(s.recordedFailures, failure)
	return s.scanFailure, s.scanFailureSaved, s.scanFailureErr
}

func (s *reconcilerStore) CompleteMappingScan(context.Context, uuid.UUID, []labelsyncmappingstore.MappingScanRecord) (map[uuid.UUID]bool, error) {
	return s.scanCompletion, s.scanCompleteErr
}

func cloneDesiredLabels(labels map[string]labelsyncmappingstore.DesiredDeviceLabel) map[string]labelsyncmappingstore.DesiredDeviceLabel {
	clone := make(map[string]labelsyncmappingstore.DesiredDeviceLabel, len(labels))
	for key, label := range labels {
		clone[key] = label
	}
	return clone
}

func reconciliationMapping(id uuid.UUID, name string, key *string, expression string, terminating bool) labelsyncmappingstore.ReconciliationMapping {
	mapping := domain.LabelSyncMapping{
		Metadata: domain.ObjectMeta{Name: lo.ToPtr(name)},
		Spec: domain.LabelSyncMappingSpec{
			ResourceType: domain.LabelSyncMappingDevice,
			Key:          key,
			Expression:   expression,
		},
	}
	if terminating {
		deletionTimestamp := time.Unix(1, 0).UTC()
		mapping.Metadata.DeletionTimestamp = &deletionTimestamp
	}
	mapping.Metadata.Generation = lo.ToPtr(int64(1))
	return labelsyncmappingstore.ReconciliationMapping{ID: id, Mapping: mapping}
}

func reconciliationSnapshot(labels map[string]string, owners map[string]uuid.UUID, mappings ...labelsyncmappingstore.ReconciliationMapping) labelsyncmappingstore.DeviceLabelReconciliationSnapshot {
	device := testDevice("amd64", nil)
	device.Metadata.ResourceVersion = lo.ToPtr("12")
	device.Metadata.Labels = lo.ToPtr(labels)
	deviceLabels := make([]labelsyncmappingstore.DeviceLabelOwnership, 0, len(labels))
	for key, value := range labels {
		var mappingID *uuid.UUID
		if id, ok := owners[key]; ok {
			mappingID = lo.ToPtr(id)
		}
		deviceLabels = append(deviceLabels, labelsyncmappingstore.DeviceLabelOwnership{Key: key, Value: value, MappingID: mappingID})
	}
	return labelsyncmappingstore.DeviceLabelReconciliationSnapshot{
		Device:       device,
		DeviceLabels: deviceLabels,
		Mappings:     mappings,
	}
}

func reconciliationTestID(value string) uuid.UUID {
	return uuid.MustParse("00000000-0000-4000-8000-" + value)
}

func TestReconcilerReconcileDeviceLabels(t *testing.T) {
	orgID := uuid.New()

	t.Run("When scalar and map results are valid it should apply owned outputs and preserve unmanaged labels", func(t *testing.T) {
		scalarID := reconciliationTestID("000000000001")
		mapID := reconciliationTestID("000000000002")
		staleID := reconciliationTestID("000000000003")
		state := &reconcilerStore{
			snapshot: reconciliationSnapshot(
				map[string]string{"manual": "preserved", "old-architecture": "stale", "old-site": "stale", "stale-owner": "stale"},
				map[string]uuid.UUID{"old-architecture": scalarID, "old-site": mapID, "stale-owner": staleID},
				reconciliationMapping(scalarID, "architecture", lo.ToPtr("systeminfo/architecture"), "architecture", false),
				reconciliationMapping(mapID, "custom-info", nil, "custom-info", false),
			),
			writeResult: labelsyncmappingstore.DeviceLabelWriteResult{LabelsChanged: true},
		}
		evaluator := &fakeEvaluator{responses: map[string]reconciliationResponse{
			"architecture": {result: ScalarResult("aarch64")},
			"custom-info":  {result: MapResult{"custominfo/site": "east-coast", "model": "edge"}},
		}}

		result, err := newTestReconciler(t, state, evaluator).ReconcileDeviceLabels(context.Background(), orgID, "edge-01")

		require.NoError(t, err)
		assert.True(t, result.LabelsChanged)
		require.Len(t, state.appliedLabels, 1)
		assert.Equal(t, map[string]labelsyncmappingstore.DesiredDeviceLabel{
			"manual":                  {Value: "preserved"},
			"systeminfo/architecture": {Value: "aarch64", MappingID: &scalarID},
			"custominfo/site":         {Value: "east-coast", MappingID: &mapID},
			"model":                   {Value: "edge", MappingID: &mapID},
		}, state.appliedLabels[0])
		require.Len(t, result.MappingOutcomes, 2)
		assert.NoError(t, result.MappingOutcomes[0].Err)
		assert.NoError(t, result.MappingOutcomes[1].Err)
		require.Len(t, evaluator.activations, 2)
		activation, ok := evaluator.activations[0].(map[string]any)
		require.True(t, ok)
		assert.Contains(t, activation, "metadata")
		assert.Contains(t, activation, "spec")
		assert.Contains(t, activation, "status")
	})

	t.Run("When a result is missing or omits a map key it should clean only the corresponding owned labels", func(t *testing.T) {
		scalarID := reconciliationTestID("000000000011")
		mapID := reconciliationTestID("000000000012")
		state := &reconcilerStore{snapshot: reconciliationSnapshot(
			map[string]string{"manual": "preserved", "scalar": "stale", "site": "old", "cleared": "old"},
			map[string]uuid.UUID{"scalar": scalarID, "site": mapID, "cleared": mapID},
			reconciliationMapping(scalarID, "scalar", lo.ToPtr("scalar"), "scalar", false),
			reconciliationMapping(mapID, "map", nil, "map", false),
		)}
		evaluator := &fakeEvaluator{responses: map[string]reconciliationResponse{
			"scalar": {result: NoResult{}},
			"map":    {result: MapResult{"site": "east"}},
		}}

		_, err := newTestReconciler(t, state, evaluator).ReconcileDeviceLabels(context.Background(), orgID, "edge-01")

		require.NoError(t, err)
		assert.Equal(t, map[string]labelsyncmappingstore.DesiredDeviceLabel{
			"manual": {Value: "preserved"},
			"site":   {Value: "east", MappingID: &mapID},
		}, state.appliedLabels[0])
	})

	t.Run("When a map contains any invalid entry it should retain all previous outputs and ignore partial results", func(t *testing.T) {
		mapID := reconciliationTestID("000000000021")
		scalarID := reconciliationTestID("000000000022")
		entryErr := entryFailuresEvaluationError(FailureInvalidMapEntry, "converting CEL map result", []EntryFailure{{
			Key: "bad key", Kind: FailureInvalidMapEntry, Message: "invalid label key",
		}})
		state := &reconcilerStore{snapshot: reconciliationSnapshot(
			map[string]string{"manual": "preserved", "old-map-a": "a", "old-map-b": "b", "scalar": "old"},
			map[string]uuid.UUID{"old-map-a": mapID, "old-map-b": mapID, "scalar": scalarID},
			reconciliationMapping(mapID, "map", nil, "invalid-map", false),
			reconciliationMapping(scalarID, "scalar", lo.ToPtr("scalar"), "valid-scalar", false),
		)}
		evaluator := &fakeEvaluator{responses: map[string]reconciliationResponse{
			"invalid-map":  {result: MapResult{"partial": "must-not-apply"}, err: entryErr},
			"valid-scalar": {result: ScalarResult("new")},
		}}

		result, err := newTestReconciler(t, state, evaluator).ReconcileDeviceLabels(context.Background(), orgID, "edge-01")

		require.NoError(t, err)
		assert.Equal(t, map[string]labelsyncmappingstore.DesiredDeviceLabel{
			"manual":    {Value: "preserved"},
			"old-map-a": {Value: "a", MappingID: &mapID},
			"old-map-b": {Value: "b", MappingID: &mapID},
			"scalar":    {Value: "new", MappingID: &scalarID},
		}, state.appliedLabels[0])
		require.Len(t, result.MappingOutcomes, 2)
		assert.ErrorAs(t, result.MappingOutcomes[0].Err, new(*EvaluationError))
		assert.NoError(t, result.MappingOutcomes[1].Err)
	})

	t.Run("When a mapping result has the wrong top-level shape it should retain that mapping's outputs", func(t *testing.T) {
		scalarID := reconciliationTestID("000000000031")
		mapID := reconciliationTestID("000000000032")
		state := &reconcilerStore{snapshot: reconciliationSnapshot(
			map[string]string{"old-scalar": "scalar", "old-map": "map"},
			map[string]uuid.UUID{"old-scalar": scalarID, "old-map": mapID},
			reconciliationMapping(scalarID, "scalar", lo.ToPtr("scalar"), "scalar-map", false),
			reconciliationMapping(mapID, "map", nil, "map-scalar", false),
		)}
		evaluator := &fakeEvaluator{responses: map[string]reconciliationResponse{
			"scalar-map": {result: MapResult{"new": "invalid"}},
			"map-scalar": {result: ScalarResult("invalid")},
		}}

		result, err := newTestReconciler(t, state, evaluator).ReconcileDeviceLabels(context.Background(), orgID, "edge-01")

		require.NoError(t, err)
		assert.Equal(t, map[string]labelsyncmappingstore.DesiredDeviceLabel{
			"old-scalar": {Value: "scalar", MappingID: &scalarID},
			"old-map":    {Value: "map", MappingID: &mapID},
		}, state.appliedLabels[0])
		assert.Error(t, result.MappingOutcomes[0].Err)
		assert.Error(t, result.MappingOutcomes[1].Err)
	})

	t.Run("When mappings emit the same key it should reject colliding candidates and continue unrelated outputs", func(t *testing.T) {
		scalarID := reconciliationTestID("000000000041")
		firstMapID := reconciliationTestID("000000000042")
		secondMapID := reconciliationTestID("000000000043")
		independentID := reconciliationTestID("000000000044")
		state := &reconcilerStore{snapshot: reconciliationSnapshot(
			map[string]string{"manual": "preserved", "shared": "old-map-value"},
			map[string]uuid.UUID{"shared": firstMapID},
			reconciliationMapping(scalarID, "scalar", lo.ToPtr("shared"), "scalar", false),
			reconciliationMapping(firstMapID, "first-map", nil, "first-map", false),
			reconciliationMapping(secondMapID, "second-map", nil, "second-map", false),
			reconciliationMapping(independentID, "independent", lo.ToPtr("unrelated"), "independent", false),
		)}
		evaluator := &fakeEvaluator{responses: map[string]reconciliationResponse{
			"scalar":      {result: ScalarResult("scalar-value")},
			"first-map":   {result: MapResult{"shared": "first", "map-only": "allowed"}},
			"second-map":  {result: MapResult{"shared": "second"}},
			"independent": {result: ScalarResult("independent-value")},
		}}

		result, err := newTestReconciler(t, state, evaluator).ReconcileDeviceLabels(context.Background(), orgID, "edge-01")

		require.NoError(t, err)
		assert.Equal(t, map[string]labelsyncmappingstore.DesiredDeviceLabel{
			"manual":    {Value: "preserved"},
			"shared":    {Value: "old-map-value", MappingID: &firstMapID},
			"map-only":  {Value: "allowed", MappingID: &firstMapID},
			"unrelated": {Value: "independent-value", MappingID: &independentID},
		}, state.appliedLabels[0])
		assert.Error(t, result.MappingOutcomes[0].Err)
		assert.Error(t, result.MappingOutcomes[1].Err)
		assert.Error(t, result.MappingOutcomes[2].Err)
		assert.NoError(t, result.MappingOutcomes[3].Err)
	})

	t.Run("When a map claims an unmanaged or scalar-reserved key it should preserve existing ownership and allow unrelated keys", func(t *testing.T) {
		mapID := reconciliationTestID("000000000051")
		scalarID := reconciliationTestID("000000000052")
		state := &reconcilerStore{snapshot: reconciliationSnapshot(
			map[string]string{"manual": "operator", "reserved": "old-map"},
			map[string]uuid.UUID{"reserved": mapID},
			reconciliationMapping(mapID, "map", nil, "map", false),
			reconciliationMapping(scalarID, "terminating-scalar", lo.ToPtr("reserved"), "unused", true),
		)}
		evaluator := &fakeEvaluator{responses: map[string]reconciliationResponse{
			"map": {result: MapResult{"manual": "must-not-take", "reserved": "must-not-overwrite", "safe": "applied"}},
		}}

		result, err := newTestReconciler(t, state, evaluator).ReconcileDeviceLabels(context.Background(), orgID, "edge-01")

		require.NoError(t, err)
		assert.Equal(t, map[string]labelsyncmappingstore.DesiredDeviceLabel{
			"manual":   {Value: "operator"},
			"reserved": {Value: "old-map", MappingID: &mapID},
			"safe":     {Value: "applied", MappingID: &mapID},
		}, state.appliedLabels[0])
		require.Len(t, result.MappingOutcomes, 1)
		assert.Error(t, result.MappingOutcomes[0].Err)
	})

	t.Run("When combined outputs exceed the aggregate limit it should clean empty mappings and retain prior non-empty outputs", func(t *testing.T) {
		mappingIDs := []uuid.UUID{
			reconciliationTestID("000000000061"),
			reconciliationTestID("000000000062"),
			reconciliationTestID("000000000063"),
		}
		labels := map[string]string{"manual": "preserved", "retired": "remove"}
		owners := map[string]uuid.UUID{"retired": reconciliationTestID("000000000064")}
		mappings := []labelsyncmappingstore.ReconciliationMapping{
			reconciliationMapping(mappingIDs[0], "first", nil, "first", false),
			reconciliationMapping(mappingIDs[1], "second", nil, "second", false),
			reconciliationMapping(mappingIDs[2], "third", nil, "third", false),
			reconciliationMapping(owners["retired"], "empty", nil, "empty", false),
		}
		responses := make(map[string]reconciliationResponse)
		for mappingIndex, count := range []int{50, 50, 1} {
			outputs := make(MapResult, count)
			for index := 0; index < count; index++ {
				key := fmt.Sprintf("key-%03d", mappingIndex*50+index)
				outputs[key] = "new"
				labels[key] = "old"
				owners[key] = mappingIDs[mappingIndex]
			}
			responses[mappings[mappingIndex].Mapping.Spec.Expression] = reconciliationResponse{result: outputs}
		}
		responses["empty"] = reconciliationResponse{result: MapResult{}}
		state := &reconcilerStore{snapshot: reconciliationSnapshot(labels, owners, mappings...)}

		result, err := newTestReconciler(t, state, &fakeEvaluator{responses: responses}).ReconcileDeviceLabels(context.Background(), orgID, "edge-01")

		require.NoError(t, err)
		require.Len(t, result.MappingOutcomes, 4)
		assert.Error(t, result.MappingOutcomes[0].Err)
		assert.Error(t, result.MappingOutcomes[1].Err)
		assert.Error(t, result.MappingOutcomes[2].Err)
		assert.NoError(t, result.MappingOutcomes[3].Err)
		assert.Len(t, state.appliedLabels[0], 102)
		assert.Equal(t, labelsyncmappingstore.DesiredDeviceLabel{Value: "preserved"}, state.appliedLabels[0]["manual"])
		assert.NotContains(t, state.appliedLabels[0], "retired")
		for key, owner := range owners {
			if key == "retired" {
				continue
			}
			assert.Equal(t, labelsyncmappingstore.DesiredDeviceLabel{Value: "old", MappingID: &owner}, state.appliedLabels[0][key])
		}
	})

	t.Run("When applying detects a stale snapshot it should reload and retry the complete reconciliation", func(t *testing.T) {
		mappingID := reconciliationTestID("000000000071")
		state := &reconcilerStore{
			snapshot:    reconciliationSnapshot(nil, nil, reconciliationMapping(mappingID, "architecture", lo.ToPtr("architecture"), "architecture", false)),
			applyErrors: []error{labelsyncmappingstore.ErrDeviceLabelReconciliationConflict},
			writeResult: labelsyncmappingstore.DeviceLabelWriteResult{LabelsChanged: true},
		}
		evaluator := &fakeEvaluator{responses: map[string]reconciliationResponse{
			"architecture": {result: ScalarResult("aarch64")},
		}}
		events := &reconciliationEventService{}

		result, err := newTestReconciler(t, state, evaluator, events).ReconcileDeviceLabels(context.Background(), orgID, "edge-01")

		require.NoError(t, err)
		assert.True(t, result.LabelsChanged)
		assert.Equal(t, 2, state.loadCalls)
		assert.Equal(t, 2, state.applyCalls)
		assert.Len(t, evaluator.activations, 2)
		assertLabelsUpdatedEvent(t, events, "edge-01")
	})

	t.Run("When every apply attempt conflicts it should stop after five complete attempts", func(t *testing.T) {
		const expectedAttempts = 5
		mappingID := reconciliationTestID("000000000072")
		conflicts := make([]error, expectedAttempts)
		for index := range conflicts {
			conflicts[index] = labelsyncmappingstore.ErrDeviceLabelReconciliationConflict
		}
		state := &reconcilerStore{
			snapshot:    reconciliationSnapshot(nil, nil, reconciliationMapping(mappingID, "architecture", lo.ToPtr("architecture"), "architecture", false)),
			applyErrors: conflicts,
		}
		evaluator := &fakeEvaluator{responses: map[string]reconciliationResponse{
			"architecture": {result: ScalarResult("aarch64")},
		}}
		events := &reconciliationEventService{}

		_, err := newTestReconciler(t, state, evaluator, events).ReconcileDeviceLabels(context.Background(), orgID, "edge-01")

		require.ErrorIs(t, err, labelsyncmappingstore.ErrDeviceLabelReconciliationConflict)
		assert.Equal(t, expectedAttempts, state.loadCalls)
		assert.Equal(t, expectedAttempts, state.applyCalls)
		assert.Len(t, evaluator.activations, expectedAttempts)
		assert.Empty(t, events.created)
	})

	t.Run("When applying fails for a reason other than a stale snapshot it should not retry", func(t *testing.T) {
		writeErr := errors.New("database unavailable")
		state := &reconcilerStore{
			snapshot:    reconciliationSnapshot(nil, nil),
			applyErrors: []error{writeErr},
		}
		events := &reconciliationEventService{}

		_, err := newTestReconciler(t, state, &fakeEvaluator{}, events).ReconcileDeviceLabels(context.Background(), orgID, "edge-01")

		require.ErrorIs(t, err, writeErr)
		assert.Equal(t, 1, state.loadCalls)
		assert.Equal(t, 1, state.applyCalls)
		assert.Empty(t, events.created)
	})

	t.Run("When the context is canceled after a conflict it should stop before retrying", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		state := &reconcilerStore{
			snapshot:    reconciliationSnapshot(nil, nil),
			applyErrors: []error{labelsyncmappingstore.ErrDeviceLabelReconciliationConflict},
			onApply:     cancel,
		}
		events := &reconciliationEventService{}

		_, err := newTestReconciler(t, state, &fakeEvaluator{}, events).ReconcileDeviceLabels(ctx, orgID, "edge-01")

		require.ErrorIs(t, err, context.Canceled)
		assert.Equal(t, 1, state.loadCalls)
		assert.Equal(t, 1, state.applyCalls)
		assert.Empty(t, events.created)
	})

	t.Run("When called inside a store transaction it should not apply labels or publish an event", func(t *testing.T) {
		db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{
			Logger: logger.Default.LogMode(logger.Silent),
		})
		require.NoError(t, err)

		state := &reconcilerStore{snapshot: reconciliationSnapshot(nil, nil)}
		events := &reconciliationEventService{}
		reconciler := newTestReconciler(t, state, &fakeEvaluator{}, events)
		rollbackErr := errors.New("rollback caller transaction")
		var reconciliationErr error

		err = transactionstore.WithTransaction(context.Background(), db, func(txCtx context.Context) error {
			_, reconciliationErr = reconciler.ReconcileDeviceLabels(txCtx, orgID, "edge-01")
			return rollbackErr
		})

		require.ErrorIs(t, err, rollbackErr)
		require.ErrorContains(t, reconciliationErr, "cannot run inside an existing store transaction")
		assert.Zero(t, state.loadCalls)
		assert.Zero(t, state.applyCalls)
		assert.Empty(t, events.created)
	})

	t.Run("When labels are unchanged it should not emit an update event", func(t *testing.T) {
		state := &reconcilerStore{snapshot: reconciliationSnapshot(nil, nil)}
		events := &reconciliationEventService{}

		result, err := newTestReconciler(t, state, &fakeEvaluator{}, events).ReconcileDeviceLabels(context.Background(), orgID, "edge-01")

		require.NoError(t, err)
		assert.False(t, result.LabelsChanged)
		assert.Empty(t, events.created)
	})

	t.Run("When loading the snapshot fails it should return a device-level error", func(t *testing.T) {
		state := &reconcilerStore{loadErr: errors.New("store unavailable")}
		result, err := newTestReconciler(t, state, &fakeEvaluator{}).ReconcileDeviceLabels(context.Background(), orgID, "edge-01")
		require.ErrorContains(t, err, "store unavailable")
		assert.Empty(t, result.MappingOutcomes)
		assert.Equal(t, 0, state.applyCalls)
	})

	t.Run("When one mapping fails it should record only that mapping with its captured token", func(t *testing.T) {
		failedMappingID := reconciliationTestID("000000000081")
		healthyMappingID := reconciliationTestID("000000000082")
		failedMapping := reconciliationMapping(failedMappingID, "failing", lo.ToPtr("failing"), "failing", false)
		failedMapping.Mapping.Metadata.Generation = lo.ToPtr(int64(4))
		failedMapping.DeletionRevision = lo.ToPtr(int64(11))
		healthyMapping := reconciliationMapping(healthyMappingID, "healthy", lo.ToPtr("healthy"), "healthy", false)
		state := &reconcilerStore{snapshot: reconciliationSnapshot(nil, nil, failedMapping, healthyMapping)}
		evaluator := &fakeEvaluator{responses: map[string]reconciliationResponse{
			"failing": {err: errors.New("evaluation failed")},
			"healthy": {result: ScalarResult("value")},
		}}
		reconciler := newTestReconciler(t, state, evaluator)

		result, err := reconciler.ReconcileDeviceLabels(context.Background(), orgID, "edge-01")
		require.NoError(t, err)
		require.Len(t, result.MappingOutcomes, 2)
		require.Error(t, result.MappingOutcomes[0].Err)
		assert.Equal(t, failedMappingID, result.MappingOutcomes[0].MappingID)
		assert.EqualValues(t, 4, result.MappingOutcomes[0].Generation)
		assert.Equal(t, lo.ToPtr(int64(11)), result.MappingOutcomes[0].DeletionRevision)
		assert.NoError(t, result.MappingOutcomes[1].Err)

		require.NoError(t, reconciler.RecordFailures(context.Background(), orgID, result.MappingOutcomes))
		require.Len(t, state.recordedFailures, 1)
		assert.Equal(t, failedMappingID, state.recordedFailures[0].MappingID)
		assert.EqualValues(t, 4, state.recordedFailures[0].Generation)
		assert.Equal(t, lo.ToPtr(int64(11)), state.recordedFailures[0].DeletionRevision)
		assert.Contains(t, state.recordedFailures[0].Message, "evaluation failed")
	})

	t.Run("When applying labels fails it should return failures for every captured mapping", func(t *testing.T) {
		firstID := reconciliationTestID("000000000083")
		secondID := reconciliationTestID("000000000084")
		writeErr := errors.New("label write failed")
		state := &reconcilerStore{
			snapshot: reconciliationSnapshot(nil, nil,
				reconciliationMapping(firstID, "first", lo.ToPtr("first"), "first", false),
				reconciliationMapping(secondID, "second", lo.ToPtr("second"), "second", false),
			),
			applyErrors: []error{writeErr},
		}
		evaluator := &fakeEvaluator{responses: map[string]reconciliationResponse{
			"first":  {result: ScalarResult("one")},
			"second": {result: ScalarResult("two")},
		}}

		result, err := newTestReconciler(t, state, evaluator).ReconcileDeviceLabels(context.Background(), orgID, "edge-01")

		require.ErrorIs(t, err, writeErr)
		require.Len(t, result.MappingOutcomes, 2)
		assert.Equal(t, firstID, result.MappingOutcomes[0].MappingID)
		assert.Equal(t, secondID, result.MappingOutcomes[1].MappingID)
		assert.ErrorIs(t, result.MappingOutcomes[0].Err, writeErr)
		assert.ErrorIs(t, result.MappingOutcomes[1].Err, writeErr)
	})
}

func TestReconcilerMappingScanStoreBoundary(t *testing.T) {
	orgID := uuid.New()
	mappingID := reconciliationTestID("000000000091")
	deletionRevision := int64(14)
	storeRecord := labelsyncmappingstore.MappingScanRecord{
		MappingID:        mappingID,
		Generation:       3,
		DeletionRevision: &deletionRevision,
		FailureRevision:  8,
	}
	token := MappingScanToken{
		MappingID:        mappingID,
		Generation:       3,
		DeletionRevision: &deletionRevision,
		FailureRevision:  8,
	}

	t.Run("When scan targets are listed it should preserve every completion token field", func(t *testing.T) {
		state := &reconcilerStore{scanTargets: []labelsyncmappingstore.MappingScanRecord{storeRecord}}
		actual, err := newTestReconciler(t, state, &fakeEvaluator{}).ListMappingScanTargets(context.Background(), orgID)

		require.NoError(t, err)
		require.Equal(t, []MappingScanToken{token}, actual)
	})

	t.Run("When a scan failure is recorded it should return the new failure revision", func(t *testing.T) {
		state := &reconcilerStore{scanFailure: storeRecord, scanFailureSaved: true}
		outcome := MappingOutcome{
			MappingID:        mappingID,
			Generation:       3,
			DeletionRevision: &deletionRevision,
			Err:              errors.New("device reconciliation failed"),
		}

		updated, saved, err := newTestReconciler(t, state, &fakeEvaluator{}).RecordMappingScanFailure(context.Background(), orgID, outcome)

		require.NoError(t, err)
		require.True(t, saved)
		require.Equal(t, token, updated)
		require.Len(t, state.recordedFailures, 1)
		require.Equal(t, labelsyncmappingstore.ReconciliationFailure{
			MappingID:        mappingID,
			Generation:       3,
			DeletionRevision: &deletionRevision,
			Message:          "device reconciliation failed",
		}, state.recordedFailures[0])
	})

	t.Run("When completion is fenced it should return per-mapping results", func(t *testing.T) {
		state := &reconcilerStore{scanCompletion: map[uuid.UUID]bool{mappingID: false}}
		actual, err := newTestReconciler(t, state, &fakeEvaluator{}).CompleteMappingScan(context.Background(), orgID, []MappingScanToken{token})

		require.NoError(t, err)
		require.Equal(t, map[uuid.UUID]bool{mappingID: false}, actual)
	})
}

func assertLabelsUpdatedEvent(t *testing.T, events *reconciliationEventService, deviceName string) {
	t.Helper()
	require.Len(t, events.created, 1)
	event := events.created[0]
	require.Equal(t, domain.EventReasonResourceUpdated, event.Reason)
	require.Equal(t, domain.DeviceKind, event.InvolvedObject.Kind)
	require.Equal(t, deviceName, event.InvolvedObject.Name)
	require.NotNil(t, event.Details)
	details, err := event.Details.AsResourceUpdatedDetails()
	require.NoError(t, err)
	require.Equal(t, []domain.ResourceUpdatedDetailsUpdatedFields{domain.Labels}, details.UpdatedFields)
}
