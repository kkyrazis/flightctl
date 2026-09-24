package labelsyncmapping

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/flightctl/flightctl/internal/domain"
	labelsyncmappingstore "github.com/flightctl/flightctl/internal/store/labelsyncmapping"
	"github.com/google/uuid"
	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	snapshot      labelsyncmappingstore.DeviceLabelReconciliationSnapshot
	loadErr       error
	loadCalls     int
	applyCalls    int
	applyErrors   []error
	writeResult   labelsyncmappingstore.DeviceLabelWriteResult
	appliedLabels []map[string]labelsyncmappingstore.DesiredDeviceLabel
	onApply       func()
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

		result, err := NewReconciler(state, evaluator).ReconcileDeviceLabels(context.Background(), orgID, "edge-01")

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

		_, err := NewReconciler(state, evaluator).ReconcileDeviceLabels(context.Background(), orgID, "edge-01")

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

		result, err := NewReconciler(state, evaluator).ReconcileDeviceLabels(context.Background(), orgID, "edge-01")

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

		result, err := NewReconciler(state, evaluator).ReconcileDeviceLabels(context.Background(), orgID, "edge-01")

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

		result, err := NewReconciler(state, evaluator).ReconcileDeviceLabels(context.Background(), orgID, "edge-01")

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

		result, err := NewReconciler(state, evaluator).ReconcileDeviceLabels(context.Background(), orgID, "edge-01")

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

		result, err := NewReconciler(state, &fakeEvaluator{responses: responses}).ReconcileDeviceLabels(context.Background(), orgID, "edge-01")

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

	t.Run("When loading the snapshot fails it should return a device-level error", func(t *testing.T) {
		state := &reconcilerStore{loadErr: errors.New("store unavailable")}
		result, err := NewReconciler(state, &fakeEvaluator{}).ReconcileDeviceLabels(context.Background(), orgID, "edge-01")
		require.ErrorContains(t, err, "store unavailable")
		assert.Empty(t, result.MappingOutcomes)
		assert.Equal(t, 0, state.applyCalls)
	})
}
