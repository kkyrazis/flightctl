package tasks

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/flightctl/flightctl/internal/domain"
	checkpointservice "github.com/flightctl/flightctl/internal/service/checkpoint"
	deviceservice "github.com/flightctl/flightctl/internal/service/device"
	labelsyncmappingservice "github.com/flightctl/flightctl/internal/service/labelsyncmapping"
	"github.com/google/uuid"
	"github.com/samber/lo"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

type mappingScanReconcilerStub struct {
	targets          []labelsyncmappingservice.MappingScanToken
	targetErr        error
	reconciled       []string
	reconcileResults map[string]labelsyncmappingservice.ReconciliationResult
	reconcileErr     map[string]error
	failures         []labelsyncmappingservice.MappingOutcome
	failureTokens    map[uuid.UUID]labelsyncmappingservice.MappingScanToken
	failureSaved     map[uuid.UUID]bool
	failureErr       error
	completed        [][]labelsyncmappingservice.MappingScanToken
	completeResults  map[uuid.UUID]bool
	completeErr      error
}

func (r *mappingScanReconcilerStub) ListMappingScanTargets(context.Context, uuid.UUID) ([]labelsyncmappingservice.MappingScanToken, error) {
	return r.targets, r.targetErr
}

func (r *mappingScanReconcilerStub) ReconcileDeviceLabels(_ context.Context, _ uuid.UUID, name string) (labelsyncmappingservice.ReconciliationResult, error) {
	r.reconciled = append(r.reconciled, name)
	return r.reconcileResults[name], r.reconcileErr[name]
}

func (r *mappingScanReconcilerStub) RecordMappingScanFailure(_ context.Context, _ uuid.UUID, outcome labelsyncmappingservice.MappingOutcome) (labelsyncmappingservice.MappingScanToken, bool, error) {
	r.failures = append(r.failures, outcome)
	return r.failureTokens[outcome.MappingID], r.failureSaved[outcome.MappingID], r.failureErr
}

func (r *mappingScanReconcilerStub) CompleteMappingScan(_ context.Context, _ uuid.UUID, tokens []labelsyncmappingservice.MappingScanToken) (map[uuid.UUID]bool, error) {
	r.completed = append(r.completed, append([]labelsyncmappingservice.MappingScanToken(nil), tokens...))
	return r.completeResults, r.completeErr
}

type mappingScanCheckpointHarness struct {
	data     []byte
	writes   [][]byte
	getCalls int
	setCalls int
}

func newMappingScanCheckpointMock(ctrl *gomock.Controller, orgID uuid.UUID, initial []byte) (*checkpointservice.MockService, *mappingScanCheckpointHarness) {
	harness := &mappingScanCheckpointHarness{data: append([]byte(nil), initial...)}
	mock := checkpointservice.NewMockService(ctrl)
	mock.EXPECT().GetCheckpoint(gomock.Any(), mappingScanCheckpointConsumer, orgID.String()).DoAndReturn(
		func(context.Context, string, string) ([]byte, domain.Status) {
			harness.getCalls++
			if harness.data == nil {
				return nil, domain.StatusResourceNotFound("Checkpoint", orgID.String())
			}
			return append([]byte(nil), harness.data...), domain.StatusOK()
		},
	).AnyTimes()
	mock.EXPECT().SetCheckpoint(gomock.Any(), mappingScanCheckpointConsumer, orgID.String(), gomock.Any()).DoAndReturn(
		func(_ context.Context, _, _ string, data []byte) domain.Status {
			harness.setCalls++
			checkpointBytes := append([]byte(nil), data...)
			harness.data = checkpointBytes
			harness.writes = append(harness.writes, checkpointBytes)
			return domain.StatusOK()
		},
	).AnyTimes()
	return mock, harness
}

func TestNewMappingScanTaskRejectsInvalidConfig(t *testing.T) {
	for _, tc := range []struct {
		name   string
		config MappingScanConfig
	}{
		{name: "When page size is zero it should be rejected", config: MappingScanConfig{PageSize: 0, TimeBudget: time.Second}},
		{name: "When page size exceeds the device list maximum it should be rejected", config: MappingScanConfig{PageSize: 1001, TimeBudget: time.Second}},
		{name: "When time budget is non-positive it should be rejected", config: MappingScanConfig{PageSize: 100, TimeBudget: 0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			_, err := NewMappingScanTask(&mappingScanReconcilerStub{}, deviceservice.NewMockService(ctrl), checkpointservice.NewMockService(ctrl), tc.config, logrus.New())
			require.Error(t, err)
		})
	}
	t.Run("When page size is at the maximum it should be accepted", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		_, err := NewMappingScanTask(&mappingScanReconcilerStub{}, deviceservice.NewMockService(ctrl), checkpointservice.NewMockService(ctrl), MappingScanConfig{PageSize: maxMappingScanPageSize, TimeBudget: time.Second}, logrus.New())
		require.NoError(t, err)
	})
}

func TestMappingScanTaskSkipsDeviceScanWhenNoTargets(t *testing.T) {
	ctx := context.Background()
	orgID := uuid.New()
	ctrl := gomock.NewController(t)
	deviceSvc := deviceservice.NewMockService(ctrl)
	reconciler := &mappingScanReconcilerStub{}
	checkpoints, checkpointHarness := newMappingScanCheckpointMock(ctrl, orgID, nil)
	task, err := NewMappingScanTask(reconciler, deviceSvc, checkpoints, MappingScanConfig{PageSize: 100, TimeBudget: time.Second}, logrus.New())
	require.NoError(t, err)

	task.Poll(ctx, orgID)

	require.Empty(t, reconciler.completed)
	require.Equal(t, 1, checkpointHarness.getCalls)
	require.Zero(t, checkpointHarness.setCalls)
	require.Nil(t, checkpointHarness.data)
}

func TestMappingScanTaskResumesCursorAndCompletesOnlyAfterFinalPage(t *testing.T) {
	ctx := context.Background()
	orgID := uuid.New()
	mappingID := uuid.New()
	token := labelsyncmappingservice.MappingScanToken{MappingID: mappingID, Generation: 7, FailureRevision: 2}
	reconciler := &mappingScanReconcilerStub{
		targets:          []labelsyncmappingservice.MappingScanToken{token},
		reconcileResults: map[string]labelsyncmappingservice.ReconciliationResult{},
		reconcileErr:     map[string]error{},
		completeResults:  map[uuid.UUID]bool{mappingID: true},
	}
	ctrl := gomock.NewController(t)
	checkpoints, checkpointHarness := newMappingScanCheckpointMock(ctrl, orgID, nil)
	deviceSvc := deviceservice.NewMockService(ctrl)
	continueToken := "after-device-1"
	firstLimit := int32(100)
	deviceSvc.EXPECT().ListDevices(gomock.Any(), orgID, gomock.Any(), gomock.Nil()).DoAndReturn(
		func(_ context.Context, _ uuid.UUID, params domain.ListDevicesParams, _ any) (*domain.DeviceList, domain.Status) {
			require.Equal(t, firstLimit, lo.FromPtr(params.Limit))
			require.Nil(t, params.Continue)
			return &domain.DeviceList{Items: []domain.Device{mappingScanTestDevice("device-1")}, Metadata: domain.ListMeta{Continue: &continueToken}}, domain.StatusOK()
		},
	)
	deviceSvc.EXPECT().ListDevices(gomock.Any(), orgID, gomock.Any(), gomock.Nil()).DoAndReturn(
		func(_ context.Context, _ uuid.UUID, params domain.ListDevicesParams, _ any) (*domain.DeviceList, domain.Status) {
			require.Equal(t, firstLimit, lo.FromPtr(params.Limit))
			require.Equal(t, continueToken, lo.FromPtr(params.Continue))
			return &domain.DeviceList{Items: []domain.Device{mappingScanTestDevice("device-2")}}, domain.StatusOK()
		},
	)
	task, err := NewMappingScanTask(reconciler, deviceSvc, checkpoints, MappingScanConfig{PageSize: 100, TimeBudget: time.Second}, logrus.New())
	require.NoError(t, err)
	start := time.Now()
	now := start
	clockCalls := 0
	task.now = func() time.Time {
		clockCalls++
		if clockCalls == 1 {
			return start
		}
		return now
	}

	// The first complete page exceeds the budget; its cursor is checkpointed and
	// completion must wait for the next scheduled run.
	now = start.Add(2 * time.Second)
	task.Poll(ctx, orgID)
	require.Empty(t, reconciler.completed)
	require.NotNil(t, checkpointHarness.data)
	firstCheckpoint := decodeMappingScanCheckpointBytes(t, checkpointHarness.writes[0])
	require.Equal(t, &continueToken, firstCheckpoint.Cursor)
	require.Equal(t, []mappingScanProgress{{Token: token}}, firstCheckpoint.Mappings)

	// The following run resumes at the saved opaque cursor and completes the
	// campaign after its final page.
	task.now = func() time.Time { return now }
	task.Poll(ctx, orgID)
	require.Equal(t, [][]labelsyncmappingservice.MappingScanToken{{token}}, reconciler.completed)
	finalCheckpoint := decodeMappingScanCheckpointBytes(t, checkpointHarness.data)
	require.Nil(t, finalCheckpoint.Cursor)
	require.Empty(t, finalCheckpoint.Mappings)
	require.Equal(t, []string{"device-1", "device-2"}, reconciler.reconciled)
}

func TestMappingScanTaskRetriesDeviceFailureFromTheSameCursor(t *testing.T) {
	ctx := context.Background()
	orgID := uuid.New()
	mappingID := uuid.New()
	cursor := "after-device-1"
	token := labelsyncmappingservice.MappingScanToken{MappingID: mappingID, Generation: 7, FailureRevision: 2}
	updatedToken := token
	updatedToken.FailureRevision++
	initialCheckpoint, err := json.Marshal(mappingScanCheckpoint{
		Version:  mappingScanCheckpointVersion,
		Cursor:   &cursor,
		Mappings: []mappingScanProgress{{Token: token}},
	})
	require.NoError(t, err)
	reconciler := &mappingScanReconcilerStub{
		targets:          []labelsyncmappingservice.MappingScanToken{token},
		reconcileResults: map[string]labelsyncmappingservice.ReconciliationResult{},
		reconcileErr:     map[string]error{"device-2": errors.New("temporary device store failure")},
		failureTokens:    map[uuid.UUID]labelsyncmappingservice.MappingScanToken{mappingID: updatedToken},
		failureSaved:     map[uuid.UUID]bool{mappingID: true},
		completeResults:  map[uuid.UUID]bool{mappingID: true},
	}
	ctrl := gomock.NewController(t)
	checkpoints, checkpointHarness := newMappingScanCheckpointMock(ctrl, orgID, initialCheckpoint)
	deviceSvc := deviceservice.NewMockService(ctrl)
	deviceSvc.EXPECT().ListDevices(gomock.Any(), orgID, gomock.Any(), gomock.Nil()).DoAndReturn(
		func(_ context.Context, _ uuid.UUID, params domain.ListDevicesParams, _ any) (*domain.DeviceList, domain.Status) {
			require.Equal(t, cursor, lo.FromPtr(params.Continue))
			return &domain.DeviceList{Items: []domain.Device{mappingScanTestDevice("device-2")}}, domain.StatusOK()
		},
	).Times(2)
	task, err := NewMappingScanTask(reconciler, deviceSvc, checkpoints, MappingScanConfig{PageSize: 100, TimeBudget: time.Minute}, logrus.New())
	require.NoError(t, err)

	task.Poll(ctx, orgID)
	failedCheckpoint := decodeMappingScanCheckpointBytes(t, checkpointHarness.data)
	require.Equal(t, &cursor, failedCheckpoint.Cursor)
	require.Equal(t, updatedToken, failedCheckpoint.Mappings[0].Token)
	require.False(t, failedCheckpoint.Mappings[0].Failed)
	require.Empty(t, reconciler.completed)

	reconciler.targets = []labelsyncmappingservice.MappingScanToken{updatedToken}
	delete(reconciler.reconcileErr, "device-2")
	task.Poll(ctx, orgID)
	require.Equal(t, [][]labelsyncmappingservice.MappingScanToken{{updatedToken}}, reconciler.completed)
	require.Equal(t, []string{"device-2", "device-2"}, reconciler.reconciled)
}

func TestMappingScanTaskKeepsFailuresIsolatedFromSuccessfulMappings(t *testing.T) {
	ctx := context.Background()
	orgID := uuid.New()
	failedID := uuid.New()
	successID := uuid.New()
	failedToken := labelsyncmappingservice.MappingScanToken{MappingID: failedID, Generation: 3, FailureRevision: 4}
	successToken := labelsyncmappingservice.MappingScanToken{MappingID: successID, Generation: 5, FailureRevision: 1}
	updatedFailureToken := failedToken
	updatedFailureToken.FailureRevision++
	reconciler := &mappingScanReconcilerStub{
		targets:          []labelsyncmappingservice.MappingScanToken{failedToken, successToken},
		reconcileResults: map[string]labelsyncmappingservice.ReconciliationResult{"device-1": {MappingOutcomes: []labelsyncmappingservice.MappingOutcome{{MappingID: failedID, Generation: 3, Err: errors.New("mapping failed")}}}},
		reconcileErr:     map[string]error{},
		failureTokens:    map[uuid.UUID]labelsyncmappingservice.MappingScanToken{failedID: updatedFailureToken},
		failureSaved:     map[uuid.UUID]bool{failedID: true},
		completeResults:  map[uuid.UUID]bool{successID: true},
	}
	ctrl := gomock.NewController(t)
	checkpoints, checkpointHarness := newMappingScanCheckpointMock(ctrl, orgID, nil)
	deviceSvc := deviceservice.NewMockService(ctrl)
	deviceSvc.EXPECT().ListDevices(gomock.Any(), orgID, gomock.Any(), gomock.Nil()).Return(
		&domain.DeviceList{Items: []domain.Device{mappingScanTestDevice("device-1")}}, domain.StatusOK())
	task, err := NewMappingScanTask(reconciler, deviceSvc, checkpoints, MappingScanConfig{PageSize: 100, TimeBudget: time.Minute}, logrus.New())
	require.NoError(t, err)
	task.Poll(ctx, orgID)

	require.Len(t, reconciler.failures, 1)
	require.Equal(t, failedID, reconciler.failures[0].MappingID)
	require.Len(t, reconciler.completed, 1)
	require.Equal(t, []labelsyncmappingservice.MappingScanToken{successToken}, reconciler.completed[0])
	require.Equal(t, updatedFailureToken.FailureRevision, decodeMappingScanCheckpointBytes(t, checkpointHarness.writes[0]).Mappings[0].Token.FailureRevision)
}

func TestMappingScanTaskDuplicatePollsRemainIdempotent(t *testing.T) {
	ctx := context.Background()
	orgID := uuid.New()
	mappingID := uuid.New()
	token := labelsyncmappingservice.MappingScanToken{MappingID: mappingID, Generation: 1}
	reconciler := &mappingScanReconcilerStub{
		targets:          []labelsyncmappingservice.MappingScanToken{token},
		reconcileResults: map[string]labelsyncmappingservice.ReconciliationResult{},
		reconcileErr:     map[string]error{},
		completeResults:  map[uuid.UUID]bool{mappingID: true},
	}
	ctrl := gomock.NewController(t)
	checkpoints, checkpointHarness := newMappingScanCheckpointMock(ctrl, orgID, nil)
	deviceSvc := deviceservice.NewMockService(ctrl)
	deviceSvc.EXPECT().ListDevices(gomock.Any(), orgID, gomock.Any(), gomock.Nil()).Return(
		&domain.DeviceList{Items: []domain.Device{mappingScanTestDevice("device-1")}}, domain.StatusOK()).Times(2)
	task, err := NewMappingScanTask(reconciler, deviceSvc, checkpoints, MappingScanConfig{PageSize: 100, TimeBudget: time.Minute}, logrus.New())
	require.NoError(t, err)

	task.Poll(ctx, orgID)
	task.Poll(ctx, orgID)

	require.Equal(t, [][]labelsyncmappingservice.MappingScanToken{{token}, {token}}, reconciler.completed)
	require.Equal(t, []string{"device-1", "device-1"}, reconciler.reconciled)
	require.NotNil(t, checkpointHarness.data)
}

func TestMappingScanTaskRestartsOnlyTheMappingWithAChangedToken(t *testing.T) {
	ctx := context.Background()
	orgID := uuid.New()
	changedID := uuid.New()
	unchangedID := uuid.New()
	oldToken := labelsyncmappingservice.MappingScanToken{MappingID: changedID, Generation: 1}
	newToken := labelsyncmappingservice.MappingScanToken{MappingID: changedID, Generation: 2}
	unchangedToken := labelsyncmappingservice.MappingScanToken{MappingID: unchangedID, Generation: 3}
	reconciler := &mappingScanReconcilerStub{
		targets:          []labelsyncmappingservice.MappingScanToken{oldToken, unchangedToken},
		reconcileResults: map[string]labelsyncmappingservice.ReconciliationResult{},
		reconcileErr:     map[string]error{},
		completeResults:  map[uuid.UUID]bool{changedID: false, unchangedID: true},
	}
	ctrl := gomock.NewController(t)
	checkpoints, _ := newMappingScanCheckpointMock(ctrl, orgID, nil)
	deviceSvc := deviceservice.NewMockService(ctrl)
	continueToken := "after-device-1"
	deviceSvc.EXPECT().ListDevices(gomock.Any(), orgID, gomock.Any(), gomock.Nil()).DoAndReturn(
		func(_ context.Context, _ uuid.UUID, params domain.ListDevicesParams, _ any) (*domain.DeviceList, domain.Status) {
			require.Nil(t, params.Continue)
			return &domain.DeviceList{Items: []domain.Device{mappingScanTestDevice("device-1")}, Metadata: domain.ListMeta{Continue: &continueToken}}, domain.StatusOK()
		},
	)
	deviceSvc.EXPECT().ListDevices(gomock.Any(), orgID, gomock.Any(), gomock.Nil()).DoAndReturn(
		func(_ context.Context, _ uuid.UUID, params domain.ListDevicesParams, _ any) (*domain.DeviceList, domain.Status) {
			require.Equal(t, continueToken, lo.FromPtr(params.Continue))
			return &domain.DeviceList{Items: []domain.Device{mappingScanTestDevice("device-2")}}, domain.StatusOK()
		},
	)
	deviceSvc.EXPECT().ListDevices(gomock.Any(), orgID, gomock.Any(), gomock.Nil()).DoAndReturn(
		func(_ context.Context, _ uuid.UUID, params domain.ListDevicesParams, _ any) (*domain.DeviceList, domain.Status) {
			require.Nil(t, params.Continue)
			return &domain.DeviceList{Items: []domain.Device{mappingScanTestDevice("device-3")}}, domain.StatusOK()
		},
	)
	task, err := NewMappingScanTask(reconciler, deviceSvc, checkpoints, MappingScanConfig{PageSize: 100, TimeBudget: time.Second}, logrus.New())
	require.NoError(t, err)
	start := time.Now()
	clockCalls := 0
	task.now = func() time.Time {
		clockCalls++
		if clockCalls == 1 {
			return start
		}
		return start.Add(2 * time.Second)
	}

	// Save progress for both mappings at one shared cursor.
	task.Poll(ctx, orgID)
	reconciler.targets = []labelsyncmappingservice.MappingScanToken{newToken, unchangedToken}
	task.Poll(ctx, orgID)

	// The old token is fenced. The unchanged mapping resumes at the shared
	// cursor, while the changed mapping starts at the beginning next campaign.
	reconciler.targets = []labelsyncmappingservice.MappingScanToken{newToken}
	task.Poll(ctx, orgID)
	require.Equal(t, [][]labelsyncmappingservice.MappingScanToken{
		{unchangedToken},
		{newToken},
	}, reconciler.completed)
	require.Equal(t, []string{"device-1", "device-2", "device-3"}, reconciler.reconciled)
}

func TestMappingScanTaskRetriesDeviceFailureAfterDroppingAStaleMappingToken(t *testing.T) {
	ctx := context.Background()
	orgID := uuid.New()
	changedID := uuid.New()
	unchangedID := uuid.New()
	cursor := "after-device-1"
	oldToken := labelsyncmappingservice.MappingScanToken{MappingID: changedID, Generation: 1}
	newToken := labelsyncmappingservice.MappingScanToken{MappingID: changedID, Generation: 2}
	unchangedToken := labelsyncmappingservice.MappingScanToken{MappingID: unchangedID, Generation: 3, FailureRevision: 4}
	updatedUnchangedToken := unchangedToken
	updatedUnchangedToken.FailureRevision++
	initialCheckpoint, err := json.Marshal(mappingScanCheckpoint{
		Version:  mappingScanCheckpointVersion,
		Cursor:   &cursor,
		Mappings: []mappingScanProgress{{Token: oldToken}, {Token: unchangedToken}},
	})
	require.NoError(t, err)
	reconciler := &mappingScanReconcilerStub{
		targets:          []labelsyncmappingservice.MappingScanToken{newToken, unchangedToken},
		reconcileResults: map[string]labelsyncmappingservice.ReconciliationResult{},
		reconcileErr:     map[string]error{"device-2": errors.New("temporary device store failure")},
		failureTokens:    map[uuid.UUID]labelsyncmappingservice.MappingScanToken{unchangedID: updatedUnchangedToken},
		failureSaved:     map[uuid.UUID]bool{unchangedID: true},
		completeResults:  map[uuid.UUID]bool{changedID: true, unchangedID: true},
	}
	ctrl := gomock.NewController(t)
	checkpoints, checkpointHarness := newMappingScanCheckpointMock(ctrl, orgID, initialCheckpoint)
	deviceSvc := deviceservice.NewMockService(ctrl)
	deviceSvc.EXPECT().ListDevices(gomock.Any(), orgID, gomock.Any(), gomock.Nil()).DoAndReturn(
		func(_ context.Context, _ uuid.UUID, params domain.ListDevicesParams, _ any) (*domain.DeviceList, domain.Status) {
			require.Equal(t, cursor, lo.FromPtr(params.Continue))
			return &domain.DeviceList{Items: []domain.Device{mappingScanTestDevice("device-2")}}, domain.StatusOK()
		},
	).Times(2)
	deviceSvc.EXPECT().ListDevices(gomock.Any(), orgID, gomock.Any(), gomock.Nil()).DoAndReturn(
		func(_ context.Context, _ uuid.UUID, params domain.ListDevicesParams, _ any) (*domain.DeviceList, domain.Status) {
			require.Nil(t, params.Continue)
			return &domain.DeviceList{Items: []domain.Device{mappingScanTestDevice("device-1")}}, domain.StatusOK()
		},
	)
	task, err := NewMappingScanTask(reconciler, deviceSvc, checkpoints, MappingScanConfig{PageSize: 100, TimeBudget: time.Minute}, logrus.New())
	require.NoError(t, err)

	task.Poll(ctx, orgID)
	failedCheckpoint := decodeMappingScanCheckpointBytes(t, checkpointHarness.data)
	require.Equal(t, &cursor, failedCheckpoint.Cursor)
	require.Equal(t, []mappingScanProgress{{Token: updatedUnchangedToken}}, failedCheckpoint.Mappings)
	require.Len(t, reconciler.failures, 1)
	require.Equal(t, unchangedID, reconciler.failures[0].MappingID)
	require.Empty(t, reconciler.completed)

	reconciler.targets = []labelsyncmappingservice.MappingScanToken{newToken, updatedUnchangedToken}
	delete(reconciler.reconcileErr, "device-2")
	task.Poll(ctx, orgID)
	require.Equal(t, [][]labelsyncmappingservice.MappingScanToken{{updatedUnchangedToken}}, reconciler.completed)

	reconciler.targets = []labelsyncmappingservice.MappingScanToken{newToken}
	task.Poll(ctx, orgID)
	require.Equal(t, [][]labelsyncmappingservice.MappingScanToken{{updatedUnchangedToken}, {newToken}}, reconciler.completed)
}

func TestMappingScanTaskRestartsWhenCheckpointVersionIsUnsupported(t *testing.T) {
	ctx := context.Background()
	orgID := uuid.New()
	mappingID := uuid.New()
	token := labelsyncmappingservice.MappingScanToken{MappingID: mappingID, Generation: 1}
	ctrl := gomock.NewController(t)
	checkpointData := []byte(`{"version":99,"cursor":"must-not-resume","mappings":[]}`)
	checkpoints, checkpointHarness := newMappingScanCheckpointMock(ctrl, orgID, checkpointData)
	deviceSvc := deviceservice.NewMockService(ctrl)
	deviceSvc.EXPECT().ListDevices(gomock.Any(), orgID, gomock.Any(), gomock.Nil()).DoAndReturn(
		func(_ context.Context, _ uuid.UUID, params domain.ListDevicesParams, _ any) (*domain.DeviceList, domain.Status) {
			require.Nil(t, params.Continue)
			return &domain.DeviceList{}, domain.StatusOK()
		},
	)
	reconciler := &mappingScanReconcilerStub{
		targets:          []labelsyncmappingservice.MappingScanToken{token},
		reconcileResults: map[string]labelsyncmappingservice.ReconciliationResult{},
		reconcileErr:     map[string]error{},
		completeResults:  map[uuid.UUID]bool{mappingID: true},
	}
	task, err := NewMappingScanTask(reconciler, deviceSvc, checkpoints, MappingScanConfig{PageSize: 100, TimeBudget: time.Minute}, logrus.New())
	require.NoError(t, err)

	task.Poll(ctx, orgID)

	require.Equal(t, [][]labelsyncmappingservice.MappingScanToken{{token}}, reconciler.completed)
	require.Equal(t, mappingScanCheckpointVersion, decodeMappingScanCheckpointBytes(t, checkpointHarness.data).Version)
}

func mappingScanTestDevice(name string) domain.Device {
	return domain.Device{Metadata: domain.ObjectMeta{Name: lo.ToPtr(name)}}
}

func decodeMappingScanCheckpointBytes(t *testing.T, raw []byte) mappingScanCheckpoint {
	t.Helper()
	var checkpoint mappingScanCheckpoint
	require.NoError(t, json.Unmarshal(raw, &checkpoint))
	return checkpoint
}
