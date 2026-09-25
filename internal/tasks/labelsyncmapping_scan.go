package tasks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/flightctl/flightctl/internal/config"
	"github.com/flightctl/flightctl/internal/domain"
	"github.com/flightctl/flightctl/internal/flterrors"
	checkpointservice "github.com/flightctl/flightctl/internal/service/checkpoint"
	deviceservice "github.com/flightctl/flightctl/internal/service/device"
	labelsyncmappingservice "github.com/flightctl/flightctl/internal/service/labelsyncmapping"
	"github.com/google/uuid"
	"github.com/samber/lo"
	"github.com/sirupsen/logrus"
)

const (
	mappingScanCheckpointConsumer = "label-sync-mapping-scan"
	mappingScanCheckpointVersion  = 1
	maxMappingScanPageSize        = config.MaxLabelMappingScanPageSize
)

// LabelMappingScanConfig bounds the amount of device work performed by one poll.
type LabelMappingScanConfig struct {
	PageSize   int
	TimeBudget time.Duration
}

type mappingScanReconciler interface {
	ListMappingScanTargets(context.Context, uuid.UUID) ([]labelsyncmappingservice.MappingScanToken, error)
	ReconcileDeviceLabels(context.Context, uuid.UUID, string) (labelsyncmappingservice.ReconciliationResult, error)
	RecordMappingScanFailure(context.Context, uuid.UUID, labelsyncmappingservice.MappingOutcome) (labelsyncmappingservice.MappingScanToken, bool, error)
	CompleteMappingScan(context.Context, uuid.UUID, []labelsyncmappingservice.MappingScanToken) (map[uuid.UUID]bool, error)
}

type mappingScanCheckpoint struct {
	Version      int                   `json:"version"`
	Cursor       *string               `json:"cursor,omitempty"`
	ScanComplete bool                  `json:"scanComplete,omitempty"`
	Mappings     []mappingScanProgress `json:"mappings"`
}

type mappingScanProgress struct {
	Token  labelsyncmappingservice.MappingScanToken `json:"token"`
	Failed bool                                     `json:"failed,omitempty"`
}

// LabelMappingScanTask runs a resumable device-label mapping scan for one org.
type LabelMappingScanTask struct {
	log         logrus.FieldLogger
	reconciler  mappingScanReconciler
	deviceSvc   deviceservice.Service
	checkpoints checkpointservice.Service
	config      LabelMappingScanConfig
}

func NewLabelMappingScanTask(
	reconciler mappingScanReconciler,
	deviceSvc deviceservice.Service,
	checkpoints checkpointservice.Service,
	config LabelMappingScanConfig,
	log logrus.FieldLogger,
) (*LabelMappingScanTask, error) {
	if reconciler == nil || deviceSvc == nil || checkpoints == nil {
		return nil, errors.New("mapping scan task requires a reconciler, device service, and checkpoint service")
	}
	if config.PageSize < 1 || config.PageSize > maxMappingScanPageSize {
		return nil, fmt.Errorf("mapping scan page size must be between 1 and %d", maxMappingScanPageSize)
	}
	if config.TimeBudget <= 0 {
		return nil, errors.New("mapping scan time budget must be positive")
	}
	if log == nil {
		log = logrus.New()
	}
	return &LabelMappingScanTask{
		log:         log,
		reconciler:  reconciler,
		deviceSvc:   deviceSvc,
		checkpoints: checkpoints,
		config:      config,
	}, nil
}

// Poll advances one organization's mapping scan by whole device pages.
func (t *LabelMappingScanTask) Poll(ctx context.Context, orgID uuid.UUID) {
	targets, err := t.reconciler.ListMappingScanTargets(ctx, orgID)
	if err != nil {
		t.log.WithError(err).WithField("orgID", orgID).Error("Failed to list mapping scan targets")
		return
	}

	checkpoint, found, valid, err := t.loadCheckpoint(ctx, orgID)
	if err != nil {
		t.log.WithError(err).WithField("orgID", orgID).Error("Failed to load mapping scan checkpoint")
		return
	}
	if found && !valid {
		t.log.WithField("orgID", orgID).Warn("Mapping scan checkpoint is invalid; restarting the campaign")
	}
	if len(targets) == 0 {
		if found && (!valid || len(checkpoint.Mappings) > 0 || checkpoint.Cursor != nil || checkpoint.ScanComplete) {
			t.persistIdleCheckpoint(ctx, orgID)
		}
		return
	}

	checkpoint = mappingScanCampaignCheckpoint(targets, checkpoint, found && valid)
	if len(checkpoint.Mappings) == 0 {
		return
	}

	startedAt := time.Now()
	for {
		if err := ctx.Err(); err != nil {
			t.log.WithError(err).WithField("orgID", orgID).Warn("Mapping scan stopped before the next page")
			return
		}
		if checkpoint.ScanComplete {
			t.completeCampaign(ctx, orgID, checkpoint)
			return
		}

		devices, ok := t.listDevicePage(ctx, orgID, checkpoint.Cursor)
		if !ok {
			return
		}
		retryPage, err := t.processDevicePage(ctx, orgID, &checkpoint, devices)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				t.log.WithError(err).WithField("orgID", orgID).Warn("Mapping scan stopped during a device page")
			} else {
				t.log.WithError(err).WithField("orgID", orgID).Error("Failed to reconcile a mapping scan device page")
			}
			return
		}
		if retryPage {
			if err := t.persistCheckpoint(ctx, orgID, checkpoint); err != nil {
				t.log.WithError(err).WithField("orgID", orgID).Error("Failed to persist mapping scan checkpoint after a device failure")
			}
			return
		}
		if devices.Metadata.Continue != nil && checkpoint.Cursor != nil && *devices.Metadata.Continue == *checkpoint.Cursor {
			t.log.WithFields(logrus.Fields{"orgID": orgID, "cursor": *checkpoint.Cursor}).Error("Device list made no progress during mapping scan")
			return
		}
		checkpoint.Cursor = cloneString(devices.Metadata.Continue)
		checkpoint.ScanComplete = devices.Metadata.Continue == nil
		if err := t.persistCheckpoint(ctx, orgID, checkpoint); err != nil {
			t.log.WithError(err).WithField("orgID", orgID).Error("Failed to persist mapping scan checkpoint")
			return
		}
		if checkpoint.ScanComplete {
			t.completeCampaign(ctx, orgID, checkpoint)
			return
		}
		if time.Since(startedAt) >= t.config.TimeBudget {
			t.log.WithFields(logrus.Fields{"orgID": orgID, "pageSize": t.config.PageSize, "timeBudget": t.config.TimeBudget}).Info("Mapping scan reached its execution time budget")
			return
		}
	}
}

func (t *LabelMappingScanTask) listDevicePage(ctx context.Context, orgID uuid.UUID, cursor *string) (*domain.DeviceList, bool) {
	limit := int32(t.config.PageSize)
	devices, status := t.deviceSvc.ListDevices(ctx, orgID, domain.ListDevicesParams{
		Limit:    &limit,
		Continue: cloneString(cursor),
	}, nil)
	if status.Code >= http.StatusBadRequest {
		t.log.WithField("orgID", orgID).Errorf("Failed to list devices for mapping scan: %s", status.Message)
		return nil, false
	}
	return devices, true
}

func (t *LabelMappingScanTask) processDevicePage(ctx context.Context, orgID uuid.UUID, checkpoint *mappingScanCheckpoint, devices *domain.DeviceList) (bool, error) {
	retryPage := false
	for _, device := range devices.Items {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		deviceName := *device.Metadata.Name
		result, reconcileErr := t.reconciler.ReconcileDeviceLabels(ctx, orgID, deviceName)
		if errors.Is(reconcileErr, flterrors.ErrResourceNotFound) && len(result.MappingOutcomes) == 0 {
			continue
		}
		if err := t.recordDeviceOutcomes(ctx, orgID, checkpoint, result.MappingOutcomes, reconcileErr); err != nil {
			return false, fmt.Errorf("reconcile mapping scan device %s: %w", deviceName, err)
		}
		if reconcileErr != nil {
			retryPage = true
		}
	}
	return retryPage, nil
}

func (t *LabelMappingScanTask) recordDeviceOutcomes(
	ctx context.Context,
	orgID uuid.UUID,
	checkpoint *mappingScanCheckpoint,
	outcomes []labelsyncmappingservice.MappingOutcome,
	reconcileErr error,
) error {
	byID := make(map[uuid.UUID]labelsyncmappingservice.MappingOutcome, len(outcomes))
	for _, outcome := range outcomes {
		byID[outcome.MappingID] = outcome
	}
	if errors.Is(reconcileErr, context.Canceled) || errors.Is(reconcileErr, context.DeadlineExceeded) {
		return reconcileErr
	}

	for i := range checkpoint.Mappings {
		progress := &checkpoint.Mappings[i]
		if progress.Failed {
			continue
		}
		outcome, hasOutcome := byID[progress.Token.MappingID]
		failure := reconcileErr
		if hasOutcome {
			failure = errors.Join(failure, outcome.Err)
		}
		if failure == nil {
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		outcome.MappingID = progress.Token.MappingID
		outcome.Generation = progress.Token.Generation
		outcome.DeletionRevision = cloneScanRevision(progress.Token.DeletionRevision)
		outcome.Err = failure
		updatedToken, saved, err := t.reconciler.RecordMappingScanFailure(ctx, orgID, outcome)
		if err != nil {
			return fmt.Errorf("record failure for mapping %s: %w", progress.Token.MappingID, err)
		}
		if saved {
			progress.Token = updatedToken
		}
		if reconcileErr == nil {
			progress.Failed = true
		}
	}
	return nil
}

func (t *LabelMappingScanTask) completeCampaign(ctx context.Context, orgID uuid.UUID, checkpoint mappingScanCheckpoint) {
	tokens := make([]labelsyncmappingservice.MappingScanToken, 0, len(checkpoint.Mappings))
	for _, progress := range checkpoint.Mappings {
		if !progress.Failed {
			tokens = append(tokens, progress.Token)
		}
	}
	if len(tokens) > 0 {
		completed, err := t.reconciler.CompleteMappingScan(ctx, orgID, tokens)
		if err != nil {
			t.log.WithError(err).WithField("orgID", orgID).Error("Failed to complete mapping scan")
			return
		}
		for _, token := range tokens {
			if !completed[token.MappingID] {
				t.log.WithFields(logrus.Fields{"orgID": orgID, "mappingID": token.MappingID}).Info("Mapping scan completion was fenced; it will be retried in a later campaign")
			}
		}
	}
	t.persistIdleCheckpoint(ctx, orgID)
}

func (t *LabelMappingScanTask) loadCheckpoint(ctx context.Context, orgID uuid.UUID) (mappingScanCheckpoint, bool, bool, error) {
	data, status := t.checkpoints.GetCheckpoint(ctx, mappingScanCheckpointConsumer, orgID.String())
	if status.Code == http.StatusNotFound {
		return mappingScanCheckpoint{}, false, true, nil
	}
	if status.Code >= http.StatusBadRequest {
		return mappingScanCheckpoint{}, false, false, fmt.Errorf("checkpoint service returned %d: %s", status.Code, status.Message)
	}
	var checkpoint mappingScanCheckpoint
	if err := json.Unmarshal(data, &checkpoint); err != nil || !validMappingScanCheckpoint(checkpoint) {
		return mappingScanCheckpoint{}, true, false, nil
	}
	return checkpoint, true, true, nil
}

func validMappingScanCheckpoint(checkpoint mappingScanCheckpoint) bool {
	if checkpoint.Version != mappingScanCheckpointVersion || (checkpoint.ScanComplete && checkpoint.Cursor != nil) {
		return false
	}
	seen := make(map[uuid.UUID]struct{}, len(checkpoint.Mappings))
	for _, progress := range checkpoint.Mappings {
		if progress.Token.MappingID == uuid.Nil {
			return false
		}
		if _, exists := seen[progress.Token.MappingID]; exists {
			return false
		}
		seen[progress.Token.MappingID] = struct{}{}
	}
	return true
}

func mappingScanCampaignCheckpoint(
	targets []labelsyncmappingservice.MappingScanToken,
	checkpoint mappingScanCheckpoint,
	resume bool,
) mappingScanCheckpoint {
	current := make(map[uuid.UUID]labelsyncmappingservice.MappingScanToken, len(targets))
	for _, target := range targets {
		current[target.MappingID] = target
	}
	if resume && len(checkpoint.Mappings) > 0 {
		remaining := make([]mappingScanProgress, 0, len(checkpoint.Mappings))
		for _, progress := range checkpoint.Mappings {
			if currentToken, stillEligible := current[progress.Token.MappingID]; stillEligible && mappingScanTokensMatch(progress.Token, currentToken) {
				remaining = append(remaining, cloneMappingScanProgress(progress))
			}
		}
		if len(remaining) > 0 {
			checkpoint.Mappings = remaining
			return checkpoint
		}
	}
	checkpoint = mappingScanCheckpoint{Version: mappingScanCheckpointVersion, Mappings: make([]mappingScanProgress, 0, len(targets))}
	for _, target := range targets {
		checkpoint.Mappings = append(checkpoint.Mappings, mappingScanProgress{Token: cloneMappingScanToken(target)})
	}
	return checkpoint
}

func mappingScanTokensMatch(left, right labelsyncmappingservice.MappingScanToken) bool {
	if left.MappingID != right.MappingID || left.Generation != right.Generation || left.FailureRevision != right.FailureRevision {
		return false
	}
	if left.DeletionRevision == nil || right.DeletionRevision == nil {
		return left.DeletionRevision == nil && right.DeletionRevision == nil
	}
	return *left.DeletionRevision == *right.DeletionRevision
}

func (t *LabelMappingScanTask) persistCheckpoint(ctx context.Context, orgID uuid.UUID, checkpoint mappingScanCheckpoint) error {
	data, err := json.Marshal(checkpoint)
	if err != nil {
		return err
	}
	status := t.checkpoints.SetCheckpoint(ctx, mappingScanCheckpointConsumer, orgID.String(), data)
	if status.Code >= http.StatusBadRequest {
		return fmt.Errorf("checkpoint service returned %d: %s", status.Code, status.Message)
	}
	return nil
}

func (t *LabelMappingScanTask) persistIdleCheckpoint(ctx context.Context, orgID uuid.UUID) {
	if err := t.persistCheckpoint(ctx, orgID, mappingScanCheckpoint{Version: mappingScanCheckpointVersion, Mappings: []mappingScanProgress{}}); err != nil {
		t.log.WithError(err).WithField("orgID", orgID).Error("Failed to clear mapping scan checkpoint")
	}
}

func cloneMappingScanProgress(progress mappingScanProgress) mappingScanProgress {
	progress.Token = cloneMappingScanToken(progress.Token)
	return progress
}

func cloneMappingScanToken(token labelsyncmappingservice.MappingScanToken) labelsyncmappingservice.MappingScanToken {
	token.DeletionRevision = cloneScanRevision(token.DeletionRevision)
	return token
}

func cloneScanRevision(value *int64) *int64 {
	if value == nil {
		return nil
	}
	return lo.ToPtr(*value)
}

func cloneString(value *string) *string {
	if value == nil {
		return nil
	}
	return lo.ToPtr(*value)
}
