package labelsyncmapping

import (
	"context"
	"errors"

	"github.com/google/uuid"
)

type DesiredDeviceLabel struct {
	Value     string
	MappingID *uuid.UUID
}

type DeviceLabelWriteResult struct {
	LabelsChanged bool
}

type ReconciliationFailure struct {
	MappingID        uuid.UUID
	Generation       int64
	DeletionRevision *int64
	Message          string
}

type MappingScanRecord struct {
	MappingID        uuid.UUID
	Generation       int64
	DeletionRevision *int64
	FailureRevision  int64
}

type MappingScanStore interface {
	ListMappingScanTargets(context.Context, uuid.UUID) ([]MappingScanRecord, error)
	RecordMappingScanFailure(context.Context, uuid.UUID, ReconciliationFailure) (MappingScanRecord, bool, error)
	CompleteMappingScan(context.Context, uuid.UUID, []MappingScanRecord) (map[uuid.UUID]bool, error)
}

type ReconciliationStore interface {
	ReconciliationSnapshotStore
	MappingScanStore
	ApplyDeviceLabelReconciliation(context.Context, uuid.UUID, string, DeviceLabelReconciliationSnapshot, map[string]DesiredDeviceLabel) (DeviceLabelWriteResult, error)
	RecordReconciliationFailure(context.Context, uuid.UUID, ReconciliationFailure) (bool, error)
}

var ErrDeviceLabelReconciliationConflict = errors.New("device label reconciliation snapshot conflict")
