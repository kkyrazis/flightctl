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

type ReconciliationStore interface {
	ReconciliationSnapshotStore
	ApplyDeviceLabelReconciliation(context.Context, uuid.UUID, string, DeviceLabelReconciliationSnapshot, map[string]DesiredDeviceLabel) (DeviceLabelWriteResult, error)
	RecordReconciliationFailure(context.Context, uuid.UUID, ReconciliationFailure) (bool, error)
}

var ErrDeviceLabelReconciliationConflict = errors.New("device label reconciliation snapshot conflict")
