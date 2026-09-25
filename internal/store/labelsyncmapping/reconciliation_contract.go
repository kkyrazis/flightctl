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

type ReconciliationStore interface {
	ReconciliationSnapshotStore
	ApplyDeviceLabelReconciliation(context.Context, uuid.UUID, string, DeviceLabelReconciliationSnapshot, map[string]DesiredDeviceLabel) (DeviceLabelWriteResult, error)
}

var ErrDeviceLabelReconciliationConflict = errors.New("device label reconciliation snapshot conflict")
