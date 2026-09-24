package labelsyncmapping

import (
	"context"
	"database/sql"
	"errors"

	"github.com/flightctl/flightctl/internal/domain"
	"github.com/flightctl/flightctl/internal/store"
	"github.com/flightctl/flightctl/internal/store/model"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type DeviceLabelOwnership struct {
	Key       string
	Value     string
	MappingID *uuid.UUID
}

type ReconciliationMapping struct {
	ID      uuid.UUID
	Mapping domain.LabelSyncMapping
}

type DeviceLabelReconciliationSnapshot struct {
	Device          domain.Device
	DeviceLabels    []DeviceLabelOwnership
	Mappings        []ReconciliationMapping
	MappingRevision int64
}

type ReconciliationSnapshotStore interface {
	LoadDeviceLabelReconciliationSnapshot(context.Context, uuid.UUID, string) (DeviceLabelReconciliationSnapshot, error)
}

func (s *labelSyncMappingStore) LoadDeviceLabelReconciliationSnapshot(ctx context.Context, orgID uuid.UUID, deviceName string) (DeviceLabelReconciliationSnapshot, error) {
	var snapshot DeviceLabelReconciliationSnapshot
	err := s.getDB(ctx).Transaction(func(tx *gorm.DB) error {
		var device model.Device
		if err := tx.Where("org_id = ? AND name = ?", orgID, deviceName).Take(&device).Error; err != nil {
			return store.ErrorFromGormError(err)
		}
		resource, err := device.ToApiResource()
		if err != nil {
			return err
		}
		snapshot.Device = *resource

		var deviceLabels []model.DeviceLabel
		if err := tx.Where("org_id = ? AND device_name = ?", orgID, deviceName).
			Order("label_key ASC").Find(&deviceLabels).Error; err != nil {
			return err
		}
		snapshot.DeviceLabels = make([]DeviceLabelOwnership, len(deviceLabels))
		for i, label := range deviceLabels {
			snapshot.DeviceLabels[i] = DeviceLabelOwnership{
				Key:       label.LabelKey,
				Value:     label.LabelValue,
				MappingID: label.LabelSyncMappingID,
			}
		}

		var mappingRows []model.LabelSyncMapping
		if err := tx.Where("org_id = ? AND spec IS NOT NULL AND spec->>'resourceType' = ?", orgID, domain.LabelSyncMappingDevice).
			Order("name ASC").Find(&mappingRows).Error; err != nil {
			return err
		}
		snapshot.Mappings = make([]ReconciliationMapping, len(mappingRows))
		for i, mapping := range mappingRows {
			resource, err := mapping.ToApiResource()
			if err != nil {
				return err
			}
			snapshot.Mappings[i] = ReconciliationMapping{ID: mapping.ID, Mapping: *resource}
		}

		var state model.LabelSyncState
		err = tx.Where("org_id = ? AND resource_type = ?", orgID, domain.LabelSyncMappingDevice).Take(&state).Error
		if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		if err == nil {
			snapshot.MappingRevision = state.Revision
		}
		return nil
	}, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return DeviceLabelReconciliationSnapshot{}, err
	}
	return snapshot, nil
}
