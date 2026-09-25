package labelsyncmapping

import (
	"context"
	"database/sql"
	"errors"
	"maps"
	"sort"
	"strconv"

	"github.com/flightctl/flightctl/internal/domain"
	"github.com/flightctl/flightctl/internal/flterrors"
	"github.com/flightctl/flightctl/internal/store"
	"github.com/flightctl/flightctl/internal/store/model"
	"github.com/google/uuid"
	"github.com/samber/lo"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
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

var _ ReconciliationStore = (*labelSyncMappingStore)(nil)

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

// ApplyDeviceLabelReconciliation commits label values and their mapping owners
// only when the device and mapping revisions still match the evaluated snapshot.
func (s *labelSyncMappingStore) ApplyDeviceLabelReconciliation(ctx context.Context, orgID uuid.UUID, deviceName string, snapshot DeviceLabelReconciliationSnapshot, desired map[string]DesiredDeviceLabel) (DeviceLabelWriteResult, error) {
	resourceVersion, err := strconv.ParseInt(lo.FromPtr(snapshot.Device.Metadata.ResourceVersion), 10, 64)
	if err != nil {
		return DeviceLabelWriteResult{}, flterrors.ErrIllegalResourceVersionFormat
	}
	labels := deviceLabelValues(desired)
	keys := reconciliationKeys(snapshot, desired)
	writeResult := DeviceLabelWriteResult{}

	err = store.RunInTransaction(ctx, s.db, func(tx *gorm.DB) error {
		if err := lockLabelKeys(tx, orgID, domain.LabelSyncMappingDevice, keys); err != nil {
			return err
		}

		var device model.Device
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("org_id = ? AND name = ?", orgID, deviceName).Take(&device).Error; err != nil {
			return store.ErrorFromGormError(err)
		}
		if lo.FromPtr(device.ResourceVersion) != resourceVersion || !maps.Equal(device.Labels, lo.FromPtr(snapshot.Device.Metadata.Labels)) {
			return ErrDeviceLabelReconciliationConflict
		}

		var currentRows []model.DeviceLabel
		if err := tx.Where("org_id = ? AND device_name = ?", orgID, deviceName).Order("label_key ASC").Find(&currentRows).Error; err != nil {
			return err
		}
		if !deviceLabelRowsMatchSnapshot(currentRows, snapshot.DeviceLabels) {
			return ErrDeviceLabelReconciliationConflict
		}

		if err := lockState(tx, orgID, domain.LabelSyncMappingDevice); err != nil {
			return err
		}
		var state model.LabelSyncState
		if err := tx.Where("org_id = ? AND resource_type = ?", orgID, domain.LabelSyncMappingDevice).Take(&state).Error; err != nil {
			return err
		}
		if state.Revision != snapshot.MappingRevision {
			return ErrDeviceLabelReconciliationConflict
		}

		writeResult.LabelsChanged = !maps.Equal(device.Labels, labels)
		if writeResult.LabelsChanged {
			if err := updateDeviceLabelValues(tx, orgID, deviceName, resourceVersion, labels); err != nil {
				return err
			}
		}
		return updateDeviceLabelOwners(tx, orgID, deviceName, snapshot.DeviceLabels, desired, writeResult.LabelsChanged)
	})
	if err != nil {
		return DeviceLabelWriteResult{}, err
	}
	return writeResult, nil
}

func reconciliationKeys(snapshot DeviceLabelReconciliationSnapshot, desired map[string]DesiredDeviceLabel) []string {
	keys := make([]string, 0, len(snapshot.DeviceLabels)+len(lo.FromPtr(snapshot.Device.Metadata.Labels))+len(desired))
	seen := make(map[string]struct{}, cap(keys))
	for _, label := range snapshot.DeviceLabels {
		seen[label.Key] = struct{}{}
	}
	for key := range lo.FromPtr(snapshot.Device.Metadata.Labels) {
		seen[key] = struct{}{}
	}
	for key := range desired {
		seen[key] = struct{}{}
	}
	for key := range seen {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func deviceLabelValues(desired map[string]DesiredDeviceLabel) map[string]string {
	labels := make(map[string]string, len(desired))
	for key, label := range desired {
		labels[key] = label.Value
	}
	return labels
}

func deviceLabelRowsMatchSnapshot(current []model.DeviceLabel, expected []DeviceLabelOwnership) bool {
	if len(current) != len(expected) {
		return false
	}
	currentByKey := make(map[string]model.DeviceLabel, len(current))
	for _, label := range current {
		currentByKey[label.LabelKey] = label
	}
	for _, label := range expected {
		currentLabel, ok := currentByKey[label.Key]
		if !ok || currentLabel.LabelValue != label.Value || !sameMappingID(currentLabel.LabelSyncMappingID, label.MappingID) {
			return false
		}
	}
	return true
}

func sameMappingID(left, right *uuid.UUID) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func updateDeviceLabelValues(tx *gorm.DB, orgID uuid.UUID, deviceName string, resourceVersion int64, labels map[string]string) error {
	var alias *string
	if value, ok := labels["alias"]; ok {
		alias = &value
	}
	result := tx.Model(&model.Device{}).
		Where("org_id = ? AND name = ? AND resource_version = ?", orgID, deviceName, resourceVersion).
		Updates(map[string]interface{}{
			"alias":            alias,
			"labels":           model.MakeJSONMap(labels),
			"resource_version": gorm.Expr("resource_version + 1"),
		})
	if result.Error != nil {
		return store.ErrorFromGormError(result.Error)
	}
	if result.RowsAffected != 1 {
		return ErrDeviceLabelReconciliationConflict
	}
	return nil
}

func updateDeviceLabelOwners(tx *gorm.DB, orgID uuid.UUID, deviceName string, current []DeviceLabelOwnership, desired map[string]DesiredDeviceLabel, labelsChanged bool) error {
	currentByKey := make(map[string]DeviceLabelOwnership, len(current))
	for _, label := range current {
		currentByKey[label.Key] = label
	}
	keys := make([]string, 0, len(desired))
	for key := range desired {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		label := desired[key]
		previous, exists := currentByKey[key]
		if exists && sameMappingID(previous.MappingID, label.MappingID) {
			continue
		}
		if !exists && label.MappingID == nil && labelsChanged {
			continue
		}

		write := tx.Model(&model.DeviceLabel{}).
			Where("org_id = ? AND device_name = ? AND label_key = ?", orgID, deviceName, key).
			Update("label_sync_mapping_id", label.MappingID)
		if write.Error != nil {
			return store.ErrorFromGormError(write.Error)
		}
		if write.RowsAffected == 0 {
			row := model.DeviceLabel{
				OrgID:              orgID,
				DeviceName:         deviceName,
				LabelKey:           key,
				LabelValue:         label.Value,
				LabelSyncMappingID: label.MappingID,
			}
			if err := tx.Clauses(clause.OnConflict{
				Columns:   []clause.Column{{Name: "org_id"}, {Name: "device_name"}, {Name: "label_key"}},
				DoUpdates: clause.AssignmentColumns([]string{"label_value", "label_sync_mapping_id"}),
			}).Create(&row).Error; err != nil {
				return store.ErrorFromGormError(err)
			}
		}
	}
	return nil
}
