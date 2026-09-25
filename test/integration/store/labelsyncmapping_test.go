package store_test

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"time"

	api "github.com/flightctl/flightctl/api/core/v1beta1"
	"github.com/flightctl/flightctl/internal/config"
	"github.com/flightctl/flightctl/internal/domain"
	"github.com/flightctl/flightctl/internal/flterrors"
	labelsyncmappingservice "github.com/flightctl/flightctl/internal/service/labelsyncmapping"
	"github.com/flightctl/flightctl/internal/store"
	devicestore "github.com/flightctl/flightctl/internal/store/device"
	labelsyncmappingstore "github.com/flightctl/flightctl/internal/store/labelsyncmapping"
	"github.com/flightctl/flightctl/internal/store/model"
	organizationstore "github.com/flightctl/flightctl/internal/store/organization"
	flightlog "github.com/flightctl/flightctl/pkg/log"
	testutil "github.com/flightctl/flightctl/test/util"
	"github.com/flightctl/flightctl/test/util/testdb"
	"github.com/google/uuid"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/samber/lo"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var _ = Describe("LabelSyncMappingStore", func() {
	var (
		ctx          context.Context
		log          *logrus.Logger
		cfg          *config.Config
		dbName       string
		db           *gorm.DB
		orgID        uuid.UUID
		otherOrgID   uuid.UUID
		deviceStore  devicestore.Store
		mappingStore labelsyncmappingstore.Store
	)

	BeforeEach(func() {
		ctx = testutil.StartSpecTracerForGinkgo(suiteCtx)
		log = flightlog.InitLogs()
		var err error
		cfg, dbName, db, err = testdb.CreateTestDB(ctx, log, "", store.InitDB)
		Expect(err).NotTo(HaveOccurred())
		deviceStore = devicestore.NewDeviceStore(db, log.WithField("pkg", "device-store"))
		mappingStore = labelsyncmappingstore.NewStore(db, log.WithField("pkg", "labelsyncmapping-store"))
		organizationStore := organizationstore.NewOrganizationStore(db)
		orgID = uuid.New()
		otherOrgID = uuid.New()
		Expect(testutil.CreateTestOrganization(ctx, organizationStore, orgID)).To(Succeed())
		Expect(testutil.CreateTestOrganization(ctx, organizationStore, otherOrgID)).To(Succeed())
	})

	AfterEach(func() {
		Expect(testdb.DeleteTestDB(ctx, log, cfg, db, dbName)).To(Succeed())
	})

	It("When mappings share an organization it should persist them independently and advance the revision", func() {
		first, err := mappingStore.Create(ctx, orgID, newLabelSyncMapping("architecture", "architecture"))
		Expect(err).NotTo(HaveOccurred())
		Expect(lo.FromPtr(first.Metadata.Generation)).To(Equal(int64(1)))
		second, err := mappingStore.Create(ctx, orgID, newLabelSyncMapping("site", "site"))
		Expect(err).NotTo(HaveOccurred())
		Expect(lo.FromPtr(second.Metadata.Name)).To(Equal("site"))
		revision, err := labelSyncRevision(ctx, db, orgID, domain.LabelSyncMappingDevice)
		Expect(err).NotTo(HaveOccurred())
		Expect(revision).To(Equal(int64(2)))
		list, err := mappingStore.List(ctx, orgID, store.ListParams{})
		Expect(err).NotTo(HaveOccurred())
		Expect(list.Items).To(HaveLen(2))
	})

	It("When mappings are stored it should persist stable identity, lifecycle revisions, and DeviceLabel ownership", func() {
		for _, column := range []string{"id", "failure_revision", "deletion_revision", "deletion_timestamp"} {
			Expect(db.Migrator().HasColumn("label_sync_mappings", column)).To(BeTrue(), "missing label_sync_mappings.%s", column)
		}
		Expect(db.Migrator().HasColumn("device_labels", "label_sync_mapping_id")).To(BeTrue())
		Expect(db.Migrator().HasIndex("label_sync_mappings", "label_sync_mappings_org_id_id_uq")).To(BeTrue())
		Expect(db.Migrator().HasIndex("label_sync_mappings", "label_sync_mappings_org_resource_destination_key_uq")).To(BeTrue())
		Expect(db.Migrator().HasIndex("device_labels", "device_labels_label_sync_mapping_idx")).To(BeTrue())
		Expect(db.Migrator().HasIndex("device_labels", "device_labels_label_sync_key_idx")).To(BeTrue())
		Expect(db.Migrator().HasConstraint(&model.DeviceLabel{}, "device_labels_label_sync_mapping_fk")).To(BeTrue())

		first, err := mappingStore.Create(ctx, orgID, newLabelSyncMapping("scalar", "systeminfo/architecture"))
		Expect(err).NotTo(HaveOccurred())
		mapMapping := newLabelSyncMapping("map", "")
		mapMapping.Spec.Key = nil
		_, err = mappingStore.Create(ctx, orgID, mapMapping)
		Expect(err).NotTo(HaveOccurred())

		var firstIdentity struct {
			ID               uuid.UUID
			FailureRevision  int64
			DeletionRevision *int64
		}
		Expect(db.Raw("SELECT id, failure_revision, deletion_revision FROM label_sync_mappings WHERE org_id = ? AND name = ?", orgID, "scalar").Scan(&firstIdentity).Error).To(Succeed())
		Expect(firstIdentity.ID).NotTo(Equal(uuid.Nil))
		Expect(firstIdentity.FailureRevision).To(Equal(int64(0)))
		Expect(firstIdentity.DeletionRevision).To(BeNil())
		Expect(lo.FromPtr(first.Metadata.Name)).To(Equal("scalar"))
	})

	It("When a worker reports a mapping failure it should conditionally degrade only the captured generation", func() {
		mappingHandler := labelsyncmappingservice.NewServiceHandler(mappingStore)
		created, status := mappingHandler.CreateLabelSyncMapping(ctx, orgID, *newLabelSyncMapping("worker-failure", "architecture"))
		Expect(status.Code).To(Equal(int32(201)))
		_, status = mappingHandler.CreateLabelSyncMapping(ctx, orgID, *newLabelSyncMapping("unaffected", "site"))
		Expect(status.Code).To(Equal(int32(201)))
		var err error
		var identity model.LabelSyncMapping
		Expect(db.Where("org_id = ? AND name = ?", orgID, "worker-failure").Take(&identity).Error).To(Succeed())
		failureStore, ok := mappingStore.(labelsyncmappingstore.ReconciliationStore)
		Expect(ok).To(BeTrue())
		failure := labelsyncmappingstore.ReconciliationFailure{
			MappingID:        identity.ID,
			Generation:       lo.FromPtr(created.Metadata.Generation),
			DeletionRevision: identity.DeletionRevision,
			Message:          "expression evaluation failed",
		}

		updated, err := failureStore.RecordReconciliationFailure(ctx, orgID, failure)
		Expect(err).NotTo(HaveOccurred())
		Expect(updated).To(BeTrue())
		degraded, err := mappingStore.Get(ctx, orgID, "worker-failure")
		Expect(err).NotTo(HaveOccurred())
		Expect(lo.FromPtr(degraded.Status.Conditions)).To(ContainElement(SatisfyAll(
			HaveField("Type", domain.ConditionType("Ready")),
			HaveField("Status", domain.ConditionStatusFalse),
			HaveField("Reason", "Degraded"),
			HaveField("Message", "expression evaluation failed"),
			HaveField("ObservedGeneration", lo.ToPtr(int64(1))),
		)))
		unaffected, err := mappingStore.Get(ctx, orgID, "unaffected")
		Expect(err).NotTo(HaveOccurred())
		Expect(lo.FromPtr(unaffected.Status.Conditions)[0].Reason).To(Equal("Pending"))
		var unaffectedIdentity model.LabelSyncMapping
		Expect(db.Select("failure_revision").Where("org_id = ? AND name = ?", orgID, "unaffected").Take(&unaffectedIdentity).Error).To(Succeed())
		Expect(unaffectedIdentity.FailureRevision).To(BeZero())

		updated, err = failureStore.RecordReconciliationFailure(ctx, orgID, failure)
		Expect(err).NotTo(HaveOccurred())
		Expect(updated).To(BeTrue())
		Expect(db.Select("failure_revision").Where("org_id = ? AND id = ?", orgID, identity.ID).Take(&identity).Error).To(Succeed())
		Expect(identity.FailureRevision).To(Equal(int64(2)))

		staleFailure := failure
		staleFailure.Generation++
		updated, err = failureStore.RecordReconciliationFailure(ctx, orgID, staleFailure)
		Expect(err).NotTo(HaveOccurred())
		Expect(updated).To(BeFalse())
		Expect(db.Select("failure_revision").Where("org_id = ? AND id = ?", orgID, identity.ID).Take(&identity).Error).To(Succeed())
		Expect(identity.FailureRevision).To(Equal(int64(2)))

		deleted, err := mappingStore.Delete(ctx, orgID, "worker-failure")
		Expect(err).NotTo(HaveOccurred())
		Expect(deleted).To(BeTrue())
		updated, err = failureStore.RecordReconciliationFailure(ctx, orgID, failure)
		Expect(err).NotTo(HaveOccurred())
		Expect(updated).To(BeFalse())
		Expect(db.Select("failure_revision").Where("org_id = ? AND id = ?", orgID, identity.ID).Take(&identity).Error).To(Succeed())
		Expect(identity.FailureRevision).To(Equal(int64(2)))
	})

	It("When mapping names or keys belong to another organization it should isolate them", func() {
		_, err := mappingStore.Create(ctx, orgID, newLabelSyncMapping("architecture", "architecture"))
		Expect(err).NotTo(HaveOccurred())
		_, err = mappingStore.Create(ctx, otherOrgID, newLabelSyncMapping("architecture", "architecture"))
		Expect(err).NotTo(HaveOccurred())
		list, err := mappingStore.List(ctx, otherOrgID, store.ListParams{})
		Expect(err).NotTo(HaveOccurred())
		Expect(list.Items).To(HaveLen(1))
	})

	It("When a scalar key is reserved in an organization it should reject a second mapping", func() {
		_, err := mappingStore.Create(ctx, orgID, newLabelSyncMapping("first", "systeminfo/architecture"))
		Expect(err).NotTo(HaveOccurred())
		_, err = mappingStore.Create(ctx, orgID, newLabelSyncMapping("second", "systeminfo/architecture"))
		Expect(err).To(MatchError(flterrors.ErrLabelSyncConflict))
	})

	It("When a mapping changes and begins deletion it should retain the tombstone and advance the organization revision", func() {
		mapping, err := mappingStore.Create(ctx, orgID, newLabelSyncMapping("architecture", "architecture"))
		Expect(err).NotTo(HaveOccurred())
		mapping.Spec.Expression = "status.systemInfo.architecture + '-v2'"
		updated, _, err := mappingStore.Update(ctx, orgID, mapping)
		Expect(err).NotTo(HaveOccurred())
		Expect(lo.FromPtr(updated.Metadata.Generation)).To(Equal(int64(2)))
		deleted, err := mappingStore.Delete(ctx, orgID, "architecture")
		Expect(err).NotTo(HaveOccurred())
		Expect(deleted).To(BeTrue())
		terminating, err := mappingStore.Get(ctx, orgID, "architecture")
		Expect(err).NotTo(HaveOccurred())
		Expect(terminating.Metadata.DeletionTimestamp).NotTo(BeNil())
		Expect(lo.FromPtr(terminating.Status.Conditions)[0].Reason).To(Equal("Pending"))
		var tombstone model.LabelSyncMapping
		Expect(db.Select("id", "resource_version", "deletion_revision").Where("org_id = ? AND name = ?", orgID, "architecture").Take(&tombstone).Error).To(Succeed())
		Expect(tombstone.DeletionRevision).NotTo(BeNil())
		Expect(*tombstone.DeletionRevision).To(Equal(lo.FromPtr(tombstone.ResourceVersion)))
		_, err = mappingStore.Create(ctx, orgID, newLabelSyncMapping("replacement", "architecture"))
		Expect(err).To(MatchError(flterrors.ErrLabelSyncConflict))
		revision, err := labelSyncRevision(ctx, db, orgID, domain.LabelSyncMappingDevice)
		Expect(err).NotTo(HaveOccurred())
		Expect(revision).To(Equal(int64(3)))
		finalized, err := mappingStore.FinalizeDelete(ctx, orgID, "architecture")
		Expect(err).NotTo(HaveOccurred())
		Expect(finalized).To(BeTrue())
		_, err = mappingStore.Get(ctx, orgID, "architecture")
		Expect(err).To(MatchError(ContainSubstring("resource not found")))
		Expect(db.Unscoped().Where("org_id = ? AND name = ?", orgID, "architecture").Take(&tombstone).Error).To(MatchError(gorm.ErrRecordNotFound))
		revision, err = labelSyncRevision(ctx, db, orgID, domain.LabelSyncMappingDevice)
		Expect(err).NotTo(HaveOccurred())
		Expect(revision).To(Equal(int64(4)))
		recreated, err := mappingStore.Create(ctx, orgID, newLabelSyncMapping("architecture", "architecture"))
		Expect(err).NotTo(HaveOccurred())
		Expect(lo.FromPtr(recreated.Metadata.Generation)).To(Equal(int64(1)))
		var recreatedMapping model.LabelSyncMapping
		Expect(db.Select("id").Where("org_id = ? AND name = ?", orgID, "architecture").Take(&recreatedMapping).Error).To(Succeed())
		Expect(recreatedMapping.ID).NotTo(Equal(tombstone.ID))
		revision, err = labelSyncRevision(ctx, db, orgID, domain.LabelSyncMappingDevice)
		Expect(err).NotTo(HaveOccurred())
		Expect(revision).To(Equal(int64(5)))
	})

	It("When concurrent mappings claim a scalar key it should admit only one reservation", func() {
		start := make(chan struct{})
		results := make(chan error, 2)
		var wait sync.WaitGroup
		for _, name := range []string{"first", "second"} {
			wait.Add(1)
			go func(name string) {
				defer wait.Done()
				<-start
				_, err := mappingStore.Create(ctx, orgID, newLabelSyncMapping(name, "systeminfo/architecture"))
				results <- err
			}(name)
		}
		close(start)
		wait.Wait()
		close(results)

		created, conflicts := 0, 0
		for err := range results {
			if err == nil {
				created++
				continue
			}
			Expect(err).To(MatchError(flterrors.ErrLabelSyncConflict))
			conflicts++
		}
		Expect(created).To(Equal(1))
		Expect(conflicts).To(Equal(1))
	})

	It("When an unmanaged device label exists it should reject a scalar key claim", func() {
		deviceStore := devicestore.NewDeviceStore(db, log)
		labels := map[string]string{"systeminfo/architecture": "operator-value"}
		testutil.CreateTestDevice(ctx, deviceStore, orgID, "unmanaged-label", nil, nil, &labels)
		_, err := mappingStore.Create(ctx, orgID, newLabelSyncMapping("architecture", "systeminfo/architecture"))
		Expect(err).To(MatchError(flterrors.ErrLabelSyncConflict))
	})

	It("When a mapping already owns a key it should allow an atomic map-to-scalar change", func() {
		mapping := newLabelSyncMapping("mapping", "")
		mapping.Spec.Key = nil
		created, err := mappingStore.Create(ctx, orgID, mapping)
		Expect(err).NotTo(HaveOccurred())
		var storedMapping model.LabelSyncMapping
		Expect(db.Select("id").Where("org_id = ? AND name = ?", orgID, "mapping").Take(&storedMapping).Error).To(Succeed())

		deviceStore := devicestore.NewDeviceStore(db, log)
		labels := map[string]string{"systeminfo/architecture": "x86_64"}
		testutil.CreateTestDevice(ctx, deviceStore, orgID, "mapped-device", nil, nil, &labels)
		Expect(db.Model(&model.DeviceLabel{}).
			Where("org_id = ? AND device_name = ? AND label_key = ?", orgID, "mapped-device", "systeminfo/architecture").
			Update("label_sync_mapping_id", storedMapping.ID).Error).To(Succeed())

		created.Spec.Key = lo.ToPtr("systeminfo/architecture")
		updated, _, err := mappingStore.Update(ctx, orgID, created)
		Expect(err).NotTo(HaveOccurred())
		Expect(lo.FromPtr(updated.Metadata.Generation)).To(Equal(int64(2)))
	})

	It("When a mapping owns a DeviceLabel it should preserve ownership on value changes and delete it with the label", func() {
		_, err := mappingStore.Create(ctx, orgID, newLabelSyncMapping("architecture", "systeminfo/architecture"))
		Expect(err).NotTo(HaveOccurred())
		var storedMapping model.LabelSyncMapping
		Expect(db.Select("id").Where("org_id = ? AND name = ?", orgID, "architecture").Take(&storedMapping).Error).To(Succeed())
		mappingID := storedMapping.ID

		deviceStore := devicestore.NewDeviceStore(db, log)
		labels := map[string]string{"systeminfo/architecture": "x86_64"}
		testutil.CreateTestDevice(ctx, deviceStore, orgID, "mapped-device", nil, nil, &labels)
		Expect(db.Model(&model.DeviceLabel{}).
			Where("org_id = ? AND device_name = ? AND label_key = ?", orgID, "mapped-device", "systeminfo/architecture").
			Update("label_sync_mapping_id", mappingID).Error).To(Succeed())

		updatedLabels := model.JSONMap[string, string]{"systeminfo/architecture": "aarch64"}
		Expect(db.Model(&model.Device{}).Where("org_id = ? AND name = ?", orgID, "mapped-device").Update("labels", updatedLabels).Error).To(Succeed())

		var label model.DeviceLabel
		Expect(db.Where("org_id = ? AND device_name = ? AND label_key = ?", orgID, "mapped-device", "systeminfo/architecture").Take(&label).Error).To(Succeed())
		Expect(label.LabelValue).To(Equal("aarch64"))
		Expect(label.LabelSyncMappingID).To(Equal(&mappingID))

		Expect(mappingStore.Delete(ctx, orgID, "architecture")).To(BeTrue())
		finalized, err := mappingStore.FinalizeDelete(ctx, orgID, "architecture")
		Expect(err).NotTo(HaveOccurred())
		Expect(finalized).To(BeFalse())

		emptyLabels := model.JSONMap[string, string]{}
		Expect(db.Model(&model.Device{}).Where("org_id = ? AND name = ?", orgID, "mapped-device").Update("labels", emptyLabels).Error).To(Succeed())
		Expect(db.Where("org_id = ? AND device_name = ? AND label_key = ?", orgID, "mapped-device", "systeminfo/architecture").Take(&label).Error).To(HaveOccurred())
		finalized, err = mappingStore.FinalizeDelete(ctx, orgID, "architecture")
		Expect(err).NotTo(HaveOccurred())
		Expect(finalized).To(BeTrue())
	})

	It("When a device reconciliation snapshot is loaded it should include current labels, mapping identities, terminating mappings, and revision", func() {
		_, err := mappingStore.Create(ctx, orgID, newLabelSyncMapping("architecture", "architecture"))
		Expect(err).NotTo(HaveOccurred())
		_, err = mappingStore.Create(ctx, orgID, newLabelSyncMapping("model", "model"))
		Expect(err).NotTo(HaveOccurred())

		var architectureMapping, modelMapping model.LabelSyncMapping
		Expect(db.Where("org_id = ? AND name = ?", orgID, "architecture").Take(&architectureMapping).Error).To(Succeed())
		Expect(db.Where("org_id = ? AND name = ?", orgID, "model").Take(&modelMapping).Error).To(Succeed())

		labels := map[string]string{
			"architecture": "x86_64",
			"manual":       "preserved",
			"model":        "edge",
		}
		testutil.CreateTestDevice(ctx, deviceStore, orgID, "snapshot-device", nil, nil, &labels)
		Expect(db.Model(&model.DeviceLabel{}).
			Where("org_id = ? AND device_name = ? AND label_key = ?", orgID, "snapshot-device", "architecture").
			Update("label_sync_mapping_id", architectureMapping.ID).Error).To(Succeed())
		Expect(db.Model(&model.DeviceLabel{}).
			Where("org_id = ? AND device_name = ? AND label_key = ?", orgID, "snapshot-device", "model").
			Update("label_sync_mapping_id", modelMapping.ID).Error).To(Succeed())

		deleted, err := mappingStore.Delete(ctx, orgID, "model")
		Expect(err).NotTo(HaveOccurred())
		Expect(deleted).To(BeTrue())

		snapshotStore, ok := mappingStore.(labelsyncmappingstore.ReconciliationSnapshotStore)
		Expect(ok).To(BeTrue())
		snapshot, err := snapshotStore.LoadDeviceLabelReconciliationSnapshot(ctx, orgID, "snapshot-device")
		Expect(err).NotTo(HaveOccurred())
		Expect(snapshot.Device.Metadata.Name).To(Equal(lo.ToPtr("snapshot-device")))
		Expect(snapshot.Device.Metadata.ResourceVersion).NotTo(BeNil())
		Expect(lo.FromPtr(snapshot.Device.Metadata.Labels)).To(Equal(labels))
		Expect(snapshot.MappingRevision).To(Equal(int64(3)))

		deviceLabels := make(map[string]labelsyncmappingstore.DeviceLabelOwnership, len(snapshot.DeviceLabels))
		for _, label := range snapshot.DeviceLabels {
			deviceLabels[label.Key] = label
		}
		Expect(deviceLabels).To(HaveLen(3))
		Expect(deviceLabels["architecture"]).To(Equal(labelsyncmappingstore.DeviceLabelOwnership{
			Key: "architecture", Value: "x86_64", MappingID: &architectureMapping.ID,
		}))
		Expect(deviceLabels["manual"]).To(Equal(labelsyncmappingstore.DeviceLabelOwnership{
			Key: "manual", Value: "preserved", MappingID: nil,
		}))
		Expect(deviceLabels["model"]).To(Equal(labelsyncmappingstore.DeviceLabelOwnership{
			Key: "model", Value: "edge", MappingID: &modelMapping.ID,
		}))

		mappings := make(map[string]labelsyncmappingstore.ReconciliationMapping, len(snapshot.Mappings))
		for _, mapping := range snapshot.Mappings {
			mappings[lo.FromPtr(mapping.Mapping.Metadata.Name)] = mapping
		}
		Expect(mappings).To(HaveLen(2))
		Expect(mappings["architecture"].ID).To(Equal(architectureMapping.ID))
		Expect(mappings["architecture"].Mapping.Metadata.DeletionTimestamp).To(BeNil())
		Expect(mappings["model"].ID).To(Equal(modelMapping.ID))
		Expect(mappings["model"].Mapping.Metadata.DeletionTimestamp).NotTo(BeNil())
	})

	It("When a device is absent it should fail to load a reconciliation snapshot", func() {
		snapshotStore, ok := mappingStore.(labelsyncmappingstore.ReconciliationSnapshotStore)
		Expect(ok).To(BeTrue())
		_, err := snapshotStore.LoadDeviceLabelReconciliationSnapshot(ctx, orgID, "missing-device")
		Expect(err).To(MatchError(flterrors.ErrResourceNotFound))
	})

	It("When reconciled values change it should update device labels and mapping ownership atomically", func() {
		_, err := mappingStore.Create(ctx, orgID, newLabelSyncMapping("architecture", "architecture"))
		Expect(err).NotTo(HaveOccurred())
		var storedMapping model.LabelSyncMapping
		Expect(db.Select("id").Where("org_id = ? AND name = ?", orgID, "architecture").Take(&storedMapping).Error).To(Succeed())
		mappingID := storedMapping.ID

		labels := map[string]string{"architecture": "x86_64", "manual": "preserved"}
		testutil.CreateTestDevice(ctx, deviceStore, orgID, "apply-device", nil, nil, &labels)
		reconciliationStore, ok := mappingStore.(labelsyncmappingstore.ReconciliationStore)
		Expect(ok).To(BeTrue())
		snapshot, err := reconciliationStore.LoadDeviceLabelReconciliationSnapshot(ctx, orgID, "apply-device")
		Expect(err).NotTo(HaveOccurred())
		resourceVersion, err := strconv.ParseInt(lo.FromPtr(snapshot.Device.Metadata.ResourceVersion), 10, 64)
		Expect(err).NotTo(HaveOccurred())

		result, err := reconciliationStore.ApplyDeviceLabelReconciliation(ctx, orgID, "apply-device", snapshot, map[string]labelsyncmappingstore.DesiredDeviceLabel{
			"architecture": {Value: "aarch64", MappingID: &mappingID},
			"manual":       {Value: "preserved"},
		})

		Expect(err).NotTo(HaveOccurred())
		Expect(result).To(Equal(labelsyncmappingstore.DeviceLabelWriteResult{LabelsChanged: true}))
		device, err := deviceStore.Get(ctx, orgID, "apply-device")
		Expect(err).NotTo(HaveOccurred())
		Expect(lo.FromPtr(device.Metadata.Labels)).To(Equal(map[string]string{"architecture": "aarch64", "manual": "preserved"}))
		updatedResourceVersion, err := strconv.ParseInt(lo.FromPtr(device.Metadata.ResourceVersion), 10, 64)
		Expect(err).NotTo(HaveOccurred())
		Expect(updatedResourceVersion).To(Equal(resourceVersion + 1))

		var managedLabel, manualLabel model.DeviceLabel
		Expect(db.Where("org_id = ? AND device_name = ? AND label_key = ?", orgID, "apply-device", "architecture").Take(&managedLabel).Error).To(Succeed())
		Expect(db.Where("org_id = ? AND device_name = ? AND label_key = ?", orgID, "apply-device", "manual").Take(&manualLabel).Error).To(Succeed())
		Expect(managedLabel.LabelValue).To(Equal("aarch64"))
		Expect(managedLabel.LabelSyncMappingID).To(Equal(&mappingID))
		Expect(manualLabel.LabelValue).To(Equal("preserved"))
		Expect(manualLabel.LabelSyncMappingID).To(BeNil())
	})

	It("When owner stamping fails it should roll back the label value update", func() {
		_, err := mappingStore.Create(ctx, orgID, newLabelSyncMapping("architecture", "architecture"))
		Expect(err).NotTo(HaveOccurred())
		labels := map[string]string{"architecture": "x86_64"}
		testutil.CreateTestDevice(ctx, deviceStore, orgID, "rollback-device", nil, nil, &labels)
		reconciliationStore, ok := mappingStore.(labelsyncmappingstore.ReconciliationStore)
		Expect(ok).To(BeTrue())
		snapshot, err := reconciliationStore.LoadDeviceLabelReconciliationSnapshot(ctx, orgID, "rollback-device")
		Expect(err).NotTo(HaveOccurred())
		invalidMappingID := uuid.New()

		_, err = reconciliationStore.ApplyDeviceLabelReconciliation(ctx, orgID, "rollback-device", snapshot, map[string]labelsyncmappingstore.DesiredDeviceLabel{
			"architecture": {Value: "aarch64", MappingID: &invalidMappingID},
		})
		Expect(err).To(HaveOccurred())

		device, err := deviceStore.Get(ctx, orgID, "rollback-device")
		Expect(err).NotTo(HaveOccurred())
		Expect(lo.FromPtr(device.Metadata.Labels)).To(Equal(labels))
		var label model.DeviceLabel
		Expect(db.Where("org_id = ? AND device_name = ? AND label_key = ?", orgID, "rollback-device", "architecture").Take(&label).Error).To(Succeed())
		Expect(label.LabelValue).To(Equal("x86_64"))
		Expect(label.LabelSyncMappingID).To(BeNil())
	})

	It("When only label ownership changes it should avoid updating device labels and remain idempotent", func() {
		_, err := mappingStore.Create(ctx, orgID, newLabelSyncMapping("architecture", "architecture"))
		Expect(err).NotTo(HaveOccurred())
		var storedMapping model.LabelSyncMapping
		Expect(db.Select("id").Where("org_id = ? AND name = ?", orgID, "architecture").Take(&storedMapping).Error).To(Succeed())
		mappingID := storedMapping.ID

		labels := map[string]string{"architecture": "x86_64", "manual": "preserved"}
		testutil.CreateTestDevice(ctx, deviceStore, orgID, "owner-only-device", nil, nil, &labels)
		reconciliationStore, ok := mappingStore.(labelsyncmappingstore.ReconciliationStore)
		Expect(ok).To(BeTrue())
		snapshot, err := reconciliationStore.LoadDeviceLabelReconciliationSnapshot(ctx, orgID, "owner-only-device")
		Expect(err).NotTo(HaveOccurred())
		staleSnapshot := snapshot
		resourceVersion, err := strconv.ParseInt(lo.FromPtr(snapshot.Device.Metadata.ResourceVersion), 10, 64)
		Expect(err).NotTo(HaveOccurred())
		desired := map[string]labelsyncmappingstore.DesiredDeviceLabel{
			"architecture": {Value: "x86_64", MappingID: &mappingID},
			"manual":       {Value: "preserved"},
		}

		result, err := reconciliationStore.ApplyDeviceLabelReconciliation(ctx, orgID, "owner-only-device", snapshot, desired)

		Expect(err).NotTo(HaveOccurred())
		Expect(result).To(Equal(labelsyncmappingstore.DeviceLabelWriteResult{}))
		device, err := deviceStore.Get(ctx, orgID, "owner-only-device")
		Expect(err).NotTo(HaveOccurred())
		Expect(lo.FromPtr(device.Metadata.ResourceVersion)).To(Equal(strconv.FormatInt(resourceVersion, 10)))
		var architectureLabel model.DeviceLabel
		Expect(db.Where("org_id = ? AND device_name = ? AND label_key = ?", orgID, "owner-only-device", "architecture").Take(&architectureLabel).Error).To(Succeed())
		Expect(architectureLabel.LabelSyncMappingID).To(Equal(&mappingID))

		_, err = reconciliationStore.ApplyDeviceLabelReconciliation(ctx, orgID, "owner-only-device", staleSnapshot, desired)
		Expect(err).To(MatchError(labelsyncmappingstore.ErrDeviceLabelReconciliationConflict))

		snapshot, err = reconciliationStore.LoadDeviceLabelReconciliationSnapshot(ctx, orgID, "owner-only-device")
		Expect(err).NotTo(HaveOccurred())
		result, err = reconciliationStore.ApplyDeviceLabelReconciliation(ctx, orgID, "owner-only-device", snapshot, desired)
		Expect(err).NotTo(HaveOccurred())
		Expect(result).To(Equal(labelsyncmappingstore.DeviceLabelWriteResult{}))
	})

	It("When the device resource version changes it should reject a stale reconciliation write", func() {
		labels := map[string]string{"manual": "before"}
		testutil.CreateTestDevice(ctx, deviceStore, orgID, "stale-device", nil, nil, &labels)
		reconciliationStore, ok := mappingStore.(labelsyncmappingstore.ReconciliationStore)
		Expect(ok).To(BeTrue())
		snapshot, err := reconciliationStore.LoadDeviceLabelReconciliationSnapshot(ctx, orgID, "stale-device")
		Expect(err).NotTo(HaveOccurred())
		_, _, _, err = deviceStore.Mutate(ctx, orgID, "stale-device", &snapshot.Device, func(mutation *devicestore.DeviceMutation) error {
			updatedLabels := lo.FromPtr(mutation.Device.Metadata.Labels)
			updatedLabels["manual"] = "operator-update"
			mutation.Device.Metadata.Labels = &updatedLabels
			return nil
		})
		Expect(err).NotTo(HaveOccurred())

		_, err = reconciliationStore.ApplyDeviceLabelReconciliation(ctx, orgID, "stale-device", snapshot, map[string]labelsyncmappingstore.DesiredDeviceLabel{
			"manual": {Value: "before"},
		})
		Expect(err).To(MatchError(labelsyncmappingstore.ErrDeviceLabelReconciliationConflict))
	})

	It("When the mapping revision changes it should reject a stale reconciliation write", func() {
		_, err := mappingStore.Create(ctx, orgID, newLabelSyncMapping("architecture", "architecture"))
		Expect(err).NotTo(HaveOccurred())
		labels := map[string]string{"manual": "preserved"}
		testutil.CreateTestDevice(ctx, deviceStore, orgID, "stale-revision-device", nil, nil, &labels)
		reconciliationStore, ok := mappingStore.(labelsyncmappingstore.ReconciliationStore)
		Expect(ok).To(BeTrue())
		snapshot, err := reconciliationStore.LoadDeviceLabelReconciliationSnapshot(ctx, orgID, "stale-revision-device")
		Expect(err).NotTo(HaveOccurred())
		mapping, err := mappingStore.Get(ctx, orgID, "architecture")
		Expect(err).NotTo(HaveOccurred())
		mapping.Spec.Expression = "status.systemInfo.architecture + '-v2'"
		_, _, err = mappingStore.Update(ctx, orgID, mapping)
		Expect(err).NotTo(HaveOccurred())

		_, err = reconciliationStore.ApplyDeviceLabelReconciliation(ctx, orgID, "stale-revision-device", snapshot, map[string]labelsyncmappingstore.DesiredDeviceLabel{
			"manual": {Value: "preserved"},
		})
		Expect(err).To(MatchError(labelsyncmappingstore.ErrDeviceLabelReconciliationConflict))
	})

	It("When a terminating mapping has no desired output it should clean owned labels before finalization", func() {
		_, err := mappingStore.Create(ctx, orgID, newLabelSyncMapping("architecture", "architecture"))
		Expect(err).NotTo(HaveOccurred())
		var storedMapping model.LabelSyncMapping
		Expect(db.Select("id").Where("org_id = ? AND name = ?", orgID, "architecture").Take(&storedMapping).Error).To(Succeed())
		mappingID := storedMapping.ID

		labels := map[string]string{"architecture": "x86_64", "manual": "preserved"}
		testutil.CreateTestDevice(ctx, deviceStore, orgID, "terminating-device", nil, nil, &labels)
		Expect(db.Model(&model.DeviceLabel{}).
			Where("org_id = ? AND device_name = ? AND label_key = ?", orgID, "terminating-device", "architecture").
			Update("label_sync_mapping_id", mappingID).Error).To(Succeed())
		deleted, err := mappingStore.Delete(ctx, orgID, "architecture")
		Expect(err).NotTo(HaveOccurred())
		Expect(deleted).To(BeTrue())

		reconciliationStore, ok := mappingStore.(labelsyncmappingstore.ReconciliationStore)
		Expect(ok).To(BeTrue())
		snapshot, err := reconciliationStore.LoadDeviceLabelReconciliationSnapshot(ctx, orgID, "terminating-device")
		Expect(err).NotTo(HaveOccurred())
		result, err := reconciliationStore.ApplyDeviceLabelReconciliation(ctx, orgID, "terminating-device", snapshot, map[string]labelsyncmappingstore.DesiredDeviceLabel{
			"manual": {Value: "preserved"},
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(result).To(Equal(labelsyncmappingstore.DeviceLabelWriteResult{LabelsChanged: true}))
		finalized, err := mappingStore.FinalizeDelete(ctx, orgID, "architecture")
		Expect(err).NotTo(HaveOccurred())
		Expect(finalized).To(BeTrue())
	})

	It("When a device label update races with reconciliation it should retry and preserve both current outputs", func() {
		_, err := mappingStore.Create(ctx, orgID, newLabelSyncMapping("architecture", "architecture"))
		Expect(err).NotTo(HaveOccurred())
		var storedMapping model.LabelSyncMapping
		Expect(db.Select("id").Where("org_id = ? AND name = ?", orgID, "architecture").Take(&storedMapping).Error).To(Succeed())

		labels := map[string]string{"manual": "before", "unrelated": "preserved"}
		testutil.CreateTestDevice(ctx, deviceStore, orgID, "device-update-race", nil, nil, &labels)
		evaluator := newBlockingLabelSyncEvaluator()
		events := &recordingLabelSyncEvents{}
		reconciliationStore, ok := mappingStore.(labelsyncmappingstore.ReconciliationStore)
		Expect(ok).To(BeTrue())
		reconciler, err := labelsyncmappingservice.NewReconciler(reconciliationStore, evaluator, events, log)
		Expect(err).NotTo(HaveOccurred())
		reconcileCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		defer evaluator.releaseFirstEvaluation()
		resultCh := make(chan integrationReconciliationResult, 1)
		go func() {
			result, err := reconciler.ReconcileDeviceLabels(reconcileCtx, orgID, "device-update-race")
			resultCh <- integrationReconciliationResult{result: result, err: err}
		}()

		select {
		case expression := <-evaluator.firstEvaluation:
			Expect(expression).To(Equal("device.status.systemInfo.architecture"))
		case <-reconcileCtx.Done():
			Fail(fmt.Sprintf("reconciler did not begin evaluating before timeout: %v", reconcileCtx.Err()))
		}

		before, err := deviceStore.Get(reconcileCtx, orgID, "device-update-race")
		Expect(err).NotTo(HaveOccurred())
		_, _, _, err = deviceStore.Mutate(reconcileCtx, orgID, "device-update-race", before, func(mutation *devicestore.DeviceMutation) error {
			updatedLabels := lo.FromPtr(mutation.Device.Metadata.Labels)
			updatedLabels["manual"] = "operator-update"
			mutation.Device.Metadata.Labels = &updatedLabels
			return nil
		})
		Expect(err).NotTo(HaveOccurred())
		evaluator.releaseFirstEvaluation()

		var reconciliation integrationReconciliationResult
		select {
		case reconciliation = <-resultCh:
		case <-reconcileCtx.Done():
			Fail(fmt.Sprintf("reconciler did not finish after the device update: %v", reconcileCtx.Err()))
		}
		Expect(reconciliation.err).NotTo(HaveOccurred())
		Expect(reconciliation.result.LabelsChanged).To(BeTrue())
		Expect(reconciliation.result.MappingOutcomes).To(HaveLen(1))
		Expect(reconciliation.result.MappingOutcomes[0].Err).NotTo(HaveOccurred())
		Expect(evaluator.evaluatedExpressions()).To(Equal([]string{
			"device.status.systemInfo.architecture",
			"device.status.systemInfo.architecture",
		}))

		device, err := deviceStore.Get(ctx, orgID, "device-update-race")
		Expect(err).NotTo(HaveOccurred())
		Expect(lo.FromPtr(device.Metadata.Labels)).To(Equal(map[string]string{
			"architecture": "device.status.systemInfo.architecture",
			"manual":       "operator-update",
			"unrelated":    "preserved",
		}))
		var managedLabel, manualLabel model.DeviceLabel
		Expect(db.Where("org_id = ? AND device_name = ? AND label_key = ?", orgID, "device-update-race", "architecture").Take(&managedLabel).Error).To(Succeed())
		Expect(managedLabel.LabelSyncMappingID).To(Equal(&storedMapping.ID))
		Expect(db.Where("org_id = ? AND device_name = ? AND label_key = ?", orgID, "device-update-race", "manual").Take(&manualLabel).Error).To(Succeed())
		Expect(manualLabel.LabelSyncMappingID).To(BeNil())
		recordedEvents := events.snapshot()
		Expect(recordedEvents).To(HaveLen(1))
		Expect(recordedEvents[0].Reason).To(Equal(domain.EventReasonResourceUpdated))
		details, err := recordedEvents[0].Details.AsResourceUpdatedDetails()
		Expect(err).NotTo(HaveOccurred())
		Expect(details.UpdatedFields).To(Equal([]domain.ResourceUpdatedDetailsUpdatedFields{domain.Labels}))
	})

	It("When a mapping changes during evaluation it should retry using the current mapping revision", func() {
		mappingResource := newLabelSyncMapping("architecture", "architecture")
		mappingResource.Spec.Expression = "old-expression"
		_, err := mappingStore.Create(ctx, orgID, mappingResource)
		Expect(err).NotTo(HaveOccurred())
		var storedMapping model.LabelSyncMapping
		Expect(db.Select("id").Where("org_id = ? AND name = ?", orgID, "architecture").Take(&storedMapping).Error).To(Succeed())

		labels := map[string]string{"manual": "preserved"}
		testutil.CreateTestDevice(ctx, deviceStore, orgID, "mapping-update-race", nil, nil, &labels)
		evaluator := newBlockingLabelSyncEvaluator()
		events := &recordingLabelSyncEvents{}
		reconciliationStore, ok := mappingStore.(labelsyncmappingstore.ReconciliationStore)
		Expect(ok).To(BeTrue())
		reconciler, err := labelsyncmappingservice.NewReconciler(reconciliationStore, evaluator, events, log)
		Expect(err).NotTo(HaveOccurred())
		reconcileCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		defer evaluator.releaseFirstEvaluation()
		resultCh := make(chan integrationReconciliationResult, 1)
		go func() {
			result, err := reconciler.ReconcileDeviceLabels(reconcileCtx, orgID, "mapping-update-race")
			resultCh <- integrationReconciliationResult{result: result, err: err}
		}()

		select {
		case expression := <-evaluator.firstEvaluation:
			Expect(expression).To(Equal("old-expression"))
		case <-reconcileCtx.Done():
			Fail(fmt.Sprintf("reconciler did not begin evaluating before timeout: %v", reconcileCtx.Err()))
		}

		currentMapping, err := mappingStore.Get(reconcileCtx, orgID, "architecture")
		Expect(err).NotTo(HaveOccurred())
		currentMapping.Spec.Expression = "current-expression"
		_, _, err = mappingStore.Update(reconcileCtx, orgID, currentMapping)
		Expect(err).NotTo(HaveOccurred())
		evaluator.releaseFirstEvaluation()

		var reconciliation integrationReconciliationResult
		select {
		case reconciliation = <-resultCh:
		case <-reconcileCtx.Done():
			Fail(fmt.Sprintf("reconciler did not finish after the mapping update: %v", reconcileCtx.Err()))
		}
		Expect(reconciliation.err).NotTo(HaveOccurred())
		Expect(reconciliation.result.LabelsChanged).To(BeTrue())
		Expect(reconciliation.result.MappingOutcomes).To(HaveLen(1))
		Expect(reconciliation.result.MappingOutcomes[0].Err).NotTo(HaveOccurred())
		Expect(evaluator.evaluatedExpressions()).To(Equal([]string{"old-expression", "current-expression"}))

		device, err := deviceStore.Get(ctx, orgID, "mapping-update-race")
		Expect(err).NotTo(HaveOccurred())
		Expect(lo.FromPtr(device.Metadata.Labels)).To(Equal(map[string]string{
			"architecture": "current-expression",
			"manual":       "preserved",
		}))
		var managedLabel model.DeviceLabel
		Expect(db.Where("org_id = ? AND device_name = ? AND label_key = ?", orgID, "mapping-update-race", "architecture").Take(&managedLabel).Error).To(Succeed())
		Expect(managedLabel.LabelSyncMappingID).To(Equal(&storedMapping.ID))
		recordedEvents := events.snapshot()
		Expect(recordedEvents).To(HaveLen(1))
		Expect(recordedEvents[0].Reason).To(Equal(domain.EventReasonResourceUpdated))
	})

	It("When a mapping mutation contends with reconciliation it should converge to the current revision", func() {
		mappingResource := newLabelSyncMapping("architecture", "architecture")
		mappingResource.Spec.Expression = "old-expression"
		_, err := mappingStore.Create(ctx, orgID, mappingResource)
		Expect(err).NotTo(HaveOccurred())
		testutil.CreateTestDevice(ctx, deviceStore, orgID, "mapping-transaction-race", nil, nil, nil)

		// Hold the revision row so both the reconciliation apply and mapping
		// mutation enter their write transactions before either can finish.
		testCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		revisionLock := db.WithContext(testCtx).Begin()
		Expect(revisionLock.Error).NotTo(HaveOccurred())
		defer revisionLock.Rollback()
		var lockedState model.LabelSyncState
		Expect(revisionLock.Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("org_id = ? AND resource_type = ?", orgID, domain.LabelSyncMappingDevice).
			Take(&lockedState).Error).To(Succeed())

		evaluator := newBlockingLabelSyncEvaluator()
		events := &recordingLabelSyncEvents{}
		reconciliationStore, ok := mappingStore.(labelsyncmappingstore.ReconciliationStore)
		Expect(ok).To(BeTrue())
		reconciler, err := labelsyncmappingservice.NewReconciler(reconciliationStore, evaluator, events, log)
		Expect(err).NotTo(HaveOccurred())
		defer evaluator.releaseFirstEvaluation()

		reconciliationCh := make(chan integrationReconciliationResult, 1)
		go func() {
			result, err := reconciler.ReconcileDeviceLabels(testCtx, orgID, "mapping-transaction-race")
			reconciliationCh <- integrationReconciliationResult{result: result, err: err}
		}()
		select {
		case expression := <-evaluator.firstEvaluation:
			Expect(expression).To(Equal("old-expression"))
		case <-testCtx.Done():
			Fail(fmt.Sprintf("reconciler did not begin evaluating before timeout: %v", testCtx.Err()))
		}
		evaluator.releaseFirstEvaluation()

		mappingUpdateCh := make(chan error, 1)
		go func() {
			current, err := mappingStore.Get(testCtx, orgID, "architecture")
			if err != nil {
				mappingUpdateCh <- err
				return
			}
			current.Spec.Expression = "current-expression"
			_, _, err = mappingStore.Update(testCtx, orgID, current)
			mappingUpdateCh <- err
		}()
		Expect(waitForDatabaseLockWaiters(testCtx, db, 2)).To(Succeed())
		Expect(revisionLock.Commit().Error).NotTo(HaveOccurred())

		var reconciliation integrationReconciliationResult
		select {
		case reconciliation = <-reconciliationCh:
		case <-testCtx.Done():
			Fail(fmt.Sprintf("reconciler did not finish after the revision contention: %v", testCtx.Err()))
		}
		Expect(reconciliation.err).NotTo(HaveOccurred())
		select {
		case err = <-mappingUpdateCh:
			Expect(err).NotTo(HaveOccurred())
		case <-testCtx.Done():
			Fail(fmt.Sprintf("mapping update did not finish after the revision contention: %v", testCtx.Err()))
		}

		// If reconciliation won the state-row lock, it may have committed the old
		// value immediately before the mapping update. A subsequent pass must still
		// converge; if the update won, the first pass itself exercises the CAS retry.
		_, err = reconciler.ReconcileDeviceLabels(testCtx, orgID, "mapping-transaction-race")
		Expect(err).NotTo(HaveOccurred())
		device, err := deviceStore.Get(testCtx, orgID, "mapping-transaction-race")
		Expect(err).NotTo(HaveOccurred())
		Expect(lo.FromPtr(device.Metadata.Labels)).To(Equal(map[string]string{
			"architecture": "current-expression",
		}))
	})

	It("When an operator label write contends with reconciliation it should preserve both updates", func() {
		_, err := mappingStore.Create(ctx, orgID, newLabelSyncMapping("architecture", "architecture"))
		Expect(err).NotTo(HaveOccurred())
		labels := map[string]string{"manual": "before"}
		testutil.CreateTestDevice(ctx, deviceStore, orgID, "device-transaction-race", nil, nil, &labels)

		// Hold the device row after the reconciler has taken its snapshot. Both the
		// reconciliation apply and operator mutation must contend on the row.
		testCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		deviceLock := db.WithContext(testCtx).Begin()
		Expect(deviceLock.Error).NotTo(HaveOccurred())
		defer deviceLock.Rollback()
		var lockedDevice model.Device
		Expect(deviceLock.Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("org_id = ? AND name = ?", orgID, "device-transaction-race").
			Take(&lockedDevice).Error).To(Succeed())

		evaluator := newBlockingLabelSyncEvaluator()
		events := &recordingLabelSyncEvents{}
		reconciliationStore, ok := mappingStore.(labelsyncmappingstore.ReconciliationStore)
		Expect(ok).To(BeTrue())
		reconciler, err := labelsyncmappingservice.NewReconciler(reconciliationStore, evaluator, events, log)
		Expect(err).NotTo(HaveOccurred())
		defer evaluator.releaseFirstEvaluation()

		reconciliationCh := make(chan integrationReconciliationResult, 1)
		go func() {
			result, err := reconciler.ReconcileDeviceLabels(testCtx, orgID, "device-transaction-race")
			reconciliationCh <- integrationReconciliationResult{result: result, err: err}
		}()
		select {
		case expression := <-evaluator.firstEvaluation:
			Expect(expression).To(Equal("device.status.systemInfo.architecture"))
		case <-testCtx.Done():
			Fail(fmt.Sprintf("reconciler did not begin evaluating before timeout: %v", testCtx.Err()))
		}
		evaluator.releaseFirstEvaluation()

		operatorUpdateCh := make(chan error, 1)
		go func() {
			_, _, _, err := deviceStore.Mutate(testCtx, orgID, "device-transaction-race", nil, func(mutation *devicestore.DeviceMutation) error {
				updatedLabels := lo.FromPtr(mutation.Device.Metadata.Labels)
				updatedLabels["manual"] = "operator-update"
				mutation.Device.Metadata.Labels = &updatedLabels
				return nil
			})
			operatorUpdateCh <- err
		}()
		Expect(waitForDatabaseLockWaiters(testCtx, db, 2)).To(Succeed())
		Expect(deviceLock.Commit().Error).NotTo(HaveOccurred())

		var reconciliation integrationReconciliationResult
		select {
		case reconciliation = <-reconciliationCh:
		case <-testCtx.Done():
			Fail(fmt.Sprintf("reconciler did not finish after the device-row contention: %v", testCtx.Err()))
		}
		Expect(reconciliation.err).NotTo(HaveOccurred())
		select {
		case err = <-operatorUpdateCh:
			Expect(err).NotTo(HaveOccurred())
		case <-testCtx.Done():
			Fail(fmt.Sprintf("operator update did not finish after the device-row contention: %v", testCtx.Err()))
		}

		device, err := deviceStore.Get(testCtx, orgID, "device-transaction-race")
		Expect(err).NotTo(HaveOccurred())
		Expect(lo.FromPtr(device.Metadata.Labels)).To(Equal(map[string]string{
			"architecture": "device.status.systemInfo.architecture",
			"manual":       "operator-update",
		}))
		var managedLabel, manualLabel model.DeviceLabel
		Expect(db.Where("org_id = ? AND device_name = ? AND label_key = ?", orgID, "device-transaction-race", "architecture").Take(&managedLabel).Error).To(Succeed())
		Expect(db.Where("org_id = ? AND device_name = ? AND label_key = ?", orgID, "device-transaction-race", "manual").Take(&manualLabel).Error).To(Succeed())
		Expect(managedLabel.LabelSyncMappingID).NotTo(BeNil())
		Expect(manualLabel.LabelSyncMappingID).To(BeNil())
	})

	It("When reconciliation overlaps on label keys across devices it should commit every device without deadlock", func() {
		mappingResource := newLabelSyncMapping("multi-output", "")
		mappingResource.Spec.Key = nil
		_, err := mappingStore.Create(ctx, orgID, mappingResource)
		Expect(err).NotTo(HaveOccurred())
		var storedMapping model.LabelSyncMapping
		Expect(db.Select("id").Where("org_id = ? AND name = ?", orgID, "multi-output").Take(&storedMapping).Error).To(Succeed())
		reconciliationStore, ok := mappingStore.(labelsyncmappingstore.ReconciliationStore)
		Expect(ok).To(BeTrue())

		const sharedKeyCount = 12
		deviceNames := []string{"overlap-device-a", "overlap-device-b", "overlap-device-c", "overlap-device-d"}
		type reconciliationWrite struct {
			deviceName string
			snapshot   labelsyncmappingstore.DeviceLabelReconciliationSnapshot
			desired    map[string]labelsyncmappingstore.DesiredDeviceLabel
		}
		writes := make([]reconciliationWrite, 0, len(deviceNames))
		for deviceIndex, deviceName := range deviceNames {
			labels := map[string]string{"manual": "preserved"}
			testutil.CreateTestDevice(ctx, deviceStore, orgID, deviceName, nil, nil, &labels)
			snapshot, err := reconciliationStore.LoadDeviceLabelReconciliationSnapshot(ctx, orgID, deviceName)
			Expect(err).NotTo(HaveOccurred())
			desired := map[string]labelsyncmappingstore.DesiredDeviceLabel{
				"manual": {Value: "preserved"},
			}
			for keyIndex := 0; keyIndex < sharedKeyCount; keyIndex++ {
				key := fmt.Sprintf("shared-%02d", keyIndex)
				desired[key] = labelsyncmappingstore.DesiredDeviceLabel{
					Value:     fmt.Sprintf("device-%d-value-%d", deviceIndex, keyIndex),
					MappingID: &storedMapping.ID,
				}
			}
			uniqueKey := fmt.Sprintf("unique-%d", deviceIndex)
			desired[uniqueKey] = labelsyncmappingstore.DesiredDeviceLabel{
				Value:     fmt.Sprintf("value-%d", deviceIndex),
				MappingID: &storedMapping.ID,
			}
			writes = append(writes, reconciliationWrite{deviceName: deviceName, snapshot: snapshot, desired: desired})
		}

		testCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		start := make(chan struct{})
		type reconciliationWriteResult struct {
			deviceName string
			write      labelsyncmappingstore.DeviceLabelWriteResult
			err        error
		}
		results := make(chan reconciliationWriteResult, len(writes))
		for _, write := range writes {
			go func(write reconciliationWrite) {
				<-start
				result, err := reconciliationStore.ApplyDeviceLabelReconciliation(testCtx, orgID, write.deviceName, write.snapshot, write.desired)
				results <- reconciliationWriteResult{deviceName: write.deviceName, write: result, err: err}
			}(write)
		}
		close(start)

		for range writes {
			select {
			case result := <-results:
				Expect(result.err).NotTo(HaveOccurred(), "device %s", result.deviceName)
				Expect(result.write).To(Equal(labelsyncmappingstore.DeviceLabelWriteResult{LabelsChanged: true}))
			case <-testCtx.Done():
				Fail(fmt.Sprintf("overlapping reconciliations did not all complete: %v", testCtx.Err()))
			}
		}

		for deviceIndex, deviceName := range deviceNames {
			device, err := deviceStore.Get(ctx, orgID, deviceName)
			Expect(err).NotTo(HaveOccurred())
			labels := map[string]string{"manual": "preserved"}
			for keyIndex := 0; keyIndex < sharedKeyCount; keyIndex++ {
				labels[fmt.Sprintf("shared-%02d", keyIndex)] = fmt.Sprintf("device-%d-value-%d", deviceIndex, keyIndex)
			}
			uniqueKey := fmt.Sprintf("unique-%d", deviceIndex)
			labels[uniqueKey] = fmt.Sprintf("value-%d", deviceIndex)
			Expect(lo.FromPtr(device.Metadata.Labels)).To(Equal(labels))

			var deviceLabels []model.DeviceLabel
			Expect(db.Where("org_id = ? AND device_name = ?", orgID, deviceName).Find(&deviceLabels).Error).To(Succeed())
			type persistedLabel struct {
				value string
				owner *uuid.UUID
			}
			persisted := make(map[string]persistedLabel, len(deviceLabels))
			for _, label := range deviceLabels {
				persisted[label.LabelKey] = persistedLabel{value: label.LabelValue, owner: label.LabelSyncMappingID}
			}
			expected := make(map[string]persistedLabel, len(labels))
			for key, value := range labels {
				var owner *uuid.UUID
				if key != "manual" {
					owner = &storedMapping.ID
				}
				expected[key] = persistedLabel{value: value, owner: owner}
			}
			Expect(persisted).To(Equal(expected))
		}
	})
})

func labelSyncRevision(ctx context.Context, db *gorm.DB, orgID uuid.UUID, resourceType domain.LabelSyncMappingResourceType) (int64, error) {
	var state model.LabelSyncState
	if err := db.WithContext(ctx).Where("org_id = ? AND resource_type = ?", orgID, resourceType).Take(&state).Error; err != nil {
		return 0, err
	}
	return state.Revision, nil
}

func newLabelSyncMapping(name, key string) *api.LabelSyncMapping {
	return &api.LabelSyncMapping{
		ApiVersion: "flightctl.io/v1beta1",
		Kind:       api.LabelSyncMappingKindLabelSyncMapping,
		Metadata:   api.ObjectMeta{Name: &name},
		Spec: api.LabelSyncMappingSpec{
			ResourceType: api.LabelSyncMappingSpecResourceTypeDevice,
			Key:          lo.ToPtr(key),
			Expression:   "device.status.systemInfo.architecture",
		},
	}
}

type integrationReconciliationResult struct {
	result labelsyncmappingservice.ReconciliationResult
	err    error
}

type blockingLabelSyncEvaluator struct {
	mu              sync.Mutex
	expressions     []string
	firstEvaluation chan string
	release         chan struct{}
	releaseOnce     sync.Once
}

func newBlockingLabelSyncEvaluator() *blockingLabelSyncEvaluator {
	return &blockingLabelSyncEvaluator{
		firstEvaluation: make(chan string, 1),
		release:         make(chan struct{}),
	}
}

func (e *blockingLabelSyncEvaluator) Evaluate(expression string, _ labelsyncmappingservice.Activation) (labelsyncmappingservice.Result, error) {
	e.mu.Lock()
	first := len(e.expressions) == 0
	e.expressions = append(e.expressions, expression)
	e.mu.Unlock()
	if first {
		e.firstEvaluation <- expression
		<-e.release
	}
	return labelsyncmappingservice.ScalarResult(expression), nil
}

func (*blockingLabelSyncEvaluator) ValidateExpressionIs(string, labelsyncmappingservice.ResultKind) error {
	return nil
}

func (e *blockingLabelSyncEvaluator) releaseFirstEvaluation() {
	e.releaseOnce.Do(func() { close(e.release) })
}

func (e *blockingLabelSyncEvaluator) evaluatedExpressions() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.expressions...)
}

type recordingLabelSyncEvents struct {
	mu      sync.Mutex
	created []*domain.Event
}

func (e *recordingLabelSyncEvents) CreateEvent(_ context.Context, _ uuid.UUID, event *domain.Event) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.created = append(e.created, event)
}

func (*recordingLabelSyncEvents) HandleGenericResourceDeletedEvents(context.Context, domain.ResourceKind, uuid.UUID, string, interface{}, interface{}, bool, error) {
}

func (e *recordingLabelSyncEvents) snapshot() []*domain.Event {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]*domain.Event(nil), e.created...)
}

func waitForDatabaseLockWaiters(ctx context.Context, db *gorm.DB, minimum int64) error {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var waiting int64
		if err := db.WithContext(ctx).Raw(`SELECT COUNT(*) FROM pg_stat_activity
			WHERE datname = current_database() AND wait_event_type = 'Lock'`).Scan(&waiting).Error; err != nil {
			return err
		}
		if waiting >= minimum {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("timed out waiting for %d database lock waiters (observed %d): %w", minimum, waiting, ctx.Err())
		case <-ticker.C:
		}
	}
}
