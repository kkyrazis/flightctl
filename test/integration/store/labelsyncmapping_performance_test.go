package store_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/flightctl/flightctl/internal/config"
	"github.com/flightctl/flightctl/internal/domain"
	deviceservice "github.com/flightctl/flightctl/internal/service/device"
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
	"gorm.io/gorm"
)

const labelSyncMeasurementRepetitions = 20

var _ = Describe("LabelSyncMapping performance measurements", Label("performance"), Serial, func() {
	var (
		ctx        context.Context
		cfg        *config.Config
		dbName     string
		db         *gorm.DB
		observedDB *gorm.DB
		orgID      uuid.UUID
		devices    *devicestore.DeviceStore
		mappings   labelsyncmappingstore.Store
		reconciler labelsyncmappingservice.Service
		recorder   *labelSyncQueryRecorder
		pool       *labelSyncMeasurementPool
	)

	BeforeEach(func() {
		ctx = testutil.StartSpecTracerForGinkgo(suiteCtx)
		log := flightlog.InitLogs()
		var err error
		cfg, dbName, db, err = testdb.CreateTestDB(ctx, log, "", store.InitDB)
		Expect(err).NotTo(HaveOccurred())
		orgID = uuid.New()
		Expect(testutil.CreateTestOrganization(ctx, organizationstore.NewOrganizationStore(db), orgID)).To(Succeed())
		sqlDB, err := db.DB()
		Expect(err).NotTo(HaveOccurred())
		pool = &labelSyncMeasurementPool{DB: sqlDB}
		recorder = &labelSyncQueryRecorder{Interface: db.Logger}
		observedDB = db.Session(&gorm.Session{Context: ctx, Logger: recorder})
		observedDB.ConnPool = pool
		observedDB.Statement.ConnPool = pool
		devices = devicestore.NewDeviceStore(observedDB, log)
		mappings = labelsyncmappingstore.NewStore(observedDB, log)
		evaluator, err := labelsyncmappingservice.NewEvaluator()
		Expect(err).NotTo(HaveOccurred())
		reconciler, _ = newReconciliationService(devices, mappings, evaluator, log)

		_, source, _, ok := runtime.Caller(0)
		Expect(ok).To(BeTrue())
		entries, err := labelsyncmappingservice.ReadInitialLabelSyncMappingEntries(filepath.Join(filepath.Dir(source), "../../../packaging/flightctl/label-sync/mappings.yaml"))
		Expect(err).NotTo(HaveOccurred())
		for _, entry := range entries {
			var mapping domain.LabelSyncMapping
			Expect(json.Unmarshal(entry, &mapping)).To(Succeed())
			kind := labelsyncmappingservice.ResultKindMap
			if mapping.Spec.Key != nil {
				kind = labelsyncmappingservice.ResultKindScalar
			}
			Expect(evaluator.ValidateExpressionIs(mapping.Spec.Expression, kind)).To(Succeed())
			_, err := mappings.Create(ctx, orgID, &mapping)
			Expect(err).NotTo(HaveOccurred())
		}
		AddReportEntry("fixture", map[string]any{"mappings": len(entries), "repetitions": labelSyncMeasurementRepetitions, "go_version": runtime.Version()})
	})

	AfterEach(func() {
		Expect(testdb.DeleteTestDB(ctx, flightlog.InitLogs(), cfg, db, dbName)).To(Succeed())
	})

	createDevice := func(name string) *domain.Device {
		device := newLabelSyncDevice(name, map[string]string{"manual": "preserved"})
		device.Status = lo.ToPtr(domain.NewDeviceStatus())
		Expect(json.Unmarshal([]byte(`{"agentVersion":"1.4.0","architecture":"x86_64","biosVendor":"vendor","biosVersion":"1","cpuProcessors":"4","deltaEligible":true,"distroId":"rhel","distroVersion":"9","kernel":"6.12","memoryTotalKb":"8388608","productName":"edge","customInfo":{"site":"lab"},"tpmVendorInfo":"vendor","gpus":[],"kvm":{"enabled":true},"osMode":"image"}`), &device.Status.SystemInfo)).To(Succeed())
		created, err := devices.Create(ctx, orgID, device, nil)
		Expect(err).NotTo(HaveOccurred())
		return created
	}

	measure := func(samples *labelSyncMeasurements, operation func()) {
		recorder.drain()
		pool.begins.Store(0)
		pool.commits.Store(0)
		pool.rollbacks.Store(0)
		started := time.Now()
		operation()
		samples.durations = append(samples.durations, time.Since(started))
		for _, query := range recorder.drain() {
			query = strings.TrimSpace(query)
			switch {
			case strings.HasPrefix(query, "SELECT"):
				samples.Selects++
			case strings.HasPrefix(query, "UPDATE"):
				samples.Updates++
			}
		}
		samples.Transactions += pool.begins.Load()
		samples.Commits += pool.commits.Load()
		samples.Rollbacks += pool.rollbacks.Load()
	}

	It("When mapping definitions are unchanged it should measure snapshot loads separately from revision reads", func() {
		var snapshots, revisions labelSyncMeasurements
		var definitionBytes int
		for i := 0; i < labelSyncMeasurementRepetitions; i++ {
			var snapshot labelsyncmappingstore.DeviceMappingsSnapshot
			measure(&snapshots, func() {
				var err error
				snapshot, err = mappings.GetDeviceMappingsSnapshot(ctx, orgID)
				Expect(err).NotTo(HaveOccurred())
			})
			encoded, err := json.Marshal(snapshot)
			Expect(err).NotTo(HaveOccurred())
			definitionBytes = len(encoded)
			measure(&revisions, func() {
				revision, err := mappings.GetDeviceMappingsRevision(ctx, orgID)
				Expect(err).NotTo(HaveOccurred())
				Expect(revision).To(Equal(snapshot.Revision))
			})
		}
		Expect(snapshots.Selects).To(Equal(labelSyncMeasurementRepetitions))
		Expect(snapshots.Transactions).To(BeZero())
		AddReportEntry("mapping-snapshot-json-bytes", definitionBytes)
		AddReportEntry("mapping-snapshot-load", snapshots.report())
		AddReportEntry("mapping-revision-read", revisions.report())
	})

	It("When CEL-visible status changes leave labels unchanged it should measure steady-state reconciliation", func() {
		device := createDevice("steady-state")
		_, err := reconciler.ReconcileDeviceLabels(ctx, orgID, *device.Metadata.Name)
		Expect(err).NotTo(HaveOccurred())
		var samples labelSyncMeasurements
		for i := 0; i < labelSyncMeasurementRepetitions; i++ {
			before, err := devices.Get(ctx, orgID, "steady-state")
			Expect(err).NotTo(HaveOccurred())
			updated := *before
			status := *before.Status
			updated.Status = &status
			updated.Status.SystemInfo.BootID = fmt.Sprintf("boot-%d", i)
			_, _, err = devices.UpdateStatus(ctx, orgID, &updated, before)
			Expect(err).NotTo(HaveOccurred())
			measure(&samples, func() {
				result, err := reconciler.ReconcileDeviceLabels(ctx, orgID, "steady-state")
				Expect(err).NotTo(HaveOccurred())
				Expect(result.MappingApplyCommitted).To(BeTrue())
				Expect(result.LabelsChanged || result.OwnershipChanged).To(BeFalse())
			})
		}
		Expect(samples.Transactions).To(Equal(int64(labelSyncMeasurementRepetitions)))
		Expect(samples.Selects).To(Equal(5 * labelSyncMeasurementRepetitions))
		Expect(samples.Updates).To(BeZero())
		Expect(samples.Rollbacks).To(BeZero())
		Expect(samples.Commits).To(Equal(samples.Transactions))
		AddReportEntry("steady-state", samples.report())
	})

	It("When acquiring and transferring managed labels it should measure ownership write amplification", func() {
		var acquisition, transfer labelSyncMeasurements
		for i := 0; i < labelSyncMeasurementRepetitions; i++ {
			device := createDevice(fmt.Sprintf("acquisition-%02d", i))
			measure(&acquisition, func() {
				result, err := reconciler.ReconcileDeviceLabels(ctx, orgID, *device.Metadata.Name)
				Expect(err).NotTo(HaveOccurred())
				Expect(result.LabelsChanged && result.OwnershipChanged).To(BeTrue())
			})
		}
		snapshot, err := devices.GetLabelSnapshot(ctx, orgID, "acquisition-00")
		Expect(err).NotTo(HaveOccurred())
		desired := map[string]domain.DesiredDeviceLabel{}
		originalOwners := map[string]*uuid.UUID{}
		var managed int
		for _, label := range snapshot.Labels {
			desired[label.Key] = domain.DesiredDeviceLabel{Value: label.Value, MappingID: label.MappingID}
			if label.MappingID != nil {
				originalOwners[label.Key] = label.MappingID
				managed++
			}
		}
		// A map mapping can own all keys; isolate store-level owner transfer from CEL output collisions.
		_, err = mappings.Create(ctx, orgID, mapLabelSyncMapping("transfer-target"))
		Expect(err).NotTo(HaveOccurred())
		targetID := mappingID(ctx, db, orgID, "transfer-target")
		for i := 0; i < labelSyncMeasurementRepetitions; i++ {
			snapshot, err = devices.GetLabelSnapshot(ctx, orgID, "acquisition-00")
			Expect(err).NotTo(HaveOccurred())
			for _, label := range snapshot.Labels {
				if label.MappingID == nil {
					continue
				}
				value := desired[label.Key]
				value.MappingID = &targetID
				if i%2 == 1 {
					value.MappingID = originalOwners[label.Key]
				}
				desired[label.Key] = value
			}
			measure(&transfer, func() {
				result, err := devices.ApplyLabels(ctx, orgID, "acquisition-00", snapshot, desired, nil)
				Expect(err).NotTo(HaveOccurred())
				Expect(result.OwnershipChanged).To(BeTrue())
				Expect(result.LabelsChanged || result.ManagedLabelsChanged).To(BeFalse())
			})
		}
		persisted, err := devices.GetLabelSnapshot(ctx, orgID, "acquisition-00")
		Expect(err).NotTo(HaveOccurred())
		for _, label := range persisted.Labels {
			Expect(label.Value).To(Equal(desired[label.Key].Value))
			Expect(label.MappingID).To(Equal(desired[label.Key].MappingID))
		}
		Expect(acquisition.Updates).To(Equal(2 * labelSyncMeasurementRepetitions))
		Expect(transfer.Updates).To(Equal(2 * labelSyncMeasurementRepetitions))
		Expect(managed).To(BeNumerically(">", 0))
		Expect(acquisition.Rollbacks + transfer.Rollbacks).To(BeZero())
		Expect(acquisition.Commits).To(Equal(acquisition.Transactions))
		Expect(transfer.Commits).To(Equal(transfer.Transactions))
		AddReportEntry("managed-labels", managed)
		AddReportEntry("initial-acquisition", acquisition.report())
		AddReportEntry("owner-only-transfer", transfer.report())
	})

	It("When one managed value changes it should measure trigger writes to unchanged labels", func() {
		createDevice("value-change")
		_, err := reconciler.ReconcileDeviceLabels(ctx, orgID, "value-change")
		Expect(err).NotTo(HaveOccurred())
		var samples labelSyncMeasurements
		var unchangedRowsRewritten int
		for i := 0; i < labelSyncMeasurementRepetitions; i++ {
			snapshot, err := devices.GetLabelSnapshot(ctx, orgID, "value-change")
			Expect(err).NotTo(HaveOccurred())
			desired := map[string]domain.DesiredDeviceLabel{}
			for _, label := range snapshot.Labels {
				desired[label.Key] = domain.DesiredDeviceLabel{Value: label.Value, MappingID: label.MappingID}
			}
			key := "systeminfo.flightctl.io/architecture"
			label := desired[key]
			label.Value = fmt.Sprintf("arch-%d", i)
			desired[key] = label
			versions := labelSyncRowVersions(ctx, db, orgID, "value-change")
			measure(&samples, func() {
				result, err := devices.ApplyLabels(ctx, orgID, "value-change", snapshot, desired, nil)
				Expect(err).NotTo(HaveOccurred())
				Expect(result.LabelsChanged).To(BeTrue())
				Expect(result.OwnershipChanged).To(BeFalse())
			})
			for otherKey, version := range labelSyncRowVersions(ctx, db, orgID, "value-change") {
				if otherKey != key && versions[otherKey] != version {
					unchangedRowsRewritten++
				}
			}
		}
		AddReportEntry("one-label-value-change", samples.report())
		AddReportEntry("unchanged-label-rows-rewritten", unchangedRowsRewritten)
		Expect(unchangedRowsRewritten).To(BeZero())
	})

	It("When scan pages contain rendered payloads it should measure listing materialization separately from reconciliation", func() {
		const pageSize = 100
		payload := `[{"name":"rendered","data":"` + strings.Repeat("x", 64*1024) + `"}]`
		for i := 0; i < pageSize; i++ {
			device := newLabelSyncDevice(fmt.Sprintf("page-%03d", i), nil)
			_, err := devices.Create(ctx, orgID, device, &devicestore.DeviceRendered{Config: payload, Applications: payload, OsImage: "rendered-image"})
			Expect(err).NotTo(HaveOccurred())
		}
		deviceService := deviceservice.NewDeviceServiceHandler(devices, nil, nil, &recordingEvents{}, nil, "", flightlog.InitLogs())
		var samples, identities, projected labelSyncMeasurements
		var pageNames []string
		for i := 0; i < labelSyncMeasurementRepetitions; i++ {
			measure(&samples, func() {
				pageNames = nil
				page, err := devices.List(ctx, orgID, devicestore.DeviceListParams{ListParams: store.ListParams{Limit: pageSize}})
				Expect(err).NotTo(HaveOccurred())
				Expect(page.Items).To(HaveLen(pageSize))
				for _, device := range page.Items {
					pageNames = append(pageNames, *device.Metadata.Name)
				}
			})
			measure(&projected, func() {
				page, status := deviceService.ListDeviceIdentities(ctx, orgID, pageSize, nil)
				Expect(status.Code).To(Equal(int32(200)), status.Message)
				var names []string
				for _, device := range page.Items {
					Expect(device.Spec).To(BeNil())
					Expect(device.Status).To(BeNil())
					names = append(names, *device.Metadata.Name)
				}
				Expect(names).To(Equal(pageNames))
			})
			measure(&identities, func() {
				var names []string
				Expect(observedDB.Model(&model.Device{}).Select("name").Where("org_id = ? AND spec IS NOT NULL", orgID).
					Order("name ASC").Limit(pageSize+1).Pluck("name", &names).Error).NotTo(HaveOccurred())
				Expect(names).To(Equal(pageNames))
			})
		}
		// Logical text bytes, excluding protocol overhead and TOAST compression.
		var renderedBytes int64
		Expect(db.WithContext(ctx).Raw(`SELECT COALESCE(SUM(octet_length(rendered_config::text) + octet_length(rendered_applications::text) + octet_length(rendered_os::text)), 0) FROM devices WHERE org_id = ?`, orgID).Scan(&renderedBytes).Error).NotTo(HaveOccurred())
		AddReportEntry("page-size", pageSize)
		AddReportEntry("rendered-text-bytes-per-page", renderedBytes)
		AddReportEntry("full-device-listing", samples.report())
		AddReportEntry("identity-page-listing", projected.report())
		AddReportEntry("name-only-query-control", identities.report())
	})
})

type labelSyncMeasurements struct {
	Selects      int
	Updates      int
	Transactions int64
	Commits      int64
	Rollbacks    int64
	durations    []time.Duration
}

func (m labelSyncMeasurements) report() map[string]any {
	sort.Slice(m.durations, func(i, j int) bool { return m.durations[i] < m.durations[j] })
	var total time.Duration
	for _, duration := range m.durations {
		total += duration
	}
	return map[string]any{
		"operations": len(m.durations), "selects": m.Selects, "updates": m.Updates,
		"transactions": m.Transactions, "commits": m.Commits, "rollbacks": m.Rollbacks,
		"total": total.String(), "median": m.durations[len(m.durations)/2].String(),
		"p95": m.durations[(len(m.durations)*95-1)/100].String(),
	}
}

// GORM's SQL logger omits transaction-control calls and trigger-internal writes.
// Count explicit transactions at the connection boundary and label row versions separately.
type labelSyncMeasurementPool struct {
	*sql.DB
	begins    atomic.Int64
	commits   atomic.Int64
	rollbacks atomic.Int64
}

func (p *labelSyncMeasurementPool) GetDBConn() (*sql.DB, error) { return p.DB, nil }

func (p *labelSyncMeasurementPool) BeginTx(ctx context.Context, opts *sql.TxOptions) (gorm.ConnPool, error) {
	tx, err := p.DB.BeginTx(ctx, opts)
	if err != nil {
		return nil, err
	}
	p.begins.Add(1)
	return &labelSyncMeasurementTx{Tx: tx, pool: p}, nil
}

type labelSyncMeasurementTx struct {
	*sql.Tx
	pool *labelSyncMeasurementPool
}

func (t *labelSyncMeasurementTx) Commit() error {
	err := t.Tx.Commit()
	if err == nil {
		t.pool.commits.Add(1)
	}
	return err
}

func (t *labelSyncMeasurementTx) Rollback() error {
	err := t.Tx.Rollback()
	if err == nil {
		t.pool.rollbacks.Add(1)
	}
	return err
}

func labelSyncRowVersions(ctx context.Context, db *gorm.DB, orgID uuid.UUID, name string) map[string]string {
	var rows []struct {
		LabelKey   string
		RowVersion string
	}
	Expect(db.WithContext(ctx).Raw("SELECT label_key, xmin::text AS row_version FROM device_labels WHERE org_id = ? AND device_name = ?", orgID, name).Scan(&rows).Error).NotTo(HaveOccurred())
	versions := make(map[string]string, len(rows))
	for _, row := range rows {
		versions[row.LabelKey] = row.RowVersion
	}
	return versions
}
