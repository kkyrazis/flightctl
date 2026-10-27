# Label-sync integration measurements

Run the focused PostgreSQL measurement scenarios:

```bash
make integration-test \
  TEST_DIR=./test/integration/store \
  INTEGRATION_PROCS=1 \
  INTEGRATION_GINKGO_FOCUS='LabelSyncMapping performance measurements'
```

For repeated runs, add `INTEGRATION_TEST_COUNT=3`. Keep the environment, race
instrumentation, fixture sizes, and repetition count the same when comparing
branches. Avoid simultaneous builds or other test suites during timing runs.
The suite uses the existing integration containers and requires Podman.

The scenarios report Ginkgo entries in the console and in
`reports/integration_timing.json` and `reports/junit_integration_test.xml`.
Copy reports to a separate location before another integration invocation
replaces them. All scenarios carry the `performance` label and run serially.
They assert correctness and stable optimization boundaries (one explicit
transaction and five SELECTs per no-op reconciliation, a single-statement
mapping snapshot read, two UPDATEs per acquisition/transfer,
and zero unchanged-label row rewrites), with no machine-dependent timing
thresholds.

## Workloads

Each scenario uses a fresh organization/database, the shipped mapping manifest,
and 20 operations per reported measurement. Compiled CEL programs are warmed
before measurement. Fixture creation, status persistence, ownership snapshot
reads for store-only applies, and diagnostic queries are outside timed regions.

| Report | Measured operation |
| --- | --- |
| `mapping-snapshot-load` | Consistent mapping definition/revision load |
| `mapping-revision-read` | Revision-only read of the same organization |
| `steady-state` | Full reconciliation after a CEL-visible boot ID change that leaves label outputs unchanged |
| `initial-acquisition` | Full reconciliation of a fresh device with populated system information and a manual label |
| `owner-only-transfer` | Store apply alternating all managed keys between their original owners and another persisted map mapping, preserving values |
| `one-label-value-change` | Store apply changing one managed value, preserving ownership |
| `full-device-listing` | Existing store listing of 100 devices, each with two rendered payloads containing 64 KiB of data |
| `identity-page-listing` | Production identity-page service used by mapping scans, with ordinary listing cursors and metadata |
| `name-only-query-control` | Ordered/scoped name-only query for the same listing fixture |

The name-only control is a diagnostic lower bound, not a production replacement
for the paginated device service API. Its one-page fixture avoids continuation
and remaining-count queries. Pagination and campaign recovery require separate
correctness coverage before changing the scan path.

The initial-acquisition fixture derives its managed label count from actual
shipped expressions; it does not assume that count stays fixed as mappings evolve.
Owner-only transfer and single-value change isolate store work and intentionally
do not include CEL, event dispatch, or a full reconciliation reload.

## Event-driven worker measurement

To measure device label work from persisted status events:

```bash
make integration-test \
  TEST_DIR=./test/integration/tasks \
  INTEGRATION_PROCS=1 \
  INTEGRATION_TEST_COUNT=2 \
  INTEGRATION_GINKGO_FOCUS='status events leave labels unchanged'
```

The `status-event-worker` report uses one architecture mapping, a warmed worker
reconciliation, and 20 agent status replacements that change the CEL-visible
boot ID without changing label outputs. It verifies that each replacement
persists an identity-only event, then times `DeviceLabelReconciliationLogic.Reconcile`
for that event against the real database and service. Status persistence, event
lookup, and task construction are outside the timed region. Queue delivery,
dispatch, and acknowledgement are not measured. These timings should not be
compared directly with the six-mapping store fixture above.

## Signals and interpretation

- SELECT/UPDATE counts come from the GORM SQL logger. They count application
  statements, including `UPDATE ... RETURNING`, but exclude SQL executed inside
  PostgreSQL triggers. Fixture and diagnostic statements are drained before each
  measurement.
- BEGIN/commit/rollback counts come from a test-only connection wrapper. This
  observes explicit GORM transactions, including its default write transactions,
  not implicit PostgreSQL statement transactions. It preserves the same SQL pool
  and transaction options.
- `unchanged-label-rows-rewritten` compares PostgreSQL `xmin` between committed
  applies, excluding the changed key. It measures row-version churn, not WAL
  bytes, query count, or disk traffic.
- `mapping-snapshot-json-bytes` is the serialized API snapshot size, not database
  wire bytes.
- `rendered-text-bytes-per-page` sums persisted rendered columns' logical text
  lengths. Encryption envelopes can make this larger than the original fixture.
  It excludes protocol overhead, TOAST compression, and other device columns;
  it is not a network capture.
- Durations include Go/GORM/CEL, assertions, SQL recording, database work, and the
  integration runner's race instrumentation. Reports contain total, upper median,
  and nearest-rank p95 wall time. Twenty samples describe local behavior, not a
  production latency distribution.

Use query/transaction counts and correctness checks as stable comparisons first.
Treat timing as directional evidence requiring repeated runs. These scenarios
can justify follow-on experiments in transaction overhead, mapping caching,
ownership batching, scan projections, and label-index write amplification. They
do not measure end-to-end rollout throughput or prove its original regression's
root cause.
