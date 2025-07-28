//go:build amd64 || arm64

package tpm

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"
	"testing"

	agent_config "github.com/flightctl/flightctl/internal/agent/config"
	"github.com/flightctl/flightctl/internal/agent/device/fileio"
	"github.com/flightctl/flightctl/pkg/log"
	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/stretchr/testify/require"
)

// TestFixture provides a common test fixture for TPM tests
type TestFixture struct {
	client *Client
}

// TestData contains common test data for TPM operations
type TestData struct {
	client *Client
	nonce  []byte
	pcrSel *tpm2.TPMLPCRSelection
}

// testEcdsaSignature represents an ECDSA signature for ASN.1 encoding (used in crypto tests)
type testEcdsaSignature struct {
	R *big.Int
	S *big.Int
}

// openTPMSimulator creates a TPM simulator client for testing
func openTPMSimulator(t *testing.T, init bool) (*Client, error) {
	t.Helper()
	require := require.New(t)

	simulator, err := simulator.Get()
	require.NoError(err)

	// Create a test ReadWriter and temporary path for persistence
	rw := createTestReadWriter(t)
	tempPath := "test_persistence.yaml"

	// Create all components like newClientWithConnection does
	p, err := newPersistence(rw, tempPath)
	require.NoError(err)

	cm := newConnectionManager(simulator, "test_simulator")
	km := newKeyManager(cm, p)
	am := newAttestationManager(cm, km)
	co := newCryptoOperations(cm, km)
	sc := newSystemCollector(cm, km, am, log.NewPrefixLogger("test"))
	o := newOwnership(cm, p)

	tpm := &Client{
		log:                log.NewPrefixLogger("test"),
		persistence:        p,
		connection:         cm,
		keyManager:         km,
		attestationManager: am,
		cryptoOperations:   co,
		systemCollector:    sc,
		ownership:          o,
	}

	if init {
		err = tpm.keyManager.initialize(nil) // No storage hierarchy auth for tests
		require.NoError(err)

	}
	return tpm, nil
}

// setupTestFixture creates a test fixture with a TPM client
func setupTestFixture(t *testing.T, init bool) (*TestFixture, error) {
	t.Helper()

	tpm, err := openTPMSimulator(t, init)
	if err != nil {
		return nil, fmt.Errorf("unable to open tpm simulator: %w", err)
	}

	return &TestFixture{client: tpm}, nil
}

// setupTestData creates test data with a TPM client, nonce, and PCR selection
func setupTestData(t *testing.T, init bool) (TestData, func()) {
	t.Helper()
	require := require.New(t)

	f, err := setupTestFixture(t, init)
	require.NoError(err)

	nonce := make([]byte, 8)
	_, err = io.ReadFull(rand.Reader, nonce)
	require.NoError(err)

	selection := createTestFullPCRSelection()

	data := TestData{
		client: f.client,
		nonce:  nonce,
		pcrSel: selection,
	}

	cleanup := func() {
		data.client.Close(context.Background())
	}

	return data, cleanup
}

// createTestReadWriter creates a test ReadWriter with a temporary directory
func createTestReadWriter(t *testing.T) fileio.ReadWriter {
	t.Helper()
	tempDir := t.TempDir()
	return fileio.NewReadWriter(fileio.WithTestRootDir(tempDir))
}

// createTestFullPCRSelection creates a full PCR selection for testing
func createTestFullPCRSelection() *tpm2.TPMLPCRSelection {
	return &tpm2.TPMLPCRSelection{
		PCRSelections: []tpm2.TPMSPCRSelection{
			{
				Hash:      tpm2.TPMAlgSHA256,
				PCRSelect: tpm2.PCClientCompatible.PCRs(uint(tpm2.TPMAlgSHA256)),
			},
		},
	}
}

// verifyTestECDSASignature verifies an ECDSA signature against data
func verifyTestECDSASignature(pubKey *ecdsa.PublicKey, data []byte, signature []byte) error {
	// Parse ASN.1 encoded signature
	var sig testEcdsaSignature
	_, err := asn1.Unmarshal(signature, &sig)
	if err != nil {
		return fmt.Errorf("failed to parse signature: %w", err)
	}

	// Hash the data
	hash := sha256.Sum256(data)

	// Verify signature
	if !ecdsa.Verify(pubKey, hash[:], sig.R, sig.S) {
		return fmt.Errorf("signature verification failed")
	}

	return nil
}

// newTestClientWithConnection creates a new TPM client with the given connection (used in ownership tests)
func newTestClientWithConnection(conn io.ReadWriteCloser, sysPath string, log *log.PrefixLogger, rw fileio.ReadWriter, config *agent_config.Config) (*Client, error) {
	// Create persistence
	p, err := newPersistence(rw, config.TPM.PersistencePath)
	if err != nil {
		return nil, fmt.Errorf("creating persistence: %w", err)
	}

	// Create all components
	cm := newConnectionManager(conn, sysPath)
	km := newKeyManager(cm, p)
	am := newAttestationManager(cm, km)
	co := newCryptoOperations(cm, km)
	sc := newSystemCollector(cm, km, am, log)
	o := newOwnership(cm, p)

	client := &Client{
		log:                log,
		persistence:        p,
		connection:         cm,
		keyManager:         km,
		attestationManager: am,
		cryptoOperations:   co,
		systemCollector:    sc,
		ownership:          o,
	}

	// Initialize based on configuration
	if !config.TPM.SkipOwnership {
		password, err := o.ensureStorageHierarchyPassword()
		if err != nil {
			return nil, fmt.Errorf("ensuring storage hierarchy password: %w", err)
		}
		km.setStorageHierarchyAuth(password)
	}

	// Initialize key manager
	err = km.initialize(km.storageHierarchyAuth)
	if err != nil {
		return nil, fmt.Errorf("initializing key manager: %w", err)
	}

	return client, nil
}
