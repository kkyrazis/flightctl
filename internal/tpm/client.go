package tpm

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"io"

	agent_config "github.com/flightctl/flightctl/internal/agent/config"
	"github.com/flightctl/flightctl/internal/agent/device/fileio"
	"github.com/flightctl/flightctl/pkg/log"
	pbattest "github.com/google/go-tpm-tools/proto/attest"
	pbtpm "github.com/google/go-tpm-tools/proto/tpm"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

// Ensure Client implements crypto.Signer interface
var _ crypto.Signer = (*Client)(nil)

// ClientConfig contains configuration options for creating a TPM client.
type ClientConfig struct {
	Log             *log.PrefixLogger
	DeviceWriter    fileio.ReadWriter
	PersistencePath string
	DevicePath      string
}

// Client represents a connection to a TPM device and manages TPM operations.
type Client struct {
	log                *log.PrefixLogger
	persistence        *persistence
	ownership          *ownership
	connection         *connectionManager
	keyManager         *keyManager
	attestationManager *attestationManager
	cryptoOperations   *cryptoOperations
	systemCollector    *systemCollector
}

// NewClient creates a new TPM client with the given configuration.
func NewClient(log *log.PrefixLogger, rw fileio.ReadWriter, config *agent_config.Config) (*Client, error) {
	sysPath := config.TPM.Path
	tpm, err := resolveFromPath(rw, log, sysPath)
	if err != nil {
		return nil, fmt.Errorf("resolving TPM: %w", err)
	}

	// open the TPM connection
	conn, err := tpmutil.OpenTPM(tpm.resourceMgrPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open TPM device at %s: %w", tpm.resourceMgrPath, err)
	}

	return newClientWithConnection(conn, sysPath, log, rw, config)
}

// newClientWithConnection creates a new TPM client with the provided connection.
// This helper function is useful for testing with simulators.
func newClientWithConnection(conn io.ReadWriteCloser, sysPath string, log *log.PrefixLogger, rw fileio.ReadWriter, config *agent_config.Config) (*Client, error) {
	var err error

	p, err := newPersistence(rw, config.TPM.PersistencePath)
	if err != nil {
		return nil, fmt.Errorf("creating persistence: %w", err)
	}

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

	ctx := context.Background()

	var storageHierarchyAuth []byte
	if config.TPM.SkipOwnership {
		storageHierarchyAuth = nil
	} else {
		password, err := client.ownership.ensureStorageHierarchyPassword()
		if err != nil {
			_ = client.Close(ctx)
			return nil, fmt.Errorf("ensuring storage hierarchy password: %w", err)
		}
		storageHierarchyAuth = password
	}

	err = client.keyManager.initialize(storageHierarchyAuth)
	if err != nil {
		_ = client.Close(ctx)
		return nil, fmt.Errorf("initializing key manager: %w", err)
	}

	return client, nil
}

// GetPath returns the TPM device path.
func (t *Client) GetPath() string {
	return t.connection.getPath()
}

// GetLocalAttestationPubKey returns the public key of the Local Attestation Key.
func (t *Client) GetLocalAttestationPubKey() (crypto.PublicKey, error) {
	return t.keyManager.localAttestationPubKey()
}

// UpdateNonce updates the current nonce for attestation operations.
func (t *Client) UpdateNonce(nonce []byte) error {
	return t.attestationManager.updateNonce(nonce)
}

// VendorInfoCollector returns TPM vendor information as a string for system info collection.
func (t *Client) VendorInfoCollector(ctx context.Context) string {
	if t == nil {
		return ""
	}
	return t.systemCollector.vendorInfoCollector(ctx)
}

// AttestationCollector returns TPM attestation as a string for system info collection.
func (t *Client) AttestationCollector(ctx context.Context) string {
	if t == nil {
		return ""
	}
	return t.systemCollector.attestationCollector(ctx)
}

// Close closes the TPM connection and flushes any transient handles.
// It should be called when the TPM is no longer needed to free resources.
func (t *Client) Close(ctx context.Context) error {
	if t == nil {
		return nil
	}
	var errs []error

	// Close key manager (flushes all key handles)
	if err := t.keyManager.close(); err != nil {
		errs = append(errs, fmt.Errorf("closing key manager: %w", err))
	}

	// Close connection manager
	if err := t.connection.close(); err != nil {
		errs = append(errs, fmt.Errorf("closing connection: %w", err))
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

// VendorInfo returns the TPM manufacturer information.
// This can be used to identify the TPM vendor and model.
func (t *Client) VendorInfo() ([]byte, error) {
	if t == nil {
		return nil, fmt.Errorf("cannot get TPM vendor info: nil receiver")
	}
	return t.systemCollector.vendorInfo()
}

// ReadPCRValues reads PCR values from the TPM and populates the provided map.
// The map keys are formatted as "pcr01", "pcr02", etc., and values are hex-encoded.
func (t *Client) ReadPCRValues(measurements map[string]string) error {
	if t == nil {
		return nil
	}
	return t.systemCollector.readPCRValues(measurements)
}

// GetAttestation generates a TPM attestation using the provided nonce and attestation key.
// The nonce must be at least MinNonceLength bytes long for security.
func (t *Client) GetAttestation(nonce []byte, ak *tpm2.NamedHandle) (*pbattest.Attestation, error) {
	return t.attestationManager.attestation(nonce, ak)
}

// GetQuote generates a TPM quote using the provided nonce, attestation key, and PCR selection.
// The quote provides cryptographic evidence of the current PCR values.
func (t *Client) GetQuote(nonce []byte, ak *tpm2.NamedHandle, pcrSelection *tpm2.TPMLPCRSelection) (*pbtpm.Quote, error) {
	return t.attestationManager.quote(nonce, ak, pcrSelection)
}

// crypto.Signer interface methods

func (t *Client) Public() crypto.PublicKey {
	return t.cryptoOperations.public()
}

func (t *Client) GetSigner() crypto.Signer {
	return t
}

// Sign signs the given data using the TPM's LDevID key.
// The rand parameter is ignored as the TPM generates its own randomness internally.
// Opts is ignored as the only hash type supported is SHA256 (as defined by the creation of the key)
func (t *Client) Sign(rand io.Reader, data []byte, opts crypto.SignerOpts) ([]byte, error) {
	return t.cryptoOperations.sign(rand, data, opts)
}

// Endorsement key methods

func (t *Client) EndorsementKeyCert() ([]byte, error) {
	return t.cryptoOperations.endorsementKeyCert()
}

func (t *Client) EndorsementKeyPublic() ([]byte, error) {
	return t.cryptoOperations.endorsementKeyPublic()
}

// Clear resets the TPM Hierarchies and removes any persisted data.
func (t *Client) Clear() error {
	// https://trustedcomputinggroup.org/wp-content/uploads/Trusted-Platform-Module-2.0-Library-Part-3-Version-184_pub.pdf
	// clear only works with the lockout or platform hierarchy owners
	// it clears the lockout, endorsement, and owner hierarchies.
	// Platform or Lockout auth is required
	// Preventing lockout from being able to clear is possible via a setting.
	hierarchies := []struct {
		name string
		cmd  tpm2.Clear
	}{
		{
			name: "lockout",
			cmd: tpm2.Clear{
				AuthHandle: tpm2.AuthHandle{
					Handle: tpm2.TPMRHLockout,
					Auth:   tpm2.PasswordAuth(nil),
				},
			},
		},
		{
			name: "platform",
			cmd: tpm2.Clear{
				AuthHandle: tpm2.AuthHandle{
					Handle: tpm2.TPMRHPlatform,
					Auth:   tpm2.PasswordAuth(nil),
				},
			},
		},
	}
	var errs []error
	for _, hier := range hierarchies {
		if _, err := hier.cmd.Execute(t.connection.transport()); err != nil {
			errs = append(errs, fmt.Errorf("%q clearing TPM hierarchies: %w", hier.name, err))
		}
	}
	// try all valid hierarchies. If all the hierarchies have auth, we won't be able to clear it properly
	if len(errs) == len(hierarchies) {
		return fmt.Errorf("clearing TPM hierarchies: %w", errors.Join(errs...))
	}

	// Clear components
	t.ownership.clear()
	t.keyManager.clear()

	if err := t.persistence.clear(); err != nil {
		return fmt.Errorf("clearing persistence file: %w", err)
	}

	return nil
}
