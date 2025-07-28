package tpm

import (
	"crypto"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"io/fs"
	"math/big"

	"github.com/google/go-tpm/tpm2"
)

var (
	// errHandleBlobNotFound indicates that no LDevID data was found in the TPM blob
	errHandleBlobNotFound = errors.New("handle blob not found")
)

// keyManager handles TPM key creation, management, and operations
type keyManager struct {
	conn                 *connectionManager
	persistence          *persistence
	srk                  *tpm2.NamedHandle
	ldevid               *tpm2.NamedHandle
	ldevidPub            crypto.PublicKey
	lak                  *tpm2.NamedHandle
	storageHierarchyAuth []byte
}

// newKeyManager creates a new key manager with dependencies
func newKeyManager(conn *connectionManager, persistence *persistence) *keyManager {
	return &keyManager{
		conn:        conn,
		persistence: persistence,
	}
}

// setStorageHierarchyAuth sets the storage hierarchy authentication
func (km *keyManager) setStorageHierarchyAuth(auth []byte) {
	km.storageHierarchyAuth = auth
}

// initialize sets the storage hierarchy auth and creates all required keys
func (km *keyManager) initialize(storageHierarchyAuth []byte) error {
	km.storageHierarchyAuth = storageHierarchyAuth

	_, err := km.generateSRKPrimary()
	if err != nil {
		return fmt.Errorf("generating SRK: %w", err)
	}

	_, err = km.ensureLDevID()
	if err != nil {
		return fmt.Errorf("creating LDevID: %w", err)
	}

	_, err = km.ldevIDPubKey()
	if err != nil {
		return fmt.Errorf("reading LDevID public key: %w", err)
	}

	_, err = km.ensureLAK()
	if err != nil {
		return fmt.Errorf("creating LAK: %w", err)
	}

	return nil
}

// generateSRKPrimary (re-)creates an ECC Primary Storage Root Key in the Owner/Storage Hierarchy.
// This key is deterministically generated from the Storage Primary Seed + input parameters.
func (km *keyManager) generateSRKPrimary() (*tpm2.NamedHandle, error) {
	createPrimaryCmd := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(km.storageHierarchyAuth),
		},
		InPublic: tpm2.New2B(tpm2.ECCSRKTemplate),
	}
	createPrimaryRsp, err := createPrimaryCmd.Execute(km.conn.transport())
	if err != nil {
		return nil, fmt.Errorf("creating SRK primary: %w", err)
	}
	km.srk = &tpm2.NamedHandle{
		Handle: createPrimaryRsp.ObjectHandle,
		Name:   createPrimaryRsp.Name,
	}
	return km.srk, nil
}

// ensureLDevID ensures an LDevID key exists using blob storage at the specified path.
// The Storage Root Key (srk) is used as the parent for the LDevID.
func (km *keyManager) ensureLDevID() (*tpm2.NamedHandle, error) {
	var err error
	km.ldevid, err = km.ensureKey(km.persistence.loadLDevIDBlob, km.persistence.saveLDevIDBlob, LDevIDTemplate)
	if err != nil {
		return nil, fmt.Errorf("ensuring ldevid: %w", err)
	}
	return km.ldevid, nil
}

// ensureLAK creates a Local Attestation Key (LAK) for TPM attestation operations.
// The LAK is an asymmetric key that persists for the device's lifecycle and can be used
// to sign TPM-internal data such as attestations. This is a Restricted signing key.
// Key attributes: Restricted=yes, Sign=yes, Decrypt=no, FixedTPM=yes, SensitiveDataOrigin=yes
// The LAK is created as a child of the SRK to properly handle storage hierarchy authentication.
func (km *keyManager) ensureLAK() (*tpm2.NamedHandle, error) {
	var err error
	km.lak, err = km.ensureKey(km.persistence.loadLAKBlob, km.persistence.saveLAKBlob, AttestationKeyTemplate)
	if err != nil {
		return nil, fmt.Errorf("ensuring LAK: %w", err)
	}
	return km.lak, nil
}

// ensureKey handles the generic key creation and loading logic
func (km *keyManager) ensureKey(load loadBlobFunc, save saveBlobFunc, template tpm2.TPMTPublic) (*tpm2.NamedHandle, error) {
	// Try to load existing blob from file
	public, private, err := load()
	if err == nil {
		return km.loadKeyFromBlob(*public, *private)
	}
	if errors.Is(err, fs.ErrNotExist) || errors.Is(err, errHandleBlobNotFound) {
		createCmd := tpm2.Create{
			ParentHandle: *km.srk,
			InPublic:     tpm2.New2B(template),
		}
		createRsp, err := createCmd.Execute(km.conn.transport())
		if err != nil {
			return nil, fmt.Errorf("creating key: %w", err)
		}

		err = save(createRsp.OutPublic, createRsp.OutPrivate)
		if err != nil {
			return nil, fmt.Errorf("saving blob to file: %w", err)
		}

		return km.loadKeyFromBlob(createRsp.OutPublic, createRsp.OutPrivate)
	}
	// File exists but couldn't be loaded (corrupted, invalid format, etc.)
	return nil, fmt.Errorf("loading blob from persistence: %w", err)
}

// loadKeyFromBlob will load a key for the existing SRK from key blob parts
// According to https://trustedcomputinggroup.org/wp-content/uploads/TPM-2p0-Keys-for-Device-Identity-and-Attestation_v1_r12_pub10082021.pdf
// the blobs returned are safe to be stored as the private portion returned is encrypted by the TPM.
func (km *keyManager) loadKeyFromBlob(public tpm2.TPM2BPublic, private tpm2.TPM2BPrivate) (*tpm2.NamedHandle, error) {
	loadCmd := tpm2.Load{
		ParentHandle: km.srk,
		InPrivate:    private,
		InPublic:     public,
	}

	loadRsp, err := loadCmd.Execute(km.conn.transport())
	if err != nil {
		return nil, fmt.Errorf("loading key: %w", err)
	}

	return &tpm2.NamedHandle{
		Handle: loadRsp.ObjectHandle,
		Name:   loadRsp.Name,
	}, nil
}

// ldevIDPubKey retrieves and caches the LDevID public key
func (km *keyManager) ldevIDPubKey() (crypto.PublicKey, error) {
	pubKey, err := km.eccPublicKey(km.ldevid)
	if err != nil {
		return nil, fmt.Errorf("ldevid public key: %w", err)
	}
	km.ldevidPub = pubKey
	return pubKey, nil
}

// localAttestationPubKey returns the public key of the Local Attestation Key.
func (km *keyManager) localAttestationPubKey() (crypto.PublicKey, error) {
	if km.lak == nil {
		return nil, fmt.Errorf("lak is not yet initialized")
	}
	return km.eccPublicKey(km.lak)
}

// eccPublicKey extracts the ECC public key from a TPM handle
func (km *keyManager) eccPublicKey(namedHandle *tpm2.NamedHandle) (crypto.PublicKey, error) {
	if namedHandle == nil {
		return nil, fmt.Errorf("invalid handle provided")
	}
	pub, err := tpm2.ReadPublic{
		ObjectHandle: namedHandle.Handle,
	}.Execute(km.conn.transport())
	if err != nil {
		return nil, fmt.Errorf("could not read public key: %w", err)
	}
	outpub, err := pub.OutPublic.Contents()
	if err != nil {
		return nil, fmt.Errorf("could not get contents of TPM2Bpublic: %w", err)
	}
	if outpub.Type != tpm2.TPMAlgECC {
		return nil, fmt.Errorf("public key alg %d for key is unsupported", outpub.Type)
	}
	details, err := outpub.Parameters.ECCDetail()
	if err != nil {
		return nil, fmt.Errorf("cannot read ecc details for key: %w", err)
	}
	curve, err := details.CurveID.Curve()
	if err != nil {
		return nil, fmt.Errorf("could not get curve id for key: %w", err)
	}
	unique, err := outpub.Unique.ECC()
	if err != nil {
		return nil, fmt.Errorf("could not get unique parameters for key: %w", err)
	}
	pubkey := &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(unique.X.Buffer),
		Y:     new(big.Int).SetBytes(unique.Y.Buffer),
	}
	return pubkey, nil
}

// createLDevID creates an ECC LDevID key pair under the Storage/Owner hierarchy with the Storage Root Key as parent.
func (km *keyManager) createLDevID() (*tpm2.NamedHandle, error) {
	if km.srk == nil {
		return nil, fmt.Errorf("SRK not initialized")
	}
	createCmd := tpm2.Create{
		ParentHandle: *km.srk,
		InPublic:     tpm2.New2B(LDevIDTemplate),
	}
	createRsp, err := createCmd.Execute(km.conn.transport())
	if err != nil {
		return nil, fmt.Errorf("executing LDevID create command: %w", err)
	}
	loadCmd := tpm2.Load{
		ParentHandle: *km.srk,
		InPrivate:    createRsp.OutPrivate,
		InPublic:     createRsp.OutPublic,
	}

	loadRsp, err := loadCmd.Execute(km.conn.transport())
	if err != nil {
		return nil, fmt.Errorf("error loading ldevid key: %w", err)
	}

	km.ldevid = &tpm2.NamedHandle{
		Handle: loadRsp.ObjectHandle,
		Name:   loadRsp.Name,
	}

	return km.ldevid, nil
}

// public returns the cached LDevID public key
func (km *keyManager) public() crypto.PublicKey {
	return km.ldevidPub
}

// srkHandle returns the Storage Root Key handle
func (km *keyManager) srkHandle() *tpm2.NamedHandle {
	return km.srk
}

// ldevIDHandle returns the LDevID handle
func (km *keyManager) ldevIDHandle() *tpm2.NamedHandle {
	return km.ldevid
}

// lakHandle returns the LAK handle
func (km *keyManager) lakHandle() *tpm2.NamedHandle {
	return km.lak
}

// close flushes all key handles
func (km *keyManager) close() error {
	var errs []error

	// Close LAK if it exists
	if km.lak != nil {
		if err := km.conn.flushContextForHandle(km.lak.Handle); err != nil {
			errs = append(errs, fmt.Errorf("flushing LAK handle: %w", err))
		}
		km.lak = nil
	}

	// Flush transient handles before closing
	if km.srk != nil {
		if err := km.conn.flushContextForHandle(km.srk.Handle); err != nil {
			errs = append(errs, fmt.Errorf("flushing SRK handle: %w", err))
		}
		km.srk = nil
	}

	if km.ldevid != nil {
		if err := km.conn.flushContextForHandle(km.ldevid.Handle); err != nil {
			errs = append(errs, fmt.Errorf("flushing LDevID handle: %w", err))
		}
		km.ldevid = nil
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

// clear resets all key handles and cached data
func (km *keyManager) clear() {
	km.srk = nil
	km.ldevid = nil
	km.lak = nil
	km.ldevidPub = nil
	km.storageHierarchyAuth = nil
}
