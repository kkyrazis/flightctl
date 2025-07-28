package tpm

import (
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// ownership handles TPM ownership workflow logic and password management
type ownership struct {
	conn                 *connectionManager
	persistence          *persistence
	storageHierarchyAuth []byte
}

// newOwnership creates a new ownership instance with references to connection manager and persistence
func newOwnership(conn *connectionManager, persistence *persistence) *ownership {
	return &ownership{
		conn:        conn,
		persistence: persistence,
	}
}

// ensureStorageHierarchyPassword ensures the storage hierarchy has a password set.
// If no password is currently set, it generates and sets a new random password.
// Returns the password being used for the storage hierarchy.
func (o *ownership) ensureStorageHierarchyPassword() ([]byte, error) {
	if o.storageAuth() != nil {
		return o.storageAuth(), nil
	}

	authSet, err := o.checkStorageHierarchyAuthStatus()
	if err != nil {
		return nil, fmt.Errorf("checking storage hierarchy auth status: %w", err)
	}

	if !authSet {
		password, err := o.generateStoragePassword()
		if err != nil {
			return nil, fmt.Errorf("generating storage hierarchy password: %w", err)
		}

		// ensure we persist the password before we change it
		err = o.sealStoragePassword(password)
		if err != nil {
			return nil, fmt.Errorf("sealing storage password: %w", err)
		}

		if err := o.changeStorageHierarchyPassword(nil, password); err != nil {
			return nil, fmt.Errorf("setting storage hierarchy password: %w", err)
		}

		o.storageHierarchyAuth = password
		return password, nil
	}

	password, err := o.unsealStoragePassword()
	if err != nil {
		return nil, fmt.Errorf("unseal storage password: %w", err)
	}
	o.storageHierarchyAuth = password
	return password, nil
}

// resetStorageHierarchyPassword resets the storage hierarchy password to empty.
// If no auth is currently set, it returns early without error.
// If auth is set, it unseals the current password and changes it back to empty.
func (o *ownership) resetStorageHierarchyPassword() error {
	if o.storageAuth() == nil {
		return nil
	}

	currentPassword, err := o.unsealStoragePassword()
	if err != nil {
		return fmt.Errorf("unsealing current storage password: %w", err)
	}

	if err := o.changeStorageHierarchyPassword(currentPassword, []byte{}); err != nil {
		return fmt.Errorf("changing storage hierarchy password to empty: %w", err)
	}

	if err := o.persistence.clearSealedPasswordBlob(); err != nil {
		return fmt.Errorf("clearing sealed password blob: %w", err)
	}

	o.clear()
	return nil
}

// checkStorageHierarchyAuthStatus checks if the storage hierarchy has a password set
// using TPM GetCapabilities command. Returns true if a password is set.
func (o *ownership) checkStorageHierarchyAuthStatus() (bool, error) {
	getCapCmd := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTPermanent),
		PropertyCount: 1,
	}

	rsp, err := getCapCmd.Execute(o.conn.transport())
	if err != nil {
		return false, fmt.Errorf("getting TPM capabilities: %w", err)
	}

	data, err := rsp.CapabilityData.Data.TPMProperties()
	if err != nil {
		return false, fmt.Errorf("parsing properties: %w", err)
	}
	for _, prop := range data.TPMProperty {
		if prop.Property == tpm2.TPMPTPermanent {
			// ownerAuthSet is bit 0 of this value.
			return prop.Value&0x1 != 0, nil
		}
	}
	return false, fmt.Errorf("no valid properties found")
}

// generateStoragePassword generates a random storage hierarchy password using TPM RNG
func (o *ownership) generateStoragePassword() ([]byte, error) {
	// Use TPM's hardware random number generator for 32-byte password
	getRandCmd := tpm2.GetRandom{
		BytesRequested: 32,
	}

	rsp, err := getRandCmd.Execute(o.conn.transport())
	if err != nil {
		return nil, fmt.Errorf("generating TPM random password: %w", err)
	}

	if len(rsp.RandomBytes.Buffer) != 32 {
		return nil, fmt.Errorf("TPM returned %d bytes, expected 32", len(rsp.RandomBytes.Buffer))
	}

	return rsp.RandomBytes.Buffer, nil
}

// changeStorageHierarchyPassword changes the storage hierarchy password
func (o *ownership) changeStorageHierarchyPassword(currentPassword []byte, newPassword []byte) error {
	changeAuthCmd := tpm2.HierarchyChangeAuth{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(currentPassword),
		},
		NewAuth: tpm2.TPM2BAuth{Buffer: newPassword},
	}

	_, err := changeAuthCmd.Execute(o.conn.transport())
	if err != nil {
		return fmt.Errorf("setting storage hierarchy password: %w", err)
	}

	return nil
}

// sealStoragePassword seals the storage hierarchy password using PCR policy
func (o *ownership) sealStoragePassword(password []byte) error {
	if len(password) == 0 {
		return fmt.Errorf("password cannot be empty")
	}

	pcrSelection := createSealPCRSelection()

	policyDigest, err := o.calculatePCRPolicyDigest(pcrSelection)
	if err != nil {
		return fmt.Errorf("calculating PCR policy digest: %w", err)
	}

	endorsementPrimary, err := o.createEndorsementPrimary()
	if err != nil {
		return err
	}
	defer func() { _ = o.conn.flushContextForHandle(endorsementPrimary.Handle) }()

	// Create the template with the calculated policy digest
	// Make an explicit copy to avoid modifying the global template
	template := StoragePasswordPCRSealTemplate
	template.AuthPolicy = tpm2.TPM2BDigest{Buffer: policyDigest}

	// Create the sealed object using endorsement primary as parent
	createCmd := tpm2.Create{
		ParentHandle: *endorsementPrimary,
		InPublic:     tpm2.New2B(template),
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				Data: tpm2.NewTPMUSensitiveCreate(&tpm2.TPM2BSensitiveData{Buffer: password}),
			},
		},
	}

	createRsp, err := createCmd.Execute(o.conn.transport())
	if err != nil {
		return fmt.Errorf("creating sealed object: %w", err)
	}

	// Save the sealed blob and PCR selection to file
	err = o.persistence.saveSealedPasswordBlob(createRsp.OutPublic, createRsp.OutPrivate, pcrSelection)
	if err != nil {
		return fmt.Errorf("saving sealed password blob: %w", err)
	}

	return nil
}

// unsealStoragePassword unseals the storage hierarchy password using PCR policy
func (o *ownership) unsealStoragePassword() ([]byte, error) {
	public, private, pcrSelection, err := o.persistence.loadSealedPasswordBlob()
	if err != nil {
		return nil, fmt.Errorf("loading sealed password blob: %w", err)
	}

	endorsementPrimary, err := o.createEndorsementPrimary()
	if err != nil {
		return nil, fmt.Errorf("creating endorsement primary key: %w", err)
	}
	defer func() { _ = o.conn.flushContextForHandle(endorsementPrimary.Handle) }()

	loadCmd := tpm2.Load{
		ParentHandle: *endorsementPrimary,
		InPublic:     *public,
		InPrivate:    *private,
	}

	loadRsp, err := loadCmd.Execute(o.conn.transport())
	if err != nil {
		return nil, fmt.Errorf("loading sealed object: %w", err)
	}
	defer func() { _ = o.conn.flushContextForHandle(loadRsp.ObjectHandle) }()

	unsealCmd := tpm2.Unseal{
		ItemHandle: tpm2.AuthHandle{
			Handle: loadRsp.ObjectHandle,
			Name:   loadRsp.Name,
			Auth: tpm2.Policy(tpm2.TPMAlgSHA256, 16, func(tpm transport.TPM, handle tpm2.TPMISHPolicy, policyRef tpm2.TPM2BNonce) error {
				policyPCRCmd := tpm2.PolicyPCR{
					PolicySession: handle,
					PcrDigest:     tpm2.TPM2BDigest{},
					Pcrs:          *pcrSelection,
				}
				_, err := policyPCRCmd.Execute(tpm)
				return err
			}),
		},
	}

	unsealRsp, err := unsealCmd.Execute(o.conn.transport())
	if err != nil {
		return nil, fmt.Errorf("unsealing password: %w", err)
	}

	return unsealRsp.OutData.Buffer, nil
}

// createEndorsementPrimary creates an endorsement hierarchy primary key
func (o *ownership) createEndorsementPrimary() (*tpm2.NamedHandle, error) {
	createPrimaryCmd := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHEndorsement,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic: tpm2.New2B(tpm2.ECCSRKTemplate),
	}

	createPrimaryRsp, err := createPrimaryCmd.Execute(o.conn.transport())
	if err != nil {
		return nil, fmt.Errorf("creating endorsement primary key: %w", err)
	}

	endorsementPrimary := &tpm2.NamedHandle{
		Handle: createPrimaryRsp.ObjectHandle,
		Name:   createPrimaryRsp.Name,
	}

	return endorsementPrimary, nil
}

// createPCRPolicySession creates a policy session for PCR-based authorization.
// Returns the policy session handle and the computed policy digest.
func (o *ownership) createPCRPolicySession(pcrSelection *tpm2.TPMLPCRSelection) ([]byte, error) {
	startAuthCmd := tpm2.StartAuthSession{
		NonceCaller: tpm2.TPM2BNonce{Buffer: make([]byte, 16)},
		SessionType: tpm2.TPMSEPolicy,
		Symmetric: tpm2.TPMTSymDef{
			Algorithm: tpm2.TPMAlgNull,
		},
		AuthHash: tpm2.TPMAlgSHA256,
	}

	startAuthRsp, err := startAuthCmd.Execute(o.conn.transport())
	if err != nil {
		return nil, fmt.Errorf("starting policy session: %w", err)
	}

	sessionHandle := startAuthRsp.SessionHandle
	defer func() { _ = o.conn.flushContextForHandle(sessionHandle) }()

	policyPCRCmd := tpm2.PolicyPCR{
		PolicySession: sessionHandle,
		PcrDigest:     tpm2.TPM2BDigest{},
		Pcrs:          *pcrSelection,
	}

	_, err = policyPCRCmd.Execute(o.conn.transport())
	if err != nil {
		return nil, fmt.Errorf("applying PCR policy: %w", err)
	}

	policyGetDigestCmd := tpm2.PolicyGetDigest{
		PolicySession: sessionHandle,
	}

	policyGetDigestRsp, err := policyGetDigestCmd.Execute(o.conn.transport())
	if err != nil {
		return nil, fmt.Errorf("getting policy digest: %w", err)
	}

	return policyGetDigestRsp.PolicyDigest.Buffer, nil
}

// calculatePCRPolicyDigest calculates the PCR policy digest for the given selection
func (o *ownership) calculatePCRPolicyDigest(pcrSelection *tpm2.TPMLPCRSelection) ([]byte, error) {
	policyDigest, err := o.createPCRPolicySession(pcrSelection)
	if err != nil {
		return nil, fmt.Errorf("creating PCR policy session: %w", err)
	}

	return policyDigest, nil
}

// storageAuth returns the current storage hierarchy auth
func (o *ownership) storageAuth() []byte {
	return o.storageHierarchyAuth
}

// clear resets the ownership component state
func (o *ownership) clear() {
	o.storageHierarchyAuth = nil
}
