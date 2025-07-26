package tpm

import (
	"fmt"
	"os"

	"github.com/flightctl/flightctl/internal/agent/device/fileio"
	"github.com/google/go-tpm/tpm2"
	"sigs.k8s.io/yaml"
)

// handleBlob represents a serialized key pair for storage.
type handleBlob struct {
	// PublicBlob contains the serialized public key data.
	PublicBlob []byte `json:"public"`
	// PrivateBlob contains the serialized private key data.
	PrivateBlob []byte `json:"private"`
}

// sealedPasswordBlob represents a sealed password object and its associated PCR
type sealedPasswordBlob struct {
	PublicBlob []byte `json:"public"`
	// PrivateBlob contains the serialized private key data of the sealed object.
	PrivateBlob []byte `json:"private"`
	// PCRs contains the PCR selection used for the authorization policy.
	PCRs *tpm2.TPMLPCRSelection `json:"pcrs"`
}

// tpmBlob represents the unified storage format for both sealed password and LDevID
type tpmBlob struct {
	// SealedPassword contains the sealed storage hierarchy password data
	SealedPassword *sealedPasswordBlob `json:"sealed_password,omitempty"`
	// LDevID contains the Local Device Identity key data
	LDevID *handleBlob `json:"ldevid,omitempty"`
	// LAK contains the Local Attestation key data
	LAK *handleBlob `json:"lak,omitempty"`
}

type loadBlobFunc func() (*tpm2.TPM2BPublic, *tpm2.TPM2BPrivate, error)
type saveBlobFunc func(tpm2.TPM2BPublic, tpm2.TPM2BPrivate) error

// persistence handles TPM blob serialization/deserialization and file I/O operations
type persistence struct {
	rw   fileio.ReadWriter
	path string
}

// newPersistence creates a new persistence instance with the given file I/O interface and storage path
func newPersistence(rw fileio.ReadWriter, path string) (*persistence, error) {
	if path == "" {
		return nil, fmt.Errorf("persistence path cannot be empty")
	}
	return &persistence{
		rw:   rw,
		path: path,
	}, nil
}

// saveTPMBlob saves a unified tpmBlob to disk as YAML
func (p *persistence) saveTPMBlob(blob *tpmBlob) error {
	data, err := yaml.Marshal(blob)
	if err != nil {
		return fmt.Errorf("marshaling TPM blob to YAML: %w", err)
	}

	err = p.rw.WriteFile(p.path, data, 0600)
	if err != nil {
		return fmt.Errorf("writing TPM blob to file %s: %w", p.path, err)
	}

	return nil
}

// loadTPMBlob loads a unified tpmBlob from disk
func (p *persistence) loadTPMBlob() (*tpmBlob, error) {
	data, err := p.rw.ReadFile(p.path)
	if err != nil {
		return nil, err
	}

	var blob tpmBlob
	err = yaml.Unmarshal(data, &blob)
	if err != nil {
		return nil, fmt.Errorf("unmarshaling YAML from file %s: %w", p.path, err)
	}

	return &blob, nil
}

func (p *persistence) saveUpdate(update func(blob *tpmBlob)) error {
	// Load existing TPM blob or create new one
	blob, err := p.loadTPMBlob()
	if err != nil {
		// If file doesn't exist, create new blob
		if os.IsNotExist(err) {
			blob = &tpmBlob{}
		} else {
			return fmt.Errorf("loading existing TPM blob: %w", err)
		}
	}
	update(blob)
	return p.saveTPMBlob(blob)
}

func (p *persistence) loadHandleBlob(selector func(blob *tpmBlob) *handleBlob) (*tpm2.TPM2BPublic, *tpm2.TPM2BPrivate, error) {
	tmpBlob, err := p.loadTPMBlob()
	if err != nil {
		return nil, nil, fmt.Errorf("loading TPM blob: %w", err)
	}

	blob := selector(tmpBlob)
	if blob == nil {
		return nil, nil, errHandleBlobNotFound
	}

	public := tpm2.BytesAs2B[tpm2.TPMTPublic](blob.PublicBlob)
	private := tpm2.TPM2BPrivate{Buffer: blob.PrivateBlob}

	return &public, &private, nil
}

// saveLDevIDBlob saves LDevID key data to the TPM blob file
func (p *persistence) saveLDevIDBlob(public tpm2.TPM2BPublic, private tpm2.TPM2BPrivate) error {
	return p.saveUpdate(func(blob *tpmBlob) {
		blob.LDevID = &handleBlob{
			PublicBlob:  public.Bytes(),
			PrivateBlob: private.Buffer,
		}
	})
}

// loadLDevIDBlob loads LDevID key data from the TPM blob file
func (p *persistence) loadLDevIDBlob() (*tpm2.TPM2BPublic, *tpm2.TPM2BPrivate, error) {
	return p.loadHandleBlob(func(blob *tpmBlob) *handleBlob {
		return blob.LDevID
	})
}

// saveLAKBlob saves LAK key data to the TPM blob file
func (p *persistence) saveLAKBlob(public tpm2.TPM2BPublic, private tpm2.TPM2BPrivate) error {
	return p.saveUpdate(func(blob *tpmBlob) {
		blob.LAK = &handleBlob{
			PublicBlob:  public.Bytes(),
			PrivateBlob: private.Buffer,
		}
	})
}

// loadLAKBlob loads LAK key data from the TPM blob file
func (p *persistence) loadLAKBlob() (*tpm2.TPM2BPublic, *tpm2.TPM2BPrivate, error) {
	return p.loadHandleBlob(func(blob *tpmBlob) *handleBlob {
		return blob.LAK
	})
}

// saveSealedPasswordBlob saves sealed password data to the TPM blob file
func (p *persistence) saveSealedPasswordBlob(public tpm2.TPM2BPublic, private tpm2.TPM2BPrivate, pcrSelection *tpm2.TPMLPCRSelection) error {
	// Load existing TPM blob or create new one
	tmpBlob, err := p.loadTPMBlob()
	if err != nil {
		// If file doesn't exist, create new blob
		if os.IsNotExist(err) {
			tmpBlob = &tpmBlob{}
		} else {
			return fmt.Errorf("loading existing TPM blob: %w", err)
		}
	}

	// Update sealed password section
	tmpBlob.SealedPassword = &sealedPasswordBlob{
		PublicBlob:  public.Bytes(),
		PrivateBlob: private.Buffer,
		PCRs:        pcrSelection,
	}

	// Save unified blob
	return p.saveTPMBlob(tmpBlob)
}

// loadSealedPasswordBlob loads sealed password data from the TPM blob file
func (p *persistence) loadSealedPasswordBlob() (*tpm2.TPM2BPublic, *tpm2.TPM2BPrivate, *tpm2.TPMLPCRSelection, error) {
	// Load unified TPM blob
	tmpBlob, err := p.loadTPMBlob()
	if err != nil {
		return nil, nil, nil, err
	}

	// Check if sealed password section exists
	if tmpBlob.SealedPassword == nil {
		return nil, nil, nil, fmt.Errorf("no sealed password data found in TPM blob at %s", p.path)
	}

	public := tpm2.BytesAs2B[tpm2.TPMTPublic](tmpBlob.SealedPassword.PublicBlob)
	private := tpm2.TPM2BPrivate{Buffer: tmpBlob.SealedPassword.PrivateBlob}

	return &public, &private, tmpBlob.SealedPassword.PCRs, nil
}

// clearSealedPasswordBlob removes sealed password data from the TPM blob file
func (p *persistence) clearSealedPasswordBlob() error {
	// Load existing TPM blob
	tmpBlob, err := p.loadTPMBlob()
	if err != nil {
		// If file doesn't exist, nothing to clear
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("loading existing TPM blob: %w", err)
	}

	// Clear sealed password section
	tmpBlob.SealedPassword = nil

	// Save updated blob
	return p.saveTPMBlob(tmpBlob)
}
