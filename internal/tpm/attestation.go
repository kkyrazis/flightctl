package tpm

import (
	"bytes"
	"fmt"

	"github.com/google/go-tpm-tools/client"
	pbattest "github.com/google/go-tpm-tools/proto/attest"
	pbtpm "github.com/google/go-tpm-tools/proto/tpm"
	"github.com/google/go-tpm/tpm2"
)

// attestationManager handles TPM attestation operations, quotes, and PCR management
type attestationManager struct {
	conn      *connectionManager
	keyMgr    *keyManager
	currNonce []byte
}

// newAttestationManager creates a new attestation manager with dependencies
func newAttestationManager(conn *connectionManager, keyMgr *keyManager) *attestationManager {
	return &attestationManager{
		conn:   conn,
		keyMgr: keyMgr,
	}
}

// updateNonce updates the current nonce for attestation operations.
func (am *attestationManager) updateNonce(nonce []byte) error {
	if len(nonce) < MinNonceLength {
		return fmt.Errorf("nonce does not meet minimum length of %d bytes", MinNonceLength)
	}
	if bytes.Equal(am.currNonce, nonce) {
		return fmt.Errorf("cannot update nonce to same value as current nonce")
	}

	am.currNonce = nonce
	return nil
}

// attestation generates a TPM attestation using the provided nonce and attestation key.
// The nonce must be at least MinNonceLength bytes long for security.
func (am *attestationManager) attestation(nonce []byte, ak *tpm2.NamedHandle) (*pbattest.Attestation, error) {
	// TODO - may want to use CertChainFetcher in the AttestOpts in the future
	// see https://pkg.go.dev/github.com/google/go-tpm-tools/client#AttestOpts

	if len(nonce) < MinNonceLength {
		return nil, fmt.Errorf("nonce does not meet minimum length of %d bytes", MinNonceLength)
	}
	if ak == nil {
		return nil, fmt.Errorf("no attestation key provided")
	}

	akPubKey, err := am.attestationKeyPublic(ak)
	if err != nil {
		return nil, fmt.Errorf("failed to get AK public key: %w", err)
	}

	pcrSelection := createFullPCRSelection()

	quote, err := am.quote(nonce, ak, pcrSelection)
	if err != nil {
		return nil, fmt.Errorf("failed to get quote: %w", err)
	}

	// Create attestation response
	attestation := &pbattest.Attestation{
		AkPub:  akPubKey,
		Quotes: []*pbtpm.Quote{quote},
		// Other fields like AkCert, IntermediateCerts are optional
	}

	return attestation, nil
}

// attestationKeyPublic reads the public area of the attestation key and marshals it
func (am *attestationManager) attestationKeyPublic(ak *tpm2.NamedHandle) ([]byte, error) {
	readPubCmd := tpm2.ReadPublic{
		ObjectHandle: ak.Handle,
	}

	readPubRsp, err := readPubCmd.Execute(am.conn.transport())
	if err != nil {
		return nil, fmt.Errorf("failed to read public area: %w", err)
	}

	// Marshal the public area to bytes
	pubBytes := tpm2.Marshal(readPubRsp.OutPublic)
	return pubBytes, nil
}

// quote generates a TPM quote using the provided nonce, attestation key, and PCR selection.
// The quote provides cryptographic evidence of the current PCR values.
func (am *attestationManager) quote(nonce []byte, ak *tpm2.NamedHandle, pcrSelection *tpm2.TPMLPCRSelection) (*pbtpm.Quote, error) {
	if len(nonce) < MinNonceLength {
		return nil, fmt.Errorf("nonce does not meet minimum length of %d bytes", MinNonceLength)
	}
	if ak == nil {
		return nil, fmt.Errorf("no attestation key provided")
	}
	if pcrSelection == nil {
		return nil, fmt.Errorf("no pcr selection provided")
	}

	// Create TPM2 Quote command using the correct API
	quoteCmd := tpm2.Quote{
		SignHandle: tpm2.AuthHandle{
			Handle: ak.Handle,
			Name:   ak.Name,
			Auth:   tpm2.PasswordAuth(nil), // LAK uses password auth
		},
		QualifyingData: tpm2.TPM2BData{Buffer: nonce},
		InScheme: tpm2.TPMTSigScheme{
			Scheme: tpm2.TPMAlgECDSA,
			Details: tpm2.NewTPMUSigScheme(
				tpm2.TPMAlgECDSA,
				&tpm2.TPMSSchemeHash{HashAlg: tpm2.TPMAlgSHA256},
			),
		},
		PCRSelect: *pcrSelection,
	}

	quoteRsp, err := quoteCmd.Execute(am.conn.transport())
	if err != nil {
		return nil, fmt.Errorf("failed to execute TPM quote: %w", err)
	}

	// Convert signature to bytes using Marshal
	sigBytes := tpm2.Marshal(quoteRsp.Signature)

	// Create the quote response in the expected protobuf format
	quote := &pbtpm.Quote{
		Quote:  quoteRsp.Quoted.Bytes(),
		RawSig: sigBytes,
	}

	pcrs, err := client.ReadPCRs(am.conn.conn, convertTPMLPCRSelectionToPCRSelection(pcrSelection))
	if err != nil {
		return nil, fmt.Errorf("reading PCRs: %w", err)
	}

	quote.Pcrs = pcrs

	return quote, nil
}

// attestationCollector returns TPM attestation as a string for system info collection.
func (am *attestationManager) attestationCollector() string {
	if am.conn.conn == nil {
		return ""
	}
	lak := am.keyMgr.lakHandle()
	if lak == nil {
		return ""
	}

	att, err := am.attestation(am.currNonce, lak)
	if err != nil {
		return ""
	}
	return att.String()
}
