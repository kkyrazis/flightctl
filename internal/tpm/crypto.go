package tpm

import (
	"crypto"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/tpm2"
)

// cryptoOperations handles TPM cryptographic operations including signing and endorsement keys
type cryptoOperations struct {
	conn   *connectionManager
	keyMgr *keyManager
}

// newCryptoOperations creates a new crypto operations manager with dependencies
func newCryptoOperations(conn *connectionManager, keyMgr *keyManager) *cryptoOperations {
	return &cryptoOperations{
		conn:   conn,
		keyMgr: keyMgr,
	}
}

// ecdsaSignature represents an ECDSA signature for ASN.1 encoding
type ecdsaSignature struct {
	R *big.Int
	S *big.Int
}

// sign signs the given data using the TPM's LDevID key.
// The rand parameter is ignored as the TPM generates its own randomness internally.
// Opts is ignored as the only hash type supported is SHA256 (as defined by the creation of the key)
func (co *cryptoOperations) sign(rand io.Reader, data []byte, opts crypto.SignerOpts) ([]byte, error) {
	ldevid := co.keyMgr.ldevIDHandle()
	if ldevid == nil {
		return nil, fmt.Errorf("LDevID not initialized")
	}

	sign := tpm2.Sign{
		KeyHandle: tpm2.NamedHandle{
			Handle: ldevid.Handle,
			Name:   ldevid.Name,
		},
		Digest: tpm2.TPM2BDigest{
			Buffer: data[:],
		},
		Validation: tpm2.TPMTTKHashCheck{
			Tag: tpm2.TPMSTHashCheck,
		},
	}

	signRsp, err := sign.Execute(co.conn.transport())
	if err != nil {
		return nil, fmt.Errorf("failed to sign digest with ldevid: %w", err)
	}
	ecdsaSig, err := signRsp.Signature.Signature.ECDSA()
	if err != nil {
		return nil, fmt.Errorf("failed to get ECDSA signature from sign response: %w", err)
	}
	bigR := new(big.Int).SetBytes(ecdsaSig.SignatureR.Buffer)
	bigS := new(big.Int).SetBytes(ecdsaSig.SignatureS.Buffer)
	es := ecdsaSignature{
		R: bigR,
		S: bigS,
	}
	signature, err := asn1.Marshal(es)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal ECDSA signature: %w", err)
	}
	return signature, nil
}

// public returns the LDevID public key
func (co *cryptoOperations) public() crypto.PublicKey {
	return co.keyMgr.public()
}

// endorsementKey gets the endorsement key from the TPM, trying both RSA and ECC variants
func (co *cryptoOperations) endorsementKey() (*client.Key, error) {
	if co.conn.conn == nil {
		return nil, fmt.Errorf("cannot read endorsement key certificate: no connection available")
	}
	// gather errors so that we can report all the types we attempted
	// but if any method returns a key we return that key and drop the errors
	var errs []error
	keyFactories := []struct {
		name    string
		factory func(io.ReadWriter) (*client.Key, error)
	}{
		{"rsa", client.EndorsementKeyRSA},
		{"ecc", client.EndorsementKeyECC},
	}
	for _, keyFactory := range keyFactories {
		key, err := keyFactory.factory(co.conn.conn)
		if err == nil {
			return key, nil
		}
		errs = append(errs, fmt.Errorf("reading %s endorsement: %w", keyFactory.name, err))
	}
	return nil, errors.Join(errs...)
}

// endorsementKeyCert retrieves the endorsement key certificate
func (co *cryptoOperations) endorsementKeyCert() ([]byte, error) {
	key, err := co.endorsementKey()
	if err != nil {
		return nil, fmt.Errorf("reading cert: %w", err)
	}
	defer key.Close()
	return key.CertDERBytes(), nil
}

// endorsementKeyPublic retrieves the endorsement key public area
func (co *cryptoOperations) endorsementKeyPublic() ([]byte, error) {
	key, err := co.endorsementKey()
	if err != nil {
		return nil, fmt.Errorf("reading cert: %w", err)
	}
	res, err := key.PublicArea().Encode()
	if err != nil {
		return nil, fmt.Errorf("encoding public key: %w", err)
	}
	defer key.Close()
	return res, nil
}
