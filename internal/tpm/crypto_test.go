//go:build amd64 || arm64

package tpm

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSign(t *testing.T) {
	require := require.New(t)
	data, cleanup := setupTestData(t, true)
	defer cleanup()

	// TPM Sign expects a 32-byte hash (SHA-256)
	testHash := sha256.Sum256([]byte("test data to sign"))

	t.Run("successful signing", func(t *testing.T) {
		signature, err := data.client.Sign(nil, testHash[:], nil)
		require.NoError(err)
		require.NotEmpty(signature)

		// Verify signature is ASN.1 encoded
		var sig testEcdsaSignature
		_, err = asn1.Unmarshal(signature, &sig)
		require.NoError(err)
		require.NotNil(sig.R)
		require.NotNil(sig.S)
		require.True(sig.R.Sign() > 0, "R should be positive")
		require.True(sig.S.Sign() > 0, "S should be positive")
	})

	t.Run("signing different hash inputs", func(t *testing.T) {
		testCases := []struct {
			name     string
			origData []byte
		}{
			{"empty data hash", []byte{}},
			{"small data hash", []byte("hello")},
			{"medium data hash", make([]byte, 256)},
			{"large data hash", make([]byte, 1024)},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				// Hash the data first since TPM expects a digest
				hash := sha256.Sum256(tc.origData)
				signature, err := data.client.Sign(rand.Reader, hash[:], crypto.SHA256)
				require.NoError(err)
				require.NotEmpty(signature)
			})
		}
	})

	t.Run("rand parameter is ignored", func(t *testing.T) {
		// Sign with nil rand
		sig1, err := data.client.Sign(nil, testHash[:], nil)
		require.NoError(err)

		// Sign with real rand - should still work (rand is ignored)
		sig2, err := data.client.Sign(rand.Reader, testHash[:], nil)
		require.NoError(err)

		// Both signatures should be valid (though different due to randomness)
		require.NotEmpty(sig1)
		require.NotEmpty(sig2)
	})
}

func TestSignAndVerify(t *testing.T) {
	require := require.New(t)
	data, cleanup := setupTestData(t, true)
	defer cleanup()

	t.Run("sign and verify integration", func(t *testing.T) {
		testPayloads := [][]byte{
			[]byte("test message 1"),
			[]byte("another test message"),
			[]byte(""),
			make([]byte, 100), // filled with zeros
		}

		// Get public key
		pubKey, err := data.client.keyManager.ldevIDPubKey()
		require.NoError(err)
		ecdsaPubKey := pubKey.(*ecdsa.PublicKey)

		for i, payload := range testPayloads {
			t.Run(fmt.Sprintf("payload_%d", i), func(t *testing.T) {
				// Hash the payload since TPM expects a digest
				hash := sha256.Sum256(payload)

				// Sign the hash
				signature, err := data.client.Sign(rand.Reader, hash[:], crypto.SHA256)
				require.NoError(err)

				// Verify the signature against the original payload
				err = verifyTestECDSASignature(ecdsaPubKey, payload, signature)
				require.NoError(err, "signature verification should succeed")
			})
		}
	})

	t.Run("verification fails with wrong data", func(t *testing.T) {
		originalData := []byte("original data")
		wrongData := []byte("wrong data")

		// Get public key
		pubKey, err := data.client.keyManager.ldevIDPubKey()
		require.NoError(err)
		ecdsaPubKey := pubKey.(*ecdsa.PublicKey)

		// Hash and sign original data
		originalHash := sha256.Sum256(originalData)
		signature, err := data.client.Sign(rand.Reader, originalHash[:], crypto.SHA256)
		require.NoError(err)

		// Try to verify with wrong data - should fail
		err = verifyTestECDSASignature(ecdsaPubKey, wrongData, signature)
		require.Error(err, "verification should fail with wrong data")
	})
}

func TestCryptoSignerInterface(t *testing.T) {
	data, cleanup := setupTestData(t, true)
	defer cleanup()

	t.Run("TPM implements crypto.Signer", func(t *testing.T) {
		require := require.New(t)
		// Verify TPM implements crypto.Signer interface
		var signer crypto.Signer = data.client
		require.NotNil(signer)

		// Test Public() method
		pubKey := signer.Public()
		require.NotNil(pubKey)

		ecdsaPubKey, ok := pubKey.(*ecdsa.PublicKey)
		require.True(ok, "public key should be *ecdsa.PublicKey")
		require.Equal("P-256", ecdsaPubKey.Curve.Params().Name)
	})

	t.Run("signer-only interface test with full sign and verify", func(t *testing.T) {
		require := require.New(t)
		// This test uses TPM only as crypto.Signer interface
		testSignerInterface := func(signer crypto.Signer) error {
			testData := []byte("interface test data")
			// Hash the data since TPM expects a digest
			testHash := sha256.Sum256(testData)

			// Sign using only crypto.Signer interface
			signature, err := signer.Sign(rand.Reader, testHash[:], crypto.SHA256)
			if err != nil {
				return fmt.Errorf("signing failed: %w", err)
			}

			// Get public key using only crypto.Signer interface
			pubKey := signer.Public()
			ecdsaPubKey, ok := pubKey.(*ecdsa.PublicKey)
			if !ok {
				return fmt.Errorf("expected *ecdsa.PublicKey, got %T", pubKey)
			}

			// Verify signature against original data (verifyTestECDSASignature will hash it)
			return verifyTestECDSASignature(ecdsaPubKey, testData, signature)
		}

		// Test with TPM as crypto.Signer
		var signer crypto.Signer = data.client
		err := testSignerInterface(signer)
		require.NoError(err, "signer interface test should pass")
	})

	t.Run("GetSigner returns self", func(t *testing.T) {
		require := require.New(t)
		signer := data.client.GetSigner()
		require.Equal(data.client, signer, "GetSigner should return the TPM instance itself")
	})
}

func TestEndorsementKeyPublic(t *testing.T) {
	tests := []struct {
		name               string
		setupTPM           func(t *testing.T) *Client
		expectError        bool
		expectedErrContent string
		validateResult     func(t *testing.T, data []byte)
	}{
		{
			name: "successful public key retrieval with simulator",
			setupTPM: func(t *testing.T) *Client {
				require := require.New(t)
				tpm, err := openTPMSimulator(t, false)
				require.NoError(err)
				return tpm
			},
			expectError: false,
			validateResult: func(t *testing.T, data []byte) {
				require := require.New(t)
				require.NotEmpty(data, "encoded public key data should not be empty")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require := require.New(t)
			tpm := tc.setupTPM(t)
			defer func() {
				_ = tpm.Close(context.Background())
			}()

			publicKeyData, err := tpm.EndorsementKeyPublic()

			if tc.expectError {
				require.Error(err)
				require.Contains(err.Error(), tc.expectedErrContent)
				require.Empty(publicKeyData)
				return
			}

			require.NoError(err)
			if tc.validateResult != nil {
				tc.validateResult(t, publicKeyData)
			}
		})
	}
}
