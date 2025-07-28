//go:build amd64 || arm64

package tpm

import (
	"crypto/ecdsa"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/stretchr/testify/require"
)

func TestLAK(t *testing.T) {
	data, cleanup := setupTestData(t, false)
	defer cleanup()

	_, err := data.client.keyManager.generateSRKPrimary()
	require.NoError(t, err)

	_, err = data.client.keyManager.ensureLAK()
	require.NoError(t, err)

	// Test that we can get the public key from the LAK
	pubKey, err := data.client.GetLocalAttestationPubKey()
	require.NoError(t, err)
	require.NotNil(t, pubKey)

	// Verify it's an ECDSA public key with P-256 curve
	ecdsaPubKey, ok := pubKey.(*ecdsa.PublicKey)
	require.True(t, ok, "LAK public key should be *ecdsa.PublicKey")
	require.Equal(t, "P-256", ecdsaPubKey.Curve.Params().Name)
}

func TestLoadLDevIDErrors(t *testing.T) {
	data, cleanup := setupTestData(t, false)
	defer cleanup()
	_, err := data.client.keyManager.generateSRKPrimary()
	require.NoError(t, err)
	invalidPublic := tpm2.New2B(tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
	})
	invalidPrivate := tpm2.TPM2BPrivate{
		Buffer: []byte{0x00, 0x01, 0x02},
	}
	_, err = data.client.keyManager.loadKeyFromBlob(invalidPublic, invalidPrivate)
	require.Error(t, err)
	require.Contains(t, err.Error(), "loading key")
}

func TestLoadLDevIDFromBlob(t *testing.T) {
	require := require.New(t)
	data, cleanup := setupTestData(t, false)
	defer cleanup()
	_, err := data.client.keyManager.generateSRKPrimary()
	require.NoError(err)

	createCmd := tpm2.Create{
		ParentHandle: data.client.keyManager.srkHandle(),
		InPublic:     tpm2.New2B(LDevIDTemplate),
	}
	transportTPM := data.client.connection.transport()
	createRsp, err := createCmd.Execute(transportTPM)
	require.NoError(err)

	loadedLDevID, err := data.client.keyManager.loadKeyFromBlob(createRsp.OutPublic, createRsp.OutPrivate)
	require.NoError(err)
	require.NotNil(loadedLDevID)
	require.NotEqual(tpm2.TPMHandle(0), loadedLDevID.Handle)
	require.NotEmpty(loadedLDevID.Name)
}

func TestEnsureLDevID(t *testing.T) {
	require := require.New(t)
	data, cleanup := setupTestData(t, false)
	defer cleanup()
	_, err := data.client.keyManager.generateSRKPrimary()
	require.NoError(err)

	readWriter := createTestReadWriter(t)
	data.client.persistence, _ = newPersistence(readWriter, data.client.persistence.path)

	ldevid1, err := data.client.keyManager.ensureLDevID()
	require.NoError(err)
	require.NotNil(ldevid1)
	err = data.client.connection.flushContextForHandle(ldevid1.Handle)
	require.NoError(err)
	ldevid2, err := data.client.keyManager.ensureLDevID()
	require.NoError(err)
	require.NotNil(ldevid2)

	require.Equal(ldevid1.Name, ldevid2.Name)
}

func TestEnsureLDevIDEdgeCases(t *testing.T) {
	tests := []struct {
		name          string
		setupFunc     func(t *testing.T) *Client
		expectError   bool
		errorContains string
	}{
		{
			name: "corrupted file recovery",
			setupFunc: func(t *testing.T) *Client {
				data, cleanup := setupTestData(t, false)
				t.Cleanup(cleanup)

				// Write corrupted file to the existing persistence path
				corruptedContent := "invalid yaml content: [unclosed bracket"
				err := data.client.persistence.rw.WriteFile(data.client.persistence.path, []byte(corruptedContent), 0600)
				require.NoError(t, err)

				return data.client
			},
			expectError:   true,
			errorContains: "loading blob from persistence",
		},
		{
			name: "successful recovery from missing file",
			setupFunc: func(t *testing.T) *Client {
				data, cleanup := setupTestData(t, false)
				_, err := data.client.keyManager.generateSRKPrimary()
				require.NoError(t, err)
				t.Cleanup(cleanup)
				err = data.client.persistence.rw.RemoveFile(data.client.persistence.path)
				require.NoError(t, err)
				return data.client
			},
			expectError:   false,
			errorContains: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tpmClient := tt.setupFunc(t)

			_, err := tpmClient.keyManager.ensureLDevID()

			if tt.expectError {
				require.Error(t, err)
				if tt.errorContains != "" {
					require.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestGetLDevIDPubKey(t *testing.T) {
	t.Run("successful retrieval", func(t *testing.T) {
		require := require.New(t)
		data, cleanup := setupTestData(t, true)
		defer cleanup()
		pubKey, err := data.client.keyManager.ldevIDPubKey()
		require.NoError(err)
		require.NotNil(pubKey)

		// Verify it's an ECDSA public key
		ecdsaPubKey, ok := pubKey.(*ecdsa.PublicKey)
		require.True(ok, "public key should be *ecdsa.PublicKey")

		// Verify it's P-256 curve
		require.Equal("P-256", ecdsaPubKey.Curve.Params().Name)

		// Verify coordinates are valid
		require.True(ecdsaPubKey.X.Sign() > 0, "X coordinate should be positive")
		require.True(ecdsaPubKey.Y.Sign() > 0, "Y coordinate should be positive")
	})

	t.Run("error when ldevid not initialized", func(t *testing.T) {
		require := require.New(t)
		data, cleanup := setupTestData(t, false)
		defer cleanup()

		_, err := data.client.keyManager.ldevIDPubKey()
		require.Error(err)
		require.Contains(err.Error(), "invalid handle provided")
	})
}
