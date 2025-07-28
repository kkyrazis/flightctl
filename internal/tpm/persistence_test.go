//go:build amd64 || arm64

package tpm

import (
	"testing"

	"github.com/flightctl/flightctl/internal/agent/device/fileio"
	"github.com/google/go-tpm/tpm2"
	"github.com/stretchr/testify/require"
)

func TestSaveLDevIDBlob(t *testing.T) {
	tests := []struct {
		name          string
		setupFunc     func(t *testing.T) (*Client, fileio.ReadWriter, tpm2.TPM2BPublic, tpm2.TPM2BPrivate)
		path          string
		expectError   bool
		errorContains string
	}{
		{
			name: "success case",
			setupFunc: func(t *testing.T) (*Client, fileio.ReadWriter, tpm2.TPM2BPublic, tpm2.TPM2BPrivate) {
				data, cleanup := setupTestData(t, true)
				t.Cleanup(cleanup)
				err := data.client.connection.flushContextForHandle(data.client.keyManager.lakHandle().Handle)
				require.NoError(t, err)

				readWriter := createTestReadWriter(t)
				data.client.persistence, _ = newPersistence(readWriter, data.client.persistence.path)

				// Create valid blob data
				createCmd := tpm2.Create{
					ParentHandle: data.client.keyManager.srkHandle(),
					InPublic:     tpm2.New2B(LDevIDTemplate),
				}
				transportTPM := data.client.connection.transport()
				createRsp, err := createCmd.Execute(transportTPM)
				require.NoError(t, err)

				return data.client, readWriter, createRsp.OutPublic, createRsp.OutPrivate
			},
			path:        "test_blob.yaml",
			expectError: false,
		},
		{
			name: "YAML marshaling success with nested path",
			setupFunc: func(t *testing.T) (*Client, fileio.ReadWriter, tpm2.TPM2BPublic, tpm2.TPM2BPrivate) {
				data, cleanup := setupTestData(t, true)
				t.Cleanup(cleanup)
				err := data.client.connection.flushContextForHandle(data.client.keyManager.lakHandle().Handle)
				require.NoError(t, err)

				readWriter := createTestReadWriter(t)
				data.client.persistence, _ = newPersistence(readWriter, data.client.persistence.path)

				// Create valid blob data
				createCmd := tpm2.Create{
					ParentHandle: data.client.keyManager.srkHandle(),
					InPublic:     tpm2.New2B(LDevIDTemplate),
				}
				transportTPM := data.client.connection.transport()
				createRsp, err := createCmd.Execute(transportTPM)
				require.NoError(t, err)

				return data.client, readWriter, createRsp.OutPublic, createRsp.OutPrivate
			},
			path:        "nested/test_blob.yaml",
			expectError: false,
		},
		{
			name: "empty blob data",
			setupFunc: func(t *testing.T) (*Client, fileio.ReadWriter, tpm2.TPM2BPublic, tpm2.TPM2BPrivate) {
				data, cleanup := setupTestData(t, true)
				t.Cleanup(cleanup)
				err := data.client.connection.flushContextForHandle(data.client.keyManager.lakHandle().Handle)
				require.NoError(t, err)

				readWriter := createTestReadWriter(t)
				data.client.persistence, _ = newPersistence(readWriter, data.client.persistence.path)

				// Create empty blob data
				emptyPublic := tpm2.TPM2BPublic{}
				emptyPrivate := tpm2.TPM2BPrivate{}

				return data.client, readWriter, emptyPublic, emptyPrivate
			},
			path:        "empty_blob.yaml",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpClient, _, public, private := tt.setupFunc(t)

			err := tmpClient.persistence.saveLDevIDBlob(public, private)

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

func TestLoadLDevIDBlobErrors(t *testing.T) {
	tests := []struct {
		name          string
		setupFunc     func(t *testing.T) *Client
		expectError   bool
		errorContains string
	}{
		{
			name: "file not found",
			setupFunc: func(t *testing.T) *Client {
				data, cleanup := setupTestData(t, true)
				t.Cleanup(cleanup)

				err := data.client.persistence.rw.RemoveFile(data.client.persistence.path)
				require.NoError(t, err)

				return data.client
			},
			expectError:   true,
			errorContains: "",
		},
		{
			name: "corrupted YAML",
			setupFunc: func(t *testing.T) *Client {
				data, cleanup := setupTestData(t, true)
				t.Cleanup(cleanup)

				// Write corrupted YAML to the persistence path
				corruptedContent := "invalid yaml content: [unclosed bracket"
				err := data.client.persistence.rw.WriteFile(data.client.persistence.path, []byte(corruptedContent), 0600)
				require.NoError(t, err)

				return data.client
			},
			expectError:   true,
			errorContains: "unmarshaling YAML",
		},
		{
			name: "invalid blob structure",
			setupFunc: func(t *testing.T) *Client {
				data, cleanup := setupTestData(t, true)
				t.Cleanup(cleanup)

				// Write YAML with wrong structure to the persistence path
				invalidYAML := `
invalid_field: "value"
another_field: 123
`
				err := data.client.persistence.rw.WriteFile(data.client.persistence.path, []byte(invalidYAML), 0600)
				require.NoError(t, err)

				return data.client
			},
			expectError:   true, // Should error when no LDevID data is found
			errorContains: "handle blob not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpClient := tt.setupFunc(t)

			_, _, err := tmpClient.persistence.loadLDevIDBlob()

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
