//go:build amd64 || arm64

package tpm

import (
	"context"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/stretchr/testify/require"
)

func TestFlushContextForHandle(t *testing.T) {
	data, cleanup := setupTestData(t, true)
	defer cleanup()

	err := data.client.connection.flushContextForHandle(data.client.keyManager.lakHandle().Handle)
	require.NoError(t, err)

	// Create a transient LDevID for testing
	ldevid, err := data.client.keyManager.createLDevID()
	require.NoError(t, err)
	require.NotNil(t, ldevid)

	tests := []struct {
		name        string
		handle      tpm2.TPMHandle
		shouldError bool
		description string
	}{
		{
			name:        "flush transient handle",
			handle:      ldevid.Handle,
			shouldError: false,
			description: "transient handle should flush successfully",
		},
		{
			name:        "flush persistent handle (no-op)",
			handle:      persistentHandleMin,
			shouldError: false,
			description: "persistent handle should be a no-op and not error",
		},
		{
			name:        "flush another persistent handle",
			handle:      persistentHandleMin + 1,
			shouldError: false,
			description: "another persistent handle should also be a no-op",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := data.client.connection.flushContextForHandle(tt.handle)
			if tt.shouldError {
				require.Error(t, err, tt.description)
			} else {
				require.NoError(t, err, tt.description)
			}
		})
	}
}

func TestCloseFlushesHandles(t *testing.T) {
	require := require.New(t)
	f, err := setupTestFixture(t, true)
	require.NoError(err)

	// Verify handles are set
	require.NotNil(f.client.keyManager.srkHandle())
	require.NotNil(f.client.keyManager.ldevIDHandle())

	// Close should flush handles and set them to nil
	err = f.client.Close(context.Background())
	require.NoError(err)

	// Verify handles are cleared
	require.Nil(f.client.keyManager.srkHandle())
	require.Nil(f.client.keyManager.ldevIDHandle())
}
