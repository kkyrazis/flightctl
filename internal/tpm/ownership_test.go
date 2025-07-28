//go:build amd64 || arm64

package tpm

import (
	"context"
	"testing"

	agent_config "github.com/flightctl/flightctl/internal/agent/config"
	"github.com/flightctl/flightctl/pkg/log"
	"github.com/google/go-tpm-tools/simulator"
	"github.com/stretchr/testify/require"
)

func TestStorageAuthStatus(t *testing.T) {
	data, cleanup := setupTestData(t, false)
	defer cleanup()
	require := require.New(t)
	set, err := data.client.ownership.checkStorageHierarchyAuthStatus()
	require.NoError(err)
	require.False(set)
	err = data.client.ownership.changeStorageHierarchyPassword(nil, []byte("test"))
	require.NoError(err)
	set, err = data.client.ownership.checkStorageHierarchyAuthStatus()
	require.NoError(err)
	require.True(set)
}

func TestSetStorageHierarchyPassword(t *testing.T) {
	data, cleanup := setupTestData(t, false)
	defer cleanup()
	require := require.New(t)
	err := data.client.ownership.changeStorageHierarchyPassword(nil, []byte("test"))
	require.NoError(err)
	data.client.keyManager.setStorageHierarchyAuth(nil)
	// fails to create when there is no auth
	_, err = data.client.keyManager.generateSRKPrimary()
	require.Error(err)
	data.client.keyManager.setStorageHierarchyAuth([]byte("test"))
	// creates successfully when auth
	_, err = data.client.keyManager.generateSRKPrimary()
	require.NoError(err)
}

func TestSealPassword(t *testing.T) {
	require := require.New(t)
	simulator, err := simulator.Get()
	require.NoError(err)

	rw := createTestReadWriter(t)

	// Create all components
	p, err := newPersistence(rw, "test_seal.yaml")
	require.NoError(err)
	cm := newConnectionManager(simulator, "test_seal")
	km := newKeyManager(cm, p)
	o := newOwnership(cm, p)

	client := &Client{
		persistence: p,
		connection:  cm,
		keyManager:  km,
		ownership:   o,
	}
	defer client.Close(context.Background())
	defer simulator.Close()

	pass := []byte("secure password")
	err = client.ownership.sealStoragePassword(pass)
	require.NoError(err)
	unsealed, err := client.ownership.unsealStoragePassword()
	require.NoError(err)
	require.Equal(pass, unsealed)
}

func TestOwnershipEnsureStorageHierarchyPassword(t *testing.T) {
	t.Run("returns cached password when already set", func(t *testing.T) {
		require := require.New(t)
		data, cleanup := setupTestData(t, false)
		defer cleanup()

		// Set a known password in the ownership cache
		expectedPassword := []byte("test-cached-password-123")
		data.client.ownership.storageHierarchyAuth = expectedPassword

		// Call the function
		password, err := data.client.ownership.ensureStorageHierarchyPassword()

		// Should return cached password immediately
		require.NoError(err)
		require.Equal(expectedPassword, password)
	})

	t.Run("generates new password when auth not set", func(t *testing.T) {
		require := require.New(t)

		// Use lighter setup like TestSealPassword to avoid TPM object memory issues
		simulator, err := simulator.Get()
		require.NoError(err)
		defer simulator.Close()

		rw := createTestReadWriter(t)

		// Create all components
		p, err := newPersistence(rw, "test_ownership.yaml")
		require.NoError(err)
		cm := newConnectionManager(simulator, "test_ownership")
		km := newKeyManager(cm, p)
		o := newOwnership(cm, p)

		client := &Client{
			persistence: p,
			connection:  cm,
			keyManager:  km,
			ownership:   o,
		}
		defer client.Close(context.Background())

		// Ensure ownership cache is empty (should be default)
		require.Nil(client.ownership.storageAuth())

		// Verify TPM has no storage hierarchy auth set (default for fresh simulator)
		authSet, err := client.ownership.checkStorageHierarchyAuthStatus()
		require.NoError(err)
		require.False(authSet)

		// Call the function
		password, err := client.ownership.ensureStorageHierarchyPassword()

		// Should generate and return a new password
		require.NoError(err)
		require.NotNil(password)
		require.Equal(32, len(password)) // TPM passwords are 32 bytes

		// Verify TPM storage hierarchy auth is now set
		authSet, err = client.ownership.checkStorageHierarchyAuthStatus()
		require.NoError(err)
		require.True(authSet)

		// Verify sealed password file exists and can be loaded
		_, _, _, err = client.persistence.loadSealedPasswordBlob()
		require.NoError(err)
	})

	t.Run("unseals existing password when auth already set", func(t *testing.T) {
		require := require.New(t)

		// Use lighter setup like TestSealPassword to avoid TPM object memory issues
		simulator, err := simulator.Get()
		require.NoError(err)
		defer simulator.Close()

		rw := createTestReadWriter(t)

		// Create all components
		p, err := newPersistence(rw, "test_ownership2.yaml")
		require.NoError(err)
		cm := newConnectionManager(simulator, "test_ownership2")
		km := newKeyManager(cm, p)
		o := newOwnership(cm, p)

		client := &Client{
			persistence: p,
			connection:  cm,
			keyManager:  km,
			ownership:   o,
		}
		defer client.Close(context.Background())

		// Pre-setup: Generate and seal a password
		originalPassword, err := client.ownership.generateStoragePassword()
		require.NoError(err)
		require.Equal(32, len(originalPassword))

		// Seal the password to file
		err = client.ownership.sealStoragePassword(originalPassword)
		require.NoError(err)

		// Set the password on TPM to simulate existing setup
		err = client.ownership.changeStorageHierarchyPassword(nil, originalPassword)
		require.NoError(err)

		// Verify auth is now set on TPM
		authSet, err := client.ownership.checkStorageHierarchyAuthStatus()
		require.NoError(err)
		require.True(authSet)

		// Reset ownership cache to simulate fresh client load
		client.ownership.storageHierarchyAuth = nil

		// Call the function
		password, err := client.ownership.ensureStorageHierarchyPassword()

		// Should unseal and return the original password
		require.NoError(err)
		require.NotNil(password)
		require.Equal(originalPassword, password)
	})

	t.Run("resets password after it has been set", func(t *testing.T) {
		require := require.New(t)
		// Use lighter setup like TestSealPassword to avoid TPM object memory issues
		simulator, err := simulator.Get()
		require.NoError(err)
		defer simulator.Close()
		rw := createTestReadWriter(t)

		// Create all components
		p, err := newPersistence(rw, "test_ownership_reset.yaml")
		require.NoError(err)
		cm := newConnectionManager(simulator, "test_ownership_reset")
		o := newOwnership(cm, p)

		// First, set up a password like the ensureStorageHierarchyPassword would do
		password, err := o.ensureStorageHierarchyPassword()
		require.NoError(err)
		require.NotNil(password)

		// Verify TPM has auth set and sealed password exists
		authSet, err := o.checkStorageHierarchyAuthStatus()
		require.NoError(err)
		require.True(authSet)

		_, _, _, err = o.persistence.loadSealedPasswordBlob()
		require.NoError(err)

		// Now reset the password
		err = o.resetStorageHierarchyPassword()
		require.NoError(err)

		// Verify TPM storage hierarchy auth is now unset
		authSet, err = o.checkStorageHierarchyAuthStatus()
		require.NoError(err)
		require.False(authSet)

		// Verify sealed password blob has been removed
		_, _, _, err = o.persistence.loadSealedPasswordBlob()
		require.Error(err)
		require.Contains(err.Error(), "no sealed password data found")
	})
}

func TestSkipOwnership(t *testing.T) {
	t.Run("skips ownership when SkipOwnership is true", func(t *testing.T) {
		require := require.New(t)
		simulator, err := simulator.Get()
		require.NoError(err)
		defer simulator.Close()

		rw := createTestReadWriter(t)
		config := &agent_config.Config{
			TPM: agent_config.TPM{
				Enabled:         true,
				Path:            agent_config.DefaultTPMDevicePath,
				PersistencePath: "test_skip_ownership.yaml",
				SkipOwnership:   true,
			},
		}

		client, err := newTestClientWithConnection(simulator, agent_config.DefaultTPMDevicePath, log.NewPrefixLogger("test"), rw, config)
		require.NoError(err)
		defer client.Close(context.Background())

		// Verify that storageHierarchyAuth is nil when SkipOwnership is true
		require.Nil(client.ownership.storageAuth())

		// Verify TPM storage hierarchy auth is not set (default state)
		authSet, err := client.ownership.checkStorageHierarchyAuthStatus()
		require.NoError(err)
		require.False(authSet)

		// Verify no sealed password blob was created
		_, _, _, err = client.persistence.loadSealedPasswordBlob()
		require.Error(err)
		require.Contains(err.Error(), "no sealed password data found")
	})

	t.Run("runs ownership when SkipOwnership is false", func(t *testing.T) {
		require := require.New(t)
		simulator, err := simulator.Get()
		require.NoError(err)
		defer simulator.Close()

		rw := createTestReadWriter(t)
		config := &agent_config.Config{
			TPM: agent_config.TPM{
				Enabled:         true,
				Path:            agent_config.DefaultTPMDevicePath,
				PersistencePath: "test_run_ownership.yaml",
				SkipOwnership:   false,
			},
		}

		client, err := newTestClientWithConnection(simulator, agent_config.DefaultTPMDevicePath, log.NewPrefixLogger("test"), rw, config)
		require.NoError(err)
		defer client.Close(context.Background())

		// Verify that storageHierarchyAuth is set when SkipOwnership is false
		require.NotNil(client.ownership.storageAuth())
		require.Equal(32, len(client.ownership.storageAuth())) // TPM passwords are 32 bytes

		// Verify TPM storage hierarchy auth is set
		authSet, err := client.ownership.checkStorageHierarchyAuthStatus()
		require.NoError(err)
		require.True(authSet)

		// Verify sealed password blob was created
		_, _, _, err = client.persistence.loadSealedPasswordBlob()
		require.NoError(err)
	})
}
