//go:build amd64 || arm64

package tpm

import (
	"context"
	"testing"

	agent_config "github.com/flightctl/flightctl/internal/agent/config"
	"github.com/flightctl/flightctl/internal/agent/device/fileio"
	"github.com/flightctl/flightctl/pkg/log"
	"github.com/google/go-tpm-tools/simulator"
	"github.com/stretchr/testify/require"
)

func TestTPMDeviceExists(t *testing.T) {
	tempDir := t.TempDir()
	rw := fileio.NewReadWriter(fileio.WithTestRootDir(tempDir))

	// Create mock resource manager file using ReadWriter
	err := rw.WriteFile("/dev/tpmrm0", []byte{}, 0600)
	require.NoError(t, err)

	tests := []struct {
		name     string
		device   TPM
		expected bool
	}{
		{
			name: "device exists at resource manager path",
			device: TPM{
				path:            "/dev/tpm0",
				resourceMgrPath: "/dev/tpmrm0",
				rw:              rw,
			},
			expected: true,
		},
		{
			name: "device does not exist at resource manager path",
			device: TPM{
				path:            "/dev/tpm0",
				resourceMgrPath: "/dev/nonexistent",
				rw:              rw,
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.device.Exists()
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestDiscoverTPMDevices(t *testing.T) {
	// Create a temporary directory structure to simulate /sys/class/tpm
	tempDir := t.TempDir()
	rw := fileio.NewReadWriter(fileio.WithTestRootDir(tempDir))

	// Create mock TPM directories using ReadWriter
	tpmDirs := []string{"tpm0", "tpm1", "tpm2"}
	for _, dir := range tpmDirs {
		err := rw.MkdirAll("/sys/class/tpm/"+dir, 0755)
		require.NoError(t, err)
	}

	// Create a non-TPM directory that should be ignored
	err := rw.MkdirAll("/sys/class/tpm/other", 0755)
	require.NoError(t, err)

	// Create a file that should be ignored
	err = rw.WriteFile("/sys/class/tpm/file.txt", []byte{}, 0600)
	require.NoError(t, err)

	devices, err := discover(rw)
	require.NoError(t, err)
	require.Len(t, devices, 3)

	expectedDevices := []TPM{
		{
			index:           "0",
			path:            "/dev/tpm0",
			resourceMgrPath: "/dev/tpmrm0",
			versionPath:     "/sys/class/tpm/tpm0/tpm_version_major",
			sysfsPath:       "/sys/class/tpm/tpm0",
		},
		{
			index:           "1",
			path:            "/dev/tpm1",
			resourceMgrPath: "/dev/tpmrm1",
			versionPath:     "/sys/class/tpm/tpm1/tpm_version_major",
			sysfsPath:       "/sys/class/tpm/tpm1",
		},
		{
			index:           "2",
			path:            "/dev/tpm2",
			resourceMgrPath: "/dev/tpmrm2",
			versionPath:     "/sys/class/tpm/tpm2/tpm_version_major",
			sysfsPath:       "/sys/class/tpm/tpm2",
		},
	}

	for i, expected := range expectedDevices {
		require.Equal(t, expected.index, devices[i].index)
		require.Equal(t, expected.path, devices[i].path)
		require.Equal(t, expected.resourceMgrPath, devices[i].resourceMgrPath)
		require.Equal(t, expected.versionPath, devices[i].versionPath)
		require.Equal(t, expected.sysfsPath, devices[i].sysfsPath)
		require.Equal(t, rw, devices[i].rw)
	}
}

func TestDiscoverError(t *testing.T) {
	// Test with a ReadWriter that points to a non-existent directory
	tempDir := t.TempDir()
	rw := fileio.NewReadWriter(fileio.WithTestRootDir(tempDir))

	// Try to discover TPM devices from a directory that doesn't exist
	devices, err := discover(rw)

	// The ReadWriter with test root dir will return empty results instead of error
	// when the directory doesn't exist, so we should get an empty slice
	require.NoError(t, err)
	require.Empty(t, devices)
}

func TestTPMDeviceValidateVersion2(t *testing.T) {
	tempDir := t.TempDir()
	rw := fileio.NewReadWriter(fileio.WithTestRootDir(tempDir))

	// Create mock resource manager and version files using ReadWriter
	err := rw.WriteFile("/dev/tpmrm0", []byte{}, 0600)
	require.NoError(t, err)
	err = rw.WriteFile("/sys/class/tpm/tpm0/tpm_version_major", []byte("2"), 0600)
	require.NoError(t, err)

	tests := []struct {
		name        string
		device      TPM
		expectError bool
	}{
		{
			name: "valid TPM 2.0 device",
			device: TPM{
				path:            "/dev/tpm0",
				resourceMgrPath: "/dev/tpmrm0",
				versionPath:     "/sys/class/tpm/tpm0/tpm_version_major",
				rw:              rw,
			},
			expectError: false,
		},
		{
			name: "resource manager does not exist",
			device: TPM{
				path:            "/dev/tpm0",
				resourceMgrPath: "/dev/nonexistent",
				versionPath:     "/sys/class/tpm/tpm0/tpm_version_major",
				rw:              rw,
			},
			expectError: true,
		},
		{
			name: "version file does not exist",
			device: TPM{
				path:            "/dev/tpm0",
				resourceMgrPath: "/dev/tpmrm0",
				versionPath:     "/sys/class/tpm/tpm0/nonexistent",
				rw:              rw,
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.device.ValidateVersion2()
			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestResolveDefault(t *testing.T) {
	tests := []struct {
		name           string
		setup          func(rw fileio.ReadWriter)
		expectError    bool
		expectedDevice *TPM
	}{
		{
			name: "returns first valid TPM device when available",
			setup: func(rw fileio.ReadWriter) {
				// Create multiple TPM devices
				err := rw.MkdirAll("/sys/class/tpm/tpm0", 0755)
				require.NoError(t, err)
				err = rw.MkdirAll("/sys/class/tpm/tpm1", 0755)
				require.NoError(t, err)

				// Create resource manager files for both
				err = rw.WriteFile("/dev/tpmrm0", []byte{}, 0600)
				require.NoError(t, err)
				err = rw.WriteFile("/dev/tpmrm1", []byte{}, 0600)
				require.NoError(t, err)

				// Create version files for both (TPM 2.0)
				err = rw.WriteFile("/sys/class/tpm/tpm0/tpm_version_major", []byte("2"), 0600)
				require.NoError(t, err)
				err = rw.WriteFile("/sys/class/tpm/tpm1/tpm_version_major", []byte("2"), 0600)
				require.NoError(t, err)
			},
			expectError: false,
			expectedDevice: &TPM{
				index:           "0",
				path:            "/dev/tpm0",
				resourceMgrPath: "/dev/tpmrm0",
				versionPath:     "/sys/class/tpm/tpm0/tpm_version_major",
				sysfsPath:       "/sys/class/tpm/tpm0",
			},
		},
		{
			name: "returns error when no TPM devices exist",
			setup: func(rw fileio.ReadWriter) {
				// Don't create any TPM devices
			},
			expectError: true,
		},
		{
			name: "returns error when TPM devices exist but are not version 2.0",
			setup: func(rw fileio.ReadWriter) {
				// Create TPM device directory
				err := rw.MkdirAll("/sys/class/tpm/tpm0", 0755)
				require.NoError(t, err)

				// Create resource manager file
				err = rw.WriteFile("/dev/tpmrm0", []byte{}, 0600)
				require.NoError(t, err)

				// Create version file with non-2.0 version
				err = rw.WriteFile("/sys/class/tpm/tpm0/tpm_version_major", []byte("1"), 0600)
				require.NoError(t, err)
			},
			expectError: true,
		},
		{
			name: "returns error when resource manager files don't exist",
			setup: func(rw fileio.ReadWriter) {
				// Create TPM device directory
				err := rw.MkdirAll("/sys/class/tpm/tpm0", 0755)
				require.NoError(t, err)

				// Create version file but not resource manager files
				err = rw.WriteFile("/sys/class/tpm/tpm0/tpm_version_major", []byte("2"), 0600)
				require.NoError(t, err)
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := t.TempDir()
			rw := fileio.NewReadWriter(fileio.WithTestRootDir(tempDir))

			tt.setup(rw)

			device, err := resolveDefault(rw, log.NewPrefixLogger("test"))

			if tt.expectError {
				require.Error(t, err)
				require.Nil(t, device)
			} else {
				require.NoError(t, err)
				require.NotNil(t, device)
				require.Equal(t, tt.expectedDevice.index, device.index)
				require.Equal(t, tt.expectedDevice.path, device.path)
				require.Equal(t, tt.expectedDevice.resourceMgrPath, device.resourceMgrPath)
				require.Equal(t, tt.expectedDevice.versionPath, device.versionPath)
				require.Equal(t, tt.expectedDevice.sysfsPath, device.sysfsPath)
				require.Equal(t, rw, device.rw)
			}
		})
	}
}

func TestResolve(t *testing.T) {
	tests := []struct {
		name        string
		setup       func(rw fileio.ReadWriter)
		path        string
		expectError bool
		expectedTPM *TPM
	}{
		{
			name: "resolves tpm by resource manager path",
			setup: func(rw fileio.ReadWriter) {
				err := rw.MkdirAll("/sys/class/tpm/tpm0", 0755)
				require.NoError(t, err)
				err = rw.WriteFile("/dev/tpmrm0", []byte{}, 0600)
				require.NoError(t, err)
				err = rw.WriteFile("/sys/class/tpm/tpm0/tpm_version_major", []byte("2"), 0600)
				require.NoError(t, err)
			},
			path:        "/dev/tpmrm0",
			expectError: false,
			expectedTPM: &TPM{
				index:           "0",
				path:            "/dev/tpm0",
				resourceMgrPath: "/dev/tpmrm0",
				versionPath:     "/sys/class/tpm/tpm0/tpm_version_major",
				sysfsPath:       "/sys/class/tpm/tpm0",
			},
		},
		{
			name: "resolves tpm by direct path",
			setup: func(rw fileio.ReadWriter) {
				err := rw.MkdirAll("/sys/class/tpm/tpm1", 0755)
				require.NoError(t, err)
				err = rw.WriteFile("/dev/tpmrm1", []byte{}, 0600)
				require.NoError(t, err)
				err = rw.WriteFile("/sys/class/tpm/tpm1/tpm_version_major", []byte("2"), 0600)
				require.NoError(t, err)
			},
			path:        "/dev/tpm1",
			expectError: false,
			expectedTPM: &TPM{
				index:           "1",
				path:            "/dev/tpm1",
				resourceMgrPath: "/dev/tpmrm1",
				versionPath:     "/sys/class/tpm/tpm1/tpm_version_major",
				sysfsPath:       "/sys/class/tpm/tpm1",
			},
		},
		{
			name: "returns error for non-existent device",
			setup: func(rw fileio.ReadWriter) {
			},
			path:        "/dev/tpmrm99",
			expectError: true,
		},
		{
			name: "returns error for non-TPM2 device",
			setup: func(rw fileio.ReadWriter) {
				err := rw.MkdirAll("/sys/class/tpm/tpm0", 0755)
				require.NoError(t, err)
				err = rw.WriteFile("/dev/tpmrm0", []byte{}, 0600)
				require.NoError(t, err)
				err = rw.WriteFile("/sys/class/tpm/tpm0/tpm_version_major", []byte("1"), 0600)
				require.NoError(t, err)
			},
			path:        "/dev/tpmrm0",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := t.TempDir()
			rw := fileio.NewReadWriter(fileio.WithTestRootDir(tempDir))

			tt.setup(rw)

			device, err := resolve(rw, tt.path)

			if tt.expectError {
				require.Error(t, err)
				require.Nil(t, device)
			} else {
				require.NoError(t, err)
				require.NotNil(t, device)
				require.Equal(t, tt.expectedTPM.index, device.index)
				require.Equal(t, tt.expectedTPM.path, device.path)
				require.Equal(t, tt.expectedTPM.resourceMgrPath, device.resourceMgrPath)
				require.Equal(t, tt.expectedTPM.versionPath, device.versionPath)
				require.Equal(t, tt.expectedTPM.sysfsPath, device.sysfsPath)
				require.Equal(t, rw, device.rw)
			}
		})
	}
}

func TestClear(t *testing.T) {
	require := require.New(t)
	simulator, err := simulator.Get()
	require.NoError(err)
	t.Cleanup(func() { simulator.Close() })

	rw := createTestReadWriter(t)
	config := &agent_config.Config{
		TPM: agent_config.TPM{
			Enabled:         true,
			Path:            agent_config.DefaultTPMDevicePath,
			PersistencePath: "test_wipe_with_auth.yaml",
			SkipOwnership:   false,
		},
	}

	client, err := newTestClientWithConnection(simulator, agent_config.DefaultTPMDevicePath, log.NewPrefixLogger("test"), rw, config)
	require.NoError(err)
	t.Cleanup(func() { client.Close(context.Background()) })

	originalName := client.keyManager.srkHandle().Name.Buffer

	err = client.Clear()
	require.NoError(err)

	// Verify storageHierarchyAuth is reset to nil
	require.Nil(client.ownership.storageAuth())

	// Verify TPM storage hierarchy auth status is false (cleared)
	authSet, err := client.ownership.checkStorageHierarchyAuthStatus()
	require.NoError(err)
	require.False(authSet)

	// Verify persistence file is removed (should get file not found error)
	_, err = client.persistence.loadTPMBlob()
	require.Error(err)

	// check to see that we have a new SRK
	srk, err := client.keyManager.generateSRKPrimary()
	require.NoError(err)
	require.NotEqual(originalName, srk.Name.Buffer)
}
