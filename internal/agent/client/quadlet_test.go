package client

import (
	"path/filepath"
	"testing"

	"github.com/flightctl/flightctl/internal/agent/device/fileio"
	"github.com/stretchr/testify/require"
)

func TestNamespacedQuadlet(t *testing.T) {
	tests := []struct {
		name     string
		appID    string
		filename string
		expected string
	}{
		{
			name:     "container file",
			appID:    "myapp",
			filename: "web.container",
			expected: "myapp-web.container",
		},
		{
			name:     "volume file",
			appID:    "testapp",
			filename: "data.volume",
			expected: "testapp-data.volume",
		},
		{
			name:     "with dashes in name",
			appID:    "my-app",
			filename: "my-service.container",
			expected: "my-app-my-service.container",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := namespacedQuadlet(tt.appID, tt.filename)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestPrefixQuadletReference(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		appID    string
		expected string
	}{
		{
			name:     "container not prefixed",
			value:    "web.container",
			appID:    "myapp",
			expected: "myapp-web.container",
		},
		{
			name:     "container already prefixed",
			value:    "myapp-web.container",
			appID:    "myapp",
			expected: "myapp-web.container",
		},
		{
			name:     "volume not prefixed",
			value:    "data.volume",
			appID:    "myapp",
			expected: "myapp-data.volume",
		},
		{
			name:     "network not prefixed",
			value:    "app-net.network",
			appID:    "myapp",
			expected: "myapp-app-net.network",
		},
		{
			name:     "image not prefixed",
			value:    "base.image",
			appID:    "myapp",
			expected: "myapp-base.image",
		},
		{
			name:     "pod not prefixed",
			value:    "services.pod",
			appID:    "myapp",
			expected: "myapp-services.pod",
		},
		{
			name:     "non-quadlet file",
			value:    "some-service.service",
			appID:    "myapp",
			expected: "some-service.service",
		},
		{
			name:     "regular string",
			value:    "nginx:latest",
			appID:    "myapp",
			expected: "nginx:latest",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := prefixQuadletReference(tt.value, tt.appID)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestUpdateSystemdReference(t *testing.T) {
	tests := []struct {
		name             string
		value            string
		appID            string
		quadletBasenames map[string]struct{}
		expected         string
	}{
		{
			name:  "service from our app",
			value: "web.service",
			appID: "myapp",
			quadletBasenames: map[string]struct{}{
				"web": {},
			},
			expected: "myapp-web.service",
		},
		{
			name:  "external service",
			value: "chronyd.service",
			appID: "myapp",
			quadletBasenames: map[string]struct{}{
				"web": {},
			},
			expected: "chronyd.service",
		},
		{
			name:  "direct quadlet reference",
			value: "db.container",
			appID: "myapp",
			quadletBasenames: map[string]struct{}{
				"web": {},
				"db":  {},
			},
			expected: "myapp-db.container",
		},
		{
			name:  "already prefixed service",
			value: "myapp-web.service",
			appID: "myapp",
			quadletBasenames: map[string]struct{}{
				"web": {},
			},
			expected: "myapp-web.service",
		},
		{
			name:  "volume reference",
			value: "data.volume",
			appID: "myapp",
			quadletBasenames: map[string]struct{}{
				"data": {},
			},
			expected: "myapp-data.volume",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := updateSystemdReference(tt.value, tt.appID, tt.quadletBasenames)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestUpdateSpaceSeparatedReferences(t *testing.T) {
	tests := []struct {
		name             string
		value            string
		appID            string
		quadletBasenames map[string]struct{}
		expected         string
	}{
		{
			name:  "single reference",
			value: "web.service",
			appID: "myapp",
			quadletBasenames: map[string]struct{}{
				"web": {},
			},
			expected: "myapp-web.service",
		},
		{
			name:  "multiple app services",
			value: "web.service db.service",
			appID: "myapp",
			quadletBasenames: map[string]struct{}{
				"web": {},
				"db":  {},
			},
			expected: "myapp-web.service myapp-db.service",
		},
		{
			name:  "mixed app and external services",
			value: "web.service chronyd.service db.service",
			appID: "myapp",
			quadletBasenames: map[string]struct{}{
				"web": {},
				"db":  {},
			},
			expected: "myapp-web.service chronyd.service myapp-db.service",
		},
		{
			name:  "quadlet references",
			value: "db.container data.volume",
			appID: "myapp",
			quadletBasenames: map[string]struct{}{
				"db":   {},
				"data": {},
			},
			expected: "myapp-db.container myapp-data.volume",
		},
		{
			name:  "empty string",
			value: "",
			appID: "myapp",
			quadletBasenames: map[string]struct{}{
				"web": {},
			},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := updateSpaceSeparatedReferences(tt.value, tt.appID, tt.quadletBasenames)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestUpdateMountValue(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		appID    string
		expected string
	}{
		{
			name:     "volume mount",
			value:    "type=volume,source=data.volume,destination=/data",
			appID:    "myapp",
			expected: "type=volume,source=myapp-data.volume,destination=/data",
		},
		{
			name:     "image mount",
			value:    "type=image,source=config.image,destination=/config",
			appID:    "myapp",
			expected: "type=image,source=myapp-config.image,destination=/config",
		},
		{
			name:     "bind mount",
			value:    "type=bind,source=/host/path,destination=/container",
			appID:    "myapp",
			expected: "type=bind,source=/host/path,destination=/container",
		},
		{
			name:     "already prefixed volume",
			value:    "type=volume,source=myapp-data.volume,destination=/data",
			appID:    "myapp",
			expected: "type=volume,source=myapp-data.volume,destination=/data",
		},
		{
			name:     "volume mount with options",
			value:    "type=volume,source=data.volume,destination=/data,ro=true",
			appID:    "myapp",
			expected: "type=volume,source=myapp-data.volume,destination=/data,ro=true",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := updateMountValue(tt.value, tt.appID)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestUpdateVolumeValue(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		appID    string
		expected string
	}{
		{
			name:     "quadlet volume simple",
			value:    "data.volume:/data",
			appID:    "myapp",
			expected: "myapp-data.volume:/data",
		},
		{
			name:     "quadlet volume with options",
			value:    "data.volume:/data:ro",
			appID:    "myapp",
			expected: "myapp-data.volume:/data:ro",
		},
		{
			name:     "host path volume",
			value:    "/host/path:/container",
			appID:    "myapp",
			expected: "/host/path:/container",
		},
		{
			name:     "already prefixed",
			value:    "myapp-data.volume:/data",
			appID:    "myapp",
			expected: "myapp-data.volume:/data",
		},
		{
			name:     "volume only source",
			value:    "data.volume",
			appID:    "myapp",
			expected: "myapp-data.volume",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := updateVolumeValue(tt.value, tt.appID)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestInstallQuadlet(t *testing.T) {
	tests := []struct {
		name              string
		files             map[string][]byte
		appID             string
		expectedFiles     []string
		expectedDropIns   map[string]bool
		checkFileContents map[string]func(*testing.T, []byte)
	}{
		{
			name: "simple container with no references",
			files: map[string][]byte{
				"web.container": []byte(`[Container]
Image=nginx:latest
`),
			},
			appID: "myapp",
			expectedFiles: []string{
				"myapp-web.container",
				"myapp-.container.d/99-flightctl.conf",
			},
			expectedDropIns: map[string]bool{
				"myapp-.container.d": true,
			},
			checkFileContents: map[string]func(*testing.T, []byte){
				"myapp-web.container": func(t *testing.T, content []byte) {
					require.Contains(t, string(content), "[Container]")
					require.Contains(t, string(content), "nginx:latest")
				},
				"myapp-.container.d/99-flightctl.conf": func(t *testing.T, content []byte) {
					require.Contains(t, string(content), "[Container]")
					require.Contains(t, string(content), "io.flightctl.quadlet.project=myapp")
				},
			},
		},
		{
			name: "container with volume and network references",
			files: map[string][]byte{
				"web.container": []byte(`[Container]
Image=nginx:latest
Volume=data.volume:/data
Network=app-net.network
`),
				"data.volume": []byte(`[Volume]
`),
				"app-net.network": []byte(`[Network]
`),
			},
			appID: "myapp",
			expectedFiles: []string{
				"myapp-web.container",
				"myapp-data.volume",
				"myapp-app-net.network",
				"myapp-.container.d/99-flightctl.conf",
				"myapp-.volume.d/99-flightctl.conf",
				"myapp-.network.d/99-flightctl.conf",
			},
			checkFileContents: map[string]func(*testing.T, []byte){
				"myapp-web.container": func(t *testing.T, content []byte) {
					require.Contains(t, string(content), "myapp-data.volume:/data")
					require.Contains(t, string(content), "myapp-app-net.network")
				},
			},
		},
		{
			name: "container with .env file",
			files: map[string][]byte{
				"web.container": []byte(`[Container]
Image=nginx:latest
`),
				".env": []byte("ENV_VAR=value\n"),
			},
			appID: "myapp",
			expectedFiles: []string{
				"myapp-web.container",
				".env",
				"myapp-.container.d/99-flightctl.conf",
			},
			checkFileContents: map[string]func(*testing.T, []byte){
				"myapp-.container.d/99-flightctl.conf": func(t *testing.T, content []byte) {
					require.Contains(t, string(content), "EnvironmentFile")
					require.Contains(t, string(content), ".env")
				},
			},
		},
		{
			name: "container with unit dependencies",
			files: map[string][]byte{
				"web.container": []byte(`[Unit]
After=db.container chronyd.service

[Container]
Image=nginx:latest
`),
				"db.container": []byte(`[Container]
Image=postgres:latest
`),
			},
			appID: "myapp",
			expectedFiles: []string{
				"myapp-web.container",
				"myapp-db.container",
			},
			checkFileContents: map[string]func(*testing.T, []byte){
				"myapp-web.container": func(t *testing.T, content []byte) {
					require.Contains(t, string(content), "myapp-db.container chronyd.service")
				},
			},
		},
		{
			name: "already namespaced files",
			files: map[string][]byte{
				"myapp-web.container": []byte(`[Container]
Image=nginx:latest
Volume=myapp-data.volume:/data
`),
				"myapp-data.volume": []byte(`[Volume]
`),
			},
			appID: "myapp",
			expectedFiles: []string{
				"myapp-web.container",
				"myapp-data.volume",
			},
			checkFileContents: map[string]func(*testing.T, []byte){
				"myapp-web.container": func(t *testing.T, content []byte) {
					require.Contains(t, string(content), "myapp-data.volume:/data")
				},
			},
		},
		{
			name: "all reference types",
			files: map[string][]byte{
				"app.container": []byte(`[Unit]
After=db.service init.container chronyd.service
Requires=db.service network.target
Before=services.pod

[Install]
WantedBy=multi-user.target default.target

[Container]
Image=base.image
Network=app-net.network
Pod=services.pod
Volume=data.volume:/data
Volume=logs.volume:/logs:ro
Mount=type=volume,source=cache.volume,destination=/cache
Mount=type=image,source=config.image,destination=/config
Mount=type=bind,source=/host/path,destination=/bind
`),
				"db.container": []byte(`[Unit]
After=network.target

[Container]
Image=postgres:latest
Volume=data.volume:/var/lib/postgresql
`),
				"init.container": []byte(`[Container]
Image=alpine:latest
`),
				"services.pod": []byte(`[Unit]
After=app-net.network

[Pod]
Network=app-net.network
Volume=shared.volume:/shared
`),
				"data.volume": []byte(`[Volume]
`),
				"logs.volume": []byte(`[Volume]
`),
				"cache.volume": []byte(`[Volume]
`),
				"shared.volume": []byte(`[Volume]
`),
				"cache-vol.volume": []byte(`[Volume]
Image=vol-base.image
`),
				"base.image": []byte(`[Image]
`),
				"config.image": []byte(`[Image]
`),
				"vol-base.image": []byte(`[Image]
`),
				"app-net.network": []byte(`[Network]
`),
				".env": []byte("ENV_VAR=value\n"),
			},
			appID: "myapp",
			expectedFiles: []string{
				"myapp-app.container",
				"myapp-db.container",
				"myapp-init.container",
				"myapp-services.pod",
				"myapp-data.volume",
				"myapp-logs.volume",
				"myapp-cache.volume",
				"myapp-shared.volume",
				"myapp-cache-vol.volume",
				"myapp-base.image",
				"myapp-config.image",
				"myapp-vol-base.image",
				"myapp-app-net.network",
				".env",
				"myapp-.container.d/99-flightctl.conf",
				"myapp-.pod.d/99-flightctl.conf",
				"myapp-.volume.d/99-flightctl.conf",
				"myapp-.image.d/99-flightctl.conf",
				"myapp-.network.d/99-flightctl.conf",
			},
			checkFileContents: map[string]func(*testing.T, []byte){
				"myapp-app.container": func(t *testing.T, content []byte) {
					contentStr := string(content)
					// Unit section - mix of quadlet services, direct quadlets, and external services
					require.Contains(t, contentStr, "myapp-db.service")
					require.Contains(t, contentStr, "myapp-init.container")
					require.Contains(t, contentStr, "chronyd.service")
					require.Contains(t, contentStr, "myapp-services.pod")
					// Install section
					require.Contains(t, contentStr, "multi-user.target")
					// Container section - all reference types
					require.Contains(t, contentStr, "myapp-base.image")
					require.Contains(t, contentStr, "myapp-app-net.network")
					require.Contains(t, contentStr, "myapp-services.pod")
					require.Contains(t, contentStr, "myapp-data.volume:/data")
					require.Contains(t, contentStr, "myapp-logs.volume:/logs:ro")
					require.Contains(t, contentStr, "source=myapp-cache.volume")
					require.Contains(t, contentStr, "source=myapp-config.image")
					// Bind mount should NOT be prefixed
					require.Contains(t, contentStr, "source=/host/path")
				},
				"myapp-db.container": func(t *testing.T, content []byte) {
					require.Contains(t, string(content), "myapp-data.volume:/var/lib/postgresql")
				},
				"myapp-services.pod": func(t *testing.T, content []byte) {
					contentStr := string(content)
					require.Contains(t, contentStr, "myapp-app-net.network")
					require.Contains(t, contentStr, "myapp-shared.volume:/shared")
				},
				"myapp-cache-vol.volume": func(t *testing.T, content []byte) {
					require.Contains(t, string(content), "myapp-vol-base.image")
				},
				"myapp-.container.d/99-flightctl.conf": func(t *testing.T, content []byte) {
					contentStr := string(content)
					require.Contains(t, contentStr, "io.flightctl.quadlet.project=myapp")
					require.Contains(t, contentStr, "EnvironmentFile")
					require.Contains(t, contentStr, ".env")
				},
			},
		},
		{
			name: "simple drop-in",
			files: map[string][]byte{
				"web.container": []byte(`[Container]
Image=nginx:latest
`),
				"web.container.d/10-custom.conf": []byte(`[Container]
Network=backend.network
`),
				"backend.network": []byte(`[Network]
`),
			},
			appID: "myapp",
			expectedFiles: []string{
				"myapp-web.container",
				"myapp-backend.network",
				"myapp-web.container.d/10-custom.conf",
				"myapp-.container.d/99-flightctl.conf",
				"myapp-.network.d/99-flightctl.conf",
			},
			checkFileContents: map[string]func(*testing.T, []byte){
				"myapp-web.container.d/10-custom.conf": func(t *testing.T, content []byte) {
					require.Contains(t, string(content), "myapp-backend.network")
				},
			},
		},
		{
			name: "top-level drop-in",
			files: map[string][]byte{
				"web.container": []byte(`[Container]
Image=nginx:latest
`),
				"container.d/05-base.conf": []byte(`[Container]
Volume=logs.volume:/logs
`),
				"logs.volume": []byte(`[Volume]
`),
			},
			appID: "myapp",
			expectedFiles: []string{
				"myapp-web.container",
				"myapp-logs.volume",
				"myapp-.container.d/05-base.conf",
				"myapp-.container.d/99-flightctl.conf",
				"myapp-.volume.d/99-flightctl.conf",
			},
			checkFileContents: map[string]func(*testing.T, []byte){
				"myapp-.container.d/05-base.conf": func(t *testing.T, content []byte) {
					require.Contains(t, string(content), "myapp-logs.volume:/logs")
				},
			},
		},
		{
			name: "hierarchical drop-ins",
			files: map[string][]byte{
				"foo-bar.container": []byte(`[Container]
Image=test:latest
`),
				"container.d/01-global.conf": []byte(`[Unit]
After=network.target
`),
				"foo-.container.d/02-foo.conf": []byte(`[Container]
Network=foo-net.network
`),
				"foo-bar.container.d/03-specific.conf": []byte(`[Container]
Volume=data.volume:/data
`),
				"foo-net.network": []byte(`[Network]
`),
				"data.volume": []byte(`[Volume]
`),
			},
			appID: "myapp",
			expectedFiles: []string{
				"myapp-foo-bar.container",
				"myapp-foo-net.network",
				"myapp-data.volume",
				"myapp-.container.d/01-global.conf",
				"myapp-foo-.container.d/02-foo.conf",
				"myapp-foo-bar.container.d/03-specific.conf",
				"myapp-.container.d/99-flightctl.conf",
				"myapp-.network.d/99-flightctl.conf",
				"myapp-.volume.d/99-flightctl.conf",
			},
			checkFileContents: map[string]func(*testing.T, []byte){
				"myapp-.container.d/01-global.conf": func(t *testing.T, content []byte) {
					require.Contains(t, string(content), "[Unit]")
					require.Contains(t, string(content), "network.target")
				},
				"myapp-foo-.container.d/02-foo.conf": func(t *testing.T, content []byte) {
					require.Contains(t, string(content), "myapp-foo-net.network")
				},
				"myapp-foo-bar.container.d/03-specific.conf": func(t *testing.T, content []byte) {
					require.Contains(t, string(content), "myapp-data.volume:/data")
				},
			},
		},
		{
			name: "drop-in with multiple references",
			files: map[string][]byte{
				"app.container": []byte(`[Container]
Image=app:latest
`),
				"app.container.d/10-config.conf": []byte(`[Unit]
After=db.container init.container

[Container]
Network=app-net.network
Volume=data.volume:/data
Volume=logs.volume:/logs
Mount=type=volume,source=cache.volume,destination=/cache
`),
				"db.container": []byte(`[Container]
Image=db:latest
`),
				"init.container": []byte(`[Container]
Image=init:latest
`),
				"app-net.network": []byte(`[Network]
`),
				"data.volume": []byte(`[Volume]
`),
				"logs.volume": []byte(`[Volume]
`),
				"cache.volume": []byte(`[Volume]
`),
			},
			appID: "myapp",
			expectedFiles: []string{
				"myapp-app.container",
				"myapp-db.container",
				"myapp-init.container",
				"myapp-app-net.network",
				"myapp-data.volume",
				"myapp-logs.volume",
				"myapp-cache.volume",
				"myapp-app.container.d/10-config.conf",
			},
			checkFileContents: map[string]func(*testing.T, []byte){
				"myapp-app.container.d/10-config.conf": func(t *testing.T, content []byte) {
					contentStr := string(content)
					require.Contains(t, contentStr, "myapp-db.container")
					require.Contains(t, contentStr, "myapp-init.container")
					require.Contains(t, contentStr, "myapp-app-net.network")
					require.Contains(t, contentStr, "myapp-data.volume:/data")
					require.Contains(t, contentStr, "myapp-logs.volume:/logs")
					require.Contains(t, contentStr, "source=myapp-cache.volume")
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			rw := fileio.NewReadWriter()
			rw.SetRootdir(tmpDir)

			for filename, content := range tt.files {
				// Create parent directory if file is in a subdirectory
				dir := filepath.Dir(filename)
				if dir != "." && dir != "/" {
					err := rw.MkdirAll(dir, fileio.DefaultDirectoryPermissions)
					require.NoError(t, err)
				}
				err := rw.WriteFile(filename, content, fileio.DefaultFilePermissions)
				require.NoError(t, err)
			}

			err := InstallQuadlet(rw, "/", tt.appID)
			require.NoError(t, err)

			for _, expectedFile := range tt.expectedFiles {
				content, err := rw.ReadFile(expectedFile)
				require.NoError(t, err, "expected file %s to exist", expectedFile)
				require.NotEmpty(t, content, "expected file %s to have content", expectedFile)

				if checkFn, ok := tt.checkFileContents[expectedFile]; ok {
					checkFn(t, content)
				}
			}
		})
	}
}
