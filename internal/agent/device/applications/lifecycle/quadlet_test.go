package lifecycle

import (
	"context"
	"fmt"
	"io/fs"
	"testing"

	"github.com/flightctl/flightctl/internal/agent/client"
	"github.com/flightctl/flightctl/internal/agent/device/fileio"
	"github.com/flightctl/flightctl/pkg/executer"
	"github.com/flightctl/flightctl/pkg/log"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

type mockDirEntry struct {
	name  string
	isDir bool
}

func (m *mockDirEntry) Name() string               { return m.name }
func (m *mockDirEntry) IsDir() bool                { return m.isDir }
func (m *mockDirEntry) Type() fs.FileMode          { return 0 }
func (m *mockDirEntry) Info() (fs.FileInfo, error) { return nil, nil }

func TestQuadlet_Execute(t *testing.T) {
	require := require.New(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	testCases := []struct {
		name       string
		action     *Action
		setupMocks func(*executer.MockExecuter, *fileio.MockReadWriter)
		wantErr    bool
	}{
		{
			name: "ActionAdd success",
			action: &Action{
				Type: ActionAdd,
				Name: "test-app",
				Path: "/test/path",
				ID:   "test-id",
			},
			setupMocks: func(mockExec *executer.MockExecuter, mockRW *fileio.MockReadWriter) {
				mockExec.EXPECT().ExecuteWithContext(gomock.Any(), "/usr/bin/systemctl", "daemon-reload").Return("", "", 0)
				mockRW.EXPECT().ReadDir("/test/path").Return([]fs.DirEntry{}, nil)
				mockExec.EXPECT().ExecuteWithContext(gomock.Any(), "/usr/bin/systemctl", "enable", "--now").Return("", "", 0)
			},
			wantErr: false,
		},
		{
			name: "ActionRemove success",
			action: &Action{
				Type: ActionRemove,
				Name: "test-app",
				ID:   "test-id",
			},
			setupMocks: func(mockExec *executer.MockExecuter, mockRW *fileio.MockReadWriter) {
				mockExec.EXPECT().ExecuteWithContext(gomock.Any(), "/usr/bin/systemctl", "list-units", "--all", "--output", "json", "test-id*").Return("[]", "", 0)
				mockExec.EXPECT().ExecuteWithContext(gomock.Any(), "/usr/bin/systemctl", "disable", "--now").Return("", "", 0)
				mockExec.EXPECT().ExecuteWithContext(gomock.Any(), "/usr/bin/systemctl", "daemon-reload").Return("", "", 0)
			},
			wantErr: false,
		},
		{
			name: "ActionUpdate success",
			action: &Action{
				Type: ActionUpdate,
				Name: "test-app",
				Path: "/test/path",
				ID:   "test-id",
			},
			setupMocks: func(mockExec *executer.MockExecuter, mockRW *fileio.MockReadWriter) {
				mockExec.EXPECT().ExecuteWithContext(gomock.Any(), "/usr/bin/systemctl", "list-units", "--all", "--output", "json", "test-id*").Return("[]", "", 0)
				mockExec.EXPECT().ExecuteWithContext(gomock.Any(), "/usr/bin/systemctl", "disable", "--now").Return("", "", 0)
				mockExec.EXPECT().ExecuteWithContext(gomock.Any(), "/usr/bin/systemctl", "daemon-reload").Return("", "", 0)
				mockExec.EXPECT().ExecuteWithContext(gomock.Any(), "/usr/bin/systemctl", "daemon-reload").Return("", "", 0)
				mockRW.EXPECT().ReadDir("/test/path").Return([]fs.DirEntry{}, nil)
				mockExec.EXPECT().ExecuteWithContext(gomock.Any(), "/usr/bin/systemctl", "enable", "--now").Return("", "", 0)
			},
			wantErr: false,
		},
		{
			name: "unsupported action type",
			action: &Action{
				Type: "invalid",
				Name: "test-app",
			},
			setupMocks: func(mockExec *executer.MockExecuter, mockRW *fileio.MockReadWriter) {
			},
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockExec := executer.NewMockExecuter(ctrl)
			mockRW := fileio.NewMockReadWriter(ctrl)
			tc.setupMocks(mockExec, mockRW)

			systemd := client.NewSystemd(mockExec)
			logger := log.NewPrefixLogger("test")
			q := NewQuadlet(logger, mockRW, systemd)

			err := q.Execute(context.Background(), tc.action)
			if tc.wantErr {
				require.Error(err)
			} else {
				require.NoError(err)
			}
		})
	}
}

func TestQuadlet_add(t *testing.T) {
	require := require.New(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	testCases := []struct {
		name       string
		action     *Action
		setupMocks func(*executer.MockExecuter, *fileio.MockReadWriter)
		wantErr    bool
	}{
		{
			name: "add container file",
			action: &Action{
				Name: "test-app",
				Path: "/test/path",
			},
			setupMocks: func(mockExec *executer.MockExecuter, mockRW *fileio.MockReadWriter) {
				mockExec.EXPECT().ExecuteWithContext(gomock.Any(), "/usr/bin/systemctl", "daemon-reload").Return("", "", 0)
				mockRW.EXPECT().ReadDir("/test/path").Return([]fs.DirEntry{
					&mockDirEntry{name: "app.container", isDir: false},
				}, nil)
				mockExec.EXPECT().ExecuteWithContext(gomock.Any(), "/usr/bin/systemctl", "enable", "--now", "app.service").Return("", "", 0)
			},
			wantErr: false,
		},
		{
			name: "add pod file with ServiceName",
			action: &Action{
				Name: "test-app",
				Path: "/test/path",
			},
			setupMocks: func(mockExec *executer.MockExecuter, mockRW *fileio.MockReadWriter) {
				mockExec.EXPECT().ExecuteWithContext(gomock.Any(), "/usr/bin/systemctl", "daemon-reload").Return("", "", 0)
				mockRW.EXPECT().ReadDir("/test/path").Return([]fs.DirEntry{
					&mockDirEntry{name: "app.pod", isDir: false},
				}, nil)
				mockRW.EXPECT().ReadFile("app.pod").Return([]byte("[Pod]\nServiceName=custom.service\n"), nil)
				mockExec.EXPECT().ExecuteWithContext(gomock.Any(), "/usr/bin/systemctl", "enable", "--now", "custom.service").Return("", "", 0)
			},
			wantErr: false,
		},
		{
			name: "add pod file without ServiceName",
			action: &Action{
				Name: "test-app",
				Path: "/test/path",
			},
			setupMocks: func(mockExec *executer.MockExecuter, mockRW *fileio.MockReadWriter) {
				mockExec.EXPECT().ExecuteWithContext(gomock.Any(), "/usr/bin/systemctl", "daemon-reload").Return("", "", 0)
				mockRW.EXPECT().ReadDir("/test/path").Return([]fs.DirEntry{
					&mockDirEntry{name: "mypod.pod", isDir: false},
				}, nil)
				mockRW.EXPECT().ReadFile("mypod.pod").Return([]byte("[Pod]\nName=mypod\n"), nil)
				mockExec.EXPECT().ExecuteWithContext(gomock.Any(), "/usr/bin/systemctl", "enable", "--now", "mypod-pod.service").Return("", "", 0)
			},
			wantErr: false,
		},
		{
			name: "add target file",
			action: &Action{
				Name: "test-app",
				Path: "/test/path",
			},
			setupMocks: func(mockExec *executer.MockExecuter, mockRW *fileio.MockReadWriter) {
				mockExec.EXPECT().ExecuteWithContext(gomock.Any(), "/usr/bin/systemctl", "daemon-reload").Return("", "", 0)
				mockRW.EXPECT().ReadDir("/test/path").Return([]fs.DirEntry{
					&mockDirEntry{name: "app.target", isDir: false},
				}, nil)
				mockExec.EXPECT().ExecuteWithContext(gomock.Any(), "/usr/bin/systemctl", "enable", "--now", "app.target").Return("", "", 0)
			},
			wantErr: false,
		},
		{
			name: "add mixed files with correct ordering",
			action: &Action{
				Name: "test-app",
				Path: "/test/path",
			},
			setupMocks: func(mockExec *executer.MockExecuter, mockRW *fileio.MockReadWriter) {
				mockExec.EXPECT().ExecuteWithContext(gomock.Any(), "/usr/bin/systemctl", "daemon-reload").Return("", "", 0)
				mockRW.EXPECT().ReadDir("/test/path").Return([]fs.DirEntry{
					&mockDirEntry{name: "app1.container", isDir: false},
					&mockDirEntry{name: "app.target", isDir: false},
					&mockDirEntry{name: "app2.container", isDir: false},
				}, nil)
				mockExec.EXPECT().ExecuteWithContext(gomock.Any(), "/usr/bin/systemctl", "enable", "--now", "app.target", "app1.service", "app2.service").Return("", "", 0)
			},
			wantErr: false,
		},
		{
			name: "skip directories and unknown files",
			action: &Action{
				Name: "test-app",
				Path: "/test/path",
			},
			setupMocks: func(mockExec *executer.MockExecuter, mockRW *fileio.MockReadWriter) {
				mockExec.EXPECT().ExecuteWithContext(gomock.Any(), "/usr/bin/systemctl", "daemon-reload").Return("", "", 0)
				mockRW.EXPECT().ReadDir("/test/path").Return([]fs.DirEntry{
					&mockDirEntry{name: "subdir", isDir: true},
					&mockDirEntry{name: "readme.txt", isDir: false},
					&mockDirEntry{name: "app.container", isDir: false},
				}, nil)
				mockExec.EXPECT().ExecuteWithContext(gomock.Any(), "/usr/bin/systemctl", "enable", "--now", "app.service").Return("", "", 0)
			},
			wantErr: false,
		},
		{
			name: "daemon reload fails",
			action: &Action{
				Name: "test-app",
				Path: "/test/path",
			},
			setupMocks: func(mockExec *executer.MockExecuter, mockRW *fileio.MockReadWriter) {
				mockExec.EXPECT().ExecuteWithContext(gomock.Any(), "/usr/bin/systemctl", "daemon-reload").Return("", "reload failed", 1)
			},
			wantErr: true,
		},
		{
			name: "ReadDir fails",
			action: &Action{
				Name: "test-app",
				Path: "/test/path",
			},
			setupMocks: func(mockExec *executer.MockExecuter, mockRW *fileio.MockReadWriter) {
				mockExec.EXPECT().ExecuteWithContext(gomock.Any(), "/usr/bin/systemctl", "daemon-reload").Return("", "", 0)
				mockRW.EXPECT().ReadDir("/test/path").Return(nil, fmt.Errorf("directory not found"))
			},
			wantErr: true,
		},
		{
			name: "EnableMany fails",
			action: &Action{
				Name: "test-app",
				Path: "/test/path",
			},
			setupMocks: func(mockExec *executer.MockExecuter, mockRW *fileio.MockReadWriter) {
				mockExec.EXPECT().ExecuteWithContext(gomock.Any(), "/usr/bin/systemctl", "daemon-reload").Return("", "", 0)
				mockRW.EXPECT().ReadDir("/test/path").Return([]fs.DirEntry{
					&mockDirEntry{name: "app.container", isDir: false},
				}, nil)
				mockExec.EXPECT().ExecuteWithContext(gomock.Any(), "/usr/bin/systemctl", "enable", "--now", "app.service").Return("", "enable failed", 1)
			},
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockExec := executer.NewMockExecuter(ctrl)
			mockRW := fileio.NewMockReadWriter(ctrl)
			tc.setupMocks(mockExec, mockRW)

			systemd := client.NewSystemd(mockExec)
			logger := log.NewPrefixLogger("test")
			q := NewQuadlet(logger, mockRW, systemd)

			err := q.add(context.Background(), tc.action)
			if tc.wantErr {
				require.Error(err)
			} else {
				require.NoError(err)
			}
		})
	}
}

func TestQuadlet_remove(t *testing.T) {
	require := require.New(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	testCases := []struct {
		name       string
		action     *Action
		setupMocks func(*executer.MockExecuter, *fileio.MockReadWriter)
		wantErr    bool
	}{
		{
			name: "remove with matching units",
			action: &Action{
				Name: "test-app",
				ID:   "app-123",
			},
			setupMocks: func(mockExec *executer.MockExecuter, mockRW *fileio.MockReadWriter) {
				unitsJSON := `[{"unit":"app-123-web.service","load":"loaded","active":"active","sub":"running","description":"Web Service"}]`
				mockExec.EXPECT().ExecuteWithContext(gomock.Any(), "/usr/bin/systemctl", "list-units", "--all", "--output", "json", "app-123*").Return(unitsJSON, "", 0)
				mockExec.EXPECT().ExecuteWithContext(gomock.Any(), "/usr/bin/systemctl", "disable", "--now", "app-123-web.service").Return("", "", 0)
				mockExec.EXPECT().ExecuteWithContext(gomock.Any(), "/usr/bin/systemctl", "daemon-reload").Return("", "", 0)
			},
			wantErr: false,
		},
		{
			name: "remove with no matching units",
			action: &Action{
				Name: "test-app",
				ID:   "app-456",
			},
			setupMocks: func(mockExec *executer.MockExecuter, mockRW *fileio.MockReadWriter) {
				mockExec.EXPECT().ExecuteWithContext(gomock.Any(), "/usr/bin/systemctl", "list-units", "--all", "--output", "json", "app-456*").Return("[]", "", 0)
				mockExec.EXPECT().ExecuteWithContext(gomock.Any(), "/usr/bin/systemctl", "disable", "--now").Return("", "", 0)
				mockExec.EXPECT().ExecuteWithContext(gomock.Any(), "/usr/bin/systemctl", "daemon-reload").Return("", "", 0)
			},
			wantErr: false,
		},
		{
			name: "ListUnitsByMatchPattern fails",
			action: &Action{
				Name: "test-app",
				ID:   "app-789",
			},
			setupMocks: func(mockExec *executer.MockExecuter, mockRW *fileio.MockReadWriter) {
				mockExec.EXPECT().ExecuteWithContext(gomock.Any(), "/usr/bin/systemctl", "list-units", "--all", "--output", "json", "app-789*").Return("", "list failed", 1)
			},
			wantErr: true,
		},
		{
			name: "DisableMany fails",
			action: &Action{
				Name: "test-app",
				ID:   "app-999",
			},
			setupMocks: func(mockExec *executer.MockExecuter, mockRW *fileio.MockReadWriter) {
				unitsJSON := `[{"unit":"app-999-web.service","load":"loaded","active":"active","sub":"running","description":"Web Service"}]`
				mockExec.EXPECT().ExecuteWithContext(gomock.Any(), "/usr/bin/systemctl", "list-units", "--all", "--output", "json", "app-999*").Return(unitsJSON, "", 0)
				mockExec.EXPECT().ExecuteWithContext(gomock.Any(), "/usr/bin/systemctl", "disable", "--now", "app-999-web.service").Return("", "disable failed", 1)
			},
			wantErr: true,
		},
		{
			name: "daemon reload fails after disable",
			action: &Action{
				Name: "test-app",
				ID:   "app-000",
			},
			setupMocks: func(mockExec *executer.MockExecuter, mockRW *fileio.MockReadWriter) {
				mockExec.EXPECT().ExecuteWithContext(gomock.Any(), "/usr/bin/systemctl", "list-units", "--all", "--output", "json", "app-000*").Return("[]", "", 0)
				mockExec.EXPECT().ExecuteWithContext(gomock.Any(), "/usr/bin/systemctl", "disable", "--now").Return("", "", 0)
				mockExec.EXPECT().ExecuteWithContext(gomock.Any(), "/usr/bin/systemctl", "daemon-reload").Return("", "reload failed", 1)
			},
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockExec := executer.NewMockExecuter(ctrl)
			mockRW := fileio.NewMockReadWriter(ctrl)
			tc.setupMocks(mockExec, mockRW)

			systemd := client.NewSystemd(mockExec)
			logger := log.NewPrefixLogger("test")
			q := NewQuadlet(logger, mockRW, systemd)

			err := q.remove(context.Background(), tc.action)
			if tc.wantErr {
				require.Error(err)
			} else {
				require.NoError(err)
			}
		})
	}
}

func TestQuadlet_update(t *testing.T) {
	require := require.New(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	testCases := []struct {
		name       string
		action     *Action
		setupMocks func(*executer.MockExecuter, *fileio.MockReadWriter)
		wantErr    bool
	}{
		{
			name: "update success",
			action: &Action{
				Name: "test-app",
				Path: "/test/path",
				ID:   "app-123",
			},
			setupMocks: func(mockExec *executer.MockExecuter, mockRW *fileio.MockReadWriter) {
				mockExec.EXPECT().ExecuteWithContext(gomock.Any(), "/usr/bin/systemctl", "list-units", "--all", "--output", "json", "app-123*").Return("[]", "", 0)
				mockExec.EXPECT().ExecuteWithContext(gomock.Any(), "/usr/bin/systemctl", "disable", "--now").Return("", "", 0)
				mockExec.EXPECT().ExecuteWithContext(gomock.Any(), "/usr/bin/systemctl", "daemon-reload").Return("", "", 0)
				mockExec.EXPECT().ExecuteWithContext(gomock.Any(), "/usr/bin/systemctl", "daemon-reload").Return("", "", 0)
				mockRW.EXPECT().ReadDir("/test/path").Return([]fs.DirEntry{
					&mockDirEntry{name: "app.container", isDir: false},
				}, nil)
				mockExec.EXPECT().ExecuteWithContext(gomock.Any(), "/usr/bin/systemctl", "enable", "--now", "app.service").Return("", "", 0)
			},
			wantErr: false,
		},
		{
			name: "update fails on remove",
			action: &Action{
				Name: "test-app",
				Path: "/test/path",
				ID:   "app-456",
			},
			setupMocks: func(mockExec *executer.MockExecuter, mockRW *fileio.MockReadWriter) {
				mockExec.EXPECT().ExecuteWithContext(gomock.Any(), "/usr/bin/systemctl", "list-units", "--all", "--output", "json", "app-456*").Return("", "list failed", 1)
			},
			wantErr: true,
		},
		{
			name: "update fails on add",
			action: &Action{
				Name: "test-app",
				Path: "/test/path",
				ID:   "app-789",
			},
			setupMocks: func(mockExec *executer.MockExecuter, mockRW *fileio.MockReadWriter) {
				mockExec.EXPECT().ExecuteWithContext(gomock.Any(), "/usr/bin/systemctl", "list-units", "--all", "--output", "json", "app-789*").Return("[]", "", 0)
				mockExec.EXPECT().ExecuteWithContext(gomock.Any(), "/usr/bin/systemctl", "disable", "--now").Return("", "", 0)
				mockExec.EXPECT().ExecuteWithContext(gomock.Any(), "/usr/bin/systemctl", "daemon-reload").Return("", "", 0)
				mockExec.EXPECT().ExecuteWithContext(gomock.Any(), "/usr/bin/systemctl", "daemon-reload").Return("", "reload failed", 1)
			},
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockExec := executer.NewMockExecuter(ctrl)
			mockRW := fileio.NewMockReadWriter(ctrl)
			tc.setupMocks(mockExec, mockRW)

			systemd := client.NewSystemd(mockExec)
			logger := log.NewPrefixLogger("test")
			q := NewQuadlet(logger, mockRW, systemd)

			err := q.update(context.Background(), tc.action)
			if tc.wantErr {
				require.Error(err)
			} else {
				require.NoError(err)
			}
		})
	}
}

func TestQuadlet_collectTargets(t *testing.T) {
	require := require.New(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	testCases := []struct {
		name       string
		path       string
		setupMocks func(*fileio.MockReadWriter)
		want       []string
		wantErr    bool
	}{
		{
			name: "container files generate service names",
			path: "/test/path",
			setupMocks: func(mockRW *fileio.MockReadWriter) {
				mockRW.EXPECT().ReadDir("/test/path").Return([]fs.DirEntry{
					&mockDirEntry{name: "web.container", isDir: false},
					&mockDirEntry{name: "db.container", isDir: false},
				}, nil)
			},
			want:    []string{"web.service", "db.service"},
			wantErr: false,
		},
		{
			name: "pod files with ServiceName",
			path: "/test/path",
			setupMocks: func(mockRW *fileio.MockReadWriter) {
				mockRW.EXPECT().ReadDir("/test/path").Return([]fs.DirEntry{
					&mockDirEntry{name: "mypod.pod", isDir: false},
				}, nil)
				mockRW.EXPECT().ReadFile("mypod.pod").Return([]byte("[Pod]\nServiceName=custom-pod.service\n"), nil)
			},
			want:    []string{"custom-pod.service"},
			wantErr: false,
		},
		{
			name: "pod files without ServiceName",
			path: "/test/path",
			setupMocks: func(mockRW *fileio.MockReadWriter) {
				mockRW.EXPECT().ReadDir("/test/path").Return([]fs.DirEntry{
					&mockDirEntry{name: "mypod.pod", isDir: false},
				}, nil)
				mockRW.EXPECT().ReadFile("mypod.pod").Return([]byte("[Pod]\nName=mypod\n"), nil)
			},
			want:    []string{"mypod-pod.service"},
			wantErr: false,
		},
		{
			name: "target files preserved",
			path: "/test/path",
			setupMocks: func(mockRW *fileio.MockReadWriter) {
				mockRW.EXPECT().ReadDir("/test/path").Return([]fs.DirEntry{
					&mockDirEntry{name: "app.target", isDir: false},
				}, nil)
			},
			want:    []string{"app.target"},
			wantErr: false,
		},
		{
			name: "mixed files with correct ordering",
			path: "/test/path",
			setupMocks: func(mockRW *fileio.MockReadWriter) {
				mockRW.EXPECT().ReadDir("/test/path").Return([]fs.DirEntry{
					&mockDirEntry{name: "web.container", isDir: false},
					&mockDirEntry{name: "app.target", isDir: false},
					&mockDirEntry{name: "db.container", isDir: false},
					&mockDirEntry{name: "other.target", isDir: false},
				}, nil)
			},
			want:    []string{"app.target", "other.target", "web.service", "db.service"},
			wantErr: false,
		},
		{
			name: "skip directories and unknown extensions",
			path: "/test/path",
			setupMocks: func(mockRW *fileio.MockReadWriter) {
				mockRW.EXPECT().ReadDir("/test/path").Return([]fs.DirEntry{
					&mockDirEntry{name: "subdir", isDir: true},
					&mockDirEntry{name: "readme.txt", isDir: false},
					&mockDirEntry{name: "config.yaml", isDir: false},
					&mockDirEntry{name: "app.container", isDir: false},
				}, nil)
			},
			want:    []string{"app.service"},
			wantErr: false,
		},
		{
			name: "ReadDir fails",
			path: "/test/path",
			setupMocks: func(mockRW *fileio.MockReadWriter) {
				mockRW.EXPECT().ReadDir("/test/path").Return(nil, fmt.Errorf("directory not found"))
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "serviceName fails for pod",
			path: "/test/path",
			setupMocks: func(mockRW *fileio.MockReadWriter) {
				mockRW.EXPECT().ReadDir("/test/path").Return([]fs.DirEntry{
					&mockDirEntry{name: "mypod.pod", isDir: false},
				}, nil)
				mockRW.EXPECT().ReadFile("mypod.pod").Return(nil, fmt.Errorf("read failed"))
			},
			want:    nil,
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockRW := fileio.NewMockReadWriter(ctrl)
			tc.setupMocks(mockRW)

			logger := log.NewPrefixLogger("test")
			q := &Quadlet{
				rw:  mockRW,
				log: logger,
			}

			got, err := q.collectTargets(tc.path)
			if tc.wantErr {
				require.Error(err)
			} else {
				require.NoError(err)
				require.Equal(tc.want, got)
			}
		})
	}
}

func TestQuadlet_serviceName(t *testing.T) {
	require := require.New(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	testCases := []struct {
		name        string
		file        string
		section     string
		defaultName string
		setupMocks  func(*fileio.MockReadWriter)
		want        string
		wantErr     bool
	}{
		{
			name:        "pod with ServiceName key",
			file:        "mypod.pod",
			section:     "Pod",
			defaultName: "mypod-pod.service",
			setupMocks: func(mockRW *fileio.MockReadWriter) {
				mockRW.EXPECT().ReadFile("mypod.pod").Return([]byte("[Pod]\nServiceName=custom.service\n"), nil)
			},
			want:    "custom.service",
			wantErr: false,
		},
		{
			name:        "pod without ServiceName key",
			file:        "mypod.pod",
			section:     "Pod",
			defaultName: "mypod-pod.service",
			setupMocks: func(mockRW *fileio.MockReadWriter) {
				mockRW.EXPECT().ReadFile("mypod.pod").Return([]byte("[Pod]\nName=mypod\n"), nil)
			},
			want:    "mypod-pod.service",
			wantErr: false,
		},
		{
			name:        "ReadFile fails",
			file:        "mypod.pod",
			section:     "Pod",
			defaultName: "mypod-pod.service",
			setupMocks: func(mockRW *fileio.MockReadWriter) {
				mockRW.EXPECT().ReadFile("mypod.pod").Return(nil, fmt.Errorf("file not found"))
			},
			want:    "",
			wantErr: true,
		},
		{
			name:        "invalid INI format",
			file:        "mypod.pod",
			section:     "Pod",
			defaultName: "mypod-pod.service",
			setupMocks: func(mockRW *fileio.MockReadWriter) {
				mockRW.EXPECT().ReadFile("mypod.pod").Return([]byte("invalid ini content\n[[["), nil)
			},
			want:    "",
			wantErr: true,
		},
		{
			name:        "missing section",
			file:        "mypod.pod",
			section:     "Pod",
			defaultName: "mypod-pod.service",
			setupMocks: func(mockRW *fileio.MockReadWriter) {
				mockRW.EXPECT().ReadFile("mypod.pod").Return([]byte("[Container]\nImage=nginx\n"), nil)
			},
			want:    "",
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockRW := fileio.NewMockReadWriter(ctrl)
			tc.setupMocks(mockRW)

			logger := log.NewPrefixLogger("test")
			q := &Quadlet{
				rw:  mockRW,
				log: logger,
			}

			got, err := q.serviceName(tc.file, tc.section, tc.defaultName)
			if tc.wantErr {
				require.Error(err)
			} else {
				require.NoError(err)
				require.Equal(tc.want, got)
			}
		})
	}
}
