package validation

import (
	"testing"

	"github.com/flightctl/flightctl/internal/api/common"
	"github.com/samber/lo"
	"github.com/stretchr/testify/require"
)

func TestValidateQuadletSpec(t *testing.T) {
	require := require.New(t)

	tests := []struct {
		name          string
		spec          *common.QuadletSpec
		wantErrCount  int
		wantErrSubstr string
	}{
		{
			name: "container with no image",
			spec: &common.QuadletSpec{
				Type:  common.QuadletTypeContainer,
				Image: nil,
			},
			wantErrCount:  1,
			wantErrSubstr: "must have an Image key",
		},
		{
			name: "container with valid OCI reference",
			spec: &common.QuadletSpec{
				Type:  common.QuadletTypeContainer,
				Image: lo.ToPtr("quay.io/podman/hello:latest"),
			},
			wantErrCount: 0,
		},
		{
			name: "container with .image reference",
			spec: &common.QuadletSpec{
				Type:  common.QuadletTypeContainer,
				Image: lo.ToPtr("my-app.image"),
			},
			wantErrCount: 0,
		},
		{
			name: "container with .build reference",
			spec: &common.QuadletSpec{
				Type:  common.QuadletTypeContainer,
				Image: lo.ToPtr("my-app.build"),
			},
			wantErrCount:  1,
			wantErrSubstr: ".build quadlet types are unsupported",
		},
		{
			name: "container with invalid OCI reference",
			spec: &common.QuadletSpec{
				Type:  common.QuadletTypeContainer,
				Image: lo.ToPtr("nginx:latest"),
			},
			wantErrCount:  1,
			wantErrSubstr: "container.image",
		},
		{
			name: "volume with no image",
			spec: &common.QuadletSpec{
				Type:  common.QuadletTypeVolume,
				Image: nil,
			},
			wantErrCount: 0,
		},
		{
			name: "volume with valid OCI reference",
			spec: &common.QuadletSpec{
				Type:  common.QuadletTypeVolume,
				Image: lo.ToPtr("quay.io/containers/volume:latest"),
			},
			wantErrCount: 0,
		},
		{
			name: "volume with .image reference",
			spec: &common.QuadletSpec{
				Type:  common.QuadletTypeVolume,
				Image: lo.ToPtr("my-volume.image"),
			},
			wantErrCount: 0,
		},
		{
			name: "volume with invalid OCI reference",
			spec: &common.QuadletSpec{
				Type:  common.QuadletTypeVolume,
				Image: lo.ToPtr("alpine:3.18"),
			},
			wantErrCount:  1,
			wantErrSubstr: "volume.image",
		},
		{
			name: "image with valid OCI reference",
			spec: &common.QuadletSpec{
				Type:  common.QuadletTypeImage,
				Image: lo.ToPtr("quay.io/fedora/fedora:latest"),
			},
			wantErrCount: 0,
		},
		{
			name: "image with no image",
			spec: &common.QuadletSpec{
				Type:  common.QuadletTypeImage,
				Image: nil,
			},
			wantErrCount:  1,
			wantErrSubstr: ".image quadlet must have an Image key",
		},
		{
			name: "image with invalid OCI reference",
			spec: &common.QuadletSpec{
				Type:  common.QuadletTypeImage,
				Image: lo.ToPtr("busybox"),
			},
			wantErrCount:  1,
			wantErrSubstr: "image.image",
		},
		{
			name: "image with .image reference",
			spec: &common.QuadletSpec{
				Type:  common.QuadletTypeImage,
				Image: lo.ToPtr("another.image"),
			},
			wantErrCount:  1,
			wantErrSubstr: "image.image",
		},
		{
			name: "network with no image",
			spec: &common.QuadletSpec{
				Type:  common.QuadletTypeNetwork,
				Image: nil,
			},
			wantErrCount: 0,
		},
		{
			name: "pod with no image",
			spec: &common.QuadletSpec{
				Type:  common.QuadletTypePod,
				Image: nil,
			},
			wantErrCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errs := ValidateQuadletSpec(tt.spec)
			require.Len(errs, tt.wantErrCount, "expected %d errors, got %d: %v", tt.wantErrCount, len(errs), errs)
			if tt.wantErrSubstr != "" && len(errs) > 0 {
				require.Contains(errs[0].Error(), tt.wantErrSubstr)
			}
		})
	}
}

func TestValidateQuadletPaths(t *testing.T) {
	require := require.New(t)

	tests := []struct {
		name          string
		paths         []string
		wantErr       bool
		wantErrSubstr string
	}{
		// Valid cases
		{
			name:    "single container file",
			paths:   []string{"app.container"},
			wantErr: false,
		},
		{
			name:    "single volume file",
			paths:   []string{"data.volume"},
			wantErr: false,
		},
		{
			name:    "multiple valid types",
			paths:   []string{"app.container", "data.volume"},
			wantErr: false,
		},
		{
			name:    "all supported types",
			paths:   []string{"app.container", "data.volume", "net.network", "img.image", "mypod.pod"},
			wantErr: false,
		},
		{
			name:    "mix of supported quadlet and non-quadlet files",
			paths:   []string{"app.container", "config.yaml", "README.txt"},
			wantErr: false,
		},
		{
			name:    "unknown extensions mixed with valid quadlet",
			paths:   []string{"app.container", "script.sh", "data.conf"},
			wantErr: false,
		},
		{
			name:    "nested non-quadlet files with root quadlet",
			paths:   []string{"app.container", "config/settings.yaml", "scripts/deploy.sh"},
			wantErr: false,
		},

		// Invalid cases
		{
			name:          "empty paths slice",
			paths:         []string{},
			wantErr:       true,
			wantErrSubstr: "at least one file must be provided",
		},
		{
			name:          "contains build file - unsupported",
			paths:         []string{"app.build"},
			wantErr:       true,
			wantErrSubstr: "unsupported quadlet type \".build\"",
		},
		{
			name:          "contains artifact file - unsupported",
			paths:         []string{"app.artifact"},
			wantErr:       true,
			wantErrSubstr: "unsupported quadlet type \".artifact\"",
		},
		{
			name:          "contains kube file - unsupported",
			paths:         []string{"app.kube"},
			wantErr:       true,
			wantErrSubstr: "unsupported quadlet type \".kube\"",
		},
		{
			name:          "mix of valid and unsupported",
			paths:         []string{"app.container", "build.build"},
			wantErr:       true,
			wantErrSubstr: "unsupported quadlet type \".build\"",
		},
		{
			name:          "only non-quadlet files - no supported types",
			paths:         []string{"config.txt", "data.yaml"},
			wantErr:       true,
			wantErrSubstr: "at least one supported quadlet type",
		},
		{
			name:          "only build file - both unsupported and no valid types",
			paths:         []string{"app.build"},
			wantErr:       true,
			wantErrSubstr: "unsupported quadlet type \".build\"",
		},
		{
			name:          "nested quadlet file - must be at root",
			paths:         []string{"config/app.container"},
			wantErr:       true,
			wantErrSubstr: "quadlet file must be at root level",
		},
		{
			name:          "mix of root and nested quadlet files",
			paths:         []string{"app.container", "subdir/data.volume"},
			wantErr:       true,
			wantErrSubstr: "quadlet file must be at root level",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateQuadletPaths(tt.paths)
			if tt.wantErr {
				require.Error(err)
				if tt.wantErrSubstr != "" {
					require.Contains(err.Error(), tt.wantErrSubstr)
				}
				return
			}
			require.NoError(err)
		})
	}
}
