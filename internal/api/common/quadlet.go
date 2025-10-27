package common

import (
	"fmt"
	"path/filepath"

	"github.com/containers/podman/v5/pkg/systemd/parser"
	"github.com/containers/podman/v5/pkg/systemd/quadlet"
)

// QuadletType represents the type of Quadlet unit file.
type QuadletType string

const (
	QuadletTypeContainer QuadletType = "container"
	QuadletTypeVolume    QuadletType = "volume"
	QuadletTypeNetwork   QuadletType = "network"
	QuadletTypeImage     QuadletType = "image"
	QuadletTypePod       QuadletType = "pod"

	QuadletExtensionContainer = ".container"
	QuadletExtensionVolume    = ".volume"
	QuadletExtensionNetwork   = ".network"
	QuadletExtensionImage     = ".image"
	QuadletExtensionPod       = ".pod"
)

var (
	ErrUnsupportedQuadletType = fmt.Errorf("unsupported quadlet type")
	ErrNonQuadletType         = fmt.Errorf("non quadlet type")
)

var (
	SupportedQuadletExtensions = map[string]struct{}{
		QuadletExtensionContainer: {},
		QuadletExtensionVolume:    {},
		QuadletExtensionNetwork:   {},
		QuadletExtensionImage:     {},
		QuadletExtensionPod:       {},
	}
	UnsupportedQuadletExtensions = map[string]struct{}{
		".build":    {},
		".artifact": {},
		".kube":     {},
	}
	UnsupportedQuadletSections = map[string]struct{}{
		"Build":    {},
		"Artifact": {},
		"Kube":     {},
	}
)

const (
	quadletKeyImage = "Image"
)

// QuadletSpec represents a Quadlet unit file specification.
type QuadletSpec struct {
	Type  QuadletType
	Image *string
}

// IsQuadletFile returns true if the supplied path should reference a quadlet
func IsQuadletFile(path string) bool {
	ext := filepath.Ext(path)
	if _, ok := SupportedQuadletExtensions[ext]; ok {
		return true
	}
	if _, ok := UnsupportedQuadletExtensions[ext]; ok {
		return true
	}
	return false
}

// ParseQuadletSpec parses unit file data into a QuadletSpec
func ParseQuadletSpec(data []byte) (*QuadletSpec, error) {
	unit := parser.NewUnitFile()
	err := unit.Parse(string(data))
	if err != nil {
		return nil, fmt.Errorf("parsing unit: %w", err)
	}

	for group := range UnsupportedQuadletSections {
		if unit.HasGroup(group) {
			return nil, fmt.Errorf("%w: type: %s", ErrUnsupportedQuadletType, group)
		}
	}

	typeSections := map[string]QuadletType{
		quadlet.ContainerGroup: QuadletTypeContainer,
		quadlet.VolumeGroup:    QuadletTypeVolume,
		quadlet.NetworkGroup:   QuadletTypeNetwork,
		quadlet.ImageGroup:     QuadletTypeImage,
		quadlet.PodGroup:       QuadletTypePod,
	}

	var detectedType QuadletType
	var detectedSection string
	foundCount := 0

	for sectionName, quadletType := range typeSections {
		if unit.HasGroup(sectionName) {
			detectedType = quadletType
			detectedSection = sectionName
			foundCount++
		}
	}

	if foundCount == 0 {
		return nil, ErrNonQuadletType
	}

	if foundCount > 1 {
		return nil, fmt.Errorf("multiple quadlet type sections found")
	}

	spec := &QuadletSpec{
		Type: detectedType,
	}

	if image, ok := unit.Lookup(detectedSection, quadlet.KeyImage); ok {
		spec.Image = &image
	}

	return spec, nil
}
