package validation

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/flightctl/flightctl/internal/api/common"
)

// ValidateQuadletSpec verifies the QuadletSpec for common issues
func ValidateQuadletSpec(spec *common.QuadletSpec) []error {
	var errs []error

	switch spec.Type {
	case common.QuadletTypeContainer:
		if spec.Image == nil {
			errs = append(errs, fmt.Errorf(".container quadlet must have an Image key"))
		} else {
			image := *spec.Image
			if isQuadletBuildReference(image) {
				errs = append(errs, fmt.Errorf(".build quadlet types are unsupported: %s", image))
			} else if !isQuadletImageReference(image) {
				if err := ValidateOciImageReferenceStrict(spec.Image, "container.image"); err != nil {
					errs = append(errs, err...)
				}
			}
		}

	case common.QuadletTypeVolume:
		if spec.Image != nil {
			image := *spec.Image
			if !isQuadletImageReference(image) {
				if err := ValidateOciImageReferenceStrict(spec.Image, "volume.image"); err != nil {
					errs = append(errs, err...)
				}
			}
		}

	case common.QuadletTypeImage:
		if spec.Image == nil {
			errs = append(errs, fmt.Errorf(".image quadlet must have an Image key"))
		} else {
			if err := ValidateOciImageReferenceStrict(spec.Image, "image.image"); err != nil {
				errs = append(errs, err...)
			}
		}

	case common.QuadletTypeNetwork, common.QuadletTypePod:
		// no validation required

	default:
		errs = append(errs, fmt.Errorf("unsupported quadlet type %s", spec.Type))
	}

	return errs
}

// isQuadletImageReference returns true if the reference ends with ".image"
func isQuadletImageReference(ref string) bool {
	return strings.HasSuffix(ref, ".image")
}

// isQuadletBuildReference returns true if the reference ends with ".build"
func isQuadletBuildReference(ref string) bool {
	return strings.HasSuffix(ref, ".build")
}

// ValidateQuadletPaths validates a list of paths for inline quadlet applications
func ValidateQuadletPaths(paths []string) error {
	var errs []error

	if len(paths) == 0 {
		return fmt.Errorf("no paths provided")
	}

	foundSupported := false

	for _, path := range paths {
		ext := filepath.Ext(path)

		if _, ok := common.SupportedQuadletExtensions[ext]; ok {
			if !isAtRoot(path) {
				errs = append(errs, fmt.Errorf("quadlet file must be at root level: %q", path))
			}
			foundSupported = true
			continue
		}

		if _, ok := common.UnsupportedQuadletExtensions[ext]; ok {
			errs = append(errs, fmt.Errorf("unsupported quadlet type %q in path: %s", ext, path))
			continue
		}
	}

	if !foundSupported {
		errs = append(errs, fmt.Errorf("no supported quadlet types supplied"))
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	return nil
}
