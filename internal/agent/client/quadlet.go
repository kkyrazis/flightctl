package client

import (
	"bytes"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/containers/podman/v5/pkg/systemd/parser"
	"github.com/containers/podman/v5/pkg/systemd/quadlet"
	"github.com/flightctl/flightctl/internal/agent/device/fileio"
)

const (
	QuadletProjectLabelKey = "io.flightctl.quadlet.project"

	QuadletContainerExtension = ".container"
	QuadletVolumeExtension    = ".volume"
	QuadletNetworkExtension   = ".network"
	QuadletImageExtension     = ".image"
	QuadletPodExtension       = ".pod"

	quadletDropInFile = "99-flightctl.conf"
)

// QuadletSections maps Podman quadlet file extensions to their corresponding systemd unit section names.
// This mapping is used to identify valid quadlet files and determine which section name to use when
// creating or updating quadlet unit files.
// For more details on quadlet format, see: https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html
var QuadletSections = map[string]string{
	QuadletContainerExtension: quadlet.ContainerGroup,
	QuadletVolumeExtension:    quadlet.VolumeGroup,
	QuadletNetworkExtension:   quadlet.NetworkGroup,
	QuadletImageExtension:     quadlet.ImageGroup,
	QuadletPodExtension:       quadlet.PodGroup,
}

// InstallQuadlet prepares Podman quadlet files for use with flightctl by applying namespacing,
// updating cross-references, and adding flightctl-specific overrides.
//
// This function performs three main operations on quadlet files located at the specified path:
//
//  1. NAMESPACING: Renames quadlet files and drop-in directories to include the appID as a prefix.
//     This prevents naming conflicts when multiple applications define similarly-named resources.
//
//     Files are renamed: foo.container → {appID}-foo.container
//     The function is idempotent - already-namespaced files are not renamed again.
//
//     Drop-in directories follow systemd's hierarchical naming rules and are also namespaced:
//     - Specific drop-ins: web.container.d/ → {appID}-web.container.d/
//     - Hierarchical drop-ins: foo-.container.d/ → {appID}-foo-.container.d/
//     - Top-level type drop-ins: container.d/ → {appID}-.container.d/
//
//  2. REFERENCE UPDATING: Updates cross-references within quadlet files and drop-in configurations
//     to point to the newly namespaced resources.
//
//     This includes:
//     - Quadlet-specific references (Volume=, Network=, Image=, Pod=, Mount= parameters)
//     - Systemd references in [Unit] sections (After=, Requires=, Before=, etc.)
//     - Systemd references in [Install] sections (WantedBy=, RequiredBy=, etc.)
//
//     External system services (e.g., chronyd.service, network.target) are not modified.
//     Both quadlet files and drop-in .conf files have their references updated.
//
// 3. FLIGHTCTL OVERRIDES: Creates drop-in configuration files to add flightctl-specific settings.
//
//	For each quadlet type found, creates {appID}-.{type}.d/99-flightctl.conf containing:
//	  - Label with project identifier for filtering (io.flightctl.quadlet.project={appID})
//	  - EnvironmentFile directive pointing to .env (containers only, if .env exists)
//
//	The 99- prefix ensures these overrides have high priority and are not overridden by
//	user-provided drop-ins.
//
// Parameters:
//   - readWriter: File system interface for reading and writing files
//   - path: Absolute path to directory containing quadlet files and drop-in directories
//   - appID: Application identifier used as namespace prefix for all resources
//
// Returns:
//   - error if any operation fails during namespacing, reference updating, or override creation
//
// Example directory structure transformation:
//
//	Before:
//	  /path/
//	    web.container
//	    data.volume
//	    web.container.d/
//	      10-custom.conf
//	    .env
//
//	After:
//	  /path/
//	    myapp-web.container      (namespaced, references updated)
//	    myapp-data.volume        (namespaced)
//	    myapp-web.container.d/
//	      10-custom.conf         (references updated)
//	    myapp-.container.d/
//	      99-flightctl.conf      (flightctl overrides)
//	    myapp-.volume.d/
//	      99-flightctl.conf      (flightctl overrides)
//	    .env                     (preserved as-is)
func InstallQuadlet(readWriter fileio.ReadWriter, path string, appID string) error {
	entries, err := readWriter.ReadDir(path)
	if err != nil {
		return fmt.Errorf("reading directory: %w", err)
	}

	hasEnvFile := false
	foundTypes := make(map[string]struct{})
	quadletBasenames := make(map[string]struct{})

	// 1. apply namespacing rules by appending the supplied appID to the quadlet files
	// and any drop in directories
	for _, entry := range entries {
		if !entry.IsDir() {
			filename := entry.Name()

			if filename == ".env" {
				hasEnvFile = true
				continue
			}

			ext := filepath.Ext(filename)
			if _, ok := QuadletSections[ext]; ok {
				foundTypes[ext] = struct{}{}

				basename := strings.TrimSuffix(filename, ext)
				basename = strings.TrimPrefix(basename, fmt.Sprintf("%s-", appID))
				quadletBasenames[basename] = struct{}{}

				if err := namespaceQuadletFile(readWriter, path, appID, filename); err != nil {
					return fmt.Errorf("namespacing %s: %w", filename, err)
				}
			}
		} else {
			if err = namespaceDropInDirectory(readWriter, filepath.Join(path, entry.Name()), appID); err != nil {
				return fmt.Errorf("namespacing drop-in dir %s: %w", entry.Name(), err)
			}
		}
	}

	entries, err = readWriter.ReadDir(path)
	if err != nil {
		return fmt.Errorf("re-reading directory: %w", err)
	}

	// 2. Update any required references in quadlet files or in drop-in .conf files
	for _, entry := range entries {
		if !entry.IsDir() {
			filename := entry.Name()
			ext := filepath.Ext(filename)

			if _, ok := QuadletSections[ext]; ok {
				if err := updateQuadletReferences(readWriter, path, appID, filename, ext, quadletBasenames); err != nil {
					return fmt.Errorf("updating references in %s: %w", filename, err)
				}
			}
		} else {
			if err = updateDropInReferences(readWriter, filepath.Join(path, entry.Name()), appID, quadletBasenames); err != nil {
				return fmt.Errorf("updating drop-in references: %w", err)
			}
		}
	}

	// For any quadlet types that were found, apply flightctl overrides
	for ext := range foundTypes {
		if err := createQuadletDropIn(readWriter, path, appID, ext, hasEnvFile); err != nil {
			return fmt.Errorf("creating drop-in for %s: %w", ext, err)
		}
	}

	return nil
}

func namespacedQuadlet(appID string, name string) string {
	return fmt.Sprintf("%s-%s", appID, name)
}

// namespaceQuadletFile renames a quadlet file to include the appID prefix if it doesn't already have it
func namespaceQuadletFile(readWriter fileio.ReadWriter, dirPath, appID, filename string) error {
	if strings.HasPrefix(filename, fmt.Sprintf("%s-", appID)) {
		return nil
	}

	oldPath := filepath.Join(dirPath, filename)
	newPath := filepath.Join(dirPath, namespacedQuadlet(appID, filename))

	if err := readWriter.CopyFile(oldPath, newPath); err != nil {
		return fmt.Errorf("copying file: %w", err)
	}

	if err := readWriter.RemoveFile(oldPath); err != nil {
		return fmt.Errorf("removing original file: %w", err)
	}

	return nil
}

// namespaceDropInDirectories renames drop-in directories to match namespaced quadlet files
// For example: web.container.d/ -> myapp-web.container.d/
// Also handles hierarchical drop-ins: foo-bar.container.d/, foo-.container.d/, container.d/ -> myapp-foo-bar.container.d/, myapp-foo-.container.d/, myapp-.container.d/
func namespaceDropInDirectory(readWriter fileio.ReadWriter, dirPath, appID string) error {
	dirname := filepath.Base(dirPath)

	// ensure drop-in dir
	if !strings.HasSuffix(dirname, ".d") {
		return nil
	}

	// Check if it's a quadlet drop-in directory (e.g., web.container.d, container.d, foo-.container.d)
	baseName := strings.TrimSuffix(dirname, ".d")
	ext := filepath.Ext(baseName)

	// handle top level drop-ins like container.d
	topLevelDropIn := false
	if ext == "" {
		topLevelDropIn = true
		ext = fmt.Sprintf(".%s", baseName)
	}

	if _, ok := QuadletSections[ext]; !ok {
		return nil
	}

	prefix := fmt.Sprintf("%s-", appID)
	if strings.HasPrefix(dirname, prefix) {
		return nil
	}

	var newDirname string
	if topLevelDropIn {
		newDirname = namespacedQuadlet(appID, fmt.Sprintf(".%s", dirname))
	} else {
		newDirname = namespacedQuadlet(appID, dirname)
	}

	oldPath := dirPath
	newPath := filepath.Join(filepath.Dir(dirPath), newDirname)

	dropInEntries, err := readWriter.ReadDir(oldPath)
	if err != nil {
		return fmt.Errorf("reading drop-in directory %s: %w", oldPath, err)
	}

	if err = readWriter.MkdirAll(newPath, fileio.DefaultDirectoryPermissions); err != nil {
		return fmt.Errorf("creating new drop-in directory: %w", err)
	}

	for _, dropInEntry := range dropInEntries {
		if dropInEntry.IsDir() {
			continue
		}

		oldFilePath := filepath.Join(oldPath, dropInEntry.Name())
		newFilePath := filepath.Join(newPath, dropInEntry.Name())

		if err = readWriter.CopyFile(oldFilePath, newFilePath); err != nil {
			return fmt.Errorf("copying %s: %w", oldFilePath, err)
		}
	}

	if err = readWriter.RemoveAll(oldPath); err != nil {
		return fmt.Errorf("removing old drop-in directory: %w", err)
	}

	return nil
}

// createQuadletDropIn creates a drop-in override directory and configuration file
// for a specific quadlet type. It adds the project label and optionally the EnvironmentFile parameter.
func createQuadletDropIn(readWriter fileio.ReadWriter, dirPath, appID, extension string, hasEnvFile bool) error {
	dropInDir := filepath.Join(dirPath, fmt.Sprintf("%s-%s.d", appID, extension))
	if err := readWriter.MkdirAll(dropInDir, fileio.DefaultDirectoryPermissions); err != nil {
		return fmt.Errorf("creating drop-in directory: %w", err)
	}

	sectionName := QuadletSections[extension]
	unit := parser.NewUnitFile()

	// add label for tracking quadlet events by app id
	labelLine := fmt.Sprintf("%s=%s", QuadletProjectLabelKey, appID)
	unit.Add(sectionName, quadlet.KeyLabel, labelLine)

	// Only containers support environment files
	if hasEnvFile && extension == QuadletContainerExtension {
		unit.Add(sectionName, quadlet.KeyEnvironmentFile, filepath.Join(dirPath, ".env"))
	}

	b := new(bytes.Buffer)
	if err := unit.Write(b); err != nil {
		return fmt.Errorf("serializing drop-in unit: %w", err)
	}

	dropInFile := filepath.Join(dropInDir, quadletDropInFile)
	if err := readWriter.WriteFile(dropInFile, b.Bytes(), fileio.DefaultFilePermissions); err != nil {
		return fmt.Errorf("writing drop-in file: %w", err)
	}

	return nil
}

// prefixQuadletReference prefixes a quadlet filename reference with appID if it's not already prefixed
func prefixQuadletReference(value, appID string) string {
	for ext := range QuadletSections {
		if strings.HasSuffix(value, ext) {
			prefix := fmt.Sprintf("%s-", appID)
			if !strings.HasPrefix(value, prefix) {
				return namespacedQuadlet(appID, value)
			}
			return value
		}
	}
	return value
}

// updateSystemdReference updates references in [Unit] and [Install] sections
// It handles both direct quadlet references and service references generated by our quadlets
func updateSystemdReference(value, appID string, quadletBasenames map[string]struct{}) string {
	if strings.HasSuffix(value, ".service") {
		basename := strings.TrimSuffix(value, ".service")
		if _, exists := quadletBasenames[basename]; exists {
			return namespacedQuadlet(appID, value)
		}
		return value
	}

	return prefixQuadletReference(value, appID)
}

// updateSpaceSeparatedReferences updates space-separated systemd references
func updateSpaceSeparatedReferences(value, appID string, quadletBasenames map[string]struct{}) string {
	parts := strings.Fields(value)
	for i, part := range parts {
		parts[i] = updateSystemdReference(part, appID, quadletBasenames)
	}
	return strings.Join(parts, " ")
}

// updateMountValue updates Mount= parameter values to prefix quadlet references
func updateMountValue(value, appID string) string {
	parts := strings.Split(value, ",")
	var mountType string

	for i, part := range parts {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}

		key := strings.TrimSpace(kv[0])
		val := strings.TrimSpace(kv[1])

		if key == "type" {
			mountType = val
		}

		if key == "source" && (mountType == "volume" || mountType == "image") {
			parts[i] = fmt.Sprintf("%s=%s", key, prefixQuadletReference(val, appID))
		}
	}

	return strings.Join(parts, ",")
}

// updateVolumeValue updates Volume= parameter values to prefix quadlet references
func updateVolumeValue(value, appID string) string {
	parts := strings.SplitN(value, ":", 2)
	if len(parts) >= 1 {
		parts[0] = prefixQuadletReference(parts[0], appID)
	}
	return strings.Join(parts, ":")
}

// updateSystemdSection updates references in [Unit] or [Install] sections
func updateSystemdSection(unit *parser.UnitFile, sectionName, appID string, quadletBasenames map[string]struct{}) {
	for _, key := range unit.ListKeys(sectionName) {
		vals := unit.LookupAll(sectionName, key)
		unit.Unset(sectionName, key)
		for _, val := range vals {
			unit.Add(sectionName, key, updateSpaceSeparatedReferences(val, appID, quadletBasenames))
		}
	}
}

// updateOptionsByName updates all options matching the given section and names using the transform function
func updateOptionsByName(unit *parser.UnitFile, sectionName string, names []string, transform func(string) string) {
	for _, key := range names {
		vals := unit.LookupAll(sectionName, key)
		unit.Unset(sectionName, key)
		for _, val := range vals {
			unit.Add(sectionName, key, transform(val))
		}
	}
}

// updateContainerSection updates references in [Container] section
func updateContainerSection(unit *parser.UnitFile, appID string) {
	updateOptionsByName(unit, quadlet.ContainerGroup, []string{quadlet.KeyImage, quadlet.KeyNetwork, quadlet.KeyPod}, func(val string) string {
		return prefixQuadletReference(val, appID)
	})
	updateOptionsByName(unit, quadlet.ContainerGroup, []string{quadlet.KeyMount}, func(val string) string {
		return updateMountValue(val, appID)
	})
	updateOptionsByName(unit, quadlet.ContainerGroup, []string{quadlet.KeyVolume}, func(val string) string {
		return updateVolumeValue(val, appID)
	})
}

// updatePodSection updates references in [Pod] section
func updatePodSection(unit *parser.UnitFile, appID string) {
	updateOptionsByName(unit, quadlet.PodGroup, []string{quadlet.KeyNetwork}, func(val string) string {
		return prefixQuadletReference(val, appID)
	})
	updateOptionsByName(unit, quadlet.PodGroup, []string{quadlet.KeyVolume}, func(val string) string {
		return updateVolumeValue(val, appID)
	})
}

// updateVolumeSection updates references in [Volume] section
func updateVolumeSection(unit *parser.UnitFile, appID string) {
	updateOptionsByName(unit, quadlet.VolumeGroup, []string{quadlet.KeyImage}, func(val string) string {
		return prefixQuadletReference(val, appID)
	})
}

// updateQuadletReferences updates cross-references within a quadlet file after it has been namespaced
func updateQuadletReferences(readWriter fileio.ReadWriter, dirPath, appID, filename, extension string, quadletBasenames map[string]struct{}) error {
	filePath := filepath.Join(dirPath, filename)
	content, err := readWriter.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("reading file: %w", err)
	}

	unit := parser.NewUnitFile()
	unit.Path = dirPath
	unit.Filename = filename
	if err = unit.Parse(string(content)); err != nil {
		return fmt.Errorf("parsing unit content: %w", err)
	}

	updateSystemdSection(unit, "Unit", appID, quadletBasenames)
	updateSystemdSection(unit, "Install", appID, quadletBasenames)

	switch extension {
	case QuadletContainerExtension:
		updateContainerSection(unit, appID)
	case QuadletPodExtension:
		updatePodSection(unit, appID)
	case QuadletVolumeExtension:
		updateVolumeSection(unit, appID)
	}

	buf := new(bytes.Buffer)
	if err = unit.Write(buf); err != nil {
		return fmt.Errorf("writing unit: %w", err)
	}

	if err := readWriter.WriteFile(filePath, buf.Bytes(), fileio.DefaultFilePermissions); err != nil {
		return fmt.Errorf("writing file: %w", err)
	}

	return nil
}

// updateDropInReferences updates references within drop-in .conf files after drop-in directories have been namespaced
func updateDropInReferences(readWriter fileio.ReadWriter, dirPath, appID string, quadletBasenames map[string]struct{}) error {
	dirname := filepath.Base(dirPath)

	if !strings.HasSuffix(dirname, ".d") {
		return nil
	}

	prefix := fmt.Sprintf("%s-", appID)
	if !strings.HasPrefix(dirname, prefix) {
		return nil
	}

	baseName := strings.TrimSuffix(dirname, ".d")
	ext := filepath.Ext(baseName)

	if _, ok := QuadletSections[ext]; !ok {
		return nil
	}

	dropInPath := dirPath
	confEntries, err := readWriter.ReadDir(dropInPath)
	if err != nil {
		return fmt.Errorf("reading drop-in directory %s: %w", dropInPath, err)
	}

	for _, confEntry := range confEntries {
		if confEntry.IsDir() {
			continue
		}

		confFilename := confEntry.Name()
		if !strings.HasSuffix(confFilename, ".conf") {
			continue
		}

		if err = updateQuadletReferences(readWriter, dropInPath, appID, confFilename, ext, quadletBasenames); err != nil {
			return fmt.Errorf("updating drop-in: %w", err)
		}
	}

	return nil
}
