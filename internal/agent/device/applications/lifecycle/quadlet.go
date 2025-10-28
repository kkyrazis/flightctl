package lifecycle

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/flightctl/flightctl/internal/agent/client"
	"github.com/flightctl/flightctl/internal/agent/device/fileio"
	"github.com/flightctl/flightctl/pkg/log"
	"gopkg.in/ini.v1"
)

const (
	QuadletAppPath         = "/etc/containers/systemd"
	EmbeddedQuadletAppPath = "/usr/local/etc/containers/systemd"
)

var _ ActionHandler = (*Quadlet)(nil)

type Quadlet struct {
	systemd *client.Systemd
	rw      fileio.ReadWriter
	log     *log.PrefixLogger
}

func NewQuadlet(log *log.PrefixLogger, rw fileio.ReadWriter, systemd *client.Systemd) *Quadlet {
	return &Quadlet{
		systemd: systemd,
		rw:      rw,
		log:     log,
	}
}

func (q *Quadlet) add(ctx context.Context, action *Action) error {
	appName := action.Name
	q.log.Debugf("Starting quadlet application: %s path: %s", appName, action.Path)

	if err := q.systemd.DaemonReload(ctx); err != nil {
		return fmt.Errorf("daemon reload: %w", err)
	}

	services, err := q.collectTargets(action.Path)
	if err != nil {
		return fmt.Errorf("collecting targets: %w", err)
	}

	if err := q.systemd.EnableMany(ctx, services, client.WithEnableNow()); err != nil {
		return fmt.Errorf("starting service %s: %w", strings.Join(services, ","), err)
	}

	q.log.Infof("Started quadlet application: %s", appName)
	return nil
}

// remove disables and reloads the systemd services associated with the specified application
// note, the current state of the application directory can't be used as it has likely been modified already.
func (q *Quadlet) remove(ctx context.Context, action *Action) error {
	appName := action.Name
	q.log.Debugf("Removing quadlet application: %s", appName)

	// TODO this will need to be based on whatever we namespace with. Will be fleshed out once that is implemented
	servicesMatch := fmt.Sprintf("%s*", action.ID)
	units, err := q.systemd.ListUnitsByMatchPattern(ctx, []string{servicesMatch})
	if err != nil {
		return fmt.Errorf("listing units: %w", err)
	}

	unitNames := make([]string, 0, len(units))
	for _, unit := range units {
		unitNames = append(unitNames, unit.Unit)
	}

	err = q.systemd.DisableMany(ctx, unitNames, client.WithDisableNow())
	if err != nil {
		return fmt.Errorf("stopping service(s) %s: %w", strings.Join(unitNames, ","), err)
	}

	if err := q.systemd.DaemonReload(ctx); err != nil {
		return fmt.Errorf("daemon reload: %w", err)
	}

	q.log.Infof("Removed quadlet application: %s", appName)
	return nil
}

// update is just a combination of disabling the existing units and then starting the new ones based on the current state
func (q *Quadlet) update(ctx context.Context, action *Action) error {
	if err := q.remove(ctx, action); err != nil {
		return fmt.Errorf("removing app: %q: %w", action.Name, err)
	}
	if err := q.add(ctx, action); err != nil {
		return fmt.Errorf("adding app: %q: %w", action.Name, err)
	}
	return nil
}

func (q *Quadlet) Execute(ctx context.Context, action *Action) error {
	switch action.Type {
	case ActionAdd:
		return q.add(ctx, action)
	case ActionRemove:
		return q.remove(ctx, action)
	case ActionUpdate:
		return q.update(ctx, action)
	default:
		return fmt.Errorf("unsupported action type: %s", action.Type)
	}
}

func (q *Quadlet) serviceName(file string, quadletSection string, defaultName string) (string, error) {
	contents, err := q.rw.ReadFile(file)
	if err != nil {
		return "", fmt.Errorf("reading quadlet %s: %w", file, err)
	}
	quad, err := ini.Load(contents)
	if err != nil {
		return "", fmt.Errorf("parsing quadlet %s: %w", file, err)
	}
	section, err := quad.GetSection(quadletSection)
	if err != nil {
		return "", fmt.Errorf("missing section %s: %w", quadletSection, err)
	}
	if section.HasKey("ServiceName") {
		return section.Key("ServiceName").String(), nil
	}
	return defaultName, nil
}

func (q *Quadlet) collectTargets(path string) ([]string, error) {
	entries, err := q.rw.ReadDir(path)
	if err != nil {
		return nil, fmt.Errorf("reading directory: %w", err)
	}

	var services []string
	var targets []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		filename := entry.Name()
		ext := filepath.Ext(filename)
		baseName := strings.TrimSuffix(filename, ext)

		var serviceName string
		switch ext {
		case ".container":
			serviceName = baseName + ".service"
		case ".pod":
			serviceName, err = q.serviceName(entry.Name(), "Pod", fmt.Sprintf("%s-pod.service", baseName))
			if err != nil {
				return nil, fmt.Errorf("getting %s service name: %w", filename, err)
			}
		case ".target":
			targets = append(targets, filename)
			continue
		default:
			continue
		}

		services = append(services, serviceName)
	}

	// ensure that targets are processed first and services are
	// secondary.
	return append(targets, services...), nil
}
