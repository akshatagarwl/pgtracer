package uprobe

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/prometheus/procfs"
)

type LibraryInfo struct {
	Path      string
	StartAddr string
	EndAddr   string
}

type ProbeType int

const (
	Uprobe ProbeType = iota
	Uretprobe
)

type ProbeSpec struct {
	Name    string
	Symbol  string
	Type    ProbeType
	Program *ebpf.Program
}

type Manager struct {
	mu              sync.RWMutex
	procFS          procfs.FS
	procPath        string
	probeSpecs      []ProbeSpec
	attachments     map[int]*ProcessAttachment
	cleanupInterval time.Duration
}

type ProcessAttachment struct {
	PID         int
	LibraryInfo *LibraryInfo
	Links       []link.Link
	AttachedAt  time.Time
}

func NewManager(procPath string, cleanupInterval time.Duration, probeSpecs []ProbeSpec) (*Manager, error) {
	fs, err := procfs.NewFS(procPath)
	if err != nil {
		return nil, fmt.Errorf("create procfs: %w", err)
	}

	return &Manager{
		procFS:          fs,
		procPath:        procPath,
		probeSpecs:      probeSpecs,
		attachments:     make(map[int]*ProcessAttachment),
		cleanupInterval: cleanupInterval,
	}, nil
}

func (m *Manager) HandleLibraryLoad(pid int, libraryName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.attachments[pid]; exists {
		slog.Debug("pid already has uprobe attached", "pid", pid)
		return nil
	}

	libInfo, err := m.findLibrary(pid, "libpq")
	if err != nil {
		return fmt.Errorf("find library: %w", err)
	}

	slog.Info("found libpq for pid",
		"pid", pid,
		"path", libInfo.Path,
		"start_addr", libInfo.StartAddr,
		"end_addr", libInfo.EndAddr)

	ex, err := link.OpenExecutable(libInfo.Path)
	if err != nil {
		return fmt.Errorf("open executable: %w", err)
	}

	var links []link.Link

	for _, spec := range m.probeSpecs {
		if spec.Program == nil {
			continue
		}

		var l link.Link
		var err error

		switch spec.Type {
		case Uprobe:
			l, err = ex.Uprobe(spec.Symbol, spec.Program, nil)
		case Uretprobe:
			l, err = ex.Uretprobe(spec.Symbol, spec.Program, nil)
		}

		if err != nil {
			slog.Warn("failed to attach probe",
				"name", spec.Name,
				"symbol", spec.Symbol,
				"type", spec.Type,
				"error", err)
		} else {
			links = append(links, l)
			slog.Debug("attached probe",
				"name", spec.Name,
				"symbol", spec.Symbol,
				"type", spec.Type)
		}
	}

	if len(links) == 0 {
		return fmt.Errorf("no probes could be attached")
	}

	m.attachments[pid] = &ProcessAttachment{
		PID:         pid,
		LibraryInfo: libInfo,
		Links:       links,
		AttachedAt:  time.Now(),
	}

	slog.Info("attached uprobe to library", "pid", pid, "library", libInfo.Path)
	return nil
}

func (m *Manager) findLibrary(pid int, libraryPrefix string) (*LibraryInfo, error) {
	proc, err := m.procFS.Proc(pid)
	if err != nil {
		return nil, fmt.Errorf("get proc %d: %w", pid, err)
	}

	maps, err := proc.ProcMaps()
	if err != nil {
		return nil, fmt.Errorf("read maps for pid %d: %w", pid, err)
	}

	for _, mapping := range maps {
		if mapping.Pathname == "" {
			continue
		}

		basename := filepath.Base(mapping.Pathname)
		if strings.HasPrefix(basename, libraryPrefix) {
			hostPath := fmt.Sprintf("%s/%d/root%s", m.procPath, pid, mapping.Pathname)

			if _, err := link.OpenExecutable(hostPath); err == nil {
				return &LibraryInfo{
					Path:      hostPath,
					StartAddr: fmt.Sprintf("0x%x", mapping.StartAddr),
					EndAddr:   fmt.Sprintf("0x%x", mapping.EndAddr),
				}, nil
			}

			return &LibraryInfo{
				Path:      mapping.Pathname,
				StartAddr: fmt.Sprintf("0x%x", mapping.StartAddr),
				EndAddr:   fmt.Sprintf("0x%x", mapping.EndAddr),
			}, nil
		}
	}

	return nil, fmt.Errorf("library %s not found in pid %d", libraryPrefix, pid)
}

func (m *Manager) processExists(pid int) bool {
	_, err := m.procFS.Proc(pid)
	return err == nil
}

func (m *Manager) StartCleanupService(ctx context.Context) {
	ticker := time.NewTicker(m.cleanupInterval)
	defer ticker.Stop()

	slog.Info("cleanup service started", "interval", m.cleanupInterval)

	for {
		select {
		case <-ctx.Done():
			slog.Info("cleanup service stopping")
			m.cleanupAll()
			return

		case <-ticker.C:
			m.performCleanup()
		}
	}
}

func (m *Manager) performCleanup() {
	m.mu.Lock()
	defer m.mu.Unlock()

	cleaned := 0

	for pid, attachment := range m.attachments {
		if !m.processExists(pid) {
			for _, link := range attachment.Links {
				if err := link.Close(); err != nil {
					slog.Error("failed to close probe",
						"pid", pid,
						"error", err)
				}
			}
			delete(m.attachments, pid)
			cleaned++
			slog.Debug("closed uprobe for dead process", "pid", pid)
		}
	}

	if cleaned > 0 {
		slog.Info("cleanup completed", "processes_cleaned", cleaned)
	}
}

func (m *Manager) cleanupAll() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for pid, attachment := range m.attachments {
		for _, link := range attachment.Links {
			link.Close()
		}
		slog.Info("closed uprobe", "pid", pid)
	}

	m.attachments = make(map[int]*ProcessAttachment)
	slog.Info("all uprobes cleaned up")
}

func (m *Manager) Close() error {
	m.cleanupAll()
	return nil
}
