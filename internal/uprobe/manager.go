package uprobe

import (
	"context"
	"debug/elf"
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

type ProbeProgram struct {
	Uprobe    *ebpf.Program
	Uretprobe *ebpf.Program
}

type ProbeRegistry map[string]map[string]ProbeProgram

type Manager struct {
	mu              sync.RWMutex
	procFS          procfs.FS
	procPath        string
	registry        ProbeRegistry
	attachments     map[int]*ProcessAttachment
	cleanupInterval time.Duration
}

type ProcessAttachment struct {
	PID        int
	Links      []link.Link
	AttachedAt time.Time
}

func NewManager(procPath string, cleanupInterval time.Duration, registry ProbeRegistry) (*Manager, error) {
	fs, err := procfs.NewFS(procPath)
	if err != nil {
		return nil, fmt.Errorf("create procfs: %w", err)
	}

	return &Manager{
		procFS:          fs,
		procPath:        procPath,
		registry:        registry,
		attachments:     make(map[int]*ProcessAttachment),
		cleanupInterval: cleanupInterval,
	}, nil
}

func (m *Manager) HandleExec(pid int) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.attachments[pid]; exists {
		slog.Debug("pid already has uprobe attached", "pid", pid)
		return nil
	}

	exePath := fmt.Sprintf("%s/%d/exe", m.procPath, pid)

	file, err := elf.Open(exePath)
	if err != nil {
		return fmt.Errorf("open exe: %w", err)
	}
	defer file.Close()

	isGo := false
	for _, section := range file.Sections {
		if section.Name == ".gopclntab" {
			isGo = true
			break
		}
	}

	if !isGo {
		return fmt.Errorf("not a Go binary")
	}

	symbols, err := file.Symbols()
	if err != nil {
		symbols, _ = file.DynamicSymbols()
	}

	if symbols == nil {
		return fmt.Errorf("no symbols found")
	}

	libpqSymbol := "github.com/lib/pq.(*conn).query"
	found := false
	for _, sym := range symbols {
		if sym.Name == libpqSymbol {
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("lib/pq not found in Go binary")
	}

	slog.Info("detected Go binary with lib/pq", "pid", pid, "path", exePath)
	library := "lib/pq"
	symbol := libpqSymbol
	targetPath := exePath

	symbolMap, ok := m.registry[library]
	if !ok {
		return fmt.Errorf("no probes registered for library %s", library)
	}

	programs, ok := symbolMap[symbol]
	if !ok {
		return fmt.Errorf("no probes registered for symbol %s in library %s", symbol, library)
	}

	ex, err := link.OpenExecutable(targetPath)
	if err != nil {
		return fmt.Errorf("open executable %s: %w", targetPath, err)
	}

	var links []link.Link

	if programs.Uprobe != nil {
		l, err := ex.Uprobe(symbol, programs.Uprobe, nil)
		if err != nil {
			slog.Warn("failed to attach uprobe",
				"pid", pid,
				"path", targetPath,
				"symbol", symbol,
				"error", err)
			return fmt.Errorf("failed to attach uprobe: %w", err)
		}
		links = append(links, l)
		slog.Debug("attached uprobe",
			"pid", pid,
			"path", targetPath,
			"symbol", symbol)

		if programs.Uretprobe != nil {
			l, err := ex.Uretprobe(symbol, programs.Uretprobe, nil)
			if err != nil {
				slog.Warn("failed to attach uretprobe, cleaning up",
					"pid", pid,
					"path", targetPath,
					"symbol", symbol,
					"error", err)
				for _, link := range links {
					link.Close()
				}
				return fmt.Errorf("failed to attach uretprobe: %w", err)
			}
			links = append(links, l)
			slog.Debug("attached uretprobe",
				"pid", pid,
				"path", targetPath,
				"symbol", symbol)
		}
	}

	if len(links) == 0 {
		return fmt.Errorf("no probes attached for pid %d", pid)
	}

	m.attachments[pid] = &ProcessAttachment{
		PID:        pid,
		Links:      links,
		AttachedAt: time.Now(),
	}

	slog.Info("attached probes",
		"pid", pid,
		"library", library,
		"symbol", symbol,
		"count", len(links))
	return nil
}

func (m *Manager) HandleLibraryLoad(pid int, libraryName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.attachments[pid]; exists {
		slog.Debug("pid already has uprobe attached", "pid", pid)
		return nil
	}

	if !strings.HasPrefix(libraryName, "libpq") {
		return fmt.Errorf("not a libpq library: %s", libraryName)
	}

	proc, err := m.procFS.Proc(pid)
	if err != nil {
		return fmt.Errorf("get proc %d: %w", pid, err)
	}

	maps, err := proc.ProcMaps()
	if err != nil {
		return fmt.Errorf("read maps for pid %d: %w", pid, err)
	}

	var targetPath string
	for _, mapping := range maps {
		if mapping.Pathname == "" {
			continue
		}

		basename := filepath.Base(mapping.Pathname)
		if strings.HasPrefix(basename, "libpq") {
			targetPath = mapping.Pathname
			slog.Info("found native libpq", "pid", pid, "path", targetPath)
			break
		}
	}

	if targetPath == "" {
		return fmt.Errorf("libpq not found in pid %d maps", pid)
	}

	library := "libpq"
	symbol := "PQsendQuery"

	symbolMap, ok := m.registry[library]
	if !ok {
		return fmt.Errorf("no probes registered for library %s", library)
	}

	programs, ok := symbolMap[symbol]
	if !ok {
		return fmt.Errorf("no probes registered for symbol %s in library %s", symbol, library)
	}

	ex, err := link.OpenExecutable(targetPath)
	if err != nil {
		return fmt.Errorf("open executable %s: %w", targetPath, err)
	}

	var links []link.Link

	if programs.Uprobe != nil {
		l, err := ex.Uprobe(symbol, programs.Uprobe, nil)
		if err != nil {
			slog.Warn("failed to attach uprobe",
				"pid", pid,
				"path", targetPath,
				"symbol", symbol,
				"error", err)
			return fmt.Errorf("failed to attach uprobe: %w", err)
		}
		links = append(links, l)
		slog.Debug("attached uprobe",
			"pid", pid,
			"path", targetPath,
			"symbol", symbol)

		if programs.Uretprobe != nil {
			l, err := ex.Uretprobe(symbol, programs.Uretprobe, nil)
			if err != nil {
				slog.Warn("failed to attach uretprobe, cleaning up",
					"pid", pid,
					"path", targetPath,
					"symbol", symbol,
					"error", err)
				for _, link := range links {
					link.Close()
				}
				return fmt.Errorf("failed to attach uretprobe: %w", err)
			}
			links = append(links, l)
			slog.Debug("attached uretprobe",
				"pid", pid,
				"path", targetPath,
				"symbol", symbol)
		}
	}

	if len(links) == 0 {
		return fmt.Errorf("no probes attached for pid %d", pid)
	}

	m.attachments[pid] = &ProcessAttachment{
		PID:        pid,
		Links:      links,
		AttachedAt: time.Now(),
	}

	slog.Info("attached libpq probes",
		"pid", pid,
		"library", library,
		"symbol", symbol,
		"count", len(links))
	return nil
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
