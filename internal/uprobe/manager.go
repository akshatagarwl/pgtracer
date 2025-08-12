package uprobe

import (
	"context"
	"debug/elf"
	"debug/gosym"
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

func findGoFunctionsFromPclntab(file *elf.File) (map[string]uint64, error) {
	pclntabSection := file.Section(".gopclntab")
	if pclntabSection == nil {
		return nil, fmt.Errorf("no .gopclntab section found")
	}

	pclntabData, err := pclntabSection.Data()
	if err != nil {
		return nil, fmt.Errorf("read .gopclntab: %w", err)
	}

	textSection := file.Section(".text")
	if textSection == nil {
		return nil, fmt.Errorf("no .text section found")
	}

	lineTable := gosym.NewLineTable(pclntabData, textSection.Addr)
	symTable, err := gosym.NewTable(nil, lineTable)
	if err != nil {
		return nil, fmt.Errorf("create symbol table from gopclntab: %w", err)
	}

	functions := make(map[string]uint64)
	for _, fn := range symTable.Funcs {
		functions[fn.Name] = fn.Entry
	}

	return functions, nil
}

func (m *Manager) HandleExec(pid int) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	exePath := fmt.Sprintf("%s/%d/exe", m.procPath, pid)
	slog.Debug("handling exec event", "pid", pid, "path", exePath)

	file, err := elf.Open(exePath)
	if err != nil {
		slog.Debug("failed to open exe", "pid", pid, "error", err)
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
		slog.Debug("not a Go binary", "pid", pid)
		return fmt.Errorf("not a Go binary")
	}

	slog.Debug("detected Go binary", "pid", pid)

	libpqSymbol := "github.com/lib/pq.(*conn).query"
	found := false
	var symbolOffset uint64

	symbols, err := file.Symbols()
	if err != nil {
		slog.Debug("no symbols in symbol table", "pid", pid, "error", err)
		symbols, _ = file.DynamicSymbols()
	}

	if symbols != nil {
		slog.Debug("checking symbols", "pid", pid, "count", len(symbols))
		for _, sym := range symbols {
			if sym.Name == libpqSymbol {
				found = true
				slog.Debug("found lib/pq in symbols", "pid", pid)
				break
			}
		}
	}

	if !found {
		slog.Debug("symbols not found in symbol table, trying gopclntab", "pid", pid)
		functions, err := findGoFunctionsFromPclntab(file)
		if err != nil {
			slog.Debug("failed to parse gopclntab", "pid", pid, "error", err)
			return fmt.Errorf("failed to parse gopclntab: %w", err)
		}

		slog.Debug("parsed gopclntab", "pid", pid, "functions", len(functions))

		if addr, ok := functions[libpqSymbol]; ok {
			found = true
			textSection := file.Section(".text")
			if textSection != nil {
				symbolOffset = addr - textSection.Addr + textSection.Offset
				slog.Debug("found lib/pq in gopclntab",
					"pid", pid,
					"addr", fmt.Sprintf("0x%x", addr),
					"text_addr", fmt.Sprintf("0x%x", textSection.Addr),
					"text_offset", fmt.Sprintf("0x%x", textSection.Offset),
					"final_offset", fmt.Sprintf("0x%x", symbolOffset))
			}
		} else {
			slog.Debug("lib/pq not found in gopclntab", "pid", pid)
		}
	}

	if !found {
		slog.Debug("lib/pq not found in binary", "pid", pid)
		return fmt.Errorf("lib/pq not found in Go binary")
	}

	if symbolOffset > 0 {
		slog.Debug("detected stripped Go binary with lib/pq",
			"pid", pid,
			"path", exePath,
			"offset", fmt.Sprintf("0x%x", symbolOffset))
	} else {
		slog.Debug("detected Go binary with lib/pq", "pid", pid, "path", exePath)
	}

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
		var l link.Link
		var err error

		if symbolOffset > 0 {
			opts := &link.UprobeOptions{
				Address: symbolOffset,
			}
			l, err = ex.Uprobe("", programs.Uprobe, opts)
		} else {
			l, err = ex.Uprobe(symbol, programs.Uprobe, nil)
		}

		if err != nil {
			slog.Debug("failed to attach uprobe",
				"pid", pid,
				"path", targetPath,
				"symbol", symbol,
				"offset", fmt.Sprintf("0x%x", symbolOffset),
				"error", err)
			return fmt.Errorf("failed to attach uprobe: %w", err)
		}
		links = append(links, l)
		slog.Debug("attached uprobe",
			"pid", pid,
			"path", targetPath,
			"symbol", symbol,
			"offset", fmt.Sprintf("0x%x", symbolOffset))

		if programs.Uretprobe != nil {
			if symbolOffset > 0 {
				opts := &link.UprobeOptions{
					Address: symbolOffset,
				}
				l, err = ex.Uretprobe("", programs.Uretprobe, opts)
			} else {
				l, err = ex.Uretprobe(symbol, programs.Uretprobe, nil)
			}

			if err != nil {
				slog.Debug("failed to attach uretprobe, cleaning up",
					"pid", pid,
					"path", targetPath,
					"symbol", symbol,
					"offset", fmt.Sprintf("0x%x", symbolOffset),
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
				"symbol", symbol,
				"offset", fmt.Sprintf("0x%x", symbolOffset))
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

	slog.Debug("attached probes",
		"pid", pid,
		"library", library,
		"symbol", symbol,
		"count", len(links))
	return nil
}

func (m *Manager) HandleLibraryLoad(pid int, libraryName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

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

	var links []link.Link
	for _, mapping := range maps {
		if mapping.Pathname == "" {
			continue
		}

		basename := filepath.Base(mapping.Pathname)
		if strings.HasPrefix(basename, "libpq") {
			targetPath := fmt.Sprintf("%s/%d/map_files/%x-%x", m.procPath, pid, mapping.StartAddr, mapping.EndAddr)
			slog.Debug("found native libpq", "pid", pid, "path", targetPath)

			ex, err := link.OpenExecutable(targetPath)
			if err != nil {
				slog.Debug("failed to open executable", "target_path", targetPath, "error", err)
				continue
			}

			if programs.Uprobe != nil {
				l, err := ex.Uprobe(symbol, programs.Uprobe, nil)
				if err != nil {
					slog.Debug("failed to attach uprobe",
						"pid", pid,
						"path", targetPath,
						"symbol", symbol,
						"error", err)
					slog.Debug("failed to attach uprobe", "error", err)
					continue
				}
				links = append(links, l)
				slog.Debug("attached uprobe",
					"pid", pid,
					"path", targetPath,
					"symbol", symbol)

				if programs.Uretprobe != nil {
					l, err := ex.Uretprobe(symbol, programs.Uretprobe, nil)
					if err != nil {
						slog.Debug("failed to attach uretprobe, cleaning up",
							"pid", pid,
							"path", targetPath,
							"symbol", symbol,
							"error", err)
						for _, link := range links {
							link.Close()
						}
						slog.Debug("failed to attach uretprobe", "error", err)
						continue
					}
					links = append(links, l)
					slog.Debug("attached uretprobe",
						"pid", pid,
						"path", targetPath,
						"symbol", symbol)
				}
			}
		}
	}

	m.attachments[pid] = &ProcessAttachment{
		PID:        pid,
		Links:      links,
		AttachedAt: time.Now(),
	}

	if len(links) == 0 {
		slog.Debug("no probes attached for pid", "pid", pid)
	}

	slog.Debug("attached libpq probes",
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
					slog.Debug("failed to close probe",
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
