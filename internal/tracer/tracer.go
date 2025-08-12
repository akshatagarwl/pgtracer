package tracer

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"runtime"
	"time"

	"github.com/akshatagarwl/pgtracer/internal/bpf"
	"github.com/akshatagarwl/pgtracer/internal/uprobe"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

type EventReader interface {
	Read() ([]byte, error)
	Close() error
}

type ringBufReader struct {
	*ringbuf.Reader
}

func (r *ringBufReader) Read() ([]byte, error) {
	record, err := r.Reader.Read()
	if err != nil {
		return nil, err
	}
	return record.RawSample, nil
}

type perfBufReader struct {
	*perf.Reader
}

func (p *perfBufReader) Read() ([]byte, error) {
	for {
		record, err := p.Reader.Read()
		if err != nil {
			return nil, err
		}
		if record.LostSamples > 0 {
			slog.Warn("lost samples", "count", record.LostSamples)
			continue
		}
		return record.RawSample, nil
	}
}

type BpfObjects interface {
	Close() error
}

type BpfPrograms struct {
	TracePqsendquery    *ebpf.Program
	TracePqsendqueryRet *ebpf.Program
	TraceGoPqQuery      *ebpf.Program
	TraceGoPqQueryRet   *ebpf.Program
	KprobeFileOpen      *ebpf.Program
	TraceExecveExit     *ebpf.Program
	Events              *ebpf.Map
}

type Tracer struct {
	useRingBuf    bool
	links         []link.Link
	reader        EventReader
	objs          BpfObjects
	uprobeManager *uprobe.Manager
}

func New(usePerfBuf bool, procPath string, cleanupInterval time.Duration) (*Tracer, error) {
	slog.Info("initializing tracer")

	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock: %w", err)
	}

	useRingBuf := !usePerfBuf && features.HaveMapType(ebpf.RingBuf) == nil

	slog.Info("loading ebpf",
		"architecture", runtime.GOARCH,
		"use_ring_buffer", useRingBuf)

	t := &Tracer{
		useRingBuf: useRingBuf,
	}

	programs, err := t.loadBpfObjects(useRingBuf)
	if err != nil {
		return nil, err
	}

	registry := uprobe.ProbeRegistry{
		"libpq": {
			"PQsendQuery": uprobe.ProbeProgram{
				Uprobe:    programs.TracePqsendquery,
				Uretprobe: programs.TracePqsendqueryRet,
			},
		},
		"lib/pq": {
			"github.com/lib/pq.(*conn).query": uprobe.ProbeProgram{
				Uprobe:    programs.TraceGoPqQuery,
				Uretprobe: programs.TraceGoPqQueryRet,
			},
		},
	}

	if err := t.attachKernelProbes(programs); err != nil {
		t.Close()
		return nil, err
	}

	if err := t.createEventReader(useRingBuf, programs.Events); err != nil {
		t.Close()
		return nil, err
	}

	uprobeManager, err := uprobe.NewManager(procPath, cleanupInterval, registry)
	if err != nil {
		t.Close()
		return nil, fmt.Errorf("create uprobe manager: %w", err)
	}
	t.uprobeManager = uprobeManager

	return t, nil
}

func (t *Tracer) loadBpfObjects(useRingBuf bool) (*BpfPrograms, error) {
	if useRingBuf {
		ringObjs := &bpf.BpfRingbufObjects{}
		if err := bpf.LoadBpfRingbufObjects(ringObjs, nil); err != nil {
			return nil, fmt.Errorf("load ringbuf objects: %w", err)
		}
		t.objs = ringObjs
		return &BpfPrograms{
			TracePqsendquery:    ringObjs.TracePqsendquery,
			TracePqsendqueryRet: ringObjs.TracePqsendqueryRet,
			TraceGoPqQuery:      ringObjs.TraceGoPqQuery,
			TraceGoPqQueryRet:   ringObjs.TraceGoPqQueryRet,
			KprobeFileOpen:      ringObjs.KprobeFileOpen,
			TraceExecveExit:     ringObjs.TraceExecveExit,
			Events:              ringObjs.Events,
		}, nil
	}

	perfObjs := &bpf.BpfPerfbufObjects{}
	if err := bpf.LoadBpfPerfbufObjects(perfObjs, nil); err != nil {
		return nil, fmt.Errorf("load perfbuf objects: %w", err)
	}
	t.objs = perfObjs
	return &BpfPrograms{
		TracePqsendquery:    perfObjs.TracePqsendquery,
		TracePqsendqueryRet: perfObjs.TracePqsendqueryRet,
		TraceGoPqQuery:      perfObjs.TraceGoPqQuery,
		TraceGoPqQueryRet:   perfObjs.TraceGoPqQueryRet,
		KprobeFileOpen:      perfObjs.KprobeFileOpen,
		TraceExecveExit:     perfObjs.TraceExecveExit,
		Events:              perfObjs.Events,
	}, nil
}

func (t *Tracer) attachKernelProbes(programs *BpfPrograms) error {
	slog.Info("attaching kernel probes")

	kprobeLink, err := link.Kprobe("do_dentry_open", programs.KprobeFileOpen, nil)
	if err != nil {
		return fmt.Errorf("attach kprobe: %w", err)
	}
	t.links = append(t.links, kprobeLink)
	slog.Info("attached kprobe for do_dentry_open")

	execLink, err := link.Tracepoint("syscalls", "sys_exit_execve", programs.TraceExecveExit, nil)
	if err != nil {
		return fmt.Errorf("attach execve tracepoint: %w", err)
	}
	t.links = append(t.links, execLink)
	slog.Info("attached execve tracepoint")

	return nil
}

func (t *Tracer) createEventReader(useRingBuf bool, eventsMap *ebpf.Map) error {
	if useRingBuf {
		rd, err := ringbuf.NewReader(eventsMap)
		if err != nil {
			return fmt.Errorf("new ringbuf reader: %w", err)
		}
		t.reader = &ringBufReader{rd}
	} else {
		rd, err := perf.NewReader(eventsMap, 4096)
		if err != nil {
			return fmt.Errorf("new perf reader: %w", err)
		}
		t.reader = &perfBufReader{rd}
	}
	return nil
}

func (t *Tracer) Run() error {
	slog.Info("tracing events", "message", "press ctrl+c to stop")

	for {
		rawSample, err := t.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) || errors.Is(err, perf.ErrClosed) {
				return nil
			}
			slog.Error("reading event", "error", err)
			continue
		}

		if len(rawSample) < 4 {
			slog.Error("event too small", "size", len(rawSample))
			continue
		}

		eventType := binary.LittleEndian.Uint32(rawSample[:4])

		slog.Debug("received event", "type", eventType)

		switch bpf.BpfEventType(eventType) {
		case bpf.BpfEventTypeEVENT_TYPE_LIBRARY_LOAD:
			t.handleLibraryLoadEvent(rawSample)

		case bpf.BpfEventTypeEVENT_TYPE_POSTGRES_QUERY:
			t.handlePostgresQueryEvent(rawSample)

		case bpf.BpfEventTypeEVENT_TYPE_GO_POSTGRES_QUERY:
			t.handleGoPostgresQueryEvent(rawSample)

		case bpf.BpfEventTypeEVENT_TYPE_EXEC:
			t.handleExecEvent(rawSample)

		default:
			slog.Warn("unknown event type", "type", eventType)
		}
	}
}

func (t *Tracer) handleLibraryLoadEvent(rawSample []byte) {
	var event bpf.BpfLibraryLoadEvent
	if err := binary.Read(bytes.NewBuffer(rawSample), binary.LittleEndian, &event); err != nil {
		slog.Error("parsing library load event", "error", err)
		return
	}
	comm := unix.ByteSliceToString(event.Header.Comm[:])
	libName := unix.ByteSliceToString(event.LibraryName[:])
	slog.Info("library loaded",
		"pid", event.Header.Pid,
		"tgid", event.Header.Tgid,
		"comm", comm,
		"library", libName,
	)

	if err := t.uprobeManager.HandleLibraryLoad(int(event.Header.Pid), libName); err != nil {
		slog.Debug("uprobe attachment skipped",
			"pid", event.Header.Pid,
			"library", libName,
			"reason", err)
	}
}

func (t *Tracer) handlePostgresQueryEvent(rawSample []byte) {
	var event bpf.BpfPostgresQueryEvent
	if err := binary.Read(bytes.NewBuffer(rawSample), binary.LittleEndian, &event); err != nil {
		slog.Error("parsing postgres query event", "error", err)
		return
	}
	comm := unix.ByteSliceToString(event.Header.Comm[:])
	query := unix.ByteSliceToString(event.Query[:])
	slog.Info("postgres query",
		"pid", event.Header.Pid,
		"tgid", event.Header.Tgid,
		"comm", comm,
		"conn", fmt.Sprintf("0x%x", event.ConnPtr),
		"query", query,
	)
}

func (t *Tracer) handleGoPostgresQueryEvent(rawSample []byte) {
	var event bpf.BpfGoPostgresQueryEvent
	if err := binary.Read(bytes.NewBuffer(rawSample), binary.LittleEndian, &event); err != nil {
		slog.Error("parsing go postgres query event", "error", err)
		return
	}
	comm := unix.ByteSliceToString(event.Header.Comm[:])
	query := unix.ByteSliceToString(event.Query[:])
	slog.Info("go postgres query",
		"pid", event.Header.Pid,
		"tgid", event.Header.Tgid,
		"comm", comm,
		"conn", fmt.Sprintf("0x%x", event.ConnPtr),
		"query", query,
		"query_len", event.QueryLen,
		"source", "lib/pq",
	)
}

func (t *Tracer) handleExecEvent(rawSample []byte) {
	var event bpf.BpfExecEvent
	if err := binary.Read(bytes.NewBuffer(rawSample), binary.LittleEndian, &event); err != nil {
		slog.Error("parsing exec event", "error", err)
		return
	}
	comm := unix.ByteSliceToString(event.Header.Comm[:])
	slog.Debug("exec event received",
		"pid", event.Header.Pid,
		"tgid", event.Header.Tgid,
		"comm", comm,
	)

	if err := t.uprobeManager.HandleExec(int(event.Header.Pid)); err != nil {
		slog.Debug("exec handler skipped",
			"pid", event.Header.Pid,
			"comm", comm,
			"reason", err)
	}
}

func (t *Tracer) StartCleanupService(ctx context.Context) {
	if t.uprobeManager != nil {
		t.uprobeManager.StartCleanupService(ctx)
	}
}

func (t *Tracer) Close() error {
	if t.uprobeManager != nil {
		t.uprobeManager.Close()
	}
	if t.reader != nil {
		t.reader.Close()
	}
	for _, l := range t.links {
		if l != nil {
			l.Close()
		}
	}
	if t.objs != nil {
		t.objs.Close()
	}
	return nil
}
