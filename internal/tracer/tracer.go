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

type Tracer struct {
	useRingBuf    bool
	link          link.Link
	reader        EventReader
	objs          BpfObjects
	uprobeManager *uprobe.Manager
}

func New(usePerfBuf bool, procPath string, cleanupInterval time.Duration) (*Tracer, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock: %w", err)
	}

	kernelSupportsRingBuf := features.HaveMapType(ebpf.RingBuf) == nil

	useRingBuf := kernelSupportsRingBuf && !usePerfBuf

	if !kernelSupportsRingBuf && !usePerfBuf {
		slog.Info("ring buffer not supported by kernel, using perf buffer")
		useRingBuf = false
	}

	slog.Info("loading ebpf",
		"architecture", runtime.GOARCH,
		"use_ring_buffer", useRingBuf,
		"kernel_supports_ring_buf", kernelSupportsRingBuf,
		"user_requested_perf_buf", usePerfBuf)

	t := &Tracer{
		useRingBuf: useRingBuf,
	}

	var probeSpecs []uprobe.ProbeSpec

	if useRingBuf {
		ringObjs := &bpf.BpfRingbufObjects{}
		if err := bpf.LoadBpfRingbufObjects(ringObjs, nil); err != nil {
			return nil, fmt.Errorf("load ringbuf objects: %w", err)
		}
		t.objs = ringObjs

		probeSpecs = []uprobe.ProbeSpec{
			{
				Name:    "PQsendQuery_uprobe",
				Symbol:  "PQsendQuery",
				Type:    uprobe.Uprobe,
				Program: ringObjs.TracePqsendquery,
			},
			{
				Name:    "PQsendQuery_uretprobe",
				Symbol:  "PQsendQuery",
				Type:    uprobe.Uretprobe,
				Program: ringObjs.TracePqsendqueryRet,
			},
		}

		l, err := link.Kprobe("do_dentry_open", ringObjs.KprobeFileOpen, nil)
		if err != nil {
			ringObjs.Close()
			return nil, fmt.Errorf("attach kprobe: %w", err)
		}
		t.link = l

		rd, err := ringbuf.NewReader(ringObjs.Events)
		if err != nil {
			l.Close()
			ringObjs.Close()
			return nil, fmt.Errorf("new ringbuf reader: %w", err)
		}
		t.reader = &ringBufReader{rd}
	} else {
		perfObjs := &bpf.BpfPerfbufObjects{}
		if err := bpf.LoadBpfPerfbufObjects(perfObjs, nil); err != nil {
			return nil, fmt.Errorf("load perfbuf objects: %w", err)
		}
		t.objs = perfObjs

		probeSpecs = []uprobe.ProbeSpec{
			{
				Name:    "PQsendQuery_uprobe",
				Symbol:  "PQsendQuery",
				Type:    uprobe.Uprobe,
				Program: perfObjs.TracePqsendquery,
			},
			{
				Name:    "PQsendQuery_uretprobe",
				Symbol:  "PQsendQuery",
				Type:    uprobe.Uretprobe,
				Program: perfObjs.TracePqsendqueryRet,
			},
		}

		l, err := link.Kprobe("do_dentry_open", perfObjs.KprobeFileOpen, nil)
		if err != nil {
			perfObjs.Close()
			return nil, fmt.Errorf("attach kprobe: %w", err)
		}
		t.link = l

		rd, err := perf.NewReader(perfObjs.Events, 4096)
		if err != nil {
			l.Close()
			perfObjs.Close()
			return nil, fmt.Errorf("new perf reader: %w", err)
		}
		t.reader = &perfBufReader{rd}
	}

	uprobeManager, err := uprobe.NewManager(procPath, cleanupInterval, probeSpecs)
	if err != nil {
		t.Close()
		return nil, fmt.Errorf("create uprobe manager: %w", err)
	}
	t.uprobeManager = uprobeManager

	return t, nil
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

		switch bpf.BpfEventType(eventType) {
		case bpf.BpfEventTypeEVENT_TYPE_LIBRARY_LOAD:
			var event bpf.BpfLibraryLoadEvent
			if err := binary.Read(bytes.NewBuffer(rawSample), binary.LittleEndian, &event); err != nil {
				slog.Error("parsing library load event", "error", err)
				continue
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

		case bpf.BpfEventTypeEVENT_TYPE_POSTGRES_QUERY:
			var event bpf.BpfPostgresQueryEvent
			if err := binary.Read(bytes.NewBuffer(rawSample), binary.LittleEndian, &event); err != nil {
				slog.Error("parsing postgres query event", "error", err)
				continue
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

		default:
			slog.Warn("unknown event type", "type", eventType)
		}
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
	if t.link != nil {
		t.link.Close()
	}
	if t.objs != nil {
		t.objs.Close()
	}
	return nil
}
