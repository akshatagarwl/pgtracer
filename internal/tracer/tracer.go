package tracer

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"runtime"

	"github.com/akshatagarwl/pgtracer/internal/bpf"
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
	useRingBuf bool
	link       link.Link
	reader     EventReader
	objs       BpfObjects
}

func New(usePerfBuf bool) (*Tracer, error) {
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

	t := &Tracer{useRingBuf: useRingBuf}

	if useRingBuf {
		ringObjs := &bpf.BpfRingbufObjects{}
		if err := bpf.LoadBpfRingbufObjects(ringObjs, nil); err != nil {
			return nil, fmt.Errorf("load ringbuf objects: %w", err)
		}
		t.objs = ringObjs

		l, err := link.Kprobe("sys_openat", ringObjs.KprobeOpenat, nil)
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

		l, err := link.Kprobe("sys_openat", perfObjs.KprobeOpenat, nil)
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

	return t, nil
}

func (t *Tracer) Run() error {
	slog.Info("tracing openat syscalls", "message", "press ctrl+c to stop")

	for {
		rawSample, err := t.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) || errors.Is(err, perf.ErrClosed) {
				return nil
			}
			slog.Error("reading event", "error", err)
			continue
		}

		var event bpf.BpfEvent
		if err := binary.Read(bytes.NewBuffer(rawSample), binary.LittleEndian, &event); err != nil {
			slog.Error("parsing event", "error", err)
			continue
		}

		comm := unix.ByteSliceToString(event.Comm[:])

		slog.Info("syscall event",
			"tgid", event.Tgid,
			"uid", event.Uid,
			"comm", comm,
		)
	}
}

func (t *Tracer) Close() error {
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
