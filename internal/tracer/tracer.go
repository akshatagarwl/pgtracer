package tracer

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"runtime"

	"github.com/akshatagarwl/pgtracer/internal/bpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

type Tracer struct {
	objs   bpf.BpfObjects
	link   link.Link
	reader *ringbuf.Reader
}

func New() (*Tracer, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock: %w", err)
	}

	slog.Info("loading ebpf", "architecture", runtime.GOARCH)

	var objs bpf.BpfObjects
	if err := bpf.LoadBpfObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load objects: %w", err)
	}

	l, err := link.Kprobe("sys_openat", objs.KprobeOpenat, nil)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attach kprobe: %w", err)
	}

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		l.Close()
		objs.Close()
		return nil, fmt.Errorf("new ringbuf reader: %w", err)
	}

	return &Tracer{
		objs:   objs,
		link:   l,
		reader: rd,
	}, nil
}

func (t *Tracer) Run() error {
	slog.Info("tracing openat syscalls", "message", "press ctrl+c to stop")

	for {
		record, err := t.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			slog.Error("reading from ringbuf", "error", err)
			continue
		}

		var event bpf.BpfEvent
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
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
	t.objs.Close()
	return nil
}
