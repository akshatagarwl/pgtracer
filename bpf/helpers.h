#pragma once

static __always_inline u32 extract_pid(u64 pid_tgid) {
  return pid_tgid & 0xFFFFFFFF;
}

static __always_inline u32 extract_tgid(u64 pid_tgid) { return pid_tgid >> 32; }

static __always_inline u32 extract_uid(u64 uid_gid) {
  return uid_gid & 0xFFFFFFFF;
}

static __always_inline u32 extract_gid(u64 uid_gid) { return uid_gid >> 32; }

static __always_inline struct openat_event *reserve_openat_event(void) {
#ifdef USE_RING_BUF
  return bpf_ringbuf_reserve(&events, sizeof(struct openat_event), 0);
#else
  u32 zero = 0;
  return bpf_map_lookup_elem(&openat_heap, &zero);
#endif
}

static __always_inline void send_openat_event(void *ctx,
                                              struct openat_event *e) {
#ifdef USE_RING_BUF
  bpf_ringbuf_submit(e, 0);
#else
  bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, e,
                        sizeof(struct openat_event));
#endif
}

static __always_inline void fill_event_header(struct trace_event_header *h,
                                              enum event_type type) {
  h->type = type;
  h->timestamp = bpf_ktime_get_ns();

  u64 pid_tgid = bpf_get_current_pid_tgid();
  h->pid = extract_pid(pid_tgid);
  h->tgid = extract_tgid(pid_tgid);

  bpf_get_current_comm(&h->comm, sizeof(h->comm));
}
