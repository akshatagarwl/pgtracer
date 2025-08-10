#pragma once

static __always_inline u32 extract_pid(u64 pid_tgid) {
  return pid_tgid & 0xFFFFFFFF;
}

static __always_inline u32 extract_tgid(u64 pid_tgid) { return pid_tgid >> 32; }

static __always_inline u32 extract_uid(u64 uid_gid) {
  return uid_gid & 0xFFFFFFFF;
}

static __always_inline u32 extract_gid(u64 uid_gid) { return uid_gid >> 32; }

static __always_inline struct event *reserve_event(void) {
#ifdef USE_RING_BUF
  return bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
#else
  u32 zero = 0;
  return bpf_map_lookup_elem(&event_heap, &zero);
#endif
}

static __always_inline void send_event(void *ctx, struct event *e) {
#ifdef USE_RING_BUF
  bpf_ringbuf_submit(e, 0);
#else
  bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, e,
                        sizeof(struct event));
#endif
}
