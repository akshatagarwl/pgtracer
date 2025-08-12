#pragma once

static __always_inline u32 extract_pid(u64 pid_tgid) {
  return pid_tgid & 0xFFFFFFFF;
}

static __always_inline u32 extract_tgid(u64 pid_tgid) { return pid_tgid >> 32; }

static __always_inline u32 extract_uid(u64 uid_gid) {
  return uid_gid & 0xFFFFFFFF;
}

static __always_inline u32 extract_gid(u64 uid_gid) { return uid_gid >> 32; }

#ifdef __TARGET_ARCH_x86
#define GO_PARAM1(ctx) ((ctx)->ax)
#define GO_PARAM2(ctx) ((ctx)->bx)
#define GO_PARAM3(ctx) ((ctx)->cx)
#else
#define GO_PARAM1(ctx) PT_REGS_PARM1(ctx)
#define GO_PARAM2(ctx) PT_REGS_PARM2(ctx)
#define GO_PARAM3(ctx) PT_REGS_PARM3(ctx)
#endif

static __always_inline struct library_load_event *reserve_library_event(void) {
#ifdef USE_RING_BUF
  return bpf_ringbuf_reserve(&events, sizeof(struct library_load_event), 0);
#else
  u32 zero = 0;
  return bpf_map_lookup_elem(&library_heap, &zero);
#endif
}

static __always_inline void send_library_event(void *ctx,
                                               struct library_load_event *e) {
#ifdef USE_RING_BUF
  bpf_ringbuf_submit(e, 0);
#else
  bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, e,
                        sizeof(struct library_load_event));
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

static __always_inline struct postgres_query_event *reserve_query_event(void) {
#ifdef USE_RING_BUF
  return bpf_ringbuf_reserve(&events, sizeof(struct postgres_query_event), 0);
#else
  u32 zero = 0;
  return bpf_map_lookup_elem(&query_heap, &zero);
#endif
}

static __always_inline void send_query_event(void *ctx,
                                             struct postgres_query_event *e) {
#ifdef USE_RING_BUF
  bpf_ringbuf_submit(e, 0);
#else
  bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, e,
                        sizeof(struct postgres_query_event));
#endif
}

static __always_inline struct go_postgres_query_event *reserve_go_query_event(
    void) {
#ifdef USE_RING_BUF
  return bpf_ringbuf_reserve(&events, sizeof(struct go_postgres_query_event),
                             0);
#else
  u32 zero = 0;
  return bpf_map_lookup_elem(&go_query_heap, &zero);
#endif
}

static __always_inline void send_go_query_event(
    void *ctx, struct go_postgres_query_event *e) {
#ifdef USE_RING_BUF
  bpf_ringbuf_submit(e, 0);
#else
  bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, e,
                        sizeof(struct go_postgres_query_event));
#endif
}

static __always_inline struct exec_event *reserve_exec_event(void) {
#ifdef USE_RING_BUF
  return bpf_ringbuf_reserve(&events, sizeof(struct exec_event), 0);
#else
  u32 zero = 0;
  return bpf_map_lookup_elem(&exec_heap, &zero);
#endif
}

static __always_inline void send_exec_event(void *ctx, struct exec_event *e) {
#ifdef USE_RING_BUF
  bpf_ringbuf_submit(e, 0);
#else
  bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, e,
                        sizeof(struct exec_event));
#endif
}
