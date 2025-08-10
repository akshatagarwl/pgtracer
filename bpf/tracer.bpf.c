#ifdef __TARGET_ARCH_x86
#include "vmlinux/x86_64.h"
#else
#include "vmlinux/arm64.h"
#endif

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "defs.h"
#include "maps.h"
#include "helpers.h"

char LICENSE[] SEC("license") = "GPL";

SEC("kprobe/sys_openat")
int BPF_KPROBE(kprobe_openat) {
  struct openat_event *e;

  e = reserve_openat_event();
  if (!e) return 0;

  fill_event_header(&e->header, EVENT_TYPE_OPENAT);

  u64 uid_gid = bpf_get_current_uid_gid();
  e->uid = extract_uid(uid_gid);

  send_openat_event(ctx, e);
  return 0;
}
