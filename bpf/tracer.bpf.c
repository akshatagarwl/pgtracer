#ifdef __TARGET_ARCH_x86
#include "vmlinux/x86_64.h"
#else
#include "vmlinux/arm64.h"
#endif

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "defs.h"
#include "helpers.h"
#include "maps.h"

char LICENSE[] SEC("license") = "GPL";

SEC("kprobe/sys_openat")
int BPF_KPROBE(kprobe_openat) {
  struct event *e;

  e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
  if (!e) return 0;

  u64 pid_tgid = bpf_get_current_pid_tgid();
  u64 uid_gid = bpf_get_current_uid_gid();

  e->tgid = extract_tgid(pid_tgid);
  e->uid = extract_uid(uid_gid);
  bpf_get_current_comm(&e->comm, sizeof(e->comm));

  bpf_ringbuf_submit(e, 0);
  return 0;
}
