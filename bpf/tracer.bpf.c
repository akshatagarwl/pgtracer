#ifdef __TARGET_ARCH_x86
#include "vmlinux/x86_64.h"
#else
#include "vmlinux/arm64.h"
#endif

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "defs.h"
#include "maps.h"
#include "helpers.h"

char LICENSE[] SEC("license") = "GPL";

SEC("kprobe/do_dentry_open")
int BPF_KPROBE(kprobe_file_open, struct file *file) {
  if (!file) return 0;

  struct dentry *dentry;
  struct qstr d_name;
  u8 key[64] = {0};

  BPF_CORE_READ_INTO(&dentry, file, f_path.dentry);
  if (!dentry) return 0;

  BPF_CORE_READ_INTO(&d_name, dentry, d_name);

  bpf_core_read_str(key, sizeof(key), d_name.name);

  if (key[0] == 'l' && key[1] == 'i' && key[2] == 'b' && key[3] == 'p' &&
      key[4] == 'q') {
    struct library_load_event *lib_event = reserve_library_event();
    if (lib_event) {
      fill_event_header(&lib_event->header, EVENT_TYPE_LIBRARY_LOAD);
      __builtin_memcpy(lib_event->library_name, key, 64);
      send_library_event(ctx, lib_event);
    }
  }

  return 0;
}
