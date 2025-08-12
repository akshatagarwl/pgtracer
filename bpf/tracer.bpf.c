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

  bpf_core_read(key, sizeof(key), d_name.name);

  if (key[0] == 'l' && key[1] == 'i' && key[2] == 'b' && key[3] == 'p' &&
      key[4] == 'q') {
    struct library_load_event *lib_event = reserve_library_event();
    if (lib_event) {
      fill_event_header(&lib_event->header, EVENT_TYPE_LIBRARY_LOAD);
      __builtin_memcpy(lib_event->library_name, key, 64);
      lib_event->lib_type = LIBRARY_TYPE_LIBPQ;
      send_library_event(ctx, lib_event);
    }
  }

  return 0;
}

SEC("uprobe/PQsendQuery")
int BPF_UPROBE(trace_pqsendquery, void *conn, const char *query) {
  u64 pid_tgid = bpf_get_current_pid_tgid();

  struct pg_query_args args = {
      .conn = (uintptr_t)conn,
      .query = (uintptr_t)query,
  };

  bpf_map_update_elem(&active_pg_queries, &pid_tgid, &args, BPF_ANY);

  return 0;
}

SEC("uretprobe/PQsendQuery")
int BPF_URETPROBE(trace_pqsendquery_ret, int ret) {
  u64 pid_tgid = bpf_get_current_pid_tgid();

  struct pg_query_args *args =
      bpf_map_lookup_elem(&active_pg_queries, &pid_tgid);
  if (!args) return 0;

  if (ret == 1) {
    struct postgres_query_event *event = reserve_query_event();
    if (event) {
      fill_event_header(&event->header, EVENT_TYPE_POSTGRES_QUERY);

      event->conn_ptr = args->conn;
      bpf_probe_read_user(event->query, sizeof(event->query),
                          (const char *)args->query);

      send_query_event(ctx, event);
    }
  }

  bpf_map_delete_elem(&active_pg_queries, &pid_tgid);

  return 0;
}

SEC("uprobe/go_pq_query")
int BPF_UPROBE(trace_go_pq_query) {
  u64 pid_tgid = bpf_get_current_pid_tgid();

  struct go_query_args args = {
      .conn_ptr = GO_PARAM1(ctx),
      .query_ptr = GO_PARAM2(ctx),
      .query_len = (u32)GO_PARAM3(ctx),
  };

  bpf_map_update_elem(&active_go_queries, &pid_tgid, &args, BPF_ANY);

  return 0;
}

SEC("uretprobe/go_pq_query")
int BPF_URETPROBE(trace_go_pq_query_ret) {
  u64 pid_tgid = bpf_get_current_pid_tgid();

  struct go_query_args *args =
      bpf_map_lookup_elem(&active_go_queries, &pid_tgid);
  if (!args) return 0;

  struct go_postgres_query_event *event = reserve_go_query_event();
  if (!event) {
    bpf_map_delete_elem(&active_go_queries, &pid_tgid);
    return 0;
  }

  fill_event_header(&event->header, EVENT_TYPE_GO_POSTGRES_QUERY);

  event->conn_ptr = args->conn_ptr;
  event->query_len = args->query_len;

  u32 max_len = args->query_len < sizeof(event->query) - 1
                    ? args->query_len
                    : sizeof(event->query) - 1;

  bpf_probe_read_user_str(event->query, max_len + 1, (void *)args->query_ptr);

  send_go_query_event(ctx, event);

  bpf_map_delete_elem(&active_go_queries, &pid_tgid);

  return 0;
}

SEC("tracepoint/syscalls/sys_exit_execve")
int BPF_PROG(trace_execve_exit, u64 pad, int __syscall_nr, long ret) {
  if (ret != 0) {
    return 0;
  }

  struct exec_event *event = reserve_exec_event();
  if (!event) {
    return 0;
  }

  fill_event_header(&event->header, EVENT_TYPE_EXEC);

  send_exec_event(ctx, event);

  return 0;
}
