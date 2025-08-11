#pragma once

enum event_type {
  EVENT_TYPE_LIBRARY_LOAD = 1,
  EVENT_TYPE_POSTGRES_QUERY = 2,
};

struct trace_event_header {
  enum event_type type;
  u64 timestamp;
  u32 pid;
  u32 tgid;
  u8 comm[16];
};

struct library_load_event {
  struct trace_event_header header;
  u8 library_name[64];
};

struct postgres_query_event {
  struct trace_event_header header;
  u64 conn_ptr;
  u8 query[512];
};

struct pg_query_args {
  uintptr_t conn;
  uintptr_t query;
};

const struct library_load_event *unused_library __attribute__((unused));
const struct postgres_query_event *unused_query __attribute__((unused));
