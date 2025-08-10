#pragma once

enum event_type {
  EVENT_TYPE_LIBRARY_LOAD = 1,
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

const struct library_load_event *unused_library __attribute__((unused));
