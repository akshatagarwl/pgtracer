#pragma once

enum event_type {
  EVENT_TYPE_OPENAT = 1,
};

struct trace_event_header {
  enum event_type type;
  u64 timestamp;
  u32 pid;
  u32 tgid;
  u8 comm[16];
};

struct openat_event {
  struct trace_event_header header;
  u32 uid;
};

const struct openat_event *unused_openat __attribute__((unused));
