#pragma once

struct event {
  u32 tgid;
  u32 uid;
  u8 comm[16];
};

const struct event *unused __attribute__((unused));
