#pragma once

static __always_inline u32 extract_pid(u64 pid_tgid) {
  return pid_tgid & 0xFFFFFFFF;
}

static __always_inline u32 extract_tgid(u64 pid_tgid) { return pid_tgid >> 32; }

static __always_inline u32 extract_uid(u64 uid_gid) {
  return uid_gid & 0xFFFFFFFF;
}

static __always_inline u32 extract_gid(u64 uid_gid) { return uid_gid >> 32; }
