#ifndef __BPFCTESTER_H
#define __BPFCTESTER_H
#include "../CTesterLib/syscall_args.h"

enum {
  OPEN,
  EXEC,
  WRITE,
  CLOSE,
  CREAT,
  READ,
  STAT,
  FSTAT,
  LSEEK,
  GETPID,
  ACCEPT,
  BIND,
  LISTEN,
  CONNECT,
  POLL,
  RECVFROM,
  RECVMSG,
  SELECT,
  SENDTO,
  SENDMSG,
  SHUTDOWN,
  SOCKET
};

struct event {
  int type;
  __u32 uid;
  __u32 pid;
  union{
    struct syscall_enter_open_args enter_open_args;
    struct syscall_enter_write_args enter_write_args;
    struct syscall_enter_close_args enter_close_args;
    struct syscall_enter_creat_args enter_creat_args;
    struct syscall_enter_read_args enter_read_args;
    struct syscall_enter_stat_args enter_stat_args;
    struct syscall_enter_fstat_args enter_fstat_args;
    struct syscall_enter_lseek_args enter_lseek_args;
    struct syscall_exit_open_args exit_open_args;
    struct syscall_exit_close_args exit_close_args;
    struct syscall_exit_creat_args exit_creat_args;
    struct syscall_exit_read_args exit_read_args;
    struct syscall_exit_stat_args exit_stat_args;
    struct syscall_exit_fstat_args exit_fstat_args;
    struct syscall_exit_lseek_args exit_lseek_args;
  }args;
};


int init_ctx();

#endif /* __BPFCTESTER_H */
