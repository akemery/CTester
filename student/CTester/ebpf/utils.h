#ifndef __UTILS_H
#define __UTILS_H

#include <stdbool.h>
#include <stdint.h>
#include "../CTesterLib/syscall_args.h"


int bpfctester_init();
int bpfctester_cleanup();
int bpfctester_register_proc(pid_t pid);
int bpfctester_enable_syscall(int syscall);
int bpfctester_disable_syscall(int syscall);
void bpfctester_disable_monitoring(void);
void bpfctester_enable_monitoring(void);

int bpfctester_init_kernel_data(void);
void release_resource(void);

struct stats {
   struct stats_open open;
   struct stats_close close;
   struct stats_write write;
   struct stats_creat creat;
   struct stats_read read;
   struct stats_getpid getpid;
};

struct monitored {
  bool monitored;
  uint32_t prog_pid;
  bool open;
  bool creat;
  bool close;
  bool read;
  bool write;
  bool stat;
  bool fstat;
  bool lseek;
  bool free;
  bool malloc;
  bool calloc;
  bool realloc;
  bool sleep;
  bool getpid;
  bool start_student_code;
  bool end_student_code;
};

struct banned {
  bool open;
  bool creat;
  bool close;
  bool read;
  bool write;
  bool stat;
  bool fstat;
  bool lseek;
  bool free;
  bool malloc;
  bool calloc;
  bool realloc;
  bool sleep;
  bool getpid;
};


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

#endif /* __UTILS_H */
