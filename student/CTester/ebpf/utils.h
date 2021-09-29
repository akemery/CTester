#ifndef __UTILS_H
#define __UTILS_H

int bpfctester_init();
int bpfctester_cleanup();
int bpfctester_register_proc(pid_t pid);
int bpfctester_enable_syscall(int syscall);
int bpfctester_disable_syscall(int syscall);
void begin_sandbox(void);
void end_sandbox(void);
int bpfctester_getstats(int syscall);

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
