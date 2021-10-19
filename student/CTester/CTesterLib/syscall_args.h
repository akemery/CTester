#ifndef __SYSCALL_ARGS_H__
#define __SYSCALL_ARGS_H__
#include "../ebpf/vmlinux.h"

struct syscall_enter_open_args{
    unsigned long long unused;
    long __syscall_nr;
    unsigned long long filename_ptr;
    unsigned long long flags;
    unsigned long long mode;
};

struct syscall_exit_open_args{
    unsigned long long unused;
    long __syscall_nr;
    long long ret;
    int called;   
};

struct stats_open{
    unsigned long long unused;
    struct syscall_enter_open_args last_params;
    long long lastret;
    int called;    
};

struct syscall_enter_creat_args{
    unsigned long long unused;
    long __syscall_nr;
    unsigned long long filename_ptr;
    unsigned long long mode;
};

struct syscall_exit_creat_args{
    unsigned long long unused;
    long __syscall_nr;
    long long ret;
};

struct stats_creat{
    unsigned long long unused;
    struct syscall_enter_creat_args last_params;
    long long lastret;
    int called;    
};

struct syscall_enter_close_args{
    unsigned long long unused;
    long __syscall_nr;
    unsigned long long fd;   
};

struct syscall_exit_close_args{
    unsigned long long unused;
    long __syscall_nr;
    long long ret;
};

struct stats_close{
    unsigned long long unused;
    struct syscall_enter_close_args last_params;
    long long lastret;
    int called;    
};

struct syscall_enter_read_args{
    unsigned long long unused;
    long __syscall_nr;
    unsigned long long fd;
    unsigned long long buf;
    unsigned long long count;   
};

struct syscall_exit_read_args{
    unsigned long long unused;
    long __syscall_nr;
    long long ret;
};

struct stats_read{
    unsigned long long unused;
    struct syscall_enter_read_args last_params;
    long long lastret;
    int called;    
};

struct syscall_enter_write_args{
    unsigned long long unused;
    long __syscall_nr;
    unsigned long long fd;
    unsigned long long buf;
    unsigned long long count;
};



struct syscall_exit_write_args{
    unsigned long long unused;
    long __syscall_nr;
    long ret;   
};

struct stats_write {
    struct syscall_enter_write_args last_params;
    long long lastret;
    int called;    
};

struct syscall_enter_stat_args{
    unsigned long long unused;
    long __syscall_nr;
    unsigned long long filename_ptr;
    unsigned long long statbuf;
};

struct  syscall_exit_stat_args{
    unsigned long long unused;
    long __syscall_nr;
    long long ret;
};

struct stats_stat{
    unsigned long long unused;
    struct syscall_enter_stat_args last_params;
    long long lastret;
    int called;    
};

struct syscall_enter_fstat_args{
    unsigned long long unused;
    long __syscall_nr;
    unsigned long long fd;
    unsigned long long statbuf;
};

struct syscall_exit_fstat_args{
    unsigned long long unused;
    long __syscall_nr;
    long long ret;
};

struct stats_fstat{
    unsigned long long unused;
    struct syscall_enter_fstat_args last_params;
    long long lastret;
    int called;    
};

struct syscall_enter_lseek_args{
    unsigned long long unused;
    long __syscall_nr;
    unsigned long long fd;
    unsigned long long offset;
    unsigned long long whence;
};

struct syscall_exit_lseek_args{
    unsigned long long unused;
    long __syscall_nr;
    int ret;
};

struct stats_lseek{
    struct syscall_enter_lseek_args last_params;
    int lastret;
    int called;    
};

struct syscall_enter_getpid_args{
    int __syscall_nr;
};

struct syscall_exit_getpid_args{
    unsigned long long unused;
    long __syscall_nr;
    int ret;
};

struct stats_getpid{
    int lastret;
    int called;    
};

struct stats_accept{
    struct sockaddr* addr;
    int called;
    int lastret;
};

struct stats_bind{
    struct sockaddr* addr;
    int called;
    int lastret;
};

struct stats_listen{
    int sockfd;
    int backlog;
    int called;
    int lastret;
};

struct stats_connect{
    struct sockaddr* addr;
    int lastret;
    int called;
};

struct  stats_poll{
    struct pollfd*  ufds;
    int nfds;
    int timeout;
    int called;
    int lastret;
};

struct stats_recvfrom{
    int fd;
    void* ubuf;
    int size;
    int flags;
    struct sockaddr* addr;
    int* addr_len;
    int called;
    int lastret;
};

struct stats_recvmsg{
    int fd;
    struct user_msghdr* msg;
    int flags;
    int called;
    int lastret;
};

struct stats_select{
    int fd;
    fd_set* readfds;
    fd_set* writefds;
    fd_set* exceptfds;
    int called;
    int lastret;
};

struct stats_sendto{
    int fd;
    void* buf;
    int len;
    int flags;
    struct sockaddr* addr;
    int addr_len;
    int lastret;
    int called;
};

struct stats_sendmsg{
    int fd;
    int flags;
    int called;
    int lastret;
};

struct stats_shutdown{
    int fd;
    int how;
    int lastret;
    int called;
};

struct stats_socket{
    int family;
    int type;
    int protocol;
    int lastret;
    int called;
};

#endif //__SYSCALL_ARGS_H__
