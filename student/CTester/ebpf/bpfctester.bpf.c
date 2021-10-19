#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "bpfctester.h"

char LICENSE[] SEC("license") = "GPL";


#define BPF_TP_SYSCALL_ENTER(name)  \
    SEC("tracepoint/syscalls/sys_enter_"#name)  \
    int tracepoint__syscall__sys_enter_ ## name ## (struct trace_event_raw_sys_enter* ctx) \

#define BPF_TP_SYSCALL_EXIT(name)   \
    SEC("tracepoint/syscalls/sys_exit_"#name)  \
    int tracepoint__syscall__sys_exit_ ## name ## (struct trace_event_raw_sys_exit* ctx) \    

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

struct {
  bool monitored;
  __u32 prog_pid;
  bool monitoring_open;
  bool monitoring_creat;
  bool monitoring_close;
  bool monitoring_read;
  bool monitoring_write;
  bool monitoring_stat;
  bool monitoring_fstat;
  bool monitoring_lseek;
  bool monitoring_free;
  bool monitoring_malloc;
  bool monitoring_calloc;
  bool monitoring_realloc;
  bool monitoring_sleep;
  bool monitoring_getpid;
  bool monitoring_accept;
  bool monitoring_bind;
  bool monitoring_listen;
  bool monitoring_connect;
  bool monitoring_poll;
  bool monitoring_recvfrom;
  bool monitoring_recvmsg;
  bool monitoring_recvmsg;
  bool monitoring_select;
  bool monitoring_sendto;
  bool monitoring_sendmsg;
  bool monitoring_shutdown;
  bool monitoring_socket;
  bool start_student_code;
  bool end_student_code;
}ctester_cfg = {};

#define STATS_DECL(name) struct stats_##name stats_##name

struct  {
   struct stats_open stats_open;
   struct stats_close stats_close;
   struct stats_write stats_write;
   struct stats_creat stats_creat;
   struct stats_read stats_read;
   struct stats_getpid stats_getpid;
   STATS_DECL(accept);
   STATS_DECL(bind);
   STATS_DECL(listen);
   STATS_DECL(connect);
   STATS_DECL(poll);
   STATS_DECL(recvfrom);
   STATS_DECL(recvmsg);
   STATS_DECL(select);
   STATS_DECL(sendto);
   STATS_DECL(sendmsg);
   STATS_DECL(shutdown);
   STATS_DECL(socket);
}ctester_stats = {};


SEC("tracepoint/syscalls/sys_enter_open")
int tracepoint__syscalls__sys_enter_open(struct trace_event_raw_sys_enter* ctx){
    struct syscall_enter_open_args *args;
    // Are we monitoring sysclose?
    if(!ctester_cfg.monitored || !ctester_cfg.monitoring_open)
         return 0;
       
    u64 id = (u64)bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    // Are we monitoring this process ?
    if(!ctester_cfg.prog_pid || ctester_cfg.prog_pid!=pid)
        return -1;
    args = (struct syscall_enter_open_args *)ctx;
    ctester_stats.stats_open.last_params.__syscall_nr = args->__syscall_nr;
    ctester_stats.stats_open.last_params.mode = args->mode;
    ctester_stats.stats_open.last_params.flags = args->flags;
    ctester_stats.stats_open.last_params.filename_ptr = args->filename_ptr;
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_open")
int tracepoint__syscalls__sys_exit_open(struct trace_event_raw_sys_exit* ctx){
    struct syscall_exit_open_args* args;
    // Are we monitoring sysclose?
    if(!ctester_cfg.monitored || !ctester_cfg.monitoring_open)
        return 0;
       
    u64 id = (u64)bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    // Are we monitoring this process ?
    if(!ctester_cfg.prog_pid || ctester_cfg.prog_pid!=pid)
        return -1;
    args = (struct syscall_exit_open_args*)ctx;
    ctester_stats.stats_open.last_params.__syscall_nr = args->__syscall_nr;
    ctester_stats.stats_open.lastret = args->ret;
    ctester_stats.stats_open.called++;
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int tracepoint__syscalls__sys_enter_write(struct trace_event_raw_sys_enter* ctx){
    struct syscall_enter_write_args* args;
    // Are we monitoring sysclose?
    if(!ctester_cfg.monitored || !ctester_cfg.monitoring_write)
        return 0;
       
    u64 id = (u64)bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    // Are we monitoring this process ?
    if(!ctester_cfg.prog_pid || ctester_cfg.prog_pid!=pid)
        return -1;
    args = (struct syscall_enter_write_args*)ctx;
    ctester_stats.stats_write.last_params.__syscall_nr = args->__syscall_nr;
    ctester_stats.stats_write.last_params.fd = args->fd;
    ctester_stats.stats_write.last_params.count = args->count;
    ctester_stats.stats_write.last_params.buf = args->buf;
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_write")
int tracepoint__syscalls__sys_exit_write(struct trace_event_raw_sys_exit* ctx){
    struct syscall_exit_write_args* args;
    // Are we monitoring sysclose?
    if(!ctester_cfg.monitored || !ctester_cfg.monitoring_write)
       return 0;
       
    u64 id = (u64)bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    // Are we monitoring this process ?
    if(!ctester_cfg.prog_pid || ctester_cfg.prog_pid!=pid)
       return -1;
    args = (struct syscall_exit_write_args*)ctx;
    ctester_stats.stats_write.lastret = args->ret;
    ctester_stats.stats_write.last_params.__syscall_nr = args->__syscall_nr;
    ctester_stats.stats_write.called++;
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_close")
int tracepoint__syscalls__sys_enter_close(struct trace_event_raw_sys_enter* ctx){
    struct syscall_enter_close_args* args;
    // Are we monitoring sysclose?
    if(!ctester_cfg.monitored || !ctester_cfg.monitoring_close)
        return 0;
       
    u64 id = (u64)bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    // Are we monitoring this process ?
    if(!ctester_cfg.prog_pid || ctester_cfg.prog_pid!=pid)
        return -1;
    args = (struct syscall_enter_close_args*)ctx;
    ctester_stats.stats_close.last_params.fd = args->fd;
    ctester_stats.stats_close.last_params.__syscall_nr = args->__syscall_nr;
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_close")
int tracepoint__syscalls__sys_exit_close(struct trace_event_raw_sys_exit* ctx){
    struct syscall_exit_close_args* args;
    // Are we monitoring sysclose?
    if(!ctester_cfg.monitored || !ctester_cfg.monitoring_close)
        return 0;
       
    u64 id = (u64)bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    // Are we monitoring this process ?
    if(!ctester_cfg.prog_pid || ctester_cfg.prog_pid!=pid)
        return -1;
    args = (struct syscall_exit_close_args*)ctx;
    ctester_stats.stats_close.lastret = args->ret;
    ctester_stats.stats_close.last_params.__syscall_nr = args->__syscall_nr;
    ctester_stats.stats_close.called++;
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_creat")
int tracepoint__syscalls__sys_enter_creat(struct trace_event_raw_sys_enter* ctx){
    struct syscall_enter_creat_args* args;
    // Are we monitoring syscreat?
    if(!ctester_cfg.monitored || !ctester_cfg.monitoring_creat)
        return 0;
       
    u64 id = (u64)bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    // Are we monitoring this process ?
    if(!ctester_cfg.prog_pid || ctester_cfg.prog_pid!=pid)
        return -1;
    args = (struct syscall_enter_creat_args*)ctx;
    ctester_stats.stats_creat.last_params.__syscall_nr = args->__syscall_nr;
    ctester_stats.stats_creat.last_params.mode = args->mode;
    ctester_stats.stats_creat.last_params.filename_ptr = args->filename_ptr;
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_creat")
int tracepoint__syscalls__sys_exit_creat(struct trace_event_raw_sys_exit* ctx){
    struct syscall_exit_creat_args* args;
    // Are we monitoring syscreat?
    if(!ctester_cfg.monitored || !ctester_cfg.monitoring_creat)
        return 0;
       
    u64 id = (u64)bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    // Are we monitoring this process ?
    if(!ctester_cfg.prog_pid || ctester_cfg.prog_pid!=pid)
        return -1;
    args = (struct syscall_exit_creat_args*)ctx;
    ctester_stats.stats_creat.lastret = args->ret;
    ctester_stats.stats_creat.last_params.__syscall_nr = args->__syscall_nr;
    ctester_stats.stats_creat.called++;
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_read")
int tracepoint__syscalls__sys_enter_read(struct trace_event_raw_sys_enter* ctx){
    struct syscall_enter_read_args* args;
    // Are we monitoring sysread?
    if(!ctester_cfg.monitored || !ctester_cfg.monitoring_read)
        return 0;
       
    u64 id = (u64)bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    // Are we monitoring this process ?
    if(!ctester_cfg.prog_pid || ctester_cfg.prog_pid!=pid)
        return -1;
    args = (struct syscall_enter_read_args*)ctx;
    ctester_stats.stats_read.last_params.__syscall_nr = args->__syscall_nr;
    ctester_stats.stats_read.last_params.fd = args->fd;
    ctester_stats.stats_read.last_params.buf = args->buf;
    ctester_stats.stats_read.last_params.count = args->count;
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_read")
int tracepoint__syscalls__sys_exit_read(struct trace_event_raw_sys_exit* ctx){
    struct syscall_exit_read_args* args;
    // Are we monitoring sysread?
    if(!ctester_cfg.monitored || !ctester_cfg.monitoring_read)
        return 0;
       
    u64 id = (u64)bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    // Are we monitoring this process ?
    if(!ctester_cfg.prog_pid || ctester_cfg.prog_pid!=pid)
        return -1;
    args = (struct syscall_exit_read_args*)ctx;
    ctester_stats.stats_read.last_params.__syscall_nr = args->__syscall_nr;
    ctester_stats.stats_read.lastret = args->ret;
    ctester_stats.stats_read.called++;
    return 0;
}


SEC("tracepoint/syscalls/sys_exit_getpid")
int tracepoint__syscalls__sys_exit_getpid(struct trace_event_raw_sys_exit* ctx){
    struct syscall_exit_getpid_args* args;
    // Are we monitoring sysread?
    if(!ctester_cfg.monitored || !ctester_cfg.monitoring_getpid)
        return 0;
       
    u64 id = (u64)bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    // Are we monitoring this process ?
    if(!ctester_cfg.prog_pid || ctester_cfg.prog_pid!=pid)
        return -1;
    args = (struct syscall_exit_getpid_args*)ctx;
    ctester_stats.stats_getpid.lastret = args->ret;
    ctester_stats.stats_getpid.called++;
    return 0;
}

BPF_TP_SYSCALL_ENTER(accept){
    // Are we monitoring sysaccept?
    if(!ctester_cfg.monitored || !ctester_cfg.monitoring_accept)
        return 0;
       
    u64 id = (u64)bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    // Are we monitoring this process ?
    if(!ctester_cfg.prog_pid || ctester_cfg.prog_pid!=pid)
        return -1;
    
    struct accept_args{
        int unused0;
        int unused1;
        struct sockaddr* sk;
        int* addr_len;
    }* args = (struct accept_args*)(ctx->args);

    ctester_stats.stats_accept.called++;
    ctester_stats.stats_accept.addr = args->sk;
    return 0;
}

BPF_TP_SYSCALL_ENTER(bind){
    // Are we monitoring sysbind?
    if(!ctester_cfg.monitored || !ctester_cfg.monitoring_bind)
        return 0;
       
    u64 id = (u64)bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    // Are we monitoring this process ?
    if(!ctester_cfg.prog_pid || ctester_cfg.prog_pid!=pid)
        return -1;
    
    struct bind_args{
        int unused0;
        int unused1;
        struct sockaddr* sk;
        int addrlen;
    }* args = (struct bind_args*)(ctx->args);
    ctester_stats.stats_bind.addr = args->sk;
    ctester_stats.stats_bind.called++;
    return 0;
}

BPF_TP_SYSCALL_ENTER(listen){
    // Are we monitoring syslisten?
    if(!ctester_cfg.monitored || !ctester_cfg.monitoring_listen)
        return 0;
       
    u64 id = (u64)bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    // Are we monitoring this process ?
    if(!ctester_cfg.prog_pid || ctester_cfg.prog_pid!=pid)
        return -1;
    
    struct listen_args{
        int unused;
        int fd;
        int backlog;
    }* args = (struct listen_args*)(ctx->args);
    ctester_stats.stats_listen.backlog = args->backlog;
    ctester_stats.stats_listen.sockfd = args->fd;
    ctester_stats.stats_listen.called++;
    return 0;
}

BPF_TP_SYSCALL_ENTER(connect){
    if(!ctester_cfg.monitored || !ctester_cfg.monitoring_connect)
        return 0;
       
    u64 id = (u64)bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    // Are we monitoring this process ?
    if(!ctester_cfg.prog_pid || ctester_cfg.prog_pid!=pid)
        return -1;

    struct connect_args{
        int unused;
        int fd;
        struct sockaddr* sk;
        int addrlen;
    }* args = (struct connect_args*)(ctx->args);
    ctester_stats.stats_connect.addr = args->sk;
    ctester_stats.stats_connect.called++;
    return 0;
}

BPF_TP_SYSCALL_ENTER(poll){
    if(!ctester_cfg.monitored || !ctester_cfg.monitoring_poll)
        return 0;
       
    u64 id = (u64)bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    // Are we monitoring this process ?
    if(!ctester_cfg.prog_pid || ctester_cfg.prog_pid!=pid)
        return -1;

    struct poll_args{
        int unused;
        struct pollfd* ufds;
        unsigned int nfds;
        int timeout_msecs;
    }* args = (struct poll_args*)(ctx->args);
    ctester_stats.stats_poll.called++;
    ctester_stats.stats_poll.ufds = args->ufds;
    ctester_stats.stats_poll.timeout = args->timeout_msecs;
    ctester_stats.stats_poll.nfds = args->nfds;
    return  0;
}

BPF_TP_SYSCALL_ENTER(recvfrom){
    if(!ctester_cfg.monitored || !ctester_cfg.monitoring_recvfrom)
        return 0;
       
    u64 id = (u64)bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    // Are we monitoring this process ?
    if(!ctester_cfg.prog_pid || ctester_cfg.prog_pid!=pid)
        return -1;
    
    struct recvfrom_args{
        int unused;
        int fd;
        void* ubuf;
        size_t size;
        unsigned int flags;
        struct sockaddr* addr;
        int* addr_len;
    }* args = (struct recvfrom_args*)(ctx->args);
    ctester_stats.stats_recvfrom.called++;
    ctester_stats.stats_recvfrom.addr_len = args->addr;
    ctester_stats.stats_recvfrom.fd = args->fd;
    ctester_stats.stats_recvfrom.flags = args->flags;
    ctester_stats.stats_recvfrom.size = args->size;
    ctester_stats.stats_recvfrom.ubuf = args->ubuf;
    return 0;
}

BPF_TP_SYSCALL_ENTER(recvmsg){
    if(!ctester_cfg.monitored || !ctester_cfg.monitoring_recvmsg)
        return 0;
       
    u64 id = (u64)bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    // Are we monitoring this process ?
    if(!ctester_cfg.prog_pid || ctester_cfg.prog_pid!=pid)
        return -1;
    
    struct recvmsg_args{
        int unused;
        int fd;
        struct user_msghdr* msg;
        unsigned int flags;
    }* args = (struct recvmsg_args*)(ctx->args);
    ctester_stats.stats_recvmsg.called++;
    ctester_stats.stats_recvmsg.fd = args->fd;
    ctester_stats.stats_recvmsg.flags = args->flags;
    ctester_stats.stats_recvmsg.msg = args->msg;
    return 0;
}

BPF_TP_SYSCALL_ENTER(select){
    if(!ctester_cfg.monitored || !ctester_cfg.monitoring_select)
        return 0;
       
    u64 id = (u64)bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    // Are we monitoring this process ?
    if(!ctester_cfg.prog_pid || ctester_cfg.prog_pid!=pid)
        return -1;
    
    struct select_args{
        int unused;
        int n;
        fd_set* inp;
        fd_set* outp;
        fd_set* exp;
        struct __kernel_old_timeval* tvp;
    }* args = (struct select_args*)(ctx->args);
    ctester_stats.stats_select.called++;
    ctester_stats.stats_select.readfds = args->inp;
    ctester_stats.stats_select.writefds = args->outp;
    ctester_stats.stats_select.exceptfds = args->exp;
    ctester_stats.stats_select.fd = args->n;
    return 0;
}

BPF_TP_SYSCALL_ENTER(sendto){
    if(!ctester_cfg.monitored || !ctester_cfg.monitoring_sendto)
        return 0;
       
    u64 id = (u64)bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    // Are we monitoring this process ?
    if(!ctester_cfg.prog_pid || ctester_cfg.prog_pid!=pid)
        return -1;
    
    struct sendto_args{
        int unused;
        int fd;
        void* buff;
        size_t len;
        unsigned int flags;
        struct sockaddr* addr;
        int addr_len;
    }* args = (struct sendto_args*)(ctx->args);
    ctester_stats.stats_sendto.called++;
    ctester_stats.stats_sendto.addr = args->addr;
    ctester_stats.stats_sendto.addr_len = args->addr_len;
    ctester_stats.stats_sendto.fd = args->fd;
    ctester_stats.stats_sendto.flags = args->flags;
    ctester_stats.stats_sendto.len = args->len;
    ctester_stats.stats_sendto.buf = args->buff;
    return 0;
}

BPF_TP_SYSCALL_ENTER(sendmsg){
    if(!ctester_cfg.monitored || !ctester_cfg.monitoring_sendmsg)
        return 0;
       
    u64 id = (u64)bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    // Are we monitoring this process ?
    if(!ctester_cfg.prog_pid || ctester_cfg.prog_pid!=pid)
        return -1;
    
    struct sendmsg_args{
        int unused;
        int fd;
        struct user_msghdr* msg;
        unsigned int flags;
    }* args = (struct sendmsg_args*)(ctx->args);
    ctester_stats.stats_sendmsg.called++;
    ctester_stats.stats_sendmsg.fd = args->fd;
    ctester_stats.stats_sendmsg.flags = args->flags;
    return 0;
}

BPF_TP_SYSCALL_ENTER(shutdown){
    if(!ctester_cfg.monitored || !ctester_cfg.monitoring_shutdown)
        return 0;
       
    u64 id = (u64)bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    // Are we monitoring this process ?
    if(!ctester_cfg.prog_pid || ctester_cfg.prog_pid!=pid)
        return -1;
    
    struct shutdown_args{
        int unused;
        int fd;
        int how;
    }* args = (struct shutdown_args*)(ctx->args);
    ctester_stats.stats_shutdown.fd = args->fd;
    ctester_stats.stats_shutdown.how = args->how;
    ctester_stats.stats_shutdown.called++;
    return  0;
}

BPF_TP_SYSCALL_ENTER(socket){
    if(!ctester_cfg.monitored || !ctester_cfg.monitoring_socket)
        return 0;
       
    u64 id = (u64)bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    // Are we monitoring this process ?
    if(!ctester_cfg.prog_pid || ctester_cfg.prog_pid!=pid)
        return -1;
    
    struct socket_args{
        int unused;
        int family;
        int type;
        int protocol;
    }* args = (struct socket_args*)(ctx->args);
    ctester_stats.stats_socket.called++;
    ctester_stats.stats_socket.protocol = args->protocol;
    ctester_stats.stats_socket.family = args->family;
    ctester_stats.stats_socket.type = args->type;
    return 0;
}

#define SYS_LASTRET(name) ctester_stats.stats_ ## name ## .lastret

BPF_TP_SYSCALL_EXIT(accept){
    if(!ctester_cfg.monitored || !ctester_cfg.monitoring_accept)
        return 0;
       
    u64 id = (u64)bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    // Are we monitoring this process ?
    if(!ctester_cfg.prog_pid || ctester_cfg.prog_pid!=pid)
        return -1;
    SYS_LASTRET(accept) = ctx->ret;    
}

BPF_TP_SYSCALL_EXIT(bind){
    if(!ctester_cfg.monitored || !ctester_cfg.monitoring_bind)
        return 0;
       
    u64 id = (u64)bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    // Are we monitoring this process ?
    if(!ctester_cfg.prog_pid || ctester_cfg.prog_pid!=pid)
        return -1;
    SYS_LASTRET(bind) = ctx->ret;
}

BPF_TP_SYSCALL_EXIT(listen){
    if(!ctester_cfg.monitored || !ctester_cfg.monitoring_bind)
        return 0;
       
    u64 id = (u64)bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    // Are we monitoring this process ?
    if(!ctester_cfg.prog_pid || ctester_cfg.prog_pid!=pid)
        return -1;
    SYS_LASTRET(listen) = ctx->ret;
}

BPF_TP_SYSCALL_EXIT(connect){
    if(!ctester_cfg.monitored || !ctester_cfg.monitoring_connect)
        return 0;
       
    u64 id = (u64)bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    // Are we monitoring this process ?
    if(!ctester_cfg.prog_pid || ctester_cfg.prog_pid!=pid)
        return -1;
    SYS_LASTRET(connect) = ctx->ret;
}

BPF_TP_SYSCALL_EXIT(poll){
    if(!ctester_cfg.monitored || !ctester_cfg.monitoring_listen)
        return 0;
       
    u64 id = (u64)bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    // Are we monitoring this process ?
    if(!ctester_cfg.prog_pid || ctester_cfg.prog_pid!=pid)
        return -1;
    SYS_LASTRET(poll) = ctx->ret;
}

BPF_TP_SYSCALL_EXIT(recvfrom){
    if(!ctester_cfg.monitored || !ctester_cfg.monitoring_recvfrom)
        return 0;
       
    u64 id = (u64)bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    // Are we monitoring this process ?
    if(!ctester_cfg.prog_pid || ctester_cfg.prog_pid!=pid)
        return -1;
    SYS_LASTRET(recvfrom) = ctx->ret;
}

BPF_TP_SYSCALL_EXIT(recvmsg){
    if(!ctester_cfg.monitored || !ctester_cfg.monitoring_recvmsg)
        return 0;
       
    u64 id = (u64)bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    // Are we monitoring this process ?
    if(!ctester_cfg.prog_pid || ctester_cfg.prog_pid!=pid)
        return -1;
    SYS_LASTRET(recvmsg) = ctx->ret;
}

BPF_TP_SYSCALL_EXIT(select){
    if(!ctester_cfg.monitored || !ctester_cfg.monitoring_select)
        return 0;
       
    u64 id = (u64)bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    // Are we monitoring this process ?
    if(!ctester_cfg.prog_pid || ctester_cfg.prog_pid!=pid)
        return -1;    
    SYS_LASTRET(select) = ctx->ret;
}

BPF_TP_SYSCALL_EXIT(sendto){
    if(!ctester_cfg.monitored || !ctester_cfg.monitoring_sendto)
        return 0;
       
    u64 id = (u64)bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    // Are we monitoring this process ?
    if(!ctester_cfg.prog_pid || ctester_cfg.prog_pid!=pid)
        return -1;
    SYS_LASTRET(sendto) = ctx->ret;
}

BPF_TP_SYSCALL_EXIT(sendmsg){
    if(!ctester_cfg.monitored || !ctester_cfg.monitoring_sendmsg)
        return 0;
       
    u64 id = (u64)bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    // Are we monitoring this process ?
    if(!ctester_cfg.prog_pid || ctester_cfg.prog_pid!=pid)
        return -1;
    SYS_LASTRET(sendmsg) = ctx->ret;
}

BPF_TP_SYSCALL_EXIT(shutdown){
    if(!ctester_cfg.monitored || !ctester_cfg.monitoring_shutdown)
        return 0;
       
    u64 id = (u64)bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    // Are we monitoring this process ?
    if(!ctester_cfg.prog_pid || ctester_cfg.prog_pid!=pid)
        return -1;
    SYS_LASTRET(shutdown) = ctx->ret;
}

BPF_TP_SYSCALL_EXIT(socket){
    if(!ctester_cfg.monitored || !ctester_cfg.monitoring_socket)
        return 0;
       
    u64 id = (u64)bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    // Are we monitoring this process ?
    if(!ctester_cfg.prog_pid || ctester_cfg.prog_pid!=pid)
        return -1;    
    SYS_LASTRET(socket) = ctx->ret;
}
