#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "bpfctester.h"

char LICENSE[] SEC("license") = "GPL";


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
  bool start_student_code;
  bool end_student_code;
}ctester_cfg = {};

struct  {
   struct stats_open stats_open;
   struct stats_close stats_close;
   struct stats_write stats_write;
   struct stats_creat stats_creat;
   struct stats_read stats_read;
   struct stats_getpid stats_getpid;
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
