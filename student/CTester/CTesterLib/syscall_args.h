#ifndef __SYSCALL_ARGS_H__
#define __SYSCALL_ARGS_H__

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
    int ncalled;   
};

struct stats_open{
    unsigned long long unused;
    struct syscall_enter_open_args lastparams;
    long long lastret;
    int ncalled;    
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
    struct syscall_enter_creat_args lastparams;
    long long lastret;
    int ncalled;    
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
    struct syscall_enter_close_args lastparams;
    long long lastret;
    int ncalled;    
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
    struct syscall_enter_read_args lastparams;
    long long lastret;
    int ncalled;    
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
    struct syscall_enter_write_args lastparams;
    long long lastret;
    int ncalled;    
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
    struct syscall_enter_stat_args lastparams;
    long long lastret;
    int ncalled;    
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
    struct syscall_enter_fstat_args lastparams;
    long long lastret;
    int ncalled;    
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
    struct syscall_enter_lseek_args lastparams;
    int lastret;
    int ncalled;    
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
    int ncalled;    
};


#define MONITORING_LSEEK  0x40

#endif //__SYSCALL_ARGS_H__
