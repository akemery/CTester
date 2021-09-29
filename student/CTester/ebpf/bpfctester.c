#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <unistd.h>
#include "bpfctester.h"
#include "core.h"
#include "bpfctester.skel.h"
#include "../CTesterLib/CTester_vbpf.h"

struct ring_buffer *rb = NULL;
struct bpfctester_bpf *skel;
volatile process_metadata* process = NULL; // monitored process 

static struct env {
    bool verbose;
} env;

static int init_sandbox();


static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args){
    if (level == LIBBPF_DEBUG && !env.verbose)
        return 0;
    return vfprintf(stderr, format, args);
}

static void bump_memlock_rlimit(void){
    struct rlimit rlim_new = {
        .rlim_cur	= RLIM_INFINITY,
        .rlim_max	= RLIM_INFINITY,
    };
    if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
        fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
        exit(1);
    }
}

int bpfctester_init(){
    int err = init_sandbox(); 
    if(err < 0){
        fprintf(stderr, "Failed start the test %d\n", err);
        return err;
    }
    return 0;
}

int bpfctester_cleanup(){
   ring_buffer__free(rb);
   bpfctester_bpf__destroy(skel);
   return 0;
}

int bpfctester_register_proc(pid_t pid){
    SET_MONITORED_PID(pid);
    return 0;
}

int bpfctester_enable_syscall(int syscall){
    switch(syscall){
        case WRITE:
            MONITORING(write,true);
            return 0;
        case READ:
            MONITORING(read,true);
            return 0;
        case OPEN:
            MONITORING(open,true);
            return 0;
        case CLOSE:
            MONITORING(close,true);
            return 0;
        case CREAT:
            MONITORING(creat,true);
            return 0;
        case STAT:
            MONITORING(stat,true);
            return 0;
        case FSTAT:
            MONITORING(fstat,true);
            return 0;
        case LSEEK:
            MONITORING(lseek,true);
            return 0;
        case GETPID:
            MONITORING(getpid,true);
            return 0;
    }
    return -1;
}

int bpfctester_disable_syscall(int syscall){
    switch(syscall){
        case WRITE:
            MONITORING(write,false);
            return 0;
        case READ:
            MONITORING(read,false);
            return 0;
        case OPEN:
            MONITORING(open,false);
            return 0;
        case CLOSE:
            MONITORING(close,false);
            return 0;
        case CREAT:
            MONITORING(creat,false);
            return 0;
        case STAT:
            MONITORING(stat,false);
            return 0;
        case FSTAT:
            MONITORING(fstat,false);
            return 0;
        case LSEEK:
            MONITORING(lseek,false);
            return 0;
        case GETPID:
            MONITORING(getpid,false);
            return 0;
    }
    return 0;
}

void begin_sandbox(void){
    BEGIN_SANDBOX;
}

void end_sandbox(void){
    END_SANDBOX;
}

int bpfctester_getstats(int syscall){
    switch(syscall){
        case WRITE:
            fprintf(stderr, "write %lld::%d\n", GET_STATS(write).lastret, GET_STATS(write).ncalled);
            break;
        case READ:
            fprintf(stderr, "read %lld::%d\n", GET_STATS(read).lastret, GET_STATS(read).ncalled);
            break;
        case GETPID:
            fprintf(stderr, "getpid %d::%d\n", GET_STATS(getpid).lastret, GET_STATS(getpid).ncalled);
            break; 
        case CREAT:
            fprintf(stderr, "creat %lld::%d\n", GET_STATS(creat).lastret, GET_STATS(creat).ncalled);
            break; 
        case CLOSE:
            fprintf(stderr, "close %lld::%d\n", GET_STATS(close).lastret, GET_STATS(close).ncalled);
            break; 
    }
    return 0;
}

static int init_sandbox(){
    int err;
    libbpf_set_print(libbpf_print_fn);
    /* Bump RLIMIT_MEMLOCK to create BPF maps */
    bump_memlock_rlimit();
    /* Load and verify BPF application */
    skel = bpfctester_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }
    /* Load & verify BPF programs */
    err = bpfctester_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        return err;
    }

    /* Attach tracepoints */
    err = bpfctester_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        return err;
    }
    memset(&skel->bss->ctester_stats, 0, sizeof(skel->bss->ctester_stats));
    return 0;
}
