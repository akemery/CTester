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



struct ring_buffer *rb = NULL;
struct bpfctester_bpf *skel; 

extern struct stats *stats;
extern struct monitored *monitored;

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
   bpfctester_bpf__destroy(skel);
   return 0;
}

int bpfctester_register_proc(pid_t pid){
    SET_MONITORED_PID(pid);
    return 0;
}



void bpfctester_enable_monitoring(void){
    ENABLE_MONITORING;
}

void bpfctester_disable_monitoring(void){
    DISABLE_MONITORING;
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
    fprintf(stderr, "  %p  ", &skel->bss->ctester_cfg);
    return 0;
}

int bpfctester_init_kernel_data(void){
   stats = (struct stats*) &skel->bss->ctester_stats;
   monitored = (struct monitored*) &skel->bss->ctester_cfg;
   return 0;
}
