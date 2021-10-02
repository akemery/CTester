#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <setjmp.h>
#include <signal.h>
#include <errno.h>
#include <sys/time.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>


#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>
#include <CUnit/Automated.h>

#include <libintl.h>
#include <locale.h>
#define _(STRING) gettext(STRING)
#include <dlfcn.h>
#include <malloc.h>
#include <seccomp.h>
#include "ebpf/utils.h"

#define TAGS_NB_MAX 20
#define TAGS_LEN_MAX 30

//extern bool wrap_monitoring;
//extern struct wrap_stats_t stats;
//extern struct wrap_monitor_t monitored;
//extern struct wrap_fail_t failures;
//extern struct wrap_log_t logs;

extern struct stats *stats;
extern struct monitored *monitored;
extern struct banned banned;

extern sigjmp_buf segv_jmp;

int true_stderr;
int true_stdout;
int pipe_stderr[2], usr_pipe_stderr[2];
int pipe_stdout[2], usr_pipe_stdout[2];
extern int stdout_cpy, stderr_cpy;
struct itimerval it_val;

CU_pSuite pSuite = NULL;

static bool bpf_initialized = false;

/*seccomp part*/
static int ctester_seccomp_init(void);
static void ctester_seccomp_release(void);
static int ctester_seccomp_add_rules(void);
static scmp_filter_ctx ctx = NULL;


struct info_msg {
    char *msg;
    struct info_msg *next;
};

struct __test_metadata {
    struct info_msg *fifo_in;
    struct info_msg *fifo_out;
    char problem[140];
    char descr[250];
    unsigned int weight;
    unsigned char nb_tags;
    char tags[TAGS_NB_MAX][TAGS_LEN_MAX];
    int err;
} test_metadata;


void set_test_metadata(char *problem, char *descr, unsigned int weight)
{
    test_metadata.weight = weight;
    strncpy(test_metadata.problem, problem, sizeof(test_metadata.problem));
    strncpy(test_metadata.descr, descr, sizeof(test_metadata.descr));
    if(!bpf_initialized){
        bpfctester_init();
        bpfctester_register_proc(getpid());
        bpfctester_init_kernel_data();
        bpf_initialized = true;
        ctester_seccomp_init();
        memset(&banned, 0, sizeof(struct banned));
        fprintf(stderr, "Initialized data first time\n");
    }
}

void push_info_msg(char *msg)
{
    if (strstr(msg, "#") != NULL || strstr(msg, "\n") != NULL) {
        test_metadata.err = EINVAL;
        return;
    }

    struct info_msg *item = malloc(sizeof(struct info_msg));
    if (item == NULL)
        test_metadata.err = ENOMEM;

    item->next = NULL;
    item->msg = malloc(strlen(msg) + 1);
    if (item->msg == NULL)
        test_metadata.err = ENOMEM;

    strcpy(item->msg, msg);
    if (test_metadata.fifo_in == NULL && test_metadata.fifo_out == NULL) {
        test_metadata.fifo_in = item;
        test_metadata.fifo_out = item;
    } else {
        test_metadata.fifo_out->next = item;
        test_metadata.fifo_out = item;
    }
}

void set_tag(char *tag)
{
    int i=0;
    while (tag[i] != '\0' && i < TAGS_LEN_MAX) {
        if (!isalnum(tag[i]) && tag[i] != '-' && tag[i] != '_')
            return;
        i++;
    }

    if (test_metadata.nb_tags < TAGS_NB_MAX)
        strncpy(test_metadata.tags[test_metadata.nb_tags++], tag, TAGS_LEN_MAX);
}

void segv_handler(int sig, siginfo_t *unused, void *unused2) {
    bpfctester_disable_monitoring();
    push_info_msg(_("Your code produced a segfault."));
    set_tag("sigsegv");
    bpfctester_enable_monitoring();
    siglongjmp(segv_jmp, 1);
}

void alarm_handler(int sig, siginfo_t *unused, void *unused2)
{
    bpfctester_disable_monitoring();
    push_info_msg(_("Your code exceeded the maximal allowed execution time."));
    set_tag("timeout");
    bpfctester_enable_monitoring();
    siglongjmp(segv_jmp, 1);
}

void trap_handler(int sig, siginfo_t *unused, void *unused2){
    bpfctester_disable_monitoring();
    push_info_msg(_("Your code exceeded called banned banned system call"));
    set_tag("trapped banned syscall");
    fprintf(stderr, "trapped banned syscall\n");
    bpfctester_enable_monitoring();
    
}


int sandbox_begin()
{
    int rc;
    // Start timer
    it_val.it_value.tv_sec = 2;
    it_val.it_value.tv_usec = 0;
    it_val.it_interval.tv_sec = 0;
    it_val.it_interval.tv_usec = 0;
    setitimer(ITIMER_REAL, &it_val, NULL);

    // Intercepting stdout and stderr
    dup2(pipe_stdout[1], STDOUT_FILENO);
    dup2(pipe_stderr[1], STDERR_FILENO);
    // Emptying the user pipes
    char buf[BUFSIZ];
    int n;
    while ((n = read(usr_pipe_stdout[0], buf, BUFSIZ)) > 0);
    while ((n = read(usr_pipe_stderr[0], buf, BUFSIZ)) > 0);

    //wrap_monitoring = true;
    bpfctester_enable_monitoring();
    rc = ctester_seccomp_add_rules();
    if(rc < 0){
        fprintf(stderr, "adding rules failed\n");
    }
    rc = seccomp_load(ctx);
    if(rc < 0){
        fprintf(stderr, "loading filter failed\n");
    }
    return 0;
}

void sandbox_fail()
{
    CU_FAIL("Segfault or timeout");
}

void sandbox_end()
{
    //wrap_monitoring = false;

    // Remapping stderr to the orignal one ...
    dup2(true_stdout, STDOUT_FILENO); // TODO
    dup2(true_stderr, STDERR_FILENO);

    // ... and looking for a double free warning
    char buf[BUFSIZ];
    int n;
    while ((n = read(pipe_stdout[0], buf, BUFSIZ)) > 0) {
        write(usr_pipe_stdout[1], buf, n);
        write(STDOUT_FILENO, buf, n);
    }


    while ((n = read(pipe_stderr[0], buf, BUFSIZ)) > 0) {
        if (strstr(buf, "double free or corruption") != NULL) {
            CU_FAIL("Double free or corruption");
            push_info_msg(_("Your code produced a double free."));
            set_tag("double_free");
        }
        write(usr_pipe_stderr[1], buf, n);
        write(STDERR_FILENO, buf, n);
    }


    it_val.it_value.tv_sec = 0;
    it_val.it_value.tv_usec = 0;
    it_val.it_interval.tv_sec = 0;
    it_val.it_interval.tv_usec = 0;
    setitimer(ITIMER_REAL, &it_val, NULL);
    bpfctester_disable_monitoring();
}


int init_suite1(void)
{
    return 0;
}

int clean_suite1(void)
{
    return 0;
}

void start_test()
{
    bzero(&test_metadata,sizeof(test_metadata));
    //bzero(&stats,sizeof(stats));
    //bzero(&failures,sizeof(failures));
    //bzero(&monitored,sizeof(monitored));
    //bzero(&logs,sizeof(logs));
}

int __real_exit(int status);
int __wrap_exit(int status){
    return status;
}

int run_tests(int argc, char *argv[], void *tests[], int nb_tests) {
    for (int i=1; i < argc; i++) {
        if (!strncmp(argv[i], "LANGUAGE=", 9))
                putenv(argv[i]);
    }
    setlocale (LC_ALL, "");
    bindtextdomain("tests", getenv("PWD"));
    bind_textdomain_codeset("messages", "UTF-8");
    textdomain("tests");

    mallopt(M_PERTURB, 142); // newly allocated memory with malloc will be set to ~142
    // Code for detecting properly double free errors
    mallopt(M_CHECK_ACTION, 1); // don't abort if double free
    true_stderr = dup(STDERR_FILENO); // preparing a non-blocking pipe for stderr
    true_stdout = dup(STDOUT_FILENO); // preparing a non-blocking pipe for stderr

    int *pipes[] = {pipe_stderr, pipe_stdout, usr_pipe_stdout, usr_pipe_stderr};
    for(int i=0; i < 4; i++) { // Configuring pipes to be non-blocking
        pipe(pipes[i]);
        int flags = fcntl(pipes[i][0], F_GETFL, 0);
        fcntl(pipes[i][0], F_SETFL, flags | O_NONBLOCK);
    }
    stdout_cpy = usr_pipe_stdout[0];
    stderr_cpy = usr_pipe_stderr[0];

    putenv("LIBC_FATAL_STDERR_=2"); // needed otherwise libc doesn't print to program's stderr

    /* make sure that we catch segmentation faults */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sigaction));
    sigemptyset(&sa.sa_mask);
    static char stack[SIGSTKSZ];
    stack_t ss = {
        .ss_size = SIGSTKSZ,
        .ss_sp = stack,
    };

    sa.sa_flags     = SA_NODEFER|SA_ONSTACK|SA_RESTART|SA_SIGINFO | SA_NODEFER;
    sa.sa_sigaction = segv_handler;
    sigaltstack(&ss, 0);
    sigfillset(&sa.sa_mask);
    int ret = sigaction(SIGSEGV, &sa, NULL);
    if (ret)
        return ret;
        
    sa.sa_sigaction = alarm_handler;
    ret = sigaction(SIGALRM, &sa, NULL);
    if (ret)
        return ret;
        
    sa.sa_sigaction = trap_handler;
    ret = sigaction(SIGSYS, &sa, NULL);
    if (ret)
        return ret;

    /* Output file containing succeeded / failed tests */
    FILE* f_out = fopen("results.txt", "w");
    if (!f_out)
        return -ENOENT;

    /* initialize the CUnit test registry */
    if (CUE_SUCCESS != CU_initialize_registry())
        return CU_get_error();
        
    /* add a suite to the registry */
    pSuite = CU_add_suite("Suite_1", init_suite1, clean_suite1);
    if (NULL == pSuite) {
        CU_cleanup_registry();
        return CU_get_error();
    }
    

    for (int i=0; i < nb_tests; i++) {
        Dl_info  DlInfo;
        
        if (dladdr(tests[i], &DlInfo) == 0)
            return -EFAULT;
            
        CU_pTest pTest;
        if ((pTest = CU_add_test(pSuite, "Run test for", tests[i])) == NULL) {
                CU_cleanup_registry();
                return CU_get_error();
        }
        printf("\n==== Results for test %s : ====\n", DlInfo.dli_sname);

        start_test();

        if (CU_basic_run_test(pSuite,pTest) != CUE_SUCCESS)
            return CU_get_error();

        if (test_metadata.err)
            return test_metadata.err;

        int nb = CU_get_number_of_tests_failed();
        if (nb > 0)
            ret = fprintf(f_out, "%s#FAIL#%s#%d#", test_metadata.problem,
                    test_metadata.descr, test_metadata.weight);

        else
            ret = fprintf(f_out, "%s#SUCCESS#%s#%d#", test_metadata.problem,
                    test_metadata.descr, test_metadata.weight);
        if (ret < 0)
            return ret;

        for(int i=0; i < test_metadata.nb_tags; i++) {
            ret = fprintf(f_out, "%s", test_metadata.tags[i]);
            if (ret < 0)
                return ret;

            if (i != test_metadata.nb_tags - 1) {
                ret = fprintf(f_out, ",");
                if (ret < 0)
                    return ret;
            }
        }


        while (test_metadata.fifo_in != NULL) {
            struct info_msg *head = test_metadata.fifo_in;
            ret = fprintf(f_out, "#%s", head->msg);

            if (head->msg != NULL)
                free(head->msg);
            test_metadata.fifo_in = head->next;
            free(head);

            if (ret < 0)
                return ret;
        }

        test_metadata.fifo_out = NULL;
        ret = fprintf(f_out, "\n");
        if (ret < 0)
            return ret;

    }

    fclose(f_out);

    /* Run all tests using the CUnit Basic interface */
    //CU_basic_run_tests();
    //CU_automated_run_tests();
    CU_cleanup_registry();
    return CU_get_error();
}

void release_resource(void){
    bpfctester_cleanup();
    ctester_seccomp_release();
}

static int ctester_seccomp_init(void){
    ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (ctx == NULL)
        return ENOMEM;
    return 0;  
}

static void ctester_seccomp_release(void){
    seccomp_release(ctx);
}


static int ctester_seccomp_add_rules(void){
    int rc = -1;
    if(banned.write){
        rc = seccomp_rule_add(ctx, 
            SCMP_ACT_TRAP, SCMP_SYS(write), 0);
        if(rc < 0) return rc;
    }
    if(banned.open){
        rc = seccomp_rule_add(ctx, 
            SCMP_ACT_TRAP, SCMP_SYS(open), 0);
        if(rc < 0) return rc;
    }
    if(banned.creat){
        rc = seccomp_rule_add(ctx, 
            SCMP_ACT_TRAP, SCMP_SYS(creat), 0);
        if(rc < 0) return rc;
    }
    if(banned.close){
        rc = seccomp_rule_add(ctx, 
            SCMP_ACT_TRAP, SCMP_SYS(close), 0);
        if(rc < 0) return rc;
    }
    if(banned.getpid){
        rc = seccomp_rule_add(ctx, 
            SCMP_ACT_TRAP, SCMP_SYS(getpid), 0);
        if(rc < 0) return rc;
    }
    if(banned.read){
        rc = seccomp_rule_add(ctx, 
            SCMP_ACT_TRAP, SCMP_SYS(read), 0);
        if(rc < 0) return rc;
    }
    if(banned.stat){
        rc = seccomp_rule_add(ctx, 
            SCMP_ACT_TRAP, SCMP_SYS(stat), 0);
        if(rc < 0) return rc;
    }
    if(banned.fstat){
        rc = seccomp_rule_add(ctx, 
            SCMP_ACT_TRAP, SCMP_SYS(fstat), 0);
        if(rc < 0) return rc;
    }
    /*if(banned.sleep){
        rc = seccomp_rule_add(ctx, 
            SCMP_ACT_KILL_PROCESS, SCMP_SYS(sleep), 0);
        if(rc < 0) return rc;
    }*/
    return 0;
}
