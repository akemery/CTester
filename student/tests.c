// CTester template

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include "student_code.h"
#include "CTester.h"
#include "ebpf/utils.h"


void test_myfunc_ret() {
    set_test_metadata("myfunc", _("Brief description of the test"), 1);

    int ret = 0, fd;
    
    
    monitored->getpid = true;
    SANDBOX_BEGIN;
    ret = my_getpid_func();
    SANDBOX_END;
    
    monitored->creat = true;
    monitored->read = true;
    monitored->write = true;
    monitored->close = true;
    monitored->getpid = false;
    banned.write = false;
    banned.getpid = true;
    SANDBOX_BEGIN;
    fd = my_creat_func();
    ret = my_write_func(fd);
    ret = my_read_func(fd);
    my_close_func(fd);
    //ret = my_getpid_func();
    SANDBOX_END;
    
    fprintf(stderr, "%d %d %llu, %d\n", stats->write.called, stats->getpid.called, stats->write.last_params.fd, monitored->write);
    //bpfctester_cleanup();
    CU_ASSERT_EQUAL(ret,25);
}


void test_myfunc2_ret() {
    set_test_metadata("myfunc2", _("Brief description of the test"), 2);

    int ret = 0, fd;
    
    monitored->creat = true;
    monitored->read = true;
    monitored->write = true;
    monitored->close = true;
    monitored->getpid = false;
    SANDBOX_BEGIN;
    fd = my_creat_func();
    ret = my_write_func(fd);
    ret = my_read_func(fd);
    my_close_func(fd);
    ret = my_getpid_func();
    SANDBOX_END;
    
    fprintf(stderr, "%d %d %llu, %d\n", stats->write.called, stats->getpid.called, stats->write.last_params.fd, monitored->write);
    release_resource();
    CU_ASSERT_EQUAL(ret,25);
}


int main(int argc,char** argv){
    BAN_FUNCS();
    RUN(test_myfunc_ret, test_myfunc2_ret);
    return 0;
}

