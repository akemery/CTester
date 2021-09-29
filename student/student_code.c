#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>


int my_open_func(char *args){
    return open(args,O_CREAT);
}

/*
int my_exec_func(int args){
    int err = execv("/usr/bin/bash",NULL);
}*/

int my_creat_func(void){
    return creat("log.data",S_IRUSR|S_IWUSR);
}

int my_close_func(int args){
    return close(args);
}

int my_write_func(int args){
    return write(args,"Hello, World\n", 1024);
}

int my_read_func(int args){
    char tmp[25];
    return read(args,tmp,25);
}

int my_stat_func(int args){
    struct stat buf;
    return stat("/usr/bin/bash",&buf);
}

int my_fstat_func(int args){
    struct stat buf;
    return fstat(0,&buf);
}

int my_lseek_func(int args){
    return lseek(0,SEEK_SET,0);
}

int my_getpid_func(void){
    return getpid();
}
