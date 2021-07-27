#define _GNU_SOURCE
#include <sched.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/mount.h>
#include "lib/veth.h"
#include "lib/utils.h"

#include <sys/capability.h>
#include <sys/types.h>



#include <signal.h>


#define NOT_OK_EXIT(code, msg); {if(code == -1){perror(msg); exit(-1);} }

struct container_run_para {
    char *container_ip;
    char *hostname;
    int  ifindex;
};

char* const container_args[] = {
    "/bin/sh",
    "-l",
    NULL
};

char* const child_args[] = {
  "/bin/bash",
  NULL
};


static void mount_root() 
{
    mount("none", "/", NULL, MS_REC|MS_PRIVATE, NULL);
    //remount "/proc" to make sure the "top" and "ps" show container's information
    if (mount("proc", "containerc_roots/rootfs/proc", "proc", 0, NULL) !=0 ) {
        perror("proc");
    }
    if (mount("sysfs", "containerc_roots/rootfs/sys", "sysfs", 0, NULL)!=0) {
        perror("sys");
    }
    if (mount("none", "containerc_roots/rootfs/tmp", "tmpfs", 0, NULL)!=0) {
        perror("tmp");
    }

    if (mount("udev", "containerc_roots/rootfs/dev", "devtmpfs", 0, NULL)!=0) {
        perror("dev");
    }
    if (mount("devpts", "containerc_roots/rootfs/dev/pts", "devpts", 0, NULL)!=0) {
        perror("dev/pts");
    }
    
    if (mount("shm", "containerc_roots/rootfs/dev/shm", "tmpfs", 0, NULL)!=0) {
        perror("dev/shm");
    }
   
    if (mount("tmpfs", "containerc_roots/rootfs/run", "tmpfs", 0, NULL)!=0) {
        perror("run");
    }
    /* 
     * 模仿Docker的从外向容器里mount相关的配置文件 
     * 你可以查看：/var/lib/docker/containers/<container_id>/目录，
     * 你会看到docker的这些文件的。
     */
    if (mount("./containerc_roots/conf/hosts", "./containerc_roots/rootfs/etc/hosts", "none", MS_BIND, NULL)!=0 ||
        mount("./containerc_roots/conf/hostname", "./containerc_roots/rootfs/etc/hostname", "none", MS_BIND, NULL)!=0 ||
        mount("./containerc_roots/conf/resolv.conf", "./containerc_roots/rootfs/etc/resolv.conf", "none", MS_BIND, NULL)!=0 ) {
        perror("conf 000");
    }
    /* 模仿docker run命令中的 -v, --volume=[] 参数干的事 */
    if (mount("/tmp/t1", "./containerc_roots/rootfs/mnt", "none", MS_BIND, NULL)!=0) {
        perror("mnt");
    }
    /* chroot 隔离目录 */
    if (chdir("./containerc_roots/rootfs") != 0 || chroot("./") != 0){
        perror("chdir/chroot");
    }
}

static char container_stack[1024*1024];  //子进程栈空间大小 1M

static char container_stack_pid[1024*1024]; 
/**
 * 设置挂载点
 */

void set_uid_map(pid_t pid, int inside_id, int outside_id, int length) {
    char path[256];
    sprintf(path, "/proc/%d/uid_map", getpid());
    FILE* uid_map = fopen(path, "w");
    fprintf(uid_map, "%d %d %d", inside_id, outside_id, length);
    fclose(uid_map);
}
void set_gid_map(pid_t pid, int inside_id, int outside_id, int length) {
    char path[256];
    sprintf(path, "/proc/%d/gid_map", getpid());
    FILE* gid_map = fopen(path, "w");
    fprintf(gid_map, "%d %d %d", inside_id, outside_id, length);
    fclose(gid_map);
}
int child_main(void* args) {
    cap_t caps;
    printf("在子进程中!\n");
    set_uid_map(getpid(), 0, 1000, 1);
    set_gid_map(getpid(), 0, 1000, 1);
    printf("eUID = %ld;  eGID = %ld;  ",
            (long) geteuid(), (long) getegid());
    //caps = cap_get_proc();
    //printf("capabilities: %s\n", cap_to_text(caps, NULL));
    mount_root();
    execv(child_args[0], child_args);
    return 1;
}


static void setnewenv() 
{
    char *penv = getenv("PATH");
    if (NULL == penv) {
        setenv("PATH", "/bin/", 1);
    } else {
        char *new_path = malloc(sizeof(char)*(strlen(penv)+32));
        sprintf(new_path, "%s:%s", penv, "/bin/");
        setenv("PATH", new_path, 1);
        free(new_path);
    }
}

static int container_pid(void *param){
    struct container_run_para *cparam = (struct container_run_para*)param;    
    //设置主机名
    //sethostname(cparam->hostname, strlen(cparam->hostname));

    //设置环境变量
    //setnewenv();
    mount_root();

    sleep(1);

    // veth_newname("veth1", "eth0");
    // veth_up("eth0");        
    // veth_config_ipv4("eth0", cparam->container_ip);

    execv(container_args[0], container_args);
    return 0;
}

/**
 * 容器启动 -- 实际为子进程启动
 */
static int container_run(void *param)
{    
    struct container_run_para  para;
        //获取container ip
    char ipv4[32] = {0};
    //设置主机名
    cap_t caps;
    pid_t child_pid;
    printf("在子进程中!\n");
    set_uid_map(getpid(), 0, 1000, 1);
    set_gid_map(getpid(), 0, 1000, 1);
    printf("eUID = %ld;  eGID = %ld;  ",
            (long) geteuid(), (long) getegid());

    
    // veth_create("veth0", "veth1");
    // veth_up("veth0");
    // /* ??veth0????docker?????? */
    // veth_addbr("veth0", "docker0");
    
    
    //  //获取container ip
    // new_containerip(ipv4, sizeof(ipv4));
    
    // para.hostname = (char *)param;
    // para.ifindex = veth_ifindex("veth1");
    // para.container_ip = ipv4;

    child_pid = clone(container_pid,
                      container_stack_pid + sizeof(container_stack_pid),
                      CLONE_NEWPID | CLONE_NEWNET | CLONE_NEWNS | CLONE_NEWUTS | SIGCHLD, 
                      &para);
    waitpid(child_pid, NULL, 0);

    return 0;
}
 
int main(int argc, char *argv[])
{
    struct container_run_para  para;
    pid_t child_pid;
    char ipv4[32] = {0};

    if (argc < 2) {
        printf("Usage: %s <child-hostname>\n", argv[0]);
        return -1;
    }
    // //获取docker0网卡ip地址
    
    
 /**
     * 1、创建并启动子进程，调用该函数后，父进程将继续往后执行，也就是执行后面的waitpid
     * 2、栈是从高位向低位增长，所以这里要指向高位地址
     * 3、SIGCHLD 表示子进程退出后 会发送信号给父进程 与容器技术无关
     * 4、创建各个namespace
     */
    child_pid = clone(container_run,
                      container_stack + sizeof(container_stack),
                      CLONE_NEWUSER | SIGCHLD, 
                      argv[1]);
//|
 //                     CLONE_NEWPID|CLONE_NEWNET|CLONE_NEWNS|CLONE_NEWUTS| SIGCHLD,
    /* ??veth???????namespace?? */
    //veth_network_namespace("veth1", child_pid);
    
   // NOT_OK_EXIT(child_pid, "clone");

    /* ??????????? */
    waitpid(child_pid, NULL, 0);

    return 0;
}


