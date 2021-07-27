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

#include <errno.h>

#include <signal.h>


#include <sys/stat.h>
#include <fcntl.h>

#include <dirent.h>

#define NOT_OK_EXIT(code, msg); {if(code == -1){perror(msg); exit(-1);} }

#define MAX_PATH_LEN (256)

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
//symlink
int copy_dev(char * des_path, char *src_path){

	int fd,fd2;
    char buff[1024];
    int len;

	fd = open(src_path,O_RDWR|O_CREAT);
	fd2 = open(des_path,O_RDWR|O_CREAT);
	while(len = read(fd,buff,1024))
	{
		write(fd2,buff,len);
	}
	return 0;

}

static void trave_dir(char* path) {
    DIR *d = NULL;
    struct dirent *dp = NULL; /* readdir函数的返回值就存放在这个结构体中 */
    struct stat st;    
    char p[MAX_PATH_LEN] = {0};
    char bp[MAX_PATH_LEN] = {0};
    if(stat(path, &st) < 0 || !S_ISDIR(st.st_mode)) {
        printf("invalid path: %s\n", path);
        return;
    }

    if(!(d = opendir(path))) {
        printf("opendir[%s] error: %m\n", path);
        return;
    }

    while((dp = readdir(d)) != NULL) {
        /* 把当前目录.，上一级目录..及隐藏文件都去掉，避免死循环遍历目录 */
        if((!strncmp(dp->d_name, ".", 1)) || (!strncmp(dp->d_name, "..", 2)))
            continue;

        snprintf(p, sizeof(p) - 1, "%s/%s", path, dp->d_name);
        snprintf(bp, sizeof(bp) - 1, "%s/%s", "containerc_roots/rootfs/dev", dp->d_name);
        stat(p, &st);
        if(!S_ISDIR(st.st_mode)) {
            //printf("%s\n", bp);
            mknod(bp, S_IFIFO|0666, 0);
            if(mount(p, bp, "none", MS_BIND, NULL)){
                printf("%s \n", bp);
                perror("bind dev");
            }
        } else {
            printf("dir %s/\n", dp->d_name);
            mkdir(bp ,0775);
        }
    }
    closedir(d);

    return;
}


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

    // if(mount("/dev", "./containerc_roots/rootfs/dev", "none", MS_BIND, NULL)){
    //     perror("bind dev");
    // }
    trave_dir("/dev");
    // if (mount("udev", "containerc_roots/rootfs/dev", "devtmpfs", 0, NULL)!=0) {
    //     perror("dev");
    // }
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
    sprintf(path, "/proc/%d/uid_map", pid);
    FILE* uid_map = fopen(path, "w");
    fprintf(uid_map, "%d %d %d", inside_id, outside_id, length);
    fclose(uid_map);
}
void set_gid_map(pid_t pid, int inside_id, int outside_id, int length) {
    char path[256];
    sprintf(path, "/proc/%d/gid_map", pid);
    FILE* gid_map = fopen(path, "w");
    fprintf(gid_map, "%d %d %d", inside_id, outside_id, length);
    fclose(gid_map);
}

int child_main(void* args) {
    cap_t caps;
    printf("在子进程中! %d \n", getpid());
    pid_t pid = getpid();
    set_uid_map(pid, 0, 1000, 1);
    set_gid_map(pid, 0, 1000, 1);
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



void list_caps() {
    int ret;
    struct __user_cap_header_struct    cap_header;
    struct __user_cap_data_struct cap_data[2];
    ret = capget(&cap_header, NULL);
    if (ret < 0) {
        fprintf(stderr, "capget error: %s", strerror(errno));
    }
    memset(cap_data, 0, sizeof(cap_data));
    cap_header.pid = getpid();
    ret = capget(&cap_header, &cap_data[0]);
    if (ret < 0) {
        fprintf(stderr, "capget error: %s", strerror(errno));
    } else {
        printf("Capabilities of process %8d is:", cap_header.pid);
        printf(" CapInh: 0x%08x%08x", cap_data[1].inheritable, cap_data[0].inheritable);
        printf(" CapEff: 0x%08x%08x", cap_data[1].effective, cap_data[0].effective);
        printf(" CapPrm: 0x%08x%08x", cap_data[1].permitted, cap_data[0].permitted);
        printf("\n");
    }
}


int set_caps(struct __user_cap_data_struct cap_data[2]) {
    int ret = 0;
    struct __user_cap_header_struct    cap_header;
    ret = capget(&cap_header, NULL);
    if (ret < 0) {
        fprintf(stderr, "capget error: %s", strerror(errno));
    }

    cap_header.pid = getpid();
    ret = capset(&cap_header, &cap_data[0]);
    if (ret < 0) {
        fprintf(stderr, "capget error: %s", strerror(errno));
    }
    return ret;
}

int set_all_cap(){
    struct __user_cap_data_struct cap_data[2];
    cap_data[0].inheritable = 0xffffffff;
    cap_data[1].inheritable = 0xffffffff;

    cap_data[0].effective = 0xffffffff;
    cap_data[1].effective = 0xffffffff;

    cap_data[0].permitted = 0xffffffff;
    cap_data[1].permitted = 0xffffffff;
    set_caps(cap_data);

    list_caps();
}

static int container_root(void *param){
    struct container_run_para *cparam = (struct container_run_para*)param;    
    //设置主机名
    printf("host name %s \n", cparam->hostname);
    sethostname(cparam->hostname, strlen(cparam->hostname));

    //设置环境变量
    setnewenv();
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
    int stat;

    //stat = setuid(geteuid());
    struct container_run_para  para;
        //获取container ip
    char ipv4[32] = {0};
    //设置主机名
    pid_t child_pid;
    pid_t pid = getpid();
    list_caps();
    printf("sub process ! %d uid %d gid %d  gid_cap %x\n", pid, getuid(), getegid(), CAP_SETGID);
    
    set_uid_map(pid, 0, 1000, 1);
    set_gid_map(pid, 0, 1000, 1);

    printf("eUID = %ld;  eGID = %ld;  \n",
            (long) geteuid(), (long) getegid());
    set_all_cap();

    // veth_create("veth0", "veth1");
    // veth_up("veth0");
    // /* ??veth0????docker?????? */
    // veth_addbr("veth0", "docker0");
    
    
    //  //获取container ip
    new_containerip(ipv4, sizeof(ipv4));
    
    para.hostname = (char *)param;
    para.ifindex = veth_ifindex("veth1");
    para.container_ip = ipv4;

    child_pid = clone(container_root,
                      container_stack_pid + sizeof(container_stack_pid),
                      CLONE_NEWPID | CLONE_NEWNET | CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWIPC |SIGCHLD, 
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
    if(unshare(CLONE_NEWUSER)!=0){
        printf("failed to create new user namespace \n");
    }
    
 /**
     * 1、创建并启动子进程，调用该函数后，父进程将继续往后执行，也就是执行后面的waitpid
     * 2、栈是从高位向低位增长，所以这里要指向高位地址
     * 3、SIGCHLD 表示子进程退出后 会发送信号给父进程 与容器技术无关
     * 4、创建各个namespace
     */
    container_run(argv[1]);
    // //child_pid = clone(container_run,
    //                   container_stack + sizeof(container_stack),
    //                   CLONE_NEWUSER | SIGCHLD, 
    //                   argv[1]);
//|
 //                     CLONE_NEWPID|CLONE_NEWNET|CLONE_NEWNS|CLONE_NEWUTS| SIGCHLD,
    /* ??veth???????namespace?? */
    //veth_network_namespace("veth1", child_pid);
    
   // NOT_OK_EXIT(child_pid, "clone");

    /* ??????????? */
    //waitpid(child_pid, NULL, 0);

    return 0;
}


