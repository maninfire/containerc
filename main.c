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
#include <net/if.h>
#include <grp.h>

#define NOT_OK_EXIT(code, msg); {if(code == -1){perror(msg); exit(-1);} }

#define MAX_PATH_LEN (1024)

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
        printf("Capabilities of process %8d is:\n", cap_header.pid);
        printf(" CapInh: 0x%08x%08x \n", cap_data[1].inheritable, cap_data[0].inheritable);
        printf(" CapEff: 0x%08x%08x \n", cap_data[1].effective, cap_data[0].effective);
        printf(" CapPrm: 0x%08x%08x \n", cap_data[1].permitted, cap_data[0].permitted);
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

static void trave_dir(char* path, char *dest_path, int type) {
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
        printf("opendir[%s] error: %m \n", path);
        return;
    }

    while((dp = readdir(d)) != NULL) {
        /* 把当前目录.，上一级目录..及隐藏文件都去掉，避免死循环遍历目录 */
        if((!strncmp(dp->d_name, ".", 1)) || (!strncmp(dp->d_name, "..", 2)))
            continue;

        snprintf(p, sizeof(p) - 1, "%s/%s", path, dp->d_name);
        snprintf(bp, sizeof(bp) - 1, "%s/%s", dest_path, dp->d_name);
        stat(p, &st);
        if(!S_ISDIR(st.st_mode)) {
            //printf("%s\n", bp);
            if(type == 0)
                mknod(bp, S_IFIFO|0666, 0);
            else if(type == 1)
                creat(bp,0755);
            if(mount(p, bp, "none", MS_BIND, NULL)){
                printf("%s \n", bp);
                perror("bind dev");
            }
        } else {
            mkdir(bp ,0775);
            if(strstr("net", dp->d_name))
                trave_dir(p, bp, 0);
            if(strstr("class", p) || strstr("device", p))
                trave_dir(p, bp, 1);
            printf("dir %s %s\n", p, bp);

        }
    }
    closedir(d);

    return;
}

int nsenternew(){
    int fd = 0;
    fd = open("containerc_roots/rootfs/var/run/netns/mynet",O_RDONLY);
    if(fd)
        if(setns(fd, 0)==-1)
            perror("net ns");
    return 0;
}

int en3get(){
        /*绑定net namespace */
    // if ( mount("/proc/self/ns/net", "./containerc_roots/rootfs/var/run/netns/mynet", "none", MS_BIND, NULL)!=0 ) {
    //     perror("net");
    // }

    //nsenternew();
    //trave_dir("/sys", "containerc_roots/rootfs/dev", 1);

    if (mount("/sys/devices", "./containerc_roots/rootfs/sys/devices", "none", MS_BIND, NULL)!=0){
        perror("device ens33");
    }

    if (mount("/sys/class/net/", "./containerc_roots/rootfs/sys/class/net", "none", MS_BIND, NULL)!=0){
        perror("class ens33");
    }
}

static void mount_root() 
{


    mount("none", "/", NULL, MS_REC|MS_PRIVATE, NULL);
    //remount "/proc" to make sure the "top" and "ps" show container's information
    if (mount("proc", "containerc_roots/rootfs/proc", "proc", 0, NULL) !=0 ) {
        perror("proc");
    }

    en3get();

    if (mount("none", "containerc_roots/rootfs/tmp", "tmpfs", 0, NULL)!=0) {
        perror("tmp");
    }

    trave_dir("/dev", "containerc_roots/rootfs/dev", 0);
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


int set_uid_map(pid_t pid, int inside_id, int outside_id, int length) {
    char path[256]={0};
    char buf[128]={0}; // 确保这个缓冲区足够大以存放格式化后的字符串
    int fd = 0;    
    // 使用snprintf来避免潜在的缓冲区溢出
    snprintf(path, sizeof(path), "/proc/%d/uid_map", pid);
    fd = open(path, O_WRONLY);
    if (fd == -1) {
        perror("open");
        return -1; // 返回错误代码
    }

    // 使用snprintf来格式化字符串，然后使用write来写入

    if (snprintf(buf, sizeof(buf), "%d %d %d", 
                    inside_id, outside_id, length) >= sizeof(buf)) {
        perror("snprintf");
        close(fd);
        return -1; // 缓冲区太小，无法容纳格式化后的字符串
    }
    printf("uid_map fd %d path [%s]; content: [%s] len %ld\n", 
                                        fd, path, buf, strlen(buf));
    ssize_t bytes_written = write(fd, buf, strlen(buf));
    if (bytes_written == -1) {
        perror("write");
        close(fd);
        return -1; // 写入失败
    }

    close(fd);
    return 0; // 成功完成
}

void set_gid_map(pid_t pid, int inside_id, int outside_id, int length) {
    char path[256];
    char buf[32];
    int fd;

    snprintf(path, sizeof(path), "/proc/%d/gid_map", pid);
    fd = open(path, O_WRONLY);
    if (fd == -1) {
        perror("open");
        return;
    }

    snprintf(buf, sizeof(buf), "%d %d %d", inside_id, outside_id, length);
    printf("gid_map fd %d path: [%s]; content [%s] len %ld\n",
                                         fd, path, buf, strlen(buf));    
    if (write(fd, buf, strlen(buf)) == -1) {
        perror("write");
    }
    close(fd);
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

int get_groups_show(){
    gid_t *groups;
    int ngroups = getgroups(0, NULL);
    if (ngroups == -1) {
        perror("getgroups");
        exit(EXIT_FAILURE);
    }

    // 分配内存来存储组 ID 列表
    groups = (gid_t *)malloc(ngroups * sizeof(gid_t));
    if (groups == NULL) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }

    // 获取组 ID 列表
    if (getgroups(ngroups, groups) == -1) {
        perror("getgroups");
        free(groups);
        exit(EXIT_FAILURE);
    }

    // 获取并输出每个组的名称
    printf("Current user belongs to the following groups:\n");
    for (int i = 0; i < ngroups; i++) {
        struct group *grp = getgrgid(groups[i]);
        if (grp != NULL) {
            printf("%s ", grp->gr_name);
        } else {
            printf("%d ", groups[i]);
        }
    }
    printf("\n");

    // 释放内存
    free(groups);
    return 0;
}


static int container_root(void *param){
    struct container_run_para *cparam = (struct container_run_para*)param;    
    //设置主机名
    printf("host name %s pid %d uid %d gid %d\n", cparam->hostname, getpid(), getuid(), getegid());
    sethostname(cparam->hostname, strlen(cparam->hostname));

    //设置环境变量
    setnewenv();
    mount_root();

    sleep(1);
    set_all_cap();
    gid_t groups[] = {0};
   size_t ngroups = sizeof(groups) / sizeof(groups[0]);

    // 设置补充组列表
    // if (setgroups(1, groups) == -1) {
    //     perror("setgroups");
    //     exit(EXIT_FAILURE);
    // }
    // printf("Current process supplementary groups:\n");

//     int i;
//     for (i = 0; i < ngroups; i++) {
//         printf("Group ID: %d\n", groups[i]);
//     }
//get_groups_show();
    // veth_create("veth0", "veth1");
    // veth_up("veth0");
 
    // veth_addbr("veth0", "docker0");

    // veth_newname("veth1", "eth0");
    // veth_up("eth0");
    // printf("ip %s \n", cparam->container_ip);
    // veth_config_ipv4("eth0", "192.168.3.5");
    execv(container_args[0], container_args);
    //execv(child_args[0], child_args);
    return 0;
}

void set_groups(char *cmd, int main_uid) {

    char buf[100];
    int fd;

    snprintf(buf, sizeof(buf), "/proc/%d/setgroups", main_uid);    
    if(!cmd)
        return;
    fd = openat(AT_FDCWD, buf, O_WRONLY);
    if (fd == -1) {
        perror("openat");
        return;
    }

    // 清空补充组列表
    if (write(fd, cmd, strlen(cmd)) == -1) {
        perror("write");
    }

    close(fd);
}
/**
 * 容器启动 -- 实际为子进程启动
 */
static int container_run(void *param, int main_uid)
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
    printf("process ! %d uid %d gid %d  gid_cap %x\n", pid, getuid(), getegid(), CAP_SETGID);
    
    printf("eUID = %ld;  eGID = %ld;  \n",
            (long) geteuid(), (long) getegid());    
    
    set_all_cap();
    set_groups( "deny", pid );
    set_uid_map(pid, 0, main_uid, 1);
    set_gid_map(pid, 0, main_uid, 1);

    printf("eUID = %ld;  eGID = %ld;  \n",
            (long) geteuid(), (long) getegid());
    // set_all_cap();            
    // set_groups("allow", pid);
    // veth_create("veth0", "veth1");
    // veth_up("veth0");
 
    // veth_addbr("veth0", "docker0");
        
    // //  //获取container ip
    new_containerip(ipv4, sizeof(ipv4));
    
    para.hostname = (char *)param;
    para.ifindex = veth_ifindex("veth1");
    para.container_ip = ipv4;

    child_pid = clone(container_root,
                      container_stack_pid + sizeof(container_stack_pid),
                      CLONE_NEWPID  | CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWIPC |SIGCHLD, 
                      &para);
//| CLONE_NEWNET

    waitpid(child_pid, NULL, 0);

    return 0;
}
 
int main(int argc, char *argv[])
{
    struct container_run_para  para;
    int main_uid;

    char ipv4[32] = {0};
    main_uid = getuid();
    printf("process uid %d gid %d  gid_cap %x\n", getuid(), getegid(), CAP_SETGID);
    if (argc < 2) {
        printf("Usage: %s <child-hostname>\n", argv[0]);
        return -1;
    }
    //获取docker0网卡ip地址
    if(unshare(CLONE_NEWUSER)!=0){
        printf("failed to create new user namespace \n");
    }
    
    /**
     * 1、创建并启动子进程，调用该函数后，父进程将继续往后执行，也就是执行后面的waitpid
     * 2、栈是从高位向低位增长，所以这里要指向高位地址
     * 3、SIGCHLD 表示子进程退出后 会发送信号给父进程 与容器技术无关
     * 4、创建各个namespace
     */
    
    container_run( argv[1], main_uid );
    // child_pid = clone(container_run,
    //                   container_stack + sizeof(container_stack),
    //                   CLONE_NEWUSER | SIGCHLD, 
    //                   argv[1]);

    //                     CLONE_NEWPID|CLONE_NEWNET|CLONE_NEWNS|CLONE_NEWUTS| SIGCHLD,

    //veth_network_namespace("veth1", child_pid);
    
    return 0;
}


