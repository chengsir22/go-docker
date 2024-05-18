package nsenter

/*
#define _GNU_SOURCE
#include <unistd.h>
#include <errno.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

__attribute__((constructor)) void enter_namespace(void) {
   // 这里的代码会在Go运行时启动前执行，它会在单线程的C上下文中运行
	char *go_docker_pid;
	go_docker_pid = getenv("go_docker_pid");
	if (go_docker_pid) {
		fprintf(stdout, "got go_docker_pid=%s\n", go_docker_pid);
	} else {
		fprintf(stdout, "missing go_docker_pid env skip nsenter");
		// 如果没有指定PID就不需要继续执行，直接退出
		return;
	}
	char *go_docker_cmd;
	go_docker_cmd = getenv("go_docker_cmd");
	if (go_docker_cmd) {
		fprintf(stdout, "got go_docker_cmd=%s\n", go_docker_cmd);
	} else {
		fprintf(stdout, "missing go_docker_cmd env skip nsenter");
		// 如果没有指定命令也是直接退出
		return;
	}
	int i;
	char nspath[1024];
	// 需要进入的5种namespace
	char *namespaces[] = { "ipc", "uts", "net", "pid", "mnt" };

	for (i=0; i<5; i++) {
		// 拼接对应路径，类似于/proc/pid/ns/ipc这样
		sprintf(nspath, "/proc/%s/ns/%s", go_docker_pid, namespaces[i]);
		int fd = open(nspath, O_RDONLY);
		if (fd == -1) {
			fprintf(stderr, "Failed to open %s: %s\n", nspath, strerror(errno));
			return;
		}
		// 执行setns系统调用，进入对应namespace
		if (setns(fd, 0) == -1) {
			fprintf(stderr, "setns on %s namespace failed: %s\n", namespaces[i], strerror(errno));
		} else {
			fprintf(stdout, "setns on %s namespace succeeded\n", namespaces[i]);
		}
		close(fd);
	}
	// 在进入的Namespace中执行指定命令，然后退出
	int res = system(go_docker_cmd);
	exit(res);
}
*/
import "C"
