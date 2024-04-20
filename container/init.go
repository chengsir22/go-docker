package container

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
	"syscall"

	log "github.com/sirupsen/logrus"
)

func RunContainerInitProcess() error {
	cmdArray := readUserCommand()
	if cmdArray == nil || len(cmdArray) == 0 {
		return fmt.Errorf("run container get user command error, cmdArray is nil")
	}
	// MS_NOEXEC 防止在挂载的文件系统上执行任何可执行文件
	// MS_NOSUID 防止 set-user-ID（SUID）和 set-group-ID（SGID）权限位生效
	// MS_NODEV 禁止在挂载的文件系统上访问设备文件
	defaultMountFlags := syscall.MS_NOEXEC | syscall.MS_NOSUID | syscall.MS_NODEV
	syscall.Mount("proc", "/proc", "proc", uintptr(defaultMountFlags), "")
	path, err := exec.LookPath(cmdArray[0])
	if err != nil {
		log.Errorf("Exec LookPath error %v", cmdArray[0])
		return err
	}
	log.Infof("Find path %s", path)
	// 在一个已经存在的进程上下文中，完全替换成另一个程序时
	if err := syscall.Exec(path, cmdArray, os.Environ()); err != nil {
		log.Errorf("Exec Failed %v", err)
		return err
	}
	return nil
}

func readUserCommand() []string {
	pipe := os.NewFile(uintptr(3), "pipe")
	defer pipe.Close()
	msg, err := ioutil.ReadAll(pipe)
	if err != nil {
		log.Errorf("init read pipe error %v", err)
		return nil
	}
	return strings.Split(string(msg), " ")
}
