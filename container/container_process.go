package container

import (
	"fmt"
	"go-docker/utils"
	"os"
	"os/exec"
	"syscall"

	log "github.com/sirupsen/logrus"
)

const (
	RUNNING       = "running"
	STOP          = "stopped"
	Exit          = "exited"
	InfoLoc       = "/var/lib/go-docker/containers/"
	InfoLocFormat = InfoLoc + "%s/"
	ConfigName    = "config.json"
	IDLength      = 10
	LogFile       = "%s.log"
)

type Info struct {
	Pid         string   `json:"pid"`         // 容器的init进程在宿主机上的 PID
	Id          string   `json:"id"`          // 容器Id
	Name        string   `json:"name"`        // 容器名
	Command     string   `json:"command"`     // 容器内init运行命令
	CreatedTime string   `json:"createTime"`  // 创建时间
	Status      string   `json:"status"`      // 容器的状态
	Volume      string   `json:"volume"`      // 容器挂载的 volume
	NetworkName string   `json:"networkName"` // 容器所在的网络
	PortMapping []string `json:"portmapping"` // 端口映射
	IP          string   `json:"ip"`
}

// NewParentProcess 构建 command 用于启动一个新进程
func NewParentProcess(tty bool, volume, containerId, imageName string, envSlice []string) (*exec.Cmd, *os.File) {
	readPipe, writePipe, err := os.Pipe()
	if err != nil {
		log.Errorf("New pipe error %v", err)
		return nil, nil
	}
	cmd := exec.Command("/proc/self/exe", "init")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUTS | syscall.CLONE_NEWPID | syscall.CLONE_NEWNS | syscall.CLONE_NEWNET | syscall.CLONE_NEWIPC | syscall.CLONE_NEWUSER,
		UidMappings: []syscall.SysProcIDMap{
			{
				ContainerID: 0,
				HostID:      os.Geteuid(),
				Size:        1,
			},
		},
		GidMappings: []syscall.SysProcIDMap{
			{
				ContainerID: 0,
				HostID:      os.Getgid(),
				Size:        1,
			},
		},
	}
	if tty {
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	} else {
		// 对于后台运行容器，将 stdout、stderr 重定向到日志文件中，便于后续查看
		dirPath := fmt.Sprintf(InfoLocFormat, containerId)
		if err = os.MkdirAll(dirPath, 0622); err != nil {
			log.Errorf("NewParentProcess mkdir %s error %v", dirPath, err)
			return nil, nil
		}
		stdLogFilePath := dirPath + GetLogfile(containerId)
		stdLogFile, err := os.Create(stdLogFilePath)
		if err != nil {
			log.Errorf("NewParentProcess create file %s error %v", stdLogFilePath, err)
			return nil, nil
		}
		cmd.Stdout = stdLogFile
		cmd.Stderr = stdLogFile
	}
	cmd.Env = append(os.Environ(), envSlice...)
	cmd.ExtraFiles = []*os.File{readPipe}
	NewWorkSpace(containerId, imageName, volume)
	cmd.Dir = utils.GetMerged(containerId)
	return cmd, writePipe
}
