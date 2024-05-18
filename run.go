package main

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"go-docker/cgroups"
	"go-docker/cgroups/resource"
	"go-docker/container"
	"go-docker/network"
	"os"
	"strconv"
	"strings"
)

// Run 执行具体 command
func Run(tty bool, comArray, envSlice []string, res *resource.ResourceConfig, volume, containerName, imageName string,
	net string, portMapping []string) {
	containerId := container.GenerateContainerID() // 生成 10 位容器 id

	// start container
	parent, writePipe := container.NewParentProcess(tty, volume, containerId, imageName, envSlice)
	if parent == nil {
		log.Errorf("New parent process error")
		return
	}
	// 启动init进程
	if err := parent.Start(); err != nil {
		log.Errorf("Run parent.Start err:%v", err)
		return
	}

	// 创建cgroup manager, 并通过调用set和apply设置资源限制并使限制在容器上生效
	cgroupManager := cgroups.NewCgroupManager("docker-cgroup-manager/" + containerId)
	_ = cgroupManager.Set(res)
	_ = cgroupManager.Apply(parent.Process.Pid)

	var containerIP string
	// 如果指定了网络信息则进行配置 go-docker run -it -p 80:80 --net testbridgenet xxxx
	if net != "" {
		// config container network
		containerInfo := &container.Info{
			Id:          containerId,
			Pid:         strconv.Itoa(parent.Process.Pid),
			Name:        containerName,
			PortMapping: portMapping,
		}
		ip, err := network.Connect(net, containerInfo)
		if err != nil {
			log.Errorf("Error Connect Network %v", err)
			return
		}
		containerIP = ip.String()
	}

	// record container info
	containerInfo, err := container.RecordContainerInfo(parent.Process.Pid, comArray, containerName, containerId,
		volume, net, containerIP, portMapping)
	if err != nil {
		log.Errorf("Record container info error %v", err)
		return
	}

	// 在子进程创建后才能通过pipe来发送参数
	sendInitCommand(comArray, writePipe)
	// 如果是tty，那么父进程等待，就是前台运行，否则就是跳过，实现后台运行
	if tty {
		_ = parent.Wait()
		defer cgroupManager.Destroy()
		container.DeleteWorkSpace(containerId, volume)
		err := container.DeleteContainerInfo(containerId)
		if err != nil {
			fmt.Println("delete container info error %v", err)
		}
		if net != "" {
			network.Disconnect(net, containerInfo)
		}
	}
}

// sendInitCommand 通过writePipe将指令发送给子进程
func sendInitCommand(comArray []string, writePipe *os.File) {
	command := strings.Join(comArray, " ")
	log.Infof("command all is %s", command)
	writePipe.WriteString(command)
	writePipe.Close()
}
