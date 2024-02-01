package cgroups

import (
	"fmt"
	"go-docker/log"
	"os"
	"os/exec"
	"path"
	"strconv"
)

const (
	cgroupsPath = "/sys/fs/cgroup"
	dockerName  = "go-docker"
)

func ConfigDefaultCgroups(pid int, containerName string) error {

	var (
		Path = path.Join(cgroupsPath, fmt.Sprintf("%s_%s", dockerName, containerName))
	)

	// 创建容器的控制目录
	if err := os.MkdirAll(Path, 0700); err != nil {
		return fmt.Errorf("create cgroup path fail err=%s", err)
	}
	if err := os.WriteFile(path.Join(Path, "cgroup.procs"), []byte(strconv.Itoa(pid)), 0644); err != nil {
		return fmt.Errorf("write cpu tasks fail err=%s", err)
	}
	// 设置cpu
	if err := os.WriteFile(path.Join(Path, "cgroup.subtree_control"), []byte("+cpu"), 0700); err != nil {
		return fmt.Errorf("write cgroup.subtree_control fail err=%s", err)
	}
	// 设置cpu
	if err := os.WriteFile(path.Join(Path, "cpu.max"), []byte("50000"), 0700); err != nil {
		return fmt.Errorf("write cpu quota us fail err=%s", err)
	}

	// 设置内存
	if err := os.WriteFile(path.Join(Path, "cgroup.subtree_control"), []byte("+memory"), 0700); err != nil {
		return fmt.Errorf("write cgroup.subtree_control fail err=%s", err)
	}
	if err := os.WriteFile(path.Join(Path, "memory.max"), []byte("200m"), 0700); err != nil {
		return fmt.Errorf("write memory limit bytes fail err=%s", err)
	}
	return nil
}

func CleanCgroupsPath(containerName string) error {
	output, err := exec.Command("rmdir", path.Join(cgroupsPath, fmt.Sprintf("%s_%s", dockerName, containerName))).Output()
	if err != nil {
		log.Error("rmdir fail err=%s output=%s", err, string(output))
	}
	return nil
}
