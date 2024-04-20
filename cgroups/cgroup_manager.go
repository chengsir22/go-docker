package cgroups

import (
	"github.com/chengsir22/go-docker/cgroups/subsystems"
	"github.com/sirupsen/logrus"
)

type CgroupManager struct {
	Path     string
	Resource *subsystems.ResourceConfig
}

func NewCgroupManager(path string) *CgroupManager {
	return &CgroupManager{
		Path:     path,
	}
}

// 将进程 pid 加入到 cgroup 中
func (c *CgroupManager) Apply(pid int) error {
	for _, subSysIns := range(subsystems.SubsystemsIns) {
		subSysIns.Apply(c.Path, pid)
	} 
	return nil
}

// 设置 cgroup 资源限制
func (c *CgroupManager) Set(res *subsystems.ResourceConfig) error {
	for _, subSysIns := range(subsystems.SubsystemsIns) {
		subSysIns.Set(c.Path, res)
	} 
	return nil
}

// 移除 cgroup
func (c *CgroupManager) Destroy() error {
	for _, subSysIns := range(subsystems.SubsystemsIns){
		if err := subSysIns.Remove(c.Path); err != nil {
			logrus.Warnf("remove cgroup path %s error %v", c.Path, err)
		}
	} 
	return nil
}