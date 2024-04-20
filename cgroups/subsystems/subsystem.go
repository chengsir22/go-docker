package subsystems


// go-docker run -ti -m 100m -cpuset 1 -cpushare 512 /bin/bash
type ResourceConfig struct {
	MemoryLimit string
	CpuShare    string
	CpuSet      string
}

type subsystem interface {
	Name() string
	Set(path string, res *ResourceConfig) error
	Apply(path string, pid int) error
	Remove(path string) error
}

var (
	SubsystemsIns = []subsystem{
		&CpusetSubSystem{},
		&CpuSubSystem{},
		&MemorySubSystem{},
	}
)