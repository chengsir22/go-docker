package fs

import "go-docker/cgroups/resource"

// SubsystemsIns 通过不同的subsystem初始化实例创建资源限制处理链数组
var SubsystemsIns = []resource.Subsystem{
	&CpusetSubSystem{},
	&MemorySubSystem{},
	&CpuSubSystem{},
}
