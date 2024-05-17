package fs2

import (
	"go-docker/cgroups/resource"
)

var Subsystems = []resource.Subsystem{
	&CpusetSubSystem{},
	&MemorySubSystem{},
	&CpuSubSystem{},
}
