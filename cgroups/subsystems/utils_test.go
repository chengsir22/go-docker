package subsystems

import "testing"

func TestFindCgroupMountPonit(t *testing.T) {
	t.Logf("cpu subsystem mount point %v\n", FindCgroupMountpoint("cpu"))
	t.Logf("cpuset subsystem mount point %v\n", FindCgroupMountpoint("cpuset"))
	t.Logf("memory subsystem mount point %v\n", FindCgroupMountpoint("memory"))
}
