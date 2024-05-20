package cgroups

import (
	"os"
	"sync"

	"golang.org/x/sys/unix"
)

const (
	unifiedMountpoint = "/sys/fs/cgroup"
)

var (
	isUnifiedOnce sync.Once
	isCgroupV2    bool
)

// IsCgroup2UnifiedMode returns whether we are running in cgroup v2 unified mode.
func IsCgroup2UnifiedMode() bool {
	isUnifiedOnce.Do(func() {
		var st unix.Statfs_t
		err := unix.Statfs(unifiedMountpoint, &st)
		if err != nil && os.IsNotExist(err) {
			isCgroupV2 = false
			return
		}
		isCgroupV2 = st.Type == unix.CGROUP2_SUPER_MAGIC
	})
	return isCgroupV2
}
