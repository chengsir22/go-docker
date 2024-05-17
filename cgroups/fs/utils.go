package fs

import (
	"bufio"
	"os"
	"path"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/pkg/errors"
)

// getCgroupPath 找到cgroup在文件系统中的绝对路径
func getCgroupPath(subsystem string, cgroupPath string, autoCreate bool) (string, error) {
	// 不需要自动创建就直接返回
	cgroupRoot := findCgroupMountpoint(subsystem)
	absPath := path.Join(cgroupRoot, cgroupPath)
	if !autoCreate {
		return absPath, nil
	}
	// 指定自动创建时才判断是否存在
	_, err := os.Stat(absPath)
	// 只有不存在才创建
	if err != nil && os.IsNotExist(err) {
		err = os.Mkdir(absPath, 0755)
		return absPath, err
	}
	// 其他错误或者没有错误都直接返回，如果err=nil,那么errors.Wrap(err, "")也会是nil
	return absPath, errors.Wrap(err, "create cgroup")
}

// findCgroupMountpoint 通过/proc/self/mountinfo找出挂载了某个subsystem的hierarchy cgroup根节点所在的目录
func findCgroupMountpoint(subsystem string) string {
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return ""
	}
	defer f.Close()
	// 这里主要根据各种字符串处理来找到目标位置
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		txt := scanner.Text()
		// 然后按照空格分割
		fields := strings.Split(txt, " ")
		subsystems := strings.Split(fields[len(fields)-1], ",")
		for _, opt := range subsystems {
			if opt == subsystem {
				// 如果等于指定的 subsystem，那么就返回这个挂载点跟目录，就是第四个元素，
				// 这里就是`/sys/fs/cgroup/memory`,即我们要找的根目录
				return fields[4]
			}
		}
	}

	if err = scanner.Err(); err != nil {
		log.Error("read err:", err)
		return ""
	}
	return ""
}
