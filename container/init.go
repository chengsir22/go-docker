package container

import (
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

// RunContainerInitProcess 启动容器的init进程
func RunContainerInitProcess() error {
	pipe := os.NewFile(uintptr(3), "pipe")
	defer pipe.Close()
	msg, err := io.ReadAll(pipe)
	if err != nil {
		log.Errorf("init read pipe error %v", err)
		return nil
	}
	msgStr := string(msg)
	cmdArray := strings.Split(msgStr, " ")
	if len(cmdArray) == 0 {
		return errors.New("RunContainerInitProcess error, cmdArray is nil")
	}

	setUpMount()

	path, err := exec.LookPath(cmdArray[0])
	if err != nil {
		log.Errorf("Exec loop path error %v", err)
		return err
	}
	log.Infof("Find path %s", path)
	if err = syscall.Exec(path, cmdArray[0:], os.Environ()); err != nil {
		log.Errorf("RunContainerInitProcess exec :" + err.Error())
	}
	return nil
}

// Init 挂载点
func setUpMount() {
	pwd, err := os.Getwd()
	if err != nil {
		log.Errorf("Get current location error %v", err)
		return
	}
	log.Infof("Current location is %s", pwd)

	err = syscall.Mount("", "/", "", syscall.MS_PRIVATE|syscall.MS_REC, "")

	err = pivotRoot(pwd)
	if err != nil {
		log.Errorf("pivotRoot failed,detail: %v", err)
		return
	}

	// mount /proc
	defaultMountFlags := syscall.MS_NOEXEC | syscall.MS_NOSUID | syscall.MS_NODEV
	syscall.Mount("proc", "/proc", "proc", uintptr(defaultMountFlags), "")
	// 由于前面 pivotRoot 切换了 rootfs，因此这里重新 mount 一下 /dev 目录
	// tmpfs 是基于 件系 使用 RAM、swap 分区来存储。
	// 不挂载 /dev，会导致容器内部无法访问和使用许多设备，这可能导致系统无法正常工作
	syscall.Mount("tmpfs", "/dev", "tmpfs", syscall.MS_NOSUID|syscall.MS_STRICTATIME, "mode=755")
}

func pivotRoot(root string) error {
	if err := syscall.Mount(root, root, "bind", syscall.MS_BIND|syscall.MS_REC, ""); err != nil {
		return errors.Wrap(err, "mount rootfs to itself")
	}
	// 创建 rootfs/.pivot_root 目录用于存储 old_root
	pivotDir := filepath.Join(root, ".pivot_root")
	if err := os.Mkdir(pivotDir, 0777); err != nil {
		return err
	}
	// pivot_root，即将当前根目录（rootfs）移动到 pivotDir，之后将新的根目录切换到root
	if err := syscall.PivotRoot(root, pivotDir); err != nil {
		return errors.WithMessagef(err, "pivotRoot failed,new_root:%v old_put:%v", root, pivotDir)
	}
	// 修改当前的工作目录到根目录
	if err := syscall.Chdir("/"); err != nil {
		return errors.WithMessage(err, "chdir to / failed")
	}

	// 最后再把old_root umount了，即 umount rootfs/.pivot_root
	// 由于当前已经是在 rootfs 下了，就不能再用上面的rootfs/.pivot_root这个路径了,现在直接用/.pivot_root这个路径即可
	pivotDir = filepath.Join("/", ".pivot_root")
	if err := syscall.Unmount(pivotDir, syscall.MNT_DETACH); err != nil {
		return errors.WithMessage(err, "unmount pivot_root dir")
	}
	// 删除临时文件夹
	return os.Remove(pivotDir)
}
