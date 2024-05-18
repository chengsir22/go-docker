从零实现一个简单的docker  
- 命令行工具 cli https://cli.urfave.org/
## 容器初始化
初始化时mount /proc 时要注意，mount namespace 是 shared by default，需要把所有挂载点的传播类型改为 private，避免本 namespace 中的挂载事件对其他 namespace 的影响
```go
syscall.Mount("", "/", "", syscall.MS_PRIVATE|syscall.MS_REC, "")

defaultMountFlags := syscall.MS_NOEXEC | syscall.MS_NOSUID | syscall.MS_NODEV  
_ = syscall.Mount("proc", "/proc", "proc", uintptr(defaultMountFlags), "")
```
## cgroup
cgroup 只配置内存限制，CPU 时间片权重，CPU核心数
```go
// ResourceConfig 用于传递资源限制配置的结构体，包含内存限制，CPU 时间片权重，CPU核心数
type ResourceConfig struct {
	MemoryLimit string
	CpuCfsQuota int        // CPU 时间的配额 
	CpuSet      string     // 进程可以运行的 CPU 核心或集合
}
```
每个配置都要实现 Subsystem 接口
```go
// Subsystem 接口，每个Subsystem可以实现下面的4个接口，
// 这里将cgroup抽象成了path,原因是cgroup在hierarchy的路径，便是虚拟文件系统中的虚拟路径
// Set、Apply、Remove 这3个接口都判断一下，如果没有传配置信息进来就不处理，直接返回。
type Subsystem interface {
	// Name 返回当前Subsystem的名称,比如cpu、memory
	Name() string
	// Set 设置某个cgroup在这个Subsystem中的资源限制
	Set(path string, res *ResourceConfig) error
	// Apply 将进程添加到某个cgroup中
	Apply(path string, pid int) error
	// Remove 移除某个cgroup
	Remove(path string) error
}
```
### 判断cgroup版本
```go
var (  
    isUnifiedOnce sync.Once  
    isUnified     bool  
)
// IsCgroup2UnifiedMode returns whether we are running in cgroup v2 unified mode.
func IsCgroup2UnifiedMode() bool {
	isUnifiedOnce.Do(func() {
		var st unix.Statfs_t
		err := unix.Statfs("/sys/fs/cgroup", &st)
		if err != nil && os.IsNotExist(err) {
			// For rootless containers, sweep it under the rug.
			isUnified = false
			return
		}
		isUnified = st.Type == unix.CGROUP2_SUPER_MAGIC
	})
	return isUnified
}
```
### cgroupV1
#### cgroupManagerV1
```go
type CgroupManagerV1 struct {
	// cgroup在hierarchy中的路径 相当于创建的cgroup目录相对于root cgroup目录的路径
	Path string
	// 资源配置
	Resource   *resource.ResourceConfig
	Subsystems []resource.Subsystem
}
```
#### 寻找subsystem的挂载目录
findCgroupMountpoint 通过/proc/self/mountinfo找出挂载了某个subsystem的hierarchy cgroup根节点所在的目录
```go
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
```
#### CpuSubSystem
子模块示例，其他模块同理
```go

type CpuSubSystem struct {
}

const (
	PeriodDefault = 100000
	Percent       = 100
)

func (s *CpuSubSystem) Name() string {
	return "cpu"
}

func (s *CpuSubSystem) Set(cgroupPath string, res *resource.ResourceConfig) error {
	if res.CpuCfsQuota == 0 {
		return nil
	}
	subsysCgroupPath, err := getCgroupPath(s.Name(), cgroupPath, true)
	if err != nil {
		return err
	}
	// cpu.cfs_period_us & cpu.cfs_quota_us 控制的是CPU使用时间，单位是微秒，比如每1秒钟，这个进程只能使用200ms，相当于只能用20%的CPU
	if res.CpuCfsQuota != 0 {
		// cpu.cfs_period_us 默认为100000，即100ms
		if err = os.WriteFile(path.Join(subsysCgroupPath, "cpu.cfs_period_us"), []byte(strconv.Itoa(PeriodDefault)), 0644); err != nil {
			return fmt.Errorf("set cgroup cpu share fail %v", err)
		}
		// cpu.cfs_quota_us 则根据用户传递的参数来控制，比如参数为20，就是限制为20%CPU，所以把cpu.cfs_quota_us设置为cpu.cfs_period_us的20%就行
		// 这里只是简单的计算了下，并没有处理一些特殊情况，比如负数什么的
		if err = os.WriteFile(path.Join(subsysCgroupPath, "cpu.cfs_quota_us"), []byte(strconv.Itoa(PeriodDefault/Percent*res.CpuCfsQuota)), 0644); err != nil {
			return fmt.Errorf("set cgroup cpu share fail %v", err)
		}
	}
	return nil
}

func (s *CpuSubSystem) Apply(cgroupPath string, pid int) error {
	subsysCgroupPath, err := getCgroupPath(s.Name(), cgroupPath, false)
	if err != nil {
		return fmt.Errorf("get cgroup %s error: %v", cgroupPath, err)
	}
	if err = os.WriteFile(path.Join(subsysCgroupPath, "tasks"), []byte(strconv.Itoa(pid)), 0644); err != nil {
		return fmt.Errorf("set cgroup proc fail %v", err)
	}
	return nil
}

func (s *CpuSubSystem) Remove(cgroupPath string) error {
	subsysCgroupPath, err := getCgroupPath(s.Name(), cgroupPath, false)
	if err != nil {
		return err
	}
	return os.RemoveAll(subsysCgroupPath)
}
```
### cgroupv2
和v1 大同小异，主要是一些接口名的不同：v2  cpu.max, cpuset.cpus, memory.max   v1   cpu.cfs_quota_us, cpu.cfs_period_us, cpuset.cpus, memory.limit_in_bytes  
并且将子模块组织在一个目录下统一管理
```go
func getCgroupPath(cgroupPath string, autoCreate bool) (string, error) {
	// 不需要自动创建就直接返回
	cgroupRoot := "/sys/fs/cgroup"
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
	return absPath, errors.Wrap(err, "create cgroup")
}

// Set 设置cgroupPath对应的cgroup的内存资源限制
func (s *MemorySubSystem) Set(cgroupPath string, res *resource.ResourceConfig) error {
	if res.MemoryLimit == "" {
		return nil
	}
	subCgroupPath, err := getCgroupPath(cgroupPath, true)
	if err != nil {
		return err
	}
	// 设置这个cgroup的内存限制，即将限制写入到cgroup对应目录的memory.limit_in_bytes 文件中。
	if err := os.WriteFile(path.Join(subCgroupPath, "memory.max"), []byte(res.MemoryLimit), 0644); err != nil {
		return fmt.Errorf("set cgroup memory fail %v", err)
	}
	return nil
}
```
## 构造镜像
- 获取镜像文件 alpine
```bash
mkdir -p alpine/root
docker export $(docker create alpine:3.12) | tar-C alpine/root -xvf -
```
### pivotroot 和 chroot
- pivot_root 用于将当前的根文件系统替换为另一个文件系统，并移动旧的根文件系统到一个新的位置。
- chroot 更改一个进程和其子进程的根目录。
```go
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
```
### overlay
对镜像进行写操作其实并没有修改镜像，使用了写实复制 CoW 技术。  
overlayfs 一般分为 lower、upper、merged 和 work 4个目录。
- lower 只读层，该层数据不会被修改
- upper 可读写层，**所有修改都发生在这一层，即使是修改的 lower 中的数据**。
- merged 视图层，可以看到 lower、upper 中的所有内容
- work 则是 overlayfs 内部使用
`mount -t overlay overlay -o lowerdir=/overlay/lower,upperdir=/overlay/upper,workdir=/overlay/work /mnt/merged`  
挂载卷 绑定挂载技术 -v /tmp:/tmp  `mount -t bind /tmp /var/lib/docker/containers/<container-id>/rootfs/tmp`

```go
func NewWorkSpace(containerID, imageName, volume string) {
	// 创建 lower 目录  根据 imageName 找到镜像 tar，并解压到 lower 目录中
	lowerPath := utils.GetLower(imageName)
	imagePath := utils.GetImage(imageName)
	log.Infof("lower:%s image.tar:%s", lowerPath, imagePath)
	// 检查目录是否已经存在
	exist, err := utils.PathExists(lowerPath)
	if err != nil {
		log.Infof("error judge lower dir %s exists. %v", lowerPath, err)
	}
	// 不存在则创建目录并将image.tar解压到lower文件夹中
	if !exist {
		if err = os.MkdirAll(lowerPath, 0777); err != nil {
			log.Errorf("Mkdir dir %s error. %v", lowerPath, err)
		}
		if _, err = exec.Command("tar", "-xvf", imagePath, "-C", lowerPath).CombinedOutput(); err != nil {
			log.Errorf("Untar dir %s error %v", lowerPath, err)
		}
	}

	dirs := []string{
		utils.GetMerged(containerID),
		utils.GetUpper(containerID),
		utils.GetWorker(containerID),
	}

	for _, dir := range dirs {
		if err := os.Mkdir(dir, 0777); err != nil {
			log.Errorf("mkdir dir %s error. %v", dir, err)
		}
	}

	overlayDirPath := utils.GetOverlayFSDirs(utils.GetLower(containerID), utils.GetUpper(containerID), utils.GetWorker(containerID))
	mergedPath := utils.GetMerged(containerID)
	cmd := exec.Command("mount", "-t", "overlay", "overlay", "-o", overlayDirPath, mergedPath)
	log.Infof("mount overlayfs: [%s]", cmd.String())
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Errorf("%v", err)
	}

	// 如果指定了volume则还需要mount volume   -v /tmp:/tmp 
	if volume != "" {
		mntPath := utils.GetMerged(containerID)
		hostPath, containerPath, err := volumeExtract(volume)
		if err != nil {
			log.Errorf("extract volume failed，maybe volume parameter input is not correct，detail:%v", err)
			return
		}
		mountVolume(mntPath, hostPath, containerPath)
	}
}
```
### 移除容器目录
```go
func DeleteWorkSpace(containerID, volume string) {
	if volume != "" {
		_, containerPath, err := volumeExtract(volume)
		if err != nil {
			log.Errorf("extract volume failed，maybe volume parameter input is not correct，detail:%v", err)
			return
		}
		mntPath := utils.GetMerged(containerID)
		umountVolume(mntPath, containerPath)
	}

	mntPath := utils.GetMerged(containerID)
	cmd := exec.Command("umount", mntPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	log.Infof("umountOverlayFS,cmd:%v", cmd.String())
	if err := cmd.Run(); err != nil {
		log.Errorf("%v", err)
	}

	dirs := []string{
		utils.GetMerged(containerID),
		utils.GetUpper(containerID),
		utils.GetWorker(containerID),
		utils.GetRoot(containerID), // root 目录也要删除
	}

	for _, dir := range dirs {
		if err := os.RemoveAll(dir); err != nil {
			log.Errorf("Remove dir %s error %v", dir, err)
		}
	}
}

```
- 打包镜像 `exec.Command("tar", "-cvf", imageTar, "-C", mntPath, ".")`
## 容器管理
### 保存&打印容器信息
把容器信息持久化到磁盘的 `/var/lib/go-docker/containers/<containerID>/config.json` 文件里  
退出时需要删除信息
```go
type Info struct {
	Pid         string   `json:"pid"`         // 容器的init进程在宿主机上的 PID
	Id          string   `json:"id"`          // 容器Id
	Name        string   `json:"name"`        // 容器名
	Command     string   `json:"command"`     // 容器内init运行命令
	CreatedTime string   `json:"createTime"`  // 创建时间
	Status      string   `json:"status"`      // 容器的状态
	Volume      string   `json:"volume"`      // 容器挂载的 volume
	NetworkName string   `json:"networkName"` // 容器所在的网络
	PortMapping []string `json:"portmapping"` // 端口映射
	IP          string   `json:"ip"`
}
```

docker ps 遍历所有 `/var/lib/go-docker/containers/` 下所有目录
```go
func ListContainers() {
	files, err := os.ReadDir(container.InfoLoc)
	if err != nil {
		log.Errorf("read dir %s error %v", container.InfoLoc, err)
		return
	}
	containers := make([]*container.Info, 0, len(files))
	for _, file := range files {
		containerInfo, err := getContainerInfo(file)
		if err != nil {
			log.Errorf("get container info error %v", err)
			continue
		}
		containers = append(containers, containerInfo)
	}
	// 使用text/tabwriter在控制台打印出容器信息
	w := tabwriter.NewWriter(os.Stdout, 12, 1, 3, ' ', 0)
	_, err = fmt.Fprint(w, "ID\tNAME\tPID\tIP\tSTATUS\tCOMMAND\tCREATED\n")
	if err != nil {
		log.Errorf("Fprint error %v", err)
	}
	for _, item := range containers {
		_, err = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			item.Id,
			item.Name,
			item.IP,
			item.Pid,
			item.Status,
			item.Command,
			item.CreatedTime)
		if err != nil {
			log.Errorf("Fprint error %v", err)
		}
	}
	if err = w.Flush(); err != nil {
		log.Errorf("Flush error %v", err)
	}
}
```
### 容器日志
启动容器没有 -ti 时，将容器的cmd.Stdout 和 cmd.Stderr输出 `/var/lib/go-docker/containers/<containerID>/<containerID>.log` 。`docker logs <containerID>` 就会直接读取此文件的内容  
### docker exec 进入容器内部
**`docker exec` 实则是将当前进程添加到指定容器对应的 namespace 中**，从而可以看到容器中的进程信息、网络信息等。

Goroutine 会随机在底层 OS 线程之间切换，而不是固定在某个线程，因此在 Go 中执行 setns 不能准确的知道是操作到哪个线程了，结果是不确定的，因此需要使用cgo  
```go
package nsenter

/*
#define _GNU_SOURCE
#include <unistd.h>
#include <errno.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

__attribute__((constructor)) void enter_namespace(void) {
   // 这里的代码会在Go运行时启动前执行，它会在单线程的C上下文中运行
	char *go_docker_pid;
	go_docker_pid = getenv("go_docker_pid");
	if (go_docker_pid) {
		fprintf(stdout, "got go_docker_pid=%s\n", go_docker_pid);
	} else {
		fprintf(stdout, "missing go_docker_pid env skip nsenter");
		// 如果没有指定PID就不需要继续执行，直接退出
		return;
	}
	char *go_docker_cmd;
	go_docker_cmd = getenv("go_docker_cmd");
	if (go_docker_cmd) {
		fprintf(stdout, "got go_docker_cmd=%s\n", go_docker_cmd);
	} else {
		fprintf(stdout, "missing go_docker_cmd env skip nsenter");
		// 如果没有指定命令也是直接退出
		return;
	}
	int i;
	char nspath[1024];
	// 需要进入的5种namespace
	char *namespaces[] = { "ipc", "uts", "net", "pid", "mnt" };

	for (i=0; i<5; i++) {
		// 拼接对应路径，类似于/proc/pid/ns/ipc这样
		sprintf(nspath, "/proc/%s/ns/%s", go_docker_pid, namespaces[i]);
		int fd = open(nspath, O_RDONLY);
		if (fd == -1) {
			fprintf(stderr, "Failed to open %s: %s\n", nspath, strerror(errno));
			return;
		}
		// 执行setns系统调用，进入对应namespace
		if (setns(fd, 0) == -1) {
			fprintf(stderr, "setns on %s namespace failed: %s\n", namespaces[i], strerror(errno));
		} else {
			fprintf(stdout, "setns on %s namespace succeeded\n", namespaces[i]);
		}
		close(fd);
	}
	// 在进入的Namespace中执行指定命令，然后退出
	int res = system(go_docker_cmd);
	exit(res);
}
*/
import "C"
```

```go
func ExecContainer(containerId string, comArray []string) {
	// 根据传进来的容器名获取对应的PID
	pid, err := getPidByContainerId(containerId)
	if err != nil {
		log.Errorf("Exec container getContainerPidByName %s error %v", containerId, err)
		return
	}

	cmd := exec.Command("/proc/self/exe", "exec")
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// 把命令拼接成字符串，便于传递
	cmdStr := strings.Join(comArray, " ")
	log.Infof("container pid：%s command：%s", pid, cmdStr)
	_ = os.Setenv(EnvExecPid, pid)
	_ = os.Setenv(EnvExecCmd, cmdStr)
	// 把指定PID进程的环境变量传递给新启动的进程，实现通过exec命令也能查询到容器的环境变量
	containerEnvs := getEnvsByPid(pid)
	cmd.Env = append(os.Environ(), containerEnvs...)

	if err = cmd.Run(); err != nil {
		log.Errorf("Exec container %s error %v", containerId, err)
	}
}
```
进程存放环境变量的位置是`/proc/<PID>/environ`，因此根据给定的 PID 去读取这个文件，便可以获取环境变量。在文件的内容中，每个环境变量之间是通过`\u0000`分割的，因此以此为标记来获取环境变量数组。
### stop & rm 容器
- `docker stop <containerID>` 根据容器id查找，容器信息，`syscall.Kill(pidInt, syscall.SIGTERM)` 修改状态和pid存入到info文件中
- rm ，-f 会先停止容器，然后就是删除容器 配置信息，WorkSpace，cgroup 和 网络资源
## 容器网络
### IPAM
使用bitmap存储ip使用情况  
```go
type IPAM struct {
	SubnetAllocatorPath string             // IPAM存储位置
	Subnets             *map[string]string // key 是网段， value 是分配的位图数组
}

// Allocate 在网段中分配一个可用的 IP 地址
func (ipam *IPAM) Allocate(subnet *net.IPNet) (ip net.IP, err error) {
	// 存放网段中地址分配信息的数组
	ipam.Subnets = &map[string]string{}

	// 从文件中加载已经分配的网段信息
	err = ipam.load()
	if err != nil {
		return nil, errors.Wrap(err, "load subnet allocation info error")
	}
	// 那么subnet.Mask.Size()的返回值就是前面255所对应的位数和总位数，即8和32
	_, subnet, _ = net.ParseCIDR(subnet.String())
	one, size := subnet.Mask.Size()
	// 如果之前没有分配过这个网段，则初始化网段的分配配置
	if _, exist := (*ipam.Subnets)[subnet.String()]; !exist {
		(*ipam.Subnets)[subnet.String()] = strings.Repeat("0", 1<<uint8(size-one))
	}

	for c := range (*ipam.Subnets)[subnet.String()] {
		if (*ipam.Subnets)[subnet.String()][c] == '0' {
			ipalloc := []byte((*ipam.Subnets)[subnet.String()])
			ipalloc[c] = '1'
			(*ipam.Subnets)[subnet.String()] = string(ipalloc)
			ip = subnet.IP
			for t := uint(4); t > 0; t -= 1 {
				[]byte(ip)[4-t] += uint8(c >> ((t - 1) * 8))
			}
			ip[3] += 1
			break
		}
	}
	// 最后调用dump将分配结果保存到文件中
	err = ipam.dump()
	if err != nil {
		log.Error("Allocate：dump ipam error", err)
	}
	return
}

func (ipam *IPAM) Release(subnet *net.IPNet, ipaddr *net.IP) error {
	ipam.Subnets = &map[string]string{}
	_, subnet, _ = net.ParseCIDR(subnet.String())

	err := ipam.load()
	if err != nil {
		return errors.Wrap(err, "load subnet allocation info error")
	}
	// 和分配一样的算法，反过来根据IP找到位图数组中的对应索引位置
	c := 0
	releaseIP := ipaddr.To4()
	releaseIP[3] -= 1
	for t := uint(4); t > 0; t -= 1 {
		c += int(releaseIP[t-1]-subnet.IP[t-1]) << ((4 - t) * 8)
	}
	// 然后将对应位置0
	ipalloc := []byte((*ipam.Subnets)[subnet.String()])
	ipalloc[c] = '0'
	(*ipam.Subnets)[subnet.String()] = string(ipalloc)

	// 最后调用dump将分配结果保存到文件中
	err = ipam.dump()
	if err != nil {
		log.Error("Allocate：dump ipam error", err)
	}
	return nil
}
```
### iptables
iptables 是一个基于内核空间 netfilter 的用户空间工具，用于配置 Linux 内核的防火墙规则。实现网络数据包的过滤、转发、修改等功能。`iptables -t 表 命令 规则链 规则`
![img](https://img2023.cnblogs.com/blog/2735725/202403/2735725-20240303204902743-314223011.png)

- nat 表: 用于修改数据包的源或者目的地址等信息，典型的应用是网络地址转换（Network Address Translation）。
```bash
# snat postrouting,input
iptables -t nat -A POSTROUTING -s 172.18.0.0/24 ! -o br0 -j MASQUERADE 
```
在`nat`表的`POSTROUTING`链增加规则，当数据包的源地址为`172.18.0.0/24`网段，出口设备不是`br0`时，就执行`MASQUERADE`动作。
`MASQUERADE`也是一种源地址转换动作，它会动态选择宿主机的一个 IP 做源地址转换，而`SNAT`动作必须在命令中指定固定的 IP 地址。
```shell
# ! -i testbridge: 这个选项意味着规则仅适用于不是从 testbridge 接口进来的数据包 
# dnat prerouting,output
iptables -t nat -A PREROUTING ! -i testbridge -p tcp -m tcp --dport 8080 -j DNAT --to-destination 10.0.0.4:80
```

- filter 表: 用于对数据包进行过滤，控制到达某条链上的数据包是继续放行、直接丢弃或拒绝（ACCEPT、DROP、REJECT），典型的应用是防火墙。
```
iptables -t filter -A INPUT -p tcp -s 192.168.10.0/24 -j DROP  # forward,input,filter
```

```go
// configPortMapping 配置端口映射
func configPortMapping(ep *Endpoint, isDelete bool) error {
	action := "-A"
	if isDelete {
		action = "-D"
	}

	var err error
	// 遍历容器端口映射列表
	for _, pm := range ep.PortMapping {
		// 分割成宿主机的端口和容器的端口
		portMapping := strings.Split(pm, ":")
		if len(portMapping) != 2 {
			logrus.Errorf("port mapping format error, %v", pm)
			continue
		}
		// 由于iptables没有Go语言版本的实现，所以采用exec.Command的方式直接调用命令配置
		// 在iptables的PREROUTING中添加DNAT规则
		// 将宿主机的端口请求转发到容器的地址和端口上
		// iptables -t nat -A PREROUTING ! -i testbridge -p tcp -m tcp --dport 8080 -j DNAT --to-destination 10.0.0.4:80
		iptablesCmd := fmt.Sprintf("-t nat %s PREROUTING ! -i %s -p tcp -m tcp --dport %s -j DNAT --to-destination %s:%s", action, ep.Network.Name, portMapping[0], ep.IPAddress.String(), portMapping[1])
		cmd := exec.Command("iptables", strings.Split(iptablesCmd, " ")...)
		logrus.Infoln("配置端口映射 DNAT cmd:", cmd.String())
		// 执行iptables命令,添加端口映射转发规则
		output, err := cmd.Output()
		if err != nil {
			logrus.Errorf("iptables Output, %v", output)
			continue
		}
	}
	return err
}
```
### BridgeNetworkDriver
initBridge 初始化Linux Bridge   
1. 创建 Bridge 虚拟设备  
2. 设置 Bridge 设备地址和路由  
3. 启动 Bridge 设备  
4. 设置 iptables SNAT 规则  
```go
func (d *BridgeNetworkDriver) initBridge(n *Network) error {
	bridgeName := n.Name
	// 1）创建 Bridge 虚拟设备 ip link add xxxx
	if err := createBridgeInterface(bridgeName); err != nil {
		return errors.Wrapf(err, "Failed to create bridge %s", bridgeName)
	}
	// 2）设置 Bridge 设备地址和路由
	gatewayIP := *n.IPRange

	if err := setInterfaceIP(bridgeName, gatewayIP.String()); err != nil {
		return errors.Wrapf(err, "Error set bridge ip: %s on bridge: %s", gatewayIP.String(), bridgeName)
	}
	// 3）启动 Bridge 设备
	if err := setInterfaceUP(bridgeName); err != nil {
		return errors.Wrapf(err, "Failed to set %s up", bridgeName)
	}

	// 4）设置 iptables SNAT 规则
	if err := setupIPTables(bridgeName, n.IPRange); err != nil {
		return errors.Wrapf(err, "Failed to set up iptables for %s", bridgeName)
	}
	return nil
}

// createBridgeInterface 创建Bridge设备  ip link add xxxx
func createBridgeInterface(bridgeName string) error {
	// 先检查是否己经存在了这个同名的Bridge设备
	_, err := net.InterfaceByName(bridgeName)
	// 如果已存在或报错返回创建失败
	if err == nil || !strings.Contains(err.Error(), "no such network interface") {
		return err
	}
	// create *netlink.Bridge object
	la := netlink.NewLinkAttrs()
	la.Name = bridgeName
	// 使用刚才创建的Link的属性创netlink Bridge对象
	br := &netlink.Bridge{LinkAttrs: la}
	// 调用 net link Linkadd 方法，创 Bridge 虚拟网络设备
	// netlink.LinkAdd 方法是用来创建虚拟网络设备的，相当于 ip link add xxxx
	if err = netlink.LinkAdd(br); err != nil {
		return errors.Wrapf(err, "create bridge %s error", bridgeName)
	}
	return nil
}

// Set the IP addr of a netlink interface  ip addr add 172.18.0.1/24 dev br0
func setInterfaceIP(name string, rawIP string) error {
	retries := 5
	var iface netlink.Link
	var err error
	for i := 0; i < retries; i++ {
		// 通过LinkByName方法找到需要设置的网络接口
		iface, err = netlink.LinkByName(name)
		if err == nil {
			break
		}
		log.Debugf("error retrieving new bridge netlink link [ %s ]... retrying", name)
		time.Sleep(2 * time.Second)
	}
	if err != nil {
		return errors.Wrap(err, "abandoning retrieving the new bridge link from netlink, Run [ ip link ] to troubleshoot")
	}
	// 由于 netlink.ParseIPNet 是对 net.ParseCIDR一个封装，因此可以将 net.PareCIDR中返回的IP进行整合
	// 返回值中的 ipNet 既包含了网段的信息，192 168.0.0/24 ，也包含了原始的IP 192.168.0.1
	ipNet, err := netlink.ParseIPNet(rawIP)
	if err != nil {
		return err
	}
	addr := &netlink.Addr{IPNet: ipNet}
	return netlink.AddrAdd(iface, addr)
}
```
### Network
Connect 连接容器到之前创建的网络 go-docker run -net testnet -p 8080:80 xxxx
```go
type Network struct {
	Name    string     // 网络名
	IPRange *net.IPNet // 地址段
	Driver  string     // 网络驱动名
}

// Connect 连接容器到之前创建的网络 go-docker run -net testnet -p 8080:80 xxxx
func Connect(networkName string, info *container.Info) (net.IP, error) {
	networks, err := loadNetwork()
	if err != nil {
		return nil, errors.WithMessage(err, "load network from file failed")
	}
	// 从networks字典中取到容器连接的网络的信息，networks字典中保存了当前己经创建的网络
	network, ok := networks[networkName]
	if !ok {
		return nil, fmt.Errorf("no Such Network: %s", networkName)
	}

	// 分配容器IP地址
	ip, err := ipAllocator.Allocate(network.IPRange)
	if err != nil {
		return ip, errors.Wrapf(err, "allocate ip")
	}
	// 创建网络端点
	ep := &Endpoint{
		ID:          fmt.Sprintf("%s-%s", info.Id, networkName),
		IPAddress:   ip,
		Network:     network,
		PortMapping: info.PortMapping,
	}
	// 调用网络驱动挂载和配置网络端点
	if err = drivers[network.Driver].Connect(network.Name, ep); err != nil {
		return ip, err
	}
	// 到容器的namespace配置容器网络设备IP地址
	if err = configEndpointIpAddressAndRoute(ep, info); err != nil {
		return ip, err
	}
	// 配置端口映射信息，例如 go-docker run -p 8080:80
	return ip, addPortMapping(ep)
}

// configEndpointIpAddressAndRoute 配置容器网络端点的地址和路由
func configEndpointIpAddressAndRoute(ep *Endpoint, info *container.Info) error {
	// 根据名字找到对应Veth设备
	peerLink, err := netlink.LinkByName(ep.Device.PeerName)
	if err != nil {
		return errors.WithMessagef(err, "found veth [%s] failed", ep.Device.PeerName)
	}
	// 将容器的网络端点加入到容器的网络空间中
	defer enterContainerNetNS(&peerLink, info)()

	interfaceIP := *ep.Network.IPRange
	interfaceIP.IP = ep.IPAddress
	// 设置容器内Veth端点的IP
	if err = setInterfaceIP(ep.Device.PeerName, interfaceIP.String()); err != nil {
		return fmt.Errorf("%v,%s", ep.Network, err)
	}
	// 启动容器内的Veth端点
	if err = setInterfaceUP(ep.Device.PeerName); err != nil {
		return err
	}
	// 启动它以保证容器访问自己的请求
	if err = setInterfaceUP("lo"); err != nil {
		return err
	}
	// 设置容器内的外部请求都通过容器内的Veth端点访问
	// 0.0.0.0/0的网段，表示所有的IP地址段
	_, cidr, _ := net.ParseCIDR("0.0.0.0/0")

	// 构建要添加的路由数据，包括网络设备、网关IP及目的网段
	// 相当于route add -net 0.0.0.0/0 gw (Bridge网桥地址) dev （容器内的Veth端点设备)
	defaultRoute := &netlink.Route{
		LinkIndex: peerLink.Attrs().Index,
		Gw:        ep.Network.IPRange.IP,
		Dst:       cidr,
	}
	// 调用netlink的RouteAdd,添加路由到容器的网络空间
	// RouteAdd 函数相当于route add 命令
	if err = netlink.RouteAdd(defaultRoute); err != nil {
		return err
	}
	return nil
}

// enterContainerNetNS 将容器的网络端点加入到容器的网络空间中
// 并锁定当前程序所执行的线程，使当前线程进入到容器的网络空间
// 返回值是一个函数指针，执行这个返回函数才会退出容器的网络空间，回归到宿主机的网络空间
func enterContainerNetNS(netLink *netlink.Link, info *container.Info) func() {
	// 找到容器的Net Namespace
	// /proc/[pid]/ns/net 打开这个文件的文件描述符就可以来操作Net Namespace
	// 而ContainerInfo中的PID,即容器在宿主机上映射的进程ID
	// 它对应的/proc/[pid]/ns/net就是容器内部的Net Namespace
	f, err := os.OpenFile(fmt.Sprintf("/proc/%s/ns/net", info.Pid), os.O_RDONLY, 0)
	if err != nil {
		logrus.Errorf("error get container net namespace, %v", err)
	}

	nsFD := f.Fd()
	// 锁定当前程序所执行的线程，如果不锁定操作系统线程的话
	// Go语言的goroutine可能会被调度到别的线程上去
	// 就不能保证一直在所需要的网络空间中了
	// 所以先调用runtime.LockOSThread()锁定当前程序执行的线程
	runtime.LockOSThread()

	// 修改网络端点Veth的另外一端，将其移动到容器的Net Namespace 中
	// ip link set $link netns $ns
	if err = netlink.LinkSetNsFd(*netLink, int(nsFD)); err != nil {
		logrus.Errorf("error set link netns , %v", err)
	}

	// 获取当前的网络namespace
	origns, err := netns.Get()
	if err != nil {
		logrus.Errorf("error get current netns, %v", err)
	}

	// 调用 netns.Set方法，将当前进程加入容器的Net Namespace
	if err = netns.Set(netns.NsHandle(nsFD)); err != nil {
		logrus.Errorf("error set netns, %v", err)
	}
	// 返回之前Net Namespace的函数
	// 在容器的网络空间中执行完容器配置之后调用此函数就可以将程序恢复到原生的Net Namespace
	return func() {
		// 恢复到上面获取到的之前的 Net Namespace
		netns.Set(origns)
		origns.Close()
		// 取消对当附程序的线程锁定
		runtime.UnlockOSThread()
		f.Close()
	}
}
```
