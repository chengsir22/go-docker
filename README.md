## 命名空间隔离

目前linux支持的命名空间有:

| 命名空间             |                                                              |
| -------------------- | ------------------------------------------------------------ |
| syscall.CLONE_NEWUTS | 对主机名进行隔离                                             |
| syscall.CLONE_NEWPID | 对pid空间进行隔离                                            |
| syscall.CLONE_NEWNS  | 对mount命名空间进行隔离                                      |
| syscall.CLONE_NEWNET | 对网络进行隔离                                               |
| syscall.CLONE_NEWIPC | 提供进程间通信资源的隔离，如消息队列、信号量、共享内存等。ipcs      ipcsmk -Q |

```C++
cmd := exec.Command("/bin/sh")
cmd.SysProcAttr = &syscall.SysProcAttr{
    Cloneflags: syscall.CLONE_NEWUTS | syscall.CLONE_NEWPID | syscall.CLONE_NEWNS | syscall.CLONE_NEWNET | syscall.CLONE_NEWIPC,
}
```

不过注意下，当用systemd作为init进程启动时，mount 默认的挂载方式是共享模式，这意味着你在一个mnt namespace下执行mount命令后的挂载对其他mnt 的namespace是可见的。

比如我在新mnt namespace下挂载procfs `mount -t proc proc /proc`，这将会导致主机上的procfs失效，然后你访问主机的/proc 目录将会发现主机/proc目录下的内容和新mnt namespace /proc目录下的内容是一样的。所以当你回到主机的mnt namespace去执行top命令时，将会提示你需要将procfs重新进程挂载。

解决这个问题的办法则是将新mnt namespace设置为私有模式 `mount --make-rprivate /` `mount -t proc proc /proc`

### **为程序重新挂载根文件系统**

根路径涉及到两个点，一个是mnt namespace的根路径，一个是进程自身的根路径

```Go
syscall.Chroot("./ubuntu-base-16.04.6-base-amd64")
syscall.Chdir("/")
```

不过chroot切换 文件系统根目录的方式只能改变该进程能看到的文件范围，并不能改变mnt namespace的根目录，所以替换的并不彻底。使用pivot root 的方式替换挂载目录，可以把mnt 命名空间的根目录也替换掉。**`pivot_root`****的基本思想是将一个挂载点替换为一个新的根目录，同时保留原来的挂载点。**

```Go
// systemd 为init进程时，挂载默认是共享模式挂载的，共享模式挂载会让所有命名空间都能看到各自的挂载的目录
// 后续调用pivot root会失败，所以将命名空间声明为私有的，MS_REC是mount选项中的一个标志，用于递归地挂载一个目录及其所有子目录
syscall.Mount("", "/", "", syscall.MS_PRIVATE|syscall.MS_REC, "")
syscall.Mount(newroot, newroot, "bind", syscall.MS_BIND|syscall.MS_REC, "")

syscall.PivotRoot(newroot string, putold string) (err error) 

// 接着挂载proc内存文件系统
defaultMountFlags := syscall.MS_NOEXEC | syscall.MS_NOSUID | syscall.MS_NODEV
syscall.Mount("proc", "/proc", "proc", uintptr(defaultMountFlags), "" )
```

## 联合文件系统

联合文件系统可以把其他文件系统的文件和目录挂载到同一个挂载点下，形成统一的文件系统，在挂载点下形成统一的文件视图

```Plaintext
sudo mount -t overlay overlay -o lowerdir=image-layer1:image-layer2,upperdir=container-layer,workdir=work mnt/
```

先是根据容器名创建了执行overlay挂载所需要的目录，然后通过mount命令将一个overlay类型的文件系统挂载到mntLayer(containerName)的路径下，然后mntLayer(containerName)路径下文件将作为容器的根文件系统，使用pivot root调用。

```Go
if err := syscall.Mount("overlay", mntLayer(containerName), "overlay", 0,
    fmt.Sprintf("upperdir=%s,lowerdir=%s,workdir=%s", writeLayer(containerName), 
        imagePath, workerLayer(containerName))); err != nil {
    return fmt.Errorf("mount overlay fail err=%s", err)
}
```

## 网络命名空间

### 容器之间互通

在linux上，可以用veth虚拟网络设备去连接两个不同网络命名空间，veth设备是成队出现，分别连接到不同的命名空间中， 从veth设备一端进入的网络包能够到达veth设备的另一端， 但在配置容器网络时并不是将veth设备直接连接在另一端的网络命名空间内，因为如果主机上容器过多的话，采用直接两两相连的方式，将会让网络拓扑过于复杂。所以一般是将veth设备连接到一个叫做网桥bridge的虚拟网络设备上，通过它对网络包进行转发。

**ip****地址分配管理** 使用**bitmap**对容器ip进行分配，可以快速查看该ip是否已经被分配

### **创建网络设备**

创建网桥

```Go
func createBridge(networkName string, interfaceIp *net.IPNet) (string, error) {
    // 生成网桥名称，将其截断为15个字符的长度
    bridgeName := truncate(15, fmt.Sprintf("br-%s", networkName))

    // 创建 LinkAttrs 结构体，用于描述链接设备的属性
    la := netlink.NewLinkAttrs()
    la.Name = bridgeName

    // 创建 Bridge 结构体，表示网桥
    br := &netlink.Bridge{LinkAttrs: la}

    // 使用 netlink.LinkAdd() 函数向 Linux 内核添加网桥
    if err := netlink.LinkAdd(br); err != nil {
       return "", fmt.Errorf("bridge creation failed for bridge %s: %s", bridgeName, err)
    }

    // 创建 Addr 结构体，用于描述 IP 地址配置
    addr := &netlink.Addr{IPNet: interfaceIp, Peer: interfaceIp, Label: "", Flags: 0, Scope: 0}

    // 使用 netlink.AddrAdd() 函数向网桥添加 IP 地址配置
    if err := netlink.AddrAdd(br, addr); err != nil {
       return "", fmt.Errorf("bridge add addr fail %s", err)
    }

    // 使用 netlink.LinkSetUp() 函数启用网桥
    if err := netlink.LinkSetUp(br); err != nil {
       return "", fmt.Errorf("error enabling interface for %s: %v", bridgeName, err)
    }

    // 返回创建的网桥名称
    return bridgeName, nil
}
```

### NAT

`iptables` 命令来设置 SNAT（Source NAT）规则，实现网络地址转换。SNAT 通常用于将源 IP 地址替换为其他地址，以便将出站流量路由到正确的网络。

**POSTROUTIN**: 从本机网卡出去的数据包，无论是本机的程序所发出的，还是由本机转发给其他机器的，都会触发这个钩子，它一般是用于源网络地址转换（Source NAT，SNAT）

```Go
func setSNat(bridgeName string, subnet *net.IPNet) error {
    // 构建 iptables 命令字符串，用于设置 SNAT 规则
    iptablesCmd := fmt.Sprintf("-t nat -A POSTROUTING -s %s ! -o %s -j MASQUERADE", subnet.String(), bridgeName)
    // 使用 exec 包创建命令对象
    cmd := exec.Command("iptables", strings.Split(iptablesCmd, " ")...)
    // 执行命令并获取输出
    _, err := cmd.Output()
    // 检查命令执行结果
    if err != nil {
       return fmt.Errorf("set snat fail %s", err)
    }
    // 返回 nil 表示设置 SNAT 成功
    return nil
}
```

### 容器配置ip和veth设备

```Go
func ConfigDefaultNetworkInNewNet(pid int) error {
    // 获取ip
    ip, err := IpAmfs.AllocIp(defaultSubnet)
    if err != nil {
       return fmt.Errorf("ipam alloc ip fail %s", err)
    }

    // 主机上创建 veth 设备,并连接到网桥上
    vethLink, networkConf, err := BridgeDriver.CreateVeth(defaultNetName)
    if err != nil {
       return fmt.Errorf("create veth fail err=%s", err)
    }
    // 主机上设置子进程网络命名空间 配置
    if err := BridgeDriver.setContainerIp(vethLink.PeerName, pid, ip, networkConf.BridgeIp); err != nil {
       return fmt.Errorf("setContainerIp fail err=%s peername=%s pid=%d ip=%v conf=%+v", err, vethLink.PeerName, pid, ip, networkConf)
    }
    // 通知子进程设置完毕
    log.Debug("parent process set ip success")
    return noticeSunProcessNetConfigFin(pid)
}
```

创建 Veth（Virtual Ethernet）设备并与指定的桥接设备连接

```Go
func (b *bridgeDriver) CreateVeth(networkName string) (*netlink.Veth, *NetConf, error) {
    // 检查网络命名是否存在
    if err := NetMgr.LoadConf(); err != nil {
       return nil, nil, fmt.Errorf("netMgr loadConf fail %s", err)
    }
    // 从网络配置管理器中获取指定网络的配置
    networkConf, ok := NetMgr.Storage[networkName]
    if !ok {
       return nil, nil, fmt.Errorf("name %s network is invalid", networkName)
    }

    // 通过桥接设备名称获取桥接设备
    br, err := netlink.LinkByName(networkConf.BridgeName)
    if err != nil {
       return nil, nil, fmt.Errorf("link by name fail err=%s", err)
    }

    // 创建新的 LinkAttrs 结构体，用于描述链接设备的属性
    la := netlink.NewLinkAttrs()

    // 生成 Veth 设备的名称
    vethname := truncate(15, "veth-"+strconv.Itoa(10+int(rand.Int31n(10)))+"-"+networkConf.NetworkName)
    la.Name = vethname

    // 设置 Veth 设备的 MasterIndex，将其连接到指定的桥接设备
    la.MasterIndex = br.Attrs().Index

    // 创建 Veth 设备
    vethLink := &netlink.Veth{
       LinkAttrs: la,
       PeerName:  truncate(15, "cif-"+vethname),
    }
    if err := netlink.LinkAdd(vethLink); err != nil {
       return nil, nil, fmt.Errorf("veth creation failed for bridge %s: %s", networkName, err)
    }

    // 启用 Veth 设备
    if err := netlink.LinkSetUp(vethLink); err != nil {
       return nil, nil, fmt.Errorf("error enabling interface for %s: %v", networkName, err)
    }

    // 返回创建的 Veth 设备、网络配置信息和 nil（无错误）
    return vethLink, networkConf, nil
}
```

配置容器的网络接口，设置容器内的IP地址和路由信息

```Go
func (b *bridgeDriver) setContainerIp(peerName string, pid int, containerIp net.IP, gateway *net.IPNet) error {
    // 获取容器内的 Veth 设备
    peerLink, err := netlink.LinkByName(peerName)
    if err != nil {
       return fmt.Errorf("fail config endpoint: %v", err)
    }

    // 获取本地回环接口
    loLink, err := netlink.LinkByName("lo")
    if err != nil {
       return fmt.Errorf("fail config endpoint: %v", err)
    }

    // 进入容器的网络命名空间
    defer enterContainerNetns(&peerLink, pid)()

    // 构造容器 Veth 设备的 IP 地址
    containerVethInterfaceIP := *gateway
    containerVethInterfaceIP.IP = containerIp

    // 调用 setInterfaceIP 函数设置容器 Veth 设备的 IP 地址
    if err = setInterfaceIP(peerName, containerVethInterfaceIP.String()); err != nil {
       return fmt.Errorf("%v,%s", containerIp, err)
    }

    // 启用容器内的 Veth 设备和本地回环接口
    if err := netlink.LinkSetUp(peerLink); err != nil {
       return fmt.Errorf("netlink.LinkSetUp fail  name=%s err=%s", peerName, err)
    }
    if err := netlink.LinkSetUp(loLink); err != nil {
       return fmt.Errorf("netlink.LinkSetUp fail  name=%s err=%s", peerName, err)
    }

    // 构造默认路由信息，使容器能够访问外部网络
    _, cidr, _ := net.ParseCIDR("0.0.0.0/0")
    defaultRoute := &netlink.Route{
       LinkIndex: peerLink.Attrs().Index,
       Gw:        gateway.IP,
       Dst:       cidr,
    }

    // 添加默认路由
    if err = netlink.RouteAdd(defaultRoute); err != nil {
       return fmt.Errorf("router add fail %s", err)
    }

    return nil
}
```

### 端口映射

**PREROUTING**: 在进入 IP 路由之前触发，就意味着只要接收到的数据包，无论是否真的发往本机，也都会触发这个钩子。它一般是用于**目标网络地址转换（Destination NAT，DNAT）**。

```Go
func setupNetwork(containerPID int, containerIP, containerPort, hostIP, hostPort string) {
    // 设置网络命名空间
    nsPath := fmt.Sprintf("/proc/%d/ns/net", containerPID)
    nsfile, err := os.Open(nsPath)
    if err != nil {
       fmt.Println("Error opening network namespace:", err)
       os.Exit(1)
    }
    defer nsfile.Close()

    runtime.LockOSThread()

    // 获取当前的网络 namespace
    originalNS, err := netns.Get()
    if err != nil {
       log.Error("Error getting current netns:", err)
    }

    // 移动当前进程到容器的网络命名空间
    if err := netns.Set(netns.NsHandle(nsfile.Fd())); err != nil {
       fmt.Println("Error setting network namespace:", err)
       os.Exit(1)
    }

    // 执行网络配置命令，映射容器端口到宿主机端口
    iptablesCmd := exec.Command("iptables", "-t", "nat", "-A", "PREROUTING", "-p", "tcp", "--dport", hostPort, "-j", "DNAT", "--to-destination", fmt.Sprintf("%s:%s", containerIP, containerPort))
    if err := iptablesCmd.Run(); err != nil {
       fmt.Println("Error configuring iptables:", err)
       os.Exit(1)
    }

    // 恢复当前进程到原网络命名空间
    netns.Set(originalNS)
    originalNS.Close()

    runtime.UnlockOSThread()
}
```

## Cgroups

```Go
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
```
