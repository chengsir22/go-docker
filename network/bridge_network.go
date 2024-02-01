package network

import (
	"fmt"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"go-docker/log"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type bridgeDriver struct {
}

func (b *bridgeDriver) Name() string {
	return "bridge"
}

var BridgeDriver = &bridgeDriver{}

func truncate(maxlen int, str string) string {
	if len(str) <= maxlen {
		return str
	}
	return str[:maxlen]
}

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

// like this ip 192.167.0.100/24
func genInterfaceIp(rawIpWithRange string) (*net.IPNet, error) {
	ipNet, err := netlink.ParseIPNet(rawIpWithRange)
	if err != nil {
		return nil, fmt.Errorf("parse ip fail ip=%+s err=%s", rawIpWithRange, err)
	}
	return ipNet, nil
}

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

func (b *bridgeDriver) CreateNetwork(networkName string, subnet string, networkType networktype) error {

	if networkType != BridgeNetworkType {
		return fmt.Errorf("support bridge network type now ")
	}

	// 检查网络命名是否存在
	if err := NetMgr.LoadConf(); err != nil {
		return fmt.Errorf("netMgr loadConf fail %s", err)
	}

	if netConf, ok := NetMgr.Storage[networkName]; ok {
		switch netConf.Driver {
		case "bridge":
			// 系统重启后需要重新建立网桥配置
			_, err := netlink.LinkByName(netConf.BridgeName)
			if err == nil {
				log.Info("exist default network ,will not create new network ")
				return nil
			}
		default:
			return fmt.Errorf("not support network driver")
		}
	}

	// 创建网桥
	interfaceIp, err := genInterfaceIp(subnet)
	if err != nil {
		return fmt.Errorf("genInterfaceIp err=%s", err)
	}
	bridgeName, err := createBridge(networkName, interfaceIp)
	if err != nil {
		return fmt.Errorf("createBridge err=%s", err)
	}

	_, cidr, _ := net.ParseCIDR(subnet)

	err = setSNat(bridgeName, cidr)
	if err != nil {
		log.Error("%s", err)
	}
	NetMgr.Storage[networkName] = &NetConf{
		NetworkName: networkName,
		IpRange:     cidr,
		Driver:      BridgeNetworkType.String(),
		BridgeName:  bridgeName,
		BridgeIp:    interfaceIp,
	}
	return NetMgr.Sync()
}

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

func enterContainerNetns(vethLink *netlink.Link, pid int) func() {
	// 打开容器的网络命名空间文件
	f, err := os.OpenFile(fmt.Sprintf("/proc/%d/ns/net", pid), os.O_RDONLY, 0)
	if err != nil {
		fmt.Println(fmt.Errorf("error get container net namespace, %v", err))
	}

	nsFD := f.Fd()
	runtime.LockOSThread()

	// 将 Veth 设备的另一端移到容器的网络命名空间中。这确保容器内的网络设备能够在容器的网络命名空间中运行。
	if err = netlink.LinkSetNsFd(*vethLink, int(nsFD)); err != nil {
		log.Error("error set link netns , %v", err)
	}

	// 获取当前的网络namespace
	origns, err := netns.Get()
	if err != nil {
		log.Error("error get current netns, %v", err)
	}

	// 设置当前线程到新的网络namespace，并在函数执行完成之后再恢复到之前的namespace
	if err = netns.Set(netns.NsHandle(nsFD)); err != nil {
		log.Error("error set netns, %v", err)
	}
	return func() {
		netns.Set(origns)
		origns.Close()
		runtime.UnlockOSThread()
		f.Close()
	}
}

// Set the IP addr of a netlink interface
func setInterfaceIP(name string, rawIP string) error {
	retries := 2
	var iface netlink.Link
	var err error
	for i := 0; i < retries; i++ {
		iface, err = netlink.LinkByName(name)
		if err == nil {
			break
		}
		fmt.Println(fmt.Errorf("error retrieving new bridge netlink link [ %s ]... retrying", name))
		time.Sleep(2 * time.Second)
	}
	if err != nil {
		return fmt.Errorf("Abandoning retrieving the new bridge link from netlink, Run [ ip link ] to troubleshoot the error: %v", err)
	}
	ipNet, err := netlink.ParseIPNet(rawIP)
	if err != nil {
		return err
	}
	addr := &netlink.Addr{IPNet: ipNet, Peer: ipNet, Label: "", Flags: 0, Scope: 0}
	return netlink.AddrAdd(iface, addr)
}
