package main

import (
	"fmt"
	"go-docker/cgroups/resource"
	"go-docker/network"
	"os"

	"go-docker/container"

	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

var runCommand = cli.Command{
	Name: "run",
	Usage: `Create a container with namespace and cgroups limit
			go-docker run -d -name [containerName] [imageName] [command]`,
	Flags: []cli.Flag{
		cli.BoolFlag{
			Name:  "it",
			Usage: "enable tty",
		},
		cli.StringFlag{
			Name:  "mem",
			Usage: "memory limit,e.g.: -mem 100m",
		},
		cli.StringFlag{
			Name:  "cpu",
			Usage: "cpu quota,e.g.: -cpu 100",
		},
		cli.StringFlag{
			Name:  "cpuset",
			Usage: "cpuset limit,e.g.: -cpuset 2,4",
		},
		cli.StringFlag{
			Name:  "v",
			Usage: "volume,e.g.: -v /ect/conf:/etc/conf",
		},
		cli.BoolFlag{
			Name:  "d",
			Usage: "detach container,run background",
		},
		// 提供run后面的-name指定容器名字参数
		cli.StringFlag{
			Name:  "name",
			Usage: "container name，e.g.: -name mycontainer",
		},
		cli.StringSliceFlag{
			Name:  "e",
			Usage: "set environment,e.g. -e name=mydocker",
		},
		cli.StringFlag{
			Name:  "net",
			Usage: "container network，e.g. -net testbr",
		},
		cli.StringSliceFlag{
			Name:  "p",
			Usage: "port mapping,e.g. -p 8080:80 -p 30336:3306",
		},
	},
	Action: func(context *cli.Context) error {
		if len(context.Args()) < 1 {
			return fmt.Errorf("missing container command")
		}

		var cmdArray []string
		for _, arg := range context.Args() {
			cmdArray = append(cmdArray, arg)
		}

		imageName := cmdArray[0] // 镜像名称
		cmdArray = cmdArray[1:]

		tty := context.Bool("it")
		detach := context.Bool("d")

		if tty && detach {
			return fmt.Errorf("it and d flag can not both provided")
		}
		if !detach { // 如果不是指定后台运行，就默认前台运行
			tty = true
		}

		resConf := &resource.ResourceConfig{
			MemoryLimit: context.String("mem"),
			CpuSet:      context.String("cpuset"),
			CpuCfsQuota: context.Int("cpu"),
		}
		log.Info("resConf:", resConf)
		volume := context.String("v")
		containerName := context.String("name")
		envSlice := context.StringSlice("e")

		network := context.String("net")
		portMapping := context.StringSlice("p")

		Run(tty, cmdArray, envSlice, resConf, volume, containerName, imageName, network, portMapping)
		return nil
	},
}
var initCommand = cli.Command{
	Name:  "init",
	Usage: "Init container process run user's process in container. Do not call it outside",
	Action: func(context *cli.Context) error {
		log.Infof("init come on")
		err := container.RunContainerInitProcess()
		return err
	},
}

var commitCommand = cli.Command{
	Name:  "commit",
	Usage: "commit container to image,e.g. go-docker commit <containerID> myimage",
	Action: func(context *cli.Context) error {
		if len(context.Args()) < 2 {
			return fmt.Errorf("missing container name and image name")
		}
		containerID := context.Args().Get(0)
		imageName := context.Args().Get(1)
		return commitContainer(containerID, imageName)
	},
}

var listCommand = cli.Command{
	Name:  "ps",
	Usage: "list all the containers",
	Action: func(context *cli.Context) error {
		ListContainers()
		return nil
	},
}

var logCommand = cli.Command{
	Name:  "logs",
	Usage: "print logs of a container",
	Action: func(context *cli.Context) error {
		if len(context.Args()) < 1 {
			return fmt.Errorf("please input your container id")
		}
		containerName := context.Args().Get(0)
		logContainer(containerName)
		return nil
	},
}

var execCommand = cli.Command{
	Name:  "exec",
	Usage: "exec a command into container,mydocker exec 123456789 /bin/sh",
	Action: func(context *cli.Context) error {
		// 如果环境变量存在，说明C代码已经运行过了，即setns系统调用已经执行了，这里就直接返回，避免重复执行
		if os.Getenv(EnvExecPid) != "" {
			log.Infof("pid callback pid %v", os.Getgid())
			return nil
		}
		// 格式：mydocker exec 容器名字 命令，因此至少会有两个参数
		if len(context.Args()) < 2 {
			return fmt.Errorf("missing container name or command")
		}
		containerName := context.Args().Get(0)
		// 将除了容器名之外的参数作为命令部分
		commandArray := context.Args().Tail()
		ExecContainer(containerName, commandArray)
		return nil
	},
}

var stopCommand = cli.Command{
	Name:  "stop",
	Usage: "stop a container,e.g. mydocker stop 1234567890",
	Action: func(context *cli.Context) error {
		// 期望输入是：mydocker stop 容器Id，如果没有指定参数直接打印错误
		if len(context.Args()) < 1 {
			return fmt.Errorf("missing container id")
		}
		containerId := context.Args().Get(0)
		stopContainer(containerId)
		return nil
	},
}

var removeCommand = cli.Command{
	Name:  "rm",
	Usage: "remove unused containers,e.g. mydocker rm 1234567890",
	Flags: []cli.Flag{
		cli.BoolFlag{
			Name:  "f", // 强制删除
			Usage: "force delete running container,",
		}},
	Action: func(context *cli.Context) error {
		if len(context.Args()) < 1 {
			return fmt.Errorf("missing container id")
		}
		containerId := context.Args().Get(0)
		force := context.Bool("f")
		removeContainer(containerId, force)
		return nil
	},
}

var networkCommand = cli.Command{
	Name:  "network",
	Usage: "container network commands",
	Subcommands: []cli.Command{
		{
			Name:  "create",
			Usage: "create a container network",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "driver",
					Usage: "network driver",
				},
				cli.StringFlag{
					Name:  "subnet",
					Usage: "subnet cidr",
				},
			},
			Action: func(context *cli.Context) error {
				if len(context.Args()) < 1 {
					return fmt.Errorf("missing network name")
				}
				driver := context.String("driver")
				subnet := context.String("subnet")
				name := context.Args()[0]

				err := network.CreateNetwork(driver, subnet, name)
				if err != nil {
					return fmt.Errorf("create network error: %+v", err)
				}
				return nil
			},
		},
		{
			Name:  "list",
			Usage: "list container network",
			Action: func(context *cli.Context) error {
				network.ListNetwork()
				return nil
			},
		},
		{
			Name:  "remove",
			Usage: "remove container network",
			Action: func(context *cli.Context) error {
				if len(context.Args()) < 1 {
					return fmt.Errorf("missing network name")
				}
				err := network.DeleteNetwork(context.Args()[0])
				if err != nil {
					return fmt.Errorf("remove network error: %+v", err)
				}
				return nil
			},
		},
	},
}
