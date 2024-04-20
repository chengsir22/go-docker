package main

import (
	"fmt"

	"github.com/chengsir22/go-docker/container"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
)

var runCommand = &cli.Command{
	Name:  "run",
	Usage: `Create a container `,
	Flags: []cli.Flag{
		&cli.BoolFlag{
			Name:  "ti",
			Usage: "enable tty",
		},
	},
	Action: func(ctx *cli.Context) error {
		if ctx.Args().Len() < 1 {
			return fmt.Errorf("missing container command")
		}
		var cmdArray []string
		cmdArray = append(cmdArray, ctx.Args().Slice()...)

		tty := ctx.Bool("ti")
		fmt.Println(tty)
		Run(tty, cmdArray)
		return nil
	},
}

var initCommand = &cli.Command{
	Name:  "init",
	Usage: "Init container process run user's process in container. Do not call it outside",
	Action: func(ctx *cli.Context) error {
		log.Infof("init come on")
		err := container.RunContainerInitProcess()
		return err
	},
}
