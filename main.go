package main

import (
	"os"

	log "github.com/sirupsen/logrus"

	"github.com/urfave/cli"
)

const usage = `go-docker is a simple container runtime implementation.`

func main() {
	app := cli.NewApp()
	app.Name = "go-docker"
	app.Usage = usage

	app.Commands = []cli.Command{
		runCommand,
		initCommand,
		commitCommand,
		listCommand,
		logCommand,
		execCommand,
		stopCommand,
		removeCommand,
		networkCommand,
	}

	app.Before = func(context *cli.Context) error {
		log.SetFormatter(&log.JSONFormatter{})
		log.SetOutput(os.Stdout)
		return nil
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
