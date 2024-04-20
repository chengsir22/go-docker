package main

import (
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
)

const usage = `docker is a simple container implementation`

func main() {
	app := &cli.App{
		Name:  "go-docker",
		Usage: usage,
	}

	app.Commands = []*cli.Command{
		initCommand,
		runCommand,
	}

	app.Before = func(ctx *cli.Context) error {
		log.SetFormatter(&log.JSONFormatter{})
		log.SetOutput(os.Stdout)
		return nil
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
