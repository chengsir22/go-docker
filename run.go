package main

import (
	"os"
	"strings"

	"github.com/chengsir22/go-docker/container"
	log "github.com/sirupsen/logrus"
)

func Run(tty bool, comArray []string) {
	parent, writePipe := container.NewParentProcess(tty)
	if parent == nil {
		log.Errorf("New parent process error")
		return
	}
	if err := parent.Start(); err != nil {
		log.Errorf("parent start fail, error: %v",err)
	}
	sendInitCommand(comArray, writePipe)
	defer parent.Wait()
	os.Exit(0)
}

func sendInitCommand(comArray []string, writePipe *os.File) {
	command := strings.Join(comArray, " ")
	log.Infof("command : %s", command)
	writePipe.WriteString(command)
	writePipe.Close()
}
