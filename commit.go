package main

import (
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"go-docker/utils"
	"os/exec"
)

func commitContainer(containerID, imageName string) error {
	mntPath := utils.GetMerged(containerID)
	imageTar := utils.GetImage(imageName)
	exists, err := utils.PathExists(imageTar)
	if err != nil {
		return errors.WithMessagef(err, "check is image [%s/%s] exist failed", imageName, imageTar)
	}
	if exists {
		return errors.New("Image Already Exists")
	}
	log.Infof("commitContainer imageTar:%s", imageTar)
	if _, err = exec.Command("tar", "-cvf", imageTar, "-C", mntPath, ".").CombinedOutput(); err != nil {
		return errors.WithMessagef(err, "tar folder %s failed", mntPath)
	}
	return nil
}
