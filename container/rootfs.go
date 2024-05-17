package container

import (
	log "github.com/sirupsen/logrus"
	"go-docker/utils"
	"os"
	"os/exec"
)

// NewWorkSpace Create an Overlay2 filesystem as container root workspace
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

func DeleteWorkSpace(containerID, volume string) {
	// 先 umount volume ，然后再删除目录，否则由于 bind mount 存在，删除临时目录会导致 volume 目录中的数据丢失。
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
