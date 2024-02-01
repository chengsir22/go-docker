TARGETS = hostname.sh mountkernfs.sh mountdevsubfs.sh procps urandom hwclock.sh checkroot.sh mountnfs-bootclean.sh mountnfs.sh bootmisc.sh mountall-bootclean.sh mountall.sh checkfs.sh checkroot-bootclean.sh
INTERACTIVE = checkroot.sh checkfs.sh
mountdevsubfs.sh: mountkernfs.sh
procps: mountkernfs.sh
urandom: hwclock.sh
hwclock.sh: mountdevsubfs.sh
checkroot.sh: hwclock.sh mountdevsubfs.sh hostname.sh
mountnfs-bootclean.sh: mountnfs.sh
bootmisc.sh: mountnfs-bootclean.sh mountall-bootclean.sh checkroot-bootclean.sh
mountall-bootclean.sh: mountall.sh
mountall.sh: checkfs.sh checkroot-bootclean.sh
checkfs.sh: checkroot.sh
checkroot-bootclean.sh: checkroot.sh
