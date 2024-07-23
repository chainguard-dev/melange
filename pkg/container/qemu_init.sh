#!/bin/busybox sh
set -e

/bin/mount -t proc proc -o nodev,nosuid,hidepid=2 /proc
/bin/mount -t devtmpfs -o nosuid,noexec devtmpfs /dev
/bin/mount -t sysfs sys -o nodev,nosuid,noexec /sys
/bin/mount -t tmpfs -o nodev,nosuid,noexec tmpfs /tmp

/bin/mkdir /dev/pts
/bin/mount -t devpts devpts -o noexec,nosuid,newinstance,ptmxmode=0666,mode=0620,gid=tty /dev/pts/
/bin/mount --bind /dev/pts/ptmx /dev/ptmx

# We can ignore this fail, if we use a kernel with kvm_guest.config, we won't need this
# and network will work anyway
# If this fails and we won't have network, the ifconfig command will fail anyway.
# Also we load cpu accelleration drivers in case those are needed.
/usr/bin/sort -u \
	/sys/devices/system/cpu/modalias  \
	/sys/devices/pci*/*/virtio*/modalias | /usr/bin/xargs -n1 /usr/sbin/modprobe 2>/dev/null || :

/bin/ifconfig lo up
/bin/ifconfig eth0 10.0.2.15 netmask 255.255.255.0
/bin/route add default gw 10.0.2.2 eth0
/bin/hostname "$(cat /etc/hostname)"

# Fix home permissions from cpio command
/bin/chown -R build:build /home/build

# ldconfig is run to prime ld.so.cache for glibc packages which require it.
if [ -x /sbin/ldconfig ]; then
	/sbin/ldconfig /lib /usr/lib /usr/lib64 || :
fi

/usr/bin/ssh-keygen -A
exec /usr/sbin/sshd -D
