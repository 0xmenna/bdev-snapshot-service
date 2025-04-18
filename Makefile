obj-m += the_bdev_snapshot.o
the_bdev_snapshot-objs += bdev_snapshot.o lib/scth.o lib/snapshot.o lib/scinstall.o lib/utils.o lib/auth.o lib/ioctl.o lib/snapshot.o

# Kernel build variables
KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

# Linux syscall table discoverer repository information
USCTM_REPO := https://github.com/0xmenna/usctm.git

PASSWD_PATH = $(PWD)/the_snapshot_secret

# -----------------------------------------------------------

define build_module
	make -C $(KDIR) M=$(PWD)/$1 modules;
endef

define clean_module
	make -C $(KDIR) M=$(PWD)/$1 clean
endef

define ins_snap_module_syscall
	sudo insmod the_bdev_snapshot.ko \
	the_syscall_table=$$(sudo cat /sys/module/the_usctm/parameters/sys_call_table_address) \ the_snapshot_secret=$$(sudo cat $(PASSWD_PATH))
endef

define ins_snap_module_ioctl
	sudo insmod the_bdev_snapshot.ko \
		snapshot_ioctl=1 \
		the_snapshot_secret=$$(sudo cat $(PASSWD_PATH))
endef

define ins_snap_module_all
	sudo insmod the_bdev_snapshot.ko \
		the_syscall_table=$$(sudo cat /sys/module/the_usctm/parameters/sys_call_table_address) \
		snapshot_ioctl=1 \
		the_snapshot_secret=$$(sudo cat $(PASSWD_PATH))
endef


define ins_snap_module_experimental
	sudo insmod the_bdev_snapshot.ko \
		snapshot_ioctl=1 \
		the_snapshot_secret=$$(sudo cat $(PASSWD_PATH)) \
		testing_filesystem=0
endef


define ins_module
	@if [ "$1" = "usctm" ]; then \
		sudo insmod usctm/the_usctm.ko; \
	elif [ "$1" = "bdev_snapshot_syscall" ]; then \
		$(ins_snap_module_syscall); \
	elif [ "$1" = "bdev_snapshot_ioctl" ]; then \
		$(ins_snap_module_ioctl); \
	elif [ "$1" = "bdev_snapshot_all" ]; then \
		$(ins_snap_module_all); \
	elif [ "$1" = "bdev_snapshot_experimental" ]; then \
		$(ins_snap_module_experimental); \
	else \
		sudo insmod tests/singlefile_fs/singlefilefs.ko; \
	fi
endef

define rmm_module
	sudo rmmod $1
endef

# -----------------------------------------------------------

test: build_bdev_snapshot build_testing_fs load_bdev_snapshot_ioctl load_testing_fs_driver create_testing_fs run_test_singlefilefs unload_testing_fs_driver unload_bdev_snapshot load_bdev_snapshot_experimental run_test_ext4 unload_bdev_snapshot remove_mounting_point

run_test_singlefilefs: 
	cd tests && sudo python3 snapshot_test.py "singlefilefs"

run_test_ext4:
	cd tests && sudo python3 snapshot_test.py "ext4"

all: build_usctm build_bdev_snapshot build_testing_fs

clean:
	$(call clean_module,.)
	$(call clean_module,usctm)
	$(call clean_module,tests/singlefile_fs)
	rm -rf usctm
	rm tests/singlefile_fs/singlefilemakefs

load: load_usctm load_bdev_snapshot_all load_testing_fs_driver

unload: unload_testing_fs_driver unload_bdev_snapshot unload_usctm

clone_usctm:
	@if [ ! -d "usctm" ]; then \
		git clone $(USCTM_REPO); \
	else \
		echo "usctm repository already exists, skipping clone."; \
	fi

build_usctm: clone_usctm
	$(call build_module,usctm)

build_bdev_snapshot:
	$(call build_module,.)

build_testing_fs:
	gcc tests/singlefile_fs/singlefilemakefs.c -o tests/singlefile_fs/singlefilemakefs
	$(call build_module,tests/singlefile_fs)

load_usctm:
	$(call ins_module,usctm)

load_bdev_snapshot_ioctl:
	$(call ins_module,bdev_snapshot_ioctl)

load_bdev_snapshot_syscall:
	$(call ins_module,bdev_snapshot_syscall)

load_bdev_snapshot_all:
	$(call ins_module,bdev_snapshot_all)

load_bdev_snapshot_experimental:
	$(call ins_module,bdev_snapshot_experimental)

unload_usctm:
	$(call rmm_module,usctm/the_usctm.ko)

unload_bdev_snapshot:
	$(call rmm_module,the_bdev_snapshot.ko)
	sudo rm -rf /snapshot

create_testing_fs:
	dd bs=4096 count=100 if=/dev/zero of=tests/singlefile_fs/sf.img
	./tests/singlefile_fs/singlefilemakefs tests/singlefile_fs/sf.img

	dd bs=4096 count=100 if=/dev/zero of=tests/ext4/ext4.img
	mkfs.ext4 -b 4096 tests/ext4/ext4.img

	mkdir /tmp/mnt

load_testing_fs_driver:
	$(call ins_module,singlefile_fs)

unload_testing_fs_driver:
	$(call rmm_module,tests/singlefile_fs/singlefilefs.ko)

mount_testing_fs:
	sudo mount -o loop -t singlefilefs tests/singlefile_fs/sf.img /tmp/mnt

umount_testing_fs:
	sudo umount /tmp/mnt


remove_mounting_point:
	sudo rm -rf /tmp/mnt

