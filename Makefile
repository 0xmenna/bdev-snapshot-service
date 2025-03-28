obj-m += the_bdev_snapshot.o
the_bdev_snapshot-objs += bdev_snapshot.o lib/scth.o lib/snapshot.o lib/scinstall.o lib/utils.o lib/auth.o lib/snapshot.o

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

define ins_module
	@if [ "$1" = "usctm" ]; then \
		sudo insmod usctm/the_usctm.ko; \
	elif [ "$1" = "bdev_snapshot" ]; then \
		sudo insmod the_bdev_snapshot.ko the_syscall_table=$$(sudo cat /sys/module/the_usctm/parameters/sys_call_table_address) the_snapshot_secret=$$(sudo cat $(PASSWD_PATH)); \
	else \
		sudo insmod tests/singlefile_fs/singlefilefs.ko; \
	fi
endef

define rmm_module
	sudo rmmod $1
endef

# -----------------------------------------------------------

up: all load

down: unload clean

all: build_usctm build_bdev_snapshot build_testing_fs

clean:
	$(call clean_module,.)
	$(call clean_module,usctm)
	$(call clean_module,tests/singlefile_fs)
	rm -rf usctm
	rm tests/singlefile_fs/singlefilemakefs

load: load_usctm load_bdev_snapshot load_testing_fs_driver

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

load_bdev_snapshot:
	$(call ins_module,bdev_snapshot)

unload_usctm:
	$(call rmm_module,usctm/the_usctm.ko)

unload_bdev_snapshot:
	$(call rmm_module,the_bdev_snapshot.ko)

create_testing_fs:
	dd bs=4096 count=100 if=/dev/zero of=tests/singlefile_fs/image
	./tests/singlefile_fs/singlefilemakefs tests/singlefile_fs/image
	sudo losetup /dev/loop0 tests/singlefile_fs/image
	mkdir /tmp/mnt

rm_testing_fs:
	rm -rf /tmp/mnt
	sudo losetup -d /dev/loop0
	rm tests/singlefile_fs/image

load_testing_fs_driver:
	$(call ins_module,singlefile_fs)

unload_testing_fs_driver:
	$(call rmm_module,tests/singlefile_fs/singlefilefs.ko)

mount_testing_fs:
	sudo mount -t singlefilefs /dev/loop0 /tmp/mnt

umount_testing_fs:
	sudo umount /tmp/mnt

