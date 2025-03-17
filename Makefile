obj-m += the_bdev_snapshot.o
the_bdev_snapshot-objs += bdev_snapshot.o lib/scth.o lib/snapshot.o lib/scinstall.o lib/utils.o lib/auth.o

# Kernel build variables
KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

# Linux syscall table discoverer repository information
USCTM_REPO := https://github.com/0xmenna/usctm.git

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
		sudo insmod the_bdev_snapshot.ko the_syscall_table=$$(sudo cat /sys/module/the_usctm/parameters/sys_call_table_address); \
	else \
		sudo insmod tests/singlefile_fs/singlefilefs.ko; \
	fi
endef

define rmm_module
	sudo rmmod $1
endef

# -----------------------------------------------------------

up: all mount

down: unmount clean

all: build_usctm build_bdev_snapshot build_testing_fs create_testing_fs

# Clone the usctm repository if it doesn't exist.
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
	
create_testing_fs:
	dd bs=4096 count=100 if=/dev/zero of=tests/singlefile_fs/image
	./tests/singlefile_fs/singlefilemakefs tests/singlefile_fs/image
	mkdir /tmp/mount

clean:
	$(call clean_module,.)
	$(call clean_module,usctm)
	$(call clean_module,tests/singlefile_fs)
	rm -rf usctm
	rm tests/singlefile_fs/singlefilemakefs

mount: mount_usctm mount_bdev_snapshot mount_testing_fs

unmount: unmount_bdev_snapshot unmount_testing_fs unmount_usctm

mount_usctm:
	$(call ins_module,usctm)

mount_bdev_snapshot:
	$(call ins_module,bdev_snapshot)

mount_testing_fs:
	$(call ins_module,singlefile_fs)
	sudo mount -o loop -t singlefilefs tests/singlefile_fs/image /tmp/mount/

unmount_usctm:
	$(call rmm_module,usctm/the_usctm.ko)

unmount_bdev_snapshot:
	$(call rmm_module,the_bdev_snapshot.ko)

unmount_testing_fs:
	sudo umount /tmp/mount/
	$(call rmm_module,tests/singlefile_fs/singlefilefs.ko)

