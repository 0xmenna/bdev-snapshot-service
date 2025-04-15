#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <zlib.h>

#include "snapshot.h"

#define USE_IOCTL

#ifdef USE_IOCTL

#include <fcntl.h>
#include <limits.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>

#define SNAPSHOT_IOCTL_MAGIC 'S'
#define SNAP_ACTIVATE _IOW(SNAPSHOT_IOCTL_MAGIC, 1, struct snapshot_args)
#define SNAP_DEACTIVATE _IOW(SNAPSHOT_IOCTL_MAGIC, 2, struct snapshot_args)

/* Structure shared with the kernel module */
struct snapshot_args {
      char dev_name[1024];
      char passwd[64];
};

#define DEVICE_FILE "/dev/snap"

int sys_activate_snapshot(const char *devname, const char *password) {
      int fd = open(DEVICE_FILE, O_RDWR);
      if (fd < 0) {
            return -errno;
      }

      struct snapshot_args args;
      memset(&args, 0, sizeof(args));
      strncpy(args.dev_name, devname, sizeof(args.dev_name) - 1);
      strncpy(args.passwd, password, sizeof(args.passwd) - 1);

      int ret = ioctl(fd, SNAP_ACTIVATE, &args);
      if (ret < 0) {
            close(fd);
            return -errno;
      }

      close(fd);
      return ret;
}

int sys_deactivate_snapshot(const char *devname, const char *password) {
      int fd = open(DEVICE_FILE, O_RDWR);
      if (fd < 0) {
            return -errno;
      }

      struct snapshot_args args;
      memset(&args, 0, sizeof(args));
      strncpy(args.dev_name, devname, sizeof(args.dev_name) - 1);
      strncpy(args.passwd, password, sizeof(args.passwd) - 1);

      int ret = ioctl(fd, SNAP_DEACTIVATE, &args);
      if (ret < 0) {
            close(fd);
            return -errno;
      }

      close(fd);
      return ret;
}
#else

#include <sys/syscall.h>

/* Define syscall numbers according to your kernel configuration */
#define ACTIVATE 156
#define DISACTIVATE 174

int sys_activate_snapshot(const char *devname, const char *password) {
      int ret = syscall(ACTIVATE, devname, password);
      if (ret) {
            return -errno;
      }
      return ret;
}

int sys_deactivate_snapshot(const char *devname, const char *password) {
      int ret = syscall(DISACTIVATE, devname, password);
      if (ret) {
            return -errno;
      }
      return ret;
}
#endif

uint32_t compute_checksum(const char *data, size_t size, uint32_t seed) {
      return crc32(seed, (const unsigned char *)data, size);
}
