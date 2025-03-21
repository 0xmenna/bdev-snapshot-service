#ifndef SNAPSHOT_SESSION_H

#define SNAPSHOT_SESSION_H

#include <linux/atomic.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/percpu.h>
#include <linux/sched.h>
#include <linux/signal.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/time.h>
#include <linux/timer.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/wait.h>

#include "../include/snapshot.h"

#define LIBNAME "SNAPSHOT"

#define AUDIT if (1)

#define COMMITTED_HASH_BITS 16
#define HASH_BITS 8

/* Registered devices to the snapshot subsystem */
static hregistered_devices devices[1 << HASH_BITS];

/* Per-CPU block log FIFO */
static DEFINE_PER_CPU(block_fifo, cpu_block_fifo);

static inline bool is_path(const char *devname) {
   return (strchr(devname, '/') != NULL);
}

static inline int get_device_by_name(const char *path, device_t *dev) {
   struct path p;
   int err;
   char full_path[MAX_PATH];

   if (!is_path(path)) {
      // "dev_name" is not a path: prepend /dev/ to the device name
      if (strlen(path) >= MAX_DEV_NAME) {
         AUDIT log_err("Device name too long\n");
         return -ENAMETOOLONG;
      }

      strcpy(full_path, "/dev/");
      strcat(full_path, path);
   } else {
      // "dev_name" is a path
      if (strlen(path) >= MAX_PATH) {
         AUDIT log_err("Device pathname too long\n");
         return -ENAMETOOLONG;
      }
      strcpy(full_path, path);
   }

   err = kern_path(full_path, LOOKUP_FOLLOW, &p);
   if (err) {
      AUDIT log_err("Failed to lookup %s: %d\n", full_path, err);
      return err;
   }

   // Verify that the inode represents a block device
   if (!S_ISBLK(p.dentry->d_inode->i_mode)) {
      AUDIT log_err("%s is not a block device\n", full_path);
      path_put(&p);
      return -NODEV;
   }

   // Get a reference to the dentry
   struct dentry *dentry = dget(p.dentry);
   INIT_DEV(dev, dentry);

   path_put(&p);

   return 0;
}

/**
 * try_init_snapdevice - Initializes a snap_device structure from a device
 * name.
 * @sdev: Pointer to the snap_device structure to initialize.
 * @dev_name: Name of the device to initialize.
 *
 * Returns 0 on success, or a negative error code.
 */
static int try_init_snapdevice_by_name(char *dev_name, snap_device *sdev) {
   struct path p;
   int err;
   device_t dev;
   char full_path[MAX_PATH];

   err = get_device_by_name(dev_name, &dev);
   if (err) {
      AUDIT log_err("Failed to get device by name: %d\n", err);
      return err;
   }

   INIT_SNAP_DEVICE(sdev, dev);
   AUDIT log_info("Snapshot device initialized succesfully\n");

   return 0;
}

static int init_snapshot_session(snapshot_session *snap_session, char *dev_name,
                                 struct path *parent_path) {
   struct tm tm;
   char date_str[16]; // Format: YYYYMMDD_HHMMSS
   char snap_subdirname[128];
   char snap_dirname[128];
   struct dentry *subdentry = NULL;
   int ret = 0;

   // Check that the device name is within allowed limits
   if (strlen(dev_name) >= MAX_PATH) {
      AUDIT log_err("Device name too long\n");
      return -EINVAL;
   }

   // Initialize session id and mount timestamp
   snap_session->session_id = atomic_inc_return(&global_session_id);
   snap_session->mount_timestamp = ktime_get_real_seconds();

   // Format the timestamp into a date string: YYYYMMDD_HHMMSS
   time64_to_tm(snap_session->mount_timestamp, 0, &tm);
   snprintf(date_str, sizeof(date_str), "%04ld%02ld%02ld_%02ld%02ld%02ld",
            tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min,
            tm.tm_sec);

   // Build the snapshot subdirectory name: "<dev_name>_<date_str>"
   snprintf(snap_subdirname, sizeof(snap_subdirname), "%s_%s", dev_name,
            date_str);

   // Construct the full snapshot directory path
   snprintf(snap_dirname, sizeof(snap_dirname), "%s/%s",
            parent_path->dentry->d_name.name, snap_subdirname);

   // Allocate a new dentry for the subdirectory
   subdentry = d_alloc_name(parent_path->dentry, snap_subdirname);
   if (!subdentry) {
      AUDIT log_err("Failed to allocate dentry for %s\n", snap_subdirname);
      return -ENOMEM;
   }

   // Create the new directory
   ret = vfs_mkdir(parent_path->mnt->mnt_idmap, d_inode(parent_path->dentry),
                   subdentry, 0600);
   if (ret) {
      AUDIT log_err("vfs_mkdir failed for %s: %d\n", snap_subdirname, ret);
      goto out;
   }

   // Lookup the full path of the new directory
   ret = kern_path(snap_dirname, LOOKUP_FOLLOW, &snap_session->snap_path);
   if (ret) {
      AUDIT log_err("Failed to lookup new directory %s: %d\n", snap_dirname,
                    ret);
      goto out;
   }

out:
   dput(subdentry);
   return ret;
}

int activate_snapshot(char *dev_name, char *passwd) {
   snap_device sdev;
   int err;
   dev_t devnum;

   // Check if the device is already registered
   err = try_init_snapdevice_by_name(dev_name, &sdev);
   if (err) {
      AUDIT log_err("Failed to initialize snapshot device: %d\n", err);
      return err;
   }

   devnum = d_num(&sdev);

   return -1;
}

int deactivate_snapshot(char *dev_name, char *passwd) {

   AUDIT printk("%s: service not yet implemented\n", THIS_MODULE->name);

   return -1;
}

#endif