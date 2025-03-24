
#ifndef _SNAPSHOT_H_

#define _SNAPSHOT_H_

#include <linux/atomic.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/hashtable.h>
#include <linux/jhash.h>
#include <linux/kernel.h>
#include <linux/kfifo.h>
#include <linux/kthread.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/namei.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/uaccess.h>

#include "utils.h"

#define COMMITTED_HASH_BITS 16
#define HASH_BITS 8

#define NODEV 1
#define DEXIST 2
#define NOSDEV 3
#define SDEVREPLACE 4
#define AUTHF 5
#define SBUSY 6

#define AUDIT if (1)

typedef struct _device {
      // In more recent kernels to work with block devices, we use vfs related
      // structures.
      // TODO: Once the project is done for my version use ifdefs to switch
      // implementation based on the version.
      struct dentry *dentry;
} device_t;

static inline struct dentry *d_dev(device_t *device) { return device->dentry; }

static inline struct inode *i_dev(device_t *device) {
      return device->dentry->d_inode;
}

static inline dev_t num_dev(device_t *device) {
      struct inode *inode = d_backing_inode(device->dentry);
      return inode->i_rdev;
}

static inline void dev_put(device_t *device) { dput(device->dentry); }

static inline void INIT_DEV(device_t *device, struct dentry *dentry) {
      device->dentry = dentry;
}

// Check if a block device is mounted
static bool is_block_device_mounted(struct inode *inode) {
      struct block_device *bdev;
      struct super_block *sb;

      /* Ensure the inode represents a block device */
      if (!S_ISBLK(inode->i_mode))
            return false;

      /* Get the block_device structure */
      bdev = I_BDEV(inode);

      /* Check if bd_holder is non-NULL */
      sb = bdev->bd_holder;
      if (sb)
            return true; // Filesystem is mounted
      else
            return false; // No filesystem is mounted
}

/**
 * struct snapshot_session - Represents an active snapshot session.
 * @session_id:  Unique session identifier.
 * @mount_timestamp:  Unix timestamp (u64) when the session was activated.
 * @snap_dir:    Snapshot directory path (e.g.,
 * "/snapshot/devname_timestamp").
 * @committed_blocks:  Hash table for committed blocks (i.e. blocks that
 * eventually go to storage).
 *
 */
typedef struct _snapshot_session {
      int session_id;
      u64 mount_timestamp;
      struct path snap_path;
      struct hlist_head committed_blocks[1 << COMMITTED_HASH_BITS];
} snapshot_session;

struct committed_block {
      sector_t block;
      struct hlist_node hnode;
};

/**
 * struct block_log_entry - Represents a logged block modification.
 * @session_id:   Snapshot session id to which this entry belongs.
 * @block_offset: Block (or sector) offset on the device.
 * @orig_data:    Pointer to a copy of the original block data.
 * @data_size:    Size in bytes of the block.
 *
 * Each entry records the original content of a modified block.
 */
typedef struct block_log_entry {
      int session_id;
      sector_t block;
      void *orig_data;
      size_t data_size;
} blog_entry;

/**
 * struct snap_device - Represents a block device registered to the snapshot
 * subsystem.
 * @device: Device number.
 * @snapshot_session Pointer to the active snapshot session.
 * @hnode: Hash list node for linking this device in the registered devices
 * table.
 * @rcu: RCU head for safe removal of this device from the registered devices
 */
typedef struct _snap_device {
      device_t dev;
      snapshot_session *session;
      struct hlist_node hnode;
      struct rcu_head rcu;
} snap_device;

static inline device_t dev(snap_device *sdev) { return sdev->dev; }

static inline dev_t d_num(snap_device *sdev) { return num_dev(&sdev->dev); }

static inline const char *sdev_name(snap_device *sdev) {
      return sdev->dev.dentry->d_name.name;
}

static inline u32 hash_dev(dev_t dev) { return hash_32(dev, HASH_BITS); }

static inline void INIT_SNAP_DEVICE(snap_device *sdev, device_t device) {
      sdev->dev = device;
      sdev->session = NULL;
      INIT_HLIST_NODE(&sdev->hnode);
}

/**
 * block_fifo - Used for per-CPU FIFO for block log entries.
 * @fifo: A kfifo holding pointers to block_log_entry structures.
 *
 * Each FIFO can hold entries of different sessions, allowing
 * concurrent managment of the same session.
 */
typedef struct _block_fifo {
      struct kfifo fifo; /* FIFO for (struct block_log_entry *) */
} block_fifo;

int register_my_kretprobes(void);
void unregister_my_kretprobes(void);

int activate_snapshot(const char *dev_name, const char *passwd);
int deactivate_snapshot(const char *dev_name, const char *passwd);

#endif
