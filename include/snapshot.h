#ifndef SNAPSHOT_H

#define SNAPSHOT_H

#include <linux/atomic.h>
#include <linux/blkdev.h>
#include <linux/hashtable.h>
#include <linux/jhash.h>
#include <linux/kernel.h>
#include <linux/kfifo.h>
#include <linux/kthread.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/namei.h>
#include <linux/rculist.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/uaccess.h>

#include "hlist_rcu.h"
#include "utils.h"

#define S_BLOCKS_HASH_BITS 16
#define HASH_BITS 8

#define NODEV 1
#define DEXIST 2
#define NOSDEV 3
#define AUTHF 4
#define SBUSY 5
#define MODUNLOAD 6
#define SESSIONOVFLW 7
#define SDEVNOTACTIVE 8
#define NOPHYSBLOCK 9
#define NOBHEAD 10
#define NOMNTD 11
#define PATHEXIST 12
#define FREE_SDEV 13
#define FREE_SDEV_NO_SESSION 14
#define SNAPDIR_EXIST 15
#define FREE_RCU 16
#define NOFDEV 17
#define BLOCK_COMMITTED 18
#define NO_RBLOCK 19

#define AUDIT if (1)

#define DEBUG_ASSERT(cond) BUG_ON(!(cond))

struct snapshot_devices {
      // Registered devices that are mapped to an actual block device
      // (i.e. a snapshot device is a registered block device to the
      // snapshot subsystem)
      struct hlist_head sdevices[1 << HASH_BITS];
      // Locks for the registered devices buckets
      spinlock_t s_locks[1 << HASH_BITS];
      // Registered device-files
      struct list_head fdevices;
      // Lock for the `fdevices` list
      spinlock_t f_lock;
};

// Registered devices to the snapshot subsystem
static struct snapshot_devices devices;

// A device-file (it holds the dentry associated to the file managed as
// device-file). The dentry will be related to the `lo_backing_file` of a
// loop device.
typedef struct _file_dev {
      struct dentry *dentry;
      char dev_name[MAX_DEV_LEN];
      bool is_mapped;
      struct list_head node;
      struct rcu_head rcu;
} file_dev_t;

static inline void INIT_FDEV(file_dev_t *fdev, struct dentry *dentry,
                             const char *dev_name) {
      int dev_len = strlen(dev_name);
      AUDIT DEBUG_ASSERT(dev_len < MAX_DEV_LEN);

      fdev->dentry = dget(dentry);
      strncpy(fdev->dev_name, dev_name, dev_len);
      fdev->is_mapped = false;
      INIT_LIST_HEAD(&fdev->node);
}

static inline const char *fdev_name(file_dev_t *fdev) { return fdev->dev_name; }

static void rcu_register_filedev(file_dev_t *fdev) {
      spin_lock(&devices.f_lock);
      list_add_rcu(&fdev->node, &devices.fdevices);
      spin_unlock(&devices.f_lock);
}

static void rcu_unregister_filedev(file_dev_t *fdev) {
      spin_lock(&devices.f_lock);
      list_del_rcu(&fdev->node);
      spin_unlock(&devices.f_lock);
}

static void rcu_replace_filedev(file_dev_t *old_fdev, file_dev_t *new_fdev) {
      spin_lock(&devices.f_lock);
      list_replace_rcu(&old_fdev->node, &new_fdev->node);
      spin_unlock(&devices.f_lock);
}

static inline void put_fdev_callback(struct rcu_head *rcu) {
      file_dev_t *fdev = container_of(rcu, file_dev_t, rcu);

      AUDIT log_info(
          "Callback free: loop backing file : %s , preempt_count : %d\n",
          fdev_name(fdev), preempt_count());

      dput(fdev->dentry);
      kfree(fdev);
}

// Callback function that checks wheter a device-file is already
// registered. Used within the `rcu_compute_on_filedev` function.
static inline int no_file_dev_callback(file_dev_t *fdev, void *arg) {
      if (fdev != NULL) {
            return -DEXIST;
      }
      return 0;
}

// Callback function that checks if the device-file is registered
static inline int lo_backing_file_exists_callback(file_dev_t *fdev, void *arg) {
      const char *dev_name;
      if (fdev == NULL) {
            return -NOFDEV;
      }

      // Pass the device name to the caller
      *(char **)arg = fdev->dev_name;

      return 0;
}

// Remove a device-file from the registered devices. It is
// used as a callback for the `rcu_compute_on_filedev` function.
static int remove_fdev_callback(file_dev_t *fdev, void *arg) {
      if (!fdev) {
            return -NOSDEV;
      }
      if (fdev->is_mapped) {
            // Cannot remove device file because it is mapped to a block
            // device (i.e. has an active session)
            return -SBUSY;
      }
      // Unregister the device
      rcu_unregister_filedev(fdev);

      // The free of `fdev` is demanded to the `rcu_compute_on_filedev`
      // function
      return FREE_RCU;
}

// Computes a function on a device-file. It looks up the device (via its dentry)
// and calls the compute function on the found device (it follows RCU based
// "locking").
static int rcu_compute_on_filedev(struct dentry *lookup_dentry, void *arg,
                                  int (*compute_f)(file_dev_t *, void *)) {

      file_dev_t *fdev, *found_fdev = NULL;
      struct inode *fdev_inode = NULL;
      int ret;

      struct inode *lookup_inode = d_inode(lookup_dentry);

      rcu_read_lock();
      list_for_each_entry(fdev, &devices.fdevices, node) {
            fdev_inode = d_inode(fdev->dentry);
            if (fdev_inode->i_ino == lookup_inode->i_ino &&
                fdev_inode->i_sb == lookup_inode->i_sb) {
                  found_fdev = fdev;
                  break;
            }
      }
      ret = compute_f(found_fdev, arg);
      rcu_read_unlock();

      if (ret == FREE_RCU) {
#ifdef ASYNC
            // Suited for atomic context
            call_rcu(&found_fdev->rcu, put_fdev_callback);
#else
            // Never activate this when executing in atomic context
            sychronize_rcu();
            dput(found_fdev->dentry);
            kfree(found_fdev);
#endif
            ret = 0;
      }

      return ret;
}

typedef struct generic_dev {
      enum { BDEV, FDEV } type;
      union {
            dev_t dev;
            file_dev_t fdev;
      };
} generic_dev_t;

struct snap_block {
      // The actual physical block
      sector_t block;
      // The inode of the file being modified.
      struct inode *inode;
      // A node for the hash list of committed blocks
      struct hlist_node cb_hnode;
      // A node for the hash list of reading blocks
      struct hlist_node rb_hnode;
};

static inline void INIT_SNAP_BLOCK(struct snap_block *sb, struct inode *inode,
                                   sector_t block) {
      sb->block = block;
      sb->inode = inode;
      INIT_HLIST_NODE(&sb->cb_hnode);
      INIT_HLIST_NODE(&sb->rb_hnode);
}

static inline void sb_free(struct snap_block *sb) {
      iput(sb->inode);
      kfree(sb);
}

static inline u32 hash_block(sector_t block) {
      return hash_64(block, S_BLOCKS_HASH_BITS);
}

typedef struct _snapshot_session {
      u64 mount_timestamp;
      struct path snap_path;
      struct hlist_head reading_blocks[1 << S_BLOCKS_HASH_BITS];
      spinlock_t rb_locks[1 << S_BLOCKS_HASH_BITS];
      struct hlist_head committed_blocks[1 << S_BLOCKS_HASH_BITS];
      spinlock_t cb_locks[1 << S_BLOCKS_HASH_BITS];
} snapshot_session;

static inline void init_snapshot_session(snapshot_session *snap_session,
                                         time64_t timestamp) {

      snap_session->snap_path.dentry = NULL;
      snap_session->snap_path.mnt = NULL;
      snap_session->mount_timestamp = timestamp;
}

static inline struct path session_path_get(snapshot_session *session) {
      if (session->snap_path.dentry == NULL) {
            goto ret_path;
      }
      path_get(&session->snap_path);

ret_path:
      return session->snap_path;
}

static inline void session_path_put(snapshot_session *session) {
      if (session->snap_path.dentry == NULL) {
            return;
      }
      path_put(&session->snap_path);
}

static inline struct dentry *d_session(snapshot_session *session) {
      return session->snap_path.dentry;
}

/**
 * struct snap_device - Represents a block device registered to the
 * snapshot subsystem.
 * @dev: Device number.
 * @dentry: Dentry that identifies the device. For loop devices it is the dentry
 * of the `lo_backing_file`
 * @snapshot_session: Pointer to the active snapshot session.
 * @hnode: Hash list node for linking this device in the registered
 * devices that are mapped to a block device table.
 * @rcu: RCU head for safe removal of this device from the registered
 * devices
 * @private_data: Useful for holding private data (e.g. for loop devices it can
 * hold the dentry associated to the `lo_backing_file`)
 */
typedef struct _snap_device {
      dev_t dev;
      char dev_name[MAX_DEV_LEN];
      snapshot_session *session;
      struct hlist_node hnode;
      struct rcu_head rcu;
      void *private_data;
} snap_device;

static inline dev_t d_num(snap_device *sdev) { return sdev->dev; }

static inline const char *sdev_name(snap_device *sdev) {
      return sdev->dev_name;
}

static inline u32 hash_dev(dev_t dev) { return hash_32(dev, HASH_BITS); }

static inline void INIT_SNAP_DEVICE(snap_device *sdev, dev_t dev,
                                    const char *dev_name) {
      int dev_len = strlen(dev_name);
      AUDIT DEBUG_ASSERT(dev_len < MAX_DEV_LEN);

      sdev->dev = dev;
      strncpy(sdev->dev_name, dev_name, dev_len);
      sdev->session = NULL;
      sdev->private_data = NULL;
      INIT_HLIST_NODE(&sdev->hnode);
}

// Free a snapshot device and its session
static void free_sdev(snap_device *sdev) {
      if (sdev->session) {
            snapshot_session *session = sdev->session;
            int i;

            // Release the reference held by snap_path
            path_put(&session->snap_path);

            // Free all allocated committed blocks
            for (i = 0; i < (1 << S_BLOCKS_HASH_BITS); i++) {
                  struct snap_block *sb;
                  struct hlist_node *tmp;
                  hlist_for_each_entry_safe(
                      sb, tmp, &session->committed_blocks[i], cb_hnode) {
                        hlist_del(&sb->cb_hnode);
                        kfree(sb);
                  }
            }
            kfree(session);
      }

      kfree(sdev);
}

// Callback to free a snapshot device without its session within async RCU
// context
static inline void free_sdev_no_session_callback(struct rcu_head *rcu) {
      snap_device *sdev = container_of(rcu, snap_device, rcu);

      AUDIT log_info(
          "Callback free (no session): block device : %s, preempt_count : %d\n",
          sdev_name(sdev), preempt_count());

      kfree(sdev);
}

// Callback to free a snapshot device and its session within async RCU
// context
static inline void free_sdev_callback(struct rcu_head *rcu) {
      snap_device *sdev = container_of(rcu, snap_device, rcu);

      AUDIT log_info("Callback free: block device : %s, preempt_count : %d\n",
                     sdev_name(sdev), preempt_count());

      free_sdev(sdev);
}

// Add a snapshot device to the registered devices
static inline void rcu_register_snapdevice(snap_device *sdev) {
      u32 hash = hash_dev(d_num(sdev));

      HLIST_RCU_INSERT(sdev, devices.sdevices, devices.s_locks, hash);
}

// Remove a snapshot device from the registered devices
static inline void rcu_unregister_snapdevice(snap_device *sdev) {
      u32 hash = hash_dev(d_num(sdev));

      HLIST_RCU_REMOVE(sdev, devices.s_locks, hash);
}

// Helper function to check if a snapshot device is not registered. It
// is used as a callback for the `rcu_compute_on_sdev` function.
static inline int no_sdev_callback(snap_device *sdev, void *arg) {
      if (sdev != NULL) {
            return -DEXIST;
      } else {
            return 0;
      }
}

// Remove a snapshot device from the registered snapshot devices. It is
// used as a callback for the `rcu_compute_on_sdev` function.
static int remove_sdev_callback(snap_device *sdev, void *arg) {
      if (!sdev) {
            return -NOSDEV;
      }
      if (sdev->session) {
            // Cannot remove snapshot device because it has an active
            // session
            return -SBUSY;
      }
      // Unregister the snapshot device
      rcu_unregister_snapdevice(sdev);

      // The free of `sdev` is demanded to the `rcu_compute_on_sdev`
      // function
      return FREE_SDEV;
}

// Computes a function on a snapshot device. It looks up the device by its
// `dev_t` identifier and calls the function following RCU based
// "locking".
static inline int rcu_compute_on_sdev(dev_t dev, void *arg,
                                      int (*compute_f)(snap_device *, void *)) {
      int ret;
      snap_device *sdev =
          HLIST_RCU_LOOKUP(dev, hash_dev, devices.sdevices, snap_device, d_num);

      ret = compute_f(sdev, arg);
      HLIST_RCU_READ_UNLOCK();

      if (ret == FREE_SDEV) {
#ifdef ASYNC
            // Suited for atomic context
            call_rcu(&sdev->rcu, free_sdev_callback);
#else
            // Never activate this when executing in atomic context
            sychronize_rcu();
            free_sdev(sdev);
#endif
            ret = 0;
      } else if (ret == FREE_SDEV_NO_SESSION) {
#ifdef ASYNC
            call_rcu(&sdev->rcu, free_sdev_no_session_callback);
#else
            sychronize_rcu();
            kfree(sdev);
#endif
            ret = 0;
      }

      return ret;
}

/**
 * struct block_log_entry - Represents a logged block modification.
 * @snap_path:   Identifies the snapshot path within an active session.
 * @inode:      Pointer to the inode of the file being modified. Useful to
 * retrieve the underlying device name but most importantly to mantain a
 * reference to avoid the associated fs to be unmounted. We want to be sure that
 * until there are log entries to process the file system hosted on the block
 * device of interest is not umounted.
 * @block: Block (or sector) offset on the device.
 * @orig_data:    Pointer to a copy of the original block data.
 * @data_size:    Size in bytes of the block.
 *
 * Each entry records the original content of a modified block.
 */
typedef struct block_log_entry {
      struct path snap_path;
      struct inode *inode;
      sector_t block;
      char *orig_data;
      size_t data_size;

      struct list_head node;
} blog_entry;

static void INIT_BLOG_ENTRY(blog_entry *entry, struct path snap_path,
                            sector_t block, char *bdata, size_t data_size) {
      entry->snap_path = snap_path;
      entry->inode = NULL;
      entry->block = block;
      entry->orig_data = bdata;
      entry->data_size = data_size;
      INIT_LIST_HEAD(&entry->node);
}

static inline void free_blog_entry(blog_entry *entry) {
      if (entry->orig_data) {
            kfree(entry->orig_data);
      }
      if (entry->inode) {
            iput(entry->inode);
      }
      path_put(&entry->snap_path);
}

int register_my_kretprobes(void);
void unregister_my_kretprobes(void);

int init_snapshot_path(void);
void put_snapshot_path(void);

void init_devices(void);

void init_per_cpu_work(void);
void debug_no_pending_work(void);

int activate_snapshot(const char *dev_name, const char *passwd);
int deactivate_snapshot(const char *dev_name, const char *passwd);

#endif
