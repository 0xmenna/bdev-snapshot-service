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
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/uaccess.h>

#include "hlist_rcu.h"
#include "utils.h"

#define COMMITTED_HASH_BITS 16
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

#define AUDIT if (1)

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

// A device mapped to an actual block device
typedef struct _device {
      // Instead of working with `struct block_device` we use the dentry
      // associated to the file identifying the block device (e.g.
      // /dev/sda). This avoids working with the lower level structure (in
      // most recent kernels (>= v6.8) modules must avoid working with the
      // block_device structure).
      struct dentry *dentry;
} device_t;

static inline const char *devname(device_t *dev) {
      return dev->dentry->d_name.name;
}

static inline struct dentry *d_dev(device_t *dev) { return dev->dentry; }

static inline struct inode *i_dev(device_t *dev) {
      return dev->dentry->d_inode;
}

static inline dev_t num_dev(device_t *dev) {
      struct inode *inode = i_dev(dev);
      return inode->i_rdev;
}

static inline void put_dev(device_t *dev) { dput(dev->dentry); }

static inline void dev_get(device_t *dev) { dget(dev->dentry); }

static inline void INIT_DEV(device_t *dev, struct dentry *dentry) {
      dev->dentry = dget(dentry);
}

// A device-file (it holds the dentry associated to the file managed as
// device-file). The dentry will be related to the `lo_backing_file` of a
// loop device.
typedef struct _file_dev {
      struct dentry *dentry;
      bool is_mapped;
      struct list_head node;
      struct rcu_head rcu;
} file_dev_t;

static inline void INIT_FDEV(file_dev_t *fdev, struct dentry *dentry) {
      fdev->dentry = dget(dentry);
      fdev->is_mapped = false;
      INIT_LIST_HEAD(&fdev->node);
}

static inline void put_fdev(file_dev_t *fdev) { dput(fdev->dentry); }

static void rcu_register_filedev(file_dev_t *fdev) {
      spin_lock(&devices.f_lock);
      list_add_rcu(&fdev->node, &devices.fdevices);
      spin_unlock(&devices.f_lock);

      log_info("Registered file-device %s as a backing file for a loop "
               "device\n",
               fdev->dentry->d_name.name);
}

static void rcu_unregister_filedev(file_dev_t *fdev) {
      spin_lock(&devices.f_lock);
      list_del_rcu(&fdev->node);
      spin_unlock(&devices.f_lock);
}

static inline void put_fdev_callback(struct rcu_head *rcu) {
      file_dev_t *fdev = container_of(rcu, file_dev_t, rcu);

      put_fdev(fdev);
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

// Remove a device-file from the registered devices. It is
// used as a callback for the `rcu_compute_on_filedev` function.
static int remove_fdev_callback(file_dev_t *fdev, void *arg) {
      if (!fdev) {
            log_err("No device-file found for %s\n", fdev->dentry->d_name.name);
            return -NOSDEV;
      }
      if (fdev->is_mapped) {
            // Cannot remove device file because it is mapped to a block
            // device (i.e. has an active session)
            log_err("Cannot remove device-file %s: active session\n",
                    fdev->dentry->d_name.name);
            return -SBUSY;
      }
      // Unregister the device
      rcu_unregister_filedev(fdev);

      log_info("Device-file %s unregistered\n", fdev->dentry->d_name.name);

      // The free of `fdev` is demanded to the `rcu_compute_on_filedev`
      // function
      return FREE_RCU;
}

// Computes a function on a device-file. It looks up the device and calls
// the compute function on the found device (it follows RCU based
// "locking").
static int rcu_compute_on_filedev(file_dev_t *lookup_fdev, void *arg,
                                  int (*compute_f)(file_dev_t *, void *)) {

      file_dev_t *fdev, *found_fdev = NULL;
      struct inode *fdev_inode = NULL;
      int ret;

      struct inode *lookup_inode = d_inode(lookup_fdev->dentry);

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
            put_fdev(found_fdev);
            kfree(found_fdev);
#endif
            ret = 0;
      }

      return ret;
}

typedef struct generic_dev {
      enum { BDEV, FDEV } type;
      union {
            device_t dev;
            file_dev_t fdev;
      };
} generic_dev_t;

struct committed_block {
      sector_t block;
      struct hlist_node hnode;
};

/**
 * @session_id:  Unique session identifier.
 * @mount_timestamp:  Unix timestamp (u64) when the session was activated.
 * @snap_path:    Snapshot directory path (e.g.,
 * "/snapshot/devname_timestamp").
 * @committed_blocks:  Hash table for committed blocks (i.e. blocks that
 * eventually go to storage).
 * @locks:      Spinlocks for each hash table entry.
 *
 */
typedef struct _snapshot_session {
      u64 mount_timestamp;
      struct path snap_path;
      struct hlist_head committed_blocks[1 << COMMITTED_HASH_BITS];
      spinlock_t locks[1 << COMMITTED_HASH_BITS];
} snapshot_session;

static inline int init_snapshot_session(snapshot_session *snap_session,
                                        time64_t timestamp) {

      snap_session->snap_path.dentry = NULL;
      snap_session->snap_path.mnt = NULL;
      snap_session->mount_timestamp = timestamp;

      return 0;
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
 * @device: Device number.
 * @snapshot_session Pointer to the active snapshot session.
 * @hnode: Hash list node for linking this device in the registered
 * devices that are mapped to a block device table.
 * @rcu: RCU head for safe removal of this device from the registered
 * devices
 */
typedef struct _snap_device {
      device_t dev;
      snapshot_session *session;
      struct hlist_node hnode;
      struct rcu_head rcu;
} snap_device;

static inline device_t dev(snap_device *sdev) { return sdev->dev; }

extern inline dev_t d_num(snap_device *sdev) { return num_dev(&sdev->dev); }

static inline const char *sdev_name(snap_device *sdev) {
      return devname(&sdev->dev);
}

static inline u32 hash_dev(dev_t dev) { return hash_32(dev, HASH_BITS); }

static inline void INIT_SNAP_DEVICE(snap_device *sdev, device_t device) {
      sdev->dev = device;
      sdev->session = NULL;
      INIT_HLIST_NODE(&sdev->hnode);
}

// Free a snapshot device, but without freeing the session. It must be
// used in RCU context
static inline void free_sdev_no_session(snap_device *sdev) {
      put_dev(&sdev->dev);

      kfree(sdev);
}

// Free a snapshot device and its session
static void free_sdev(snap_device *sdev) {
      if (sdev->session) {
            snapshot_session *session = sdev->session;
            int i;

            // Release the reference held by snap_path
            path_put(&session->snap_path);

            // Free all allocated committed blocks
            for (i = 0; i < (1 << COMMITTED_HASH_BITS); i++) {
                  struct committed_block *cb;
                  struct hlist_node *tmp;
                  hlist_for_each_entry_safe(
                      cb, tmp, &session->committed_blocks[i], hnode) {
                        hlist_del(&cb->hnode);
                        kfree(cb);
                  }
            }
            kfree(session);
      }

      free_sdev_no_session(sdev);
}

// Callback to free a snapshot device without its session within async RCU
// context
static inline void free_sdev_no_session_callback(struct rcu_head *rcu) {
      snap_device *sdev = container_of(rcu, snap_device, rcu);

      AUDIT log_info(
          "Callback free (no session): device : %s, preempt_count : %d\n",
          sdev_name(sdev), preempt_count());

      free_sdev_no_session(sdev);
}

// Callback to free a snapshot device and its session within async RCU
// context
static inline void free_sdev_callback(struct rcu_head *rcu) {
      snap_device *sdev = container_of(rcu, snap_device, rcu);

      AUDIT log_info("Callback free: device : %s, preempt_count : %d\n",
                     sdev_name(sdev), preempt_count());

      free_sdev(sdev);
}

// Add a snapshot device to the registered devices
static inline void rcu_register_snapdevice(snap_device *sdev) {
      u32 hash = hash_dev(d_num(sdev));

      HLIST_RCU_INSERT(sdev, devices.sdevices, devices.s_locks, hash);

      log_info("New Device %s registered\n", sdev_name(sdev));
}

// Remove a snapshot device from the registered devices
static inline void rcu_unregister_snapdevice(snap_device *sdev) {
      u32 hash = hash_dev(d_num(sdev));

      HLIST_RCU_REMOVE(sdev, devices.s_locks, hash);

      log_info("Device %s unregistered\n", sdev_name(sdev));
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
            log_err("No snapshot device found for %s\n", sdev_name(sdev));
            return -NOSDEV;
      }
      if (sdev->session) {
            // Cannot remove snapshot device because it has an active
            // session
            log_err("Cannot remove snapshot device %s: active session\n",
                    sdev_name(sdev));
            return -SBUSY;
      }
      // Unregister the snapshot device
      rcu_unregister_snapdevice(sdev);

      log_info("Snapshot device %s unregistered\n", sdev_name(sdev));

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
            free_sdev_no_session(sdev);
#endif
            ret = 0;
      }

      return ret;
}

/**
 * struct block_log_entry - Represents a logged block modification.
 * @snap_path:   Identifies the snapshot path within an active session.
 * @inode:      Pointer to the inode of the file being modified. Useful to
 * retrieve the underlying device name and to mantain a reference to avoid
 * the associated fs to be unmounted.
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
} blog_entry;

// static inline struct dentry *d_path_blog_entry(blog_entry *entry) {
//       return entry->snap_path.dentry;
// }

static inline void free_blog_entry(blog_entry *entry) {
      if (entry->orig_data) {
            kfree(entry->orig_data);
      }
      if (entry->inode) {
            iput(entry->inode);
      }
      path_put(&entry->snap_path);
}

/**
 * block_fifo - Used for per-CPU FIFO for block log entries.
 * @fifo: A kfifo holding pointers to blog_entry structures.
 *
 * Each FIFO can hold entries of different sessions, allowing
 * concurrent managment of the same session.
 */
typedef struct _block_fifo {
      struct kfifo fifo; /* FIFO for (struct blog_entry *) */
} block_fifo;

int register_my_kretprobes(void);
void unregister_my_kretprobes(void);

int init_snapshot_path(void);
void put_snapshot_path(void);

int activate_snapshot(const char *dev_name, const char *passwd);
int deactivate_snapshot(const char *dev_name, const char *passwd);

void init_devices(void);

#endif
