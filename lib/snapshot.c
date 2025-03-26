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
#include <linux/kprobes.h>
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

#include "../include/auth.h"
#include "../include/snapshot.h"

#define LIBNAME "SNAPSHOT"

#define AUDIT if (1)

#define KPROBE_MAX_ACTIVE 20
#define ASYNC

// Global sessions that keep track of the session id
// TODO: Maybe a session id is not needed, for now we keep it.
static DECLARE_SESSIONS(sessions);

// Global parent path for snapshot directories
static struct path snapshot_root_path;

// Registered devices to the snapshot subsystem
static struct hlist_head devices[1 << HASH_BITS];
// Locks for the registered devices
static spinlock_t devices_lock[1 << HASH_BITS];

// Per-CPU block log FIFO
static DEFINE_PER_CPU(block_fifo, cpu_block_fifo);

// Lookup of a snapshot device within the registered devices through RCU
static inline snap_device *rcu_sdev_read_lock(dev_t lookup_dev) {
      u32 hash = hash_dev(lookup_dev);
      snap_device *sdev;

      rcu_read_lock();
      hlist_for_each_entry_rcu(sdev, &devices[hash], hnode) {
            if (d_num(sdev) == lookup_dev) {
                  return sdev;
            }
      }

      return NULL;
}

// Unlock the RCU read lock
static inline void rcu_sdev_read_unlock(void) { rcu_read_unlock(); }

// Replaces a snapshot device within the registered devices through RCU
static inline void rcu_replace_sdev(snap_device *old_sdev,
                                    snap_device *new_sdev, u32 hash) {
      spin_lock(&devices_lock[hash]);
      hlist_replace_rcu(&old_sdev->hnode, &new_sdev->hnode);
      spin_unlock(&devices_lock[hash]);
}

// Free a snapshot device and its session without synchronization (must be used
// in RCU context)
static void free_sdev_no_sync(snap_device *sdev) {
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

      kfree(sdev);
}

// Callback to free a snapshot device and its session within async RCU context
static void free_sdev_callback(struct rcu_head *rcu) {
      snap_device *sdev = container_of(rcu, snap_device, rcu);

      AUDIT log_info("Callback free: device : %s, preempt_count : %d\n",
                     sdev_name(sdev), preempt_count());

      free_sdev_no_sync(sdev);
}

// Computes a function on a snapshot device. It looks up the device by its
// `dev_t` identifier and calls the function following RCU based "locking".
static inline int rcu_compute_on_sdev(dev_t dev,
                                      int (*compute_f)(snap_device *)) {
      int ret;
      snap_device *sdev = rcu_sdev_read_lock(dev);

      ret = compute_f(sdev);
      rcu_sdev_read_unlock();

      if (ret == SDEVREPLACE) {
#ifdef ASYNC
            call_rcu(&sdev->rcu, free_sdev_callback);
#else
            synchronize_rcu();
            free_sdev_no_sync(sdev);
#endif
            ret = 0;
      }

      return ret;
}

// Add a snapshot device to the registered devices
static void rcu_register_snapdevice(snap_device *sdev) {
      u32 hash = hash_dev(d_num(sdev));

      spin_lock(&devices_lock[hash]);
      hlist_add_tail_rcu(&sdev->hnode, &devices[hash]);
      spin_unlock(&devices_lock[hash]);

      log_info("New Device %s registered\n", sdev_name(sdev));
}

// Remove a snapshot device from the registered devices
static void rcu_unregister_snapdevice(snap_device *sdev) {
      u32 hash = hash_dev(d_num(sdev));

      spin_lock(&devices_lock[hash]);
      hlist_del_rcu(&sdev->hnode);
      spin_unlock(&devices_lock[hash]);

      log_info("Device %s unregistered\n", sdev_name(sdev));
}

bool may_open_dev(const struct path *path) {
      return !(path->mnt->mnt_flags & MNT_NODEV) &&
             !(path->mnt->mnt_sb->s_iflags & SB_I_NODEV);
}

static int get_bdev_by_name(const char *pathname, device_t *dev) {
      struct inode *inode;
      struct path path;
      int error;

      if (!pathname || !*pathname)
            return -EINVAL;

      error = kern_path(pathname, LOOKUP_FOLLOW, &path);
      if (error) {
            return error;
      }
      inode = d_backing_inode(path.dentry);
      error = -ENOTBLK;
      if (!S_ISBLK(inode->i_mode))
            goto out_path_put;

      error = -EACCES;
      if (!may_open_dev(&path))
            goto out_path_put;

      // Get a reference to the dentry
      struct dentry *dentry = dget(path.dentry);
      INIT_DEV(dev, dentry);
      error = 0;
out_path_put:
      path_put(&path);
      return error;
}

static int try_init_snapdevice_by_name(const char *dev_name,
                                       snap_device *sdev) {
      device_t dev;
      int err;

      err = get_bdev_by_name(dev_name, &dev);
      if (err) {
            AUDIT log_err("Failed to get device %s by name: %d\n", dev_name,
                          err);
            return err;
      }

      INIT_SNAP_DEVICE(sdev, dev);
      AUDIT log_info("Snapshot device %s initialized succesfully\n",
                     sdev_name(sdev));

      return 0;
}

static int init_snapshot_session(snapshot_session *snap_session,
                                 const char *dev_name, time64_t timestamp) {
      struct tm tm;
      char date_str[16]; // Format: YYYYMMDD_HHMMSS
      char snap_subdirname[128];
      char snap_dirname[128];
      struct dentry *subdentry = NULL;
      int error;

      // Initialize session id and mount timestamp
      snap_session->session_id = atomic_inc_return(&sessions.session_id);
      if (unlikely(snap_session->session_id <= 0)) {
            log_err("Reached max number of sessions\n");

            // We don't care about synchronization here. At most, more threds
            // will detect the overflow and all set the status to OVERFLOW.
            sessions.status = OVERFLOW;

            return -SESSIONOVFLW;
      }
      snap_session->mount_timestamp = timestamp;

      // Format the timestamp into a date string: YYYYMMDD_HHMMSS
      time64_to_tm(snap_session->mount_timestamp, 0, &tm);
      snprintf(date_str, sizeof(date_str), "%04ld%02ld%02ld_%02ld%02ld%02ld",
               tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour,
               tm.tm_min, tm.tm_sec);

      // Build the snapshot subdirectory name: "<dev_name>_<date_str>"
      snprintf(snap_subdirname, sizeof(snap_subdirname), "%s_%s", dev_name,
               date_str);

      // Construct the full snapshot directory path
      snprintf(snap_dirname, sizeof(snap_dirname), "/%s/%s",
               snapshot_root_path.dentry->d_name.name, snap_subdirname);

      // Allocate a new dentry for the subdirectory
      subdentry = d_alloc_name(snapshot_root_path.dentry, snap_subdirname);
      if (!subdentry) {
            AUDIT log_err("Failed to allocate dentry for %s\n",
                          snap_subdirname);
            return -ENOMEM;
      }

      // Create the new directory
      error = vfs_mkdir(snapshot_root_path.mnt->mnt_idmap,
                        d_inode(snapshot_root_path.dentry), subdentry, 0500);
      if (error) {
            AUDIT log_err("vfs_mkdir failed for %s: %d\n", snap_subdirname,
                          error);
            goto out;
      }

      // Lookup the full path of the new directory
      error = kern_path(snap_dirname, LOOKUP_FOLLOW, &snap_session->snap_path);
      if (error) {
            AUDIT log_err("Failed to lookup new directory %s: %d\n",
                          snap_dirname, error);
            goto out;
      }
      error = 0;
out:
      dput(subdentry);
      return error;
}

// Helper function to check if a snapshot device is not registered. It
// is used as a callback for the `rcu_compute_on_sdev` function.
static int no_sdev(snap_device *sdev) {
      if (sdev != NULL) {
            return -DEXIST;
      } else {
            return 0;
      }
}

// Allocate a new snapshot device if it is not already registered
static int alloc_snapdevice(const char *dev_name) {
      snap_device tmp_sdev, *sdev;
      int error;
      // Try to initialize the snapshot device
      error = try_init_snapdevice_by_name(dev_name, &tmp_sdev);
      if (error) {
            AUDIT log_err("Failed to initialize snapshot device %s: %d\n",
                          dev_name, error);
            return error;
      }
      // Check if the snapshot device is already registered
      error = rcu_compute_on_sdev(d_num(&tmp_sdev), no_sdev);
      if (error) {
            AUDIT log_err("Device %s is already registered\n",
                          sdev_name(&tmp_sdev));
            return error;
      }

      sdev = kmalloc(sizeof(snap_device), GFP_KERNEL);
      if (!sdev) {
            AUDIT log_err("Failed to allocate memory for snapshot device %s\n",
                          dev_name);
            return -ENOMEM;
      }
      memcpy(sdev, &tmp_sdev, sizeof(snap_device));

      // Register the snapshot device
      rcu_register_snapdevice(sdev);

      return 0;
}

// Remove a snapshot device from the registered snapshot devices. It is
// used as a callback for the `rcu_compute_on_sdev` function.
static int remove_sdev(snap_device *sdev) {
      if (!sdev) {
            log_err("No snapshot device found for %s\n", sdev_name(sdev));
            return -NOSDEV;
      }
      if (sdev->session) {
            // Cannot remove snapshot device because it has an active session
            log_err("Cannot remove snapshot device %s: active session\n",
                    sdev_name(sdev));
            return -SBUSY;
      }
      // Unregister the snapshot device
      rcu_unregister_snapdevice(sdev);

      // The free of `sdev` is demanded to the `rcu_compute_on_sdev` function
      return SDEVREPLACE;
}

static int dealloc_snapdevice(const char *dev_name) {
      snap_device sdev;
      int error;

      error = try_init_snapdevice_by_name(dev_name, &sdev);
      if (error) {
            return error;
      }
      error = rcu_compute_on_sdev(d_num(&sdev), remove_sdev);
      if (error) {
            return error;
      }

      return 0;
}

int init_snapshot_path(void) {
      int error;
      struct path root_path;
      struct dentry *dentry = NULL;

      // Check if /snapshot already exists
      error = kern_path("/snapshot", LOOKUP_DIRECTORY, &snapshot_root_path);
      if (!error) {
            log_info(
                "Snapshot directory already exists, no need to create it\n");
            return 0;
      } else if (error != -ENOENT) {
            return error;
      }

      error = kern_path("/", LOOKUP_DIRECTORY, &root_path);
      if (error)
            return error;

      dentry = d_alloc_name(root_path.dentry, "snapshot");
      if (!dentry) {
            error = -ENOMEM;
            goto cleanup_root;
      }

      error = vfs_mkdir(root_path.mnt->mnt_idmap, root_path.dentry->d_inode,
                        dentry, 0500);
      if (error)
            goto cleanup_all;

      /* Now that the directory is created, get its path */
      error = kern_path("/snapshot", LOOKUP_DIRECTORY, &snapshot_root_path);
      if (!error) {
            log_info("Root Snapshot directory created\n");
      }

cleanup_all:
      dput(dentry);
cleanup_root:
      path_put(&root_path);
      return error;
}

void put_snapshot_path(void) {
      path_put(&snapshot_root_path);

      log_info("Snapshot path released\n");
}

// Create a new snapshot session on mount of a registered snapshot device. It is
// used as a callback for the `rcu_compute_on_sdev` function.
static int new_session_on_mount(snap_device *sdev) {
      snap_device *old_sdev, *new_sdev;
      snapshot_session *session;
      time64_t mount_timestamp;
      int error;

      if (!sdev) {
            return -NOSDEV;
      }

      old_sdev = sdev;
      new_sdev = kmalloc(sizeof(snap_device), GFP_KERNEL);
      if (!new_sdev) {
            return -ENOMEM;
      }

      memcpy(new_sdev, old_sdev, sizeof(snap_device));

      session = kmalloc(sizeof(snapshot_session), GFP_KERNEL);
      if (!session) {
            kfree(new_sdev);
            return -ENOMEM;
      }

      mount_timestamp = ktime_get_real_seconds();
      error =
          init_snapshot_session(session, sdev_name(new_sdev), mount_timestamp);
      if (error) {
            AUDIT log_err("Failed to create new session for device %s : %d\n",
                          sdev_name(new_sdev), error);
            kfree(session);
            kfree(new_sdev);
            return error;
      }
      new_sdev->session = session;
      AUDIT log_info("New snapshot session created for device: %s\n",
                     sdev_name(sdev));

      rcu_replace_sdev(old_sdev, new_sdev, hash_dev(d_num(new_sdev)));

      // The free of `old_sdev` is demanded to the `rcu_compute_on_sdev`
      // function
      return SDEVREPLACE;
}

static int mount_bdev_ret_handler(struct kretprobe_instance *ri,
                                  struct pt_regs *regs) {
      struct dentry *mnt_dentry;
      dev_t dev;
      snap_device *sdev;
      int error;

      // TODO: other kernel versions might return a block_device
      mnt_dentry = (struct dentry *)regs_return_value(regs);
      if (IS_ERR(mnt_dentry))
            goto ret_handler;

      dev = mnt_dentry->d_sb->s_bdev->bd_dev;

      // Don't really care about the error
      rcu_compute_on_sdev(dev, new_session_on_mount);

ret_handler:
      return 0;
}

static struct kretprobe rp_mount = {
    .kp.symbol_name = "mount_bdev",
    .handler = mount_bdev_ret_handler,
    .maxactive = KPROBE_MAX_ACTIVE,
};

// Callback function to clear the snapshot session on unmount.
static int free_session_on_umount(snap_device *sdev) {
      snap_device *old_sdev, *new_sdev;

      if (!sdev)
            return -NOSDEV;

      old_sdev = sdev;
      new_sdev = kmalloc(sizeof(snap_device), GFP_KERNEL);
      if (!new_sdev)
            return -ENOMEM;

      memcpy(new_sdev, old_sdev, sizeof(snap_device));

      // Set the session pointer to NULL to mark the unmount
      new_sdev->session = NULL;
      AUDIT log_info("Snapshot session cleared for device: %s\n",
                     sdev_name(sdev));

      // Replace the old snapshot device entry with the updated one
      rcu_replace_sdev(old_sdev, new_sdev, hash_dev(d_num(new_sdev)));

      return SDEVREPLACE;
}

struct umount_data {
      dev_t dev;
};

static int umount_entry_handler(struct kretprobe_instance *ri,
                                struct pt_regs *regs) {
      struct umount_data *ud = (struct umount_data *)ri->data;
#ifdef CONFIG_X86_64
      struct super_block *sb = (struct super_block *)regs->di;
#else
#error "Unsupported architecture"
#endif

      if (!sb || !sb->s_bdev) {
            return -1;
      }

      ud->dev = sb->s_bdev->bd_dev;
      return 0;
}

static int umount_ret_handler(struct kretprobe_instance *ri,
                              struct pt_regs *regs) {
      struct umount_data *ud = (struct umount_data *)ri->data;
      dev_t dev = ud->dev;

      // Don't care about the error
      rcu_compute_on_sdev(dev, free_session_on_umount);

      return 0;
}

static struct kretprobe rp_umount = {
    .kp.symbol_name = "kill_block_super",
    .entry_handler = umount_entry_handler,
    .handler = umount_ret_handler,
    .data_size = sizeof(struct umount_data),
    .maxactive = KPROBE_MAX_ACTIVE,
};

static struct kretprobe *retprobes[] = {&rp_mount, &rp_umount};

int register_my_kretprobes(void) {
      int i, ret;

      for (i = 0; i < ARRAY_SIZE(retprobes); i++) {
            ret = register_kretprobe(retprobes[i]);
            if (ret < 0) {
                  log_err("Failed to register kretprobe %s: %d\n",
                          retprobes[i]->kp.symbol_name, ret);
                  return ret;
            } else {
                  log_info("Registered kretprobe %s\n",
                           retprobes[i]->kp.symbol_name);
            }
      }

      return 0;
}

void unregister_my_kretprobes(void) {
      int i;

      for (i = 0; i < ARRAY_SIZE(retprobes); i++) {
            unregister_kretprobe(retprobes[i]);
            log_info("Unregistered kretprobe %s\n",
                     retprobes[i]->kp.symbol_name);
      }
}

int activate_snapshot(const char *dev_name, const char *passwd) {
      int error;

      // Verifies password
      if (!snapshot_auth_verify(passwd)) {
            return -AUTHF;
      }
      AUDIT log_info("Password verified succesfully\n");
      // Tries to allocate a new snapshot device
      error = alloc_snapdevice(dev_name);
      if (error) {
            return error;
      }
      // Increment module reference count
      bool success = try_module_get(THIS_MODULE);
      if (!success) {
            return -MODUNLOAD;
      }

      return 0;
}

int deactivate_snapshot(const char *dev_name, const char *passwd) {

      snap_device sdev;
      int error;

      // Verifies password
      if (!snapshot_auth_verify(passwd)) {
            return -AUTHF;
      }

      // Tries to deallocate the snapshot device
      error = dealloc_snapdevice(dev_name);
      if (error) {
            return error;
      }
      // Decrement module reference count
      module_put(THIS_MODULE);

      return 0;
}

#endif