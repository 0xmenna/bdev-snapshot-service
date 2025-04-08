#include <linux/atomic.h>
#include <linux/buffer_head.h>
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
#include <linux/time.h>
#include <linux/timer.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/wait.h>

#include "../include/auth.h"
#include "../include/hlist_rcu.h"
#include "../include/snapshot.h"
#include "../include/utils.h"

#define LIBNAME "SNAPSHOT"

#define AUDIT if (1)
#define DEBUG

#ifdef DEBUG
#define DEBUG_ASSERT(cond) BUG_ON(!(cond))
#else
#define DEBUG_ASSERT(cond)                                                     \
      do {                                                                     \
      } while (0)
#endif

// Global parent path for snapshot directories
static struct path snapshot_root_path;

// Per-CPU block log FIFO
static DEFINE_PER_CPU(block_fifo, cpu_block_fifo);

void init_devices(void) { INIT_LIST_HEAD(&devices.fdevices); }

static inline bool may_open_device(const struct path *path) {
      return !(path->mnt->mnt_flags & MNT_NODEV) &&
             !(path->mnt->mnt_sb->s_iflags & SB_I_NODEV);
}

static int get_dev_by_name(const char *pathname, generic_dev_t *dev) {
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
      if (!S_ISBLK(inode->i_mode)) {
            // The provided pathname represents the actual pathname associated
            // to the file managed as device-file (used for a loop device).
            file_dev_t fdev;
            INIT_FDEV(&fdev, path.dentry);
            dev->type = FDEV;
            dev->fdev = fdev;

            error = 0;
            goto out_path_put;
      }
      error = -EACCES;
      if (!may_open_device(&path))
            goto out_path_put;

      // An actual block device
      dev->type = BDEV;
      dev->dev = inode->i_rdev;

      error = 0;
out_path_put:
      path_put(&path);
      return error;
}

// Function to create a new snapshot session directory. It is used as a
// callback for the `rcu_compute_on_sdev` function.
static int session_path_callback(snap_device *sdev, void *arg) {
      struct tm tm;
      char date_str[16]; // Format: YYYYMMDD_HHMMSS
      char snap_subdirname[128];
      char snap_dirname[128];
      struct dentry *subdentry = NULL;
      int ret;

      if (!sdev) {
            return -NOSDEV;
      }
      if (!sdev->session) {
            return -SDEVNOTACTIVE;
      }

      if (d_session(sdev->session)) {
            return -PATHEXIST;
      }

      // Format the timestamp into a date string: YYYYMMDD_HHMMSS
      time64_to_tm(sdev->session->mount_timestamp, 0, &tm);
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
            return -ENOMEM;
      }

      // Create the new directory
      ret = vfs_mkdir(snapshot_root_path.mnt->mnt_idmap,
                      d_inode(snapshot_root_path.dentry), subdentry, 0500);
      if (ret) {
            if (ret == -EEXIST) {
                  // Other threads may have created the directory
                  ret = -SNAPDIR_EXIST;
            }

            goto out;
      }
      // At this point, a single thread will execute this code for a given snap
      // device session, because the rest have failed to create the directory.
      snap_device *old_sdev = sdev;
      snap_device *new_sdev = kmalloc(sizeof(snap_device), GFP_KERNEL);
      if (!new_sdev) {
            ret = -ENOMEM;
            goto out;
      }
      memcpy(new_sdev, old_sdev, sizeof(snap_device));

      // Lookup the full path of the new directory
      ret =
          kern_path(snap_dirname, LOOKUP_FOLLOW, &new_sdev->session->snap_path);
      if (ret) {
            kfree(new_sdev);
            goto out;
      }

      HLIST_RCU_REPLACE(old_sdev, new_sdev, devices.s_locks,
                        hash_dev(d_num(new_sdev)));

      // This is to avoid freeing the session in the callback (since it is used
      // by the newer snap device)
      ret = FREE_SDEV_NO_SESSION;
out:
      dput(subdentry);
      return ret;
};

static int register_device(const char *dev_name) {
      generic_dev_t dev;
      int error;
      // Try to initialize the device
      error = get_dev_by_name(dev_name, &dev);
      if (error) {
            return error;
      }

      switch (dev.type) {
      case BDEV:
            snap_device tmp_sdev, *sdev;
            INIT_SNAP_DEVICE(&tmp_sdev, dev.dev);
            // Check if the snapshot device is already registered
            error =
                rcu_compute_on_sdev(d_num(&tmp_sdev), NULL, no_sdev_callback);
            if (error) {
                  log_info("Cannot register device: Block device %d already "
                           "registered\n",
                           tmp_sdev.dev);
                  return error;
            }
            sdev = kmalloc(sizeof(snap_device), GFP_KERNEL);
            if (!sdev) {
                  return -ENOMEM;
            }
            memcpy(sdev, &tmp_sdev, sizeof(snap_device));

            // Register the snapshot device
            rcu_register_snapdevice(sdev);
            log_info("Device Registered: Block device %d\n", sdev->dev);
            break;
      case FDEV:
            // Check if the device file is already registered
            error = rcu_compute_on_filedev(dev.fdev.dentry, NULL,
                                           no_file_dev_callback);
            if (error) {
                  log_info("Cannot register device: Loop backing file %s "
                           "already registered\n",
                           dev.fdev.dentry->d_name.name);
                  put_fdev(&dev.fdev);
                  return error;
            }

            file_dev_t *fdev = kmalloc(sizeof(file_dev_t), GFP_KERNEL);
            if (!fdev) {
                  put_fdev(&dev.fdev);
                  return -ENOMEM;
            }
            memcpy(fdev, &dev.fdev, sizeof(file_dev_t));

            rcu_register_filedev(fdev);
            log_info("Device Registered: Loop backing file %s\n",
                     fdev->dentry->d_name.name);
      }

      return 0;
}

static int unregister_device(const char *dev_name) {
      generic_dev_t dev;
      int error;

      error = get_dev_by_name(dev_name, &dev);
      if (error) {
            return error;
      }

      switch (dev.type) {
      case BDEV:
            error = rcu_compute_on_sdev(dev.dev, NULL, remove_sdev_callback);
            if (error) {
                  log_info("Unregister Device: Cannot remove block device %d. "
                           "Error: "
                           "%d\n",
                           dev.dev, error);
                  return error;
            }
            break;

      case FDEV:
            error = rcu_compute_on_filedev(dev.fdev.dentry, NULL,
                                           remove_fdev_callback);
            put_fdev(&dev.fdev);
            if (error) {
                  log_info(
                      "Unregister Device: Cannot remove loop backing file %s. "
                      "Error: %d\n",
                      dev.fdev.dentry->d_name.name, error);
                  return error;
            }
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

      error = vfs_mkdir(root_path.mnt->mnt_idmap, d_inode(root_path.dentry),
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

void put_snapshot_path(void) { path_put(&snapshot_root_path); }

// Create a new snapshot session on mount of a registered snapshot device. It
// is used as a callback for the `rcu_compute_on_sdev` function.
static int new_session_on_mount_callback(snap_device *sdev, void *arg) {
      snap_device *old_sdev, *new_sdev;
      snapshot_session *session;
      time64_t mount_timestamp;
      int error;

      if (!sdev) {
            return -NOSDEV;
      }

      DEBUG_ASSERT(!sdev->session);

      session = kmalloc(sizeof(snapshot_session), GFP_ATOMIC);
      if (!session) {
            return -ENOMEM;
      }

      mount_timestamp = ktime_get_real_seconds();
      init_snapshot_session(session, mount_timestamp);

      old_sdev = sdev;
      new_sdev = kmalloc(sizeof(snap_device), GFP_ATOMIC);
      if (!new_sdev) {
            kfree(session);
            return -ENOMEM;
      }
      memcpy(new_sdev, old_sdev, sizeof(snap_device));
      new_sdev->session = session;

      HLIST_RCU_REPLACE(old_sdev, new_sdev, devices.s_locks,
                        hash_dev(d_num(new_sdev)));

      return FREE_SDEV;
}

static inline int map_filedev_callback(file_dev_t *fdev, void *arg) {
      file_dev_t *old_fdev, *new_fdev;
      bool map;
      if (fdev == NULL) {
            return -NOFDEV;
      }

      old_fdev = fdev;
      map = *((bool *)arg);

      if (old_fdev->is_mapped == map) {
            return 0;
      }

      new_fdev = kmalloc(sizeof(file_dev_t), GFP_ATOMIC);
      if (!new_fdev) {
            return -ENOMEM;
      }
      memcpy(new_fdev, old_fdev, sizeof(file_dev_t));
      new_fdev->is_mapped = map;

      rcu_replace_filedev(old_fdev, new_fdev);

      get_fdev(new_fdev);

      return FREE_RCU;
}

static int mount_bdev_ret_handler(struct kretprobe_instance *ri,
                                  struct pt_regs *regs) {
      struct dentry *mnt_dentry;
      dev_t dev;
      snap_device *sdev;
      int ret;

      mnt_dentry = dget((struct dentry *)regs_return_value(regs));
      if (IS_ERR(mnt_dentry))
            goto ret_handler;

      if (mnt_dentry->d_sb->s_bdev) {
            struct block_device *bdev = mnt_dentry->d_sb->s_bdev;
            if (MAJOR(bdev->bd_dev) == LOOP_MAJOR) {
                  // Loop device

                  // Extract the backing file of the loop device
                  struct file *lo_backing_file;
                  lo_backing_file =
                      ((struct loop_device_meta *)bdev->bd_disk->private_data)
                          ->lo_backing_file;

                  // Check if the backing file is registered within the
                  // `fdevices` list
                  ret = rcu_compute_on_filedev(lo_backing_file->f_path.dentry,
                                               NULL,
                                               lo_backing_file_exists_callback);

                  if (ret) {
                        // The device-file is not registered
                        goto ret_handler;
                  }

                  // The device-file is registered. We can create a new snapshot
                  // device and activate a new session
                  snap_device tmp_sdev, *sdev;
                  INIT_SNAP_DEVICE(&tmp_sdev, bdev->bd_dev);

                  ret = rcu_compute_on_sdev(d_num(&tmp_sdev), NULL,
                                            no_sdev_callback);

                  if (unlikely(ret)) {
                        goto ret_handler;
                  }
                  sdev = kmalloc(sizeof(snap_device), GFP_ATOMIC);
                  if (!sdev) {
                        goto ret_handler;
                  }
                  memcpy(sdev, &tmp_sdev, sizeof(snap_device));

                  // Create the session
                  snapshot_session *session;
                  time64_t mount_timestamp;

                  session = kmalloc(sizeof(snapshot_session), GFP_ATOMIC);
                  if (!session) {
                        kfree(sdev);
                        goto ret_handler;
                  }

                  mount_timestamp = ktime_get_real_seconds();
                  init_snapshot_session(session, mount_timestamp);
                  sdev->session = session;
                  sdev->private_data = (void *)lo_backing_file->f_path.dentry;

                  // Register the snapshot device
                  rcu_register_snapdevice(sdev);
                  AUDIT log_info(
                      "mount_ret_handler: loop device %d registered with a new "
                      "session. "
                      "Backing file %s\n",
                      sdev->dev,
                      ((struct dentry *)sdev->private_data)->d_name.name);

                  // Map the device-file
                  bool map = true;
                  ret = rcu_compute_on_filedev(lo_backing_file->f_path.dentry,
                                               &map, map_filedev_callback);
                  if (ret) {
                        kfree(session);
                        kfree(sdev);
                        goto ret_handler;
                  }

            } else {
                  // A regular block device

                  // Don't really care about the error. If the device is not
                  // registered it simply won't perform any action.
                  rcu_compute_on_sdev(bdev->bd_dev, NULL,
                                      new_session_on_mount_callback);
                  AUDIT log_info(
                      "mount_ret_handler: new session for block device %d\n",
                      bdev->bd_dev);
            }
      }

      dput(mnt_dentry);

ret_handler:
      return 0;
}

static struct kretprobe rp_mount = {
    .kp.symbol_name = "mount_bdev",
    .handler = mount_bdev_ret_handler,
};

// Function to clear the snapshot session on unmount. For loop devices it will
// free the whole loop device. It is used as a callback for the
// `rcu_compute_on_sdev` function.
static int free_session_on_umount_callback(snap_device *sdev, void *arg) {
      snap_device *old_sdev, *new_sdev;
      int ret;

      if (!sdev)
            return -NOSDEV;

      if (MAJOR(d_num(sdev)) == LOOP_MAJOR) {
            // Loop device

            // Unmap the device-file
            bool map = false;
            ret = rcu_compute_on_filedev((struct dentry *)sdev->private_data,
                                         &map, map_filedev_callback);
            if (ret) {
                  return ret;
            }

            // Unregister the snapshot device
            rcu_unregister_snapdevice(sdev);
            AUDIT log_info("umount_callback: Loop device %d unregistered with "
                           "backing file %s\n",
                           sdev->dev,
                           ((struct dentry *)sdev->private_data)->d_name.name);
      } else {
            // Regular block device

            old_sdev = sdev;
            new_sdev = kmalloc(sizeof(snap_device), GFP_ATOMIC);
            if (!new_sdev)
                  return -ENOMEM;

            memcpy(new_sdev, old_sdev, sizeof(snap_device));

            // Set the session pointer to NULL to mark the unmount
            new_sdev->session = NULL;

            // Replace the old snapshot device entry with the updated one
            HLIST_RCU_REPLACE(old_sdev, new_sdev, devices.s_locks,
                              hash_dev(d_num(new_sdev)));

            AUDIT log_info(
                "umount_callback: Cleared session for block device %d\n",
                old_sdev->dev);
      }

      return FREE_SDEV;
}

struct umount_kretprobe_metadata {
      dev_t dev;
};

static int umount_entry_handler(struct kretprobe_instance *ri,
                                struct pt_regs *regs) {

      struct umount_kretprobe_metadata *meta =
          (struct umount_kretprobe_metadata *)ri->data;
      struct super_block *sb = NULL;

#if defined(CONFIG_X86_64)
      sb = (struct super_block *)regs->di;
#elif defined(CONFIG_ARM64)
      sb = (struct super_block *)regs->regs[0];
#else
#error "Architecture not supported"
#endif

      if (!sb || !sb->s_bdev) {
            return -1;
      }

      meta->dev = sb->s_bdev->bd_dev;
      return 0;
}

static int umount_ret_handler(struct kretprobe_instance *ri,
                              struct pt_regs *regs) {
      struct umount_kretprobe_metadata *meta =
          (struct umount_kretprobe_metadata *)ri->data;

      // Don't care about the error
      rcu_compute_on_sdev(meta->dev, NULL, free_session_on_umount_callback);

      return 0;
}

static struct kretprobe rp_umount = {
    .kp.symbol_name = "kill_block_super",
    .entry_handler = umount_entry_handler,
    .handler = umount_ret_handler,
    .data_size = sizeof(struct umount_kretprobe_metadata),
};

struct write_metadata {
      struct inode *inode;
      loff_t offset;
      size_t count;

      sector_t out_block;
};

// Callback function used to acquire the block number that will eventually be
// overwritten. It adds the block number to the session
// `reading_blocks` in order for the `sb_read` kretprobe to now which block to
// copy. It adds the block also to the session `committed_blocks` to know which
// subsequent write will not be captured because the block was already copied.
// NOTE: As of now we support a single block write at a time.
static int record_block_on_write_callback(snap_device *sdev, void *arg) {
      snapshot_session *session;
      struct snap_block *snap_block;
      struct write_metadata *wm;
      sector_t block;

      if (!sdev) {
            return -NOSDEV;
      }
      if (!sdev->session) {
            return -SDEVNOTACTIVE;
      }

      session = sdev->session;
      wm = (struct write_metadata *)arg;

      block = get_block(wm->inode, wm->offset);
      wm->out_block = block;

      snap_block = kmalloc(sizeof(struct snap_block), GFP_ATOMIC);
      if (!snap_block) {
            return -ENOMEM;
      }

      INIT_SNAP_BLOCK(snap_block, block);
      u32 b_hash = hash_block(snap_block->block);

      // Add the block to the committed blocks (if it does not exist already)
      spin_lock(&session->cb_locks[b_hash]);

      struct snap_block *sb;
      hlist_for_each_entry(sb, &session->committed_blocks[b_hash], cb_hnode) {
            if (sb->block == snap_block->block) {
                  spin_unlock(&session->cb_locks[b_hash]);

                  AUDIT log_info("record_block_on_write_callback: Block %d is "
                                 "already committed\n",
                                 snap_block->block);

                  kfree(snap_block);
                  return -BLOCK_COMMITTED;
            }
      }

      hlist_add_head(&snap_block->cb_hnode, &session->committed_blocks[b_hash]);
      spin_unlock(&session->cb_locks[b_hash]);

      // Add the block to the reading blocks
      spin_lock(&session->rb_locks[b_hash]);
      hlist_add_head(&snap_block->rb_hnode, &session->reading_blocks[b_hash]);
      spin_unlock(&session->rb_locks[b_hash]);

      return 0;
}

struct write_kretprobe_metadata {
      dev_t dev;
      sector_t block;
};

static int pre_write_handler(struct file *file, loff_t offset, size_t count,
                             struct write_kretprobe_metadata *out_meta) {
      struct write_metadata wm;
      int ret;

      if (!file || !file->f_inode)
            return -EINVAL;

      struct inode *inode = igrab(file->f_inode);
      if (!inode->i_sb->s_bdev) {
            iput(inode);
            return -NOSDEV;
      }
      dev_t dev = inode->i_sb->s_bdev->bd_dev;

      wm.inode = inode;
      wm.offset = offset;
      wm.count = count;

      // Record the block that will be overwritten. If the device is not
      // registered and has no active session it simply won't perform any
      // action.
      ret = rcu_compute_on_sdev(dev, &wm, record_block_on_write_callback);
      if (!ret) {
            out_meta->dev = dev;
            out_meta->block = wm.out_block;
      }

      iput(inode);
      return ret;
}

static int rollback_write_entry_callback(snap_device *sdev, void *arg) {
      sector_t block;
      snapshot_session *session;

      DEBUG_ASSERT(sdev != NULL && sdev->session != NULL);

      session = sdev->session;
      block = *((sector_t *)arg);

      u32 b_hash = hash_block(block);

      // Remove the block from the committed blocks
      spin_lock(&session->cb_locks[b_hash]);

      struct snap_block *sb;
      bool found = false;
      hlist_for_each_entry(sb, &session->committed_blocks[b_hash], cb_hnode) {
            if (sb->block == block) {
                  found = true;
                  hlist_del(&sb->cb_hnode);
                  spin_unlock(&session->cb_locks[b_hash]);

                  break;
            }
      }
      DEBUG_ASSERT(found);

      // Remove the block from the reading blocks
      spin_lock(&session->rb_locks[b_hash]);
      hlist_del(&sb->rb_hnode);
      spin_unlock(&session->rb_locks[b_hash]);

      kfree(sb);

      return 0;
}

static int vfs_write_entry_handler(struct kretprobe_instance *ri,
                                   struct pt_regs *regs) {
      struct file *file;
      size_t count;
      loff_t offset;
      int ret;
#ifdef CONFIG_X86_64
      file = (struct file *)regs->di;
      count = (size_t)regs->dx;
      offset = (loff_t *)regs->cx;

      struct write_kretprobe_metadata *meta =
          (struct write_kretprobe_metadata *)ri->data;

      ret = pre_write_handler(file, offset, count, meta);
      if (ret) {
            // Do not execute the ret handler
            return -1;
      }

      return 0;
#else
#error "Unsupported architecture"
#endif
}

static int vfs_write_ret_handler(struct kretprobe_instance *ri,
                                 struct pt_regs *regs) {
      ssize_t ret;
      struct write_kretprobe_metadata *meta;

      ret = *((ssize_t *)regs_return_value(regs));
      meta = (struct write_kretprobe_metadata *)ri->data;

      if (ret < 0) {
            // An error occured: we must "rollback" what the pre_handler did
            rcu_compute_on_sdev(meta->dev, (void *)&meta->block,
                                rollback_write_entry_callback);
      }

      return 0;
}

static struct kretprobe rp_vfs_write = {
    .kp.symbol_name = "vfs_write",
    .entry_handler = vfs_write_entry_handler,
    .handler = vfs_write_ret_handler,
    .data_size = sizeof(struct write_kretprobe_metadata),
};

static struct kretprobe *retprobes[] = {&rp_mount, &rp_umount, &rp_vfs_write};

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
      AUDIT log_info("Authentication successful during device %s activation\n",
                     dev_name);
      // Tries to register a new device
      error = register_device(dev_name);
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
      AUDIT log_info(
          "Authentication successful during device %s deactivation\n",
          dev_name);

      // Tries to deallocate the snapshot device
      error = unregister_device(dev_name);
      if (error) {
            return error;
      }
      // Decrement module reference count
      module_put(THIS_MODULE);

      return 0;
}
