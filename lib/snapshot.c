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
      device_t bdev;
      INIT_DEV(&dev->dev, path.dentry);
      dev->type = BDEV;
      dev->dev = bdev;

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
            AUDIT log_err("Failed to allocate dentry for %s\n",
                          snap_subdirname);
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
            AUDIT log_err("vfs_mkdir failed for %s: %d\n", snap_subdirname,
                          ret);
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
            AUDIT log_err("Failed to lookup new directory %s: %d\n",
                          snap_dirname, ret);
            kfree(new_sdev);
            goto out;
      }

      HLIST_RCU_REPLACE(old_sdev, new_sdev, devices.s_locks,
                        hash_dev(d_num(new_sdev)));

      dev_get(&new_sdev->dev);

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
            AUDIT log_err("Failed to initialize device %s: %d\n", dev_name,
                          error);
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
                  put_dev(&tmp_sdev.dev);
                  AUDIT log_err("Device %s is already registered\n",
                                sdev_name(&tmp_sdev));

                  return error;
            }
            sdev = kmalloc(sizeof(snap_device), GFP_KERNEL);
            if (!sdev) {
                  put_dev(&tmp_sdev.dev);
                  return -ENOMEM;
            }
            memcpy(sdev, &tmp_sdev, sizeof(snap_device));

            // Register the snapshot device
            rcu_register_snapdevice(sdev);
            break;
      case FDEV:
            // Check if the device file is already registered
            error =
                rcu_compute_on_filedev(&dev.fdev, NULL, no_file_dev_callback);
            if (error) {
                  put_fdev(&dev.fdev);
                  AUDIT log_err("Device file %s is already registered\n",
                                dev_name);
                  return error;
            }

            file_dev_t *fdev = kmalloc(sizeof(file_dev_t), GFP_KERNEL);
            if (!fdev) {
                  put_fdev(&dev.fdev);
                  return -ENOMEM;
            }
            memcpy(fdev, &dev.fdev, sizeof(file_dev_t));

            rcu_register_filedev(fdev);
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
            error = rcu_compute_on_sdev(num_dev(&dev.dev), NULL,
                                        remove_sdev_callback);
            put_dev(&dev.dev);
            if (error) {
                  return error;
            }
            break;

      case FDEV:
            error =
                rcu_compute_on_filedev(&dev.fdev, NULL, remove_fdev_callback);
            put_fdev(&dev.fdev);
            if (error) {
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

void put_snapshot_path(void) {
      path_put(&snapshot_root_path);

      log_info("Snapshot path released\n");
}

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
      error = init_snapshot_session(session, mount_timestamp);
      if (error) {
            kfree(session);
            return error;
      }

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

      dev_get(&new_sdev->dev);

      return FREE_SDEV;
}

static int mount_bdev_ret_handler(struct kretprobe_instance *ri,
                                  struct pt_regs *regs) {
      struct dentry *mnt_dentry;
      dev_t dev;
      snap_device *sdev;
      int error;

      mnt_dentry = dget((struct dentry *)regs_return_value(regs));
      if (IS_ERR(mnt_dentry))
            goto ret_handler;

      if (mnt_dentry->d_sb->s_bdev) {
            struct block_device *bdev = mnt_dentry->d_sb->s_bdev;
            if (MAJOR(bdev->bd_dev) == LOOP_MAJOR) {
                  // Extract the backing file of the loop device
                  struct file *lo_backing_file;
                  lo_backing_file =
                      ((struct loop_device_meta *)bdev->bd_disk->private_data)
                          ->lo_backing_file;
                  if (lo_backing_file) {
                        log_info("The backing file of the loop device is: %s",
                                 lo_backing_file->f_path.dentry->d_name.name);
                  }

            } else {
                  // A regular block device

                  // Don't really care about the error
                  rcu_compute_on_sdev(bdev->bd_dev, NULL,
                                      new_session_on_mount_callback);
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

// Function to clear the snapshot session on unmount. It is used as a
// callback for the `rcu_compute_on_sdev` function.
static int free_session_on_umount_callback(snap_device *sdev, void *arg) {
      snap_device *old_sdev, *new_sdev;

      if (!sdev)
            return -NOSDEV;

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

      dev_get(&new_sdev->dev);

      return FREE_SDEV;
}

struct umount_data {
      dev_t dev;
};

static int umount_entry_handler(struct kretprobe_instance *ri,
                                struct pt_regs *regs) {
      struct umount_data *ud = (struct umount_data *)ri->data;
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

      ud->dev = sb->s_bdev->bd_dev;
      return 0;
}

static int umount_ret_handler(struct kretprobe_instance *ri,
                              struct pt_regs *regs) {
      struct umount_data *ud = (struct umount_data *)ri->data;
      dev_t dev = ud->dev;

      // Don't care about the error
      rcu_compute_on_sdev(dev, NULL, free_session_on_umount_callback);

      return 0;
}

static struct kretprobe rp_umount = {
    .kp.symbol_name = "kill_block_super",
    .entry_handler = umount_entry_handler,
    .handler = umount_ret_handler,
    .data_size = sizeof(struct umount_data),
};

// Callback function used to retrieve the session path for a snapshot
// device. This is a helper function used within `rcu_compute_on_sdev`
static int sdev_session_path(snap_device *sdev, void *out) {

      if (!sdev) {
            return -NOSDEV;
      }
      if (!sdev->session) {
            return -SDEVNOTACTIVE;
      }
      struct path *path = (struct path *)out;
      struct path snap_path = session_path_get(sdev->session);

      *path = snap_path;

      return 0;
}

// struct out_log {
//       blog_entry **entries;
//       u32 num_entries;
// };

// Build the log that contains the original block data being overwritten
// static int build_block_log(struct inode *inode, loff_t offset, size_t count,
//                            struct path snap_path, struct out_log *out) {
//       struct super_block *sb;
//       sector_t first_block, last_block, block;
//       unsigned int blocksize;
//       struct buffer_head *bh = NULL;
//       int num_blocks, index = 0;
//       int error;

//       // Compute block range
//       first_block = offset >> inode->i_blkbits;
//       last_block = (offset + count - 1) >> inode->i_blkbits;
//       DEBUG_ASSERT(first_block <= last_block);

//       blocksize = 1 << inode->i_blkbits;
//       num_blocks = last_block - first_block + 1;

//       out->entries = kmalloc(num_blocks * sizeof(blog_entry *), GFP_ATOMIC);
//       if (!out->entries)
//             return -ENOMEM;

//       for (int i = 0; i < num_blocks; i++)
//             out->entries[i] = NULL;

//       sb = inode->i_sb;

//       // Process each block in the range
//       for (block = first_block; block <= last_block; block++) {
//             blog_entry *entry = NULL;
//             sector_t phys_block = bmap(inode, block);

//             if (!phys_block) {
//                   error = -NOPHYSBLOCK;
//                   goto cleanup;
//             }

//             bh = sb_bread(sb, phys_block);
//             if (!bh) {
//                   AUDIT log_err("Failed to read block %llu\n",
//                                 (unsigned long long)phys_block);
//                   error = -NOBHEAD;
//                   goto cleanup;
//             }
//             DEBUG_ASSERT(bh->b_size == blocksize);

//             entry = kmalloc(sizeof(blog_entry), GFP_KERNEL);
//             if (!entry) {
//                   error = -ENOMEM;
//                   goto cleanup;
//             }

//             entry->orig_data = kmalloc(blocksize, GFP_KERNEL);
//             if (!entry->orig_data) {
//                   kfree(entry);
//                   error = -ENOMEM;
//                   goto cleanup;
//             }

//             // Store block information
//             entry->block = block;
//             entry->data_size = blocksize;
//             entry->snap_path = s_refs->snap_path;
//             memcpy(entry->orig_data, bh->b_data, blocksize);

//             // Save the entry and cleanup buffer head
//             out->entries[index++] = entry;
//             brelse(bh);
//             bh = NULL;
//       }
//       out->num_entries = num_blocks;

//       return 0;

// cleanup:
//       if (bh)
//             brelse(bh);
//       for (int i = 0; i < index; i++)
//             kfree(out->entries[i]);
//       kfree(out->entries);
//       return error;
// }

// struct write_params {
//       struct file *file;
//       loff_t offset;
//       size_t count;
// };

// static int pre_write_handler(struct write_params *params, struct out_log
// *log) {
//       struct path snap_path;
//       int error;

//       struct file *file = params->file;
//       loff_t offset = params->offset;
//       size_t count = params->count;
//       if (!file || !file->f_inode)
//             return -EINVAL;

//       struct inode *inode = igrab(file->f_inode);
//       if (!inode->i_sb->s_bdev) {
//             iput(inode);
//             return -NOSDEV;
//       }
//       dev_t dev = inode->i_sb->s_bdev->bd_dev;

//       // If the snapshot device is not registered, it simply returns an error
//       error = rcu_compute_on_sdev(dev, &snap_path, sdev_session_path);
//       if (error) {
//             iput(inode);
//             return error;
//       }
//       error = build_block_log(inode, offset, count, snap_path, log);

//       return error;
// }

// static int vfs_write_entry_handler(struct kretprobe_instance *ri,
//                                    struct pt_regs *regs) {
//       struct out_log *log = (struct out_log *)ri->data;
//       struct write_params params;
//       int error;
// #ifdef CONFIG_X86_64
//       params.file = (struct file *)regs->di;
//       params.count = (size_t)regs->dx;
//       params.offset = (loff_t *)regs->cx;

//       error = pre_write_handler(&params, log);
//       if (error) {
//             return -1;
//       }

//       return 0;
// #else
// #error "Unsupported architecture"
// #endif
// }

// static struct kretprobe rp_vfs_write = {
//     .kp.symbol_name = "vfs_write",
//     .entry_handler = vfs_write_entry_handler,
//     // TODO .handler = vfs_write_ret_handler,
//     .data_size = sizeof(struct out_log),
// };

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

      // Tries to deallocate the snapshot device
      error = unregister_device(dev_name);
      if (error) {
            return error;
      }
      // Decrement module reference count
      module_put(THIS_MODULE);

      return 0;
}
