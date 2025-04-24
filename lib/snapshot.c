#include "../include/snapshot.h"
#include "../include/auth.h"
#include "../include/hlist_rcu.h"
#include "../include/utils.h"

/* Root of the snapshot directory hierarchy */
static struct path snapshot_root_path;

/* Registered devices to the snapshot subsystem */
static struct snapshot_devices devices;

/*
 * Two possible versions:
 * 1) V1 (works for the testing singlefilefs and other similar FS): Fully
 * spec-compliant, primarely hooks buffer cache. 2) EXPERIMENTAL_V2 (supports
 * other FS): Hooks submit_bio at the block layer. WARNING: Experimental version
 * may violate a bit the specifications.
 */
static SnapshotVersion version = V1;

/* Per-CPU containers for active snapshot sessions. Each file container (one for
each thread that executes on a cpu) can hold multiple block log entries */
static DEFINE_PER_CPU(struct snap_containers, session_containers);

/* Workqueue for block log processing */
static struct workqueue_struct *block_log_wq;
static int max_percpu_contexts = 1;

inline void init_devices(SnapshotVersion v) {
      INIT_LIST_HEAD(&devices.fdevices);
      version = v;
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

      dentry = lookup_one_len("snapshot", root_path.dentry, strlen("snapshot"));
      if (IS_ERR(dentry)) {
            error = PTR_ERR(dentry);
            goto cleanup_root;
      }

      error = vfs_mkdir(root_path.mnt->mnt_idmap, d_inode(root_path.dentry),
                        dentry, 0660);
      if (error)
            goto cleanup_all;

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

int init_work_queue(int max_active) {

      block_log_wq = alloc_workqueue("block_log_wq", WQ_UNBOUND, max_active);
      if (!block_log_wq) {
            return -ENOMEM;
      }
      max_percpu_contexts = max_active;
      return 0;
}

void cleanup_work_queue(void) {
      if (block_log_wq) {
            destroy_workqueue(block_log_wq);
            flush_workqueue(block_log_wq);

            log_info("block_log_wq destroyed\n");
      }
}

/* RCU based functions to manage device-files */

static inline void rcu_register_filedev(file_dev_t *fdev) {
      spin_lock(&devices.f_lock);
      list_add_rcu(&fdev->node, &devices.fdevices);
      spin_unlock(&devices.f_lock);
}

static inline void rcu_unregister_filedev(file_dev_t *fdev) {
      spin_lock(&devices.f_lock);
      list_del_rcu(&fdev->node);
      spin_unlock(&devices.f_lock);
}

static inline void rcu_replace_filedev(file_dev_t *old_fdev,
                                       file_dev_t *new_fdev) {
      spin_lock(&devices.f_lock);
      list_replace_rcu(&old_fdev->node, &new_fdev->node);
      spin_unlock(&devices.f_lock);
}

/* Callback functions used within `rcu_compute_on_fdev` */

/* Checks that a device-file is not already registered. */
static inline int no_file_dev_callback(file_dev_t *fdev, void *arg) {
      if (fdev != NULL) {
            return -DEXIST;
      }
      return 0;
}

/* Checks if a device-file is already registered and gets its name. */
static inline int lo_backing_file_exists_callback(file_dev_t *fdev, void *arg) {

      if (fdev == NULL) {
            return -NOFDEV;
      }

      // Pass the device name to the caller
      *(char **)arg = fdev->dev_name;

      return 0;
}

/* Removes a device-file from the registered devices. */
static int remove_fdev_callback(file_dev_t *fdev, void *arg) {
      if (!fdev) {
            return -NOFDEV;
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

/* Maps/unmaps a device-file. */
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

      dget(new_fdev->dentry);

      return FREE_RCU;
}

/* Callback to free a device-file (used within `call_rcu`) */
static inline void put_fdev_callback(struct rcu_head *rcu) {
      file_dev_t *fdev = container_of(rcu, file_dev_t, rcu);

      dput(fdev->dentry);
      kfree(fdev);
}

/* Computes a function on a device-file. It looks up the device (via its dentry)
and calls the compute function on the found device (it follows RCU based
syncronization). */
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

/* RCU based functions to manage snapshot devices */

static inline void rcu_register_snapdevice(snap_device *sdev) {
      u32 hash = hash_dev(d_num(sdev));

      HLIST_RCU_INSERT(sdev, devices.sdevices, devices.s_locks, hash);
}

static inline void rcu_unregister_snapdevice(snap_device *sdev) {
      u32 hash = hash_dev(d_num(sdev));

      HLIST_RCU_REMOVE(sdev, devices.s_locks, hash);
}

/* Callback function that checks that a snapshot device is not registered. It is
used within `rcu_compute_on_sdev`. */
static inline int no_sdev_callback(snap_device *sdev, void *arg) {
      if (sdev != NULL) {
            return -DEXIST;
      } else {
            return 0;
      }
}

/* Callback that removes a snapshot device from the registered snapshot devices.
It is used within `rcu_compute_on_sdev`. */
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

struct session_dentry_metadata {
      struct dentry *dentry;
      bool is_owner;
};

/* Create a new snapshot session directory and get its associated dentry. It is
 used within `rcu_compute_on_sdev`. */
static int session_dentry_callback(snap_device *sdev, void *arg) {
      char snap_subdirname[288];
      struct dentry *session_dentry = NULL;
      int ret;

      DEBUG_ASSERT(sdev != NULL && sdev->session != NULL);

      struct session_dentry_metadata *session_meta = arg;

      // This is needed to have a single thread creating the session directory
      mutex_lock(&sdev->session->snap_dir_mtx);

      if (d_session(sdev->session)) {
            // Pass the path to the caller
            session_meta->dentry = sdev->session->snap_dentry;
            mutex_unlock(&sdev->session->snap_dir_mtx);

            return 0;
      }

      // Build the snapshot subdirectory name: "<dev_name>_<timestamp>"
      snprintf(snap_subdirname, sizeof(snap_subdirname), "%s_%llu",
               sdev_name(sdev), sdev->session->mount_timestamp);

      path_to_safe_name(snap_subdirname);

      // Allocate a new dentry for the subdirectory
      session_dentry = d_alloc_name(snapshot_root_path.dentry, snap_subdirname);
      if (!session_dentry) {
            mutex_unlock(&sdev->session->snap_dir_mtx);
            return -ENOMEM;
      }

      // Create the new directory
      ret = vfs_mkdir(snapshot_root_path.mnt->mnt_idmap,
                      d_inode(snapshot_root_path.dentry), session_dentry, 0660);
      if (ret) {
            dput(session_dentry);
            mutex_unlock(&sdev->session->snap_dir_mtx);

            return ret;
      }
      // Assign the new dentry to the session and release the mutex
      sdev->session->snap_dentry = session_dentry;
      mutex_unlock(&sdev->session->snap_dir_mtx);

      log_info("Created snapshot session directory: %s\n",
               session_dentry->d_name.name);

      // Pass the dentry to the caller: it will be the owner
      session_meta->dentry = session_dentry;
      session_meta->is_owner = true;

      return 0;
}

/* Create a new snapshot session of a registered snapshot device.
It is used within `rcu_compute_on_sdev`. */
static int new_session_callback(snap_device *sdev, void *arg) {
      snap_device *old_sdev, *new_sdev;
      snapshot_session *session;
      time64_t mount_timestamp;

      struct vfsmount *mnt = arg;

      if (!sdev) {
            return -NOSDEV;
      }

      DEBUG_ASSERT(!sdev->session);

      session = kmalloc(sizeof(snapshot_session), GFP_ATOMIC);
      if (!session) {
            return -ENOMEM;
      }

      mount_timestamp = ktime_get_real_seconds();
      init_snapshot_session(session, mount_timestamp, mnt);

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

/* Frees per-cpu session containers. It is executed asyncronously within
`on_each_cpu` function. */
static void free_percpu_session_containers(void *info) {
      struct snap_containers *containers = this_cpu_ptr(&session_containers);
      struct dentry *snap_dentry = info;

      u32 hash = hash_str(snap_dentry->d_name.name, DEFAULT_HASH_BITS);

      struct snap_session_container *entry;
      struct hlist_node *tmp;
      struct snap_session_container container_lookup = {
          .session_dentry = snap_dentry,
      };

      // If only one context is allowed to execute per cpu we don't need to sync
      if (max_percpu_contexts > 1)
            write_lock(&containers->rw_locks[hash]);

      // Delete all containers with the same session name
      hlist_for_each_entry_safe(entry, tmp, &containers->hlist[hash], hnode) {
            if (containers_cmp_session(entry, &container_lookup)) {

                  hlist_del(&entry->hnode);

                  free_container(entry);

                  // Release a module ref taken during the creation of the
                  // container
                  module_put(THIS_MODULE);
            }
      }

      if (max_percpu_contexts > 1)
            write_unlock(&containers->rw_locks[hash]);
}

/* Frees a snapshot device and its session */
static void free_sdev(snap_device *sdev) {
      if (sdev->session) {
            snapshot_session *session = sdev->session;
            int i;

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

            if (session->snap_dentry) {
                  // Ensure async execution
                  on_each_cpu(free_percpu_session_containers,
                              (void *)session->snap_dentry, 0);
            }

            kfree(session);
      }

      kfree(sdev);
}

/* Callback to free a snapshot device without its session. Used within
`call_rcu` function. */
static inline void free_sdev_no_session_callback(struct rcu_head *rcu) {
      snap_device *sdev = container_of(rcu, snap_device, rcu);

      kfree(sdev);
}

/* Callback to free a snapshot device and its session. Used within `call_rcu`
function. */
static inline void free_sdev_callback(struct rcu_head *rcu) {
      snap_device *sdev = container_of(rcu, snap_device, rcu);

      free_sdev(sdev);
}

/* Computes a function on a snapshot device. It looks up the device by its
`dev_t` identifier and calls the function following RCU based
syncronization. */
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

static inline bool may_open_device(const struct path *path) {
      return !(path->mnt->mnt_flags & MNT_NODEV) &&
             !(path->mnt->mnt_sb->s_iflags & SB_I_NODEV);
}

static char *get_dev_by_pathname(const char *pathname, generic_dev_t *dev) {
      struct inode *inode;
      struct path path;
      int error;

      error = kern_path(pathname, LOOKUP_FOLLOW, &path);
      if (error) {
            return ERR_PTR(error);
      }

      char *resolved_name = d_path(&path, dev->pathname, MAX_DEV_LEN);
      if (IS_ERR(resolved_name)) {
            goto out_path_put;
      }

      inode = d_backing_inode(path.dentry);
      if (!S_ISBLK(inode->i_mode)) {
            // The provided pathname represents the actual pathname associated
            // to the file managed as device-file (used for a loop device).
            file_dev_t fdev;
            INIT_FDEV(&fdev, path.dentry, resolved_name);
            dev->type = FDEV;
            dev->fdev = fdev;

            goto out_path_put;
      }

      if (!may_open_device(&path)) {
            resolved_name = ERR_PTR(-EACCES);
            goto out_path_put;
      }

      // An actual block device
      dev->type = BDEV;
      dev->dev = inode->i_rdev;

out_path_put:
      path_put(&path);
      return resolved_name;
}

static int register_device(const char *dev_name) {
      generic_dev_t dev;
      int error;

      // Try to initialize the device
      char *resolved_name = get_dev_by_pathname(dev_name, &dev);
      if (IS_ERR(resolved_name)) {
            error = PTR_ERR(resolved_name);
            return error;
      }

      switch (dev.type) {
      case BDEV:
            snap_device tmp_sdev, *sdev;

            INIT_SNAP_DEVICE(&tmp_sdev, dev.dev, resolved_name);
            // Check if the snapshot device is already registered
            error =
                rcu_compute_on_sdev(d_num(&tmp_sdev), NULL, no_sdev_callback);
            if (error) {
                  log_info("Cannot register device: Block device %s already "
                           "registered\n",
                           sdev_name(&tmp_sdev));
                  return error;
            }
            sdev = kmalloc(sizeof(snap_device), GFP_KERNEL);
            if (!sdev) {
                  return -ENOMEM;
            }
            memcpy(sdev, &tmp_sdev, sizeof(snap_device));

            // Register the snapshot device
            rcu_register_snapdevice(sdev);
            log_info("Device Registered: Block device %s\n", sdev_name(sdev));
            break;
      case FDEV:
            // Check if the device file is already registered
            error = rcu_compute_on_filedev(dev.fdev.dentry, NULL,
                                           no_file_dev_callback);
            if (error) {
                  log_info("Cannot register device: Loop backing file %s "
                           "already registered\n",
                           dev.fdev.dev_name);
                  dput(dev.fdev.dentry);
                  return error;
            }

            file_dev_t *fdev = kmalloc(sizeof(file_dev_t), GFP_KERNEL);
            if (!fdev) {
                  dput(dev.fdev.dentry);
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

      char *resolved_name = get_dev_by_pathname(dev_name, &dev);
      if (IS_ERR(resolved_name)) {
            error = PTR_ERR(resolved_name);
            return error;
      }

      switch (dev.type) {
      case BDEV:
            error = rcu_compute_on_sdev(dev.dev, NULL, remove_sdev_callback);
            if (error) {
                  log_info("Unregister Device: Cannot remove block device %u. "
                           "Error: "
                           "%d\n",
                           dev.dev, error);
                  return error;
            }
            log_info("Unregistered Device: Block device %s\n", resolved_name);
            break;

      case FDEV:
            error = rcu_compute_on_filedev(dev.fdev.dentry, NULL,
                                           remove_fdev_callback);
            dput(dev.fdev.dentry);
            if (error) {
                  log_info(
                      "Unregister Device: Cannot remove loop backing file %s. "
                      "Error: %d\n",
                      fdev_name(&dev.fdev), error);
                  return error;
            }
            log_info("Unregistered Device: Loop backing file %s\n",
                     resolved_name);
      }

      return 0;
}

static struct snap_session_container *
create_snap_container(struct dentry *session_dentry, int cpu,
                      unsigned int block_size, bool is_owner) {
      struct snap_session_container *container = NULL;
      char container_fname[32];
      struct dentry *container_dentry = NULL;
      struct file *filp = NULL;
      int ret;

      snprintf(container_fname, sizeof(container_fname), "snap_c%d_%d", cpu,
               current->pid);

      container_dentry = d_alloc_name(session_dentry, container_fname);

      if (!container_dentry)
            return ERR_PTR(-ENOMEM);

      ret =
          vfs_create(snapshot_root_path.mnt->mnt_idmap, d_inode(session_dentry),
                     container_dentry, S_IFREG | 0660, true);
      if (ret)
            goto out_err;

      struct path child_path = {
          .mnt = snapshot_root_path.mnt,
          .dentry = container_dentry,
      };

      filp = dentry_open(&child_path, O_WRONLY | O_APPEND, current_cred());
      if (IS_ERR(filp)) {
            ret = PTR_ERR(filp);
            filp = NULL;
            goto out_err;
      }

      container = alloc_session_container(session_dentry, filp, current->pid);
      if (!container) {
            ret = -ENOMEM;
            goto out_err;
      }

      dput(container_dentry);

      if (!is_owner)
            // Take extra ref for non-owner CPUs
            dget(session_dentry);

      // Write the session header to the container file
      session_header_t header;
      header.magic = SNAPSHOT_SESSION_MAGIC;
      header.block_size = block_size;

      ret =
          kernel_write(container->file, &header, sizeof(header), &filp->f_pos);
      if (ret != sizeof(header)) {
            ret = -EIO;
            goto out_err;
      }

      return container;

out_err:
      if (container) {
            kfree(container);
      }
      if (filp)
            filp_close(filp, NULL);
      if (container_dentry)
            dput(container_dentry);
      return ERR_PTR(ret);
}

static int make_snapshot(const char *session_name, struct crypto_comp *comp,
                         struct file *container_file, u64 block_num,
                         unsigned int data_size, char *bdata) {
      snap_record_header_t header;
      struct compressed_data compressed;
      loff_t pos;
      ssize_t written;
      int ret;

      compressed.size = data_size;
      compressed.data = kmalloc(data_size, GFP_KERNEL);
      if (!compressed.data)
            return -ENOMEM;

      // Compress the data
      ret = compress_data(comp, bdata, data_size, &compressed);
      bool use_compression = true;
      if (ret) {
            // Compression failed (e.g. the compressed data is larger then the
            // original and does not fit in the buffer).
            // Fallback to original uncompressed data
            use_compression = false;
      }

      // Build the record header
      header.block_number = block_num;
      header.compressed_size = use_compression ? compressed.size : 0;
      header.is_compressed = use_compression;
      header.data_size = data_size;
      header.checksum =
          compute_checksum(bdata, data_size, (u32)header.block_number);

      AUDIT log_info(
          "Logging block %llu. Session: %s. Compressed size: %u. Data size: "
          "%u. Checksum: %u\n",
          header.block_number, session_name, header.compressed_size,
          header.data_size, header.checksum);

      pos = container_file->f_pos;

      // Write the header record
      written = kernel_write(container_file, &header, sizeof(header), &pos);
      if (written != sizeof(header)) {
            ret = -EIO;
            goto out;
      }
      pos += written;

      // Write the data
      char *data_to_write = use_compression ? compressed.data : bdata;
      unsigned int write_size = use_compression ? compressed.size : data_size;
      written = kernel_write(container_file, data_to_write, write_size, &pos);
      if (written != write_size) {
            ret = -EIO;
            goto out;
      }

      ret = 0;
out:
      kfree(compressed.data);
      return ret;
}

static int process_block(blog_work *bwork, int cpu) {
      dev_t dev;
      struct dentry *session_dentry;
      bool is_cpu_dentry_owner; // whether the CPU is the creator of the dentry
      struct snap_session_container *container;
      unsigned int block_size;
      int ret;

      dev = bwork->mnt->mnt_sb->s_bdev->bd_dev;
      session_dentry = bwork->session_dentry;

      AUDIT log_info("Processing block log work on CPU %d. Thread: %d, Device: "
                     "%u, Block: %llu\n",
                     cpu, current->pid, dev, bwork->block);

      if (!session_dentry) {
            struct session_dentry_metadata session_meta = {
                .dentry = NULL,
                .is_owner = false,
            };
            ret = rcu_compute_on_sdev(dev, (void *)&session_meta,
                                      session_dentry_callback);
            if (ret) {
                  return ret;
            }

            session_dentry = session_meta.dentry;
            is_cpu_dentry_owner = session_meta.is_owner;
      }

      struct snap_containers *containers = this_cpu_ptr(&session_containers);
      u32 hash = hash_str(session_dentry->d_name.name, DEFAULT_HASH_BITS);

      if (max_percpu_contexts > 1)
            read_lock(&containers->rw_locks[hash]);

      struct snap_session_container *entry;
      hlist_for_each_entry(entry, &containers->hlist[hash], hnode) {
            struct snap_session_container lookup_container = {
                .session_dentry = session_dentry,
                .pid = current->pid,
            };

            if (containers_cmp(entry, &lookup_container)) {
                  container = entry;

                  if (max_percpu_contexts > 1)
                        read_unlock(&containers->rw_locks[hash]);
                  goto make_snapshot;
            }
      }
      if (max_percpu_contexts > 1)
            read_unlock(&containers->rw_locks[hash]);

      switch (version) {
      case V1:
            block_size = bwork->mnt->mnt_sb->s_blocksize;
            break;
      case EXPERIMENTAL_V2:
            block_size = bdev_logical_block_size(bwork->mnt->mnt_sb->s_bdev);
            break;
      default:
            log_err("No other valid versions");
            DEBUG_ASSERT(false);
            break;
      }

      container = create_snap_container(session_dentry, cpu, block_size,
                                        is_cpu_dentry_owner);

      if (IS_ERR(container)) {
            if (is_cpu_dentry_owner)
                  dput(session_dentry);
            ret = PTR_ERR(container);

            return ret;
      }

      // Get a reference to the module after creating the container. This
      // ensures that the module does not get unloaded until there are cpus that
      // might still have to free the created containers.
      ret = try_module_get(THIS_MODULE);
      // Module should not be unloading because there is at least one active
      // session device (thus already a module reference)
      DEBUG_ASSERT(ret);

      if (max_percpu_contexts > 1)
            write_lock(&containers->rw_locks[hash]);

      hlist_add_head(&container->hnode, &containers->hlist[hash]);

      if (max_percpu_contexts > 1)
            write_unlock(&containers->rw_locks[hash]);

      AUDIT log_info("Created new session container on CPU %d. Thread id: %d. "
                     "Session: %s. Block "
                     "size: %u\n",
                     cpu, current->pid, container->session_dentry->d_name.name,
                     block_size);

make_snapshot:

      ret = make_snapshot(session_dentry->d_name.name, container->comp,
                          container->file, bwork->block, bwork->data_size,
                          bwork->orig_data);

      if (ret) {
            // No need to free the container since it could be used by later
            // snapshot operations. Free is demanded at the end of the session.
            return ret;
      }

      log_info(
          "Snapshot done. CPU: %d, Thread id: %d, Session: %s, Block: %llu",
          cpu, current->pid, session_dentry->d_name.name, bwork->block);

      return 0;
}

/* Worker function that processes a block log work */
static void process_block_log(struct work_struct *work) {

      blog_work *bwork = container_of(work, struct block_log_work, work);
      int ret;

      int cpu = smp_processor_id();

      ret = process_block(bwork, cpu);
      if (ret) {
            log_err("Error during work processing. CPU: %d, Thread id: %d, "
                    "Device: %u, Block: %llu. "
                    "Error: %d\n",
                    cpu, current->pid, bwork->mnt->mnt_sb->s_bdev->bd_dev,
                    bwork->block, ret);
      }

      // Final end of vfsmount chain at step 4.
      free_blog_work(bwork);
}

static int try_new_snapshot_session(struct dentry *dentry,
                                    struct vfsmount *mnt) {
      struct block_device *bdev = dentry->d_sb->s_bdev;
      int ret;
      if (MAJOR(bdev->bd_dev) == LOOP_MAJOR) {
            // Loop device

            // We first check that there is no snapshot device mapped to the
            // device-file
            ret = rcu_compute_on_sdev(bdev->bd_dev, NULL, no_sdev_callback);

            if (ret) {
                  return ret;
            }

            // Extract the backing file of the loop device
            struct file *lo_backing_file;
            lo_backing_file =
                ((struct loop_device_meta *)bdev->bd_disk->private_data)
                    ->lo_backing_file;

            // Check if the backing file is registered within the
            // `fdevices` list. If it is we also get the device name
            char *dev_name;
            ret = rcu_compute_on_filedev(lo_backing_file->f_path.dentry,
                                         &dev_name,
                                         lo_backing_file_exists_callback);

            if (ret) {
                  // The device-file is not registered
                  return ret;
            }

            // The device-file is registered. We can create a new snapshot
            // device and activate a new session
            snap_device tmp_sdev, *sdev;
            INIT_SNAP_DEVICE(&tmp_sdev, bdev->bd_dev, dev_name);

            sdev = kmalloc(sizeof(snap_device), GFP_ATOMIC);
            if (!sdev) {
                  return -ENOMEM;
            }
            memcpy(sdev, &tmp_sdev, sizeof(snap_device));

            // Create the session
            snapshot_session *session;
            time64_t mount_timestamp;

            session = kmalloc(sizeof(snapshot_session), GFP_ATOMIC);
            if (!session) {
                  kfree(sdev);
                  return -ENOMEM;
            }

            mount_timestamp = ktime_get_real_seconds();
            init_snapshot_session(session, mount_timestamp, mnt);
            sdev->session = session;
            sdev->private_data = (void *)lo_backing_file->f_path.dentry;

            // Register the snapshot device
            rcu_register_snapdevice(sdev);
            AUDIT log_info(
                "mount_ret_handler: loop device %u registered with a new "
                "session. "
                "Backing file %s\n",
                sdev->dev, sdev_name(sdev));

            // Map the device-file
            bool map = true;
            ret = rcu_compute_on_filedev(lo_backing_file->f_path.dentry, &map,
                                         map_filedev_callback);
            if (ret) {
                  kfree(session);
                  kfree(sdev);
                  return ret;
            }

      } else {
            // A regular block device

            // Don't really care about the error. If the device is not
            // registered it simply won't perform any action.
            ret = rcu_compute_on_sdev(bdev->bd_dev, (void *)mnt,
                                      new_session_callback);
            if (ret) {
                  return ret;
            }

            AUDIT log_info(
                "mount_ret_handler: new session for block device %u\n",
                bdev->bd_dev);
      }

      return 0;
}

static int mount_bdev_ret_handler(struct kretprobe_instance *ri,
                                  struct pt_regs *regs) {
      struct dentry *mnt_dentry;

      mnt_dentry = dget((struct dentry *)regs_return_value(regs));
      if (IS_ERR(mnt_dentry))
            goto out;

      if (mnt_dentry->d_sb->s_bdev) {
            // Don't care about the error
            // If the device is not registered it simply won't perform any
            // action.
            try_new_snapshot_session(mnt_dentry, NULL);
      }

out:
      dput(mnt_dentry);
      return 0;
}

static struct kretprobe rp_mount = {
    .kp.symbol_name = "mount_bdev",
    .handler = mount_bdev_ret_handler,
};

/* Function to clear the snapshot session on umount. For loop devices it will
free the whole `snap_device` and unmap the device-file. It is used as a callback
for the `rcu_compute_on_sdev` function. */
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
            AUDIT log_info("umount_callback: Loop device %u unregistered with "
                           "backing file %s\n",
                           sdev->dev, sdev_name(sdev));
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
                "umount_callback: Cleared session for block device %s\n",
                sdev_name(old_sdev));
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
      struct vfsmount *mnt;
      loff_t offset;
      size_t count;

      u64 block;
};

/* Callback function used to acquire the block number that will eventually be
overwritten. It adds the block number to the session
`reading_blocks` in order for the `sb_bread` kretprobe to know which block to
copy. It adds the block also to the session `committed_blocks` to know which
subsequent write will not be captured because the block was already copied.
NOTE: As of now we support a single block write at a time. */
static int record_block_on_write_callback(snap_device *sdev, void *arg) {
      snapshot_session *session;
      struct vfsmount *mnt;
      struct snap_block *snap_block;
      struct write_metadata *wm;

      if (!sdev) {
            return -NOSDEV;
      }
      if (!sdev->session) {
            return -SDEVNOTACTIVE;
      }

      session = sdev->session;
      wm = (struct write_metadata *)arg;

      mnt = version == V1 ? wm->mnt : session->mnt;
      DEBUG_ASSERT(mnt != NULL);

      // This vfsmount will traverse a chain. If it passes through all steps, it
      // will be released at the end of the deferred working process. If one of
      // the steps fails to go through, it will be released before.

      // vfsmount chain step 1.
      mnt = mntget(mnt);

      if (version == V1) {
            // We simply retrieve the physical block number being overwritten.
            // Since in many filesystems it can be a blocking function, be
            // cautious (for the singlefilefs we know is not blocking).
            int ret = get_block(wm->inode, wm->offset, &wm->block);
            DEBUG_ASSERT(!ret);
      }
      // If we are not in V1, the block is passed as an argument by
      // the caller

      snap_block = kmalloc(sizeof(struct snap_block), GFP_ATOMIC);
      if (!snap_block) {
            // End of vfsmount at chain step 1.
            mntput(mnt);
            return -ENOMEM;
      }

      INIT_SNAP_BLOCK(snap_block, mnt, wm->block);
      u32 b_hash = hash_block(snap_block->block);

      // Add the block to the committed blocks (if it does not exist already)
      spin_lock(&session->cb_locks[b_hash]);

      struct snap_block *sb;
      hlist_for_each_entry(sb, &session->committed_blocks[b_hash], cb_hnode) {
            if (sb->block == snap_block->block) {
                  spin_unlock(&session->cb_locks[b_hash]);

                  AUDIT log_info("record_block_on_write_callback: Snapshot "
                                 "device : %s; Block %llu is "
                                 "already committed\n",
                                 sdev_name(sdev), snap_block->block);

                  kfree(snap_block);

                  // End of vfsmount at chain step 1.
                  mntput(mnt);

                  return -BLOCK_COMMITTED;
            }
      }

      hlist_add_head(&snap_block->cb_hnode, &session->committed_blocks[b_hash]);
      spin_unlock(&session->cb_locks[b_hash]);

      AUDIT log_info(
          "record_block_on_write_callback: Snapshot device : %s; Block %llu "
          "committed\n",
          sdev_name(sdev), snap_block->block);

      // Add the block to the reading blocks
      spin_lock(&session->rb_locks[b_hash]);
      // vfsmount chain step 2. The vfsmount is held by the `snap_block` and
      // stored in the reading_blocks. The `snap_block` is also stored in the
      // committed list, but the lifecycle of the vfsmount is only dependent to
      // the `rading_blocks` list.
      hlist_add_head(&snap_block->rb_hnode, &session->reading_blocks[b_hash]);
      spin_unlock(&session->rb_locks[b_hash]);

      return 0;
}

struct write_kretprobe_metadata {
      dev_t dev;
      u64 block;
};

static int pre_write_handler(struct file *file, loff_t *off, size_t count,
                             struct write_kretprobe_metadata *out_meta) {
      struct write_metadata wm;
      int ret;

      if (!file || !off)
            return -EINVAL;

      struct dentry *dentry = dget(file->f_path.dentry);
      struct vfsmount *mnt = mntget(file->f_path.mnt);
      if (!dentry || !dentry->d_inode->i_sb || !dentry->d_inode->i_sb->s_bdev) {
            return -EINVAL;
      }

      dev_t dev = dentry->d_inode->i_sb->s_bdev->bd_dev;

      // Versioning check: If a filesystem does not use `mount_bdev`, we fall
      // back to session creation during the first write. NOTE: This slightly
      // violates the project specs for non-`mount_bdev` cases. To ensure
      // correctness for such other cases, users MUST avoid registering devices
      // while mounted.
      if (version == V1) {

            wm.inode = dentry->d_inode;
            wm.mnt = mnt;
            wm.offset = *off;
            wm.count = count;

            // Record the block that will be overwritten. If the device is not
            // registered and has no active session it simply won't perform any
            // action.
            // NOTE: a single block write at a time is supported.
            ret = rcu_compute_on_sdev(dev, &wm, record_block_on_write_callback);
            if (!ret) {
                  out_meta->dev = dev;
                  out_meta->block = wm.block;
            }
      } else {
            // EXPERIMENTAL_V2

            // Session creation fallback: here we check if the device is
            // registered and has an active session, or has a mapped snapshot
            // device (for loop devices)
            ret = try_new_snapshot_session(dentry, mnt);
            if (!ret) {
                  log_info("pre_write_handler: Session created at the time of "
                           "writing.\n");
            }
      }

      dput(dentry);
      mntput(mnt);

      return ret;
}

/* Callback that rollbacks the block commitment performed during a write
operation pre handler. It deletes an entry for both the `committed_blocks`
and the `reading blocks` lists. Finally, it frees the deleted node. */
static int rollback_write_entry_callback(snap_device *sdev, void *arg) {
      u64 block;
      snapshot_session *session;

      DEBUG_ASSERT(sdev != NULL && sdev->session != NULL);

      session = sdev->session;
      block = *((u64 *)arg);

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

      // the vfsmount is released during this free.
      // End of vfsmount chain at step 2.
      sb_free(sb);

      return 0;
}

static int write_entry_handler(struct kretprobe_instance *ri,
                               struct pt_regs *regs) {
      struct file *file;
      size_t count;
      loff_t *offset;
      int ret;

      struct write_kretprobe_metadata *meta =
          (struct write_kretprobe_metadata *)ri->data;

#if defined(CONFIG_X86_64)
      file = (struct file *)regs->di;
      count = (size_t)regs->dx;
      offset = (loff_t *)regs->cx;
#elif defined(CONFIG_ARM64)
      file = (struct file *)regs->regs[0];
      count = (size_t)regs->regs[2];
      offset = (loff_t *)regs->regs[3];
#else
#error "Unsupported architecture"
#endif

      ret = pre_write_handler(file, offset, count, meta);
      if (ret) {
            // Do not execute the ret handler
            return -1;
      }

      return 0;
}

static int write_ret_handler(struct kretprobe_instance *ri,
                             struct pt_regs *regs) {
      ssize_t ret;
      struct write_kretprobe_metadata *meta;

#if defined(CONFIG_X86_64)
      ret = (ssize_t)regs->ax;
#elif defined(CONFIG_ARM64)
      ret = (ssize_t)regs->regs[0];
#else
#error "Unsupported architecture"
#endif

      meta = (struct write_kretprobe_metadata *)ri->data;

      if (ret < 0) {
            AUDIT log_info("write_ret_handler: Error writing to block "
                           "device %u\n",
                           meta->dev);

            if (version == V1)
                  // We must "rollback" what the pre_handler
                  //  did
                  rcu_compute_on_sdev(meta->dev, (void *)&meta->block,
                                      rollback_write_entry_callback);
      }

      return 0;
}

static struct kretprobe rp_vfs_write = {
    .kp.symbol_name = "vfs_write",
    .entry_handler = write_entry_handler,
    .handler = write_ret_handler,
    .data_size = sizeof(struct write_kretprobe_metadata),
};

static struct kretprobe rp_kernel_write = {
    .kp.symbol_name = "kernel_write",
    .entry_handler = write_entry_handler,
    .handler = write_ret_handler,
    .data_size = sizeof(struct write_kretprobe_metadata),
};

struct read_block_metadata {
      u64 block;

      struct vfsmount *mnt;
      struct dentry *session_dentry;
};

/* Callback to check if a read block matches the one in `arg`. If so, the caller
receives the vfsmount and the
snapshot session dentry, both needed for deferred work. */
static int try_read_block_callback(snap_device *sdev, void *arg) {
      struct read_block_metadata *meta;
      snapshot_session *session;

      if (!sdev) {
            return -NOSDEV;
      }
      if (!sdev->session) {
            return -SDEVNOTACTIVE;
      }
      session = sdev->session;
      meta = (struct read_block_metadata *)arg;

      u32 b_hash = hash_block(meta->block);

      // Check wheter there is any block to read and clear it if any
      spin_lock(&session->rb_locks[b_hash]);

      struct snap_block *sb;
      hlist_for_each_entry(sb, &session->reading_blocks[b_hash], rb_hnode) {
            if (sb->block == meta->block) {
                  AUDIT log_info("try_read_block_callback: Found reading block "
                                 "%llu for device %s\n",
                                 sb->block, sdev_name(sdev));
                  hlist_del(&sb->rb_hnode);
                  spin_unlock(&session->rb_locks[b_hash]);

                  // Inform the caller about the vfsmount of the file whose
                  // write operation triggered this block read. vfsmount chain
                  // step 3.
                  meta->mnt = sb->mnt;
                  // The `snap_block` does not care about the inode anymore.
                  sb->mnt = NULL;

                  // Inform the caller also of the snapshot path (needed by the
                  // deferred worker)
                  meta->session_dentry = session->snap_dentry;

                  // No need to free `sb` since is used within the
                  // `committed_blocks`

                  return 0;
            }
      }

      spin_unlock(&session->rb_locks[b_hash]);

      return -NO_RBLOCK;
}

static int sb_bread_entry_handler(struct kretprobe_instance *ri,
                                  struct pt_regs *regs) {

      struct block_device *bdev;
      u64 block;
      gfp_t gfp;
      struct read_block_metadata *meta;
      dev_t dev;
      int ret;

#if defined(CONFIG_X86_64)
      bdev = (struct block_device *)regs->di;
      block = (u64)regs->si;
      gfp = (gfp_t)regs->cx;
#elif defined(CONFIG_ARM64)
      bdev = (struct block_device *)regs->regs[0];
      block = (u64)regs->regs[1];
      gfp = (gfp_t)regs->regs[3];
#else
#error "Unsupported architecture"
#endif

      meta = (struct read_block_metadata *)ri->data;

      if (!bdev || gfp != __GFP_MOVABLE) {
            return -1;
      }

      dev = bdev->bd_dev;

      // Check whether to read the block or not.
      // If the block must be read, then consume the node from the session
      // reading block list
      meta->block = block;
      ret = rcu_compute_on_sdev(dev, (void *)meta, try_read_block_callback);
      if (ret) {
            // No need to copy the block: the device is unregistered, has no
            // active session, or the block is irrelevant to it.
            return -1;
      }

      DEBUG_ASSERT(dev == meta->mnt->mnt_sb->s_bdev->bd_dev);

      // Execute the return handler: copy the read block and defer VFS-related
      // work.
      return 0;
}

// If this is executed, than we must copy the block and defer vfs related work
static int sb_bread_ret_handler(struct kretprobe_instance *ri,
                                struct pt_regs *regs) {
      struct buffer_head *bh;
      struct read_block_metadata *meta;
      // Log entry used to enqueue the copied block (used in deferred working).
      blog_work *bwork;
      char *bdata;

#if defined(CONFIG_X86_64)
      bh = (struct buffer_head *)regs->ax;
#elif defined(CONFIG_ARM64)
      bh = (struct buffer_head *)regs->regs[0];
#else
#error "Unsupported architecture"
#endif

      meta = (struct read_block_metadata *)ri->data;

      if (!IS_ERR(bh)) {
            // Copy the block
            bdata = kmalloc(bh->b_size, GFP_ATOMIC);
            if (!bdata) {
                  // End of vfsmount chain at step 3.
                  mntput(meta->mnt);
                  goto out;
            }
            memcpy(bdata, bh->b_data, bh->b_size);
            AUDIT log_info(
                "sb_bread_ret_handler: Copied block %llu from device %u\n",
                meta->block, meta->mnt->mnt_sb->s_bdev->bd_dev);

            // Enqueue the block log work
            bwork = kmalloc(sizeof(blog_work), GFP_ATOMIC);
            if (!bwork) {
                  kfree(bdata);
                  // End of vfsmount chain at step 3.
                  mntput(meta->mnt);
                  goto out;
            }
            INIT_BLOG_WORK(bwork, meta->session_dentry, meta->block, bdata,
                           bh->b_size, process_block_log);

            // vfsmount chain step 4.
            // It will be the responsibility of the deferred worker to release
            // it.
            bwork->mnt = meta->mnt;

            queue_work(block_log_wq, &bwork->work);

            AUDIT log_info("sb_bread_ret_handler: Snapshot work queued "
                           "succesfully for device %u\n",
                           meta->mnt->mnt_sb->s_bdev->bd_dev);
      }

out:
      return 0;
}

static struct kretprobe rp_sb_bread = {
    .kp.symbol_name =
        "__bread_gfp", // we can't probe sb_bread beacuse is an inline function
    .entry_handler = sb_bread_entry_handler,
    .handler = sb_bread_ret_handler,
    .data_size = sizeof(struct read_block_metadata),
};

struct read_bio_metadata {
      struct page **pages;
      unsigned int nr_pages;
      unsigned int size;
};

static void read_endio(struct bio *bio) {
      struct read_block_metadata meta;
      struct read_bio_metadata *bio_meta;
      dev_t dev;
      unsigned int blocks_per_page, i;
      int ret;

      bio_meta = bio->bi_private;
      dev = bio->bi_bdev->bd_dev;

      if (bio->bi_status) {
            AUDIT log_err("Read error for device %u, at sector %llu\n", dev,
                          bio->bi_iter.bi_sector);
      } else {
            AUDIT log_info("Read completed for device %u, at sector %llu\n",
                           dev, bio->bi_iter.bi_sector);
      }

      meta.block = bio->bi_iter.bi_sector;
      ret = rcu_compute_on_sdev(dev, &meta, try_read_block_callback);
      DEBUG_ASSERT(ret == 0);
      DEBUG_ASSERT(dev == meta.mnt->mnt_sb->s_bdev->bd_dev);

      const unsigned int block_size = bdev_logical_block_size(bio->bi_bdev);
      DEBUG_ASSERT(block_size <= PAGE_SIZE);
      blocks_per_page = PAGE_SIZE / block_size;

      // Allocate a new work for each page
      blog_work **bworks =
          kmalloc_array(bio_meta->nr_pages, sizeof(blog_work *), GFP_ATOMIC);
      if (!bworks)
            goto cleanup;

      sector_t start_sector = meta.block;
      unsigned int remaining_size = bio_meta->size;
      for (i = 0; i < bio_meta->nr_pages && remaining_size > 0; i++) {
            char *block_data;
            unsigned int data_size;

            struct page *page = bio_meta->pages[i];
            sector_t current_sector = start_sector + (i * blocks_per_page);

            bworks[i] = kmalloc(sizeof(blog_work), GFP_ATOMIC);
            if (!bworks[i]) {
                  goto cleanup;
            }

            data_size = min_t(unsigned int, remaining_size, PAGE_SIZE);
            block_data = kzalloc(data_size, GFP_ATOMIC);
            if (!block_data) {
                  goto cleanup;
            }

            // Copy the page to the `block_data` buffer (used later by the
            // deferred worker)
            char *page_buf = kmap_local_page(page);
            memcpy(block_data, page_buf, data_size);
            kunmap_local(page_buf);

            // We don't need it anymore
            __free_page(page);

            INIT_BLOG_WORK(bworks[i], meta.session_dentry, current_sector,
                           block_data, data_size, process_block_log);

            // vfsmount chain step 4.
            // It will be the responsibility of the deferred worker to release
            // it.
            bworks[i]->mnt = meta.mnt;

            if (i > 0)
                  // For more than one work we must get another reference
                  mntget(meta.mnt);

            // Enqueue the block log work
            queue_work(block_log_wq, &bworks[i]->work);

            remaining_size -= data_size;
      }

      goto out;

cleanup:

      log_err("read_endio: Memory allocation error\n");

      int j = bio_meta->nr_pages;
      while (--i >= 0) {
            kfree(bworks[i]->orig_data);
            kfree(bworks[i]);

            j--;
      }
      while (j-- > 0) {
            __free_page(bio_meta->pages[bio_meta->nr_pages - j]);
      }

out:
      kfree(bworks);
      kfree(bio_meta->pages);
      kfree(bio_meta);

      bio_put(bio);
}

static int submit_read_bio(struct block_device *bdev, sector_t sector,
                           struct read_bio_metadata *bio_meta) {
      struct bio *bio;
      int i;

      bio = bio_alloc(bdev, bio_meta->nr_pages, REQ_OP_READ, GFP_ATOMIC);
      if (!bio) {
            log_err("Could not allocate bio\n");
            return -ENOMEM;
      }

      // Configure bio
      bio->bi_iter.bi_sector = sector;
      bio->bi_end_io = read_endio;
      bio->bi_private = bio_meta;

      unsigned int remaining = bio_meta->size;
      for (i = 0; i < bio_meta->nr_pages && remaining > 0; i++) {
            unsigned int len = min_t(unsigned int, PAGE_SIZE, remaining);

            if (!bio_add_page(bio, bio_meta->pages[i], len, 0)) {
                  log_err("Failed to add page to bio\n");
                  bio_put(bio);
                  return -EIO;
            }
            remaining -= len;
      }

      submit_bio(bio);

      log_info(
          "Submitted read bio for device %u. Sector %llu - Data Size: %u\n",
          bdev->bd_dev, sector, bio_meta->size);

      return 0;
}

void preprocess_submit_bio(struct bio *bio) {
      dev_t dev;
      struct write_metadata wm;

      struct read_bio_metadata *bio_meta = NULL;
      struct page **pages = NULL;
      int i = 0;

      int ret;

      // Ensure we are in V2
      DEBUG_ASSERT(version == EXPERIMENTAL_V2);

      // Only intercept WRITE requests (REQ_OP_WRITE = 1)
      if (bio_op(bio) != REQ_OP_WRITE || !bio->bi_bdev)
            return;

      dev = bio->bi_bdev->bd_dev;
      wm.block = bio->bi_iter.bi_sector;

      // If device is not registered or has no active session, we simply skip it
      ret =
          rcu_compute_on_sdev(dev, (void *)&wm, record_block_on_write_callback);
      if (ret)
            return;

      bio_meta = kmalloc(sizeof(struct read_bio_metadata), GFP_ATOMIC);
      if (!bio_meta)
            return;

      unsigned int block_size = bdev_logical_block_size(bio->bi_bdev);
      unsigned int blocks =
          max(DIV_ROUND_UP(bio->bi_iter.bi_size, block_size), 1);
      unsigned int total_size = blocks * block_size;

      // Calculate number of pages needed
      bio_meta->nr_pages = DIV_ROUND_UP(total_size, PAGE_SIZE);
      bio_meta->size = total_size;

      // These pages will eventually be freed by the `read_endio` function
      pages =
          kmalloc_array(bio_meta->nr_pages, sizeof(struct page *), GFP_ATOMIC);
      if (!pages) {
            goto cleanup;
      }

      for (; i < bio_meta->nr_pages; i++) {
            pages[i] = alloc_page(GFP_ATOMIC | __GFP_ZERO);
            if (!pages[i]) {
                  goto cleanup;
            }
      }

      bio_meta->pages = pages;

      // Submit the read request
      ret = submit_read_bio(bio->bi_bdev, wm.block, bio_meta);
      if (ret) {
            goto cleanup;
      }

      return;

cleanup:
      log_err("Submit bio preprocessing: error in memory allocation");
      while (--i >= 0)
            __free_page(pages[i]);
      if (pages) {
            kfree(pages);
      }
      if (bio_meta) {
            kfree(bio_meta);
      }
}

static struct kretprobe *retprobes[] = {&rp_mount, &rp_umount, &rp_vfs_write,
                                        &rp_kernel_write, &rp_sb_bread};

int register_my_kretprobes(void) {

      int i, ret;
      struct kretprobe *rp;

      for (i = 0; i < ARRAY_SIZE(retprobes); i++) {
            rp = retprobes[i];

            if (version == EXPERIMENTAL_V2 && rp == &rp_sb_bread) {
                  // Skip the sb_bread kretprobe in V2
                  continue;
            }

            ret = register_kretprobe(rp);
            if (ret) {
                  log_err("Failed to register kretprobe %s: %d\n",
                          rp->kp.symbol_name, ret);
                  return ret;
            }
            log_info("Registered kretprobe %s\n", rp->kp.symbol_name);
      }

      return 0;
}

void unregister_my_kretprobes(void) {
      int i;

      for (i = 0; i < ARRAY_SIZE(retprobes); i++) {

            if (version == EXPERIMENTAL_V2 && retprobes[i] == &rp_sb_bread) {
                  continue;
            }

            unregister_kretprobe(retprobes[i]);
            log_info("Unregistered kretprobe %s\n",
                     retprobes[i]->kp.symbol_name);
      }
}

int activate_snapshot(const char *dev_name, const char *passwd) {
      int error;

      // Verifies password
      if (!snapshot_auth_verify(passwd)) {
            log_err("Authentication failure during device activation\n");
            return -AUTHF;
      }

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

      int error;

      // Verifies password
      if (!snapshot_auth_verify(passwd)) {
            log_err("Authentication failure during device deactivation\n");
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
