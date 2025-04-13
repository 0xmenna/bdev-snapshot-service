#include "../include/snapshot.h"
#include "../include/auth.h"
#include "../include/hlist_rcu.h"
#include "../include/utils.h"

/* Root of the snapshot directory hierarchy */
static struct path snapshot_root_path;

/* Registered devices to the snapshot subsystem */
static struct snapshot_devices devices;

/* Per-CPU containers for active snapshot sessions. Each
    file container (one per cpu) can hold multiple block log entries */
static DEFINE_PER_CPU(struct hlist_head[1 << DEFAULT_HASH_BITS],
                      session_containers);

/* Workqueue for block log processing */
static struct workqueue_struct *block_log_wq;

void init_devices(void) { INIT_LIST_HEAD(&devices.fdevices); }

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

int init_work_queue(int max_active) {

      block_log_wq = alloc_workqueue("block_log_wq", WQ_UNBOUND, max_active);
      if (!block_log_wq) {
            return -ENOMEM;
      }
      return 0;
}

void cleanup_work_queue(void) {
      if (block_log_wq) {
            destroy_workqueue(block_log_wq);
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

      AUDIT log_info(
          "Callback free: loop backing file : %s , preempt_count : %d\n",
          fdev_name(fdev), preempt_count());

      dput(fdev->dentry);
      kfree(fdev);
}

/* Computes a function on a device-file. It looks up the device (via its dentry)
and calls the compute function on the found device (it follows RCU based
"locking"). */
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
      struct tm tm;
      char date_str[16]; // Format: YYYYMMDD_HHMMSS
      char snap_subdirname[1056];
      struct dentry *session_dentry = NULL;
      int ret;

      DEBUG_ASSERT(sdev != NULL && sdev->session != NULL);

      struct session_dentry_metadata *session_meta = arg;

      if (d_session(sdev->session)) {
            // Pass the path to the caller
            session_meta->dentry = sdev->session->snap_dentry;

            return 0;
      }

      // Format the timestamp into a date string: YYYYMMDD_HHMMSS
      time64_to_tm(sdev->session->mount_timestamp, 0, &tm);
      snprintf(date_str, sizeof(date_str), "%04ld%02ld%02ld_%02ld%02ld%02ld",
               tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour,
               tm.tm_min, tm.tm_sec);

      // Build the snapshot subdirectory name: "<dev_name>_<date_str>"
      snprintf(snap_subdirname, sizeof(snap_subdirname), "%s_%s",
               sdev_name(sdev), date_str);

      // Allocate a new dentry for the subdirectory
      session_dentry = d_alloc_name(snapshot_root_path.dentry, snap_subdirname);
      if (!session_dentry) {
            return -ENOMEM;
      }

      // Create the new directory
      ret = vfs_mkdir(snapshot_root_path.mnt->mnt_idmap,
                      d_inode(snapshot_root_path.dentry), session_dentry, 0660);
      if (ret) {
            if (ret == -EEXIST) {
                  // Other threads may have created the directory
                  ret = SNAPDIR_EXIST;
            }
            dput(session_dentry);

            return ret;
      }
      log_info("Created snapshot session directory: %s\n",
               session_dentry->d_name.name);

      // At this point, a single thread will execute this code for a given snap
      // device session, because the rest have failed to create the directory.
      snap_device *old_sdev = sdev;
      snap_device *new_sdev = kmalloc(sizeof(snap_device), GFP_KERNEL);
      if (!new_sdev) {
            dput(session_dentry);
            return -ENOMEM;
      }
      memcpy(new_sdev, old_sdev, sizeof(snap_device));

      new_sdev->session->snap_dentry = session_dentry;
      HLIST_RCU_REPLACE(old_sdev, new_sdev, devices.s_locks,
                        hash_dev(d_num(new_sdev)));

      // Pass the dentry to the caller: it will be the owner
      session_meta->dentry = new_sdev->session->snap_dentry;
      session_meta->is_owner = true;

      // This is to avoid freeing the session in the callback (since it is used
      // by the newer snap device)
      return FREE_SDEV_NO_SESSION;
}

/* Create a new snapshot session on mount of a registered snapshot device.
It is used within `rcu_compute_on_sdev`. */
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

/* Frees a per-cpu session container. It is executed asyncronously within
`on_each_cpu` function. */
static void free_percpu_session_container(void *info) {
      struct hlist_head *containers = this_cpu_ptr(session_containers);
      struct dentry *snap_dentry = info;

      u32 hash = hash_str(snap_dentry->d_name.name, DEFAULT_HASH_BITS);

      struct snap_session_container *entry;
      struct snap_session_container container_lookup = {
          .session_dentry = snap_dentry,
      };
      hlist_for_each_entry(entry, &containers[hash], hnode) {
            if (containers_cmp(entry, &container_lookup)) {
                  AUDIT log_info(
                      "Freeing session container. CPU: %d. Session: %s\n",
                      smp_processor_id(), entry->session_dentry->d_name.name);

                  hlist_del(&entry->hnode);

                  filp_close(entry->file, NULL);
                  dput(entry->session_dentry);

                  kfree(entry);
            }
      }
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
                  on_each_cpu(free_percpu_session_container,
                              session->snap_dentry, 0);
            }

            kfree(session);
      }

      kfree(sdev);
}

/* Callback to free a snapshot device without its session. Used within
 * `call_rcu` function. */
static inline void free_sdev_no_session_callback(struct rcu_head *rcu) {
      snap_device *sdev = container_of(rcu, snap_device, rcu);

      AUDIT log_info(
          "Callback free (no session): block device : %s, preempt_count : %d\n",
          sdev_name(sdev), preempt_count());

      kfree(sdev);
}

/* Callback to free a snapshot device and its session. Used within `call_rcu`
 * function. */
static inline void free_sdev_callback(struct rcu_head *rcu) {
      snap_device *sdev = container_of(rcu, snap_device, rcu);

      AUDIT log_info("Callback free: block device : %s, preempt_count : %d\n",
                     sdev_name(sdev), preempt_count());

      free_sdev(sdev);
}

/* Computes a function on a snapshot device. It looks up the device by its
`dev_t` identifier and calls the function following RCU based
"locking". */
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

static int get_dev_by_name(const char *dev_name, generic_dev_t *dev) {
      char pathname[MAX_DEV_LEN];
      struct inode *inode;
      struct path path;
      int error;

      int dev_len = strlen(dev_name);

      if (dev_len >= MAX_DEV_LEN || dev_len == 0) {
            return -EINVAL;
      }

      // Check if the device name is a path
      if (!strchr(dev_name, '/')) {
            const char *dev_path = "/dev/";
            int len = strlen(dev_path) + dev_len;
            if (len >= MAX_DEV_LEN) {
                  return -EINVAL;
            }
            snprintf(pathname, sizeof(pathname), "%s%s", dev_path, dev_name);
      } else {
            snprintf(pathname, sizeof(pathname), "%s", dev_name);
      }

      error = kern_path(pathname, LOOKUP_FOLLOW, &path);
      if (error) {
            return error;
      }
      inode = d_backing_inode(path.dentry);
      if (!S_ISBLK(inode->i_mode)) {
            // The provided `dev_name` represents the actual pathname associated
            // to the file managed as device-file (used for a loop device).
            char fdev_name[MAX_DEV_LEN];
            path_to_safe_name(pathname, fdev_name, strlen(pathname));
            file_dev_t fdev;
            INIT_FDEV(&fdev, path.dentry, fdev_name);
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
            char safe_name[MAX_DEV_LEN];

            path_to_safe_name(dev_name, safe_name, strlen(dev_name));

            INIT_SNAP_DEVICE(&tmp_sdev, dev.dev, safe_name);
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
                           dev.fdev.dentry->d_name.name);
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
            dput(dev.fdev.dentry);
            if (error) {
                  log_info(
                      "Unregister Device: Cannot remove loop backing file %s. "
                      "Error: %d\n",
                      fdev_name(&dev.fdev), error);
                  return error;
            }
      }

      return 0;
}

static struct snap_session_container *
create_snap_container(struct dentry *session_dentry, int cpu, bool is_owner) {
      struct snap_session_container *container = NULL;
      char container_fname[16];
      struct dentry *container_dentry = NULL;
      struct file *filp = NULL;
      int ret;

      snprintf(container_fname, sizeof(container_fname), "snap_c%d", cpu);

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

      container = alloc_session_container(session_dentry, filp);
      if (!container) {
            ret = -ENOMEM;
            goto out_err;
      }

      dput(container_dentry);

      if (!is_owner)
            // Take extra ref for non-owner CPUs
            dget(session_dentry);

      return container;

out_err:
      if (filp)
            filp_close(filp, NULL);
      if (container_dentry)
            dput(container_dentry);
      return ERR_PTR(ret);
}

static int make_snapshot(const char *session_name, struct file *container_file,
                         sector_t block_num, size_t data_size, char *bdata) {
      snap_block_header_t header;
      loff_t pos;
      ssize_t written;
      int ret;

      // Build the record header
      header.magic = SNAPSHOT_RECORD_MAGIC;
      header.block_number = block_num;
      header.data_size = data_size;

      u32 seed = hash_str(session_name, 32);
      header.checksum = compute_checksum(bdata, data_size, seed);

      pos = container_file->f_pos;

      // Write the header record
      written = kernel_write(container_file, &header, sizeof(header), pos);
      if (written != sizeof(header)) {
            return -EIO;
      }
      pos += written;

      // Write the block data
      written = kernel_write(container_file, bdata, data_size, pos);
      if (written != data_size) {
            return -EIO;
      }

      return 0;
}

static int process_block(blog_work *bwork) {
      dev_t dev;
      struct dentry *session_dentry;
      bool is_cpu_dentry_owner; // whether the CPU is the creator of the dentry
      struct snap_session_container *container;
      int ret;

      int cpu = smp_processor_id();

      dev = bwork->inode->i_sb->s_bdev->bd_dev;
      session_dentry = bwork->session_dentry;

      AUDIT log_info(
          "Processing block log work on CPU %d. Device: %d, Block: %d\n", cpu,
          dev, bwork->block);

      if (!session_dentry) {
            struct session_dentry_metadata session_meta = {
                .dentry = NULL,
                .is_owner = false,
            };
            ret = rcu_compute_on_sdev(dev, (void *)&session_meta,
                                      session_dentry_callback);
            if (ret) {
                  // If another worker created the snapshot directory
                  // concurrently, notify the caller to re-schedule the work.
                  if (ret == SNAPDIR_EXIST)
                        return RESCHED;
                  return ret;
            }

            session_dentry = session_meta.dentry;
            is_cpu_dentry_owner = session_meta.is_owner;
      }

      struct hlist_head *containers = this_cpu_ptr(session_containers);
      u32 hash = hash_str(session_dentry->d_name.name, DEFAULT_HASH_BITS);

      struct snap_session_container *entry;
      hlist_for_each_entry(entry, &containers[hash], hnode) {
            struct snap_session_container lookup_container = {
                .session_dentry = session_dentry,
            };

            if (containers_cmp(entry, &lookup_container)) {
                  container = entry;
                  goto make_snapshot;
            }
      }

      container =
          create_snap_container(session_dentry, cpu, is_cpu_dentry_owner);

      if (IS_ERR(container)) {
            ret = PTR_ERR(container);
            return ret;
      }

      hlist_add_head(&container->hnode, &containers[hash]);

      log_info("Created new session container on CPU %d. Session: %s\n", cpu,
               container->session_dentry->d_name.name);

make_snapshot:

      ret = make_snapshot(session_dentry->d_name.name, container->file,
                          bwork->block, bwork->data_size, bwork->orig_data);
      if (ret) {
            // No need to free the container since it could be used by later
            // snapshot operations. Free is demanded at the end of the session.
            return ret;
      }

      log_info("Snapshot done. CPU: %d, Session: %s, Block: %d", cpu,
               session_dentry->d_name.name, bwork->block);

      return 0;
}

/* Worker function that processes a block log work */
static void process_block_log(struct work_struct *work) {

      blog_work *bwork = container_of(work, struct block_log_work, work);
      int ret;

      ret = process_block(bwork);
      if (ret == RESCHED) {
            log_info("Rescheduling work. Device: %d, Block: %d\n",
                     bwork->inode->i_sb->s_bdev->bd_dev, bwork->block);

            queue_work(block_log_wq, &bwork->work);
      }

      // Final end of inode chain at step 4.
      free_blog_work(bwork);
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
                  // `fdevices` list. If it is we also get the device name
                  char *dev_name;
                  ret = rcu_compute_on_filedev(lo_backing_file->f_path.dentry,
                                               &dev_name,
                                               lo_backing_file_exists_callback);

                  if (ret) {
                        // The device-file is not registered
                        goto ret_handler;
                  }

                  // The device-file is registered. We can create a new snapshot
                  // device and activate a new session
                  snap_device tmp_sdev, *sdev;
                  INIT_SNAP_DEVICE(&tmp_sdev, bdev->bd_dev, dev_name);

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
                      sdev->dev, sdev_name(sdev));

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
            AUDIT log_info("umount_callback: Loop device %d unregistered with "
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

#ifdef CONFIG_X86_64
      sb = (struct super_block *)regs->di;
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

/* Callback function used to acquire the block number that will eventually be
overwritten. It adds the block number to the session
`reading_blocks` in order for the `sb_read` kretprobe to know which block to
copy. It adds the block also to the session `committed_blocks` to know which
subsequent write will not be captured because the block was already copied.
NOTE: As of now we support a single block write at a time. */
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

      INIT_SNAP_BLOCK(snap_block, wm->inode, block);
      u32 b_hash = hash_block(snap_block->block);

      // Add the block to the committed blocks (if it does not exist already)
      spin_lock(&session->cb_locks[b_hash]);

      struct snap_block *sb;
      hlist_for_each_entry(sb, &session->committed_blocks[b_hash], cb_hnode) {
            if (sb->block == snap_block->block) {
                  spin_unlock(&session->cb_locks[b_hash]);

                  AUDIT log_info("record_block_on_write_callback: Snapshot "
                                 "device : %s; Block %d is "
                                 "already committed\n",
                                 sdev_name(sdev), snap_block->block);

                  kfree(snap_block);
                  return -BLOCK_COMMITTED;
            }
      }

      hlist_add_head(&snap_block->cb_hnode, &session->committed_blocks[b_hash]);
      spin_unlock(&session->cb_locks[b_hash]);

      AUDIT log_info(
          "record_block_on_write_callback: Snapshot device : %s; Block %d "
          "committed\n",
          sdev_name(sdev), snap_block->block);

      // Add the block to the reading blocks
      spin_lock(&session->rb_locks[b_hash]);
      // inode chain step 2. The inode is held by the `snap_block` and stored in
      // the reading_blocks. The `snap_block` is also stored in the committed
      // list, but the lifecycle of the inode is only dependent to the
      // `rading_blocks` list.
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

      // This inode will traverse a chain. If it passes through all steps, it
      // will be released at the end of the deferred working process. If one of
      // the steps fails to go through, it will be released before.

      // inode chain step 1.
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
      // Reminder: we support a single block write at a time
      ret = rcu_compute_on_sdev(dev, &wm, record_block_on_write_callback);
      if (ret) {
            // End of inode chain at step 1.
            iput(inode);
      } else {
            out_meta->dev = dev;
            out_meta->block = wm.out_block;
      }

      return ret;
}

/* Callback that rollbacks the block commitment performed during a write
operation pre handler. It deletes an entry for both the `committed_blocks`
and the `reading blocks` lists. Finally, it frees the deleted node. */
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

      // the inode is released during this free.
      // End of inode chain at step 2.
      sb_free(sb);

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
            AUDIT log_info("vfs_write_ret_handler: Error writing to block "
                           "device %d. Rolling back committed block..\n",
                           meta->dev);
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

struct sb_read_kretprobe_metadata {
      sector_t block;

      struct inode *inode;
      struct dentry *session_dentry;
};

/* Callback to check if a read block matches the one in `arg`. If so, the caller
receives the inode of the file whose write triggered the block read and the
snapshot dentry, both needed for deferred work. */
static int try_read_block_callback(snap_device *sdev, void *arg) {
      struct sb_read_kretprobe_metadata *meta;
      snapshot_session *session;

      if (!sdev) {
            return -NOSDEV;
      }
      if (!sdev->session) {
            return -SDEVNOTACTIVE;
      }
      session = sdev->session;
      meta = (struct sb_read_kretprobe_metadata *)arg;

      u32 b_hash = hash_block(meta->block);

      // Check wheter there is any block to read and clear it if any
      spin_lock(&session->rb_locks[b_hash]);

      struct snap_block *sb;
      hlist_for_each_entry(sb, &session->reading_blocks[b_hash], rb_hnode) {
            if (sb->block == meta->block) {
                  AUDIT log_info("try_read_block_callback: Found reading block "
                                 "%d for device %s\n",
                                 sb->block, sdev_name(sdev));
                  hlist_del(&sb->rb_hnode);
                  spin_unlock(&session->rb_locks[b_hash]);

                  // Inform the caller about the inode of the file whose write
                  // operation triggered this block read.
                  // inode chain step 3.
                  meta->inode = sb->inode;
                  // The `snap_block` does not care about the inode anymore.
                  sb->inode = NULL;

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

static int sb_read_entry_handler(struct kretprobe_instance *ri,
                                 struct pt_regs *regs) {

      struct super_block *sb;
      struct sb_read_kretprobe_metadata *meta;
      sector_t block;
      dev_t dev;
      int ret;

#ifdef CONFIG_X86_64
      sb = (struct super_block *)regs->di;
      block = (sector_t)regs->dx;
      meta = (struct sb_read_kretprobe_metadata *)ri->data;

      if (!sb->s_bdev) {
            return -1;
      }
      dev = sb->s_bdev->bd_dev;

      // Check wheter to read the block or not.
      // If the block must be read, then consume the node from the session
      // reading block list
      meta->block = block;
      ret = rcu_compute_on_sdev(dev, (void *)meta, try_read_block_callback);
      if (ret) {
            // No need to copy the block: the device is unregistered, has no
            // active session, or the block is irrelevant to it.
            return -1;
      }

      DEBUG_ASSERT(dev == meta->inode->i_sb->s_bdev->bd_dev);

      // Execute the return handler: copy the read block and defer VFS-related
      // work.

      return 0;
#else
#error "Unsupported architecture"
#endif
}

// If this is executed, than we must copy the block and defer vfs related work
static int sb_read_ret_handler(struct kretprobe_instance *ri,
                               struct pt_regs *regs) {
      struct buffer_head *bh;
      struct sb_read_kretprobe_metadata *meta;
      // Log entry used to enqueue the copied block (used in deferred working).
      blog_work *bwork;
      char *bdata;

      bh = (struct buffer_head *)regs_return_value(regs);
      meta = (struct sb_read_kretprobe_metadata *)ri->data;

      if (!IS_ERR(bh)) {
            // Copy the block
            bdata = kmalloc(bh->b_size, GFP_ATOMIC);
            if (!bdata) {
                  // End of inode chain at step 3.
                  iput(meta->inode);
                  goto out;
            }
            memcpy(bdata, bh->b_data, bh->b_size);
            AUDIT log_info(
                "sb_read_ret_handler: Copied block %d from device %d\n",
                meta->block, meta->inode->i_sb->s_bdev);

            // Enqueue the block log work
            bwork = kmalloc(sizeof(blog_work), GFP_ATOMIC);
            if (!bwork) {
                  kfree(bdata);
                  // End of inode chain at step 3.
                  iput(meta->inode);
                  goto out;
            }
            INIT_BLOG_WORK(bwork, meta->session_dentry, meta->block, bdata,
                           bh->b_size, process_block_log);
            // inode chain step 4.
            // It will be the responsibility of the deferred worker to release
            // it.
            bwork->inode = meta->inode;

            queue_work(block_log_wq, &bwork->work);

            AUDIT log_info("sb_read_ret_handler: Snapshot work queued "
                           "succesfully for device %d\n",
                           meta->inode->i_sb->s_bdev);
      }

out:
      return 0;
}

static struct kretprobe rp_sb_read = {
    .kp.symbol_name = "sb_bread",
    .entry_handler = sb_read_entry_handler,
    .handler = sb_read_ret_handler,
    .data_size = sizeof(struct sb_read_kretprobe_metadata),
};

static struct kretprobe *retprobes[] = {&rp_mount, &rp_umount, &rp_vfs_write,
                                        &rp_sb_read};

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
