#ifndef SNAPSHOT_H
#define SNAPSHOT_H

#include <linux/atomic.h>
#include <linux/blkdev.h>
#include <linux/buffer_head.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/hashtable.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/jhash.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/kfifo.h>
#include <linux/kprobes.h>
#include <linux/kthread.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/namei.h>
#include <linux/percpu.h>
#include <linux/rculist.h>
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

#include "hlist_rcu.h"
#include "utils.h"

/* Snapshot subsystem internal error codes */
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
#define RESCHED 20

#define AUDIT if (1)
#define DEBUG_ASSERT(cond) BUG_ON(!(cond))

#define S_BLOCKS_HASH_BITS 12
#define DEFAULT_HASH_BITS 8

/* Magic identifier used in snapshot block records ('SNAP') */
#define SNAPSHOT_RECORD_MAGIC 0x534E4150

/**
 * struct snapshot_devices - Registry for snapshot devices
 * @sdevices:      Registered devices mapped to actual block devices
 * @s_locks:       Per-bucket locks for @sdevices
 * @fdevices:      Registered file-based devices
 * @f_lock:        Lock for @fdevices list
 *
 * A snapshot device is a registered block device in the snapshot subsystem.
 */
struct snapshot_devices {
      struct hlist_head sdevices[1 << DEFAULT_HASH_BITS];
      spinlock_t s_locks[1 << DEFAULT_HASH_BITS];
      struct list_head fdevices;
      spinlock_t f_lock;
};

/**
 * struct _file_dev - Device backed by a file
 * @dentry:        Associated dentry
 * @dev_name:      Device name string
 * @is_mapped:     True if this file is mapped to a snapshot device
 * @node:          List node
 * @rcu:           RCU callback for deferred free
 */
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

/**
 * generic_dev_t - Generic device wrapper for either block or file-backed dev
 */
typedef struct generic_dev {
      enum { BDEV, FDEV } type;
      union {
            dev_t dev;
            file_dev_t fdev;
      };
} generic_dev_t;

/**
 * struct snap_block - Tracked block modified during a snapshot session
 * @block:         Physical block number
 * @inode:         Inode of the file being modified: useful to avoid umouting
 * the fs
 * @cb_hnode:      Node for committed blocks
 * @rb_hnode:      Node for reading blocks
 */
struct snap_block {
      sector_t block;
      struct inode *inode;
      struct hlist_node cb_hnode;
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

/**
 * struct _snapshot_session - Represents a snapshot mount session
 * @mount_timestamp:   Timestamp of the session start
 * @snap_dentry:       Dentry for the snapshot session
 * @reading_blocks:    Blocks that must be read (by kretprobe of `sb_read`)
 * @rb_locks:          Per-bucket locks for reading_blocks
 * @committed_blocks:  Committed blocks: to avoid recopying a
 * @cb_locks:          Per-bucket locks for committed_blocks
 */
typedef struct _snapshot_session {
      u64 mount_timestamp;
      struct dentry *snap_dentry;
      struct hlist_head reading_blocks[1 << S_BLOCKS_HASH_BITS];
      spinlock_t rb_locks[1 << S_BLOCKS_HASH_BITS];
      struct hlist_head committed_blocks[1 << S_BLOCKS_HASH_BITS];
      spinlock_t cb_locks[1 << S_BLOCKS_HASH_BITS];
} snapshot_session;

static inline void init_snapshot_session(snapshot_session *snap_session,
                                         time64_t timestamp) {
      snap_session->snap_dentry = NULL;
      snap_session->mount_timestamp = timestamp;
}

static inline struct dentry *d_session(snapshot_session *session) {
      return session->snap_dentry;
}

/**
 * struct snap_session_container - Container for session resources
 * @session_dentry:    Dentry identifying the session
 * @file:              Open file for writing the block log
 * @hnode:             Hash node for lookup
 */
struct snap_session_container {
      struct dentry *session_dentry;
      struct file *file;
      struct hlist_node hnode;
};

static inline struct snap_session_container *
alloc_session_container(struct dentry *dentry, struct file *file) {
      struct snap_session_container *c;
      c = kmalloc(sizeof(struct snap_session_container), GFP_KERNEL);
      if (!c) {
            return NULL;
      }
      c->session_dentry = dentry;
      c->file = file;
      INIT_HLIST_NODE(&c->hnode);
      return c;
}

static inline void free_container(struct snap_session_container *container) {
      if (container->file) {
            filp_close(container->file, NULL);
      }
      if (container->session_dentry) {
            dput(container->session_dentry);
      }
      kfree(container);
}

static inline bool containers_cmp(struct snap_session_container *c1,
                                  struct snap_session_container *c2) {
      // There cannot be two different valid session dentries with the same name
      if (strcmp(c1->session_dentry->d_name.name,
                 c2->session_dentry->d_name.name) == 0) {
            return true;
      }
      return false;
}

/**
 * struct _snap_device - Represents a registered snapshot device
 * @dev:              Device number
 * @dev_name:         Device name string
 * @session:          Associated snapshot session (if any)
 * @hnode:            Hash node
 * @rcu:              RCU callback
 * @private_data:     Optional private data (useful to store the backing dentry
 * for device-files)
 */
typedef struct _snap_device {
      dev_t dev;
      char dev_name[MAX_DEV_LEN];
      snapshot_session *session;
      struct hlist_node hnode;
      struct rcu_head rcu;
      void *private_data;
} snap_device;

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

static inline dev_t d_num(snap_device *sdev) { return sdev->dev; }

static inline const char *sdev_name(snap_device *sdev) {
      return sdev->dev_name;
}

static inline u32 hash_dev(dev_t dev) {
      return hash_32(dev, DEFAULT_HASH_BITS);
}

/**
 * struct block_log_work - Work to log a block before overwrite
 * @session_dentry:    Dentry for the session
 * @inode:             Inode of the file being modifed
 * @block:             Block number
 * @orig_data:         Snapshot of block data
 * @data_size:         Size of data
 * @work:              Work item
 */
typedef struct block_log_work {
      struct dentry *session_dentry;
      struct inode *inode;
      sector_t block;
      char *orig_data;
      size_t data_size;
      struct work_struct work;
} blog_work;

static inline void INIT_BLOG_WORK(blog_work *work, struct dentry *dentry,
                                  sector_t block, char *bdata, size_t data_size,
                                  void (*work_f)(struct work_struct *)) {
      work->session_dentry = dentry;
      work->inode = NULL;
      work->block = block;
      work->orig_data = bdata;
      work->data_size = data_size;
      INIT_WORK(&work->work, work_f);
}

static inline void free_blog_work(blog_work *bwork) {
      if (bwork->orig_data) {
            kfree(bwork->orig_data);
      }
      if (bwork->inode) {
            iput(bwork->inode);
      }
      kfree(bwork);
}

/**
 * struct snapshot_block_header - Metadata header stored before block data
 * @magic:           Magic number for the record ('SNAP')
 * @block_number:    Block number
 * @data_size:       Size of the block data
 * @checksum:        Block checksum
 */
typedef struct snapshot_block_header {
      u32 magic;
      u64 block_number;
      u32 data_size;
      u32 checksum;
} snap_block_header_t;

int register_my_kretprobes(void);
void unregister_my_kretprobes(void);

int init_snapshot_path(void);
void put_snapshot_path(void);

inline void init_devices(void);

int init_work_queue(int max_active);
void cleanup_work_queue(void);

int activate_snapshot(const char *dev_name, const char *passwd);
int deactivate_snapshot(const char *dev_name, const char *passwd);

#endif
