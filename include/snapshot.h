
#ifndef _SNAPSHOT_H_

#define _SNAPSHOT_H_

#include <linux/atomic.h>
#include <linux/blkdev.h>
#include <linux/hashtable.h>
#include <linux/jhash.h>
#include <linux/kfifo.h>
#include <linux/kthread.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/types.h>

#define MAX_DEV_NAME_LEN 64
#define MAX_PATH_LEN 256

/**
 * enum snapshot_state - Snapshot session states.
 * @SNAP_ACTIVE:    The session is active and logging modifications.
 * @SNAP_FINALIZED: The session has been finalized.
 */
enum snapshot_state {
   SNAP_ACTIVE,
   SNAP_FINALIZED,
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
   sector_t block_offset;
   void *orig_data;
   size_t data_size;
} blog_entry;

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

/**
 * locked_block - Identifies a "committed" block log entry that is expected to
 * be persisted.
 * @session_id:   Snapshot session id.
 * @block_offset: The block offset.
 * @hnode:       Hash list node for linking in the hash table.
 *
 */
typedef struct _committed_block {
   int session_id;
   sector_t block_offset;
   struct hlist_node hnode;
} committed_block;

/**
 * struct snapshot_session - Represents an active snapshot session.
 * @session_id:  Unique session identifier.
 * @dev_name:    Name of the block device (e.g., "/dev/sda1").
 * @mount_time:  Unix timestamp (u64) when the session was activated.
 * @snap_dir:    Snapshot directory path (e.g., "/snapshot/devname_timestamp").
 * @state:       Current state of the session.
 * @thread:      Pointer to the kernel thread handling deferred snapshot work.
 * @hnode:       Hash list node for insertion into the global session hash
 * table.
 *
 * This structure holds all metadata necessary to manage a snapshot session.
 */
typedef struct _snapshot_session {
   int session_id;
   char dev_name[MAX_DEV_NAME_LEN];
   u64 mount_timestamp;
   char snap_dir[MAX_PATH_LEN];
   enum snapshot_state state;
   struct hlist_node hnode;
} snapshot_session;

int activate_snapshot(char *dev_name, char *passwd);
int deactivate_snapshot(char *dev_name, char *passwd);

#endif
