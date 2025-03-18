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

#include "../include/snapshot.h"

#define LIBNAME "SNAPSHOT"

#define AUDIT if (1)

#define COMMITTED_HASH_BITS 16
#define SESSION_HASH_BITS 8

/* Global atomic counter for unique session IDs */
static atomic_t global_session_id;

/* Global hash table for snapshot sessions keyed by session_id */
static DECLARE_HASHTABLE(sessions, SESSION_HASH_BITS);

/* Committed block log entries hash table */
static DECLARE_HASHTABLE(committed_blocks, COMMITTED_HASH_BITS);

/*
 * Per-bucket spinlocks for the committed_blocks hash table.
 * There are 2^BLOCKED_HASH_BITS locks for each bucket.
 */
static spinlock_t committed_locks[1 << COMMITTED_HASH_BITS];

/* Per-CPU block log FIFO */
static DEFINE_PER_CPU(block_fifo, cpu_block_fifo);

int activate_snapshot(char *dev_name, char *passwd) {

   AUDIT printk("%s: service not yet implemented\n", THIS_MODULE->name);

   return -1;
}

int deactivate_snapshot(char *dev_name, char *passwd) {

   AUDIT printk("%s: service not yet implemented\n", THIS_MODULE->name);

   return -1;
}

#endif