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
#include <linux/sched.h>
#include <linux/signal.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/timer.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/wait.h>

#include "../include/snapshot.h"

#define LIBNAME "SNAPSHOT"

#define AUDIT if (1)

int activate_snapshot(char *dev_name, char *passwd) {

   AUDIT printk("%s: service not yet implemented\n", THIS_MODULE->name);

   return -1;
}

int deactivate_snapshot(char *dev_name, char *passwd) {

   AUDIT printk("%s: service not yet implemented\n", THIS_MODULE->name);

   return -1;
}