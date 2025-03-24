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

#include "../include/scinstall.h"
#include "../include/scth.h"
#include "../include/snapshot.h"
#include "../include/utils.h"

#define LIBNAME "SCINSTALL"

#define AUDIT if (1)

static unsigned long the_ni_syscall;

// Define two entries for the snapshot APIs
static unsigned long new_sys_call_array[] = {0x0, 0x0};
#define HACKED_ENTRIES (int)(sizeof(new_sys_call_array) / sizeof(unsigned long))
static int restore[HACKED_ENTRIES] = {[0 ...(HACKED_ENTRIES - 1)] - 1};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
__SYSCALL_DEFINEx(2, _activate_snapshot, char __user *, dev_name, char __user *,
                  passwd) {
#else
asmlinkage long sys_activate_snapshot(char __user *dev_name,
                                      char __user *passwd) {
#endif

      copied_params_t params;
      int error;

      error = copy_params_from_user(dev_name, passwd, &params);
      if (error) {
            return error;
      }

      return activate_snapshot(params.dev_name, params.passwd);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
long sys_activate_snapshot = (unsigned long)__x64_sys_activate_snapshot;
#else
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
__SYSCALL_DEFINEx(2, _deactivate_snapshot, char __user *, dev_name,
                  char __user *, passwd) {
#else
asmlinkage long sys_deactivate_snapshot(char __user *dev_name,
                                        char __user *passwd) {
#endif
      copied_params_t params;
      int error;

      error = copy_params_from_user(dev_name, passwd, &params);
      if (error) {
            return error;
      }

      return deactivate_snapshot(params.dev_name, params.passwd);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
long sys_deactivate_snapshot = (unsigned long)__x64_sys_deactivate_snapshot;
#else
#endif

int install_syscalls(unsigned long the_syscall_table) {
      int i;
      int ret;

      if (the_syscall_table == 0x0) {
            log_info("Cannot manage sys_call_table address set to 0x0\n");
            return -1;
      }

      AUDIT log_info("Initializing - hacked entries %d\n", HACKED_ENTRIES);

      new_sys_call_array[0] = (unsigned long)sys_activate_snapshot;
      new_sys_call_array[1] = (unsigned long)sys_deactivate_snapshot;

      ret = get_entries(restore, HACKED_ENTRIES,
                        (unsigned long *)the_syscall_table, &the_ni_syscall);

      if (ret != HACKED_ENTRIES) {
            log_info("Could not hack %d entries (just %d)\n", HACKED_ENTRIES,
                     ret);

            return -1;
      }

      unprotect_memory();
      for (i = 0; i < HACKED_ENTRIES; i++) {
            ((unsigned long *)the_syscall_table)[restore[i]] =
                (unsigned long)new_sys_call_array[i];
      }
      protect_memory();

      log_info("All new system-calls correctly installed on sys-call table\n");

      return 0;
}

void uninstall_syscalls(unsigned long the_syscall_table) {
      int i;

      log_info("Shutting down\n");

      unprotect_memory();
      for (i = 0; i < HACKED_ENTRIES; i++) {
            ((unsigned long *)the_syscall_table)[restore[i]] = the_ni_syscall;
      }
      protect_memory();

      log_info("sys-call table restored to its original content\n");
}
