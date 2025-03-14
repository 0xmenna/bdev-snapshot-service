/*
 *
 * This is free software; you can redistribute it and/or modify it under the
 * terms of the GNU General Public License as published by the Free Software
 * Foundation; either version 3 of the License, or (at your option) any later
 * version.
 *
 * This module is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 */

#define EXPORT_SYMTAB
#include <asm/apic.h>
#include <asm/cacheflush.h>
#include <asm/io.h>
#include <asm/page.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/time.h>
#include <linux/version.h>
#include <linux/vmalloc.h>

#include "include/scth.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Emanuele Valzano <emanuele.valzano@proton.me>");
MODULE_DESCRIPTION("A block device snapshot service");

#define MODNAME "BDEV_SNAPSHOT"

#define AUDIT if (1)

unsigned long the_syscall_table = 0x0;
module_param(the_syscall_table, ulong, 0660);

unsigned long the_ni_syscall;

unsigned long new_sys_call_array[] = {0x0, 0x0};
#define HACKED_ENTRIES (int)(sizeof(new_sys_call_array) / sizeof(unsigned long))
int restore[HACKED_ENTRIES] = {[0 ...(HACKED_ENTRIES - 1)] - 1};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
__SYSCALL_DEFINEx(1, _testing_syscall, int, unused) {
#else
asmlinkage long sys_testing_syscall(int unused) {
#endif

   AUDIT
   printk("%s: just a testing syscall\n", MODNAME);

   return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
long sys_testing_syscall = (unsigned long)__x64_sys_testing_syscall;
#else
#endif

int init_module(void) {
   int i;
   int ret;

   if (the_syscall_table == 0x0) {
      printk("%s: cannot manage sys_call_table address set to 0x0\n", MODNAME);
      return -1;
   }

   AUDIT {
      printk("%s: initializing - hacked entries %d\n", MODNAME, HACKED_ENTRIES);
   }

   new_sys_call_array[0] = (unsigned long)sys_testing_syscall;

   ret = get_entries(restore, HACKED_ENTRIES,
                     (unsigned long *)the_syscall_table, &the_ni_syscall);

   if (ret != HACKED_ENTRIES) {
      printk("%s: could not hack %d entries (just %d)\n", MODNAME,
             HACKED_ENTRIES, ret);
      return -1;
   }

   unprotect_memory();

   for (i = 0; i < HACKED_ENTRIES; i++) {
      ((unsigned long *)the_syscall_table)[restore[i]] =
          (unsigned long)new_sys_call_array[i];
   }

   protect_memory();

   printk("%s: all new system-calls correctly installed on sys-call table\n",
          MODNAME);

   return 0;
}

void cleanup_module(void) {
   int i;

   printk("%s: shutting down\n", MODNAME);

   unprotect_memory();
   for (i = 0; i < HACKED_ENTRIES; i++) {
      ((unsigned long *)the_syscall_table)[restore[i]] = the_ni_syscall;
   }
   protect_memory();
   printk("%s: sys-call table restored to its original content\n", MODNAME);
}