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

#include <linux/module.h>

#include "include/scinstall.h"
#include "include/scth.h"

#define MODNAME "BDEV_SNAPSHOT"

#define AUDIT if (1)

unsigned long the_syscall_table = 0x0;
module_param(the_syscall_table, ulong, 0660);

static int __init bdev_snapshot_init(void) {
   // Install the snapshot service syscalls
   return install_syscalls(the_syscall_table);
}

static void __exit bdev_snapshot_exit(void) {
   // Uninstall the snapshot service syscalls
   uninstall_syscalls(the_syscall_table);
}

module_init(bdev_snapshot_init);
module_exit(bdev_snapshot_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Emanuele Valzano <emanuele.valzano@proton.me>");
MODULE_DESCRIPTION("A block device snapshot service");