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

#include "include/auth.h"
#include "include/ioctl.h"
#include "include/scinstall.h"
#include "include/snapshot.h"
#include "include/utils.h"

#define MODNAME "BDEV_SNAPSHOT"

#define AUDIT if (1)

// Module parameters

// If no syscall support is needed just leave the syscall table address to 0x0
unsigned long the_syscall_table = 0x0;
module_param(the_syscall_table, ulong, 0660);
MODULE_PARM_DESC(the_syscall_table, "The syscall table address");

static bool snapshot_ioctl = true;
module_param(snapshot_ioctl, bool, 0660);
MODULE_PARM_DESC(
    snapshot_ioctl,
    "Enable or disable ioctl as an interface for the snapshot service");

static u8 the_snapshot_secret[MAX_SECRET_LEN];
module_param_string(the_snapshot_secret, the_snapshot_secret, MAX_SECRET_LEN,
                    0);
MODULE_PARM_DESC(the_snapshot_secret,
                 "The snapshot secret used for authentication. As soon "
                 "as its digest is stored, it will be wiped out");

static int wq_max_active = 1;
module_param(wq_max_active, int, 0660);
MODULE_PARM_DESC(wq_max_active,
                 "The maximum number of execution contexts per CPU which can "
                 "be assigned to the work items of the workqueue.");

static int version = V1;
module_param(version, int, 0660);
MODULE_PARM_DESC(
    version,
    "Subsystem version. "
    "V1: The subsystem is configured to work well with the testing "
    "singlefilefs. "
    "V2: This is experimental and designed to work with other FS as well.");

static int __init bdev_snapshot_init(void) {
      int ret;

      if (version != V1 && version != EXPERIMENTAL_V2) {
            log_err("Invalid subsystem version. Supported versions: V1: %d, "
                    "EXPERIMENTAL_V2: %d\n",
                    V1, EXPERIMENTAL_V2);
            return -1;
      }

      init_devices(version);

      // Initialize the snapshot authentication subsystem
      ret = snapshot_auth_init(the_snapshot_secret);
      if (ret)
            return ret;

      // Wipe the plain text password
      memzero_explicit(the_snapshot_secret, MAX_SECRET_LEN);
      AUDIT log_info(
          "Snapshot authentication subsystem was initialized succesfully and "
          "the plain-text password cleared out\n");

      // Initialize the snapshot directory
      ret = init_snapshot_path();
      if (ret)
            return ret;

      ret = init_work_queue(wq_max_active);
      if (ret)
            return ret;

      ret = register_my_kretprobes();
      if (ret)
            return ret;

      if (snapshot_ioctl) {
            ret = init_snapshot_control();
            if (ret)
                  return ret;
      }

      if (the_syscall_table != 0x0)
            ret = install_syscalls(the_syscall_table);

      return ret;
}

static void __exit bdev_snapshot_exit(void) {
      if (the_syscall_table != 0x0)
            uninstall_syscalls(the_syscall_table);

      if (snapshot_ioctl)
            cleanup_snapshot_control();

      unregister_my_kretprobes();

      cleanup_work_queue();

      put_snapshot_path();
}

module_init(bdev_snapshot_init);
module_exit(bdev_snapshot_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Emanuele Valzano <emanuele.valzano@proton.me>");
MODULE_DESCRIPTION("A block device snapshot service");