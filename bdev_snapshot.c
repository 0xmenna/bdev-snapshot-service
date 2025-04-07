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
#include "include/scinstall.h"
#include "include/snapshot.h"
#include "include/utils.h"

#define MODNAME "BDEV_SNAPSHOT"

#define AUDIT if (1)

// Module parameters

unsigned long the_syscall_table = 0x0;
module_param(the_syscall_table, ulong, 0660);
MODULE_PARM_DESC(the_syscall_table, "The syscall table address");

static u8 the_snapshot_secret[MAX_SECRET_LEN];
module_param_string(the_snapshot_secret, the_snapshot_secret, MAX_SECRET_LEN,
                    0);
MODULE_PARM_DESC(the_snapshot_secret,
                 "The snapshot secret used for the authentication of the "
                 "snapshot service. As soon "
                 "as its digest is stored, it will be wiped out");

static int __init bdev_snapshot_init(void) {
      int error;

      init_devices();

      // Initialize the snapshot authentication subsystem
      error = snapshot_auth_init(the_snapshot_secret);
      if (error) {
            return error;
      }
      // Wipe the plain text password
      memzero_explicit(the_snapshot_secret, MAX_SECRET_LEN);
      AUDIT log_info(
          "Snapshot authentication subsystem was initialized succesfully and "
          "the plain-text password cleared out\n");

      // Initialize the snapshot directory
      error = init_snapshot_path();
      if (error) {
            return error;
      }

      error = register_my_kretprobes();
      if (error) {
            return error;
      }

      return install_syscalls(the_syscall_table);
}

static void __exit bdev_snapshot_exit(void) {

      unregister_my_kretprobes();

      put_snapshot_path();

      uninstall_syscalls(the_syscall_table);
}

module_init(bdev_snapshot_init);
module_exit(bdev_snapshot_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Emanuele Valzano <emanuele.valzano@proton.me>");
MODULE_DESCRIPTION("A block device snapshot service");