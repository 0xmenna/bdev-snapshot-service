#ifndef SNAPSHOT_H
#define SNAPSHOT_H

/**
 * activate_snapshot - Activate the snapshot service.
 * @devname: Block device path or the path of device-file for loop devices.
 * @password: Snapshot service password.
 *
 * Returns 0 on success, negative on error.
 */
int sys_activate_snapshot(const char *devname, const char *password);

/**
 * deactivate_snapshot - Deactivate the snapshot service.
 * @devname: Block device path or the path of device-file for loop devices.
 * @password: Snapshot service password.
 *
 * Returns 0 on success, negative on error.
 */
int sys_deactivate_snapshot(const char *devname, const char *password);

#endif
