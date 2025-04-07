#ifndef SNAPSHOT_IOCTL_H
#define SNAPSHOT_IOCTL_H

#define DEVICE_NAME "snapshot"
#define CLASS_NAME "snapdev"

#define SNAPSHOT_IOCTL_MAGIC 'S'
#define SNAP_ACTIVATE _IOW(SNAPSHOT_IOCTL_MAGIC, 1, struct snapshot_args)
#define SNAP_DEACTIVATE _IOW(SNAPSHOT_IOCTL_MAGIC, 2, struct snapshot_args)

int init_snapshot_control(void);

void cleanup_snapshot_control(void);

#endif