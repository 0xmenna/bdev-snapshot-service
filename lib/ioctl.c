#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/uaccess.h>

#include "../include/ioctl.h"
#include "../include/snapshot.h"
#include "../include/utils.h"

static dev_t dev_number;
static struct class *snapshot_class;
static struct cdev snapshot_cdev;

static long snapshot_ioctl(struct file *file, unsigned int cmd,
                           unsigned long arg) {

      struct snapshot_args args;

      if (copy_from_user(&args, (void __user *)arg, sizeof(args)))
            return -EFAULT;

      switch (cmd) {
      case SNAP_ACTIVATE:
            return activate_snapshot(args.dev_name, args.passwd);
      case SNAP_DEACTIVATE:
            return deactivate_snapshot(args.dev_name, args.passwd);
      default:
            return -EINVAL;
      }
}

static int snapshot_open(struct inode *inode, struct file *file) { return 0; }

static int snapshot_release(struct inode *inode, struct file *file) {
      return 0;
}

static const struct file_operations fops = {
    .owner = THIS_MODULE,
    .open = snapshot_open,
    .release = snapshot_release,
    .unlocked_ioctl = snapshot_ioctl,
};

int init_snapshot_control(void) {
      int ret;

      ret = alloc_chrdev_region(&dev_number, 0, 1, DEVICE_NAME);
      if (ret) {
            log_err("Failed to allocate chrdev region\n");
            return ret;
      }

      cdev_init(&snapshot_cdev, &fops);
      ret = cdev_add(&snapshot_cdev, dev_number, 1);
      if (ret) {
            log_err("Failed to add cdev\n");
            unregister_chrdev_region(dev_number, 1);
            return ret;
      }

      snapshot_class = class_create(CLASS_NAME);
      if (IS_ERR(snapshot_class)) {
            log_err("Failed to create class\n");
            cdev_del(&snapshot_cdev);
            unregister_chrdev_region(dev_number, 1);
            return PTR_ERR(snapshot_class);
      }

      if (device_create(snapshot_class, NULL, dev_number, NULL, DEVICE_NAME) ==
          NULL) {
            log_err("Failed to create device\n");
            class_destroy(snapshot_class);
            cdev_del(&snapshot_cdev);
            unregister_chrdev_region(dev_number, 1);
            return -ENOMEM;
      }

      log_info("Snapshot control interface loaded\n");
      return 0;
}

void cleanup_snapshot_control(void) {
      device_destroy(snapshot_class, dev_number);
      class_destroy(snapshot_class);
      cdev_del(&snapshot_cdev);
      unregister_chrdev_region(dev_number, 1);

      log_info("Snapshot device unloaded\n");
}