#ifndef UTILS_H
#define UTILS_H

#include <crypto/hash.h>
#include <linux/crc32.h>
#include <linux/err.h>
#include <linux/jhash.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/root_dev.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>

#define MAX_SECRET_LEN 64
#define MAX_DEV_LEN 1024

// See https://elixir.bootlin.com/linux/v6.8/source/drivers/block/loop.c#L50
struct loop_device_meta {
      int lo_number;
      loff_t lo_offset;
      loff_t lo_sizelimit;
      int lo_flags;
      char lo_file_name[64];

      struct file *lo_backing_file;
};

struct snapshot_args {
      char dev_name[MAX_DEV_LEN];
      char passwd[MAX_SECRET_LEN];
};

#define log_info(fmt, ...)                                                     \
      printk(KERN_INFO "%s: " fmt, THIS_MODULE->name, ##__VA_ARGS__)

#define log_err(fmt, ...)                                                      \
      printk(KERN_ERR "%s: " fmt, THIS_MODULE->name, ##__VA_ARGS__)

int derive_sha256(const u8 *preimage, size_t preimage_len, unsigned char *out);

int copy_params_from_user(const char __user *dev_name,
                          const char __user *passwd,
                          struct snapshot_args *args);

// Get the physical block number on the device based on the offset and the inode
// of a given file
inline int get_block(struct inode *inode, loff_t offset, sector_t *block);

void path_to_safe_name(const char *pathname, char *out_pathname, size_t len);

u32 compute_checksum(const char *data, size_t size, u32 seed);

u32 hash_str(const char *str, int bits);

#endif