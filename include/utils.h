#ifndef _UTILS_H_

#define _UTILS_H_

#include <crypto/hash.h>
#include <linux/err.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/types.h>

#define MAX_SECRET_LEN 64
#define MAX_DEV_PATH 1024

typedef struct copied_params {
      char dev_name[MAX_DEV_PATH];
      char passwd[MAX_SECRET_LEN];
} copied_params_t;

#define log_info(fmt, ...)                                                     \
      printk(KERN_INFO "%s: " fmt, THIS_MODULE->name, ##__VA_ARGS__)

#define log_err(fmt, ...)                                                      \
      printk(KERN_ERR "%s: " fmt, THIS_MODULE->name, ##__VA_ARGS__)

int derive_sha256(const u8 *preimage, size_t preimage_len, unsigned char *out);

int copy_params_from_user(const char __user *dev_name,
                          const char __user *passwd, copied_params_t *params);

#endif