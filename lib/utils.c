#include <linux/buffer_head.h>
#include <linux/crypto.h>
#include <linux/err.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "../include/utils.h"

#define AUDIT if (1)

int derive_sha256(const u8 *preimage, size_t preimage_len, u8 *out) {
      struct crypto_shash *tfm;
      struct shash_desc *desc;
      int ret;

      tfm = crypto_alloc_shash("sha256", 0, 0);
      if (IS_ERR(tfm)) {
            AUDIT log_info("Could not allocate message digest "
                           "handle: %ld\n",
                           PTR_ERR(tfm));

            return PTR_ERR(tfm);
      }

      desc = kzalloc(sizeof(*desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
      if (!desc) {
            AUDIT log_info("Could not allocate memory for shash_desc\n");
            crypto_free_shash(tfm);
            return -ENOMEM;
      }
      desc->tfm = tfm;

      ret = crypto_shash_digest(desc, preimage, preimage_len, out);

      kfree(desc);
      crypto_free_shash(tfm);
      return ret;
}

int copy_params_from_user(const char __user *dev_name,
                          const char __user *passwd,
                          struct snapshot_args *args) {

      unsigned long dev_len, passw_len;

      dev_len = strnlen_user(dev_name, MAX_DEV_LEN);
      passw_len = strnlen_user(passwd, MAX_SECRET_LEN);

      if (dev_len == 0 || dev_len == MAX_DEV_LEN || passw_len == 0 ||
          passw_len == MAX_SECRET_LEN) {
            return -EFAULT;
      }

      if (copy_from_user(args->dev_name, dev_name, dev_len)) {
            return -EFAULT;
      }

      if (copy_from_user(args->passwd, passwd, passw_len)) {
            return -EFAULT;
      }

      return 0;
}

// All file systems that implement the bmap function are supported
// (https://elixir.bootlin.com/linux/v6.8/source/fs/inode.c#L1771)
inline int get_block(struct inode *inode, loff_t offset, u64 *block) {
      *block = offset / inode->i_sb->s_blocksize;

      return bmap(inode, block);
}

void path_to_safe_name(char *pathname) {
      int i;

      for (i = 0; i < strlen(pathname); i++)
            pathname[i] = (pathname[i] == '/') ? '_' : pathname[i];

      pathname[i] = '\0';
}

u32 compute_checksum(const char *data, size_t size, u32 seed) {
      return crc32(seed ^ 0xffffffff, (const unsigned char *)data, size) ^
             0xffffffff;
}

u32 hash_str(const char *str, int bits) {
      u32 hash = jhash(str, strlen(str), 0);

      // Ensure bits is in [1, 32]
      if (bits >= 32)
            return hash;
      return hash & ((1U << bits) - 1);
}

int compress_data(struct crypto_comp *comp, const char *data, size_t data_size,
                  struct compressed_data *out) {

      int ret;

      if (!data || !out)
            return -EINVAL;

      ret = crypto_comp_compress(comp, data, data_size, out->data,
                                 (unsigned int *)&out->size);
      if (ret) {
            return ret;
      }

      return 0;
}
