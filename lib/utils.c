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

      dev_len = strnlen_user(dev_name, MAX_DEV_PATH);
      passw_len = strnlen_user(passwd, MAX_SECRET_LEN);

      if (dev_len == 0 || dev_len == MAX_DEV_PATH || passw_len == 0 ||
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

#define DEFAULT_BLOCK_SIZE 4096

// As of now we support the singlefilefs, therefore we know that a
// physical block is given by: [ (offset / blocksize) + 2 ]
// TODO: It would be nice to support all file systems that use the bmap function
// (https://elixir.bootlin.com/linux/v6.8/source/fs/inode.c#L1771)
sector_t get_block(struct inode *inode, loff_t offset) {
      sector_t block = offset / DEFAULT_BLOCK_SIZE + 2;

      //     // This is equivalent to (offset / blocksize) + 2
      //     sector_t block = (offset >> inode->i_blkbits) + 2;

      return block;
}
