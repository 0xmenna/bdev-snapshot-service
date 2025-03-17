#include "../include/utils.h"

#define AUDIT if (1)

int derive_sha256(const u8 *preimage, size_t preimage_len, u8 *out) {
   struct crypto_shash *tfm;
   struct shash_desc *desc;
   int ret;

   tfm = crypto_alloc_shash("sha256", 0, 0);
   if (IS_ERR(tfm)) {
      AUDIT log_info("Could not allocate message digest "
                     "handle: %ld",
                     PTR_ERR(tfm));

      return PTR_ERR(tfm);
   }

   desc = kzalloc(sizeof(*desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
   if (!desc) {
      AUDIT log_info("Could not allocate memory for shash_desc");
      crypto_free_shash(tfm);
      return -ENOMEM;
   }
   desc->tfm = tfm;

   ret = crypto_shash_digest(desc, preimage, preimage_len, out);

   kfree(desc);
   crypto_free_shash(tfm);
   return ret;
}
