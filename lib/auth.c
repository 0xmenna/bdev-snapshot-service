#include <crypto/hash.h>
#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/err.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/rwlock.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>

#include "../include/auth.h"
#include "../include/utils.h"

#define AUDIT if (1)

#define DIGEST_SIZE 32
#define SALT "sntslt"
#define SALT_SIZE 6
#define PRE_IMAGE_SIZE MAX_SECRET_LEN + SALT_SIZE

static u8 passwd_hash[DIGEST_SIZE];

static int derive_passwd_hash(const char *passwd, u8 *out) {
      int ret;
      // Compute preimage = password||salt
      u8 preimage[PRE_IMAGE_SIZE] = {0};

      memcpy(preimage, passwd, strlen(passwd));
      memcpy(preimage + strlen(passwd), SALT, SALT_SIZE);
      // Compute the sha256 digest
      ret = derive_sha256(preimage, PRE_IMAGE_SIZE, out);
      // Wipe the preimage buffer
      memzero_explicit(preimage, PRE_IMAGE_SIZE);

      return ret;
}

static inline bool consttime_memequal(const void *s1, const void *s2,
                                      size_t n) {
      const unsigned char *p1 = s1;
      const unsigned char *p2 = s2;
      unsigned int diff = 0;
      size_t i;

      for (i = 0; i < n; i++)
            diff |= p1[i] ^ p2[i];

      return (diff == 0) ? true : false;
}

bool snapshot_auth_verify(const char *passwd) {
      u8 computed_hash[DIGEST_SIZE];

      // Verify priviledges
      if (!capable(CAP_SYS_ADMIN)) {
            AUDIT log_err("Insufficient priviledges to verify the password\n");
            return false;
      }

      if (strlen(passwd) >= MAX_SECRET_LEN) {
            return false;
      }

      int ret = derive_passwd_hash(passwd, computed_hash);
      if (ret) {
            AUDIT log_info(
                "Password hash derivation was not executed succesfully\n");
            return false;
      }

      // We make a constant time check to NOT disclose any information about the
      // digest
      bool auth_success =
          consttime_memequal(computed_hash, passwd_hash, DIGEST_SIZE);

      return auth_success;
}

int snapshot_auth_init(const char *passwd) {
      if (strlen(passwd) >= MAX_SECRET_LEN) {
            return -EINVAL;
      }
      int ret = derive_passwd_hash(passwd, passwd_hash);

      return ret;
}
