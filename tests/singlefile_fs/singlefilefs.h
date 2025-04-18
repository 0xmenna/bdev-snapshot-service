#ifndef _ONEFILEFS_H
#define _ONEFILEFS_H

#include <linux/fs.h>
#include <linux/types.h>

#define MOD_NAME "SINGLE FILE FS"

#define MAGIC 0x42424242
#define DEFAULT_BLOCK_SIZE 4096
#define SB_BLOCK_NUMBER 0
#define DEFAULT_FILE_INODE_BLOCK 1

#define FILENAME_MAXLEN 255

#define SINGLEFILEFS_ROOT_INODE_NUMBER 10
#define SINGLEFILEFS_FILE_INODE_NUMBER 1

#define SINGLEFILEFS_INODES_BLOCK_NUMBER 1

#define UNIQUE_FILE_NAME "the-file"

// inode definition
struct onefilefs_inode {
      mode_t mode; // not exploited
      uint64_t inode_no;
      uint64_t data_block_number; // not exploited

      union {
            uint64_t file_size;
            uint64_t dir_children_count;
      };
};

// superblock definition
struct onefilefs_sb_info {
      uint64_t version;
      uint64_t magic;
      uint64_t block_size;
      uint64_t inodes_count; // not exploited
      uint64_t free_blocks;  // not exploited
      uint64_t max_file_size;

      // padding to fit into a single block
      char padding[(4 * 1024) - (6 * sizeof(uint64_t))];
};

// file.c
extern const struct inode_operations onefilefs_inode_ops;
extern const struct file_operations onefilefs_file_operations;
extern const struct address_space_operations singlefilefs_aops;

// dir.c
extern const struct file_operations onefilefs_dir_operations;

#endif
