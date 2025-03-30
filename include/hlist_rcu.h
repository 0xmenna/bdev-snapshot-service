#ifndef _HLIST_RCU_H
#define _HLIST_RCU_H

#include <linux/hashtable.h>
#include <linux/jhash.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/spinlock.h>
#include <linux/types.h>

#define ASYNC

#define HLIST_RCU_READ_LOCK() rcu_read_lock()
#define HLIST_RCU_READ_UNLOCK() rcu_read_unlock()

#define HLIST_RCU_LOOKUP(key, hash_f, table, type, extract_key)                \
      ({                                                                       \
            type *__entry = NULL, *__found = NULL;                             \
            u32 __hash = hash_f(key);                                          \
            HLIST_RCU_READ_LOCK();                                             \
            hlist_for_each_entry_rcu(__entry, &((table)[__hash]), hnode) {     \
                  if (extract_key(__entry) == (key)) {                         \
                        __found = __entry;                                     \
                        break;                                                 \
                  }                                                            \
            }                                                                  \
            __found;                                                           \
      })

#define HLIST_RCU_REPLACE(old_obj, new_obj, lock_array, hash)                  \
      do {                                                                     \
            spin_lock(&(lock_array)[(hash)]);                                  \
            hlist_replace_rcu(&(old_obj)->hnode, &(new_obj)->hnode);           \
            spin_unlock(&(lock_array)[(hash)]);                                \
      } while (0)

#define HLIST_RCU_INSERT(obj, table, lock_array, hash)                         \
      do {                                                                     \
            spin_lock(&(lock_array)[(hash)]);                                  \
            hlist_add_tail_rcu(&(obj)->hnode, &table[hash]);                   \
            spin_unlock(&(lock_array)[(hash)]);                                \
      } while (0)

#define HLIST_RCU_REMOVE(obj, lock_array, hash)                                \
      do {                                                                     \
            spin_lock(&(lock_array)[(hash)]);                                  \
            hlist_del_rcu(&(obj)->hnode);                                      \
            spin_unlock(&(lock_array)[(hash)]);                                \
      } while (0)

#endif