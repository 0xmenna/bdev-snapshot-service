#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define ACTIVATE 156
#define DISACTIVATE 174

static const char *password = "Th3_Snapsh0t_s3cr3t";
static const char *dev_name = "/dev/loop0";

static int activate_snapshot() { return syscall(ACTIVATE, dev_name, password); }

static int deactivate_snapshot() {
      return syscall(DISACTIVATE, dev_name, password);
}

int main() {
      int ret = activate_snapshot();
      if (ret < 0) {
            printf("Failed to activate snapshot: %d\n", ret);
            return -1;
      }

      printf("Snapshot activated\n");

      return 0;
}