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
      // take command line arguments from program exe
      if (argc != 2) {
            printf("Usage: %s <activate|deactivate>\n", argv[0]);
            return -1;
      }

      if (strcmp(argv[1], "activate") == 0) {
            if (activate_snapshot() < 0) {
                  printf("activate_snapshot failed\n");
                  return -1;
            }
            printf("Snapshot activated\n");
      } else if (strcmp(argv[1], "deactivate") == 0) {
            if (deactivate_snapshot() < 0) {
                  printf("deactivate_snapshot failed\n");
                  return -1;
            }
            printf("Snapshot deactivated\n");
      }

      return 0;
}