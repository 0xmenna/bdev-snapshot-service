#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define SLEEP 156
#define AWAKE 174
#define NUM_THREADS 4
#define DO_SLEEP (0);

int goto_sleep() { return syscall(SLEEP); }

int awake() { return syscall(AWAKE); }

void *worker(void *args) {
   bool do_sleep;
   int res;

   do_sleep = (bool)args;
   const char *syscall_name = do_sleep ? "SLEEP" : "AWAKE";

   if (do_sleep) {
      res = goto_sleep();
   } else {
      res = awake();
   }
   printf("%s return value:  %d\n", syscall_name, res);

   return NULL;
}

int main() {

   pthread_t tid;
   bool do_sleep = DO_SLEEP;
   int i;
   for (i = 0; i < NUM_THREADS; i++) {
      // call sleep by setting the worker input to true
      pthread_create(&tid, NULL, worker, (void *)do_sleep);
   }

   pause();
}