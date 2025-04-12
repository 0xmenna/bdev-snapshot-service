#ifndef SNAPSHOT_AUTH_H
#define SNAPSHOT_AUTH_H

bool snapshot_auth_verify(const char *passwd);
int snapshot_auth_init(const char *passwd);

#endif
