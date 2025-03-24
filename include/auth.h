#ifndef _SNAPSHOT_AUTH_H_
#define _SNAPSHOT_AUTH_H_

/**
 * snapshot_auth_verify - Verify the provided password against the stored
 * digest.
 * @passwd: Pointer to the plain-text password string to verify.
 *
 * Return: true if the password is valid, false if it is invalid.
 */
bool snapshot_auth_verify(const char *passwd);

/**
 * snapshot_auth_init - Initialize the snapshot authentication subsystem.
 * @passwd: Pointer to the plain-text password string used for initialization.
 *
 * Return: 0 on success, or a negative error code on failure.
 */
inline int snapshot_auth_init(const char *passwd);

#endif
