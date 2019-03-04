#ifndef PASSMAN_H
#define PASSMAN_H

#include <linux/limits.h>

#define LOGIN_PASS  1
#define LOGIN_KEY   2
#define SALT_SIZE   64

// uncomment to disable debug output
#define PM_DEBUG_1

typedef enum status {
    PM_SUCCESS,
    PM_FAILURE
} status_t;

typedef struct _pm_user {
    unsigned short auth;
    char db[PATH_MAX];
    unsigned char* salt;
    char* login;
    char* pass;
} pm_user;

#endif // PASSMAN_h
