#ifndef PASSMAN_H
#define PASSMAN_H

#include <linux/limits.h>

#define LOGIN_PASS  1
#define LOGIN_KEY   2
#define SALT_SIZE   64

// uncomment to disable debug output
//#define PM_DEBUG_1

#define FREE(x) if(x) { free(x); x = NULL; }

typedef enum status {
    PM_SUCCESS,
    PM_FAILURE
} status_t;

typedef enum field {
    F_NB_PASS,
    F_ENTRIES_SIZE
} field_t;

/*
 * It is the place where we keep data in clear and where we do the modifcation
 * (edit, add, or delete entry) before encrypting and writing it to disk.
 */
typedef struct _log_info {
    unsigned char* buf;
    unsigned char* ptr;
    unsigned long size;
} log_info;

typedef struct _pm_user {
    unsigned short auth;
    char db[PATH_MAX];
    unsigned long nb_pass;
    unsigned long entries_total_size;
    unsigned char* iv;
    unsigned char* salt;
    char* login;
    char* pass;
} pm_user;

#endif // PASSMAN_h
