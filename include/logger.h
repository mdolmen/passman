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

void logIntoFile(
    char* output,
    log_identifier type,
    unsigned char* data,
    unsigned long dataSize);

void logPassAuthData (
    char* output,
    unsigned long id,
    unsigned long h_length,
    unsigned char* h_login,
    unsigned char* h_pass);

#endif // LOGGER_H
