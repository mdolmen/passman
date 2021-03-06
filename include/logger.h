#ifndef LOGGER_H
#define LOGGER_H

#define INIT_BUFFER_SIZE 0x200

typedef enum _log_identifier {
    pass_auth_log_id = 1,
    creds_entry_log_id
} log_identifier;

typedef struct _log_entry_header {
    unsigned long logType;
    unsigned long entrySize;
} log_entry_header;

typedef struct _pass_auth_log {
    unsigned long nb_pass;
    unsigned long entries_total_size;
    unsigned long h_length;
    unsigned long salt_length;
    unsigned long iv_length;
    unsigned char* iv;
    unsigned char* h_login;
    unsigned char* h_pass;
    unsigned char* salt;
} pass_auth_log;

typedef struct _creds_entry_log {
    unsigned long platform_length;
    unsigned long login_length;
    unsigned long pass_length;
    unsigned char* platform;
    unsigned char* login;
    unsigned char* pass;
} creds_entry_log;

void logIntoBuf(
    unsigned short add_header,
    log_info* log_buffer,
    log_identifier type,
    unsigned char* data,
    unsigned long dataSize);

/*
 * Write data to a file on disk.
 */
void flushToFile(log_info* log_buffer, char* output);

/*
 * Log authentication details to a file.
 */
void logPassAuthData (
    log_info* log_buffer,
    char* output,
    unsigned long h_length,
    unsigned long salt_length,
    unsigned long iv_length,
    unsigned char* h_login,
    unsigned char* h_pass,
    unsigned char* salt);

/*
 * Read authentication details from a file.
 * Set parameters to the hashs of the login and the password.
 */
void readPassAuthData (
    char* input,
    unsigned char** iv,
    unsigned char** h_login,
    unsigned char** h_pass,
    unsigned char** salt,
    unsigned long* nb_pass,
    unsigned long* entries_total_size);

/*
 * Log credentials for a given platform (website, app, etc.).
 */
void logCredsEntryData(
    log_info* log_buffer,
    char* output,
    char* platform,
    char* login,
    char* pass);

/*
 * Read credentials detail from a file.
 * Set parameters to those details.
 */
void readCredsEntryData(log_info* log_buffer, char* input);

/*
 * Update a member of a pass_auth_data structure in the user's file.
 */
void updateMemberInFile(
    char* output,
    field_t field,
    unsigned long new_value);

/*
 * Update the IV in the user's file.
 */
void updateIVInFile(
    char* filename,
    unsigned char* iv,
    size_t iv_size);

#endif // LOGGER_H
