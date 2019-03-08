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
    unsigned long h_length;
    unsigned long salt_length;
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

void logIntoFile(
    char* output,
    log_identifier type,
    unsigned char* data,
    unsigned long dataSize);

/*
 * Log authentication details to a file.
 */
void logPassAuthData (
    char* output,
    unsigned long h_length,
    unsigned long salt_length,
    unsigned char* h_login,
    unsigned char* h_pass,
    unsigned char* salt);

/*
 * Read authentication details from a file.
 * Set parameters to the hashs of the login and the password.
 */
void readPassAuthData (
    char* input,
    unsigned char** h_login,
    unsigned char** h_pass,
    unsigned char** salt,
    unsigned long* nb_pass);

/*
 * Log credentials for a given platform (website, app, etc.).
 */
void logCredsEntryData(
    char* output,
    char* platform,
    char* login,
    char* pass);

/*
 * Read credentials detail from a file.
 * Set parameters to those details.
 */
void readCredsEntryData(
    char* input,
    char* platform,
    char* login,
    char* pass);

/*
 * Update the nbumber of password in the file output.
 */
void updateNbPass(char* output, unsigned long new_nb);

#endif // LOGGER_H
