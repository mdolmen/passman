#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include <sys/mman.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "passman.h"
#include "logger.h"
#include "utils.h"

void logIntoFile(char* output, log_identifier type, unsigned char* data, unsigned long dataSize)
{
    FILE* fHandle = NULL;
    char* logBuffer = NULL;
    unsigned long logBufferSize = 0;

    if ( !data || !output )
        return;

    fHandle = fopen(output, "ab");
    if ( !fHandle )
        return;

    logBufferSize = dataSize + sizeof(log_entry_header);

    logBuffer = utils_malloc((size_t)logBufferSize);

    // Log into the buffer
    ((log_entry_header*)logBuffer)->logType = (unsigned long)type;
    ((log_entry_header*)logBuffer)->entrySize = logBufferSize;
    memcpy(logBuffer + sizeof(log_entry_header), data, dataSize);

#ifdef PM_DEBUG_1
    puts("[+] Writing to disk..");
#endif

    // Write on disk
    fwrite(logBuffer, logBufferSize, sizeof(char), fHandle);
    fclose(fHandle);
    
    if ( logBuffer ) {
        free(logBuffer); logBuffer = NULL;
    }

    return;
}

void logPassAuthData (
    char* output,
    unsigned long h_length,
    unsigned long salt_length,
    unsigned char* h_login,
    unsigned char* h_pass,
    unsigned char* salt)
{
    unsigned char *log_data = NULL, *tmp = NULL;
    unsigned long log_data_size = 0;

    // Count space only for fields that will be present for sure (even if ==
    // 0) in the structure
    log_data_size = sizeof(unsigned long) * 2;

    if (h_login != NULL) {
        log_data_size += h_length;
    }
    if (h_pass != NULL) {
        log_data_size += h_length;
    }
    if (salt != NULL) {
        log_data_size += salt_length;
    }

    // Copy data
    log_data = utils_malloc((size_t)log_data_size);

    ((pass_auth_log*)log_data)->h_length = h_length;
    ((pass_auth_log*)log_data)->salt_length = salt_length;

    tmp = (unsigned char*) &((pass_auth_log*)log_data)->h_login;

    if (h_login != NULL) {
        memcpy(tmp, h_login, h_length);
        tmp += h_length;
    }
    if (h_pass != NULL) {
        memcpy(tmp, h_pass, h_length);
        tmp += h_length;
    }
    if (salt != NULL) {
        memcpy(tmp, salt, salt_length);
        tmp += salt_length;
    }

#ifdef PM_DEBUG_1
    printf("(debug) log_data_size: %ld\n", log_data_size);
#endif
    logIntoFile(output, pass_auth_log_id, log_data, log_data_size);

    free(log_data);

    return;
}

void readPassAuthData (
    char* input,
    unsigned char** h_login,
    unsigned char** h_pass,
    unsigned char** salt)
{
    unsigned long log_type = 0, entry_size = 0;
    unsigned long size_entry_header = sizeof(unsigned long) * 2;
    unsigned long h_length = 0, salt_length = 0;;
    void* buffer = NULL, *tmp = NULL;
    int fd = 0;

    // map the file into memory so we can retrieve data by accessing structure
    // member
    fd = open((const char*)input, O_RDONLY);
    buffer = mmap(NULL, size_entry_header, PROT_READ, MAP_PRIVATE, fd, 0);
    if ( MAP_FAILED == buffer )
        return;

    // read entry header informations
    log_type = ((log_entry_header*)buffer)->logType;
    entry_size = ((log_entry_header*)buffer)->entrySize;
    munmap(buffer, size_entry_header);

    if ( log_type == pass_auth_log_id ) {
        // re-map with the full entry size (header + pass_auth_log)
        buffer = mmap(NULL, entry_size, PROT_READ, MAP_PRIVATE, fd, 0);
        if ( !buffer )
            return;

        // need for an intermediate pointer so we can free the whole mapped
        // memory afterwards
        tmp = buffer + size_entry_header;

        h_length = ((pass_auth_log*)tmp)->h_length;
        salt_length = ((pass_auth_log*)tmp)->salt_length;
        tmp = &((pass_auth_log*)tmp)->h_login;

        // read hash login
        *h_login = utils_malloc((size_t)h_length);
        if (h_login) {
            memcpy(*h_login, tmp, h_length);
            tmp += h_length;
        }

        // read hash password
        *h_pass = utils_malloc((size_t)h_length);
        if (h_pass) {
            memcpy(*h_pass, tmp, h_length);
            tmp += h_length;
        }

        // read salt
        *salt = utils_malloc((size_t)salt_length);
        if (salt)
            memcpy(*salt, tmp, salt_length);
    }

    if (buffer) munmap(buffer, entry_size);
}

void logCredsEntryData(
    char* output,
    unsigned long platform_length,
    unsigned long login_length,
    unsigned long pass_length,
    unsigned char* platform,
    unsigned char* login,
    unsigned char* pass)
{
    unsigned char *log_data = NULL, *tmp = NULL;
    unsigned long log_data_size = 0;

    // Count space only for fields that will be present for sure (even if ==
    // 0) in the structure
    log_data_size = sizeof(unsigned long) * 3;

    if (platform != NULL) {
        log_data_size += platform_length;
    }
    if (login != NULL) {
        log_data_size += login_length;
    }
    if (pass != NULL) {
        log_data_size += pass_length;
    }

    // Copy data
    log_data = utils_malloc((size_t)log_data_size);

    ((creds_entry_log*)log_data)->platform_length = platform_length;
    ((creds_entry_log*)log_data)->login_length = login_length;
    ((creds_entry_log*)log_data)->pass_length = pass_length;

    tmp = (unsigned char*) &((creds_entry_log*)log_data)->platform;

    if (platform != NULL) {
        memcpy(tmp, platform, platform_length);
        tmp += platform_length;
    }
    if (login != NULL) {
        memcpy(tmp, login, login_length);
        tmp += login_length;
    }
    if (pass != NULL) {
        memcpy(tmp, pass, pass_length);
        tmp += pass_length;
    }

#ifdef PM_DEBUG_1
    printf("(debug) log_data_size: %ld\n", log_data_size);
#endif
    logIntoFile(output, creds_entry_log_id, log_data, log_data_size);

    free(log_data);

    return;
}
