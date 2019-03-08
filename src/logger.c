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
    puts("(debug) Writing to disk..");
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
    unsigned long iv_length,
    unsigned char* h_login,
    unsigned char* h_pass,
    unsigned char* salt)
{
    unsigned char *log_data = NULL, *tmp = NULL;
    unsigned long log_data_size = 0;

    // Count space only for fields that will be present for sure (even if ==
    // 0) in the structure
    log_data_size = sizeof(unsigned long) * 5 + iv_length;

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

    // nb_pass will be incremented as passwords get added
    ((pass_auth_log*)log_data)->nb_pass = 0;

    ((pass_auth_log*)log_data)->h_length = h_length;
    ((pass_auth_log*)log_data)->salt_length = salt_length;
    ((pass_auth_log*)log_data)->iv_length = iv_length;

    tmp = (unsigned char*) &((pass_auth_log*)log_data)->iv;

    // init the IV to 0 to make room for it in the file
    memset(tmp, '\0', iv_length);
    tmp += iv_length;

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
    unsigned char** iv,
    unsigned char** h_login,
    unsigned char** h_pass,
    unsigned char** salt,
    unsigned long* nb_pass)
{
    unsigned long log_type = 0, entry_size = 0;
    unsigned long size_entry_header = sizeof(unsigned long) * 2;
    unsigned long h_length = 0, salt_length = 0, iv_length = 0;
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

    // the first structure should always be an authentication one
    if ( log_type == pass_auth_log_id ) {
        // re-map with the full entry size (header + pass_auth_log)
        buffer = mmap(NULL, entry_size, PROT_READ, MAP_PRIVATE, fd, 0);
        if ( !buffer )
            return;

        // need for an intermediate pointer so we can free the whole mapped
        // memory afterwards
        tmp = buffer + size_entry_header;

        *nb_pass = ((pass_auth_log*)tmp)->nb_pass;
        h_length = ((pass_auth_log*)tmp)->h_length;
        salt_length = ((pass_auth_log*)tmp)->salt_length;
        iv_length = ((pass_auth_log*)tmp)->iv_length;

        tmp = &((pass_auth_log*)tmp)->iv;

        // read iv
        *iv = utils_malloc((size_t)iv_length);
        if (iv) {
            memcpy(*iv, tmp, iv_length);
            tmp += iv_length;
        }

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

    if (fd) close(fd);
    if (buffer) munmap(buffer, entry_size);
}

void logCredsEntryData(
    char* output,
    char* platform,
    char* login,
    char* pass)
{
    unsigned char *log_data = NULL, *tmp = NULL;
    unsigned long log_data_size = 0;
    unsigned long platform_length = 0, login_length = 0, pass_length = 0;

    // Count space only for fields that will be present for sure (even if ==
    // 0) in the structure
    log_data_size = sizeof(unsigned long) * 3;

    if (platform != NULL) {
        platform_length = strlen(platform);
        log_data_size += platform_length + 1;
    }
    if (login != NULL) {
        login_length = strlen(login);
        log_data_size += login_length + 1;
    }
    if (pass != NULL) {
        pass_length = strlen(pass);
        log_data_size += pass_length + 1;
    }

    // Copy data
    log_data = utils_malloc((size_t)log_data_size);

    ((creds_entry_log*)log_data)->platform_length = platform_length;
    ((creds_entry_log*)log_data)->login_length = login_length;
    ((creds_entry_log*)log_data)->pass_length = pass_length;

    tmp = (unsigned char*) &((creds_entry_log*)log_data)->platform;

    if (platform != NULL) {
        memcpy(tmp, platform, platform_length);
        tmp += platform_length + 1;
    }
    if (login != NULL) {
        memcpy(tmp, login, login_length);
        tmp += login_length + 1;
    }
    if (pass != NULL) {
        memcpy(tmp, pass, pass_length);
        tmp += pass_length + 1;
    }

#ifdef PM_DEBUG_1
    printf("(debug) log_data_size: %ld\n", log_data_size);
#endif
    
    updateMemberInFile(output, F_ENTRIES_SIZE, log_data_size);
    logIntoFile(output, creds_entry_log_id, log_data, log_data_size);

    free(log_data);

    return;
}

void updateMemberInFile(
    char* filename,
    field_t field,
    unsigned long new_value)
{
    unsigned long log_type = 0, entry_size = 0;
    unsigned long size_entry_header = sizeof(unsigned long) * 2;
    void* buffer = NULL, *tmp = NULL;
    int fd = 0;

    // map the file into memory so we can retrieve data by accessing structure
    // member
    fd = open((const char*)filename, O_RDWR);
    buffer = mmap(NULL, size_entry_header, PROT_READ, MAP_PRIVATE, fd, 0);
    if ( MAP_FAILED == buffer )
        return;

    // read entry header informations
    log_type = ((log_entry_header*)buffer)->logType;
    entry_size = ((log_entry_header*)buffer)->entrySize;
    munmap(buffer, size_entry_header);

    // the first structure should always be an authentication one
    if ( log_type == pass_auth_log_id ) {
        // re-map with the full entry size (header + pass_auth_log)
        // using MAP_SHARED so we can write to the file
        buffer = mmap(NULL, entry_size, PROT_READ | PROT_WRITE , MAP_SHARED, fd, 0);
        if ( !buffer )
            return;

        tmp = buffer + size_entry_header;

        switch (field) {
            case F_NB_PASS:
                ((pass_auth_log*)tmp)->nb_pass = new_value;
                break;
            case F_ENTRIES_SIZE:
                ((pass_auth_log*)tmp)->entries_total_size += new_value;
                break;
            default:
                break;
        }
    }

    if (fd) close(fd);
    if (buffer) munmap(buffer, entry_size);
}

void updateIVInFile(
    char* filename,
    unsigned char* iv,
    size_t iv_size)
{
    unsigned long log_type = 0, entry_size = 0;
    unsigned long size_entry_header = sizeof(unsigned long) * 2;
    void* buffer = NULL, *tmp = NULL;
    int fd = 0;

    // map the file into memory so we can retrieve data by accessing structure
    // member
    fd = open((const char*)filename, O_RDWR);
    buffer = mmap(NULL, size_entry_header, PROT_READ, MAP_PRIVATE, fd, 0);
    if ( MAP_FAILED == buffer )
        return;

    // read entry header informations
    log_type = ((log_entry_header*)buffer)->logType;
    entry_size = ((log_entry_header*)buffer)->entrySize;
    munmap(buffer, size_entry_header);

    // the first structure should always be an authentication one
    if ( log_type == pass_auth_log_id ) {
        // re-map with the full entry size (header + pass_auth_log)
        // using MAP_SHARED so we can write to the file
        buffer = mmap(NULL, entry_size, PROT_READ | PROT_WRITE , MAP_SHARED, fd, 0);
        if ( !buffer )
            return;

        tmp = buffer + size_entry_header;

        tmp = &((pass_auth_log*)tmp)->iv;
        memcpy(tmp, iv, iv_size);
    }

    if (fd) close(fd);
    if (buffer) munmap(buffer, entry_size);
}

/*
void readCredsEntryData(
    char* input,
    char** platform,
    char** login,
    char** pass)
{
    unsigned long log_type = 0, entry_size = 0;
    unsigned long size_entry_header = sizeof(unsigned long) * 2;
    unsigned long platform_length = 0, login_length = 0, pass_length = 0;
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

    // the first structure should always be an authentication one
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
*/
