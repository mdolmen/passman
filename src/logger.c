#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

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
    unsigned long id,
    unsigned long h_length,
    unsigned char* h_login,
    unsigned char* h_pass)
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

    // Copy data
    log_data = utils_malloc((size_t)log_data_size);

    ((pass_auth_log*)log_data)->id = id;
    ((pass_auth_log*)log_data)->h_length = h_length;

    tmp = (unsigned char*) &((pass_auth_log*)log_data)->h_login;

    if (h_login != NULL) {
        memcpy(tmp, h_login, h_length);
        tmp += h_length;
    }
    if (h_pass != NULL) {
        memcpy(tmp, h_pass, h_length);
        tmp += h_length;
    }

    printf("log_data_size: %ld\n", log_data_size);
    logIntoFile(output, pass_auth_log_id, log_data, log_data_size);

    free(log_data);

    return;
}
