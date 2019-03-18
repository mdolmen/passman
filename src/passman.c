#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/limits.h>
#include <sys/types.h>
#include <dirent.h>
#include <signal.h>

#include <crypto_hash.h>
#include <crypto_verify_32.h>
#include <crypto_stream.h>
#include <randombytes.h>

#include "passman.h"
#include "io.h"
#include "logger.h"
#include "utils.h"

static volatile short is_running = 1;

void sigint_handler(int signum)
{
    is_running = 0;
}

/*
 * Allows a user to connect and open up his file.
 */
status_t pm_login(pm_user* user, unsigned short method)
{
    status_t status = PM_SUCCESS;
    DIR* directory = NULL;
    struct dirent* entry = NULL;
    char input[PATH_MAX] = { '\0' };
    unsigned char h_ulogin[crypto_hash_BYTES] = { '\0' };
    unsigned char h_upass[crypto_hash_BYTES] = { '\0' };
    unsigned char* h_login = NULL, *h_pass = NULL;
    short cmp = 0;

    if (LOGIN_PASS == method) {
        // take user input
        printf("Login: ");
        user->login = io_get_string(BUF_SIZE);
        printf("Password: ");
        user->pass = io_get_string(BUF_SIZE);

        // hash (sha512) login and pass
        if ( crypto_hash(h_ulogin, (const unsigned char*)user->login, (unsigned long long)strlen(user->login)) != 0 ) {
            perror("crypto_hash");
            status = PM_FAILURE;
            goto exit;
        }
        if ( crypto_hash(h_upass, (const unsigned char*)user->pass, (unsigned long long)strlen(user->pass)) != 0 ) {
            perror("crypto_hash");
            status = PM_FAILURE;
            goto exit;
        }

        directory = opendir("data/");

        // browse files to see if there is a user that correspond to the given
        // credentials
        if (directory) {
            while ( (entry = readdir(directory)) && !(user->auth) ) {
                // DT_REG : entry is a regular file
                if (DT_REG == entry->d_type) {
                    // read data from binary file
                    snprintf(input, PATH_MAX, "data/%s", entry->d_name);
                    readPassAuthData(
                        input,
                        &user->iv,
                        &h_login, &h_pass, &(user->salt),
                        &user->nb_pass, &user->entries_total_size);

                    // compare
                    if (h_login && h_pass) {
                        cmp = 0;
                        cmp += crypto_verify_32(h_ulogin, h_login);
                        cmp += crypto_verify_32(h_ulogin+32, h_login+32);
                        cmp += crypto_verify_32(h_upass, h_pass);
                        cmp += crypto_verify_32(h_upass+32, h_pass+32);

                        if (cmp == 0) {
                            memcpy(user->db, input, strlen(input));
                            user->auth = 1;
                        }

                        FREE(h_login);
                        FREE(h_pass);
                        if ( !user->auth ) {
                            FREE(user->iv);
                            FREE(user->salt);
                            FREE(user->login);
                            FREE(user->pass);
                        }
                    }
                }
            }
        }

        closedir(directory);
    }
    else {
        // TODO : take user input (login + key path)
    }

exit:
    FREE(h_login);
    FREE(h_pass);

    return status;
}

/*
 * Create a new user and a create a file that will contains all of his
 * future passwords.
 */
status_t pm_create_user(log_info* log_buffer, pm_user* user, unsigned short method)
{
    status_t status = PM_SUCCESS;
    char new_file[PATH_MAX] = { '\0' };
    char* tmp = NULL;
    unsigned char h_login[crypto_hash_BYTES] = { '\0' };
    unsigned char h_pass[crypto_hash_BYTES] = { '\0' };
    unsigned char salt[SALT_SIZE] = { '\0' };
    unsigned long id = 0;
    unsigned short mismatch = 1;

    if (LOGIN_PASS == method) {
        // take user input
        printf("Login: ");
        user->login = io_get_string(BUF_SIZE);
        while (mismatch) {
            FREE(user->pass);
            FREE(tmp);

            printf("Password: ");
            user->pass = io_get_string(BUF_SIZE);
            printf("Confirm password: ");
            tmp = io_get_string(BUF_SIZE);
            putchar('\n');

            mismatch = strcmp(user->pass, tmp);
        }

        // generate a salt that will be used with the password to get a
        // symetric key ( hash(password+salt) = key ).
        randombytes(salt, SALT_SIZE);

        // hash (sha512) login and pass
        if ( crypto_hash(h_login, (const unsigned char*)user->login, (unsigned long long)strlen(user->login)) != 0 ) {
            perror("crypto_hash");
            status = PM_FAILURE;
            goto exit;
        }
        if ( crypto_hash(h_pass, (const unsigned char*)user->pass, (unsigned long long)strlen(user->pass)) != 0 ) {
            perror("crypto_hash");
            status = PM_FAILURE;
            goto exit;
        }

#ifdef PM_DEBUG_1
        printf("(debug) login: %s\n", user->login);
        for (int i = 0; i < crypto_hash_BYTES; i++) {
            printf("%02x", h_login[i]);
        }
        printf("\n(debug) pass: %s\n", user->pass);
        for (int i = 0; i < crypto_hash_BYTES; i++) {
            printf("%02x", h_pass[i]);
        }
        putchar('\n');
#endif

        // compute ID based on current number of user (1 per file in 'data/')
        id = utils_count_file_dir("data/") + 1;

        // write data to a new file
        snprintf(new_file, PATH_MAX, "data/%ld.pm", id);
        logPassAuthData(
            log_buffer,
            new_file,
            (unsigned long)crypto_hash_BYTES,
            SALT_SIZE,
            (unsigned long)crypto_stream_NONCEBYTES,
            h_login,
            h_pass,
            salt
        );
    }
    else {
        // TODO : take user input (login + key path)
    }

exit:
    FREE(user->login);
    FREE(user->pass);
    FREE(tmp);

    return status;
}

/*
 * Add a password in the file of the corresponding user.
 */
status_t pm_add_password(log_info* log_buffer, pm_user* user)
{
    char* platform = NULL, *login = NULL, *pass = NULL, *tmp = NULL;
    unsigned short mismatch = 1;

    // take user input
    printf("Platform: ");
    platform = io_get_string(BUF_SIZE);
    printf("Login: ");
    login = io_get_string(BUF_SIZE);

    while (mismatch) {
        FREE(pass);
        FREE(tmp);

        printf("Password: ");
        pass = io_get_string(BUF_SIZE);
        printf("Confirm password: ");
        tmp = io_get_string(BUF_SIZE);

        mismatch = strcmp(pass, tmp);
    }

    logCredsEntryData(log_buffer, user->db, platform, login, pass);
    user->nb_pass += 1;
    updateMemberInFile(user->db, F_NB_PASS, user->nb_pass);

    FREE(platform);
    FREE(login);
    FREE(pass);
    FREE(tmp);

    return PM_SUCCESS;
}

/*
 * Delete a password in the file of the corresponding user.
 */
status_t pm_delete_password()
{
    return PM_SUCCESS;
}

/*
 * Edit a password in the file of the corresponding user.
 */
status_t pm_edit_password()
{
    return PM_SUCCESS;
}

/*
 * Print all registered passwords of the user.
 */
status_t pm_print_all(log_info* log_buffer, pm_user* user)
{
    log_entry_header* header = NULL;
    creds_entry_log* entry = NULL;
    unsigned long log_type = 0;
    unsigned long platform_length = 0, login_length = 0, pass_length = 0;
    char* tmp = NULL;

    if ( !log_buffer->buf )
        return PM_FAILURE;

    printf("\nAll your passwords (%ld) :\n\n", user->nb_pass);

    header = (log_entry_header*)log_buffer->buf;
    entry = (creds_entry_log*)(log_buffer->buf + sizeof(log_entry_header));

    // go through the structures containing passwords
    for (unsigned long i = 0; i < user->nb_pass; i++) {
        log_type = header->logType;

        if (log_type == creds_entry_log_id) {
            platform_length = entry->platform_length;
            login_length = entry->login_length;
            pass_length = entry->pass_length;

            tmp = (char*) &entry->platform;

            printf("\tPlatform: %s\n", tmp);
            tmp += platform_length + 1;

            printf("\tLogin: %s\n", tmp);
            tmp += login_length + 1;

            printf("\tPassword: %s\n", tmp);
            tmp += pass_length + 1;
        }
        puts("\t--------------------");

        // update pointers to point to the next structure
        header = (log_entry_header*) tmp;
        entry = (creds_entry_log*) (tmp + sizeof(log_entry_header));
    }
    
    return PM_SUCCESS;
}

/*
 * Remove the file of the user.
 */
status_t pm_delete_all()
{
    return PM_SUCCESS;
}

/*
 * Encrypt the data of the user database except for the structure containing
 * user information needed to authenticate.
 */
unsigned char* pm_encrypt_data(
    log_info* log_buffer,
    pm_user* user)
{
    // cryto_hash_BYTES = 32 for sha512 which is used by default by nacl
    unsigned char key[crypto_hash_BYTES] = { '\0' };
    unsigned char iv[crypto_stream_NONCEBYTES] = { '\0' };
    unsigned char* buffer = NULL, *data_enc = NULL;
    size_t buffer_size = 0, pass_size = 0;

    // generate a key based on password and salt
    pass_size = strlen(user->pass);
    buffer_size = pass_size + SALT_SIZE;
    buffer = utils_malloc(buffer_size);

    memcpy(buffer, user->pass, pass_size);
    memcpy(buffer+pass_size, user->salt, SALT_SIZE);

    if ( crypto_hash(key, (const unsigned char*)buffer, buffer_size) != 0 ) {
        perror("crypto_hash");
        goto exit;
    }

#ifdef PM_DEBUG_1
    printf("(debug) key: ");
    for (int i = 0; i < crypto_hash_BYTES; i++) {
        printf("%02x", key[i]);
    }
    putchar('\n');
#endif

    // generate initialization vector and store it in user's file
    randombytes(iv, crypto_stream_NONCEBYTES);

    // write the iv into user's file
    updateIVInFile(user->db, iv, crypto_stream_NONCEBYTES);

    data_enc = utils_malloc(log_buffer->size);
    crypto_stream_xor(data_enc, log_buffer->buf, log_buffer->size, iv, key);

exit:
    FREE(buffer);

    return data_enc;
}

/*
 * Decrypt the encrypted data of the user database.
 */
unsigned char* pm_decrypt_data(
    log_info* log_buffer,
    pm_user* user)
{
    // cryto_hash_BYTES = 32 for sha512 which is used by default by nacl
    unsigned char key[crypto_hash_BYTES] = { '\0' };
    unsigned char* buffer = NULL, *data_dec = NULL;
    size_t buffer_size = 0, pass_size = 0;

    // generate a key based on password and salt
    pass_size = strlen(user->pass);
    buffer_size = pass_size + SALT_SIZE;
    buffer = utils_malloc(buffer_size);

    memcpy(buffer, user->pass, pass_size);
    memcpy(buffer+pass_size, user->salt, SALT_SIZE);

    if ( crypto_hash(key, (const unsigned char*)buffer, buffer_size) != 0 ) {
        perror("crypto_hash");
        goto exit;
    }

    if ( log_buffer->size > 0 ) {
        data_dec = utils_malloc(log_buffer->size);
        crypto_stream_xor(data_dec, log_buffer->buf, log_buffer->size, user->iv, key);
    }

exit:
    FREE(buffer);

    return data_dec;
}

int main(void)
{
    unsigned char* tmp = NULL;
    unsigned short choice = 0;
    pm_user* user = NULL;
    log_info log_buffer;

    log_buffer.buf = NULL;
    log_buffer.ptr = NULL;
    log_buffer.size = 0;

    user = utils_malloc(sizeof(pm_user));

    io_header();
    io_menu_login();

    while ( !user->auth ) {
        choice = io_get_choice();

        switch (choice) {
            case 1:
                pm_login(user, LOGIN_PASS);
                //sleep(1);
                break;
            case 2:
                // TODO : login with key
                break;
            case 3:
                pm_create_user(&log_buffer, user, LOGIN_PASS);
                break;
            case 4:
                goto exit;
            default:
                puts("Invalid choice!");
                break;
        }

    }

    // At this point the user is authenticated.

    // TODO : segfault when create user -> login as another one

    // get start address of passwords entries and decrypt user's passwords
    readCredsEntryData(&log_buffer, user->db);
    tmp = pm_decrypt_data(&log_buffer, user);

#ifdef PM_DEBUG_1
    if ( log_buffer.buf ) {
        printf("(debug) enc: ");
        for (int i = 0; i < 50; i++) {
            printf("%02x", log_buffer.buf[i]);
        }

        printf("\n(debug) tmp: ");
        for (int i = 0; i < 50; i++) {
            printf("%02x", tmp[i]);
        }
        putchar('\n');
    }
#endif

    FREE(log_buffer.buf);
    log_buffer.buf = tmp;

    io_menu((const char*)user->login);
    signal(SIGINT, sigint_handler);

    while ( is_running ) {
        choice = io_get_choice();

        switch (choice) {
            case 1:
                pm_add_password(&log_buffer, user);
                break;
            case 2:
                break;
            case 3:
                break;
            case 4:
                pm_print_all(&log_buffer, user);
                break;
            case 5:
                break;
            case 6:
                is_running = 0;
                break;
            default:
                puts("Invalid choice!");
                break;
        }
    }

    // seal and exit
    puts("[+] Encrypting your data..");
    tmp = pm_encrypt_data(&log_buffer, user);

    // replace data in buffer by the encrypted version
    FREE(log_buffer.buf)
    log_buffer.buf = tmp;

    flushToFile(&log_buffer, user->db);

exit:
    // Free resources.
    FREE(log_buffer.buf);
    FREE(user->iv);
    FREE(user->salt);
    FREE(user->login);
    FREE(user->pass);
    FREE(user);

    return PM_SUCCESS;
}
