#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/limits.h>
#include <sys/types.h>
#include <dirent.h>

#include <crypto_hash.h>
#include <crypto_verify_32.h>

#include "passman.h"
#include "io.h"
#include "logger.h"
#include "utils.h"

unsigned short auth = 0;
char* login = NULL;
char* pass = NULL;
char user_db[PATH_MAX] = { '\0' };

/*
 * Allows a user to connect and open up his file.
 */
status_t pm_login(unsigned short method)
{
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
        login = io_get_string(BUF_SIZE);
        printf("Password: ");
        pass = io_get_string(BUF_SIZE);

        // hash (sha512) login and pass
        if ( crypto_hash(h_ulogin, (const unsigned char*)login, (unsigned long long)strlen(login)) != 0 ) {
            perror("crypto_hash");
            exit(PM_FAILURE);
        }
        if ( crypto_hash(h_upass, (const unsigned char*)pass, (unsigned long long)strlen(pass)) != 0 ) {
            perror("crypto_hash");
            exit(PM_FAILURE);
        }

        // TODO : compare to each file (auth header)
        directory = opendir("data/");

        if (directory) {
            while ( (entry = readdir(directory)) && !auth ) {
                // DT_REG : entry is a regular file
                if (DT_REG == entry->d_type) {
                    // read data from binary file
                    snprintf(input, PATH_MAX, "data/%s", entry->d_name);
                    readPassAuthData(input, &h_login, &h_pass);

                    // compare
                    if (h_login && h_pass) {
                        cmp = 0;
                        cmp += crypto_verify_32(h_ulogin, h_login);
                        cmp += crypto_verify_32(h_ulogin+32, h_login+32);
                        cmp += crypto_verify_32(h_upass, h_pass);
                        cmp += crypto_verify_32(h_upass+32, h_pass+32);

                        if (cmp == 0) {
                            memcpy(user_db, input, strlen(input));
                            auth = 1;
                        }

                        free(h_login); h_login = NULL;
                        free(h_pass); h_pass = NULL;
                    }
                }
            }
        }

        closedir(directory);
    }
    else {
        // TODO : take user input (login + key path)
    }

    return PM_SUCCESS;
}

/*
 * Create a new user and a create a file that will contains all of his
 * future passwords.
 */
status_t pm_create_user(unsigned short method)
{
    char new_file[PATH_MAX] = { '\0' };
    char* login = NULL;
    char* pass = NULL;
    unsigned char h_login[crypto_hash_BYTES] = { '\0' };
    unsigned char h_pass[crypto_hash_BYTES] = { '\0' };
    unsigned long id = 0;

    if (LOGIN_PASS == method) {
        // take user input
        printf("Login: ");
        login = io_get_string(BUF_SIZE);
        printf("Password: ");
        pass = io_get_string(BUF_SIZE);
        // TODO : double check password ?

        // hash (sha512) login and pass
        if ( crypto_hash(h_login, (const unsigned char*)login, (unsigned long long)strlen(login)) != 0 ) {
            perror("crypto_hash");
            exit(PM_FAILURE);
        }
        if ( crypto_hash(h_pass, (const unsigned char*)pass, (unsigned long long)strlen(pass)) != 0 ) {
            perror("crypto_hash");
            exit(PM_FAILURE);
        }

#ifdef PM_DEBUG_1
        printf("(debug) login: %s", login);
        for (int i = 0; i < crypto_hash_BYTES; i++) {
            printf("%02x", h_login[i]);
        }
        printf("(debug) pass: %s", pass);
        for (int i = 0; i < crypto_hash_BYTES; i++) {
            printf("%02x", h_pass[i]);
        }
#endif

        // compute ID based on current number of user (1 per file in 'data/')
        id = utils_count_file_dir("data/") + 1;

        // write data to a new file
        snprintf(new_file, PATH_MAX, "data/%ld.pm", id);
        logPassAuthData(new_file, id, (unsigned long)crypto_hash_BYTES, h_login, h_pass);
    }
    else {
        // TODO : take user input (login + key path)
    }

    // Free resources.
    if (login) { free(login); login = NULL; }
    if (pass) { free(pass); pass = NULL; }

    return PM_SUCCESS;
}

/*
 * Add a password in the file of the corresponding user.
 */
status_t pm_add_password()
{
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
 * Print all registered password of the user.
 */
status_t pm_print_all()
{
    return PM_SUCCESS;
}

/*
 * Remove the file of the user.
 */
status_t pm_delete_all()
{
    return PM_SUCCESS;
}

int main(void)
{
    unsigned short choice = 0;

    io_header();
    io_menu_login();

    while ( !auth && (choice = io_get_choice()) != 4 ) {
        switch (choice) {
            case 1:
                pm_login(LOGIN_PASS);
                break;
            case 2:
                // TODO : login with key
                break;
            case 3:
                pm_create_user(LOGIN_PASS);
                break;
            case 4:
                return PM_SUCCESS;
            default:
                puts("Invalid choice!");
                break;
        }

    }

    // At this point the user is authenticated.

    io_menu((const char*)login);

    while ( (choice = io_get_choice()) != 6 ) {
        switch (choice) {
            case 1:
                break;
            case 2:
                break;
            case 3:
                break;
            case 4:
                break;
            case 5:
                break;
            case 6:
                return PM_SUCCESS;
            default:
                puts("Invalid choice!");
                break;
        }
    }

    // Free resources.
    if (login) { free(login); login = NULL; }
    if (pass) { free(pass); pass = NULL; }

    return PM_SUCCESS;
}
