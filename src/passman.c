#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <crypto_hash.h>

#include "passman.h"
#include "io.h"

/*
 * Allows a user to connect and open up his file.
 */
status_t pm_login(unsigned short method)
{
    char* login = NULL;
    char* pass = NULL;

    if (LOGIN_PASS == method) {
        // TODO : take user input (login + pass)
        login = io_get_string(BUF_SIZE);
        pass = io_get_string(BUF_SIZE);

        // TODO : hash and concatenate (login + mdp)
        // TODO : compare to each file (auth header)
    }
    else {
        // TODO : take user input (login + key path)
    }

    // Free resources.
    if (login) {
        free(login);
        login = NULL;
    }
    if (pass) {
        free(pass);
        pass = NULL;
    }
}

/*
 * Create a new user and a create a file that will contains all of his
 * future passwords.
 */
status_t pm_create_user(unsigned short method)
{
    // TODO : take user input
    char* login = NULL;
    char* pass = NULL;

    //const unsigned char m[...];
    unsigned long long mlen;
    unsigned char h_login[crypto_hash_BYTES];
    unsigned char h_pass[crypto_hash_BYTES];

    if (LOGIN_PASS == method) {
        // TODO : take user input (login + pass)
        login = io_get_string(BUF_SIZE);
        pass = io_get_string(BUF_SIZE);

        // TODO : hash and concatenate (login + mdp)
        if ( crypto_hash(h_login, (const char*)login, (unsigned long long)strlen(login)) != 0 ) {
            perror("crypto_hash");
            exit(PM_FAILURE);
        }
        if ( crypto_hash(h_pass, (const char*)pass, (unsigned long long)strlen(pass)) != 0 ) {
            perror("crypto_hash");
            exit(PM_FAILURE);
        }

        printf("login: %s", login);
        for (int i = 0; i < crypto_hash_BYTES; i++) {
            printf("%02x", h_login[i]);
        }

        // TODO : count file in data/ to compute new id
        // TODO : write id + hashs to a new file
    }
    else {
        // TODO : take user input (login + key path)
    }

    // Free resources.
    if (login) {
        free(login);
        login = NULL;
    }
    if (pass) {
        free(pass);
        pass = NULL;
    }
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

    while ( (choice = io_choice()) != 4) {
        switch (choice) {
            case 1:
                // TODO : login with pass
                break;
            case 2:
                // TODO : login with key
                break;
            case 3:
                // TODO : create new user
                pm_create_user(LOGIN_PASS);
                break;
            case 4:
                return PM_SUCCESS;
            default:
                puts("Invalid choice!");
                break;
        }

        printf("\nSelect your option: ");
    }

    // At this point the user is authenticated.

    // TODO : print menu while not 7

    return PM_SUCCESS;
}
