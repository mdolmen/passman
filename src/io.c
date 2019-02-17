#include <stdio.h>

#include "io.h"
#include "utils.h"

void io_header()
{
    char* header = 
        "Password Manager\n"
        "Version: 0.1\n";

    printf("%s\n", header);
}

void io_menu_login()
{
    char* menu =
        "Menu"
        "\n===="
        "\n  1. Login with password"
        "\n  2. Login with key"
        "\n  3. Create user"
        "\n  4. Quit";

    printf("%s\n\nSelect your option: ", menu);
}

void io_menu()
{
    char* menu =
        "Welcome X"
        "\n========="
        "\n\t1. Add a password"
        "\n\t2. Delete a password"
        "\n\t3. Edit a password"
        "\n\t4. Display all my passwords"
        "\n\t5. Delete all my passwords"
        "\n\t6. Quit";

    printf("%s\n\nSelect your option: ", menu);
}

unsigned short io_get_choice()
{
    char buffer[BUF_SIZE] = { '\0' };
    unsigned short choice = 0;

    // If the user enter more than a digit, we delete the rest by inserting a
    // null char.
    if ( fgets(buffer, BUF_SIZE, stdin) ) {
        buffer[1] = '\0';
        sscanf(buffer, "%hu", &choice);
    }

    return choice;
}

char* io_get_string(unsigned short max_length)
{
    char* buffer = NULL;

    buffer = utils_malloc(max_length * sizeof(char));

    fgets(buffer, max_length, stdin);
    buffer[max_length-1] = '\0';

    return buffer;
}
