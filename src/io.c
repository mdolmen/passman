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

void io_menu(const char* user)
{
    printf(
        "\nWelcome %s"
        "========="
        "\n  1. Add a password"
        "\n  2. Delete a password"
        "\n  3. Edit a password"
        "\n  4. Display all my passwords"
        "\n  5. Delete all my passwords"
        "\n  6. Quit"
        "\n\nSelect your option: ",
        user);
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
