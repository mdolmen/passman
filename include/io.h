#ifndef IO_H
#define IO_H

#define BUF_SIZE    128

/*
 * Print the header containing version info.
 */
void io_header();

/*
 * Print options menu to the user.
 */
void io_menu(const char* user);

void io_menu_login();

/*
 * Handling of user input to make a choice at a menu.
 */
unsigned short io_get_choice();

/*
 * Handling of user input for strings.
 */
char* io_get_string(unsigned short max_length);

#endif // IO_H
