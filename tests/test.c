#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <check.h>

#include "passman.h"
#include "io.h"

/*
 * Normal input.
 */
START_TEST(t_io_get_choice_1)
{
    unsigned short choice = 0;
    FILE* f = NULL;
    char* s = "3";

    // Re-open stdin as "tests/data", so we can pass input to our function.
    f = freopen("tests/data", "w+", stdin);
    if (f) {
        fwrite(s, 1, 1, f);
    }

    // Go to the beginning of the file.
    rewind(f);
    choice = io_get_choice();

	ck_assert_msg(
	    choice == 3,
		"Choice should be 3.\n"
		"choice = %d",
		choice
	);

    fclose(f);
}
END_TEST

/*
 * Wrong input.
 */
START_TEST(t_io_get_choice_2)
{
    unsigned short choice = 0;
    FILE* f = NULL;
    char* s = "fkrbqzi(aàç(th";

    // Re-open stdin as "tests/data", so we can pass input to our function.
    f = freopen("tests/data", "w+", stdin);
    if (f) {
        fwrite(s, strlen(s), 1, f);
    }

    // Go to the beginning of the file.
    rewind(f);
    choice = io_get_choice();

	ck_assert_msg(
	    choice == 0,
		"Choice should be 0.\n"
		"choice = %d",
		choice
	);

    fclose(f);
}
END_TEST

// TODO : utils_count_file_dir

// TODO : pm_create_user

Suite* passman_suite(void)
{
    Suite* s = NULL;
    TCase* tc_core = NULL;

    s = suite_create("Passman");

    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, t_io_get_choice_1);
    tcase_add_test(tc_core, t_io_get_choice_2);

    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int failed = 0;
    Suite* s = NULL;
    SRunner* sr = NULL;

    // Create an SRunner object to execute the tests suites.
    s = passman_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
