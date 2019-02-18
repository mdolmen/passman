#ifndef UTILS_H
#define UTILS_H

/*
 * Custom error-checking malloc. (Uses calloc to set memory to 0).
 */
void *utils_malloc(size_t size);

/*
 * Custom error-checking realloc.
 */
void *utils_realloc(void *ptr, size_t size);

/*
 * Free all pointers allocated in an array of pointers.
 */
void utils_free_ptr_array(void **array, int nb_items);

/*
 * Return the number of files in a directory.
 */
unsigned int utils_count_file_dir(const char* path);

#endif // UTILS_H
