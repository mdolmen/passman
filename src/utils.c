#include <stdlib.h>
#include <stdio.h>

void *utils_malloc(size_t size)
{
    void *ptr = NULL;

    ptr = calloc(size, sizeof(char));
    //ptr = malloc(size);

    if ( !ptr ) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }

    return ptr;
}

void *utils_realloc(void *ptr, size_t size)
{
    ptr = realloc(ptr, size);

    if ( !ptr ) {
        perror("realloc");
        exit(EXIT_FAILURE);
    }

    return ptr;
}

void utils_free_ptr_array(void **array, int nb_items)
{
    if (array) {
        for (int i = 0; i < nb_items; i++) {
            free(array[i]); 
            array[i] = NULL;
        }
        free(array);
        array = NULL;
    }
}
