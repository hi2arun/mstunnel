#include <malloc.h>
#include <stdlib.h>
#define __USE_GNU
#include <dlfcn.h>

#include "memmgmt.h"

#ifdef __USE_MM__
static void *(*def_malloc_hook)(size_t size, const void *caller);
static void (*def_free_hook)(void *ptr, const void *caller);
static void *(*def_realloc_hook)(void *ptr, size_t size, const void *caller);
static void *(*def_memalign_hook)(size_t alignment, size_t size, const void *caller);
#endif

/**
 * Overload malloc init hook. This is declared in malloc.h
 */
//__malloc_initialize_hook = mst_memmgmt_init;

void 
mst_memmgmt_init(void)
{
    fprintf(stderr, "%s:%s()\n", __FILE__, __func__);

#ifndef __USE_MM__
    __mst_malloc = dlsym(RTLD_NEXT, "malloc");
    __mst_free = dlsym(RTLD_NEXT, "free");
    __mst_realloc = dlsym(RTLD_NEXT, "realloc");
    __mst_memalign = dlsym(RTLD_NEXT, "memalign");

    if (!__mst_malloc || !__mst_free || !__mst_realloc || !__mst_memalign) {
        return;
    }
    fprintf (stderr, "%p, %p, %p, %p\n", __mst_malloc, __mst_free, __mst_realloc, __mst_memalign);
#else
    def_malloc_hook = __malloc_hook;
    def_free_hook = __free_hook;
    def_realloc_hook = __realloc_hook;
    def_memalign_hook = __memalign_hook;

    __malloc_hook = mst_malloc;
    __free_hook = mst_free;
    __realloc_hook = mst_realloc;
    __memalign_hook = mst_memalign;
#endif

    return;
}

void *
mst_malloc(size_t size, const void *caller)
{
    fprintf(stderr, "%s:%s()\n", __FILE__, __func__);
    // TODO: Fill in this place with MM/BM functions
    return __mst_malloc(size);
}

void
mst_free(void *ptr, const void *caller)
{
    fprintf(stderr, "%s:%s()\n", __FILE__, __func__);
    // TODO: Fill in this place with MM/BM functions
    __mst_free(ptr);
    return;
}

void *
mst_realloc(void *ptr, size_t size, const void *caller)
{
    fprintf(stderr, "%s:%s()\n", __FILE__, __func__);
    // TODO: Fill in this place with MM/BM functions
    return __mst_realloc(ptr, size);
}
   
void *
mst_memalign(size_t alignment, size_t size, const void *caller)
{
    // TODO: Fill in this place with MM/BM functions
    return __mst_memalign(alignment, size);
}

