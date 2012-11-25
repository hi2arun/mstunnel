#ifndef __MST_MEMMGMT_H__
#define __MST_MEMMGMT_H__

void mst_memmgmt_init(void);
void *mst_malloc(size_t size, const void *caller);
void mst_free(void *ptr, const void *caller);
void *mst_realloc(void *ptr, size_t size, const void *caller);
void *mst_memalign(size_t alignment, size_t size, const void *caller);

void *(*__mst_malloc)(size_t size);
void (*__mst_free)(void *ptr);
void *(*__mst_realloc)(void *ptr, size_t size);
void *(*__mst_memalign)(size_t alignment, size_t size);

#endif //!__MST_MEMMGMT_H__
