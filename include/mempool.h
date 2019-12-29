#ifndef TY_MEMPOOL_H
#define TY_MEMPOOL_H

#include <unistd.h>

enum {
	MEM_NORMAL,
	MEM_HUGEPAGE
};

typedef struct _mem_chunk {
    int mc_free_chunks;
    struct _mem_chunk *next;
}mem_chunk;

typedef struct _mempool {
    unsigned char *mp_startptr;
    mem_chunk *mp_freeptr;
    int mp_free_chunks;
    int mp_total_chunks;
    int mp_chunk_size;
    int mp_type;
}mempool;

mempool *mempool_create(int chunk_size, size_t total_size, int is_hugepage);

void mempool_destroy(mempool *mp);

void *mempool_alloc(mempool *mp);

void mempool_free(mempool *mp, void *p);

#endif