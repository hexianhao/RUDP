#include <stdio.h>
#include <stdlib.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

#include "mempool.h"

mempool *mempool_create(int chunk_size, size_t total_size, int is_hugepage) {

    if(chunk_size < (int)sizeof(mem_chunk)) {
        return NULL;
    }
    if(chunk_size % 4 != 0) {
        printf("mempool_create --> chunk_size: %d\n", chunk_size);
		return NULL;
    }

    mempool *mp = (mempool *)calloc(1, sizeof(mempool));
    if(mp == NULL) {
        printf("mempool_create --> calloc failed\n");
		return NULL;
    }

    mp->mp_type = is_hugepage;
    mp->mp_chunk_size = chunk_size;
    mp->mp_free_chunks = (total_size + (chunk_size - 1));
    mp->mp_total_chunks = mp->mp_free_chunks;

    if(is_hugepage == MEM_HUGEPAGE) {
        mp->mp_startptr = get_huge_pages(total_size, GHP_DEFAULT);
        if(mp->mp_startptr == NULL) {
            free(mp);
            assert(0);
        }
    } else {
        int res = posix_memalign((void **)&mp->mp_startptr, getpagesize(), total_size);
        if(res != 0) {
            free(mp);
            assert(0);
        }
    }

    mp->mp_freeptr = mp->mp_startptr;
    mp->mp_freeptr->mc_free_chunks = mp->mp_free_chunks;
    mp->mp_freeptr->next = NULL;

    return mp;
}


void mempool_destroy(mempool *mp) {
    if(mp->mp_type == MEM_HUGEPAGE) {
        free_huge_pages(mp->mp_startptr);
    } else {
        free(mp->mp_startptr);
    }

    free(mp);
}

void *mempool_alloc(mempool *mp) {

    mem_chunk *p = mp->mp_freeptr;

    if(mp->mp_free_chunks == 0) return NULL;

    assert(p->mc_free_chunks > 0);

    p->mc_free_chunks--;
    mp->mp_free_chunks--;

    if(p->mc_free_chunks) {
        mp->mp_freeptr = (mem_chunk*)((unsigned char *)p + mp->mp_chunk_size);
		mp->mp_freeptr->mc_free_chunks = p->mc_free_chunks;
		mp->mp_freeptr->next = p->next;
    } else {
        mp->mp_freeptr = p->next;
    }

    return p;
}

void mempool_free(mempool *mp, void *p) {
    mem_chunk *mcp = (mem_chunk *)p;

    assert(((unsigned char *)p - mp->mp_startptr) % mp->mp_chunk_size == 0);

    mcp->mc_free_chunks = 1;
    mcp->next = mp->mp_freeptr;
    mp->mp_freeptr = mcp;
    mp->mp_free_chunks++;

}

