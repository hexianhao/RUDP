#ifndef __BUFFER_H
#define __BUFFER_H

#include <unistd.h>
#include <stdint.h>

#include "mempool.h"

typedef struct _sb_manager {
    size_t chunk_size;
    uint32_t cur_num;
    uint32_t cnum;
    struct _mempool *mp;
    struct _sb_queue *freeq;

}sb_manager;

typedef struct _send_buffer {
    unsigned char *data;
    unsigned char *head;

    uint32_t head_off;
    uint32_t tail_off;
    uint32_t len;
    uint64_t cum_len;
    uint32_t size;

    uint32_t head_seq;
    uint32_t init_seq;
}send_buffer;

#ifndef _INDEX_TYPE_
#define _INDEX_TYPE_
typedef uint32_t index_type;
typedef int32_t signed_index_type;
#endif

typedef struct _sb_queue {
    index_type capacity;
    index_type head;
    index_type tail;

    struct _send_buffer **q;

}sb_queue;


/** rb frag queue **/
typedef struct _rb_frag_queue {
	index_type capacity;
	volatile index_type head;
	volatile index_type tail;

	struct _fragment_ctx ** q;
}rb_frag_queue;

/** ring buffer **/
typedef struct _fragment_ctx {
	uint32_t seq;
	uint32_t len:31,
			 is_calloc:1;
	struct _fragment_ctx *next;
}fragment_ctx;

typedef struct _ring_buffer {
    unsigned char *data;
    unsigned char *head;

    uint32_t head_offset;
    uint32_t tail_offset;

    int merged_len;
    uint64_t cum_len;
    int last_len;       // wind size
    int size;           // buff size

    uint32_t head_seq;
    uint32_t init_seq;

    fragment_ctx *fctx;
}ring_buffer;


typedef struct _rb_manager {
    size_t chunk_size;
    uint32_t cur_num;
    uint32_t cnum;

    mempool *mp;
    mempool *frag_mp;

    rb_frag_queue *free_fragq;
    rb_frag_queue *free_fragq_int;

}rb_manager;


#define MAX(a, b) ((a)>(b)?(a):(b))
#define MIN(a, b) ((a)<(b)?(a):(b))

#define NextIndex(sq, i)	(i != sq->capacity ? i + 1: 0)
#define PrevIndex(sq, i)	(i != 0 ? i - 1: sq->capacity)
#define MemoryBarrier(buf, idx)	__asm__ volatile("" : : "m" (buf), "m" (idx))


/********************send buffer related*****************************/
sb_manager *sbmanager_create(size_t chunk_size, uint32_t cnum);
send_buffer *SBInit(sb_manager *sbm, uint32_t init_seq);
void SBFree(sb_manager *sbm, send_buffer *buf);
size_t SBPut(sb_manager *sbm, send_buffer *buf, const void *data, size_t len);
sb_queue *CreateSBQueue(int capacity);
int SBEnqueue(sb_queue *sq, send_buffer *buf);
size_t SBRemove(sb_manager *sbm, send_buffer *buf, size_t len);

/********************ring buffer related*****************************/
rb_manager *RBManagerCreate(size_t chunk_size, uint32_t cnum);
size_t RBRemove(rb_manager *rbm, ring_buffer* buff, size_t len, int option);
int RBPut(rb_manager *rbm, ring_buffer* buff, 
	   void* data, uint32_t len, uint32_t cur_seq);
void RBFree(rb_manager *rbm, ring_buffer* buff);
ring_buffer *RBInit(rb_manager *rbm, uint32_t init_seq);


#endif