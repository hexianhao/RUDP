#include <stdio.h>
#include <stdlib.h>

#include "mempool.h"
#include "buffer.h"

/********************************send buffer*******************************/

sb_manager *sbmanager_create(size_t chunk_size, uint32_t cnum) {
    sb_manager *sbm = (sb_manager *)calloc(1, sizeof(sb_manager));
    if(!sbm) {
        printf("sender buffer manager create failed\n");
        return NULL;
    }

    sbm->chunk_size = chunk_size;
    sbm->cnum = cnum;
    sbm->mp = mempool_create(chunk_size, (uint64_t)chunk_size * cnum, 0);
    if(!sbm->mp) {
        printf("memory pool created failed\n");
        free(sbm);
        return NULL;
    }

    sbm->freeq = CreateSBQueue(cnum);
    if(!sbm->freeq) {
        printf("create free buffer queue failed\n");
        mempool_destroy(sbm);
        free(sbm);
        return NULL;
    }

    return sbm;
}

sb_queue *CreateSBQueue(int capacity) {
    sb_queue *sq;

    sq = (sb_queue *)calloc(1, sizeof(sb_queue));
    if(!sq) {
        return NULL;
    }

    sq->q = (send_buffer **)calloc(capacity + 1, sizeof(send_buffer *));
    if(!sq->q) {
        free(sq);
        return NULL;
    }

    sq->capacity = capacity;
    sq->head = sq->tail = 0;

    return sq;
}

send_buffer *SBInit(sb_manager *sbm, uint32_t init_seq) {
    send_buffer *buf;

    buf = SBDequeue(sbm->freeq);
    if(!buf) {
        buf = (send_buffer *)malloc(sizeof(send_buffer));
        if(!buf) {
            perror("malloc failed");
            return NULL;
        }
        buf->data = mempool_alloc(sbm->mp);
        if(!buf->data) {
            printf("Failed to fetch memory chunk for data.\n");
			free(buf);
			return NULL;
        }
        sbm->cur_num++;
    }

    buf->head = buf->data;
    buf->head_off = buf->tail_off = 0;
    buf->len = buf->cum_len = 0;

    buf->init_seq = buf->head_seq = init_seq;

    return buf;
}

size_t SBPut(sb_manager *sbm, send_buffer *buf, const void *data, size_t len) {
    size_t to_put;

    if(len <= 0) {
        return 0;
    }

    to_put = MIN(len, buf->size - buf->len);
    if (to_put <= 0) {
		return -2;
	}

    if (buf->tail_off + to_put < buf->size) {
		/* if the data fit into the buffer, copy it */
		memcpy(buf->data + buf->tail_off, data, to_put);
		buf->tail_off += to_put;
	} else {
		/* if buffer overflows, move the existing payload and merge */
		memmove(buf->data, buf->head, buf->len);
		buf->head = buf->data;
		buf->head_off = 0;
		memcpy(buf->head + buf->len, data, to_put);
		buf->tail_off = buf->len + to_put;
	}
	buf->len += to_put;
	buf->cum_len += to_put;

    return to_put;
}

size_t SBRemove(sb_manager *sbm, send_buffer *buf, size_t len) {
    size_t to_remove;

	if (len <= 0)
		return 0;

	to_remove = MIN(len, buf->len);
	if (to_remove <= 0) {
		return -2;
	}

	buf->head_off += to_remove;
	buf->head = buf->data + buf->head_off;
	buf->head_seq += to_remove;
	buf->len -= to_remove;

	/* if buffer is empty, move the head to 0 */
	if (buf->len == 0 && buf->head_off > 0) {
		buf->head = buf->data;
		buf->head_off = buf->tail_off = 0;
	}

	return to_remove;
}

void SBFree(sb_manager *sbm, send_buffer *buf) {
    if(!buf) return;

    SBEnqueue(sbm->freeq, buf);
}

int SBEnqueue(sb_queue *sq, send_buffer *buf) {
    index_type h = sq->head;
	index_type t = sq->tail;
	index_type nt = NextIndex(sq, t);

    if (nt != h) {
		sq->q[t] = buf;
		MemoryBarrier(sq->q[t], sq->tail);
		sq->tail = nt;
		return 0;
	}

	printf("Exceed capacity of buf queue!\n");
	return -1;
}

send_buffer *SBDequeue(sb_queue *sq)
{
	index_type h = sq->head;
	index_type t = sq->tail;

	if (h != t) {
		send_buffer *buf = sq->q[h];
		MemoryBarrier(sq->q[h], sq->head);
		sq->head = NextIndex(sq, h);
		assert(buf);

		return buf;
	}

	return NULL;
}

/**********************************ring buffer*********************************/

#define MAXSEQ               ((uint32_t)(0xFFFFFFFF))
/*----------------------------------------------------------------------------*/
static inline uint32_t GetMinSeq(uint32_t a, uint32_t b)
{
	if (a == b) return a;
	if (a < b) 
		return ((b - a) <= MAXSEQ/2) ? a : b;
	/* b < a */
	return ((a - b) <= MAXSEQ/2) ? b : a;
}
/*----------------------------------------------------------------------------*/
static inline uint32_t GetMaxSeq(uint32_t a, uint32_t b)
{
	if (a == b) return a;
	if (a < b) 
		return ((b - a) <= MAXSEQ/2) ? b : a;
	/* b < a */
	return ((a - b) <= MAXSEQ/2) ? a : b;
}
/*----------------------------------------------------------------------------*/
static inline int CanMerge(const fragment_ctx *a, const fragment_ctx *b)
{
	uint32_t a_end = a->seq + a->len + 1;
	uint32_t b_end = b->seq + b->len + 1;

	if (GetMinSeq(a_end, b->seq) == a_end ||
		GetMinSeq(b_end, a->seq) == b_end)
		return 0;
	return 1;
}

static inline void MergeFragments(fragment_ctx *a, fragment_ctx *b)
{
	/* merge a into b */
	uint32_t min_seq, max_seq;

	min_seq = GetMinSeq(a->seq, b->seq);
	max_seq = GetMaxSeq(a->seq + a->len, b->seq + b->len);
	b->seq  = min_seq;
	b->len  = max_seq - min_seq;
}

fragment_ctx *AllocateFragementContext(rb_manager *rbm) {
    fragment_ctx *frag;

    frag = RBFragDequeue(rbm->free_fragq);
    if(!frag) {
        frag = RBFragDequeue(rbm->free_fragq_int);
        if(!frag) {
            /* next fall back to fetching from mempool */
            frag = mempool_alloc(rbm->frag_mp);
            if(!frag) {
                printf("fragments depleted, fall back to calloc\n");
				frag = calloc(1, sizeof(fragment_ctx));
				if (frag == NULL) {
					printf("calloc failed\n");
					exit(-1);
				}
				frag->is_calloc = 1; /* mark it as allocated by calloc */
            }
        }
    }

    return frag;
}

static inline void FreeFragmentContextSingle(rb_manager *rbm, fragment_ctx *frag) {
	if (frag->is_calloc)
		free(frag);
	else	
		nmempool_free(rbm->frag_mp, frag);
}

void FreeFragmentContext(rb_manager *rbm, fragment_ctx* fctx)
{
	fragment_ctx *remove;

	if (fctx == NULL) 	
		return;

	while (fctx) {
		remove = fctx;
		fctx = fctx->next;
		FreeFragmentContextSingle(rbm, remove);
	}
}

rb_frag_queue *CreateRBFragQueue(int capacity) {
    rb_frag_queue *rb_fraq;

    rb_fraq = (rb_frag_queue *)calloc(1, sizeof(rb_frag_queue));
    if(!rb_fraq) {
        return NULL;
    }

    rb_fraq->q = (fragment_ctx **)calloc(capacity + 1, sizeof(fragment_ctx *));
    if(!rb_fraq->q) {
        free(rb_fraq);
        return NULL;
    }

    rb_fraq->capacity = capacity;
    rb_fraq->head = rb_fraq->tail = 0;

    return rb_fraq;
}

void DestroyRBFragQueue(rb_frag_queue *rb_fragq) {
	if (!rb_fragq)
		return;

	if (rb_fragq->q) {
		free((void *)rb_fragq->q);
		rb_fragq->q = NULL;
	}

	free(rb_fragq);
}

int RBFragEnqueue(rb_frag_queue *rb_fragq, fragment_ctx *frag) {
    index_type h = rb_fragq->head;
    index_type t = rb_fragq->tail;
    index_type nxt = NextIndex(rb_fragq, t);

    if(nxt != h) {
        rb_fragq->q[nxt] = frag;
        MemoryBarrier(rb_fragq->q[t], rb_fragq->tail);
        rb_fragq->tail = nxt;
        return 0;
    }

    printf("Exceed capacity of frag queue\n");
    return -1;
}

fragment_ctx *RBFragDequeue(rb_frag_queue *rb_fragq) {
    index_type h = rb_fragq->head;
	index_type t = rb_fragq->tail;

    if(h != t) {
        fragment_ctx *frag = rb_fragq->q[h];
        MemoryBarrier(rb_fragq->q[h], rb_fragq->head);
        rb_fragq->head = NextIndex(rb_fragq, h);
        assert(rb_fragq);

        return frag;
    }
    return NULL;
}

rb_manager *RBManagerCreate(size_t chunk_size, uint32_t cnum) {
    rb_manager *rbm = (rb_manager*) calloc(1, sizeof(rb_manager));

    if(!rbm) {
        perror("Create ring buffer failed");
        return NULL;
    }

    rbm->chunk_size = chunk_size;
    rbm->cnum = cnum;
    rbm->mp = (mempool *)mempool_create(chunk_size, (uint64_t)chunk_size * cnum, 0);
    if(!rbm->mp) {
        printf("Failed to allocate mp pool.\n");
		free(rbm);
		return NULL;
    }
    
    rbm->frag_mp = (mempool*)mempool_create(sizeof(fragment_ctx), 
									sizeof(fragment_ctx) * cnum, 0);
    if(!rbm->frag_mp) {
        printf("Failed to allocate frag_mp pool.\n");
		nmempool_destory(rbm->mp);
		free(rbm);
		return NULL;
    }

    rbm->free_fragq = CreateRBFragQueue(cnum);
    if (!rbm->free_fragq) {
		printf("Failed to create free fragment queue.\n");
		mempool_destory(rbm->mp);
		mempool_destory(rbm->frag_mp);
		free(rbm);
		return NULL;
	}
    rbm->free_fragq_int = CreateRBFragQueue(cnum);
	if (!rbm->free_fragq_int) {
		printf("Failed to create internal free fragment queue.\n");
		mempool_destory(rbm->mp);
		mempool_destory(rbm->frag_mp);
		DestroyRBFragQueue(rbm->free_fragq);
		free(rbm);
		return NULL;
	}

    return rbm;
}

ring_buffer *RBInit(rb_manager *rbm, uint32_t init_seq) {
	ring_buffer* buff = (ring_buffer*)calloc(1, sizeof(ring_buffer));

	if (buff == NULL){
		perror("rb_init buff");
		return NULL;
	}

	buff->data = mempool_alloc(rbm->mp);
	if(!buff->data){
		perror("rb_init MPAllocateChunk");
		free(buff);
		return NULL;
	}

	buff->size = rbm->chunk_size;
	buff->head = buff->data;
	buff->head_seq = init_seq;
	buff->init_seq = init_seq;
	
	rbm->cur_num++;

	return buff;
}

int RBPut(rb_manager *rbm, ring_buffer* buff, 
	   void* data, uint32_t len, uint32_t cur_seq) {
    int putx, end_off;
    fragment_ctx *new_ctx;
    fragment_ctx *iter;
    fragment_ctx *prev, *pprev;
    int merged = 0;

    if(len <= 0) return 0;

    if(GetMinSeq(buff->head_seq, cur_seq) != buff->head_seq) {
        return 0;
    }

    putx = cur_seq - buff->head_seq;
    end_off = putx + len;
    if(buff->size < end_off) {
        return -1;
    }

    // buffer overflows, move the data
    if(buff->size <= (buff->head_offset + end_off)) {
        memmove(buff->data, buff->head, buff->last_len);
        buff->tail_offset -= buff->head_offset;
        buff->head_offset = 0;
		buff->head = buff->data;
    }

    //copy data to buffer
    memcpy(buff->head + putx, data, len);

    // update tail
    if(buff->tail_offset < buff->head_offset + end_off) {
        buff->tail_offset = buff->head_offset + end_off;
    }
    buff->last_len = buff->tail_offset - buff->head_offset;

    // create new fragement
    new_ctx = AllocateFragementContext(rbm);
    if(!new_ctx) {
        perror("allocating new_ctx failed");
		return 0;
    }
    new_ctx->seq = cur_seq;
    new_ctx->len = len;
    new_ctx->next = NULL;

    // traverse the fragment list, and merge the new fragment if possible
    for(iter = buff->fctx, prev = NULL, pprev = NULL; 
        iter != NULL;
        pprev = prev, prev = iter, iter = iter->next) {

        if(CanMerge(new_ctx, iter)) {
            /* merge the first fragment into the second fragment */
            MergeFragements(new_ctx, iter);

            /* remove the first fragement */
            if(prev == new_ctx) {
                if (pprev)
					pprev->next = iter;
				else
					buff->fctx = iter;
				prev = pprev;
            }
            FreeFragmentContextSingle(rbm, new_ctx);
            new_ctx = iter;
            merged = 1;
        }
        else if(merged ||
                GetMaxSeq(cur_seq + len, iter->seq) == iter->seq) {
            /* if merged, or no more mergeable */
            break;
        }
    }

    if(!merged) {
        if(buff->fctx == NULL) {
            buff->fctx = new_ctx;
        } else if(GetMinSeq(new_ctx->seq, buff->fctx->seq) == buff->fctx->seq) {
            new_ctx->next = buff->fctx;
            buff->fctx = new_ctx;
        } else {
            /* in middle place */
            assert(GetMinSeq(cur_seq, prev->seq + prev->len) ==
				   prev->seq + prev->len);
			prev->next = new_ctx;
			new_ctx->next = iter;
        }
    }

    if(buff->head_seq == buff->fctx->seq) {
        buff->cum_len += buff->fctx->len - buff->merged_len;
        buff->merged_len = buff->fctx->len;
    }

    return len;
}

size_t RBRemove(rb_manager *rbm, ring_buffer* buff, size_t len, int option) {
    /* this function should be only called by application */
    if(len <= 0)
        return 0;
    
    if(buff->merged_len < len) {
        buff->merged_len = len;
    }

    buff->head_offset += len;
    buff->head = buff->data + buff->head_offset;
    buff->head_seq += len;

    buff->merged_len -= len;
    buff->last_len -= len;

    // modify fragments
    if(len == buff->fctx->len) {
        fragment_ctx *remove = buff->fctx;
        buff->fctx = buff->fctx->next;
        if(option) {
            RBFragEnqueue(rbm->free_fragq, remove);
        } else {
            RBFragEnqueue(rbm->free_fragq_int, remove);
        }
    } else if(len < buff->fctx->len) {
        buff->fctx->seq += len;
        buff->fctx->len -= len;
    } else {
        assert(0);
    }

    return len;
}

void RBFree(rb_manager *rbm, ring_buffer* buff) {
    assert(buff);
    if(buff->fctx) {
        FreeFragmentContext(rbm, buff->fctx);
    }

    if(buff->data) {
        mempool_free(rbm->mp, buff->data);
    }

    rbm->cur_num--;
    
    free(buff);
}