#include "udp.h"
#include "skbuff.h"
#include "timer.h"

static void rudp_retransmission_timeout(uint32_t ts, void *arg);

static struct sk_buff *
rudp_alloc_skb(int size) {
    int reserved = RUDP_HDR_LEN + size;
    struct sk_buff *skb = alloc_skb(reserved);

    skb_reserve(skb, reserved); /* skb->data部分留出reserved个字节 */
	skb->protocol = IP_TCP;
	skb->dlen = size;	/* dlen表示数据的大小 */

    return skb;
}

static int 
rudp_transmit_skb(struct sock *sk, struct sk_buff *skb, uint32_t seq) 
{
    struct rudp_sock *rsk = rudp_sk(sk);
    struct tcb *tcb = &rsk->tcb;
    struct rudphdr *rhdr = rudp_hdr(skb); 

    // TODO
    skb_push(skb, NULL);

    // TODO
    // Add rudphdr header

}

static int rudp_queue_transmit_skb(struct sock *sk, struct sk_buff *skb)
{
    struct rudp_sock *rsk = rudp_sk(sk);
    struct tcb *tcb = &rsk->tcb;
    struct rudphdr *rhdr = rudp_hdr(skb);
    int rc = 0;

    pthread_mutex_lock(&sk->write_queue.lock);

    if (skb_queue_empty(&sk->write_queue)) {
        rudp_rearm_rto_timer(rsk);
    }

    skb_queue_tail(&sk->write_queue, skb);	        /* 将skb加入到发送队列的尾部 */
	rc = rudp_transmit_skb(sk, skb, tcb->snd_nxt);  /* 首先将数据发送一遍 */
	tcb->snd_nxt += skb->dlen;
	pthread_mutex_unlock(&sk->write_queue.lock);

    return rc;
}

static void
rudp_notify_user(struct sock *sk)
{
	struct rudp_sock *rsk = tcp_sk(sk);
	switch (sk->state) {
	case TCP_CLOSE_WAIT:
		wait_wakeup(&rsk->wait);
		break;
	}
}


/**\
 * tcp_retransmission_timeout 如果在规定的时间内还没有收到tcp数据报的确认,那么要重传
 * 该数据包. 
\**/
static void
tcp_retransmission_timeout(uint32_t ts, void *arg)
{
    struct rudp_sock *rsk = (struct rudp_sock *)arg;
    struct tcb *tcb = &rsk->tcb;
    struct sock *sk = &rsk->sk;

    pthread_mutex_lock(&sk->write_queue.lock);
    rudp_release_retransmission_timer(rsk);

    struct sk_buff *skb = write_queue_head(sk);

    if(!skb) {
        rudp_notify_user(sk);
        goto unlock;
    }

    struct rudphdr *rh = rudp_hdr(skb);
    skb_reset_header(skb);

    rudp_transmit_skb(sk, skb, tcb->snd_una);
    /* RFC 6298: 2.5 Maximum value MAY be placed on RTO, provided it is at least
       60 seconds */
    if(rsk->rto > 60000) {

    } else {
        rsk->rto *= 2;
        rsk->backoff++;
    }

unlock:
    pthread_mutex_unlock(&sk->write_queue.lock);
}