#ifndef __UDP_H
#define __UDP_H

#include <unistd.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "sock.h"

#define rudp_sk(sk) ((struct rudp_sock *)sk)
#define rudp_hlen(rudp) (rudp->hl << 2)

/* Transmission Control Block 传输控制块 */
struct tcb {
	/* sending side 发送方 */
	uint32_t snd_una; // send unacknowledge #尚未被确认的数据的起始序列号
	uint32_t snd_nxt; // send next #下一个要发送的数据bit对应的序列号,即seq
	uint32_t snd_wnd; // send window #发送窗口的大小
	uint32_t snd_up;  // send urgent pointer
	uint32_t snd_wl1; // segment sequence number used for last window update
	uint32_t snd_wl2; // segment acknowledgment number used for last window update
	uint32_t isn;	  // initial send sequence number #初始的序列号(自己产生的)
	/* receiving side 接收方 */
	uint32_t rcv_nxt; // receive next #下一个期望收到的数据的序号,一般用作发给对方的ack序号
	uint32_t rcv_wnd; // receive window #接收窗口的大小
	uint32_t rcv_up;  // receive urgent pointer
	uint32_t irs;	  // initial receive sequence number #接收到的起始序列号(对方的起始序列号)
};

/* rudp_sock在原本sock的基础上增加了很多新的东西. */
struct rudp_sock {
    struct sock sk;
    uint16_t urdp_hdr_len;              /* rudp头部大小 */
    struct tcb tcb;				        /* 传输控制块 */
    uint8_t flags;
	uint8_t backoff;
    int32_t srtt;
    int32_t rttvar;
    uint32_t rto;
    struct wait_lock wait;	            /* 等待接收或者连接 */
    struct timer *retransmit;
    uint16_t rmss;				        /* remote maximum segment size */ 
	uint16_t smss;				        /* 最大报文段长度 */
    struct sk_buff_head ofo_queue;      /* ofo_queue用于记录那些
								        没有按照顺序到达的tcp数据报 */
};

struct rudphdr {

};

static inline struct tcphdr *rudp_hdr(const struct sk_buff *skb)
{
    return (struct tcphdr *)(skb->head);
}

#endif