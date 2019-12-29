#ifndef __UDP_H
#define __UDP_H

#include <unistd.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "buffer.h"

typedef struct _rudp_pkt {
    uint32_t init_seq;
    uint32_t seq;
    uint32_t ack;
    uint32_t wind: 16,
             offset: 16;
    unsigned char data[0];
}rudp_pkt;

typedef struct _rudp_send {
    uint32_t            snd_wnd;   // send window #发送窗口的大小
    uint32_t            snd_una;   // send unacknowledge #尚未被确认的数据的起始序列号
    uint32_t            cwnd;
    uint32_t            ssthresh;
    uint32_t            snd_nxt;   // send next #下一个要发送的数据bit对应的序列号,即seq
    uint32_t            iss;       // initial send sequence number #初始的序列号(自己产生的) 
    uint32_t            peer_wnd;  // 对端传来的窗口大小
    pthread_cond_t      write_cond;
	pthread_mutex_t     write_lock; 
    send_buffer         *sndbuf;

}rudp_send;

typedef struct _rudp_recv {
    uint32_t            rcv_wnd;   // receive window #接收窗口的大小
    uint32_t            rcv_nxt;   // receive next #下一个期望收到的数据的序号,一般用作发给对方的ack序号
    uint32_t            irs;	    // initial receive sequence number #接收到的起始序列号(对方的起始序列号)
    pthread_cond_t      read_cond;
	pthread_mutex_t     read_lock; 
    ring_buffer         *recvbuf;

}rudp_recv;


typedef struct _udp_control_block {
    rudp_recv *rcv;
    rudp_send *snd;

    struct sockaddr_in cli_addr;    /* 连接用户 */
    uint16_t mss;                   /* 最大报文段长度 */
    uint32_t last_ack;              /* 最后收到的ack */
    int is_on_timer;                

}udp_cb;

typedef struct _rudp_manager {
    sb_manager *rbm_snd;
	rb_manager *rbm_rcv;

}rudp_manager;

ssize_t recv(int sockfd, void *buf, size_t len, int flags,
                        struct sockaddr *src_addr, socklen_t *addrlen);

ssize_t send(int sockfd, const void *buf, size_t len, int flags,
                      const struct sockaddr *dest_addr, socklen_t addrlen);

#endif