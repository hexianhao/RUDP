#include <unistd.h>
#include <stdio.h>
#include <error.h>
#include <errno.h>
#include <assert.h>
#include <pthread.h>
#include <string.h>

#include "udp.h"


ssize_t recv(int sockfd, void *buf, size_t len, int flags,
                        struct sockaddr *src_addr, socklen_t *addrlen) {

    rudp_manager *rudp;
    udp_cb *ucb;
    rudp_recv *rcv = ucb->rcv;
    if(ucb == NULL) return -1;

    pthread_mutex_lock(&rcv->read_lock);

    while((int)rcv->rcv_wnd <= 0) {
        /* wait unitl rcv_wnd > 0 */
        pthread_cond_wait(&rcv->read_cond, &rcv->read_lock);
    }

    int copylen = MIN(rcv->recvbuf->merged_len, len);
    if(copylen <= 0) {
        errno = EAGAIN;
        pthread_mutex_unlock(&rcv->read_lock);
        return -1;
    }

    memcpy(buf, rcv->recvbuf->head, copylen);

    RBRemove(rudp->rbm_rcv, rcv->recvbuf, copylen, 1);
    rcv->rcv_wnd = rcv->recvbuf->size - rcv->recvbuf->merged_len;
    if(rcv->rcv_wnd <= 0) {
        printf("Recieve Buffer become full!!!\n");
    }
    pthread_mutex_unlock(&rcv->read_lock);

    return copylen;
}


ssize_t send(int sockfd, const void *buf, size_t len, int flags,
                      const struct sockaddr *dest_addr, socklen_t addrlen) {

    rudp_manager *rudp;
    udp_cb *ucb;
    rudp_send *snd = ucb->snd;
    if(ucb == NULL) return -1;

    pthread_mutex_lock(&snd->write_lock);

    while((int)snd->snd_wnd <= 0) {
        /* wait unitl snd_wnd > 0 */
        pthread_cond_wait(&snd->write_cond, &snd->write_lock);
    }

    int sndlen = MIN((int)snd->snd_wnd, len);
    if(sndlen <= 0) {
        errno = EAGAIN;
        pthread_mutex_unlock(&snd->write_lock);
        return -1;
    }

    if(!snd->sndbuf) {
        snd->sndbuf = SBInit(rudp->rbm_snd, snd->iss);
        if (!snd->sndbuf) {
            perror("send buffer init error");
            pthread_mutex_unlock(&snd->write_lock);
            return -1;
        }
    }

    int ret = SBPut(rudp->rbm_snd, snd->sndbuf, buf, sndlen);
    assert(ret == sndlen);
    if(ret <= 0) {
        perror("No memory error");
        pthread_mutex_unlock(&snd->write_lock);
        return -2;
    }

    snd->snd_wnd = snd->sndbuf->size - snd->sndbuf->len;
    if(snd->snd_wnd <= 0) {
        printf("Send Buffer become full!!!\n");
    }
    pthread_mutex_unlock(&snd->write_lock);

    return ret;
}


/**********************************thread related***********************************/

void *send_thread(void *arg) {
    
    int sockfd = *(int *)arg;
    ssize_t n;
    rudp_manager *rudp;
    udp_cb *ucb = NULL;
    rudp_send *snd;

    int cwnd;
    int mss;
    int slen;
    int dlen;

    char buf[BUFSIZ];

    while(1)
    {
        
        snd = ucb->snd;
        if(snd->snd_wnd > 0 && !ucb->is_on_timer) {
            
            slen = snd->sndbuf->len;
            cwnd = MIN(snd->cwnd, snd->peer_wnd);
            while(slen > 0 && cwnd > 0) {
                dlen = slen > mss ? mss : slen;     /* 一个报文最多只能发送mss个字节数据 */
                slen -= dlen;
                cwnd -= dlen;

                memset(buf, 0, sizeof(buf));
                
                sendto(sockfd, buf, dlen, 0, (struct sockaddr *)&ucb->cli_addr, sizeof(ucb->cli_addr));
                /*
                * add code here.
                * timer
                */
            }
        }

        /* traverse timer */
        
    }
    
    return NULL;
}


void *recv_thread(void *arg) {

    int sockfd = *(int *)arg;
    ssize_t n;
    rudp_manager *rudp;
    udp_cb *ucb = NULL;
    rudp_recv *rcv;

    struct sockaddr_in cliaddr;
    socklen_t socklen;

    char buf[BUFSIZ];

    while(1) 
    {
        n = recvfrom(sockfd, buf, BUFSIZ, 0, (struct sockaddr *)&cliaddr, &socklen);
        if(n < 0) {
            if(errno == EAGAIN) {
                continue;
            }
            break;
        }

        /* code here
         * hash hit
        */
        rcv = ucb->rcv;
        
        rudp_pkt *pkt = (rudp_pkt *)buf;
        
        /* update peer window, snd_nxt */
        pthread_mutex_lock(&ucb->snd->write_lock);

        ucb->snd->peer_wnd = pkt->wind;
        ucb->snd->snd_nxt = pkt->ack;

        if(pkt->ack > ucb->last_ack) {
            SBRemove(NULL, ucb->snd->sndbuf, ucb->last_ack - pkt->ack);
            ucb->last_ack = pkt->ack;
        }
        /* handle timer
        ** if pkt->ack == expected ack, then
        ** check timer
        */

        /* unlock */
        pthread_mutex_unlock(&ucb->snd->write_lock);

        /* update recv buffer */
        pthread_mutex_lock(&rcv->read_lock);

        RBPut(NULL, rcv->recvbuf, buf, n, pkt->seq);
        rcv->rcv_nxt = rcv->recvbuf->head_seq + rcv->recvbuf->merged_len;

        /* notify */
        pthread_cond_signal(&rcv->read_cond);
        /* unlock */
        pthread_mutex_unlock(&rcv->read_lock);

    }

    return NULL;
}