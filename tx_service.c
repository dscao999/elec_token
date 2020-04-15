#include <sys/types.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <errno.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <assert.h>
#include <unistd.h>
#include <signal.h>
#include <poll.h>
#include "global_param.h"
#include "loglog.h"
#include "wcomm.h"
#include "toktx.h"

static volatile int global_exit = 0;

static void sig_handler(int sig)
{
	if (sig == SIGTERM || sig == SIGINT)
		global_exit = 1;
}

void txrec_verify(int sock, struct winfo *wif)
{
	int suc, numb;
	struct txrec *tx;
	unsigned char sha_dgst[32];
	struct sockaddr_in *sockaddr;
	char buf[16];

	sha256_to_str(sha_dgst, (const unsigned char *)wif->wpkt.pkt, wif->wpkt.len);
	tx = tx_deserialize(wif->wpkt.pkt, wif->wpkt.len);
	if (tx) {
		suc = tx_verify(tx);
		wif->wpkt.ptype = suc;
		wif->wpkt.len = SHA_DGST_LEN;
		memcpy(wif->wpkt.pkt, sha_dgst, SHA_DGST_LEN);
		sockaddr = (struct sockaddr_in *)&wif->srcaddr;
		numb = sendto(sock, &wif->wpkt,
				wif->wpkt.len + sizeof(wif->wpkt), 0,
				(const struct sockaddr *)sockaddr,
				sizeof(struct sockaddr_in));
		if (suc)
			printf("Verified! ack: %d\n", numb);
		else
			printf("Invalid Tx! ack: %d\n", numb);
		tx_destroy(tx);
	}
}

void * tx_process(void *arg)
{
	struct wcomm *wm = arg;
	int rc;
	struct timespec tm;
	struct winfo *wif;

	do {
		pthread_mutex_lock(&wm->wmtx);
		clock_gettime(CLOCK_REALTIME, &tm);
		tm.tv_sec += 1;
		rc = 0;
		while (global_exit == 0 && wcomm_empty(wm) &&
				(rc == 0 || rc == ETIMEDOUT))
			rc = pthread_cond_timedwait(&wm->wcd, &wm->wmtx, &tm);
		if (rc != 0 && rc != ETIMEDOUT) {
			logmsg(LOG_ERR, "pthread_cond_timedwait failed: %s\n",
					strerror(rc));
			global_exit = 1;
			pthread_mutex_unlock(&wm->wmtx);
			break;
		}
		wif = NULL;
		if (!wcomm_empty(wm))
			wif = wcomm_remove(wm);
		pthread_mutex_unlock(&wm->wmtx);
		if (!wif)
			continue;
		switch(wif->wpkt.ptype) {
		case TX_REC:
			txrec_verify(wm->sock, wif);
			break;
		default:
			;
		}
		free(wif);
	} while (global_exit == 0);
	return NULL;
}

int tx_recv(int port, struct wcomm *wm)
{
	int sd, sysret, buflen, numb;
	socklen_t saddr_len;
	struct addrinfo ahint, *resaddr;
	struct sockaddr_in *sin_addr;
	char portnum[8];
	struct winfo *wif;
	struct pollfd pfd[1];

	memset(pfd, 0, sizeof(pfd));
	sd = socket(AF_INET, SOCK_DGRAM, 0);
	if (unlikely(sd == -1)) {
		logmsg(LOG_ERR, "Cannot create a UDP socket: %s\n",
				strerror(errno));
		return -errno;
	}
	pfd[0].fd = sd;
	pfd[0].events = POLLIN;

	sprintf(portnum, "%d", port);
	memset(&ahint, 0, sizeof(ahint));
	ahint.ai_flags = AI_PASSIVE;
	ahint.ai_family = AF_INET;
	ahint.ai_socktype = SOCK_DGRAM;
	sysret = getaddrinfo(NULL, portnum, &ahint, &resaddr);
	if (unlikely(sysret != 0)) {
		logmsg(LOG_ERR, "getaddrinfo failed: %s\n", strerror(errno));
		close(sd);
		return -errno;
	}
	sin_addr = (struct sockaddr_in *)resaddr->ai_addr;
	printf("Port number: %d\n", (int)ntohs(sin_addr->sin_port));
	sysret = bind(sd, resaddr->ai_addr, resaddr->ai_addrlen);
	if (sysret != 0) {
		logmsg(LOG_ERR, "bind failed: %s\n", strerror(errno));
		freeaddrinfo(resaddr);
		close(sd);
		return -errno;
	}
	freeaddrinfo(resaddr);
	wm->sock = sd;
	buflen = MAX_TXSIZE - sizeof(struct sockaddr_storage);
	do {
		wif = wcomm_getarea(wm);
		saddr_len = sizeof(wif->srcaddr);
		do {
			pfd[0].revents = 0;
			sysret = poll(pfd, 1, 800);
			if (sysret == 0)
				continue;
			else if (sysret == -1 && errno != EINTR) {
				logmsg(LOG_ERR, "poll error: %s\n",
						strerror(errno));
				global_exit = 1;
			}
		} while ((pfd[0].revents & POLLIN) == 0 && global_exit == 0);
		if (global_exit)
			break;
		numb = recvfrom(sd, &wif->wpkt, buflen, 0,
				(struct sockaddr *)&wif->srcaddr, &saddr_len);
		if (numb == -1) {
		       	if (errno != EINTR) {
				logmsg(LOG_ERR, "recvfrom error: %s\n",
						strerror(errno));
				global_exit = 1;
			}
			continue;
		} else if (numb == wif->wpkt.len + sizeof(struct wpacket))
			wcomm_signal(wm);
		else
			logmsg(LOG_ERR, "NULL or truncated packet received!\n");
	} while (global_exit == 0);
	close(sd);
	return 0;
}

int main(int argc, char *argv[])
{
	struct wcomm *wm;
	int retv, sysret;
	struct sigaction sigact;
	pthread_t rcvthd;

	global_param_init(NULL, 1, 0);
	wm = wcomm_init();
	if (!wm)
		return 1;

	memset(&sigact, 0, sizeof(sigact));
	sigact.sa_handler = sig_handler;
	sysret = sigaction(SIGTERM, &sigact, NULL);
	if (unlikely(sysret == -1))
		logmsg(LOG_WARNING, "Cannot install signal handler for " \
				"SIGTERM: %s\n", strerror(errno));
	sysret = sigaction(SIGINT, &sigact, NULL);
	if (unlikely(sysret == -1))
		logmsg(LOG_WARNING, "Cannot install signal handler for " \
				"SIGINT: %s\n", strerror(errno));

	sysret = pthread_create(&rcvthd, NULL, tx_process, wm);
	if (sysret) {
		logmsg(LOG_ERR, "pthread create failed: %s\n",
				strerror(errno));
		return 2;
	}
	retv = tx_recv(g_param->netp.port, wm);
	if (retv < 0)
		retv = -retv;
	pthread_join(rcvthd, NULL);

	return retv;
}
