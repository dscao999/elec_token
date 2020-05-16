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
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <poll.h>
#include <string.h>
#include <my_global.h>
#include <mysql.h>
#include "global_param.h"
#include "loglog.h"
#include "wcomm.h"
#include "toktx.h"
#include "base64.h"

static volatile int global_exit = 0;

static void mysig_handler(int sig)
{
	if (sig == SIGTERM || sig == SIGINT || sig == SIGPIPE)
		global_exit = 1;
}

struct hashtx_info {
	unsigned long sha_len;
	unsigned char sha_dgst[SHA_DGST_LEN];
	union {
		unsigned long txrec_len;
		unsigned int txseq;
	};
};

struct hashkey_query {
	unsigned long value, ripe_len;
	unsigned char keyhash[RIPEMD_LEN];
	unsigned short etoken_id;
};

struct txrec_info {
	MYSQL *mcon;
	MYSQL_STMT *qmt, *imt, *umt;
	union {
		struct hashtx_info txop;
		struct hashkey_query val_query;
	};
	MYSQL_BIND mbnd[2], rbnd[1];
	struct wpacket wpkt;
} __attribute__((aligned(8)));

static void txrec_info_release(struct txrec_info *txp)
{
	if (txp->umt)
		mysql_stmt_close(txp->umt);
	if (txp->imt)
		mysql_stmt_close(txp->imt);
	if (txp->qmt)
		mysql_stmt_close(txp->qmt);
	if (txp->mcon)
		mysql_close(txp->mcon);
}

static const char txid_query[] = "SELECT seq FROM txrec_pool WHERE " \
				  "txhash = ? LOCK IN SHARE MODE";
static const char txid_insert[] = "INSERT INTO txrec_pool(txhash, txdata) " \
				  "VALUES(?, ?)";
static const char utxo_query[] = "SELECT value FROM utxo WHERE keyhash = ? " \
				  "AND etoken_id = ? AND in_process = false " \
				  "AND blockid > 1";

static int txrec_verify(int sock, const struct winfo *wif,
		struct txrec_info *txp)
{
	int suc, mysql_retv, txcnt, numb;
	struct txrec *tx;
	struct sockaddr_in *sockaddr;

	sha256_dgst_2str(txp->txop.sha_dgst,
			(const unsigned char *)wif->wpkt.pkt, wif->wpkt.len);
	suc = 3;
	tx = tx_deserialize(wif->wpkt.pkt, wif->wpkt.len);
	if (!tx)
		goto exit_100;
	suc = tx_verify(tx);
	tx_destroy(tx);
	if (suc == 0)
		goto exit_100;

	if (mysql_query(txp->mcon, "START TRANSACTION")) {
		logmsg(LOG_ERR, "START TRANSACTION failed: %s\n",
				mysql_error(txp->mcon));
		suc = -1;
		goto exit_100;
	}
	txp->txop.sha_len = SHA_DGST_LEN;
	if (mysql_stmt_execute(txp->qmt)) {
		logmsg(LOG_ERR, "mysql_execute failed: %s, %s\n", txid_query,
				mysql_stmt_error(txp->qmt));
		suc = -1;
		goto exit_100;
	}
	txcnt = 0;
	mysql_retv = mysql_stmt_fetch(txp->qmt);
	while (mysql_retv != MYSQL_NO_DATA) {
		txcnt += 1;
		mysql_retv = mysql_stmt_fetch(txp->qmt);
	}
	if (txcnt > 0)
		suc = 2;
	mysql_stmt_free_result(txp->qmt);

exit_100:
	txp->txop.txrec_len = wif->wpkt.len;
	if (suc == 1 && mysql_stmt_execute(txp->imt)) {
		logmsg(LOG_ERR, "mysql_execute failed: %s, %s\n", txid_query,
				mysql_stmt_error(txp->qmt));
		suc = -1;
	}
	if (mysql_commit(txp->mcon)) {
		logmsg(LOG_ERR, "COMMIT failed: %s\n", mysql_error(txp->mcon));
		suc = -1;
	}
	txp->wpkt.ptype = suc;
	txp->wpkt.len = SHA_DGST_LEN;
	memcpy(txp->wpkt.pkt, txp->txop.sha_dgst, SHA_DGST_LEN);
	sockaddr = (struct sockaddr_in *)&wif->srcaddr;
	numb = sendto(sock, &txp->wpkt, sizeof(struct wpacket)+txp->wpkt.len, 0,
			(const struct sockaddr *)sockaddr,
			sizeof(struct sockaddr_in));
	if (numb == -1)
		logmsg(LOG_ERR, "sendto failed: %s\n", strerror(errno));
	return suc;
}

struct utxo_query {
	unsigned short len;
	char keyhash[0];
};

static int utxo_do_query(int sock, const struct winfo *wif,
		struct txrec_info *txp)
{
	unsigned long *ackval;
	const struct utxo_query *uq;
	unsigned short *etoken_id;
	char *curmsg;
	int mysql_retv, len, keylen, numb;
	struct wpacket *wpkt;
	struct sockaddr_in *sockaddr;

	etoken_id = (unsigned short *)wif->wpkt.pkt;
	txp->val_query.etoken_id = *etoken_id;
	txp->val_query.ripe_len = RIPEMD_LEN;
	wpkt = &txp->wpkt;
	curmsg = wpkt->pkt;

	len = 0;
	uq = (const struct utxo_query *)(wif->wpkt.pkt + sizeof(unsigned short));
	while (uq->len != 0) {
		numb = str2bin_b64(txp->val_query.keyhash, RIPEMD_LEN, uq->keyhash);
		assert(numb == RIPEMD_LEN);
		ackval = (unsigned long *)curmsg;
		*ackval = 0;
		curmsg += sizeof(unsigned long);
		strcpy(curmsg, uq->keyhash);
		keylen = align8(strlen(uq->keyhash) + 1);
		curmsg += keylen;
		len += sizeof(unsigned long) + keylen;
		if (mysql_stmt_execute(txp->umt)) {
			logmsg(LOG_ERR, "mysql_execute failed: %s, %s\n",
					utxo_query, mysql_stmt_error(txp->umt));
		} else {
			mysql_stmt_store_result(txp->umt);
			mysql_retv = mysql_stmt_fetch(txp->umt);
			while (mysql_retv != MYSQL_NO_DATA) {
				*ackval += txp->val_query.value;
				mysql_retv = mysql_stmt_fetch(txp->umt);
			}
			mysql_stmt_free_result(txp->umt);
		}
		uq = (const struct utxo_query *)(((const char *)(uq + 1)) + uq->len);
	}
	wpkt->len = len;
	wpkt->ptype = 1;
	sockaddr = (struct sockaddr_in *)&wif->srcaddr;
	numb = sendto(sock, wpkt, sizeof(struct wpacket)+wpkt->len, 0,
			(const struct sockaddr *)sockaddr,
			sizeof(struct sockaddr_in));
	if (numb == -1)
		logmsg(LOG_ERR, "sendto failed: %s\n", strerror(errno));
	return 0;
}

static inline int notify_tx_logging(int pipd)
{
	int numb, pingpong = 1;


	numb = write(pipd, &pingpong, sizeof(pingpong));
	if (numb == -1)
		logmsg(LOG_ERR, "Cannot write to pipe: %d -> %s\n", errno,
				strerror(errno));
	return numb;
}

static int txrec_info_init(struct txrec_info *txp, struct winfo *wif)
{
	int retv = 0;

	memset(txp, 0, sizeof(struct txrec_info));

	txp->mcon = mysql_init(NULL);
	if (!check_pointer(txp->mcon))
		return -ENOMEM;
	if (mysql_real_connect(txp->mcon, g_param->db.host, g_param->db.user,
				g_param->db.passwd, g_param->db.dbname, 0,
				NULL, 0) == NULL ) {
		logmsg(LOG_ERR, "mysql_real_connect failed: %s\n",
				mysql_error(txp->mcon));
		retv = -mysql_errno(txp->mcon);
		goto err_exit_10;
	}
	txp->qmt = mysql_stmt_init(txp->mcon);
	if (!check_pointer(txp->qmt)) {
		retv = -ENOMEM;
		goto err_exit_10;
	}
	if (mysql_stmt_prepare(txp->qmt, txid_query, strlen(txid_query))) {
		logmsg(LOG_ERR, "Sql statement preparation failed: %s:%s \n",
				txid_query, mysql_stmt_error(txp->qmt));
		retv = -mysql_stmt_errno(txp->qmt);
		goto err_exit_20;
	}
	memset(txp->mbnd, 0, sizeof(MYSQL_BIND));
	txp->mbnd[0].buffer_type = MYSQL_TYPE_BLOB;
	txp->mbnd[0].buffer = txp->txop.sha_dgst;
	txp->mbnd[0].buffer_length = SHA_DGST_LEN;
	txp->mbnd[0].length = &txp->txop.sha_len;
	if (mysql_stmt_bind_param(txp->qmt, txp->mbnd)) {
		logmsg(LOG_ERR, "mysql_stmt_bind_param failed: %s, %s\n",
				txid_query, mysql_stmt_error(txp->qmt));
		retv = -mysql_stmt_errno(txp->qmt);
		goto err_exit_20;
	}
	memset(txp->rbnd, 0, sizeof(MYSQL_BIND));
	txp->rbnd[0].buffer_type = MYSQL_TYPE_LONG;
	txp->rbnd[0].buffer = &txp->txop.txseq;
	txp->rbnd[0].is_unsigned = 1;
	if (mysql_stmt_bind_result(txp->qmt, txp->rbnd)) {
		logmsg(LOG_ERR, "mysql_stmt_bind_result failed: %s, %s\n",
				txid_query, mysql_stmt_error(txp->qmt));
		retv = -mysql_stmt_errno(txp->qmt);
		goto err_exit_20;
	}

	txp->imt = mysql_stmt_init(txp->mcon);
	if (!check_pointer(txp->imt)) {
		retv = -ENOMEM;
		goto err_exit_20;
	}
	if (mysql_stmt_prepare(txp->imt, txid_insert, strlen(txid_insert))) {
		logmsg(LOG_ERR, "Sql statement preparation failed: %s:%s \n",
				txid_insert, mysql_stmt_error(txp->imt));
		retv = -mysql_stmt_errno(txp->imt);
		goto err_exit_30;
	}
	memset(txp->mbnd, 0, 2*sizeof(MYSQL_BIND));
	txp->mbnd[0].buffer_type = MYSQL_TYPE_BLOB;
	txp->mbnd[0].buffer = txp->txop.sha_dgst;
	txp->mbnd[0].buffer_length = SHA_DGST_LEN;
	txp->mbnd[0].length = &txp->txop.sha_len;
	txp->mbnd[1].buffer_type = MYSQL_TYPE_BLOB;
	txp->mbnd[1].buffer = wif->wpkt.pkt;
	txp->mbnd[1].buffer_length = MAX_TXSIZE - sizeof(struct winfo);
	txp->mbnd[1].length = &txp->txop.txrec_len;
	if (mysql_stmt_bind_param(txp->imt, txp->mbnd)) {
		logmsg(LOG_ERR, "mysql_stmt_bind_param failed: %s, %s\n",
				txid_query, mysql_stmt_error(txp->qmt));
		retv = -mysql_stmt_errno(txp->imt);
		goto err_exit_30;
	}

	txp->umt = mysql_stmt_init(txp->mcon);
	if (!check_pointer(txp->umt)) {
		retv = -ENOMEM;
		goto err_exit_30;
	}
	if (mysql_stmt_prepare(txp->umt, utxo_query, strlen(utxo_query))) {
		logmsg(LOG_ERR, "Sql statement preparation failed: %s:%s \n",
				utxo_query, mysql_stmt_error(txp->umt));
		retv = -mysql_stmt_errno(txp->umt);
		goto err_exit_40;
	}
	memset(txp->mbnd, 0, 2*sizeof(MYSQL_BIND));
	txp->mbnd[0].buffer_type = MYSQL_TYPE_BLOB;
	txp->mbnd[0].buffer = txp->val_query.keyhash;
	txp->mbnd[0].buffer_length = RIPEMD_LEN;
	txp->mbnd[0].length = &txp->val_query.ripe_len;
	txp->mbnd[1].buffer_type = MYSQL_TYPE_SHORT;
	txp->mbnd[1].buffer = &txp->val_query.etoken_id;
	txp->mbnd[1].is_unsigned = 1;
	if (mysql_stmt_bind_param(txp->umt, txp->mbnd)) {
		logmsg(LOG_ERR, "mysql_stmt_bind_param failed: %s, %s\n",
				txid_query, mysql_stmt_error(txp->umt));
		retv = -mysql_stmt_errno(txp->umt);
		goto err_exit_40;
	}
	memset(txp->rbnd, 0, sizeof(MYSQL_BIND));
	txp->rbnd[0].buffer_type = MYSQL_TYPE_LONGLONG;
	txp->rbnd[0].buffer = &txp->val_query.value;
	txp->rbnd[0].is_unsigned = 1;
	if (mysql_stmt_bind_result(txp->umt, txp->rbnd)) {
		logmsg(LOG_ERR, "mysql_stmt_bind_result failed: %s, %s\n",
				txid_query, mysql_stmt_error(txp->qmt));
		retv = -mysql_stmt_errno(txp->umt);
		goto err_exit_40;
	}

	return retv;

err_exit_40:
	mysql_stmt_close(txp->umt);
err_exit_30:
	mysql_stmt_close(txp->imt);
err_exit_20:
	mysql_stmt_close(txp->qmt);
err_exit_10:
	mysql_close(txp->mcon);
	return retv;
}

void *tx_process(void *arg)
{
	struct wcomm *wm = arg;
	int rc, verified;
	struct timespec tm;
	const struct winfo *cwif;
	struct winfo *wif;
	struct txrec_info *txp;

	wif = malloc(2*MAX_TXSIZE+sizeof(struct txrec_info));
	if (!check_pointer(wif))
		return NULL;
	txp= (struct txrec_info *)(((unsigned char *)wif) + MAX_TXSIZE);
	if (txrec_info_init(txp, wif) != 0)
		goto exit_5;

	do {
		pthread_mutex_lock(&wm->wmtx);
		clock_gettime(CLOCK_REALTIME, &tm);
		tm.tv_sec += 1;
		rc = 0;
		while (global_exit == 0 && wcomm_empty(wm) &&
				(rc == 0 || rc == ETIMEDOUT)) {
			rc = pthread_cond_timedwait(&wm->wcd, &wm->wmtx, &tm);
			tm.tv_sec += 1;
		}
		if (unlikely(rc != 0 && rc != ETIMEDOUT)) {
			logmsg(LOG_ERR, "pthread_cond_timedwait failed: %s\n",
					strerror(rc));
			global_exit = 1;
			pthread_mutex_unlock(&wm->wmtx);
			continue;
		}
		cwif = NULL;
		if (!wcomm_empty(wm)) {
			cwif = wcomm_getload(wm);
			memcpy(wif, cwif, sizeof(struct winfo) + cwif->wpkt.len);
			wcomm_tail_inc(wm);
		}
		pthread_mutex_unlock(&wm->wmtx);
		if (!cwif)
			continue;
		switch(wif->wpkt.ptype) {
		case TX_REC:
			verified = txrec_verify(wm->sock, wif, txp);
			if (verified == 1 && wm->pipd != -1) {
				if (notify_tx_logging(wm->pipd) == -1)
					global_exit = 1;
			}
			break;
		case UTXO_REQ:
			utxo_do_query(wm->sock, wif, txp);
			break;
		default:
			;
		}
	} while (global_exit == 0);

	txrec_info_release(txp);
exit_5:
	free(wif);
	global_exit = 1;
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
	if (!wm) {
		global_param_exit();
		return 1;
	}
	if (argc > 1)
		wm->pipd = atoi(argv[1]);
	else
		wm->pipd = -1;

	memset(&sigact, 0, sizeof(sigact));
	sigact.sa_handler = mysig_handler;
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
		retv = 3;
		goto exit_10;
	}

	retv = tx_recv(g_param->netp.port, wm);
	if (retv < 0) {
		retv = -retv;
		global_exit = 1;
	}

	pthread_join(rcvthd, NULL);

exit_10:
	global_param_exit();
	wcomm_exit(wm);
	return retv;
}
