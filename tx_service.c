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
#include <my_global.h>
#include <mysql.h>
#include "global_param.h"
#include "loglog.h"
#include "wcomm.h"
#include "toktx.h"

static volatile int global_exit = 0;

static void mysig_handler(int sig)
{
	if (sig == SIGTERM || sig == SIGINT)
		global_exit = 1;
}

static const char txid_query[] = "select seq from txrec_pool where " \
				  "txhash = ?";
static const char txid_insert[] = "insert into txrec_pool(txhash, txdata) " \
				  "values(?, ?)";
static int txrec_verify(int sock, const struct winfo *wif,
		unsigned char *sha_dgst, MYSQL_STMT *qstmt, MYSQL_STMT *istmt)
{
	int suc, mysql_retv, txcnt, numb;
	struct txrec *tx;
	struct {
		struct wpacket wpkt;
		unsigned char sha_dgst[SHA_DGST_LEN];
	} ack;
	struct sockaddr_in *sockaddr;

	sha256_to_str(sha_dgst, (const unsigned char *)wif->wpkt.pkt,
			wif->wpkt.len);
	suc = 3;
	tx = tx_deserialize(wif->wpkt.pkt, wif->wpkt.len);
	if (!tx)
		goto exit_100;
	suc = tx_verify(tx);
	tx_destroy(tx);
	if (suc == 0)
		goto exit_100;

	if (mysql_stmt_execute(qstmt)) {
		logmsg(LOG_ERR, "mysql_execute failed: %s, %s\n", txid_query,
				mysql_stmt_error(qstmt));
		suc = -1;
		goto exit_100;
	}
	txcnt = 0;
	mysql_retv = mysql_stmt_fetch(qstmt);
	while (mysql_retv != MYSQL_NO_DATA) {
		txcnt += 1;
		mysql_retv = mysql_stmt_fetch(qstmt);
	}
	if (txcnt > 0)
		suc = 2;
	mysql_stmt_free_result(qstmt);

exit_100:
	if (suc == 1 && mysql_stmt_execute(istmt)) {
		logmsg(LOG_ERR, "mysql_execute failed: %s, %s\n", txid_query,
				mysql_stmt_error(qstmt));
		suc = -1;
	}
	ack.wpkt.ptype = suc;
	ack.wpkt.len = SHA_DGST_LEN;
	memcpy(ack.wpkt.pkt, sha_dgst, SHA_DGST_LEN);
	sockaddr = (struct sockaddr_in *)&wif->srcaddr;
	numb = sendto(sock, &ack, sizeof(ack), 0,
			(const struct sockaddr *)sockaddr,
			sizeof(struct sockaddr_in));
	if (numb == -1)
		logmsg(LOG_ERR, "sendto failed: %s\n", strerror(errno));
	return suc;
}

static int utxo_query(int sock, const struct winfo *wif)
{
	return 0;
}

void *tx_process(void *arg)
{
	struct wcomm *wm = arg;
	int rc, valid;
	struct timespec tm;
	const struct winfo *cwif;
	struct winfo *wif;
	unsigned char *sha_dgst;
	unsigned long shalen, txrec_len;
	unsigned int tx_seq;
	MYSQL *mcon;
	MYSQL_STMT *qstmt, *istmt;
	MYSQL_BIND *mbnd, *rbnd;

	wif = malloc(MAX_TXSIZE+SHA_DGST_LEN+2*sizeof(MYSQL_BIND));
	if (!check_pointer(wif))
		return NULL;
	sha_dgst = ((unsigned char *)wif) + MAX_TXSIZE;
	mbnd = (MYSQL_BIND *)(sha_dgst + SHA_DGST_LEN);
	rbnd = (MYSQL_BIND *)(sha_dgst + SHA_DGST_LEN + sizeof(MYSQL_BIND));

	mcon = mysql_init(NULL);
	if (!check_pointer(mcon))
		goto exit_5;
	if (mysql_real_connect(mcon, g_param->db.host, g_param->db.user,
				g_param->db.passwd, g_param->db.dbname, 0,
				NULL, 0) == NULL ) {
		logmsg(LOG_ERR, "mysql_real_connect failed: %s\n",
				mysql_error(mcon));
		goto exit_10;
	}
	qstmt = mysql_stmt_init(mcon);
	if (!check_pointer(qstmt))
		goto exit_10;
	if (mysql_stmt_prepare(qstmt, txid_query, strlen(txid_query))) {
		logmsg(LOG_ERR, "Sql statement preparation failed: %s:%s \n",
				txid_query, mysql_stmt_error(qstmt));
		goto exit_20;
	}
	shalen = SHA_DGST_LEN;
	memset(mbnd, 0, sizeof(MYSQL_BIND));
	mbnd[0].buffer_type = MYSQL_TYPE_BLOB;
	mbnd[0].buffer = sha_dgst;
	mbnd[0].buffer_length = SHA_DGST_LEN;
	mbnd[0].length = &shalen;
	if (mysql_stmt_bind_param(qstmt, mbnd)) {
		logmsg(LOG_ERR, "mysql_stmt_bind_param failed: %s, %s\n",
				txid_query, mysql_stmt_error(qstmt));
		global_exit = 1;
		goto exit_20;
	}
	memset(rbnd, 0, sizeof(MYSQL_BIND));
	rbnd[0].buffer_type = MYSQL_TYPE_LONG;
	rbnd[0].buffer = &tx_seq;
	rbnd[0].is_unsigned = 1;
	if (mysql_stmt_bind_result(qstmt, rbnd)) {
		logmsg(LOG_ERR, "mysql_stmt_bind_result failed: %s, %s\n",
				txid_query, mysql_stmt_error(qstmt));
		goto exit_20;
	}

	istmt = mysql_stmt_init(mcon);
	if (!check_pointer(istmt))
		goto exit_20;
	if (mysql_stmt_prepare(istmt, txid_insert, strlen(txid_insert))) {
		logmsg(LOG_ERR, "Sql statement preparation failed: %s:%s \n",
				txid_insert, mysql_stmt_error(qstmt));
		goto exit_30;
	}
	memset(mbnd, 0, 2*sizeof(MYSQL_BIND));
	mbnd[0].buffer_type = MYSQL_TYPE_BLOB;
	mbnd[0].buffer = sha_dgst;
	mbnd[0].buffer_length = SHA_DGST_LEN;
	mbnd[0].length = &shalen;
	mbnd[1].buffer_type = MYSQL_TYPE_BLOB;
	mbnd[1].buffer = wif->wpkt.pkt;
	mbnd[1].buffer_length = MAX_TXSIZE - sizeof(struct winfo);
	mbnd[1].length = &txrec_len;
	if (mysql_stmt_bind_param(istmt, mbnd)) {
		logmsg(LOG_ERR, "mysql_stmt_bind_param failed: %s, %s\n",
				txid_query, mysql_stmt_error(qstmt));
		global_exit = 1;
		goto exit_20;
	}

	do {
		pthread_mutex_lock(&wm->wmtx);
		clock_gettime(CLOCK_REALTIME, &tm);
		tm.tv_sec += 1;
		rc = 0;
		while (global_exit == 0 && wcomm_empty(wm) &&
				(rc == 0 || rc == ETIMEDOUT))
			rc = pthread_cond_timedwait(&wm->wcd, &wm->wmtx, &tm);
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
			txrec_len = wif->wpkt.len;
			valid = txrec_verify(wm->sock, wif, sha_dgst, qstmt,
					istmt);
			if (valid == 1)
				mysql_commit(mcon);
			break;
		case UTXO_REQ:
			utxo_query(wm->sock, wif);
			break;
		default:
			;
		}
	} while (global_exit == 0);

exit_30:
	mysql_stmt_close(istmt);
exit_20:
	mysql_stmt_close(qstmt);
exit_10:
	mysql_close(mcon);
exit_5:
	free(wif);
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
		return 2;
	}
	retv = tx_recv(g_param->netp.port, wm);
	if (retv < 0)
		retv = -retv;
	pthread_join(rcvthd, NULL);
	wcomm_exit(wm);

	return retv;
}
