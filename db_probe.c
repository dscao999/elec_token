#include <stdio.h>
#include <string.h>
#include "loglog.h"
#include "db_probe.h"

void static getcmd(char *buf, int len)
{
	FILE *fin;
	int numb;

	fin = fopen("/proc/self/cmdline", "rb");
	numb = fread(buf, 1, 128, fin);
	if (numb > 0)
		buf[numb] = 0;
	else
		buf[0] = 0;
	fclose(fin);
}

int check_db_probe(MYSQL *mcon, struct timespec *tm0)
{
	static const char utxo_query[] = "SELECT COUNT(*) FROM utxo " \
					 "WHERE blockid > 1 " \
					 "AND in_process != 1";
	MYSQL_RES *mres;
	MYSQL_ROW row;
	long retv = -1;
	char *fd1, *buf;
	struct timespec tm1;

	clock_gettime(CLOCK_MONOTONIC_COARSE, &tm1);
	if (mysql_query(mcon, utxo_query)) {
		logmsg(LOG_ERR, "Cannot execute %s->%s\n", utxo_query,
				mysql_error(mcon));
		retv = -mysql_errno(mcon);
		goto exit_10;
	}
	mres = mysql_store_result(mcon);
	if (mres == NULL) {
		logmsg(LOG_ERR, "Bad results from %s->%s\n", utxo_query,
				mysql_error(mcon));
		retv = -mysql_errno(mcon);
		goto exit_10;
	}
	row = mysql_fetch_row(mres);
	if (row == NULL) {
		logmsg(LOG_ERR, "Empty results from %s->%s\n", utxo_query);
		goto exit_20;
	}
	fd1 = row[0];
	if (unlikely(fd1 == NULL)) {
		logmsg(LOG_ERR, "Bad results from %s->%s\n", utxo_query);
		goto exit_20;
	}
	retv = atol(fd1);

	if (tm1.tv_sec - tm0->tv_sec > 24*3600) {
		buf = malloc(128);
		if (check_pointer(buf)) {
			getcmd(buf, 128);
			logmsg(LOG_INFO, "%s: Total valid utxo records: %ld\n",
					buf, retv);
			free(buf);
		} else {
			logmsg(LOG_INFO, "Total valid utxo records: %ld\n",
					retv);
		}
		*tm0 = tm1;
	}

exit_20:
	mysql_free_result(mres);
exit_10:
	return retv;
}
